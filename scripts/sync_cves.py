#!/usr/bin/env python3
"""Incremental sync of CVE data from cvelistV5 git repository.

1. Read last_commit_hash from sync_state table
2. git pull to get latest changes
3. git diff between saved hash and current HEAD
4. Parse and upsert only changed files (MariaDB via SQLAlchemy)
5. Update sync_state with new hash
6. Clear cache
"""

import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

# Add project paths
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from import_cves import parse_cve_file

logger = logging.getLogger('sync_cves')

CVE_REPO_URL = 'https://github.com/CVEProject/cvelistV5.git'
DEFAULT_CVE_DIR = os.environ.get('CVE_REPO_PATH', 'cvelistV5')
SOURCE_KEY = 'cve'


def _get_engine():
    """Create a SQLAlchemy engine from environment variables."""
    from sqlalchemy import create_engine
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        host = os.environ.get('DB_HOST', 'localhost')
        port = os.environ.get('DB_PORT', '3306')
        user = os.environ.get('DB_USER', 'cvedb')
        password = os.environ.get('DB_PASSWORD', 'cvedb')
        database = os.environ.get('DB_NAME', 'cve_database')
        database_url = f'mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset=utf8mb4'
    return create_engine(database_url)


def _get_saved_hash(session):
    """Read last imported commit hash from sync_state table."""
    from models.orm import SyncState
    row = session.query(SyncState).filter(SyncState.source == SOURCE_KEY).first()
    return row.last_commit_hash if row else None


def _save_sync_state(session, commit_hash, files_changed, records_updated, status):
    """Update sync_state table with new hash and stats."""
    from models.orm import SyncState
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    row = session.query(SyncState).filter(SyncState.source == SOURCE_KEY).first()
    if row:
        row.last_commit_hash = commit_hash
        row.last_sync_time = now
        row.files_changed = files_changed
        row.records_updated = records_updated
        row.status = status
    else:
        session.add(SyncState(
            source=SOURCE_KEY, last_commit_hash=commit_hash,
            last_sync_time=now, files_changed=files_changed,
            records_updated=records_updated, status=status,
        ))


def git_pull(repo_dir):
    """Pull latest changes. Returns current HEAD hash."""
    if not os.path.isdir(os.path.join(repo_dir, '.git')):
        logger.info(f"Cloning {CVE_REPO_URL}...")
        subprocess.run(['git', 'clone', '--depth=1', CVE_REPO_URL, repo_dir],
                       check=True, capture_output=True, text=True)
    else:
        try:
            subprocess.run(
                ['git', 'pull', '--ff-only'], cwd=repo_dir,
                capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError:
            # ff-only failed — try fetch + reset
            logger.warning("git pull --ff-only failed, trying fetch + reset")
            subprocess.run(['git', 'fetch', 'origin'], cwd=repo_dir,
                           capture_output=True, text=True)
            subprocess.run(['git', 'reset', '--hard', 'origin/main'], cwd=repo_dir,
                           capture_output=True, text=True)
    head = subprocess.run(
        ['git', 'rev-parse', 'HEAD'], cwd=repo_dir,
        capture_output=True, text=True
    ).stdout.strip()
    return head


def get_changed_files(repo_dir, old_hash, new_hash):
    """Get list of changed JSON files between two commits."""
    if old_hash is None:
        # No saved hash — treat as initial import (all files)
        import glob
        return glob.glob(os.path.join(repo_dir, 'cves', '**', '*.json'), recursive=True)

    # Ensure we have enough history for diff (shallow clones may not)
    try:
        subprocess.run(
            ['git', 'cat-file', '-e', old_hash],
            cwd=repo_dir, capture_output=True, check=True
        )
    except subprocess.CalledProcessError:
        logger.info(f"Old hash {old_hash[:12]} not in history, fetching deeper...")
        subprocess.run(['git', 'fetch', '--unshallow'], cwd=repo_dir,
                       capture_output=True, text=True)

    result = subprocess.run(
        ['git', 'diff', '--name-only', f'{old_hash}..{new_hash}', '--', 'cves/*.json'],
        cwd=repo_dir, capture_output=True, text=True
    )
    files = []
    for line in result.stdout.strip().split('\n'):
        if line and line.endswith('.json') and 'delta' not in line:
            full_path = os.path.join(repo_dir, line)
            if os.path.isfile(full_path):
                files.append(full_path)
    return files


def upsert_cve(session, record):
    """Insert or update a single CVE record using SQLAlchemy ORM."""
    from models.orm import Cve, AffectedProduct, CvssScore, CweEntry, Reference

    c = record['cve']
    cve_id = c['cve_id']

    existing = session.query(Cve).filter(Cve.cve_id == cve_id).first()
    if existing:
        session.delete(existing)
        session.flush()

    cve = Cve(
        cve_id=c['cve_id'], state=c['state'],
        assigner_org_id=c['assigner_org_id'],
        assigner_short_name=c['assigner_short_name'],
        date_reserved=c['date_reserved'], date_published=c['date_published'],
        date_updated=c['date_updated'], description=c['description'],
        severity=c['severity'], data_version=c['data_version'],
    )
    session.add(cve)

    for a in record['affected']:
        session.add(AffectedProduct(
            cve_id=cve_id, vendor=a['vendor'], product=a['product'],
            platform=a['platform'], version_start=a['version_start'],
            version_end=a['version_end'], version_exact=a['version_exact'],
            default_status=a['default_status'], status=a['status'],
            version_end_type=a.get('version_end_type', ''),
        ))

    for s in record['cvss']:
        session.add(CvssScore(
            cve_id=cve_id, version=s['version'],
            vector_string=s['vector_string'], base_score=s['base_score'],
            base_severity=s['base_severity'], attack_vector=s['attack_vector'],
            attack_complexity=s['attack_complexity'],
            privileges_required=s['privileges_required'],
            user_interaction=s['user_interaction'], scope=s['scope'],
            confidentiality_impact=s['confidentiality_impact'],
            integrity_impact=s['integrity_impact'],
            availability_impact=s['availability_impact'], source=s['source'],
        ))

    for w in record['cwe']:
        session.add(CweEntry(
            cve_id=cve_id, cwe_id=w['cwe_id'], description=w['description'],
        ))

    for r in record['references']:
        session.add(Reference(
            cve_id=cve_id, url=r['url'], tags=r['tags'],
        ))


def sync(session=None, repo_dir=None):
    """Run incremental CVE sync. Returns dict with results."""
    repo_dir = repo_dir or DEFAULT_CVE_DIR
    start = time.time()
    result = {'source': SOURCE_KEY, 'status': 'success', 'files_changed': 0,
              'records_updated': 0, 'errors': 0, 'duration': 0}

    close_after = False
    try:
        # Get or create session
        if session is None:
            from sqlalchemy.orm import sessionmaker
            engine = _get_engine()
            Session = sessionmaker(bind=engine)
            session = Session()
            close_after = True

        # Read saved hash from DB
        saved_hash = _get_saved_hash(session)
        logger.info(f"CVE sync: saved hash = {saved_hash or 'none'}")

        # Git pull and get current HEAD
        current_hash = git_pull(repo_dir)
        logger.info(f"CVE sync: current HEAD = {current_hash}")

        if saved_hash == current_hash:
            result['status'] = 'no_changes'
            logger.info("CVE sync: no changes (hash matches)")
            return result

        # Find changed files
        changed = get_changed_files(repo_dir, saved_hash, current_hash)
        result['files_changed'] = len(changed)
        logger.info(f"CVE sync: {len(changed)} files changed")

        if not changed:
            # Hash changed but no JSON files changed (e.g. README update)
            _save_sync_state(session, current_hash, 0, 0, 'no_cve_changes')
            session.commit()
            result['status'] = 'no_cve_changes'
            return result

        # Upsert changed CVEs
        for filepath in changed:
            record = parse_cve_file(filepath)
            if record:
                try:
                    upsert_cve(session, record)
                    result['records_updated'] += 1
                except Exception as e:
                    result['errors'] += 1
                    logger.error(f"Error upserting {filepath}: {e}")
                    session.rollback()

        # Save new hash
        _save_sync_state(session, current_hash, result['files_changed'],
                         result['records_updated'], 'success')
        session.commit()

        # Clear cache
        try:
            from database import cache
            cache.clear()
            logger.info("Cache cleared")
        except Exception:
            pass

    except Exception as e:
        result['status'] = 'error'
        result['error_message'] = str(e)
        logger.error(f"CVE sync error: {e}")

    finally:
        if close_after and session:
            session.close()

    result['duration'] = round(time.time() - start, 2)
    logger.info(f"CVE sync done: {result}")
    return result


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print(sync())
