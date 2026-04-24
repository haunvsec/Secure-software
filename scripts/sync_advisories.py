#!/usr/bin/env python3
"""Incremental sync of security advisory data from git repository.

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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from import_advisories import parse_advisory

logger = logging.getLogger('sync_advisories')

ADVISORY_REPO_URL = 'https://github.com/haunvsec/security-advisory-db.git'
DEFAULT_ADVISORY_DIR = os.environ.get('ADVISORY_REPO_PATH', 'security-advisory-db')
SOURCE_KEY = 'advisory'


def _get_engine():
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
    from models.orm import SyncState
    row = session.query(SyncState).filter(SyncState.source == SOURCE_KEY).first()
    return row.last_commit_hash if row else None


def _save_sync_state(session, commit_hash, files_changed, records_updated, status):
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
    if not os.path.isdir(os.path.join(repo_dir, '.git')):
        logger.info(f"Cloning {ADVISORY_REPO_URL}...")
        subprocess.run(['git', 'clone', '--depth=1', ADVISORY_REPO_URL, repo_dir],
                       check=True, capture_output=True, text=True)
    else:
        subprocess.run(
            ['git', 'pull', '--ff-only'], cwd=repo_dir,
            capture_output=True, text=True, check=True
        )
    head = subprocess.run(
        ['git', 'rev-parse', 'HEAD'], cwd=repo_dir,
        capture_output=True, text=True
    ).stdout.strip()
    return head


def get_changed_files(repo_dir, old_hash, new_hash):
    if old_hash is None:
        import glob
        files = glob.glob(os.path.join(repo_dir, '**', '*.json'), recursive=True)
        return [f for f in files if '.git' not in f]

    result = subprocess.run(
        ['git', 'diff', '--name-only', f'{old_hash}..{new_hash}', '--', '*.json'],
        cwd=repo_dir, capture_output=True, text=True
    )
    files = []
    for line in result.stdout.strip().split('\n'):
        if line and line.endswith('.json'):
            full_path = os.path.join(repo_dir, line)
            if os.path.isfile(full_path):
                files.append(full_path)
    return files


def upsert_advisory(session, record):
    from models.orm import (
        SecurityAdvisory, AdvisoryAffectedProduct, AdvisoryCve, AdvisoryReference,
    )

    adv = record['advisory']
    adv_id = adv['id']

    existing = session.query(SecurityAdvisory).filter(SecurityAdvisory.id == adv_id).first()
    if existing:
        session.delete(existing)
        session.flush()

    advisory = SecurityAdvisory(
        id=adv['id'], source=adv['source'], title=adv['title'],
        description=adv['description'], severity=adv['severity'],
        cvss_score=adv['cvss_score'], cvss_vector=adv['cvss_vector'],
        published_date=adv['published_date'], modified_date=adv['modified_date'],
        url=adv['url'], vendor=adv.get('vendor', ''),
        solution=adv['solution'], json_file=adv['json_file'],
    )
    session.add(advisory)

    for ap in record['affected']:
        session.add(AdvisoryAffectedProduct(
            advisory_id=adv_id,
            vendor=ap['vendor'], product=ap['product'],
            version_range=ap['version_range'], fixed_version=ap['fixed_version'],
        ))

    for cve_id in record['cves']:
        if cve_id:
            session.add(AdvisoryCve(advisory_id=adv_id, cve_id=cve_id))

    for ref_url in record['references']:
        if ref_url:
            session.add(AdvisoryReference(advisory_id=adv_id, url=ref_url))


def sync(session=None, repo_dir=None):
    repo_dir = repo_dir or DEFAULT_ADVISORY_DIR
    start = time.time()
    result = {'source': SOURCE_KEY, 'status': 'success', 'files_changed': 0,
              'records_updated': 0, 'errors': 0, 'duration': 0}

    close_after = False
    try:
        if session is None:
            from sqlalchemy.orm import sessionmaker
            engine = _get_engine()
            Session = sessionmaker(bind=engine)
            session = Session()
            close_after = True

        saved_hash = _get_saved_hash(session)
        logger.info(f"Advisory sync: saved hash = {saved_hash or 'none'}")

        current_hash = git_pull(repo_dir)
        logger.info(f"Advisory sync: current HEAD = {current_hash}")

        if saved_hash == current_hash:
            result['status'] = 'no_changes'
            logger.info("Advisory sync: no changes (hash matches)")
            return result

        changed = get_changed_files(repo_dir, saved_hash, current_hash)
        result['files_changed'] = len(changed)
        logger.info(f"Advisory sync: {len(changed)} files changed")

        if not changed:
            _save_sync_state(session, current_hash, 0, 0, 'no_advisory_changes')
            session.commit()
            result['status'] = 'no_advisory_changes'
            return result

        for filepath in changed:
            record = parse_advisory(filepath)
            if record:
                try:
                    upsert_advisory(session, record)
                    result['records_updated'] += 1
                except Exception as e:
                    result['errors'] += 1
                    logger.error(f"Error upserting {filepath}: {e}")
                    session.rollback()

        _save_sync_state(session, current_hash, result['files_changed'],
                         result['records_updated'], 'success')
        session.commit()

        try:
            from database import cache
            cache.clear()
        except Exception:
            pass

    except Exception as e:
        result['status'] = 'error'
        result['error_message'] = str(e)
        logger.error(f"Advisory sync error: {e}")

    finally:
        if close_after and session:
            session.close()

    result['duration'] = round(time.time() - start, 2)
    logger.info(f"Advisory sync done: {result}")
    return result


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print(sync())
