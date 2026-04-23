#!/usr/bin/env python3
"""Incremental sync of security advisory data from git repository.

1. git pull to get latest changes
2. git diff to find changed JSON files
3. Parse and upsert only changed files (MariaDB via SQLAlchemy)
4. Clear cache

Advisory JSON now uses vendor/product directly — no fuzzy matching needed.
"""

import logging
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from import_advisories import parse_advisory

logger = logging.getLogger('sync_advisories')

ADVISORY_REPO_URL = 'https://github.com/haunvsec/security-advisory-db.git'
DEFAULT_ADVISORY_DIR = os.environ.get('ADVISORY_REPO_PATH', 'security-advisory-db')


def git_pull(repo_dir):
    """Pull latest changes. Returns (old_hash, new_hash) or None."""
    if not os.path.isdir(os.path.join(repo_dir, '.git')):
        logger.info(f"Cloning {ADVISORY_REPO_URL}...")
        subprocess.run(['git', 'clone', '--depth=1', ADVISORY_REPO_URL, repo_dir],
                       check=True, capture_output=True, text=True)
        return None, 'initial'

    old_hash = subprocess.run(
        ['git', 'rev-parse', 'HEAD'], cwd=repo_dir,
        capture_output=True, text=True
    ).stdout.strip()

    subprocess.run(
        ['git', 'pull', '--ff-only'], cwd=repo_dir,
        capture_output=True, text=True, check=True
    )

    new_hash = subprocess.run(
        ['git', 'rev-parse', 'HEAD'], cwd=repo_dir,
        capture_output=True, text=True
    ).stdout.strip()

    if old_hash == new_hash:
        return None, None
    return old_hash, new_hash


def get_changed_files(repo_dir, old_hash, new_hash):
    """Get list of changed JSON files."""
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


def upsert_advisory(session, record):
    """Insert or update a single advisory record using SQLAlchemy ORM."""
    from models.orm import (
        SecurityAdvisory, AdvisoryAffectedProduct, AdvisoryCve, AdvisoryReference,
    )

    adv = record['advisory']
    adv_id = adv['id']

    # Delete existing record (cascade handles children)
    existing = session.query(SecurityAdvisory).filter(SecurityAdvisory.id == adv_id).first()
    if existing:
        session.delete(existing)
        session.flush()

    # Insert new advisory
    advisory = SecurityAdvisory(
        id=adv['id'], source=adv['source'], title=adv['title'],
        description=adv['description'], severity=adv['severity'],
        cvss_score=adv['cvss_score'], cvss_vector=adv['cvss_vector'],
        published_date=adv['published_date'], modified_date=adv['modified_date'],
        url=adv['url'], vendor=adv['vendor'],
        solution=adv['solution'], json_file=adv['json_file'],
    )
    session.add(advisory)

    # Insert affected products — vendor/product directly from JSON
    for ap in record['affected']:
        session.add(AdvisoryAffectedProduct(
            advisory_id=adv_id,
            vendor=ap['vendor'],
            product=ap['product'],
            version_range=ap['version_range'],
            fixed_version=ap['fixed_version'],
        ))

    for cve_id in record['cves']:
        if cve_id:
            session.add(AdvisoryCve(advisory_id=adv_id, cve_id=cve_id))

    for ref_url in record['references']:
        if ref_url:
            session.add(AdvisoryReference(advisory_id=adv_id, url=ref_url))


def sync(session=None, repo_dir=None):
    """Run incremental advisory sync. Returns dict with results."""
    repo_dir = repo_dir or DEFAULT_ADVISORY_DIR
    start = time.time()
    result = {'source': 'advisory', 'status': 'success', 'files_changed': 0,
              'records_updated': 0, 'errors': 0, 'duration': 0}

    try:
        old_hash, new_hash = git_pull(repo_dir)
        if old_hash is None and new_hash is None:
            result['status'] = 'no_changes'
            logger.info("Advisory sync: no changes")
            return result

        changed = get_changed_files(repo_dir, old_hash, new_hash)
        result['files_changed'] = len(changed)
        logger.info(f"Advisory sync: {len(changed)} files changed")

        if not changed:
            result['status'] = 'no_changes'
            return result

        # Get or create SQLAlchemy session
        close_after = False
        if session is None:
            from sqlalchemy.orm import sessionmaker
            engine = _get_engine()
            Session = sessionmaker(bind=engine)
            session = Session()
            close_after = True

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

        session.commit()
        if close_after:
            session.close()

        # Clear cache
        try:
            from database import cache
            cache.clear()
        except Exception:
            pass

    except Exception as e:
        result['status'] = 'error'
        result['error_message'] = str(e)
        logger.error(f"Advisory sync error: {e}")

    result['duration'] = round(time.time() - start, 2)
    logger.info(f"Advisory sync done: {result}")
    return result


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print(sync())
