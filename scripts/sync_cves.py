#!/usr/bin/env python3
"""Incremental sync of CVE data from cvelistV5 git repository.

1. git pull to get latest changes
2. git diff to find changed JSON files
3. Parse and upsert only changed files
4. Clear cache
"""

import json
import logging
import os
import subprocess
import sys
import time

# Add project paths
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from import_cves import parse_cve_file

logger = logging.getLogger('sync_cves')

CVE_REPO_URL = 'https://github.com/CVEProject/cvelistV5.git'
DEFAULT_CVE_DIR = os.environ.get('CVE_REPO_PATH', 'cvelistV5')


def git_pull(repo_dir):
    """Pull latest changes. Returns (old_hash, new_hash) or None if no changes."""
    if not os.path.isdir(os.path.join(repo_dir, '.git')):
        logger.info(f"Cloning {CVE_REPO_URL}...")
        subprocess.run(['git', 'clone', '--depth=1', CVE_REPO_URL, repo_dir],
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
        return None, None  # No changes
    return old_hash, new_hash


def get_changed_files(repo_dir, old_hash, new_hash):
    """Get list of changed JSON files between two commits."""
    if old_hash is None:
        # Initial clone — return all JSON files
        import glob
        return glob.glob(os.path.join(repo_dir, 'cves', '**', '*.json'), recursive=True)

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


def upsert_cve(db, record):
    """Insert or update a single CVE record in the database."""
    c = record['cve']
    cursor = db.cursor()

    # Upsert CVE main record
    cursor.execute(
        "INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)",
        (c['cve_id'], c['state'], c['assigner_org_id'], c['assigner_short_name'],
         c['date_reserved'], c['date_published'], c['date_updated'],
         c['description'], c['severity'], c['data_version'])
    )

    # Delete old related data and re-insert
    cve_id = c['cve_id']
    for table in ['affected_products', 'cvss_scores', 'cwe_entries', 'references_table']:
        cursor.execute(f"DELETE FROM {table} WHERE cve_id = ?", (cve_id,))

    for a in record['affected']:
        cursor.execute(
            "INSERT INTO affected_products "
            "(cve_id, vendor, product, platform, version_start, version_end, "
            "version_exact, default_status, status, version_end_type) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (a['cve_id'], a['vendor'], a['product'], a['platform'],
             a['version_start'], a['version_end'], a['version_exact'],
             a['default_status'], a['status'], a['version_end_type'])
        )

    for s in record['cvss']:
        cursor.execute(
            "INSERT INTO cvss_scores "
            "(cve_id, version, vector_string, base_score, base_severity, "
            "attack_vector, attack_complexity, privileges_required, "
            "user_interaction, scope, confidentiality_impact, "
            "integrity_impact, availability_impact, source) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (s['cve_id'], s['version'], s['vector_string'], s['base_score'],
             s['base_severity'], s['attack_vector'], s['attack_complexity'],
             s['privileges_required'], s['user_interaction'], s['scope'],
             s['confidentiality_impact'], s['integrity_impact'],
             s['availability_impact'], s['source'])
        )

    for w in record['cwe']:
        cursor.execute(
            "INSERT INTO cwe_entries (cve_id, cwe_id, description) VALUES (?,?,?)",
            (w['cve_id'], w['cwe_id'], w['description'])
        )

    for r in record['references']:
        cursor.execute(
            "INSERT INTO references_table (cve_id, url, tags) VALUES (?,?,?)",
            (r['cve_id'], r['url'], r['tags'])
        )

    cursor.close()


def sync(db=None, repo_dir=None):
    """Run incremental CVE sync. Returns dict with results."""
    repo_dir = repo_dir or DEFAULT_CVE_DIR
    start = time.time()
    result = {'source': 'cve', 'status': 'success', 'files_changed': 0,
              'records_updated': 0, 'errors': 0, 'duration': 0}

    try:
        old_hash, new_hash = git_pull(repo_dir)
        if old_hash is None and new_hash is None:
            result['status'] = 'no_changes'
            logger.info("CVE sync: no changes")
            return result

        changed = get_changed_files(repo_dir, old_hash, new_hash)
        result['files_changed'] = len(changed)
        logger.info(f"CVE sync: {len(changed)} files changed")

        if not changed:
            result['status'] = 'no_changes'
            return result

        # Get or create DB connection
        close_after = False
        if db is None:
            import sqlite3
            db_path = os.environ.get('SQLITE_PATH', 'cve_database.db')
            db = sqlite3.connect(db_path)
            close_after = True

        for filepath in changed:
            record = parse_cve_file(filepath)
            if record:
                try:
                    upsert_cve(db, record)
                    result['records_updated'] += 1
                except Exception as e:
                    result['errors'] += 1
                    logger.error(f"Error upserting {filepath}: {e}")

        db.commit()
        if close_after:
            db.close()

        # Clear cache
        try:
            from database import cache
            for key in list(cache._cache.keys()):
                del cache._cache[key]
            logger.info("Cache cleared")
        except Exception:
            pass

    except Exception as e:
        result['status'] = 'error'
        result['error_message'] = str(e)
        logger.error(f"CVE sync error: {e}")

    result['duration'] = round(time.time() - start, 2)
    logger.info(f"CVE sync done: {result}")
    return result


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print(sync())
