#!/usr/bin/env python3
"""Incremental sync of security advisory data from git repository.

1. git pull to get latest changes
2. git diff to find changed JSON files
3. Parse and upsert only changed files with fuzzy matching
4. Clear cache
"""

import json
import logging
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from import_advisories import parse_advisory, fuzzy_match, build_vendor_product_index

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


def upsert_advisory(db, record, vp_index):
    """Insert or update a single advisory record."""
    adv = record['advisory']
    adv_id = adv['id']
    cursor = db.cursor()

    # Upsert advisory
    cursor.execute(
        "INSERT OR REPLACE INTO security_advisories "
        "(id, source, title, description, severity, cvss_score, cvss_vector, "
        "published_date, modified_date, url, ecosystem, solution, json_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (adv['id'], adv['source'], adv['title'], adv['description'],
         adv['severity'], adv['cvss_score'], adv['cvss_vector'],
         adv['published_date'], adv['modified_date'], adv['url'],
         adv['ecosystem'], adv['solution'], adv['json_file'])
    )

    # Delete old related data
    for table in ['advisory_affected_products', 'advisory_cves', 'advisory_references']:
        cursor.execute(f"DELETE FROM {table} WHERE advisory_id = ?", (adv_id,))

    # Insert affected products with fuzzy matching
    for ap in record['affected']:
        match = fuzzy_match(ap['ecosystem'], ap['name'], vp_index)
        mv = match[0] if match else (ap['ecosystem'] or '')
        mp = match[1] if match else (ap['name'] or '')
        if not match and mv and mp:
            new_key = f"{mv.lower()}||{mp.lower()}"
            if new_key not in vp_index:
                vp_index[new_key] = (mv, mp)

        cursor.execute(
            "INSERT INTO advisory_affected_products "
            "(advisory_id, ecosystem, name, version_range, fixed_version, "
            "matched_vendor, matched_product) VALUES (?,?,?,?,?,?,?)",
            (adv_id, ap['ecosystem'], ap['name'],
             ap['version_range'], ap['fixed_version'], mv, mp)
        )

    for cve_id in record['cves']:
        if cve_id:
            cursor.execute(
                "INSERT INTO advisory_cves (advisory_id, cve_id) VALUES (?,?)",
                (adv_id, cve_id)
            )

    for ref_url in record['references']:
        if ref_url:
            cursor.execute(
                "INSERT INTO advisory_references (advisory_id, url) VALUES (?,?)",
                (adv_id, ref_url)
            )

    cursor.close()


def sync(db=None, repo_dir=None):
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

        close_after = False
        if db is None:
            import sqlite3
            db_path = os.environ.get('SQLITE_PATH', 'cve_database.db')
            db = sqlite3.connect(db_path)
            close_after = True

        # Build vendor/product index for fuzzy matching
        vp_index = build_vendor_product_index(db)

        for filepath in changed:
            record = parse_advisory(filepath)
            if record:
                try:
                    upsert_advisory(db, record, vp_index)
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
