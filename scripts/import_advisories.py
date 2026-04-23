#!/usr/bin/env python3
"""Import security advisory JSON files into MariaDB.

Reads JSON files from the advisory data directory. Advisory JSON files
now use vendor/product directly in affected_products — no fuzzy matching needed.
"""

import json
import glob
import os
import sys
import pymysql

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = int(os.environ.get('DB_PORT', 3306))
DB_USER = os.environ.get('DB_USER', 'cvedb')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'cvedb')
DB_NAME = os.environ.get('DB_NAME', 'cve_database')
ADVISORY_DIR = os.environ.get(
    'ADVISORY_DIR',
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'security-advisory-db'),
)


def parse_advisory(filepath):
    """Parse a single advisory JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    adv_id = data.get('id', '')
    if not adv_id:
        return None

    advisory = {
        'id': adv_id,
        'source': data.get('source', ''),
        'title': data.get('title', ''),
        'description': data.get('description', ''),
        'severity': data.get('severity', ''),
        'cvss_score': data.get('cvss_score'),
        'cvss_vector': data.get('cvss_vector', ''),
        'published_date': data.get('published_date', ''),
        'modified_date': data.get('modified_date', ''),
        'url': data.get('url', ''),
        'vendor': data.get('vendor', ''),
        'solution': data.get('solution', ''),
        'json_file': os.path.basename(filepath),
    }

    # affected_products now has vendor/product directly
    affected = []
    for ap in data.get('affected_products', []):
        affected.append({
            'vendor': ap.get('vendor', ''),
            'product': ap.get('product', ''),
            'version_range': ap.get('version_range', ''),
            'fixed_version': ap.get('fixed_version', ''),
        })

    cves = []
    for cve in data.get('cves', []):
        if isinstance(cve, str):
            cves.append(cve)
        elif isinstance(cve, dict):
            cves.append(cve.get('id', cve.get('cve_id', '')))

    references = data.get('references', [])
    if isinstance(references, list):
        references = [r if isinstance(r, str) else r.get('url', '') for r in references]

    return {
        'advisory': advisory,
        'affected': affected,
        'cves': cves,
        'references': references,
    }


def main():
    """Main import function."""
    print(f"Importing advisories from {ADVISORY_DIR}...")
    print(f"Database: {DB_HOST}:{DB_PORT}/{DB_NAME}")

    conn = pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER,
        password=DB_PASSWORD, database=DB_NAME, charset='utf8mb4',
    )
    cursor = conn.cursor()

    # Clear existing advisory data
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
    for table in ['advisory_references', 'advisory_cves',
                   'advisory_affected_products', 'security_advisories']:
        cursor.execute(f"TRUNCATE TABLE {table}")
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
    conn.commit()

    # Collect JSON files
    json_files = glob.glob(os.path.join(ADVISORY_DIR, '**', '*.json'), recursive=True)
    json_files = [f for f in json_files if '.git' not in f]
    print(f"Found {len(json_files)} advisory JSON files")

    total = 0
    errors = 0

    for filepath in json_files:
        record = parse_advisory(filepath)
        if not record:
            errors += 1
            continue

        total += 1
        adv = record['advisory']

        try:
            # Insert advisory
            cursor.execute(
                "INSERT INTO security_advisories "
                "(id, source, title, description, severity, cvss_score, cvss_vector, "
                "published_date, modified_date, url, vendor, solution, json_file) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE title=VALUES(title), description=VALUES(description), "
                "severity=VALUES(severity), cvss_score=VALUES(cvss_score), "
                "modified_date=VALUES(modified_date)",
                (adv['id'], adv['source'], adv['title'], adv['description'],
                 adv['severity'], adv['cvss_score'], adv['cvss_vector'],
                 adv['published_date'], adv['modified_date'], adv['url'],
                 adv['vendor'], adv['solution'], adv['json_file'])
            )

            # Insert affected products — vendor/product directly from JSON
            for ap in record['affected']:
                cursor.execute(
                    "INSERT INTO advisory_affected_products "
                    "(advisory_id, vendor, product, version_range, fixed_version) "
                    "VALUES (%s,%s,%s,%s,%s)",
                    (adv['id'], ap['vendor'], ap['product'],
                     ap['version_range'], ap['fixed_version'])
                )

            # Insert CVEs
            for cve_id in record['cves']:
                if cve_id:
                    cursor.execute(
                        "INSERT INTO advisory_cves (advisory_id, cve_id) VALUES (%s,%s)",
                        (adv['id'], cve_id)
                    )

            # Insert references
            for ref_url in record['references']:
                if ref_url:
                    cursor.execute(
                        "INSERT INTO advisory_references (advisory_id, url) VALUES (%s,%s)",
                        (adv['id'], ref_url)
                    )
        except Exception as e:
            errors += 1
            print(f"  Error importing {adv['id']}: {e}")

    conn.commit()

    # Print stats
    print(f"\nImport complete!")
    print(f"  Total advisories: {total}")
    print(f"  Errors: {errors}")

    for table in ['security_advisories', 'advisory_affected_products',
                   'advisory_cves', 'advisory_references']:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        print(f"  {table}: {cursor.fetchone()[0]:,} rows")

    # Print source distribution
    print("\nAdvisories by source:")
    cursor.execute(
        "SELECT source, COUNT(*) as cnt FROM security_advisories "
        "GROUP BY source ORDER BY cnt DESC"
    )
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    conn.close()


if __name__ == '__main__':
    main()
