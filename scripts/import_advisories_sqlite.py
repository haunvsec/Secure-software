#!/usr/bin/env python3
"""Import advisory JSON files into SQLite (fast), then migrate to MariaDB."""
import json
import glob
import os
import sqlite3
import sys
import time

ADVISORY_DIR = os.environ.get(
    'ADVISORY_DIR',
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'security-advisory-db'),
)
SQLITE_PATH = os.environ.get('SQLITE_ADVISORY_PATH', 'advisories_temp.db')

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from import_advisories import parse_advisory


def create_tables(conn):
    # Drop old advisory tables to ensure clean schema (ecosystem → vendor)
    conn.executescript("""
        DROP TABLE IF EXISTS advisory_references;
        DROP TABLE IF EXISTS advisory_cves;
        DROP TABLE IF EXISTS advisory_affected_products;
        DROP TABLE IF EXISTS security_advisories;

        CREATE TABLE security_advisories (
            id TEXT PRIMARY KEY, source TEXT, title TEXT, description TEXT,
            severity TEXT, cvss_score REAL, cvss_vector TEXT,
            published_date TEXT, modified_date TEXT, url TEXT,
            vendor TEXT, solution TEXT, json_file TEXT
        );
        CREATE TABLE advisory_affected_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL, vendor TEXT, product TEXT,
            version_range TEXT, fixed_version TEXT
        );
        CREATE TABLE advisory_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL, cve_id TEXT
        );
        CREATE TABLE advisory_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL, url TEXT
        );
    """)


def main():
    print(f"Importing advisories from {ADVISORY_DIR} into SQLite {SQLITE_PATH}...")

    conn = sqlite3.connect(SQLITE_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    create_tables(conn)

    json_files = glob.glob(os.path.join(ADVISORY_DIR, '**', '*.json'), recursive=True)
    json_files = [f for f in json_files if '.git' not in f]
    print(f"Found {len(json_files)} files")

    total = errors = 0
    start = time.time()

    for fp in json_files:
        rec = parse_advisory(fp)
        if not rec:
            errors += 1
            continue
        total += 1
        adv = rec['advisory']
        conn.execute(
            "INSERT OR REPLACE INTO security_advisories VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (adv['id'], adv['source'], adv['title'], adv['description'],
             adv['severity'], adv['cvss_score'], adv['cvss_vector'],
             adv['published_date'], adv['modified_date'], adv['url'],
             adv['vendor'], adv['solution'], adv['json_file']))
        for ap in rec['affected']:
            conn.execute(
                "INSERT INTO advisory_affected_products(advisory_id,vendor,product,version_range,fixed_version) VALUES(?,?,?,?,?)",
                (adv['id'], ap['vendor'], ap['product'], ap['version_range'], ap['fixed_version']))
        for cve_id in rec['cves']:
            if cve_id:
                conn.execute("INSERT INTO advisory_cves(advisory_id,cve_id) VALUES(?,?)", (adv['id'], cve_id))
        for ref_url in rec['references']:
            if ref_url:
                conn.execute("INSERT INTO advisory_references(advisory_id,url) VALUES(?,?)", (adv['id'], ref_url))

    conn.commit()
    elapsed = time.time() - start

    for t in ['security_advisories', 'advisory_affected_products', 'advisory_cves', 'advisory_references']:
        cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t}: {cnt:,}")
    print(f"\nDone in {elapsed:.1f}s. Total: {total}, Errors: {errors}")
    conn.close()


if __name__ == '__main__':
    main()
