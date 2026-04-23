#!/usr/bin/env python3
"""Import security advisory JSON files into cve_database.db.

Reads JSON files from the advisory data directory, fuzzy-matches
ecosystem/name to existing vendor/product in the CVE database,
and creates new entries if no match >= 90%.
"""

import json
import glob
import os
import sqlite3
import sys
from difflib import SequenceMatcher

DB_PATH = "cve_database.db"
ADVISORY_DIR = "/Volumes/DATA/security_advisory/data"
MATCH_THRESHOLD = 0.90


def create_advisory_tables(conn):
    """Create advisory-related tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS security_advisories (
            id TEXT PRIMARY KEY,
            source TEXT,
            title TEXT,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            published_date TEXT,
            modified_date TEXT,
            url TEXT,
            ecosystem TEXT,
            solution TEXT,
            json_file TEXT
        );

        CREATE TABLE IF NOT EXISTS advisory_affected_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL,
            ecosystem TEXT,
            name TEXT,
            version_range TEXT,
            fixed_version TEXT,
            matched_vendor TEXT,
            matched_product TEXT,
            FOREIGN KEY (advisory_id) REFERENCES security_advisories(id)
        );

        CREATE TABLE IF NOT EXISTS advisory_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL,
            cve_id TEXT,
            FOREIGN KEY (advisory_id) REFERENCES security_advisories(id)
        );

        CREATE TABLE IF NOT EXISTS advisory_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL,
            url TEXT,
            FOREIGN KEY (advisory_id) REFERENCES security_advisories(id)
        );

        CREATE INDEX IF NOT EXISTS idx_adv_source ON security_advisories(source);
        CREATE INDEX IF NOT EXISTS idx_adv_severity ON security_advisories(severity);
        CREATE INDEX IF NOT EXISTS idx_adv_published ON security_advisories(published_date);
        CREATE INDEX IF NOT EXISTS idx_adv_ap_advisory ON advisory_affected_products(advisory_id);
        CREATE INDEX IF NOT EXISTS idx_adv_ap_vendor ON advisory_affected_products(matched_vendor);
        CREATE INDEX IF NOT EXISTS idx_adv_ap_product ON advisory_affected_products(matched_product);
        CREATE INDEX IF NOT EXISTS idx_adv_cves_advisory ON advisory_cves(advisory_id);
        CREATE INDEX IF NOT EXISTS idx_adv_cves_cve ON advisory_cves(cve_id);
        CREATE INDEX IF NOT EXISTS idx_adv_refs_advisory ON advisory_references(advisory_id);
    """)
    conn.commit()


def build_vendor_product_index(conn):
    """Build a lookup index of existing vendor/product pairs for fuzzy matching."""
    rows = conn.execute(
        "SELECT DISTINCT vendor, product FROM affected_products "
        "WHERE vendor != '' AND vendor != 'n/a' AND vendor IS NOT NULL "
        "AND product != '' AND product != 'n/a' AND product IS NOT NULL"
    ).fetchall()
    index = {}
    for r in rows:
        v, p = r[0], r[1]
        key = f"{v.lower()}||{p.lower()}"
        index[key] = (v, p)
    return index


def fuzzy_match(ecosystem, name, vp_index, _cache={}):
    """Fuzzy match ecosystem/name to vendor/product. Returns (vendor, product) or None."""
    if not ecosystem or not name:
        return None

    cache_key = f"{ecosystem.lower()}||{name.lower()}"

    # Check cache
    if cache_key in _cache:
        return _cache[cache_key]

    # Exact match first
    if cache_key in vp_index:
        _cache[cache_key] = vp_index[cache_key]
        return _cache[cache_key]

    # Try common variations
    name_lower = name.lower()
    eco_lower = ecosystem.lower()

    # Try eco/name with case-insensitive lookup
    for key, (v, p) in vp_index.items():
        kv, kp = key.split('||', 1)
        if kp == name_lower and SequenceMatcher(None, eco_lower, kv).ratio() > 0.7:
            _cache[cache_key] = (v, p)
            return (v, p)

    # Fuzzy match on product name only — limit candidates by first letter
    best_score = 0
    best_match = None
    first_char = name_lower[0] if name_lower else ''

    for key, (v, p) in vp_index.items():
        p_lower = key.split('||', 1)[1]
        # Quick filter: same first char or very short name
        if p_lower and p_lower[0] != first_char and len(name_lower) > 3:
            continue
        if abs(len(name_lower) - len(p_lower)) > 5:
            continue

        score = SequenceMatcher(None, name_lower, p_lower).ratio()
        if score > best_score:
            best_score = score
            best_match = (v, p)

    if best_score >= MATCH_THRESHOLD:
        _cache[cache_key] = best_match
        return best_match

    _cache[cache_key] = None
    return None


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
        'ecosystem': data.get('ecosystem', ''),
        'solution': data.get('solution', ''),
        'json_file': os.path.relpath(filepath, os.path.dirname(ADVISORY_DIR)),
    }

    affected = []
    for ap in data.get('affected_products', []):
        affected.append({
            'ecosystem': ap.get('ecosystem', ''),
            'name': ap.get('name', ''),
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
    print(f"Database: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    create_advisory_tables(conn)

    # Clear existing advisory data
    for table in ['advisory_references', 'advisory_cves', 'advisory_affected_products', 'security_advisories']:
        conn.execute(f"DELETE FROM {table}")
    conn.commit()

    # Build vendor/product index for fuzzy matching
    print("Building vendor/product index...")
    vp_index = build_vendor_product_index(conn)
    print(f"  {len(vp_index)} unique vendor/product pairs")

    # Collect JSON files
    json_files = glob.glob(os.path.join(ADVISORY_DIR, '**', '*.json'), recursive=True)
    json_files = [f for f in json_files if 'scheduler' not in f and '.git' not in f]
    print(f"Found {len(json_files)} advisory JSON files")

    matched = 0
    unmatched = 0
    new_products = set()
    total = 0
    errors = 0

    for filepath in json_files:
        record = parse_advisory(filepath)
        if not record:
            errors += 1
            continue

        total += 1
        adv = record['advisory']

        # Insert advisory
        conn.execute(
            "INSERT OR REPLACE INTO security_advisories "
            "(id, source, title, description, severity, cvss_score, cvss_vector, "
            "published_date, modified_date, url, ecosystem, solution, json_file) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (adv['id'], adv['source'], adv['title'], adv['description'],
             adv['severity'], adv['cvss_score'], adv['cvss_vector'],
             adv['published_date'], adv['modified_date'], adv['url'],
             adv['ecosystem'], adv['solution'], adv['json_file'])
        )

        # Insert affected products with fuzzy matching
        for ap in record['affected']:
            match = fuzzy_match(ap['ecosystem'], ap['name'], vp_index)
            if match:
                mv, mp = match
                matched += 1
            else:
                # Create new entry using ecosystem/name as vendor/product
                mv = ap['ecosystem'] or ''
                mp = ap['name'] or ''
                if mv and mp:
                    new_key = f"{mv.lower()}||{mp.lower()}"
                    if new_key not in vp_index:
                        vp_index[new_key] = (mv, mp)
                        new_products.add(f"{mv}/{mp}")
                unmatched += 1

            conn.execute(
                "INSERT INTO advisory_affected_products "
                "(advisory_id, ecosystem, name, version_range, fixed_version, "
                "matched_vendor, matched_product) VALUES (?,?,?,?,?,?,?)",
                (adv['id'], ap['ecosystem'], ap['name'],
                 ap['version_range'], ap['fixed_version'], mv, mp)
            )

        # Insert CVEs
        for cve_id in record['cves']:
            if cve_id:
                conn.execute(
                    "INSERT INTO advisory_cves (advisory_id, cve_id) VALUES (?,?)",
                    (adv['id'], cve_id)
                )

        # Insert references
        for ref_url in record['references']:
            if ref_url:
                conn.execute(
                    "INSERT INTO advisory_references (advisory_id, url) VALUES (?,?)",
                    (adv['id'], ref_url)
                )

    conn.commit()

    # Print stats
    print(f"\nImport complete!")
    print(f"  Total advisories: {total}")
    print(f"  Errors: {errors}")
    print(f"  Product matches: {matched}")
    print(f"  Unmatched (new): {unmatched}")
    print(f"  New products added: {len(new_products)}")

    for table in ['security_advisories', 'advisory_affected_products', 'advisory_cves', 'advisory_references']:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        print(f"  {table}: {row[0]} rows")

    # Print source distribution
    print("\nAdvisories by source:")
    rows = conn.execute(
        "SELECT source, COUNT(*) as cnt FROM security_advisories GROUP BY source ORDER BY cnt DESC"
    ).fetchall()
    for r in rows:
        print(f"  {r[0]}: {r[1]}")

    conn.close()


if __name__ == '__main__':
    main()
