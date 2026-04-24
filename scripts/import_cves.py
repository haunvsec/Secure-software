#!/usr/bin/env python3
"""
Import CVE data from cvelistV5 JSON files into SQLite database.
"""

import json
import os
import sqlite3
import sys
import glob
import html
import re
from datetime import datetime

DB_PATH = "cve_database.db"
CVE_DIR = "cvelistV5/cves"


def strip_html(text):
    """Remove HTML tags from text."""
    if not text:
        return text
    clean = re.sub(r'<[^>]+>', '', text)
    return html.unescape(clean).strip()


def create_schema(conn):
    """Create database tables."""
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            state TEXT,
            assigner_org_id TEXT,
            assigner_short_name TEXT,
            date_reserved TEXT,
            date_published TEXT,
            date_updated TEXT,
            description TEXT,
            severity TEXT,
            data_version TEXT
        );

        CREATE TABLE IF NOT EXISTS affected_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            vendor TEXT,
            product TEXT,
            platform TEXT,
            version_start TEXT,
            version_end TEXT,
            version_exact TEXT,
            default_status TEXT,
            status TEXT,
            version_end_type TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE TABLE IF NOT EXISTS cvss_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            version TEXT,
            vector_string TEXT,
            base_score REAL,
            base_severity TEXT,
            attack_vector TEXT,
            attack_complexity TEXT,
            privileges_required TEXT,
            user_interaction TEXT,
            scope TEXT,
            confidentiality_impact TEXT,
            integrity_impact TEXT,
            availability_impact TEXT,
            source TEXT DEFAULT 'cna',
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE TABLE IF NOT EXISTS cwe_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            cwe_id TEXT,
            description TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE TABLE IF NOT EXISTS references_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            url TEXT,
            tags TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        -- Indexes for fast lookups
        CREATE INDEX IF NOT EXISTS idx_cves_state ON cves(state);
        CREATE INDEX IF NOT EXISTS idx_cves_date_published ON cves(date_published);
        CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
        CREATE INDEX IF NOT EXISTS idx_cves_assigner ON cves(assigner_short_name);
        CREATE INDEX IF NOT EXISTS idx_affected_vendor ON affected_products(vendor);
        CREATE INDEX IF NOT EXISTS idx_affected_product ON affected_products(product);
        CREATE INDEX IF NOT EXISTS idx_affected_vendor_product ON affected_products(vendor, product);
        CREATE INDEX IF NOT EXISTS idx_affected_cve ON affected_products(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cvss_cve ON cvss_scores(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cvss_score ON cvss_scores(base_score);
        CREATE INDEX IF NOT EXISTS idx_cvss_severity ON cvss_scores(base_severity);
        CREATE INDEX IF NOT EXISTS idx_cwe_cve ON cwe_entries(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe_entries(cwe_id);
        CREATE INDEX IF NOT EXISTS idx_refs_cve ON references_table(cve_id);
    """)

    conn.commit()


def extract_cvss(metrics, cve_id, source='cna'):
    """Extract CVSS scores from metrics array."""
    results = []
    if not metrics:
        return results

    for metric in metrics:
        row = {'cve_id': cve_id, 'source': source}

        # Try CVSS 3.1, 3.0, 2.0 in order
        cvss_data = None
        version = None
        for key in ['cvssV3_1', 'cvssV3_0', 'cvssV4_0', 'cvssV2_0']:
            if key in metric:
                cvss_data = metric[key]
                version = key.replace('cvssV', '').replace('_', '.')
                break

        if not cvss_data:
            continue

        row['version'] = version
        row['vector_string'] = cvss_data.get('vectorString', '')
        row['base_score'] = cvss_data.get('baseScore')
        row['base_severity'] = cvss_data.get('baseSeverity', '')
        row['attack_vector'] = cvss_data.get('attackVector', '')
        row['attack_complexity'] = cvss_data.get('attackComplexity', '')
        row['privileges_required'] = cvss_data.get('privilegesRequired', '')
        row['user_interaction'] = cvss_data.get('userInteraction', '')
        row['scope'] = cvss_data.get('scope', '')
        row['confidentiality_impact'] = cvss_data.get('confidentialityImpact', '')
        row['integrity_impact'] = cvss_data.get('integrityImpact', '')
        row['availability_impact'] = cvss_data.get('availabilityImpact', '')

        results.append(row)

    return results


def parse_cve_file(filepath):
    """Parse a single CVE JSON file and return structured data."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    if data.get('dataType') != 'CVE_RECORD':
        return None

    metadata = data.get('cveMetadata', {})
    cve_id = metadata.get('cveId', '')
    if not cve_id:
        return None

    containers = data.get('containers', {})
    cna = containers.get('cna', {})
    adp_list = containers.get('adp', [])

    # Extract description
    descriptions = cna.get('descriptions', [])
    description = ''
    for desc in descriptions:
        if desc.get('lang', '').startswith('en'):
            description = strip_html(desc.get('value', ''))
            break
    if not description and descriptions:
        description = strip_html(descriptions[0].get('value', ''))

    # Extract CVSS from CNA
    cvss_rows = extract_cvss(cna.get('metrics', []), cve_id, 'cna')

    # Extract CVSS from ADP (e.g., NVD)
    for adp in adp_list:
        adp_source = adp.get('providerMetadata', {}).get('shortName', 'adp')
        cvss_rows.extend(extract_cvss(adp.get('metrics', []), cve_id, adp_source))

    # Determine severity from best available CVSS
    severity = ''
    if cvss_rows:
        # Prefer NVD/adp scores, then cna
        best = cvss_rows[0]
        for row in cvss_rows:
            if row['source'] != 'cna':
                best = row
                break
        severity = best.get('base_severity', '')

    # CVE main record
    cve_record = {
        'cve_id': cve_id,
        'state': metadata.get('state', ''),
        'assigner_org_id': metadata.get('assignerOrgId', ''),
        'assigner_short_name': metadata.get('assignerShortName', ''),
        'date_reserved': metadata.get('dateReserved', ''),
        'date_published': metadata.get('datePublished', ''),
        'date_updated': metadata.get('dateUpdated', ''),
        'description': description,
        'severity': severity.upper() if severity else '',
        'data_version': data.get('dataVersion', ''),
    }

    # Affected products
    affected_rows = []
    for affected in cna.get('affected', []):
        vendor = affected.get('vendor', '')
        product = affected.get('product', '')
        platforms = affected.get('platforms', [])
        platform_str = ', '.join(platforms) if platforms else ''
        default_status = affected.get('defaultStatus', '')

        versions = affected.get('versions', [])
        if versions:
            for ver in versions:
                # Determine version_end_type
                if 'lessThan' in ver:
                    vet = 'lessThan'
                elif 'lessThanOrEqual' in ver:
                    vet = 'lessThanOrEqual'
                else:
                    vet = ''
                affected_rows.append({
                    'cve_id': cve_id,
                    'vendor': vendor,
                    'product': product,
                    'platform': platform_str,
                    'version_start': ver.get('version', ''),
                    'version_end': ver.get('lessThanOrEqual', ver.get('lessThan', '')),
                    'version_exact': ver.get('version', '') if ver.get('status') == 'affected' and not ver.get('lessThanOrEqual') and not ver.get('lessThan') else '',
                    'default_status': default_status,
                    'status': ver.get('status', ''),
                    'version_end_type': vet,
                })
        else:
            affected_rows.append({
                'cve_id': cve_id,
                'vendor': vendor,
                'product': product,
                'platform': platform_str,
                'version_start': '',
                'version_end': '',
                'version_exact': '',
                'default_status': default_status,
                'status': '',
                'version_end_type': '',
            })

    # Also extract affected from ADP
    for adp in adp_list:
        for affected in adp.get('affected', []):
            vendor = affected.get('vendor', '')
            product = affected.get('product', '')
            platforms = affected.get('platforms', [])
            platform_str = ', '.join(platforms) if platforms else ''
            default_status = affected.get('defaultStatus', '')
            versions = affected.get('versions', [])
            if versions:
                for ver in versions:
                    # Determine version_end_type
                    if 'lessThan' in ver:
                        vet = 'lessThan'
                    elif 'lessThanOrEqual' in ver:
                        vet = 'lessThanOrEqual'
                    else:
                        vet = ''
                    affected_rows.append({
                        'cve_id': cve_id,
                        'vendor': vendor,
                        'product': product,
                        'platform': platform_str,
                        'version_start': ver.get('version', ''),
                        'version_end': ver.get('lessThanOrEqual', ver.get('lessThan', '')),
                        'version_exact': ver.get('version', '') if ver.get('status') == 'affected' and not ver.get('lessThanOrEqual') and not ver.get('lessThan') else '',
                        'default_status': default_status,
                        'status': ver.get('status', ''),
                        'version_end_type': vet,
                    })

    # CWE entries
    cwe_rows = []
    for pt in cna.get('problemTypes', []):
        for desc in pt.get('descriptions', []):
            cwe_rows.append({
                'cve_id': cve_id,
                'cwe_id': desc.get('cweId', ''),
                'description': desc.get('description', ''),
            })

    # References
    ref_rows = []
    for ref in cna.get('references', []):
        ref_rows.append({
            'cve_id': cve_id,
            'url': ref.get('url', ''),
            'tags': ', '.join(ref.get('tags', [])),
        })

    return {
        'cve': cve_record,
        'affected': affected_rows,
        'cvss': cvss_rows,
        'cwe': cwe_rows,
        'references': ref_rows,
    }


def insert_batch(conn, batch):
    """Insert a batch of parsed CVE records into the database."""
    cursor = conn.cursor()

    cve_rows = []
    affected_rows = []
    cvss_rows = []
    cwe_rows = []
    ref_rows = []

    for record in batch:
        if record is None:
            continue
        c = record['cve']
        cve_rows.append((
            c['cve_id'], c['state'], c['assigner_org_id'], c['assigner_short_name'],
            c['date_reserved'], c['date_published'], c['date_updated'],
            c['description'], c['severity'], c['data_version']
        ))

        for a in record['affected']:
            affected_rows.append((
                a['cve_id'], a['vendor'], a['product'], a['platform'],
                a['version_start'], a['version_end'], a['version_exact'],
                a['default_status'], a['status'], a['version_end_type']
            ))

        for s in record['cvss']:
            cvss_rows.append((
                s['cve_id'], s['version'], s['vector_string'], s['base_score'],
                s['base_severity'], s['attack_vector'], s['attack_complexity'],
                s['privileges_required'], s['user_interaction'], s['scope'],
                s['confidentiality_impact'], s['integrity_impact'],
                s['availability_impact'], s['source']
            ))

        for w in record['cwe']:
            cwe_rows.append((w['cve_id'], w['cwe_id'], w['description']))

        for r in record['references']:
            ref_rows.append((r['cve_id'], r['url'], r['tags']))

    cursor.executemany(
        "INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)", cve_rows
    )
    cursor.executemany(
        "INSERT INTO affected_products (cve_id, vendor, product, platform, version_start, version_end, version_exact, default_status, status, version_end_type) VALUES (?,?,?,?,?,?,?,?,?,?)",
        affected_rows
    )
    cursor.executemany(
        "INSERT INTO cvss_scores (cve_id, version, vector_string, base_score, base_severity, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        cvss_rows
    )
    cursor.executemany(
        "INSERT INTO cwe_entries (cve_id, cwe_id, description) VALUES (?,?,?)", cwe_rows
    )
    cursor.executemany(
        "INSERT INTO references_table (cve_id, url, tags) VALUES (?,?,?)", ref_rows
    )

    conn.commit()


def main():
    """Main import function."""
    print(f"Starting CVE import from {CVE_DIR}...")
    print(f"Database: {DB_PATH}")

    # Remove old database
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA cache_size=-200000")  # 200MB cache
    conn.execute("PRAGMA temp_store=MEMORY")

    create_schema(conn)

    # Collect all JSON files
    json_files = []
    for year_dir in sorted(os.listdir(CVE_DIR)):
        year_path = os.path.join(CVE_DIR, year_dir)
        if not os.path.isdir(year_path):
            continue
        for sub_dir in sorted(os.listdir(year_path)):
            sub_path = os.path.join(year_path, sub_dir)
            if not os.path.isdir(sub_path):
                continue
            for fname in os.listdir(sub_path):
                if fname.endswith('.json'):
                    json_files.append(os.path.join(sub_path, fname))

    total = len(json_files)
    print(f"Found {total} CVE JSON files")

    batch_size = 5000
    batch = []
    processed = 0
    errors = 0

    for filepath in json_files:
        record = parse_cve_file(filepath)
        if record:
            batch.append(record)
        else:
            errors += 1

        processed += 1

        if len(batch) >= batch_size:
            insert_batch(conn, batch)
            batch = []
            pct = (processed / total) * 100
            print(f"  Processed {processed}/{total} ({pct:.1f}%) - Errors: {errors}")

    # Insert remaining
    if batch:
        insert_batch(conn, batch)

    print(f"\nImport complete!")
    print(f"  Total files: {total}")
    print(f"  Errors: {errors}")

    # Print stats
    cursor = conn.cursor()
    for table in ['cves', 'affected_products', 'cvss_scores', 'cwe_entries', 'references_table']:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table}: {count} rows")

    # Print severity distribution
    print("\nSeverity distribution:")
    cursor.execute("SELECT severity, COUNT(*) FROM cves WHERE severity != '' GROUP BY severity ORDER BY COUNT(*) DESC")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    # Print top vendors
    print("\nTop 20 vendors by CVE count:")
    cursor.execute("""
        SELECT vendor, COUNT(DISTINCT cve_id) as cnt
        FROM affected_products
        WHERE vendor != '' AND vendor IS NOT NULL
        GROUP BY vendor
        ORDER BY cnt DESC
        LIMIT 20
    """)
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    conn.close()
    print(f"\nDatabase saved to {DB_PATH}")
    print(f"Database size: {os.path.getsize(DB_PATH) / (1024*1024):.1f} MB")


if __name__ == '__main__':
    main()
