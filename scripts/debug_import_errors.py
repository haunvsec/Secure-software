#!/usr/bin/env python3
"""Debug: find exact errors during CVE import to MariaDB."""
import os, sys, json, time
from collections import Counter
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from import_cves import parse_cve_file
import pymysql

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = int(os.environ.get('DB_PORT', 3306))
DB_USER = os.environ.get('DB_USER', 'cvedb')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'cvedb')
DB_NAME = os.environ.get('DB_NAME', 'cve_database')
CVE_DIR = os.environ.get('CVE_DIR', 'cvelistV5/cves')

# Collect files
json_files = []
for yd in sorted(os.listdir(CVE_DIR)):
    yp = os.path.join(CVE_DIR, yd)
    if not os.path.isdir(yp): continue
    for sd in sorted(os.listdir(yp)):
        sp = os.path.join(yp, sd)
        if not os.path.isdir(sp): continue
        for fn in os.listdir(sp):
            if fn.endswith('.json'):
                json_files.append(os.path.join(sp, fn))

total = len(json_files)
print(f"Total files: {total}")

# Category 1: parse_cve_file returns None
parse_errors = []
# Category 2: DB insert errors
insert_errors = Counter()
insert_error_samples = {}

conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                        password=DB_PASSWORD, database=DB_NAME, charset='utf8mb4')
cursor = conn.cursor()

# Check field length violations
max_lengths = {
    'vendor': 0, 'product': 0, 'platform': 0,
    'version_start': 0, 'version_end': 0, 'version_exact': 0,
    'vector_string': 0, 'cwe_description': 0,
}
long_fields = []

for i, fp in enumerate(json_files):
    rec = parse_cve_file(fp)
    if not rec:
        # Check why it's None
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                data = json.load(f)
            dtype = data.get('dataType', 'UNKNOWN')
            state = data.get('cveMetadata', {}).get('state', 'UNKNOWN')
            parse_errors.append(f"{os.path.basename(fp)}: dataType={dtype}, state={state}")
        except Exception as e:
            parse_errors.append(f"{os.path.basename(fp)}: {type(e).__name__}: {e}")
        continue

    # Check field lengths
    for a in rec['affected']:
        for field in ['vendor', 'product', 'platform', 'version_start', 'version_end', 'version_exact']:
            val = a.get(field, '')
            if len(val) > max_lengths[field]:
                max_lengths[field] = len(val)
            if len(val) > 255:
                long_fields.append(f"{rec['cve']['cve_id']}.{field}: {len(val)} chars")

    for s in rec['cvss']:
        vs = s.get('vector_string', '')
        if len(vs) > max_lengths['vector_string']:
            max_lengths['vector_string'] = len(vs)
        if len(vs) > 255:
            long_fields.append(f"{rec['cve']['cve_id']}.vector_string: {len(vs)} chars")

    # Try insert to catch actual DB errors
    c = rec['cve']
    try:
        cursor.execute(
            "INSERT INTO cves VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON DUPLICATE KEY UPDATE state=VALUES(state),description=VALUES(description),"
            "severity=VALUES(severity),date_updated=VALUES(date_updated)",
            (c['cve_id'],c['state'],c['assigner_org_id'],c['assigner_short_name'],
             c['date_reserved'],c['date_published'],c['date_updated'],
             c['description'],c['severity'],c['data_version']))
        for a in rec['affected']:
            cursor.execute(
                "INSERT INTO affected_products(cve_id,vendor,product,platform,"
                "version_start,version_end,version_exact,default_status,status,version_end_type)"
                " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (a['cve_id'],a['vendor'],a['product'],a['platform'],
                 a['version_start'],a['version_end'],a['version_exact'],
                 a['default_status'],a['status'],a.get('version_end_type','')))
        for s in rec['cvss']:
            cursor.execute(
                "INSERT INTO cvss_scores(cve_id,version,vector_string,base_score,"
                "base_severity,attack_vector,attack_complexity,privileges_required,"
                "user_interaction,scope,confidentiality_impact,integrity_impact,"
                "availability_impact,source) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (s['cve_id'],s['version'],s['vector_string'],s['base_score'],
                 s['base_severity'],s['attack_vector'],s['attack_complexity'],
                 s['privileges_required'],s['user_interaction'],s['scope'],
                 s['confidentiality_impact'],s['integrity_impact'],
                 s['availability_impact'],s['source']))
        for w in rec['cwe']:
            cursor.execute("INSERT INTO cwe_entries(cve_id,cwe_id,description) VALUES(%s,%s,%s)",
                (w['cve_id'],w['cwe_id'],w['description']))
        for r in rec['references']:
            cursor.execute("INSERT INTO references_table(cve_id,url,tags) VALUES(%s,%s,%s)",
                (r['cve_id'],r['url'],r['tags']))
    except Exception as e:
        err_type = type(e).__name__
        err_msg = str(e)[:200]
        key = f"{err_type}: {err_msg}"
        insert_errors[key] += 1
        if key not in insert_error_samples:
            insert_error_samples[key] = c['cve_id']

    if (i+1) % 50000 == 0:
        conn.rollback()  # Don't actually insert, just testing
        print(f"  Checked {i+1}/{total}...")

conn.rollback()
conn.close()

print(f"\n=== Parse errors (parse_cve_file returned None): {len(parse_errors)} ===")
# Group by reason
reasons = Counter()
for e in parse_errors:
    parts = e.split(': ', 1)
    if len(parts) > 1:
        reasons[parts[1]] += 1
for reason, count in reasons.most_common(20):
    print(f"  [{count}] {reason}")

print(f"\n=== Field max lengths ===")
for field, length in sorted(max_lengths.items()):
    flag = " *** EXCEEDS 255 ***" if length > 255 else ""
    print(f"  {field}: {length}{flag}")

print(f"\n=== Fields exceeding VARCHAR(255): {len(long_fields)} ===")
for lf in long_fields[:20]:
    print(f"  {lf}")
if len(long_fields) > 20:
    print(f"  ... and {len(long_fields) - 20} more")

print(f"\n=== DB insert errors: {sum(insert_errors.values())} ===")
for err, count in insert_errors.most_common(20):
    sample = insert_error_samples.get(err, '?')
    print(f"  [{count}] {err}")
    print(f"         Sample CVE: {sample}")
