#!/usr/bin/env python3
"""Import CVE data from cvelistV5 JSON files directly into MariaDB."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from import_cves import parse_cve_file
import pymysql

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = int(os.environ.get('DB_PORT', 3306))
DB_USER = os.environ.get('DB_USER', 'cvedb')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'cvedb')
DB_NAME = os.environ.get('DB_NAME', 'cve_database')
CVE_DIR = os.environ.get('CVE_DIR', 'cvelistV5/cves')

conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                        password=DB_PASSWORD, database=DB_NAME, charset='utf8mb4')
cursor = conn.cursor()
cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

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
print(f"Found {total} files. Importing into MariaDB {DB_HOST}:{DB_PORT}/{DB_NAME}...")
processed = errors = 0
start = time.time()

for fp in json_files:
    rec = parse_cve_file(fp)
    if not rec: errors += 1; processed += 1; continue
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
        errors += 1
    processed += 1
    if processed % 5000 == 0:
        conn.commit()
        pct = processed/total*100
        print(f"  {processed:,}/{total:,} ({pct:.1f}%) - {time.time()-start:.0f}s - Errors: {errors}")

conn.commit()
cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
conn.commit()

for t in ['cves','affected_products','cvss_scores','cwe_entries','references_table']:
    cursor.execute(f"SELECT COUNT(*) FROM {t}")
    print(f"  {t}: {cursor.fetchone()[0]:,}")
print(f"\nDone in {time.time()-start:.0f}s. Errors: {errors}")
conn.close()
