#!/bin/bash
set -e

# Wait for MariaDB to be ready
echo "Waiting for MariaDB..."
for i in $(seq 1 30); do
    python3 -c "
import os, pymysql
try:
    url = os.environ.get('DATABASE_URL', '')
    # Parse DATABASE_URL: mysql+pymysql://user:pass@host:port/db?charset=utf8mb4
    if url:
        from urllib.parse import urlparse
        p = urlparse(url)
        conn = pymysql.connect(host=p.hostname, port=p.port or 3306,
                               user=p.username, password=p.password,
                               database=p.path.lstrip('/').split('?')[0])
    else:
        conn = pymysql.connect(host=os.environ.get('DB_HOST','db'),
                               port=int(os.environ.get('DB_PORT','3306')),
                               user=os.environ.get('DB_USER','cvedb'),
                               password=os.environ.get('DB_PASSWORD','cvedb'),
                               database=os.environ.get('DB_NAME','cve_database'))
    conn.close()
    exit(0)
except Exception as e:
    exit(1)
" 2>/dev/null && break
    echo "  Attempt $i/30 - MariaDB not ready, waiting..."
    sleep 2
done

# Initialize schema if tables don't exist
echo "Checking database schema..."
python3 -c "
import os, pymysql
from urllib.parse import urlparse

url = os.environ.get('DATABASE_URL', '')
if url:
    p = urlparse(url)
    conn = pymysql.connect(host=p.hostname, port=p.port or 3306,
                           user=p.username, password=p.password,
                           database=p.path.lstrip('/').split('?')[0],
                           charset='utf8mb4')
else:
    conn = pymysql.connect(host=os.environ.get('DB_HOST','db'),
                           port=int(os.environ.get('DB_PORT','3306')),
                           user=os.environ.get('DB_USER','cvedb'),
                           password=os.environ.get('DB_PASSWORD','cvedb'),
                           database=os.environ.get('DB_NAME','cve_database'),
                           charset='utf8mb4')
cursor = conn.cursor()
cursor.execute(\"SHOW TABLES LIKE 'cves'\")
if not cursor.fetchone():
    print('Creating schema...')
    with open('scripts/create_mysql_schema.sql', 'r') as f:
        sql = f.read()
    for stmt in sql.split(';'):
        stmt = stmt.strip()
        if stmt:
            try:
                cursor.execute(stmt)
            except Exception as e:
                print(f'  Warning: {e}')
    conn.commit()
    print('Schema created.')
else:
    print('Schema already exists.')
conn.close()
"

echo "Starting gunicorn..."
exec gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 app:app
