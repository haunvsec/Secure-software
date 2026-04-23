#!/bin/bash
# Initialize database schema and import data
# Usage: ./scripts/init_db.sh

set -e

echo "=== Secure Software Board — Database Initialization ==="

# Wait for MariaDB to be ready
echo "Waiting for MariaDB..."
for i in $(seq 1 30); do
    if python3 -c "
import pymysql
pymysql.connect(
    host='${DB_HOST:-localhost}',
    port=int('${DB_PORT:-3306}'),
    user='${DB_USER:-cvedb}',
    password='${DB_PASSWORD:-cvedb}',
    database='${DB_NAME:-cve_database}'
)
print('OK')
" 2>/dev/null; then
        echo "MariaDB is ready!"
        break
    fi
    echo "  Attempt $i/30..."
    sleep 2
done

# Create schema
echo "Creating schema..."
python3 -c "
import pymysql
conn = pymysql.connect(
    host='${DB_HOST:-localhost}',
    port=int('${DB_PORT:-3306}'),
    user='${DB_USER:-cvedb}',
    password='${DB_PASSWORD:-cvedb}',
    database='${DB_NAME:-cve_database}'
)
with open('scripts/create_mysql_schema.sql') as f:
    sql = f.read()
cursor = conn.cursor()
for stmt in sql.split(';'):
    stmt = stmt.strip()
    if stmt and not stmt.startswith('--') and 'CREATE DATABASE' not in stmt and 'USE ' not in stmt:
        try:
            cursor.execute(stmt)
        except Exception as e:
            pass
conn.commit()
conn.close()
print('Schema created.')
"

# Migrate data from SQLite if available
SQLITE_FILE="${SQLITE_PATH:-cve_database.db}"
if [ -f "$SQLITE_FILE" ]; then
    echo "Migrating data from SQLite ($SQLITE_FILE)..."
    python3 scripts/migrate_to_mysql.py
else
    echo "No SQLite file found. Import data manually."
fi

echo "=== Initialization complete ==="
