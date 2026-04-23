#!/usr/bin/env python3
"""Migrate data from SQLite (cve_database.db) to MariaDB.

Reads all tables from SQLite and batch-inserts into MariaDB.
Requires: pymysql, environment variables for DB connection.
"""

import os
import sqlite3
import pymysql

SQLITE_PATH = os.environ.get('SQLITE_PATH', 'cve_database.db')
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = int(os.environ.get('DB_PORT', 3306))
DB_USER = os.environ.get('DB_USER', 'cvedb')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'cvedb')
DB_NAME = os.environ.get('DB_NAME', 'cve_database')
BATCH_SIZE = 5000

TABLES = [
    ('cves', 10),
    ('affected_products', 11),
    ('cvss_scores', 15),
    ('cwe_entries', 4),
    ('references_table', 4),
    ('security_advisories', 13),
    ('advisory_affected_products', 8),
    ('advisory_cves', 3),
    ('advisory_references', 3),
]


def get_mysql_conn():
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER,
        password=DB_PASSWORD, database=DB_NAME,
        charset='utf8mb4', autocommit=False,
    )


def migrate_table(sqlite_conn, mysql_conn, table_name, col_count):
    """Migrate a single table from SQLite to MariaDB."""
    cursor = sqlite_conn.execute(f"SELECT * FROM {table_name}")
    cols = [desc[0] for desc in cursor.description]
    actual_count = len(cols)

    placeholders = ', '.join(['%s'] * actual_count)
    col_names = ', '.join(f'`{c}`' for c in cols)
    insert_sql = f"INSERT INTO `{table_name}` ({col_names}) VALUES ({placeholders})"

    # Skip auto-increment id column for tables that have it
    skip_id = table_name != 'cves' and table_name != 'security_advisories'
    if skip_id and cols[0] == 'id':
        cols = cols[1:]
        col_names = ', '.join(f'`{c}`' for c in cols)
        placeholders = ', '.join(['%s'] * len(cols))
        insert_sql = f"INSERT INTO `{table_name}` ({col_names}) VALUES ({placeholders})"

    my_cursor = mysql_conn.cursor()
    batch = []
    total = 0

    for row in cursor:
        row_data = tuple(row)
        if skip_id:
            row_data = row_data[1:]  # skip id column
        batch.append(row_data)
        if len(batch) >= BATCH_SIZE:
            my_cursor.executemany(insert_sql, batch)
            mysql_conn.commit()
            total += len(batch)
            print(f"  {table_name}: {total:,} rows migrated...")
            batch = []

    if batch:
        my_cursor.executemany(insert_sql, batch)
        mysql_conn.commit()
        total += len(batch)

    print(f"  {table_name}: {total:,} rows total")
    return total


def main():
    print(f"Migrating from {SQLITE_PATH} to MariaDB {DB_HOST}:{DB_PORT}/{DB_NAME}")

    if not os.path.isfile(SQLITE_PATH):
        print(f"ERROR: SQLite file not found: {SQLITE_PATH}")
        return

    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    mysql_conn = get_mysql_conn()

    # Create schema first
    print("Creating schema...")
    schema_file = os.path.join(os.path.dirname(__file__), 'create_mysql_schema.sql')
    if os.path.isfile(schema_file):
        with open(schema_file) as f:
            sql = f.read()
        my_cursor = mysql_conn.cursor()
        # Execute each statement separately
        for stmt in sql.split(';'):
            stmt = stmt.strip()
            if stmt and not stmt.startswith('--') and not stmt.startswith('CREATE DATABASE') and not stmt.startswith('USE '):
                try:
                    my_cursor.execute(stmt)
                except pymysql.err.OperationalError as e:
                    if 'already exists' not in str(e):
                        print(f"  Warning: {e}")
        mysql_conn.commit()
    print("Schema created.")

    # Disable foreign key checks for faster import
    my_cursor = mysql_conn.cursor()
    my_cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

    # Truncate existing data
    print("Clearing existing data...")
    for table_name, _ in reversed(TABLES):
        try:
            my_cursor.execute(f"TRUNCATE TABLE `{table_name}`")
        except Exception:
            pass
    mysql_conn.commit()

    # Migrate each table
    print("\nMigrating tables...")
    for table_name, col_count in TABLES:
        try:
            sqlite_conn.execute(f"SELECT 1 FROM {table_name} LIMIT 1")
        except sqlite3.OperationalError:
            print(f"  {table_name}: skipped (not in SQLite)")
            continue
        migrate_table(sqlite_conn, mysql_conn, table_name, col_count)

    # Re-enable foreign key checks
    my_cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
    mysql_conn.commit()

    print("\nMigration complete!")
    # Print row counts
    for table_name, _ in TABLES:
        try:
            my_cursor.execute(f"SELECT COUNT(*) FROM `{table_name}`")
            count = my_cursor.fetchone()[0]
            print(f"  {table_name}: {count:,} rows")
        except Exception:
            pass

    sqlite_conn.close()
    mysql_conn.close()


if __name__ == '__main__':
    main()
