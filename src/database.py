"""Database connection and cache management.

Supports both MariaDB (production) and SQLite (development fallback).
Set DB_TYPE=sqlite and SQLITE_PATH for SQLite mode.
"""

import os
import sqlite3
import time
from typing import Any

from flask import g


class SimpleCache:
    """In-memory cache with TTL."""

    def __init__(self):
        self._cache: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        if key not in self._cache:
            return None
        expiry, value = self._cache[key]
        if time.time() > expiry:
            del self._cache[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: int = 3600):
        self._cache[key] = (time.time() + ttl, value)


cache = SimpleCache()


class _SQLiteDictCursor:
    """SQLite cursor wrapper returning dicts and accepting %s placeholders."""

    def __init__(self, conn):
        self._conn = conn
        self._cursor = conn.cursor()

    def execute(self, sql, params=()):
        # Convert MySQL syntax to SQLite
        sql = sql.replace('%s', '?')
        sql = sql.replace('REGEXP', 'GLOB_REGEXP')  # handled by custom function
        # LEFT(col, N) → SUBSTR(col, 1, N)
        import re
        sql = re.sub(r'LEFT\((\w+(?:\.\w+)?),\s*(\d+)\)', r'SUBSTR(\1, 1, \2)', sql)
        # SUBSTRING(col, M, N) → SUBSTR(col, M, N) (already compatible)
        sql = sql.replace('SUBSTRING(', 'SUBSTR(')
        # REGEXP operator: SQLite needs custom function
        sql = sql.replace('GLOB_REGEXP', 'REGEXP')
        self._cursor.execute(sql, params)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        return dict(row) if row else None

    def fetchall(self):
        return [dict(r) for r in self._cursor.fetchall()]

    def close(self):
        self._cursor.close()


class _SQLiteCompat:
    """SQLite connection wrapper compatible with pymysql DictCursor interface."""

    def __init__(self, sqlite_conn):
        self._conn = sqlite_conn

    def cursor(self):
        return _SQLiteDictCursor(self._conn)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def _get_sqlite_db():
    """Get SQLite connection (development fallback)."""
    from flask import current_app
    db_path = current_app.config.get('SQLITE_PATH', 'cve_database.db')
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"SQLite file not found: {db_path}")
    import re
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.create_function('REGEXP', 2, lambda pattern, string: bool(re.search(pattern, string or '')))
    return _SQLiteCompat(conn)


def _get_mysql_db():
    """Get MariaDB connection (production)."""
    import pymysql
    import pymysql.cursors
    from flask import current_app
    cfg = current_app.config
    return pymysql.connect(
        host=cfg['DB_HOST'],
        port=cfg['DB_PORT'],
        user=cfg['DB_USER'],
        password=cfg['DB_PASSWORD'],
        database=cfg['DB_NAME'],
        charset=cfg['DB_CHARSET'],
        cursorclass=pymysql.cursors.DictCursor,
    )


def get_db():
    """Get database connection for the current request."""
    if 'db' not in g:
        from flask import current_app
        db_type = current_app.config.get('DB_TYPE', 'sqlite')
        try:
            if db_type == 'mysql':
                g.db = _get_mysql_db()
            else:
                g.db = _get_sqlite_db()
        except Exception as e:
            raise ConnectionError(f"Cannot connect to database: {e}")
    return g.db


def close_db(exception=None):
    """Close database connection when the request ends."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(app):
    """Register database teardown with Flask app."""
    app.teardown_appcontext(close_db)
