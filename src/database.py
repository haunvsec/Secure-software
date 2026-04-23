"""Database connection and cache management."""

import time
from typing import Any

import pymysql
import pymysql.cursors
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


def get_db():
    """Get MariaDB connection for the current request."""
    if 'db' not in g:
        from flask import current_app
        cfg = current_app.config
        try:
            g.db = pymysql.connect(
                host=cfg['DB_HOST'],
                port=cfg['DB_PORT'],
                user=cfg['DB_USER'],
                password=cfg['DB_PASSWORD'],
                database=cfg['DB_NAME'],
                charset=cfg['DB_CHARSET'],
                cursorclass=pymysql.cursors.DictCursor,
            )
        except pymysql.err.OperationalError as e:
            raise ConnectionError(f"Cannot connect to MariaDB: {e}")
    return g.db


def close_db(exception=None):
    """Close database connection when the request ends."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(app):
    """Register database teardown with Flask app."""
    app.teardown_appcontext(close_db)
