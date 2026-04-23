"""Database connection and cache management using SQLAlchemy.

MariaDB only — no SQLite fallback. Uses SQLAlchemy engine with connection
pooling and scoped sessions for Flask request lifecycle.
"""

import os
import time
from typing import Any

from flask import g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from models.orm import Base


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

    def clear(self):
        self._cache.clear()


cache = SimpleCache()

# Module-level engine and session factory (initialized by init_db)
engine = None
SessionFactory = None
ScopedSession = None


def _build_database_url(app_config) -> str:
    """Build DATABASE_URL from config or environment."""
    url = app_config.get('DATABASE_URL') or os.environ.get('DATABASE_URL')
    if url:
        return url
    host = app_config.get('DB_HOST', 'localhost')
    port = app_config.get('DB_PORT', 3306)
    user = app_config.get('DB_USER', 'cvedb')
    password = app_config.get('DB_PASSWORD', 'cvedb')
    database = app_config.get('DB_NAME', 'cve_database')
    charset = app_config.get('DB_CHARSET', 'utf8mb4')
    return f'mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset={charset}'


def init_db(app):
    """Initialize SQLAlchemy engine and register teardown with Flask app."""
    global engine, SessionFactory, ScopedSession

    database_url = _build_database_url(app.config)
    pool_size = app.config.get('POOL_SIZE', 10)
    max_overflow = app.config.get('POOL_MAX_OVERFLOW', 20)

    engine = create_engine(
        database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle=3600,
        pool_pre_ping=True,
    )

    SessionFactory = sessionmaker(bind=engine)
    ScopedSession = scoped_session(SessionFactory)

    app.teardown_appcontext(close_db)


def get_session():
    """Get SQLAlchemy session for the current request."""
    if 'db_session' not in g:
        if ScopedSession is None:
            raise ConnectionError("Database not initialized. Call init_db() first.")
        g.db_session = ScopedSession()
    return g.db_session


def close_db(exception=None):
    """Close session when the request ends."""
    session = g.pop('db_session', None)
    if session is not None:
        session.close()
    if ScopedSession is not None:
        ScopedSession.remove()
