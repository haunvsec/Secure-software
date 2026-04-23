"""Application configuration."""

import os


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')

    # SQLAlchemy DATABASE_URL (MariaDB only)
    # Format: mysql+pymysql://user:password@host:port/database?charset=utf8mb4
    DATABASE_URL = os.environ.get('DATABASE_URL')

    # Individual DB settings (used if DATABASE_URL not set)
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 3306))
    DB_USER = os.environ.get('DB_USER', 'cvedb')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'cvedb')
    DB_NAME = os.environ.get('DB_NAME', 'cve_database')
    DB_CHARSET = 'utf8mb4'

    # Connection pool settings
    POOL_SIZE = int(os.environ.get('POOL_SIZE', 10))
    POOL_MAX_OVERFLOW = int(os.environ.get('POOL_MAX_OVERFLOW', 20))
