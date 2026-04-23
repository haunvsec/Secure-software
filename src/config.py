"""Application configuration."""

import os


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 3306))
    DB_USER = os.environ.get('DB_USER', 'cvedb')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'cvedb')
    DB_NAME = os.environ.get('DB_NAME', 'cve_database')
    DB_CHARSET = 'utf8mb4'
