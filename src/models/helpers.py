"""Database query functions and input sanitization for Secure Software Board.

Uses pymysql with DictCursor. Helper functions _fetchone/_fetchall/_execute
wrap cursor operations for cleaner code.
"""

import math
import re
from typing import Any


def _fetchone(db, sql, params=()):
    """Execute SQL and return one row as dict, or None."""
    cursor = db.cursor()
    cursor.execute(sql, params)
    row = cursor.fetchone()
    cursor.close()
    return row


def _fetchall(db, sql, params=()):
    """Execute SQL and return all rows as list of dicts."""
    cursor = db.cursor()
    cursor.execute(sql, params)
    rows = list(cursor.fetchall())
    cursor.close()
    return rows


def _execute(db, sql, params=()):
    """Execute SQL without returning results."""
    cursor = db.cursor()
    cursor.execute(sql, params)
    cursor.close()


# ---------------------------------------------------------------------------
# Input sanitization helpers
# ---------------------------------------------------------------------------

def sanitize_page(page_str):
    """Convert page string to int >= 1. Default: 1."""
    try:
        page = int(page_str)
        return max(page, 1)
    except (TypeError, ValueError):
        return 1


_VALID_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}


def sanitize_severity(severity):
    """Only accept CRITICAL/HIGH/MEDIUM/LOW. Otherwise return None."""
    if severity and str(severity).upper() in _VALID_SEVERITIES:
        return str(severity).upper()
    return None


def sanitize_year(year):
    """Only accept years 1999-2099. Otherwise return None."""
    try:
        y = int(year)
        if 1999 <= y <= 2099:
            return y
        return None
    except (TypeError, ValueError):
        return None


def sanitize_search(query):
    """Escape SQL special chars (% and _), convert * to %, max 200 chars.

    If no wildcard present, wraps with % on both sides (contains search).
    Returns empty string for None/empty input.
    """
    if not query:
        return ''
    q = str(query)[:200]
    # Check if user provided wildcard before any transformation
    has_wildcard = '*' in q
    # Escape existing SQL LIKE special characters
    q = q.replace('%', r'\%').replace('_', r'\_')
    # Convert user wildcard * to SQL %
    q = q.replace('*', '%')
    # If no wildcard present, add % at start and end for contains search
    if not has_wildcard:
        q = '%' + q + '%'
    return q


# ---------------------------------------------------------------------------
# Pagination helper
# ---------------------------------------------------------------------------

def get_paginated_result(db, query, count_query, params, page, per_page=50):
    """Execute a paginated query and return a standard result dict.

    Args:
        db: pymysql connection (with DictCursor).
        query: SQL SELECT query (without LIMIT/OFFSET).
        count_query: SQL SELECT COUNT(*) query.
        params: tuple of query parameters shared by both queries.
        page: current page number (1-based, already sanitized).
        per_page: items per page (default 50).

    Returns:
        dict with keys: items, total, page, pages, per_page.
    """
    cursor = db.cursor()

    # Total count
    cursor.execute(count_query, params)
    row = cursor.fetchone()
    total = list(row.values())[0] if row else 0

    # Calculate pages
    pages = max(math.ceil(total / per_page), 1) if per_page > 0 else 1

    # Clamp page to valid range
    page = max(1, min(page, pages))

    offset = (page - 1) * per_page

    # Data query with LIMIT/OFFSET
    cursor.execute(f"{query} LIMIT %s OFFSET %s", (*params, per_page, offset))
    items = list(cursor.fetchall())

    cursor.close()

    return {
        'items': items,
        'total': total,
        'page': page,
        'pages': pages,
        'per_page': per_page,
    }


# ---------------------------------------------------------------------------