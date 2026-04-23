"""Input sanitization helpers for Secure Software Board.

Sanitize functions validate and clean user input for safe use in queries.
"""

import math
import re


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
