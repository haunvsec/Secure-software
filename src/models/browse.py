"""Model functions for browse tables."""

from typing import Any

from models.helpers import (
    _fetchone, _fetchall, _execute,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    get_paginated_result, _VALID_SEVERITIES,
)

# Browse by date model functions
# ---------------------------------------------------------------------------

def get_years_with_counts(db) -> list[dict]:
    """Return list of years with CVE counts, sorted descending. Cached 1 hour."""
    from database import cache

    cached = cache.get('years_counts')
    if cached is not None:
        return cached

    rows = _fetchall(db, 
        "SELECT LEFT(date_published, 4) AS year, COUNT(*) AS count "
        "FROM cves WHERE state = 'PUBLISHED' AND date_published IS NOT NULL "
        "GROUP BY year ORDER BY year DESC"
    )
    result = list(rows) if rows else []
    cache.set('years_counts', result, 3600)
    return result


def get_months_for_year(db, year: int) -> list[dict]:
    """Return 12 months with CVE counts for a given year."""
    rows = _fetchall(db, 
        "SELECT SUBSTRING(date_published, 6, 2) AS month, COUNT(*) AS count "
        "FROM cves WHERE state = 'PUBLISHED' AND date_published LIKE %s "
        "GROUP BY month ORDER BY month",
        (f"{year}%",),
    )
    month_map = {r['month']: r['count'] for r in rows}
    result = []
    for m in range(1, 13):
        ms = f"{m:02d}"
        result.append({'month': ms, 'month_name': _MONTH_NAMES[m - 1], 'count': month_map.get(ms, 0)})
    return result


_MONTH_NAMES = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
]


def get_cves_by_month(db, year: int, month: str, page: int) -> dict:
    """Return paginated CVEs for a specific year/month."""
    prefix = f"{year}-{month}%"
    query = (
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE c.state = 'PUBLISHED' AND c.date_published LIKE %s "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED' AND date_published LIKE %s"
    )
    return get_paginated_result(db, query, count_query, (prefix,), page)


# ---------------------------------------------------------------------------
# Browse by CWE type model functions
# ---------------------------------------------------------------------------

def get_cwe_types(db, page: int) -> dict:
    """Return paginated list of CWE types with CVE counts, sorted descending. Cached 1 hour."""
    from database import cache

    cache_key = f'cwe_types_page_{page}'
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    query = (
        "SELECT cwe_id, description, COUNT(DISTINCT cve_id) AS cve_count "
        "FROM cwe_entries WHERE cwe_id IS NOT NULL AND cwe_id != '' "
        "GROUP BY cwe_id "
        "ORDER BY cve_count DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM ("
        "  SELECT cwe_id FROM cwe_entries "
        "  WHERE cwe_id IS NOT NULL AND cwe_id != '' "
        "  GROUP BY cwe_id"
        ") AS t"
    )
    result = get_paginated_result(db, query, count_query, (), page)
    cache.set(cache_key, result, 3600)
    return result


def get_cves_by_cwe(db, cwe_id: str, page: int) -> dict:
    """Return paginated CVEs for a specific CWE type."""
    query = (
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "INNER JOIN cwe_entries ce ON c.cve_id = ce.cve_id "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE ce.cwe_id = %s AND c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(DISTINCT c.cve_id) FROM cves c "
        "INNER JOIN cwe_entries ce ON c.cve_id = ce.cve_id "
        "WHERE ce.cwe_id = %s AND c.state = 'PUBLISHED'"
    )
    return get_paginated_result(db, query, count_query, (cwe_id,), page)


# ---------------------------------------------------------------------------
# Browse by severity model functions
# ---------------------------------------------------------------------------

def get_severity_summary(db) -> list[dict]:
    """Return 4 severity groups with counts and percentages. Cached 1 hour."""
    from database import cache

    cached = cache.get('severity_summary')
    if cached is not None:
        return cached

    row = _fetchone(db, 
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED'"
    )
    total = list(row.values())[0] if row else 0

    rows = _fetchall(db, 
        "SELECT severity, COUNT(*) AS count FROM cves "
        "WHERE state = 'PUBLISHED' AND severity IN ('CRITICAL','HIGH','MEDIUM','LOW') "
        "GROUP BY severity"
    )
    sev_map = {r['severity']: r['count'] for r in rows}

    result = []
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = sev_map.get(sev, 0)
        pct = round(count / total * 100, 1) if total > 0 else 0
        result.append({'severity': sev, 'count': count, 'percentage': pct})

    cache.set('severity_summary', result, 3600)
    return result


def get_cves_by_severity(db, severity: str, page: int) -> dict:
    """Return paginated CVEs for a specific severity level."""
    query = (
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE c.state = 'PUBLISHED' AND c.severity = %s "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED' AND severity = %s"
    )
    return get_paginated_result(db, query, count_query, (severity,), page)


# ---------------------------------------------------------------------------
# Browse by assigner model functions
# ---------------------------------------------------------------------------

def get_assigners(db, page: int) -> dict:
    """Return paginated list of assigners with CVE counts, sorted descending."""
    query = (
        "SELECT assigner_short_name, COUNT(*) AS cve_count "
        "FROM cves WHERE state = 'PUBLISHED' AND assigner_short_name IS NOT NULL "
        "AND assigner_short_name != '' "
        "GROUP BY assigner_short_name "
        "ORDER BY cve_count DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM ("
        "  SELECT assigner_short_name FROM cves "
        "  WHERE state = 'PUBLISHED' AND assigner_short_name IS NOT NULL "
        "  AND assigner_short_name != '' "
        "  GROUP BY assigner_short_name"
        ") AS t"
    )
    return get_paginated_result(db, query, count_query, (), page)


def get_cves_by_assigner(db, assigner: str, page: int) -> dict:
    """Return paginated CVEs for a specific assigner."""
    query = (
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE c.state = 'PUBLISHED' AND c.assigner_short_name = %s "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM cves "
        "WHERE state = 'PUBLISHED' AND assigner_short_name = %s"
    )
    return get_paginated_result(db, query, count_query, (assigner,), page)


# ---------------------------------------------------------------------------