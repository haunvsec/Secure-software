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
# Homepage model functions
# ---------------------------------------------------------------------------

def get_stats(db) -> dict[str, int]:
    """Return aggregate statistics for the homepage.

    Uses in-memory cache with 1-hour TTL to avoid repeated heavy queries.
    Returns dict with keys: total_cves, critical, high, medium, low,
    vendors, products.
    """
    from app import cache

    cached = cache.get('stats')
    if cached is not None:
        return cached

    # Total published CVEs
    row = _fetchone(db, 
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED'"
    )
    total_cves = list(row.values())[0] if row else 0

    # Severity counts
    severity_rows = _fetchall(db, 
        "SELECT severity, COUNT(*) AS cnt FROM cves WHERE state = 'PUBLISHED' GROUP BY severity"
    )
    severity_map: dict[str, int] = {}
    for r in severity_rows:
        sev = str(r.get('severity', '')).upper() if r.get('severity') else ''
        severity_map[sev] = r.get('cnt', 0)

    # Distinct vendors (excluding empty / n/a)
    row = _fetchone(db, 
        "SELECT COUNT(DISTINCT vendor) FROM affected_products "
        "WHERE vendor != '' AND vendor != 'n/a'"
    )
    vendors = list(row.values())[0] if row else 0

    # Distinct products (vendor/product combos, excluding empty / n/a)
    row = _fetchone(db, 
        "SELECT COUNT(DISTINCT vendor || '/' || product) FROM affected_products "
        "WHERE product != '' AND product != 'n/a'"
    )
    products = list(row.values())[0] if row else 0

    result: dict[str, int] = {
        'total_cves': total_cves,
        'critical': severity_map.get('CRITICAL', 0),
        'high': severity_map.get('HIGH', 0),
        'medium': severity_map.get('MEDIUM', 0),
        'low': severity_map.get('LOW', 0),
        'vendors': vendors,
        'products': products,
    }

    cache.set('stats', result, 3600)
    return result


def get_cves(db, page: int, year=None, severity=None) -> dict:
    """Return a paginated list of published CVEs with optional filters.

    Args:
        db: pymysql connection.
        page: current page number (1-based).
        year: optional year filter (int or str). Filters date_published LIKE 'year%'.
        severity: optional severity filter (CRITICAL/HIGH/MEDIUM/LOW).

    Returns:
        Standard paginated dict {items, total, page, pages, per_page}.
        Each item contains: cve_id, description, severity, date_published,
        base_score, vendor, product.
    """
    conditions = ["c.state = 'PUBLISHED'"]
    params: list[Any] = []

    if year:
        conditions.append("c.date_published LIKE %s")
        params.append(f"{year}%")
    if severity:
        conditions.append("c.severity = %s")
        params.append(severity)

    where = " AND ".join(conditions)

    query = f"""
        SELECT c.cve_id, c.description, c.severity, c.date_published,
               cs.base_score, ap.vendor, ap.product
        FROM cves c
        LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id
        LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
        WHERE {where}
        GROUP BY c.cve_id
        ORDER BY c.date_published DESC
    """
    count_query = f"SELECT COUNT(*) FROM cves c WHERE {where}"

    return get_paginated_result(db, query, count_query, tuple(params), page)


def get_latest_cves(db, limit: int = 10) -> list[dict[str, Any]]:
    """Return the *limit* most recently published CVEs.

    Each dict contains: cve_id, description, severity, date_published,
    base_score (from cvss_scores, may be None).
    """
    rows = _fetchall(db, 
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC "
        "LIMIT %s",
        (limit,),
    )

    return list(rows) if rows else []


# ---------------------------------------------------------------------------
# CVE detail model functions
# ---------------------------------------------------------------------------

def get_cve_detail(db, cve_id: str) -> dict | None:
    """Return full CVE information or None if not found.

    Returns dict with keys: cve_id, state, description, date_reserved,
    date_published, date_updated, assigner_short_name, assigner_org_id,
    severity, data_version.
    """
    row = _fetchone(db, 
        "SELECT cve_id, state, description, date_reserved, date_published, "
        "       date_updated, assigner_short_name, assigner_org_id, severity, "
        "       data_version "
        "FROM cves WHERE cve_id = %s",
        (cve_id,),
    )
    if row is None:
        return None
    return dict(row)


def get_cve_cvss(db, cve_id: str) -> list[dict]:
    """Return all CVSS scores for a CVE with source labels.

    Each dict contains: version, vector_string, base_score, base_severity,
    attack_vector, attack_complexity, privileges_required, user_interaction,
    scope, confidentiality_impact, integrity_impact, availability_impact,
    source.
    """
    rows = _fetchall(db, 
        "SELECT version, vector_string, base_score, base_severity, "
        "       attack_vector, attack_complexity, privileges_required, "
        "       user_interaction, scope, confidentiality_impact, "
        "       integrity_impact, availability_impact, source "
        "FROM cvss_scores WHERE cve_id = %s "
        "ORDER BY base_score DESC",
        (cve_id,),
    )
    return list(rows) if rows else []


def get_cve_affected(db, cve_id: str) -> list[dict]:
    """Return affected products for a CVE.

    Each dict contains: vendor, product, platform, version_start,
    version_end, version_exact, default_status, status.
    """
    rows = _fetchall(db, 
        "SELECT vendor, product, platform, version_start, version_end, "
        "       version_exact, default_status, status "
        "FROM affected_products WHERE cve_id = %s "
        "ORDER BY vendor, product",
        (cve_id,),
    )
    return list(rows) if rows else []


def get_cve_cwes(db, cve_id: str) -> list[dict]:
    """Return CWE entries for a CVE.

    Each dict contains: cwe_id, description.
    """
    rows = _fetchall(db, 
        "SELECT cwe_id, description "
        "FROM cwe_entries WHERE cve_id = %s "
        "ORDER BY cwe_id",
        (cve_id,),
    )
    return list(rows) if rows else []


def get_cve_references(db, cve_id: str) -> list[dict]:
    """Return reference URLs for a CVE.

    Each dict contains: url, tags.
    """
    rows = _fetchall(db, 
        "SELECT url, tags "
        "FROM references_table WHERE cve_id = %s "
        "ORDER BY url",
        (cve_id,),
    )
    return list(rows) if rows else []


# ---------------------------------------------------------------------------
# Browse by date model functions
# ---------------------------------------------------------------------------

def get_years_with_counts(db) -> list[dict]:
    """Return list of years with CVE counts, sorted descending. Cached 1 hour."""
    from app import cache

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
    from app import cache

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
        ")"
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
    from app import cache

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
        ")"
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
# Vendor & Product model functions
# ---------------------------------------------------------------------------

def get_vendors(db, letter: str | None = None, search: str | None = None, page: int = 1) -> dict:
    """Return paginated vendors filtered by letter or search, excluding n/a and empty."""
    conditions = ["ap.vendor != '' AND ap.vendor != 'n/a' AND ap.vendor IS NOT NULL"]
    params: list = []

    if search:
        search_pattern = sanitize_search(search)
        conditions.append("ap.vendor LIKE %s ESCAPE '\\'")
        params.append(search_pattern)
    elif letter:
        if letter.isdigit():
            conditions.append("ap.vendor REGEXP '^[0-9]'")
        else:
            conditions.append("LOWER(ap.vendor) LIKE %s ESCAPE '\\'")
            params.append(f"{letter.lower()}%")
    else:
        # Default to 'A'
        conditions.append("LOWER(ap.vendor) LIKE 'a%'")

    where = " AND ".join(conditions)

    query = (
        f"SELECT ap.vendor, COUNT(DISTINCT ap.product) AS product_count, "
        f"COUNT(DISTINCT ap.cve_id) AS vuln_count "
        f"FROM affected_products ap "
        f"WHERE {where} "
        f"GROUP BY ap.vendor "
        f"ORDER BY ap.vendor"
    )
    count_query = (
        f"SELECT COUNT(*) FROM ("
        f"  SELECT ap.vendor FROM affected_products ap "
        f"  WHERE {where} GROUP BY ap.vendor"
        f")"
    )
    return get_paginated_result(db, query, count_query, tuple(params), page)


def get_vendor_detail(db, vendor: str) -> dict | None:
    """Return vendor name, total CVEs, severity distribution. None if not found."""
    row = _fetchone(db, 
        "SELECT COUNT(DISTINCT cve_id) AS total_cves "
        "FROM affected_products WHERE vendor = %s",
        (vendor,),
    )
    if row is None or row['total_cves'] == 0:
        return None

    sev_rows = _fetchall(db, 
        "SELECT c.severity, COUNT(DISTINCT c.cve_id) AS count "
        "FROM cves c INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = %s AND c.state = 'PUBLISHED' "
        "GROUP BY c.severity",
        (vendor,),
    )
    severity = {r['severity']: r['count'] for r in sev_rows if r['severity']}

    return {
        'vendor': vendor,
        'total_cves': row['total_cves'],
        'critical': severity.get('CRITICAL', 0),
        'high': severity.get('HIGH', 0),
        'medium': severity.get('MEDIUM', 0),
        'low': severity.get('LOW', 0),
    }


def get_vendor_products(db, vendor: str, page: int) -> dict:
    """Return paginated products for a vendor with CVE counts."""
    query = (
        "SELECT product, COUNT(DISTINCT cve_id) AS cve_count "
        "FROM affected_products WHERE vendor = %s "
        "AND product != '' AND product != 'n/a' AND product IS NOT NULL "
        "GROUP BY product ORDER BY cve_count DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM ("
        "  SELECT product FROM affected_products WHERE vendor = %s "
        "  AND product != '' AND product != 'n/a' AND product IS NOT NULL "
        "  GROUP BY product"
        ")"
    )
    return get_paginated_result(db, query, count_query, (vendor,), page)


def get_products(db, search: str | None = None, page: int = 1) -> dict:
    """Return paginated products (most popular by CVE count), with optional search."""
    conditions = ["ap.product != '' AND ap.product != 'n/a' AND ap.product IS NOT NULL"]
    params: list = []

    if search:
        search_pattern = sanitize_search(search)
        conditions.append("ap.product LIKE %s ESCAPE '\\'")
        params.append(search_pattern)

    where = " AND ".join(conditions)

    query = (
        f"SELECT ap.product, ap.vendor, COUNT(DISTINCT ap.cve_id) AS cve_count "
        f"FROM affected_products ap "
        f"WHERE {where} "
        f"GROUP BY ap.vendor, ap.product "
        f"ORDER BY cve_count DESC"
    )
    count_query = (
        f"SELECT COUNT(*) FROM ("
        f"  SELECT ap.product FROM affected_products ap "
        f"  WHERE {where} GROUP BY ap.vendor, ap.product"
        f")"
    )
    return get_paginated_result(db, query, count_query, tuple(params), page)


def get_product_detail(db, vendor: str, product: str) -> dict | None:
    """Return product name, vendor, total CVEs, severity distribution. None if not found."""
    row = _fetchone(db, 
        "SELECT COUNT(DISTINCT cve_id) AS total_cves "
        "FROM affected_products WHERE vendor = %s AND product = %s",
        (vendor, product),
    )
    if row is None or row['total_cves'] == 0:
        return None

    sev_rows = _fetchall(db, 
        "SELECT c.severity, COUNT(DISTINCT c.cve_id) AS count "
        "FROM cves c INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = %s AND ap.product = %s AND c.state = 'PUBLISHED' "
        "GROUP BY c.severity",
        (vendor, product),
    )
    severity = {r['severity']: r['count'] for r in sev_rows if r['severity']}

    return {
        'vendor': vendor,
        'product': product,
        'total_cves': row['total_cves'],
        'critical': severity.get('CRITICAL', 0),
        'high': severity.get('HIGH', 0),
        'medium': severity.get('MEDIUM', 0),
        'low': severity.get('LOW', 0),
    }


def get_product_cves(db, vendor: str, product: str, page: int) -> dict:
    """Return paginated CVEs affecting a specific product."""
    query = (
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE ap.vendor = %s AND ap.product = %s AND c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(DISTINCT c.cve_id) FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = %s AND ap.product = %s AND c.state = 'PUBLISHED'"
    )
    return get_paginated_result(db, query, count_query, (vendor, product), page)


# ---------------------------------------------------------------------------
# Search model functions
# ---------------------------------------------------------------------------

_CVE_ID_RE = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)


def search_cves(db, cve_id: str | None = None, keyword: str | None = None,
                vendor: str | None = None, product: str | None = None,
                page: int = 1) -> dict | str:
    """Search CVEs by multiple criteria. Returns paginated dict or CVE ID string for redirect."""
    # Exact CVE ID match → redirect
    if cve_id and _CVE_ID_RE.match(cve_id.strip()):
        cve_id_clean = cve_id.strip().upper()
        row = _fetchone(db, "SELECT cve_id FROM cves WHERE cve_id = %s", (cve_id_clean,))
        if row:
            return row['cve_id']

    conditions = ["c.state = 'PUBLISHED'"]
    params: list = []
    need_ap_join = False

    if keyword:
        kw = sanitize_search(keyword)
        conditions.append("c.description LIKE %s ESCAPE '\\'")
        params.append(kw)

    if vendor:
        v = sanitize_search(vendor)
        conditions.append("ap.vendor LIKE %s ESCAPE '\\'")
        params.append(v)
        need_ap_join = True

    if product:
        p = sanitize_search(product)
        conditions.append("ap.product LIKE %s ESCAPE '\\'")
        params.append(p)
        need_ap_join = True

    where = " AND ".join(conditions)
    join_ap = "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id" if need_ap_join else ""

    query = (
        f"SELECT c.cve_id, c.description, c.severity, c.date_published, "
        f"       cs.base_score "
        f"FROM cves c "
        f"{join_ap} "
        f"LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        f"WHERE {where} "
        f"GROUP BY c.cve_id "
        f"ORDER BY c.date_published DESC"
    )
    count_query = (
        f"SELECT COUNT(*) FROM ("
        f"  SELECT c.cve_id FROM cves c {join_ap} "
        f"  WHERE {where} GROUP BY c.cve_id"
        f")"
    )
    return get_paginated_result(db, query, count_query, tuple(params), page)


def get_product_version_ranges(db, vendor: str, product: str) -> list[dict]:
    """Return version ranges for a product (for safe version computation)."""
    rows = _fetchall(db, 
        "SELECT version_end, version_end_type, cve_id "
        "FROM affected_products "
        "WHERE vendor = %s AND product = %s AND version_end != '' AND version_end IS NOT NULL",
        (vendor, product),
    )
    return list(rows) if rows else []


# ---------------------------------------------------------------------------
# Product version model functions
# ---------------------------------------------------------------------------

def get_product_versions(db, vendor: str, product: str, page: int = 1, per_page: int = 50) -> dict:
    """Return paginated version ranges for a product.

    Returns dict with:
      - version_ranges: list of {version_start, version_end, version_end_type, cve_count}
        — affected ranges, sorted by version_end desc (semver)
      - total, page, pages, per_page — pagination info
    """
    import math
    from safe_version import parse_version

    range_rows = _fetchall(db, 
        "SELECT version_start, version_end, version_end_type, "
        "       COUNT(DISTINCT cve_id) AS cve_count "
        "FROM affected_products "
        "WHERE vendor = %s AND product = %s "
        "AND version_end != '' AND version_end IS NOT NULL "
        "AND (version_exact = '' OR version_exact IS NULL) "
        "GROUP BY version_start, version_end, version_end_type",
        (vendor, product),
    )
    all_ranges = [dict(r) for r in range_rows]

    def _range_sort_key(item):
        parsed = parse_version(item['version_end'])
        if parsed is None:
            return (0,)
        return (1,) + parsed

    all_ranges.sort(key=_range_sort_key, reverse=True)

    total = len(all_ranges)
    pages = max(math.ceil(total / per_page), 1)
    page = max(1, min(page, pages))
    offset = (page - 1) * per_page
    page_ranges = all_ranges[offset:offset + per_page]

    return {
        'version_ranges': page_ranges,
        'total': total,
        'page': page,
        'pages': pages,
        'per_page': per_page,
    }


def get_version_detail(db, vendor: str, product: str, version: str) -> dict | None:
    """Return version info with total CVEs and severity distribution. None if not found."""
    # Check version exists
    row = _fetchone(db, 
        "SELECT COUNT(DISTINCT ap.cve_id) AS total_cves "
        "FROM affected_products ap "
        "WHERE ap.vendor = %s AND ap.product = %s "
        "AND (ap.version_exact = %s OR (ap.version_start = %s AND (ap.version_exact = '' OR ap.version_exact IS NULL)))",
        (vendor, product, version, version),
    )
    if row is None or row['total_cves'] == 0:
        return None

    sev_rows = _fetchall(db, 
        "SELECT c.severity, COUNT(DISTINCT c.cve_id) AS count "
        "FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = %s AND ap.product = %s "
        "AND (ap.version_exact = %s OR (ap.version_start = %s AND (ap.version_exact = '' OR ap.version_exact IS NULL))) "
        "AND c.state = 'PUBLISHED' "
        "GROUP BY c.severity",
        (vendor, product, version, version),
    )
    severity = {r['severity']: r['count'] for r in sev_rows if r['severity']}

    return {
        'vendor': vendor,
        'product': product,
        'version': version,
        'total_cves': row['total_cves'],
        'critical': severity.get('CRITICAL', 0),
        'high': severity.get('HIGH', 0),
        'medium': severity.get('MEDIUM', 0),
        'low': severity.get('LOW', 0),
    }


def get_version_cves(db, vendor: str, product: str, version: str, page: int) -> dict:
    """Return paginated CVEs affecting a specific version of a product."""
    version_cond = (
        "(ap.version_exact = %s OR (ap.version_start = %s "
        "AND (ap.version_exact = '' OR ap.version_exact IS NULL)))"
    )
    query = (
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        f"WHERE ap.vendor = %s AND ap.product = %s AND {version_cond} "
        "AND c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(DISTINCT c.cve_id) FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        f"WHERE ap.vendor = %s AND ap.product = %s AND {version_cond} "
        "AND c.state = 'PUBLISHED'"
    )
    return get_paginated_result(db, query, count_query,
                                (vendor, product, version, version), page)


# ---------------------------------------------------------------------------
# Safe version references
# ---------------------------------------------------------------------------

_PRIORITY_TAGS = {'patch', 'vendor-advisory', 'release-notes', 'fix'}


def get_safe_version_references(db, cve_ids: list[str] | str, max_refs: int = 5) -> list[dict]:
    """Return references from CVEs related to a safe version branch.

    If cve_ids is a single string, fetches references from that CVE only
    (the CVE with the highest version_end that defines the safe version).
    Prioritizes URLs with tags containing 'patch', 'vendor-advisory',
    'release-notes', or 'fix'. Returns at most max_refs results.
    """
    if not cve_ids:
        return []

    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    placeholders = ','.join('%s' for _ in cve_ids)
    rows = _fetchall(db, 
        f"SELECT url, tags FROM references_table "
        f"WHERE cve_id IN ({placeholders}) AND url != '' AND url IS NOT NULL "
        f"ORDER BY url",
        tuple(cve_ids),
    )

    # Separate priority and non-priority refs
    priority = []
    others = []
    for r in rows:
        ref = dict(r)
        tags_lower = (ref.get('tags') or '').lower()
        if any(t in tags_lower for t in _PRIORITY_TAGS):
            priority.append(ref)
        else:
            others.append(ref)

    # Deduplicate by URL
    seen = set()
    result = []
    for ref in priority + others:
        if ref['url'] not in seen:
            seen.add(ref['url'])
            result.append(ref)
        if len(result) >= max_refs:
            break

    return result


# ---------------------------------------------------------------------------
# Fixed CVEs by branch
# ---------------------------------------------------------------------------

def get_fixed_cves_by_branch(db, vendor: str, product: str, branch: str, page: int) -> dict:
    """Return paginated CVEs fixed in a specific version branch of a product.

    Matches version_end that either equals branch exactly or starts with 'branch.'.
    """
    query = (
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE ap.vendor = %s AND ap.product = %s "
        "AND (ap.version_end = %s OR ap.version_end LIKE %s) "
        "AND ap.version_end != '' "
        "AND c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(DISTINCT c.cve_id) FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = %s AND ap.product = %s "
        "AND (ap.version_end = %s OR ap.version_end LIKE %s) "
        "AND ap.version_end != '' "
        "AND c.state = 'PUBLISHED'"
    )
    like_pattern = f"{branch}.%"
    return get_paginated_result(db, query, count_query,
                                (vendor, product, branch, like_pattern), page)


# ---------------------------------------------------------------------------
# Security Advisory model functions
# ---------------------------------------------------------------------------

def get_advisories(db, page: int, source: str | None = None,
                   severity: str | None = None) -> dict:
    """Return paginated list of security advisories with optional filters."""
    conditions = ["1=1"]
    params: list = []

    if source:
        conditions.append("sa.source = %s")
        params.append(source)
    if severity:
        conditions.append("UPPER(sa.severity) = %s")
        params.append(severity.upper())

    where = " AND ".join(conditions)

    query = (
        f"SELECT sa.id, sa.source, sa.title, sa.severity, sa.cvss_score, "
        f"sa.published_date, sa.url, sa.vendor, "
        f"(SELECT COUNT(*) FROM advisory_cves ac WHERE ac.advisory_id = sa.id) AS cve_count "
        f"FROM security_advisories sa "
        f"WHERE {where} "
        f"ORDER BY sa.published_date DESC"
    )
    count_query = f"SELECT COUNT(*) FROM security_advisories sa WHERE {where}"
    return get_paginated_result(db, query, count_query, tuple(params), page)


def get_advisory_sources(db) -> list[dict]:
    """Return list of advisory sources with counts."""
    rows = _fetchall(db, 
        "SELECT source, COUNT(*) AS count FROM security_advisories "
        "GROUP BY source ORDER BY count DESC"
    )
    return list(rows) if rows else []


def get_advisory_detail(db, advisory_id: str) -> dict | None:
    """Return full advisory detail or None if not found."""
    row = _fetchone(db, 
        "SELECT * FROM security_advisories WHERE id = %s",
        (advisory_id,),
    )
    if row is None:
        return None
    return dict(row)


def get_advisory_affected(db, advisory_id: str) -> list[dict]:
    """Return affected products for an advisory."""
    rows = _fetchall(db, 
        "SELECT vendor, product, version_range, fixed_version "
        "FROM advisory_affected_products WHERE advisory_id = %s "
        "ORDER BY product",
        (advisory_id,),
    )
    return list(rows) if rows else []


def get_advisory_cves(db, advisory_id: str) -> list[dict]:
    """Return CVEs linked to an advisory, with severity info if available."""
    rows = _fetchall(db, 
        "SELECT ac.cve_id, c.severity, c.description, cs.base_score "
        "FROM advisory_cves ac "
        "LEFT JOIN cves c ON ac.cve_id = c.cve_id "
        "LEFT JOIN cvss_scores cs ON ac.cve_id = cs.cve_id "
        "WHERE ac.advisory_id = %s "
        "GROUP BY ac.cve_id "
        "ORDER BY ac.cve_id",
        (advisory_id,),
    )
    return list(rows) if rows else []


def get_advisory_refs(db, advisory_id: str) -> list[str]:
    """Return reference URLs for an advisory."""
    rows = _fetchall(db, 
        "SELECT url FROM advisory_references WHERE advisory_id = %s ORDER BY url",
        (advisory_id,),
    )
    return [r['url'] for r in rows if r['url']]


def get_product_advisories(db, vendor: str, product: str) -> list[dict]:
    """Return advisories affecting a specific vendor/product with fixed versions."""
    rows = _fetchall(db, 
        "SELECT sa.id, sa.title, sa.severity, sa.cvss_score, sa.published_date, "
        "       sa.url, sa.source, "
        "       aap.version_range, aap.fixed_version "
        "FROM security_advisories sa "
        "INNER JOIN advisory_affected_products aap ON sa.id = aap.advisory_id "
        "WHERE LOWER(aap.vendor) = LOWER(%s) "
        "AND LOWER(aap.product) = LOWER(%s) "
        "ORDER BY sa.published_date DESC",
        (vendor, product),
    )
    return list(rows) if rows else []
