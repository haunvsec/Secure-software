"""Database query functions and input sanitization for CVE Database Website."""

import math
import re
from typing import Any


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
        db: sqlite3 connection (with row_factory = sqlite3.Row).
        query: SQL SELECT query (without LIMIT/OFFSET).
        count_query: SQL SELECT COUNT(*) query.
        params: dict or tuple of query parameters shared by both queries.
        page: current page number (1-based, already sanitized).
        per_page: items per page (default 50).

    Returns:
        dict with keys: items, total, page, pages, per_page.
    """
    # Total count
    row = db.execute(count_query, params).fetchone()
    total = row[0] if row else 0

    # Calculate pages
    pages = max(math.ceil(total / per_page), 1) if per_page > 0 else 1

    # Clamp page to valid range
    page = max(1, min(page, pages))

    offset = (page - 1) * per_page

    # Data query with LIMIT/OFFSET
    rows = db.execute(f"{query} LIMIT ? OFFSET ?", (*params, per_page, offset)).fetchall()
    items = [dict(r) for r in rows]

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
    row = db.execute(
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED'"
    ).fetchone()
    total_cves = row[0] if row else 0

    # Severity counts
    severity_rows = db.execute(
        "SELECT severity, COUNT(*) FROM cves WHERE state = 'PUBLISHED' GROUP BY severity"
    ).fetchall()
    severity_map: dict[str, int] = {}
    for r in severity_rows:
        severity_map[str(r[0]).upper() if r[0] else ''] = r[1]

    # Distinct vendors (excluding empty / n/a)
    row = db.execute(
        "SELECT COUNT(DISTINCT vendor) FROM affected_products "
        "WHERE vendor != '' AND vendor != 'n/a'"
    ).fetchone()
    vendors = row[0] if row else 0

    # Distinct products (vendor/product combos, excluding empty / n/a)
    row = db.execute(
        "SELECT COUNT(DISTINCT vendor || '/' || product) FROM affected_products "
        "WHERE product != '' AND product != 'n/a'"
    ).fetchone()
    products = row[0] if row else 0

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
        db: sqlite3 connection.
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
        conditions.append("c.date_published LIKE ?")
        params.append(f"{year}%")
    if severity:
        conditions.append("c.severity = ?")
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
    rows = db.execute(
        "SELECT c.cve_id, c.description, c.severity, c.date_published, "
        "       cs.base_score "
        "FROM cves c "
        "LEFT JOIN cvss_scores cs ON c.cve_id = cs.cve_id "
        "WHERE c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC "
        "LIMIT ?",
        (limit,),
    ).fetchall()

    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# CVE detail model functions
# ---------------------------------------------------------------------------

def get_cve_detail(db, cve_id: str) -> dict | None:
    """Return full CVE information or None if not found.

    Returns dict with keys: cve_id, state, description, date_reserved,
    date_published, date_updated, assigner_short_name, assigner_org_id,
    severity, data_version.
    """
    row = db.execute(
        "SELECT cve_id, state, description, date_reserved, date_published, "
        "       date_updated, assigner_short_name, assigner_org_id, severity, "
        "       data_version "
        "FROM cves WHERE cve_id = ?",
        (cve_id,),
    ).fetchone()
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
    rows = db.execute(
        "SELECT version, vector_string, base_score, base_severity, "
        "       attack_vector, attack_complexity, privileges_required, "
        "       user_interaction, scope, confidentiality_impact, "
        "       integrity_impact, availability_impact, source "
        "FROM cvss_scores WHERE cve_id = ? "
        "ORDER BY base_score DESC",
        (cve_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_cve_affected(db, cve_id: str) -> list[dict]:
    """Return affected products for a CVE.

    Each dict contains: vendor, product, platform, version_start,
    version_end, version_exact, default_status, status.
    """
    rows = db.execute(
        "SELECT vendor, product, platform, version_start, version_end, "
        "       version_exact, default_status, status "
        "FROM affected_products WHERE cve_id = ? "
        "ORDER BY vendor, product",
        (cve_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_cve_cwes(db, cve_id: str) -> list[dict]:
    """Return CWE entries for a CVE.

    Each dict contains: cwe_id, description.
    """
    rows = db.execute(
        "SELECT cwe_id, description "
        "FROM cwe_entries WHERE cve_id = ? "
        "ORDER BY cwe_id",
        (cve_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_cve_references(db, cve_id: str) -> list[dict]:
    """Return reference URLs for a CVE.

    Each dict contains: url, tags.
    """
    rows = db.execute(
        "SELECT url, tags "
        "FROM references_table WHERE cve_id = ? "
        "ORDER BY url",
        (cve_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Browse by date model functions
# ---------------------------------------------------------------------------

def get_years_with_counts(db) -> list[dict]:
    """Return list of years with CVE counts, sorted descending. Cached 1 hour."""
    from app import cache

    cached = cache.get('years_counts')
    if cached is not None:
        return cached

    rows = db.execute(
        "SELECT SUBSTR(date_published, 1, 4) AS year, COUNT(*) AS count "
        "FROM cves WHERE state = 'PUBLISHED' AND date_published IS NOT NULL "
        "GROUP BY year ORDER BY year DESC"
    ).fetchall()
    result = [dict(r) for r in rows]
    cache.set('years_counts', result, 3600)
    return result


def get_months_for_year(db, year: int) -> list[dict]:
    """Return 12 months with CVE counts for a given year."""
    rows = db.execute(
        "SELECT SUBSTR(date_published, 6, 2) AS month, COUNT(*) AS count "
        "FROM cves WHERE state = 'PUBLISHED' AND date_published LIKE ? "
        "GROUP BY month ORDER BY month",
        (f"{year}%",),
    ).fetchall()
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
        "WHERE c.state = 'PUBLISHED' AND c.date_published LIKE ? "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED' AND date_published LIKE ?"
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
        "WHERE ce.cwe_id = ? AND c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(DISTINCT c.cve_id) FROM cves c "
        "INNER JOIN cwe_entries ce ON c.cve_id = ce.cve_id "
        "WHERE ce.cwe_id = ? AND c.state = 'PUBLISHED'"
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

    row = db.execute(
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED'"
    ).fetchone()
    total = row[0] if row else 0

    rows = db.execute(
        "SELECT severity, COUNT(*) AS count FROM cves "
        "WHERE state = 'PUBLISHED' AND severity IN ('CRITICAL','HIGH','MEDIUM','LOW') "
        "GROUP BY severity"
    ).fetchall()
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
        "WHERE c.state = 'PUBLISHED' AND c.severity = ? "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM cves WHERE state = 'PUBLISHED' AND severity = ?"
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
        "WHERE c.state = 'PUBLISHED' AND c.assigner_short_name = ? "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM cves "
        "WHERE state = 'PUBLISHED' AND assigner_short_name = ?"
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
        conditions.append("ap.vendor LIKE ? ESCAPE '\\'")
        params.append(search_pattern)
    elif letter:
        if letter.isdigit():
            conditions.append("ap.vendor GLOB '[0-9]*'")
        else:
            conditions.append("LOWER(ap.vendor) LIKE ? ESCAPE '\\'")
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
    row = db.execute(
        "SELECT COUNT(DISTINCT cve_id) AS total_cves "
        "FROM affected_products WHERE vendor = ?",
        (vendor,),
    ).fetchone()
    if row is None or row['total_cves'] == 0:
        return None

    sev_rows = db.execute(
        "SELECT c.severity, COUNT(DISTINCT c.cve_id) AS count "
        "FROM cves c INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = ? AND c.state = 'PUBLISHED' "
        "GROUP BY c.severity",
        (vendor,),
    ).fetchall()
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
        "FROM affected_products WHERE vendor = ? "
        "AND product != '' AND product != 'n/a' AND product IS NOT NULL "
        "GROUP BY product ORDER BY cve_count DESC"
    )
    count_query = (
        "SELECT COUNT(*) FROM ("
        "  SELECT product FROM affected_products WHERE vendor = ? "
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
        conditions.append("ap.product LIKE ? ESCAPE '\\'")
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
    row = db.execute(
        "SELECT COUNT(DISTINCT cve_id) AS total_cves "
        "FROM affected_products WHERE vendor = ? AND product = ?",
        (vendor, product),
    ).fetchone()
    if row is None or row['total_cves'] == 0:
        return None

    sev_rows = db.execute(
        "SELECT c.severity, COUNT(DISTINCT c.cve_id) AS count "
        "FROM cves c INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = ? AND ap.product = ? AND c.state = 'PUBLISHED' "
        "GROUP BY c.severity",
        (vendor, product),
    ).fetchall()
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
        "WHERE ap.vendor = ? AND ap.product = ? AND c.state = 'PUBLISHED' "
        "GROUP BY c.cve_id "
        "ORDER BY c.date_published DESC"
    )
    count_query = (
        "SELECT COUNT(DISTINCT c.cve_id) FROM cves c "
        "INNER JOIN affected_products ap ON c.cve_id = ap.cve_id "
        "WHERE ap.vendor = ? AND ap.product = ? AND c.state = 'PUBLISHED'"
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
        row = db.execute("SELECT cve_id FROM cves WHERE cve_id = ?", (cve_id_clean,)).fetchone()
        if row:
            return row['cve_id']

    conditions = ["c.state = 'PUBLISHED'"]
    params: list = []
    need_ap_join = False

    if keyword:
        kw = sanitize_search(keyword)
        conditions.append("c.description LIKE ? ESCAPE '\\'")
        params.append(kw)

    if vendor:
        v = sanitize_search(vendor)
        conditions.append("ap.vendor LIKE ? ESCAPE '\\'")
        params.append(v)
        need_ap_join = True

    if product:
        p = sanitize_search(product)
        conditions.append("ap.product LIKE ? ESCAPE '\\'")
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
    rows = db.execute(
        "SELECT version_end, version_end_type, cve_id "
        "FROM affected_products "
        "WHERE vendor = ? AND product = ? AND version_end != '' AND version_end IS NOT NULL",
        (vendor, product),
    ).fetchall()
    return [dict(r) for r in rows]
