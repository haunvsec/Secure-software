"""Model functions for vendors tables."""

from typing import Any

from models.helpers import (
    _fetchone, _fetchall, _execute,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    get_paginated_result, _VALID_SEVERITIES,
)

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
        f") AS t"
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
        ") AS t"
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
        f") AS t"
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