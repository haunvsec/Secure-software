"""Model functions for search tables."""

from typing import Any

from models.helpers import (
    _fetchone, _fetchall, _execute,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    get_paginated_result, _VALID_SEVERITIES,
)

import re

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
        f") AS t"
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