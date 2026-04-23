"""Model functions for products tables."""

from typing import Any

from models.helpers import (
    _fetchone, _fetchall, _execute,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    get_paginated_result, _VALID_SEVERITIES,
)

import math

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