"""Model functions for cves tables."""

from typing import Any

from models.helpers import (
    _fetchone, _fetchall, _execute,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    get_paginated_result, _VALID_SEVERITIES,
)

# Homepage model functions
# ---------------------------------------------------------------------------

def get_stats(db) -> dict[str, int]:
    """Return aggregate statistics for the homepage.

    Uses in-memory cache with 1-hour TTL to avoid repeated heavy queries.
    Returns dict with keys: total_cves, critical, high, medium, low,
    vendors, products.
    """
    from database import cache

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