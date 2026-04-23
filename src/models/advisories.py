"""Model functions for advisories tables."""

from typing import Any

from models.helpers import (
    _fetchone, _fetchall, _execute,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    get_paginated_result, _VALID_SEVERITIES,
)

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
        f"sa.published_date, sa.url, sa.ecosystem, "
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
        "SELECT ecosystem, name, version_range, fixed_version, "
        "       matched_vendor, matched_product "
        "FROM advisory_affected_products WHERE advisory_id = %s "
        "ORDER BY name",
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
        "WHERE LOWER(aap.matched_vendor) = LOWER(%s) "
        "AND LOWER(aap.matched_product) = LOWER(%s) "
        "ORDER BY sa.published_date DESC",
        (vendor, product),
    )
    return list(rows) if rows else []
