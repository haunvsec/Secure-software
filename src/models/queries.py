"""SQLAlchemy ORM query functions for Secure Software Board.

Replaces raw SQL queries with ORM-based queries. All functions accept
a SQLAlchemy session and return dicts/lists for template compatibility.
Sanitize functions are kept from helpers.py.
"""

import math
import re
from typing import Any

from sqlalchemy import func, desc, and_, or_, distinct, literal_column
from sqlalchemy.orm import Session

from models.orm import (
    Cve, AffectedProduct, CvssScore, CweEntry, Reference,
    SecurityAdvisory, AdvisoryAffectedProduct, AdvisoryCve, AdvisoryReference,
)

# Re-export sanitize functions (unchanged)
from models.helpers import (
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    _VALID_SEVERITIES,
)


# ---------------------------------------------------------------------------
# Pagination helper
# ---------------------------------------------------------------------------

def get_paginated(query, page: int, per_page: int = 50) -> dict:
    """Standard pagination wrapper for SQLAlchemy queries.

    Args:
        query: SQLAlchemy query object (supports .count(), .offset(), .limit()).
        page: 1-based page number.
        per_page: items per page.

    Returns:
        dict with keys: items, total, page, pages, per_page.
    """
    total = query.count()
    pages = max(math.ceil(total / per_page), 1) if per_page > 0 else 1
    page = max(1, min(page, pages))
    offset = (page - 1) * per_page
    items = query.offset(offset).limit(per_page).all()
    return {
        'items': items,
        'total': total,
        'page': page,
        'pages': pages,
        'per_page': per_page,
    }


def _row_to_dict(row) -> dict:
    """Convert a SQLAlchemy ORM instance or Row to dict."""
    if hasattr(row, '__dict__'):
        d = {k: v for k, v in row.__dict__.items() if not k.startswith('_')}
        # Convert Decimal to float for JSON/template compat
        for k, v in d.items():
            if hasattr(v, 'is_finite'):  # Decimal
                d[k] = float(v)
        return d
    if hasattr(row, '_mapping'):
        d = dict(row._mapping)
        for k, v in d.items():
            if hasattr(v, 'is_finite'):
                d[k] = float(v)
        return d
    return dict(row)


# ---------------------------------------------------------------------------
# Homepage
# ---------------------------------------------------------------------------

def get_stats(session: Session) -> dict[str, int]:
    """Aggregate statistics for the homepage. Cached 1 hour."""
    from database import cache

    cached = cache.get('stats')
    if cached is not None:
        return cached

    total_cves = session.query(func.count(Cve.cve_id)).filter(
        Cve.state == 'PUBLISHED'
    ).scalar() or 0

    sev_rows = session.query(
        Cve.severity, func.count(Cve.cve_id)
    ).filter(Cve.state == 'PUBLISHED').group_by(Cve.severity).all()
    sev_map = {str(s).upper(): c for s, c in sev_rows if s}

    vendors = session.query(func.count(distinct(AffectedProduct.vendor))).filter(
        AffectedProduct.vendor != '', AffectedProduct.vendor != 'n/a',
    ).scalar() or 0

    # Use subquery for product count — faster than CONCAT on TEXT columns
    products_subq = session.query(
        AffectedProduct.vendor, AffectedProduct.product
    ).filter(
        AffectedProduct.product != '', AffectedProduct.product != 'n/a',
    ).distinct().subquery()
    products = session.query(func.count()).select_from(products_subq).scalar() or 0

    result = {
        'total_cves': total_cves,
        'critical': sev_map.get('CRITICAL', 0),
        'high': sev_map.get('HIGH', 0),
        'medium': sev_map.get('MEDIUM', 0),
        'low': sev_map.get('LOW', 0),
        'vendors': vendors,
        'products': products,
    }
    cache.set('stats', result, 3600)
    return result


def get_latest_cves(session: Session, limit: int = 10) -> list[dict]:
    """Return the most recently published CVEs."""
    rows = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).outerjoin(CvssScore, Cve.cve_id == CvssScore.cve_id).filter(
        Cve.state == 'PUBLISHED'
    ).group_by(Cve.cve_id).order_by(
        desc(Cve.date_published)
    ).limit(limit).all()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# CVE list and detail
# ---------------------------------------------------------------------------

def get_cves(session: Session, page: int, year=None, severity=None) -> dict:
    """Paginated published CVEs with optional year/severity filters."""
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated,
        CvssScore.base_score, AffectedProduct.vendor, AffectedProduct.product,
    ).outerjoin(CvssScore, Cve.cve_id == CvssScore.cve_id).outerjoin(
        AffectedProduct, Cve.cve_id == AffectedProduct.cve_id
    ).filter(Cve.state == 'PUBLISHED')

    if year:
        q = q.filter(Cve.date_published.like(f'{year}%'))
    if severity:
        q = q.filter(Cve.severity == severity)

    q = q.group_by(Cve.cve_id).order_by(desc(Cve.date_published))
    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


def get_cve_detail(session: Session, cve_id: str) -> dict | None:
    """Full CVE information or None."""
    cve = session.query(Cve).filter(Cve.cve_id == cve_id).first()
    if cve is None:
        return None
    return _row_to_dict(cve)


def get_cve_cvss(session: Session, cve_id: str) -> list[dict]:
    """All CVSS scores for a CVE."""
    rows = session.query(CvssScore).filter(
        CvssScore.cve_id == cve_id
    ).order_by(desc(CvssScore.base_score)).all()
    return [_row_to_dict(r) for r in rows]


def get_cve_affected(session: Session, cve_id: str) -> list[dict]:
    """Affected products for a CVE."""
    rows = session.query(AffectedProduct).filter(
        AffectedProduct.cve_id == cve_id
    ).order_by(AffectedProduct.vendor, AffectedProduct.product).all()
    return [_row_to_dict(r) for r in rows]


def get_cve_cwes(session: Session, cve_id: str) -> list[dict]:
    """CWE entries for a CVE."""
    rows = session.query(CweEntry).filter(
        CweEntry.cve_id == cve_id
    ).order_by(CweEntry.cwe_id).all()
    return [_row_to_dict(r) for r in rows]


def get_cve_references(session: Session, cve_id: str) -> list[dict]:
    """Reference URLs for a CVE."""
    rows = session.query(Reference).filter(
        Reference.cve_id == cve_id
    ).order_by(Reference.url).all()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Browse by date
# ---------------------------------------------------------------------------

_MONTH_NAMES = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
]


def get_years_with_counts(session: Session) -> list[dict]:
    """Years with CVE counts, sorted descending. Cached 1 hour."""
    from database import cache

    cached = cache.get('years_counts')
    if cached is not None:
        return cached

    rows = session.query(
        func.left(Cve.date_published, 4).label('year'),
        func.count().label('count'),
    ).filter(
        Cve.state == 'PUBLISHED', Cve.date_published.isnot(None),
    ).group_by('year').order_by(desc('year')).all()

    result = [_row_to_dict(r) for r in rows]
    cache.set('years_counts', result, 3600)
    return result


def get_months_for_year(session: Session, year: int) -> list[dict]:
    """12 months with CVE counts for a given year."""
    rows = session.query(
        func.substring(Cve.date_published, 6, 2).label('month'),
        func.count().label('count'),
    ).filter(
        Cve.state == 'PUBLISHED', Cve.date_published.like(f'{year}%'),
    ).group_by('month').order_by('month').all()

    month_map = {r.month: r.count for r in rows}
    result = []
    for m in range(1, 13):
        ms = f'{m:02d}'
        result.append({'month': ms, 'month_name': _MONTH_NAMES[m - 1], 'count': month_map.get(ms, 0)})
    return result


def get_cves_by_month(session: Session, year: int, month: str, page: int) -> dict:
    """Paginated CVEs for a specific year/month."""
    prefix = f'{year}-{month}%'
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).outerjoin(CvssScore, Cve.cve_id == CvssScore.cve_id).filter(
        Cve.state == 'PUBLISHED', Cve.date_published.like(prefix),
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


# ---------------------------------------------------------------------------
# Browse by CWE type
# ---------------------------------------------------------------------------

def get_cwe_types(session: Session, page: int) -> dict:
    """Paginated CWE types with CVE counts. Cached 1 hour."""
    from database import cache

    cache_key = f'cwe_types_page_{page}'
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    q = session.query(
        CweEntry.cwe_id,
        CweEntry.description,
        func.count(distinct(CweEntry.cve_id)).label('cve_count'),
        func.max(Cve.date_published).label('latest_date'),
    ).join(Cve, CweEntry.cve_id == Cve.cve_id).filter(
        CweEntry.cwe_id.isnot(None), CweEntry.cwe_id != '',
        Cve.state == 'PUBLISHED',
    ).group_by(CweEntry.cwe_id).order_by(desc('latest_date'))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    cache.set(cache_key, result, 3600)
    return result


def get_cves_by_cwe(session: Session, cwe_id: str, page: int) -> dict:
    """Paginated CVEs for a specific CWE type."""
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).join(CweEntry, Cve.cve_id == CweEntry.cve_id).outerjoin(
        CvssScore, Cve.cve_id == CvssScore.cve_id
    ).filter(
        CweEntry.cwe_id == cwe_id, Cve.state == 'PUBLISHED',
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


# ---------------------------------------------------------------------------
# Browse by severity
# ---------------------------------------------------------------------------

def get_severity_summary(session: Session) -> list[dict]:
    """4 severity groups with counts and percentages. Cached 1 hour."""
    from database import cache

    cached = cache.get('severity_summary')
    if cached is not None:
        return cached

    total = session.query(func.count(Cve.cve_id)).filter(
        Cve.state == 'PUBLISHED'
    ).scalar() or 0

    rows = session.query(
        Cve.severity, func.count().label('count'),
    ).filter(
        Cve.state == 'PUBLISHED',
        Cve.severity.in_(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
    ).group_by(Cve.severity).all()

    sev_map = {r.severity: r.count for r in rows}
    result = []
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = sev_map.get(sev, 0)
        pct = round(count / total * 100, 1) if total > 0 else 0
        result.append({'severity': sev, 'count': count, 'percentage': pct})

    cache.set('severity_summary', result, 3600)
    return result


def get_cves_by_severity(session: Session, severity: str, page: int) -> dict:
    """Paginated CVEs for a specific severity level."""
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).outerjoin(CvssScore, Cve.cve_id == CvssScore.cve_id).filter(
        Cve.state == 'PUBLISHED', Cve.severity == severity,
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


# ---------------------------------------------------------------------------
# Browse by assigner
# ---------------------------------------------------------------------------

def get_assigners(session: Session, page: int) -> dict:
    """Paginated assigners sorted by latest CVE date."""
    q = session.query(
        Cve.assigner_short_name,
        func.count().label('cve_count'),
        func.max(Cve.date_published).label('latest_date'),
    ).filter(
        Cve.state == 'PUBLISHED',
        Cve.assigner_short_name.isnot(None),
        Cve.assigner_short_name != '',
    ).group_by(Cve.assigner_short_name).order_by(desc('latest_date'))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


def get_cves_by_assigner(session: Session, assigner: str, page: int) -> dict:
    """Paginated CVEs for a specific assigner."""
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).outerjoin(CvssScore, Cve.cve_id == CvssScore.cve_id).filter(
        Cve.state == 'PUBLISHED', Cve.assigner_short_name == assigner,
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


# ---------------------------------------------------------------------------
# Vendors
# ---------------------------------------------------------------------------

def get_vendors(session: Session, letter: str | None = None,
                    search: str | None = None, page: int = 1) -> dict:
    """Paginated vendors filtered by letter or search, sorted by latest CVE date."""
    q = session.query(
        AffectedProduct.vendor,
        func.count(distinct(AffectedProduct.product)).label('product_count'),
        func.count(distinct(AffectedProduct.cve_id)).label('vuln_count'),
        func.max(Cve.date_published).label('latest_date'),
    ).join(Cve, AffectedProduct.cve_id == Cve.cve_id).filter(
        AffectedProduct.vendor != '',
        AffectedProduct.vendor != 'n/a',
        AffectedProduct.vendor.isnot(None),
        Cve.state == 'PUBLISHED',
    )

    if search:
        search_pattern = sanitize_search(search)
        q = q.filter(AffectedProduct.vendor.like(search_pattern))
    elif letter:
        if letter.isdigit():
            q = q.filter(AffectedProduct.vendor.regexp_match('^[0-9]'))
        else:
            q = q.filter(func.lower(AffectedProduct.vendor).like(f'{letter.lower()}%'))
    else:
        q = q.filter(func.lower(AffectedProduct.vendor).like('a%'))

    q = q.group_by(AffectedProduct.vendor).order_by(desc('latest_date'))
    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


def get_vendor_detail(session: Session, vendor: str) -> dict | None:
    """Vendor name, total CVEs, severity distribution. None if not found."""
    total = session.query(func.count(distinct(AffectedProduct.cve_id))).filter(
        AffectedProduct.vendor == vendor,
    ).scalar() or 0

    if total == 0:
        return None

    sev_rows = session.query(
        Cve.severity, func.count(distinct(Cve.cve_id)).label('count'),
    ).join(AffectedProduct, Cve.cve_id == AffectedProduct.cve_id).filter(
        AffectedProduct.vendor == vendor, Cve.state == 'PUBLISHED',
    ).group_by(Cve.severity).all()

    severity = {r.severity: r.count for r in sev_rows if r.severity}
    return {
        'vendor': vendor,
        'total_cves': total,
        'critical': severity.get('CRITICAL', 0),
        'high': severity.get('HIGH', 0),
        'medium': severity.get('MEDIUM', 0),
        'low': severity.get('LOW', 0),
    }


def get_vendor_products(session: Session, vendor: str, page: int) -> dict:
    """Paginated products for a vendor with CVE counts, sorted by latest CVE date."""
    q = session.query(
        AffectedProduct.product,
        func.count(distinct(AffectedProduct.cve_id)).label('cve_count'),
        func.max(Cve.date_published).label('latest_date'),
    ).join(Cve, AffectedProduct.cve_id == Cve.cve_id).filter(
        AffectedProduct.vendor == vendor,
        AffectedProduct.product != '',
        AffectedProduct.product != 'n/a',
        AffectedProduct.product.isnot(None),
        Cve.state == 'PUBLISHED',
    ).group_by(AffectedProduct.product).order_by(desc('latest_date'))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------

def get_products(session: Session, search: str | None = None, page: int = 1) -> dict:
    """Paginated products sorted by latest CVE date, with optional search."""
    q = session.query(
        AffectedProduct.product,
        AffectedProduct.vendor,
        func.count(distinct(AffectedProduct.cve_id)).label('cve_count'),
        func.max(Cve.date_published).label('latest_date'),
    ).join(Cve, AffectedProduct.cve_id == Cve.cve_id).filter(
        AffectedProduct.product != '',
        AffectedProduct.product != 'n/a',
        AffectedProduct.product.isnot(None),
        Cve.state == 'PUBLISHED',
    )

    if search:
        search_pattern = sanitize_search(search)
        q = q.filter(AffectedProduct.product.like(search_pattern))

    q = q.group_by(AffectedProduct.vendor, AffectedProduct.product).order_by(desc('latest_date'))
    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


def get_product_detail(session: Session, vendor: str, product: str) -> dict | None:
    """Product name, vendor, total CVEs, severity distribution. None if not found."""
    total = session.query(func.count(distinct(AffectedProduct.cve_id))).filter(
        AffectedProduct.vendor == vendor, AffectedProduct.product == product,
    ).scalar() or 0

    if total == 0:
        return None

    sev_rows = session.query(
        Cve.severity, func.count(distinct(Cve.cve_id)).label('count'),
    ).join(AffectedProduct, Cve.cve_id == AffectedProduct.cve_id).filter(
        AffectedProduct.vendor == vendor, AffectedProduct.product == product,
        Cve.state == 'PUBLISHED',
    ).group_by(Cve.severity).all()

    severity = {r.severity: r.count for r in sev_rows if r.severity}
    return {
        'vendor': vendor,
        'product': product,
        'total_cves': total,
        'critical': severity.get('CRITICAL', 0),
        'high': severity.get('HIGH', 0),
        'medium': severity.get('MEDIUM', 0),
        'low': severity.get('LOW', 0),
    }


def get_product_cves(session: Session, vendor: str, product: str, page: int) -> dict:
    """Paginated CVEs affecting a specific product."""
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).join(AffectedProduct, Cve.cve_id == AffectedProduct.cve_id).outerjoin(
        CvssScore, Cve.cve_id == CvssScore.cve_id
    ).filter(
        AffectedProduct.vendor == vendor, AffectedProduct.product == product,
        Cve.state == 'PUBLISHED',
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


# ---------------------------------------------------------------------------
# Product versions and safe version references
# ---------------------------------------------------------------------------

def get_product_versions(session: Session, vendor: str, product: str,
                             page: int = 1, per_page: int = 50) -> dict:
    """Paginated version ranges for a product."""
    from safe_version import parse_version

    rows = session.query(
        AffectedProduct.version_start,
        AffectedProduct.version_end,
        AffectedProduct.version_end_type,
        func.count(distinct(AffectedProduct.cve_id)).label('cve_count'),
    ).filter(
        AffectedProduct.vendor == vendor,
        AffectedProduct.product == product,
        AffectedProduct.version_end != '',
        AffectedProduct.version_end.isnot(None),
        or_(AffectedProduct.version_exact == '', AffectedProduct.version_exact.is_(None)),
    ).group_by(
        AffectedProduct.version_start,
        AffectedProduct.version_end,
        AffectedProduct.version_end_type,
    ).all()

    all_ranges = [_row_to_dict(r) for r in rows]

    def _range_sort_key(item):
        parsed = parse_version(item['version_end'])
        return (1,) + parsed if parsed else (0,)

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


def get_version_detail(session: Session, vendor: str, product: str,
                           version: str) -> dict | None:
    """Version info with total CVEs and severity distribution. None if not found."""
    total = session.query(func.count(distinct(AffectedProduct.cve_id))).filter(
        AffectedProduct.vendor == vendor,
        AffectedProduct.product == product,
        or_(
            AffectedProduct.version_exact == version,
            and_(
                AffectedProduct.version_start == version,
                or_(AffectedProduct.version_exact == '', AffectedProduct.version_exact.is_(None)),
            ),
        ),
    ).scalar() or 0

    if total == 0:
        return None

    sev_rows = session.query(
        Cve.severity, func.count(distinct(Cve.cve_id)).label('count'),
    ).join(AffectedProduct, Cve.cve_id == AffectedProduct.cve_id).filter(
        AffectedProduct.vendor == vendor,
        AffectedProduct.product == product,
        or_(
            AffectedProduct.version_exact == version,
            and_(
                AffectedProduct.version_start == version,
                or_(AffectedProduct.version_exact == '', AffectedProduct.version_exact.is_(None)),
            ),
        ),
        Cve.state == 'PUBLISHED',
    ).group_by(Cve.severity).all()

    severity = {r.severity: r.count for r in sev_rows if r.severity}
    return {
        'vendor': vendor,
        'product': product,
        'version': version,
        'total_cves': total,
        'critical': severity.get('CRITICAL', 0),
        'high': severity.get('HIGH', 0),
        'medium': severity.get('MEDIUM', 0),
        'low': severity.get('LOW', 0),
    }


def get_version_cves(session: Session, vendor: str, product: str,
                         version: str, page: int) -> dict:
    """Paginated CVEs affecting a specific version of a product."""
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).join(AffectedProduct, Cve.cve_id == AffectedProduct.cve_id).outerjoin(
        CvssScore, Cve.cve_id == CvssScore.cve_id
    ).filter(
        AffectedProduct.vendor == vendor,
        AffectedProduct.product == product,
        or_(
            AffectedProduct.version_exact == version,
            and_(
                AffectedProduct.version_start == version,
                or_(AffectedProduct.version_exact == '', AffectedProduct.version_exact.is_(None)),
            ),
        ),
        Cve.state == 'PUBLISHED',
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


_PRIORITY_TAGS = {'patch', 'vendor-advisory', 'release-notes', 'fix'}


def get_safe_version_references(session: Session, cve_ids: list[str] | str,
                                    max_refs: int = 5) -> list[dict]:
    """References from CVEs related to a safe version branch."""
    if not cve_ids:
        return []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    rows = session.query(Reference).filter(
        Reference.cve_id.in_(cve_ids),
        Reference.url != '',
        Reference.url.isnot(None),
    ).order_by(Reference.url).all()

    priority, others = [], []
    for r in rows:
        ref = _row_to_dict(r)
        tags_lower = (ref.get('tags') or '').lower()
        if any(t in tags_lower for t in _PRIORITY_TAGS):
            priority.append(ref)
        else:
            others.append(ref)

    seen = set()
    result = []
    for ref in priority + others:
        if ref['url'] not in seen:
            seen.add(ref['url'])
            result.append(ref)
        if len(result) >= max_refs:
            break
    return result


def get_fixed_cves_by_branch(session: Session, vendor: str, product: str,
                                 branch: str, page: int) -> dict:
    """Paginated CVEs fixed in a specific version branch."""
    like_pattern = f'{branch}.%'
    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    ).join(AffectedProduct, Cve.cve_id == AffectedProduct.cve_id).outerjoin(
        CvssScore, Cve.cve_id == CvssScore.cve_id
    ).filter(
        AffectedProduct.vendor == vendor,
        AffectedProduct.product == product,
        or_(AffectedProduct.version_end == branch, AffectedProduct.version_end.like(like_pattern)),
        AffectedProduct.version_end != '',
        Cve.state == 'PUBLISHED',
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

_CVE_ID_RE = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)


def search_cves(session: Session, cve_id: str | None = None,
                    keyword: str | None = None, vendor: str | None = None,
                    product: str | None = None, page: int = 1) -> dict | str:
    """Search CVEs by multiple criteria. Returns paginated dict or CVE ID string for redirect."""
    if cve_id and _CVE_ID_RE.match(cve_id.strip()):
        cve_id_clean = cve_id.strip().upper()
        exists = session.query(Cve.cve_id).filter(Cve.cve_id == cve_id_clean).first()
        if exists:
            return exists.cve_id

    filters = [Cve.state == 'PUBLISHED']
    need_ap_join = False

    if keyword:
        kw = sanitize_search(keyword)
        filters.append(Cve.description.like(kw))
    if vendor:
        v = sanitize_search(vendor)
        filters.append(AffectedProduct.vendor.like(v))
        need_ap_join = True
    if product:
        p = sanitize_search(product)
        filters.append(AffectedProduct.product.like(p))
        need_ap_join = True

    q = session.query(
        Cve.cve_id, Cve.description, Cve.severity, Cve.date_published,
        Cve.date_updated, CvssScore.base_score,
    )
    if need_ap_join:
        q = q.join(AffectedProduct, Cve.cve_id == AffectedProduct.cve_id)
    q = q.outerjoin(CvssScore, Cve.cve_id == CvssScore.cve_id).filter(
        *filters
    ).group_by(Cve.cve_id).order_by(desc(Cve.date_published))

    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


def get_product_version_ranges(session: Session, vendor: str,
                                   product: str) -> list[dict]:
    """Version ranges for a product (for safe version computation)."""
    rows = session.query(
        AffectedProduct.version_end,
        AffectedProduct.version_end_type,
        AffectedProduct.cve_id,
    ).filter(
        AffectedProduct.vendor == vendor,
        AffectedProduct.product == product,
        AffectedProduct.version_end != '',
        AffectedProduct.version_end.isnot(None),
    ).all()
    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Advisories
# ---------------------------------------------------------------------------

def get_advisories(session: Session, page: int, source: str | None = None,
                       severity: str | None = None) -> dict:
    """Paginated security advisories with optional filters."""
    cve_count_subq = session.query(
        func.count(AdvisoryCve.id)
    ).filter(
        AdvisoryCve.advisory_id == SecurityAdvisory.id
    ).correlate(SecurityAdvisory).scalar_subquery().label('cve_count')

    q = session.query(
        SecurityAdvisory.id,
        SecurityAdvisory.source,
        SecurityAdvisory.title,
        SecurityAdvisory.severity,
        SecurityAdvisory.cvss_score,
        SecurityAdvisory.published_date,
        SecurityAdvisory.modified_date,
        SecurityAdvisory.url,
        SecurityAdvisory.vendor,
        cve_count_subq,
    )

    if source:
        q = q.filter(SecurityAdvisory.source == source)
    if severity:
        q = q.filter(func.upper(SecurityAdvisory.severity) == severity.upper())

    q = q.order_by(desc(SecurityAdvisory.published_date))
    result = get_paginated(q, page)
    result['items'] = [_row_to_dict(r) for r in result['items']]
    return result


def get_advisory_sources(session: Session) -> list[dict]:
    """Advisory sources with counts, sorted by latest published date."""
    rows = session.query(
        SecurityAdvisory.source,
        func.count().label('count'),
        func.max(SecurityAdvisory.published_date).label('latest_date'),
    ).group_by(SecurityAdvisory.source).order_by(desc('latest_date')).all()
    return [_row_to_dict(r) for r in rows]


def get_advisory_detail(session: Session, advisory_id: str) -> dict | None:
    """Full advisory detail or None."""
    adv = session.query(SecurityAdvisory).filter(SecurityAdvisory.id == advisory_id).first()
    if adv is None:
        return None
    return _row_to_dict(adv)


def get_advisory_affected(session: Session, advisory_id: str) -> list[dict]:
    """Affected products for an advisory."""
    rows = session.query(AdvisoryAffectedProduct).filter(
        AdvisoryAffectedProduct.advisory_id == advisory_id,
    ).order_by(AdvisoryAffectedProduct.product).all()
    return [_row_to_dict(r) for r in rows]


def get_advisory_cves(session: Session, advisory_id: str) -> list[dict]:
    """CVEs linked to an advisory, with severity info."""
    rows = session.query(
        AdvisoryCve.cve_id,
        Cve.severity,
        Cve.description,
        CvssScore.base_score,
    ).outerjoin(Cve, AdvisoryCve.cve_id == Cve.cve_id).outerjoin(
        CvssScore, AdvisoryCve.cve_id == CvssScore.cve_id
    ).filter(
        AdvisoryCve.advisory_id == advisory_id,
    ).group_by(AdvisoryCve.cve_id).order_by(desc(Cve.date_published)).all()
    return [_row_to_dict(r) for r in rows]


def get_advisory_refs(session: Session, advisory_id: str) -> list[str]:
    """Reference URLs for an advisory."""
    rows = session.query(AdvisoryReference.url).filter(
        AdvisoryReference.advisory_id == advisory_id,
    ).order_by(AdvisoryReference.url).all()
    return [r.url for r in rows if r.url]


def get_product_advisories(session: Session, vendor: str,
                               product: str) -> list[dict]:
    """Advisories affecting a specific vendor/product with fixed versions."""
    rows = session.query(
        SecurityAdvisory.id,
        SecurityAdvisory.title,
        SecurityAdvisory.severity,
        SecurityAdvisory.cvss_score,
        SecurityAdvisory.published_date,
        SecurityAdvisory.url,
        SecurityAdvisory.source,
        AdvisoryAffectedProduct.version_range,
        AdvisoryAffectedProduct.fixed_version,
    ).join(
        AdvisoryAffectedProduct,
        SecurityAdvisory.id == AdvisoryAffectedProduct.advisory_id,
    ).filter(
        func.lower(AdvisoryAffectedProduct.vendor) == func.lower(vendor),
        func.lower(AdvisoryAffectedProduct.product) == func.lower(product),
    ).order_by(desc(SecurityAdvisory.published_date)).all()
    return [_row_to_dict(r) for r in rows]
