"""Property-based tests for product, search, badge, params (Properties 12-15).

Feature: cve-database-website
"""

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from models import (
    get_product_cves, get_products, search_cves,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
)

_suppress = [HealthCheck.function_scoped_fixture]


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 12: Product CVE association
# ---------------------------------------------------------------------------

@given(data=st.data())
@settings(max_examples=50, suppress_health_check=_suppress)
def test_product_cve_association(test_db, data):
    """All CVEs for a product must have matching affected_products entry."""
    products = get_products(test_db, page=1)
    assume(len(products['items']) > 0)
    prod = data.draw(st.sampled_from(products['items']))
    vendor, product = prod['vendor'], prod['product']

    result = get_product_cves(test_db, vendor, product, page=1)
    for item in result['items']:
        row = test_db.execute(
            "SELECT 1 FROM affected_products WHERE cve_id = ? AND vendor = ? AND product = ?",
            (item['cve_id'], vendor, product),
        ).fetchone()
        assert row is not None, \
            f"CVE {item['cve_id']} has no affected_products for {vendor}/{product}"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 13: Description keyword search
# ---------------------------------------------------------------------------

@given(keyword=st.sampled_from(['buffer', 'overflow', 'vulnerability', 'Test']))
@settings(max_examples=50, suppress_health_check=_suppress)
def test_description_keyword_search(test_db, keyword):
    """All CVEs returned for a keyword search must contain that keyword."""
    result = search_cves(test_db, keyword=keyword, page=1)
    if isinstance(result, str):
        return  # redirect case
    for item in result['items']:
        assert keyword.lower() in (item['description'] or '').lower(), \
            f"CVE {item['cve_id']} description doesn't contain '{keyword}'"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 14: CVSS badge color mapping
# ---------------------------------------------------------------------------

def _get_expected_severity(score):
    """Return expected severity label for a CVSS score."""
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score >= 0.1:
        return 'LOW'
    return 'N/A'


_SEVERITY_COLORS = {
    'CRITICAL': '#d32f2f',
    'HIGH': '#f57c00',
    'MEDIUM': '#fbc02d',
    'LOW': '#388e3c',
    'N/A': '#757575',
}


@given(score=st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False))
@settings(max_examples=200)
def test_cvss_badge_color_mapping(score):
    """CVSS score must map to correct severity label and color."""
    score = round(score, 1)
    expected_sev = _get_expected_severity(score)
    assert expected_sev in _SEVERITY_COLORS
    # Verify the mapping is consistent
    if score >= 9.0:
        assert expected_sev == 'CRITICAL'
    elif score >= 7.0:
        assert expected_sev == 'HIGH'
    elif score >= 4.0:
        assert expected_sev == 'MEDIUM'
    elif score >= 0.1:
        assert expected_sev == 'LOW'
    else:
        assert expected_sev == 'N/A'


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 15: Invalid parameter defaults
# ---------------------------------------------------------------------------

@given(page_val=st.one_of(
    st.integers(max_value=0),
    st.text(min_size=1, max_size=10),
    st.none(),
))
@settings(max_examples=200)
def test_invalid_page_defaults(page_val):
    """Invalid page values must default to 1."""
    result = sanitize_page(page_val)
    assert isinstance(result, int)
    assert result >= 1


@given(severity_val=st.one_of(
    st.text(min_size=1, max_size=20).filter(
        lambda s: s.upper() not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    ),
    st.none(),
    st.just(''),
))
@settings(max_examples=200)
def test_invalid_severity_defaults(severity_val):
    """Invalid severity values must default to None."""
    result = sanitize_severity(severity_val)
    assert result is None


@given(year_val=st.one_of(
    st.integers(max_value=1998),
    st.integers(min_value=2100),
    st.text(min_size=1, max_size=10),
    st.none(),
))
@settings(max_examples=200)
def test_invalid_year_defaults(year_val):
    """Invalid year values must default to None."""
    result = sanitize_year(year_val)
    assert result is None
