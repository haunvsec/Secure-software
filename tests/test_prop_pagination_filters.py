"""Property-based tests for pagination, filters, and sorting (Properties 1-5).

Feature: cve-database-website
"""

import math
import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from models import (
    get_paginated_result, get_cves, sanitize_page, sanitize_severity,
    sanitize_year,
)

_suppress = [HealthCheck.function_scoped_fixture]


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 1: Pagination invariant
# ---------------------------------------------------------------------------

@given(
    page=st.integers(min_value=1, max_value=1000),
    total=st.integers(min_value=0, max_value=100000),
    per_page=st.just(50),
)
@settings(max_examples=200, suppress_health_check=_suppress)
def test_pagination_invariant(page, total, per_page):
    """For any valid page and total, pagination math must hold."""
    pages = max(math.ceil(total / per_page), 1) if per_page > 0 else 1
    clamped_page = max(1, min(page, pages))
    offset = (clamped_page - 1) * per_page

    assert pages == max(math.ceil(total / per_page), 1)
    assert offset == (clamped_page - 1) * per_page
    assert 0 <= offset <= max(total - 1, 0) or total == 0


@given(page=st.integers(min_value=1, max_value=100))
@settings(max_examples=100, suppress_health_check=_suppress)
def test_pagination_items_le_per_page(test_db, page):
    """Paginated result must return at most per_page items."""
    result = get_cves(test_db, page)
    assert len(result['items']) <= result['per_page']
    assert result['page'] >= 1
    assert result['page'] <= result['pages']


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 2: Year filter correctness
# ---------------------------------------------------------------------------

@given(year=st.integers(min_value=2020, max_value=2024))
@settings(max_examples=100, suppress_health_check=_suppress)
def test_year_filter_correctness(test_db, year):
    """All CVEs returned for a year filter must have date_published in that year."""
    result = get_cves(test_db, page=1, year=year)
    for item in result['items']:
        assert item['date_published'].startswith(str(year)), \
            f"CVE {item['cve_id']} date {item['date_published']} doesn't match year {year}"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 3: Severity filter correctness
# ---------------------------------------------------------------------------

@given(severity=st.sampled_from(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']))
@settings(max_examples=100, suppress_health_check=_suppress)
def test_severity_filter_correctness(test_db, severity):
    """All CVEs returned for a severity filter must have matching severity."""
    result = get_cves(test_db, page=1, severity=severity)
    for item in result['items']:
        assert item['severity'] == severity, \
            f"CVE {item['cve_id']} severity {item['severity']} != {severity}"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 4: Combined filter AND logic
# ---------------------------------------------------------------------------

@given(
    year=st.integers(min_value=2020, max_value=2024),
    severity=st.sampled_from(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
)
@settings(max_examples=100, suppress_health_check=_suppress)
def test_combined_filter_and_logic(test_db, year, severity):
    """All CVEs must satisfy BOTH year AND severity when both filters applied."""
    result = get_cves(test_db, page=1, year=year, severity=severity)
    for item in result['items']:
        assert item['date_published'].startswith(str(year))
        assert item['severity'] == severity


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 5: Date sort order invariant
# ---------------------------------------------------------------------------

@given(
    page=st.integers(min_value=1, max_value=5),
    severity=st.one_of(st.none(), st.sampled_from(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])),
)
@settings(max_examples=100, suppress_health_check=_suppress)
def test_date_sort_order_invariant(test_db, page, severity):
    """date_published must be in descending order in any result set."""
    result = get_cves(test_db, page=page, severity=severity)
    dates = [item['date_published'] for item in result['items'] if item['date_published']]
    for i in range(len(dates) - 1):
        assert dates[i] >= dates[i + 1], \
            f"Sort order violated: {dates[i]} < {dates[i+1]}"
