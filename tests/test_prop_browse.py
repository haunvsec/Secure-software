"""Property-based tests for browse pages (Properties 6-11).

Feature: cve-database-website
"""

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from models import (
    get_cwe_types, get_cves_by_cwe, get_assigners, get_cves_by_assigner,
    get_vendors, get_severity_summary, get_cves_by_severity,
)

_suppress = [HealthCheck.function_scoped_fixture]


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 6: CWE filter correctness
# ---------------------------------------------------------------------------

@given(data=st.data())
@settings(max_examples=50, suppress_health_check=_suppress)
def test_cwe_filter_correctness(test_db, data):
    """All CVEs returned for a CWE filter must have that CWE in cwe_entries."""
    # Pick a CWE from the database
    cwe_types = get_cwe_types(test_db, page=1)
    assume(len(cwe_types['items']) > 0)
    cwe = data.draw(st.sampled_from([c['cwe_id'] for c in cwe_types['items']]))

    result = get_cves_by_cwe(test_db, cwe, page=1)
    for item in result['items']:
        row = test_db.execute(
            "SELECT 1 FROM cwe_entries WHERE cve_id = ? AND cwe_id = ?",
            (item['cve_id'], cwe),
        ).fetchone()
        assert row is not None, \
            f"CVE {item['cve_id']} returned for {cwe} but has no matching cwe_entry"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 7: Count-based sort order invariant
# ---------------------------------------------------------------------------

@given(page=st.integers(min_value=1, max_value=3))
@settings(max_examples=50, suppress_health_check=_suppress)
def test_cwe_count_sort_order(test_db, page):
    """CWE types list must have cve_count in descending order."""
    result = get_cwe_types(test_db, page=page)
    counts = [item['cve_count'] for item in result['items']]
    for i in range(len(counts) - 1):
        assert counts[i] >= counts[i + 1], \
            f"CWE sort violated: {counts[i]} < {counts[i+1]}"


@given(page=st.integers(min_value=1, max_value=3))
@settings(max_examples=50, suppress_health_check=_suppress)
def test_assigner_count_sort_order(test_db, page):
    """Assigners list must have cve_count in descending order."""
    result = get_assigners(test_db, page=page)
    counts = [item['cve_count'] for item in result['items']]
    for i in range(len(counts) - 1):
        assert counts[i] >= counts[i + 1], \
            f"Assigner sort violated: {counts[i]} < {counts[i+1]}"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 8: Assigner filter correctness
# ---------------------------------------------------------------------------

@given(data=st.data())
@settings(max_examples=50, suppress_health_check=_suppress)
def test_assigner_filter_correctness(test_db, data):
    """All CVEs returned for an assigner must have matching assigner_short_name."""
    assigners_result = get_assigners(test_db, page=1)
    assume(len(assigners_result['items']) > 0)
    assigner = data.draw(
        st.sampled_from([a['assigner_short_name'] for a in assigners_result['items']])
    )

    result = get_cves_by_assigner(test_db, assigner, page=1)
    for item in result['items']:
        row = test_db.execute(
            "SELECT assigner_short_name FROM cves WHERE cve_id = ?",
            (item['cve_id'],),
        ).fetchone()
        assert row is not None
        assert row['assigner_short_name'] == assigner, \
            f"CVE {item['cve_id']} assigner {row['assigner_short_name']} != {assigner}"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 9: Letter filter correctness
# ---------------------------------------------------------------------------

@given(letter=st.sampled_from(list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')))
@settings(max_examples=100, suppress_health_check=_suppress)
def test_letter_filter_correctness(test_db, letter):
    """All vendors returned for a letter filter must start with that letter."""
    result = get_vendors(test_db, letter=letter, page=1)
    for item in result['items']:
        if letter.isdigit():
            assert item['vendor'][0].isdigit(), \
                f"Vendor '{item['vendor']}' doesn't start with a digit"
        else:
            assert item['vendor'][0].lower() == letter.lower(), \
                f"Vendor '{item['vendor']}' doesn't start with '{letter}'"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 10: Wildcard search correctness
# ---------------------------------------------------------------------------

@given(prefix=st.sampled_from(['micro', 'goo', 'app', 'lin', 'apa']))
@settings(max_examples=50, suppress_health_check=_suppress)
def test_wildcard_search_correctness(test_db, prefix):
    """Wildcard search results must match the pattern."""
    search_term = f"{prefix}*"
    result = get_vendors(test_db, search=search_term, page=1)
    for item in result['items']:
        assert item['vendor'].lower().startswith(prefix.lower()), \
            f"Vendor '{item['vendor']}' doesn't match wildcard '{search_term}'"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 11: Vendor exclusion invariant
# ---------------------------------------------------------------------------

@given(
    letter=st.one_of(
        st.sampled_from(list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')),
        st.none(),
    ),
)
@settings(max_examples=100, suppress_health_check=_suppress)
def test_vendor_exclusion_invariant(test_db, letter):
    """No vendor in results should be 'n/a', empty, or NULL."""
    if letter:
        result = get_vendors(test_db, letter=letter, page=1)
    else:
        result = get_vendors(test_db, page=1)
    for item in result['items']:
        assert item['vendor'] not in ('n/a', '', None), \
            f"Excluded vendor found: '{item['vendor']}'"
