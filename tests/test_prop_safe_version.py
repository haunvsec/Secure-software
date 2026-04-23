"""Property-based tests for safe version module (Properties 16-21).

Feature: cve-database-website
"""

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from safe_version import (
    parse_version, compare_versions, get_version_branch, compute_safe_versions,
)

_suppress = [HealthCheck.function_scoped_fixture]

# Strategy for valid version components
_version_part = st.integers(min_value=0, max_value=999)
_version_str = st.tuples(
    _version_part, _version_part, _version_part
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}")


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 16: Version end type parsing
# ---------------------------------------------------------------------------

@given(
    version=_version_str,
    vet=st.sampled_from(['lessThan', 'lessThanOrEqual']),
)
@settings(max_examples=200)
def test_version_end_type_round_trip(version, vet):
    """Version end type must be preserved through compute_safe_versions."""
    ranges = [{'version_end': version, 'version_end_type': vet, 'cve_id': 'CVE-TEST-1'}]
    result = compute_safe_versions(ranges)
    assert len(result) == 1
    if vet == 'lessThan':
        assert result[0]['operator'] == '>='
    else:
        assert result[0]['operator'] == '>'


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 17: Safe version highest bound
# ---------------------------------------------------------------------------

@given(data=st.data())
@settings(max_examples=100)
def test_safe_version_highest_bound(data):
    """Safe version must be based on the highest version_end in a branch."""
    # Generate 2-5 versions in the same branch (same major.minor)
    major = data.draw(st.integers(min_value=1, max_value=20))
    minor = data.draw(st.integers(min_value=0, max_value=50))
    patches = data.draw(st.lists(
        st.integers(min_value=0, max_value=999), min_size=2, max_size=5
    ))

    ranges = []
    for i, patch in enumerate(patches):
        ranges.append({
            'version_end': f'{major}.{minor}.{patch}',
            'version_end_type': 'lessThan',
            'cve_id': f'CVE-TEST-{i}',
        })

    result = compute_safe_versions(ranges)
    assert len(result) == 1
    assert result[0]['branch'] == f'{major}.{minor}'

    # The safe version must be the highest patch
    max_patch = max(patches)
    expected_version = f'{major}.{minor}.{max_patch}'
    assert result[0]['safe_version'] == expected_version, \
        f"Expected {expected_version}, got {result[0]['safe_version']}"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 18: Safe version boundary interpretation
# ---------------------------------------------------------------------------

@given(
    version=_version_str,
    vet=st.sampled_from(['lessThan', 'lessThanOrEqual']),
)
@settings(max_examples=200)
def test_safe_version_boundary_interpretation(version, vet):
    """lessThan -> operator '>=', lessThanOrEqual -> operator '>'."""
    ranges = [{'version_end': version, 'version_end_type': vet, 'cve_id': 'CVE-X'}]
    result = compute_safe_versions(ranges)
    assert len(result) == 1
    expected_op = '>=' if vet == 'lessThan' else '>'
    assert result[0]['operator'] == expected_op


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 19: Semver comparison total order
# ---------------------------------------------------------------------------

@given(a=_version_str, b=_version_str, c=_version_str)
@settings(max_examples=200)
def test_semver_total_order(a, b, c):
    """compare_versions must satisfy antisymmetric, transitive, total order."""
    ab = compare_versions(a, b)
    ba = compare_versions(b, a)
    bc = compare_versions(b, c)
    ac = compare_versions(a, c)

    # Antisymmetric: if a <= b and b <= a then a == b
    if ab <= 0 and ba <= 0:
        assert ab == 0 and ba == 0

    # Total: either a <= b or b <= a
    assert ab <= 0 or ba <= 0, f"Not total: compare({a},{b})={ab}, compare({b},{a})={ba}"

    # Transitive: if a <= b and b <= c then a <= c
    if ab <= 0 and bc <= 0:
        assert ac <= 0, f"Not transitive: {a}<={b} and {b}<={c} but {a}>{c}"


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 20: Unparseable version resilience
# ---------------------------------------------------------------------------

@given(
    valid_versions=st.lists(_version_str, min_size=0, max_size=3),
    invalid_versions=st.lists(
        st.text(
            alphabet=st.sampled_from('abcxyz!@#$. '),
            min_size=1, max_size=10,
        ),
        min_size=0, max_size=3,
    ),
)
@settings(max_examples=200)
def test_unparseable_version_resilience(valid_versions, invalid_versions):
    """compute_safe_versions must not raise on unparseable versions."""
    ranges = []
    for v in valid_versions:
        ranges.append({'version_end': v, 'version_end_type': 'lessThan', 'cve_id': 'CVE-V'})
    for v in invalid_versions:
        ranges.append({'version_end': v, 'version_end_type': 'lessThan', 'cve_id': 'CVE-I'})

    # Must not raise
    result = compute_safe_versions(ranges)
    assert isinstance(result, list)
    # All results must have valid structure
    for r in result:
        assert 'branch' in r
        assert 'safe_version' in r
        assert 'operator' in r
        assert 'cve_count' in r


# ---------------------------------------------------------------------------
# Feature: cve-database-website, Property 21: Version branch grouping
# ---------------------------------------------------------------------------

@given(
    major=st.integers(min_value=1, max_value=20),
    minor1=st.integers(min_value=0, max_value=50),
    minor2=st.integers(min_value=0, max_value=50),
    patch1=st.integers(min_value=0, max_value=999),
    patch2=st.integers(min_value=0, max_value=999),
)
@settings(max_examples=200)
def test_version_branch_grouping(major, minor1, minor2, patch1, patch2):
    """Same prefix -> same branch, different prefix -> different branch."""
    v1 = f'{major}.{minor1}.{patch1}'
    v2 = f'{major}.{minor2}.{patch2}'

    b1 = get_version_branch(v1)
    b2 = get_version_branch(v2)

    assert b1 is not None
    assert b2 is not None

    if minor1 == minor2:
        assert b1 == b2, f"Same prefix but different branches: {v1}->{b1}, {v2}->{b2}"
    else:
        assert b1 != b2, f"Different prefix but same branch: {v1}->{b1}, {v2}->{b2}"
