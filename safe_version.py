"""Safe version suggestion algorithm for CVE Database Website.

Analyzes version range data from CVE records to suggest the minimum safe
version for each version branch of a product.
"""


def parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse version string into a tuple of integers.

    Splits on '.', converts each part to int. Returns None if any part
    is not a valid integer.

    Examples:
        '6.3.14' -> (6, 3, 14)
        '2.4'    -> (2, 4)
        'abc'    -> None
    """
    if not version_str or not isinstance(version_str, str):
        return None
    parts = version_str.strip().split('.')
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1.

    Pads shorter version with zeros for comparison.
    Returns 0 if either version cannot be parsed.
    """
    t1 = parse_version(v1)
    t2 = parse_version(v2)
    if t1 is None or t2 is None:
        return 0
    # Pad to equal length
    max_len = max(len(t1), len(t2))
    t1 = t1 + (0,) * (max_len - len(t1))
    t2 = t2 + (0,) * (max_len - len(t2))
    if t1 < t2:
        return -1
    elif t1 > t2:
        return 1
    return 0


def get_version_branch(version_str: str) -> str | None:
    """Determine the version branch (all parts except the last).

    Examples:
        '6.3.14' -> '6.3'
        '2.4.54' -> '2.4'
        '5'      -> '*'
    Returns None if version cannot be parsed.
    """
    parsed = parse_version(version_str)
    if parsed is None:
        return None
    if len(parsed) <= 1:
        return '*'
    return '.'.join(str(p) for p in parsed[:-1])


def compute_safe_versions(version_ranges: list[dict]) -> list[dict]:
    """Compute safe version suggestions from version range data.

    Args:
        version_ranges: list of dicts with keys:
            - version_end: str (e.g. '6.3.14')
            - version_end_type: str ('lessThan' or 'lessThanOrEqual')
            - cve_id: str

    Returns:
        list of dicts with keys:
            - branch: str (e.g. '6.3')
            - safe_version: str (e.g. '6.3.14')
            - operator: str ('>=' or '>')
            - cve_count: int
        Sorted by branch.
    """
    if not version_ranges:
        return []

    # Group by branch, tracking max version_end per branch
    branches: dict[str, dict] = {}

    for vr in version_ranges:
        ve = vr.get('version_end', '')
        vet = vr.get('version_end_type', '') or 'lessThan'
        cve_id = vr.get('cve_id', '')

        if not ve:
            continue

        branch = get_version_branch(ve)
        if branch is None:
            continue  # Skip unparseable versions

        parsed = parse_version(ve)
        if parsed is None:
            continue

        if branch not in branches:
            branches[branch] = {
                'max_version': ve,
                'max_parsed': parsed,
                'max_cve_id': cve_id,
                'version_end_type': vet,
                'cve_ids': {cve_id},
            }
        else:
            entry = branches[branch]
            entry['cve_ids'].add(cve_id)
            # Pad for comparison
            max_len = max(len(parsed), len(entry['max_parsed']))
            padded_new = parsed + (0,) * (max_len - len(parsed))
            padded_old = entry['max_parsed'] + (0,) * (max_len - len(entry['max_parsed']))
            if padded_new > padded_old:
                entry['max_version'] = ve
                entry['max_parsed'] = parsed
                entry['max_cve_id'] = cve_id
                entry['version_end_type'] = vet

    # Build result, sorted by branch descending (highest version first)
    result = []
    for branch, entry in sorted(branches.items(),
                                 key=lambda x: x[1]['max_parsed'],
                                 reverse=True):
        vet = entry['version_end_type']
        operator = '>=' if vet == 'lessThan' else '>'
        result.append({
            'branch': branch,
            'safe_version': entry['max_version'],
            'operator': operator,
            'cve_count': len(entry['cve_ids']),
            'cve_ids': list(entry['cve_ids']),
            'max_cve_id': entry['max_cve_id'],
        })

    return result
