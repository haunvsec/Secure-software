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


def merge_advisory_into_safe_versions(safe_versions: list[dict],
                                       advisories: list[dict]) -> list[dict]:
    """Merge advisory fixed_version data into safe version suggestions.

    If advisories exist with fixed_version data, only show branches that
    appear in advisories. Adds 'from_advisory' flag and advisory metadata.
    Marks branches without fixed_version as potentially end-of-support.

    Args:
        safe_versions: existing safe version list from compute_safe_versions
        advisories: list of advisory dicts with version_range, fixed_version, etc.

    Returns:
        Updated safe_versions list. If advisories have fixed_version data,
        returns advisory-based suggestions instead.
    """
    if not advisories:
        return safe_versions

    # Collect fixed versions from advisories
    advisory_branches: dict[str, dict] = {}
    has_any_fixed = False

    for adv in advisories:
        fv = adv.get('fixed_version', '')
        vr = adv.get('version_range', '')
        if not fv or fv in ('unspecified', 'n/a', '', '-'):
            # Advisory without fixed version — might be end-of-support
            if vr:
                # Try to extract branch from version_range (e.g. "<= 5.7.22")
                vr_clean = vr.replace('<=', '').replace('<', '').replace('>=', '').replace('>', '').strip()
                branch = get_version_branch(vr_clean)
                if branch and branch not in advisory_branches:
                    advisory_branches[branch] = {
                        'safe_version': None,
                        'operator': '',
                        'end_of_support': True,
                        'advisory_id': adv.get('id', ''),
                        'advisory_url': adv.get('url', ''),
                        'advisory_title': adv.get('title', ''),
                    }
            continue

        has_any_fixed = True
        parsed = parse_version(fv)
        if parsed is None:
            continue

        branch = get_version_branch(fv)
        if branch is None:
            continue

        # Determine operator from version_range
        operator = '>='
        if vr:
            if '<=' in vr:
                operator = '>'
            elif '<' in vr:
                operator = '>='

        if branch not in advisory_branches:
            advisory_branches[branch] = {
                'safe_version': fv,
                'parsed': parsed,
                'operator': operator,
                'end_of_support': False,
                'advisory_id': adv.get('id', ''),
                'advisory_url': adv.get('url', ''),
                'advisory_title': adv.get('title', ''),
            }
        else:
            existing = advisory_branches[branch]
            if existing.get('end_of_support'):
                # Replace end-of-support with actual fix
                advisory_branches[branch] = {
                    'safe_version': fv,
                    'parsed': parsed,
                    'operator': operator,
                    'end_of_support': False,
                    'advisory_id': adv.get('id', ''),
                    'advisory_url': adv.get('url', ''),
                    'advisory_title': adv.get('title', ''),
                }
            elif existing.get('parsed'):
                # Keep the highest fixed version
                max_len = max(len(parsed), len(existing['parsed']))
                padded_new = parsed + (0,) * (max_len - len(parsed))
                padded_old = existing['parsed'] + (0,) * (max_len - len(existing['parsed']))
                if padded_new > padded_old:
                    existing['safe_version'] = fv
                    existing['parsed'] = parsed
                    existing['operator'] = operator
                    existing['advisory_id'] = adv.get('id', '')
                    existing['advisory_url'] = adv.get('url', '')

    if not has_any_fixed:
        return safe_versions

    # Build result from advisory branches, sorted by version desc
    result = []
    for branch, entry in sorted(advisory_branches.items(),
                                  key=lambda x: x[1].get('parsed', (0,)),
                                  reverse=True):
        item = {
            'branch': branch,
            'safe_version': entry.get('safe_version', ''),
            'operator': entry.get('operator', ''),
            'from_advisory': True,
            'end_of_support': entry.get('end_of_support', False),
            'advisory_id': entry.get('advisory_id', ''),
            'advisory_url': entry.get('advisory_url', ''),
            'advisory_title': entry.get('advisory_title', ''),
            'cve_count': 0,
            'cve_ids': [],
            'max_cve_id': '',
        }

        # Try to get cve_count from original safe_versions for this branch
        for sv in safe_versions:
            if sv['branch'] == branch:
                item['cve_count'] = sv['cve_count']
                item['cve_ids'] = sv.get('cve_ids', [])
                item['max_cve_id'] = sv.get('max_cve_id', '')
                break

        result.append(item)

    return result
