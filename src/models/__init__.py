"""Models package for Secure Software Board.

Re-exports all model functions for backward compatibility.
Each module corresponds to a database table group:
  - helpers: DB helpers, sanitization, pagination
  - cves: CVE records, CVSS, CWE, references
  - browse: Browse by date, type, severity, assigner
  - vendors: Vendor listing and detail
  - products: Product listing, detail, versions, fixed CVEs
  - search: Multi-criteria search
  - advisories: Security advisories
"""

from models.helpers import (
    _fetchone, _fetchall, _execute,
    sanitize_page, sanitize_severity, sanitize_year, sanitize_search,
    get_paginated_result, _VALID_SEVERITIES,
)

from models.browse import _MONTH_NAMES

from models.cves import (
    get_stats, get_cves, get_latest_cves,
    get_cve_detail, get_cve_cvss, get_cve_affected,
    get_cve_cwes, get_cve_references,
)

from models.browse import (
    get_years_with_counts, get_months_for_year, get_cves_by_month,
    get_cwe_types, get_cves_by_cwe,
    get_severity_summary, get_cves_by_severity,
    get_assigners, get_cves_by_assigner,
)

from models.vendors import (
    get_vendors, get_vendor_detail, get_vendor_products,
    get_products, get_product_detail, get_product_cves,
)

from models.products import (
    get_product_versions, get_version_detail, get_version_cves,
    get_safe_version_references, get_fixed_cves_by_branch,
)

from models.search import search_cves, get_product_version_ranges

from models.advisories import (
    get_advisories, get_advisory_sources, get_advisory_detail,
    get_advisory_affected, get_advisory_cves, get_advisory_refs,
    get_product_advisories,
)
