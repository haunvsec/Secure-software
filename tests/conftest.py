"""Test fixtures for CVE Database Website.

Provides an in-memory SQLite test database with ~100 representative CVE records
covering all severity levels, multiple vendors/products, CWE types, and assigners.
"""

import sqlite3
import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _create_test_db():
    """Create an in-memory SQLite database with test data."""
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row

    db.executescript("""
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY, state TEXT, assigner_org_id TEXT,
            assigner_short_name TEXT, date_reserved TEXT, date_published TEXT,
            date_updated TEXT, description TEXT, severity TEXT, data_version TEXT
        );
        CREATE TABLE affected_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
            vendor TEXT, product TEXT, platform TEXT, version_start TEXT,
            version_end TEXT, version_exact TEXT, default_status TEXT,
            status TEXT, version_end_type TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );
        CREATE TABLE cvss_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
            version TEXT, vector_string TEXT, base_score REAL,
            base_severity TEXT, attack_vector TEXT, attack_complexity TEXT,
            privileges_required TEXT, user_interaction TEXT, scope TEXT,
            confidentiality_impact TEXT, integrity_impact TEXT,
            availability_impact TEXT, source TEXT DEFAULT 'cna',
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );
        CREATE TABLE cwe_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
            cwe_id TEXT, description TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );
        CREATE TABLE references_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
            url TEXT, tags TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE INDEX idx_cves_state ON cves(state);
        CREATE INDEX idx_cves_date_published ON cves(date_published);
        CREATE INDEX idx_cves_severity ON cves(severity);
        CREATE INDEX idx_cves_assigner ON cves(assigner_short_name);
        CREATE INDEX idx_affected_vendor ON affected_products(vendor);
        CREATE INDEX idx_affected_product ON affected_products(product);
        CREATE INDEX idx_affected_vendor_product ON affected_products(vendor, product);
        CREATE INDEX idx_affected_cve ON affected_products(cve_id);
        CREATE INDEX idx_cvss_cve ON cvss_scores(cve_id);
        CREATE INDEX idx_cvss_score ON cvss_scores(base_score);
        CREATE INDEX idx_cwe_cve ON cwe_entries(cve_id);
        CREATE INDEX idx_cwe_id ON cwe_entries(cwe_id);
    """)

    # Insert ~100 CVE records across different years, severities, assigners
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    assigners = ['mitre', 'nvd', 'patchstack', 'github', 'redhat']
    vendors = ['microsoft', 'google', 'apple', 'linux', 'apache']
    products = {
        'microsoft': ['windows', 'office', 'edge'],
        'google': ['chrome', 'android'],
        'apple': ['macos', 'ios', 'safari'],
        'linux': ['kernel'],
        'apache': ['httpd', 'tomcat'],
    }
    cwes = [
        ('CWE-79', 'Cross-site Scripting (XSS)'),
        ('CWE-89', 'SQL Injection'),
        ('CWE-120', 'Buffer Overflow'),
        ('CWE-200', 'Information Exposure'),
        ('CWE-416', 'Use After Free'),
    ]
    scores = {
        'CRITICAL': (9.8, 'CRITICAL'), 'HIGH': (7.5, 'HIGH'),
        'MEDIUM': (5.5, 'MEDIUM'), 'LOW': (2.1, 'LOW'),
    }

    cve_num = 1000
    for year in [2020, 2021, 2022, 2023, 2024]:
        for month in ['01', '03', '06', '09', '12']:
            for sev_idx, sev in enumerate(severities):
                for v_idx, vendor in enumerate(vendors):
                    cve_id = f'CVE-{year}-{cve_num}'
                    cve_num += 1
                    assigner = assigners[v_idx % len(assigners)]
                    prod_list = products[vendor]
                    prod = prod_list[cve_num % len(prod_list)]
                    cwe = cwes[sev_idx % len(cwes)]
                    score, base_sev = scores[sev]
                    date_pub = f'{year}-{month}-15T00:00:00'

                    db.execute(
                        "INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (cve_id, 'PUBLISHED', f'org-{assigner}', assigner,
                         f'{year}-01-01T00:00:00', date_pub,
                         f'{year}-{month}-20T00:00:00',
                         f'Test vulnerability {cve_id} in {vendor} {prod} - {sev} severity buffer overflow issue',
                         sev, '5.1.0')
                    )
                    db.execute(
                        "INSERT INTO affected_products "
                        "(cve_id, vendor, product, platform, version_start, version_end, "
                        "version_exact, default_status, status, version_end_type) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (cve_id, vendor, prod, '', '1.0',
                         f'{sev_idx + 1}.{v_idx}.{cve_num % 20}',
                         '', 'unaffected', 'affected', 'lessThan')
                    )
                    db.execute(
                        "INSERT INTO cvss_scores "
                        "(cve_id, version, vector_string, base_score, base_severity, "
                        "attack_vector, attack_complexity, privileges_required, "
                        "user_interaction, scope, confidentiality_impact, "
                        "integrity_impact, availability_impact, source) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (cve_id, '3.1', f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                         score, base_sev, 'NETWORK', 'LOW', 'NONE', 'NONE',
                         'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 'cna')
                    )
                    db.execute(
                        "INSERT INTO cwe_entries (cve_id, cwe_id, description) VALUES (?,?,?)",
                        (cve_id, cwe[0], cwe[1])
                    )
                    db.execute(
                        "INSERT INTO references_table (cve_id, url, tags) VALUES (?,?,?)",
                        (cve_id, f'https://example.com/{cve_id}', 'vendor-advisory')
                    )

    # Add a few with n/a vendor and empty vendor for exclusion tests
    for i in range(3):
        cve_id = f'CVE-2024-{9990 + i}'
        db.execute(
            "INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)",
            (cve_id, 'PUBLISHED', 'org-mitre', 'mitre',
             '2024-01-01', '2024-06-01T00:00:00', '2024-06-05',
             f'Test CVE with bad vendor {i}', 'HIGH', '5.1.0')
        )
        vendor_val = 'n/a' if i == 0 else ('' if i == 1 else 'valid_vendor')
        db.execute(
            "INSERT INTO affected_products "
            "(cve_id, vendor, product, platform, version_start, version_end, "
            "version_exact, default_status, status, version_end_type) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (cve_id, vendor_val, 'some_product', '', '', '', '', '', '', '')
        )

    # Add version range data for safe version tests
    for i in range(5):
        cve_id = f'CVE-2024-{8000 + i}'
        db.execute(
            "INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)",
            (cve_id, 'PUBLISHED', 'org-test', 'test',
             '2024-01-01', '2024-07-01T00:00:00', '2024-07-05',
             f'Version range test CVE {i}', 'HIGH', '5.1.0')
        )
        vet = 'lessThanOrEqual' if i % 2 == 0 else 'lessThan'
        db.execute(
            "INSERT INTO affected_products "
            "(cve_id, vendor, product, platform, version_start, version_end, "
            "version_exact, default_status, status, version_end_type) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (cve_id, 'apache', 'httpd', '', '2.4.0',
             f'2.4.{50 + i}', '', 'unaffected', 'affected', vet)
        )

    # Add a REJECTED CVE to test state filtering
    db.execute(
        "INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)",
        ('CVE-2024-9999', 'REJECTED', 'org-mitre', 'mitre',
         '2024-01-01', '2024-01-15T00:00:00', '2024-01-20',
         'Rejected CVE', '', '5.1.0')
    )

    db.commit()
    return db


@pytest.fixture
def test_db():
    """Provide a fresh in-memory test database for each test."""
    db = _create_test_db()
    yield db
    db.close()


@pytest.fixture
def app_client():
    """Provide a Flask test client with the real database."""
    from app import app
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client
