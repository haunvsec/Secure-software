"""Test fixtures for Secure Software Board.

Uses SQLAlchemy with in-memory SQLite for testing. Creates ORM tables
and populates with representative CVE records (~100 CVEs).
"""

import pytest
import sys
import os

# Add project src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from models.orm import Base


def _sqlite_regexp(pattern, string):
    """SQLite REGEXP function implementation."""
    import re
    return bool(re.search(pattern, string or ''))


def _create_test_session():
    """Create an in-memory SQLite database with SQLAlchemy ORM and test data."""
    engine = create_engine('sqlite://', echo=False)

    # Register REGEXP function for SQLite (MariaDB has it natively)
    @event.listens_for(engine, 'connect')
    def _on_connect(dbapi_conn, connection_record):
        dbapi_conn.create_function('REGEXP', 2, _sqlite_regexp)
        # SQLAlchemy uses CONCAT which SQLite doesn't have natively,
        # but SQLAlchemy's func.concat compiles to || on SQLite.

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    _populate_test_data(session)
    return session, engine


def _populate_test_data(session):
    """Insert ~100 CVE records across different years, severities, assigners."""
    from models.orm import (
        Cve, AffectedProduct, CvssScore, CweEntry, Reference,
    )

    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    assigners = ['mitre', 'nvd', 'patchstack', 'github', 'redhat']
    vendors = ['microsoft', 'google', 'apple', 'linux', 'apache']
    products_map = {
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
                    prod_list = products_map[vendor]
                    prod = prod_list[cve_num % len(prod_list)]
                    cwe = cwes[sev_idx % len(cwes)]
                    score, base_sev = scores[sev]
                    date_pub = f'{year}-{month}-15T00:00:00'

                    session.add(Cve(
                        cve_id=cve_id, state='PUBLISHED',
                        assigner_org_id=f'org-{assigner}',
                        assigner_short_name=assigner,
                        date_reserved=f'{year}-01-01T00:00:00',
                        date_published=date_pub,
                        date_updated=f'{year}-{month}-20T00:00:00',
                        description=f'Test vulnerability {cve_id} in {vendor} {prod} - {sev} severity buffer overflow issue',
                        severity=sev, data_version='5.1.0',
                    ))
                    session.add(AffectedProduct(
                        cve_id=cve_id, vendor=vendor, product=prod,
                        platform='', version_start='1.0',
                        version_end=f'{sev_idx + 1}.{v_idx}.{cve_num % 20}',
                        version_exact='', default_status='unaffected',
                        status='affected', version_end_type='lessThan',
                    ))
                    session.add(CvssScore(
                        cve_id=cve_id, version='3.1',
                        vector_string='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        base_score=score, base_severity=base_sev,
                        attack_vector='NETWORK', attack_complexity='LOW',
                        privileges_required='NONE', user_interaction='NONE',
                        scope='UNCHANGED', confidentiality_impact='HIGH',
                        integrity_impact='HIGH', availability_impact='HIGH',
                        source='cna',
                    ))
                    session.add(CweEntry(
                        cve_id=cve_id, cwe_id=cwe[0], description=cwe[1],
                    ))
                    session.add(Reference(
                        cve_id=cve_id,
                        url=f'https://example.com/{cve_id}',
                        tags='vendor-advisory',
                    ))

    # Add a few with n/a vendor and empty vendor for exclusion tests
    for i in range(3):
        cve_id = f'CVE-2024-{9990 + i}'
        session.add(Cve(
            cve_id=cve_id, state='PUBLISHED',
            assigner_org_id='org-mitre', assigner_short_name='mitre',
            date_reserved='2024-01-01', date_published='2024-06-01T00:00:00',
            date_updated='2024-06-05',
            description=f'Test CVE with bad vendor {i}',
            severity='HIGH', data_version='5.1.0',
        ))
        vendor_val = 'n/a' if i == 0 else ('' if i == 1 else 'valid_vendor')
        session.add(AffectedProduct(
            cve_id=cve_id, vendor=vendor_val, product='some_product',
            platform='', version_start='', version_end='',
            version_exact='', default_status='', status='',
            version_end_type='',
        ))

    # Add version range data for safe version tests
    for i in range(5):
        cve_id = f'CVE-2024-{8000 + i}'
        session.add(Cve(
            cve_id=cve_id, state='PUBLISHED',
            assigner_org_id='org-test', assigner_short_name='test',
            date_reserved='2024-01-01', date_published='2024-07-01T00:00:00',
            date_updated='2024-07-05',
            description=f'Version range test CVE {i}',
            severity='HIGH', data_version='5.1.0',
        ))
        vet = 'lessThanOrEqual' if i % 2 == 0 else 'lessThan'
        session.add(AffectedProduct(
            cve_id=cve_id, vendor='apache', product='httpd',
            platform='', version_start='2.4.0',
            version_end=f'2.4.{50 + i}',
            version_exact='', default_status='unaffected',
            status='affected', version_end_type=vet,
        ))

    # Add a REJECTED CVE to test state filtering
    session.add(Cve(
        cve_id='CVE-2024-9999', state='REJECTED',
        assigner_org_id='org-mitre', assigner_short_name='mitre',
        date_reserved='2024-01-01', date_published='2024-01-15T00:00:00',
        date_updated='2024-01-20',
        description='Rejected CVE', severity='', data_version='5.1.0',
    ))

    session.commit()


@pytest.fixture
def test_db():
    """Provide a fresh SQLAlchemy session for each test.

    Returns a session object that can be passed directly to query functions
    in models.queries (which accept Session as first argument).
    """
    session, engine = _create_test_session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def app_client():
    """Provide a Flask test client with the real database."""
    from app import create_app
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client
