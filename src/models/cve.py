"""SQLAlchemy ORM models for CVE data.

Defines: Base, Cve, AffectedProduct, CvssScore, CweEntry, Reference.
MariaDB only — no SQLite fallback.
"""

from sqlalchemy import (
    Column, String, Text, Integer, Numeric, ForeignKey, Index,
)
from sqlalchemy.orm import relationship, DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class Cve(Base):
    __tablename__ = 'cves'

    cve_id = Column(String(30), primary_key=True)
    state = Column(String(20), index=True)
    assigner_org_id = Column(String(100))
    assigner_short_name = Column(String(100), index=True)
    date_reserved = Column(String(30))
    date_published = Column(String(30), index=True)
    date_updated = Column(String(30))
    description = Column(Text)
    severity = Column(String(20), index=True)
    data_version = Column(String(20))

    affected_products = relationship(
        'AffectedProduct', back_populates='cve', cascade='all, delete-orphan',
    )
    cvss_scores = relationship(
        'CvssScore', back_populates='cve', cascade='all, delete-orphan',
    )
    cwe_entries = relationship(
        'CweEntry', back_populates='cve', cascade='all, delete-orphan',
    )
    references = relationship(
        'Reference', back_populates='cve', cascade='all, delete-orphan',
    )


class AffectedProduct(Base):
    __tablename__ = 'affected_products'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(
        String(30), ForeignKey('cves.cve_id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    vendor = Column(String(500), index=True)
    product = Column(Text)
    platform = Column(Text)
    version_start = Column(Text)
    version_end = Column(Text)
    version_exact = Column(Text)
    default_status = Column(String(50))
    status = Column(String(50))
    version_end_type = Column(String(30))

    cve = relationship('Cve', back_populates='affected_products')


class CvssScore(Base):
    __tablename__ = 'cvss_scores'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(
        String(30), ForeignKey('cves.cve_id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    version = Column(String(10))
    vector_string = Column(String(255))
    base_score = Column(Numeric(4, 1), index=True)
    base_severity = Column(String(20))
    attack_vector = Column(String(30))
    attack_complexity = Column(String(30))
    privileges_required = Column(String(30))
    user_interaction = Column(String(30))
    scope = Column(String(30))
    confidentiality_impact = Column(String(30))
    integrity_impact = Column(String(30))
    availability_impact = Column(String(30))
    source = Column(String(50), default='cna')

    cve = relationship('Cve', back_populates='cvss_scores')


class CweEntry(Base):
    __tablename__ = 'cwe_entries'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(
        String(30), ForeignKey('cves.cve_id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    cwe_id = Column(String(30), index=True)
    description = Column(Text)

    cve = relationship('Cve', back_populates='cwe_entries')


class Reference(Base):
    __tablename__ = 'references_table'

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(
        String(30), ForeignKey('cves.cve_id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    url = Column(Text)
    tags = Column(Text)

    cve = relationship('Cve', back_populates='references')
