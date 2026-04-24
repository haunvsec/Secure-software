"""SQLAlchemy ORM models for Security Advisory data.

Defines: SecurityAdvisory, AdvisoryAffectedProduct, AdvisoryCve, AdvisoryReference.
Uses Base from models.cve to share the same metadata registry.
MariaDB only — no SQLite fallback.
"""

from sqlalchemy import (
    Column, String, Text, Integer, Numeric, ForeignKey, Index,
)
from sqlalchemy.orm import relationship

from models.cve import Base


class SecurityAdvisory(Base):
    __tablename__ = 'security_advisories'

    id = Column(String(255), primary_key=True)
    source = Column(String(50), index=True)
    title = Column(Text)
    description = Column(Text)
    severity = Column(String(20), index=True)
    cvss_score = Column(Numeric(4, 1))
    cvss_vector = Column(String(255))
    published_date = Column(String(50), index=True)
    modified_date = Column(String(50))
    url = Column(Text)
    vendor = Column(String(100))
    solution = Column(Text)
    json_file = Column(String(500))

    affected_products = relationship(
        'AdvisoryAffectedProduct', back_populates='advisory',
        cascade='all, delete-orphan',
    )
    cves = relationship(
        'AdvisoryCve', back_populates='advisory',
        cascade='all, delete-orphan',
    )
    references = relationship(
        'AdvisoryReference', back_populates='advisory',
        cascade='all, delete-orphan',
    )


class AdvisoryAffectedProduct(Base):
    __tablename__ = 'advisory_affected_products'

    id = Column(Integer, primary_key=True, autoincrement=True)
    advisory_id = Column(
        String(255), ForeignKey('security_advisories.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    vendor = Column(String(500), index=True)
    product = Column(String(2048))
    version_range = Column(String(500))
    fixed_version = Column(String(500))

    advisory = relationship('SecurityAdvisory', back_populates='affected_products')


class AdvisoryCve(Base):
    __tablename__ = 'advisory_cves'

    id = Column(Integer, primary_key=True, autoincrement=True)
    advisory_id = Column(
        String(255), ForeignKey('security_advisories.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    cve_id = Column(String(30), index=True)

    advisory = relationship('SecurityAdvisory', back_populates='cves')


class AdvisoryReference(Base):
    __tablename__ = 'advisory_references'

    id = Column(Integer, primary_key=True, autoincrement=True)
    advisory_id = Column(
        String(255), ForeignKey('security_advisories.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    url = Column(Text)

    advisory = relationship('SecurityAdvisory', back_populates='references')


class SyncState(Base):
    """Tracks last imported git commit hash per data source."""
    __tablename__ = 'sync_state'

    source = Column(String(50), primary_key=True)
    last_commit_hash = Column(String(64))
    last_sync_time = Column(String(50))
    files_changed = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    status = Column(String(20), default='success')
