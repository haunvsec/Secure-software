"""SQLAlchemy ORM models for Secure Software Board.

Re-exports all ORM classes from models.cve and models.advisory
for backward compatibility. New code should import directly from
models.cve or models.advisory.
"""

from models.cve import (  # noqa: F401
    Base,
    Cve,
    AffectedProduct,
    CvssScore,
    CweEntry,
    Reference,
)

from models.advisory import (  # noqa: F401
    SecurityAdvisory,
    AdvisoryAffectedProduct,
    AdvisoryCve,
    AdvisoryReference,
)
