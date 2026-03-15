"""StrEnum definitions for Arbiter. Explicit string values for stable serialization."""

from enum import StrEnum

__all__ = [
    "TrustTier",
    "DataTier",
    "BlastTier",
    "FindingSeverity",
    "TrustEventType",
]


class TrustTier(StrEnum):
    """Trust classification tiers. Display only -- policy must use raw TrustScore."""

    PROBATIONARY = "PROBATIONARY"
    LOW = "LOW"
    ESTABLISHED = "ESTABLISHED"
    HIGH = "HIGH"
    TRUSTED = "TRUSTED"


class DataTier(StrEnum):
    """Data classification tiers. Determines sensitivity level and handling requirements."""

    PUBLIC = "PUBLIC"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    AUTH = "AUTH"
    COMPLIANCE = "COMPLIANCE"


class BlastTier(StrEnum):
    """Blast-radius classification tiers. Determines rollout strategy for changes."""

    AUTO_MERGE = "AUTO_MERGE"
    SOAK = "SOAK"
    HUMAN_GATE = "HUMAN_GATE"


class FindingSeverity(StrEnum):
    """Finding severity levels in audit results."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrustEventType(StrEnum):
    """Trust event categories recorded in the ledger."""

    AUDIT_PASS = "AUDIT_PASS"
    AUDIT_FAIL = "AUDIT_FAIL"
    CONSISTENCY_CHECK = "CONSISTENCY_CHECK"
    ACCESS_VIOLATION = "ACCESS_VIOLATION"
    TAINT_DETECTED = "TAINT_DETECTED"
    CANARY_TRIGGERED = "CANARY_TRIGGERED"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"
    DECAY = "DECAY"
    INITIAL = "INITIAL"
