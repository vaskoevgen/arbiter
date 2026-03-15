"""Conflict detection and resolution: three-step protocol, append-only log."""

from .config import load_config
from .detector import ConflictDetector
from .errors import (
    ConflictConfigError,
    ConflictNotFoundError,
    ConflictResolutionError,
    ConflictStoreError,
)
from .models import (
    ConflictErrorCode,
    ConflictRecord,
    ConflictResolverConfig,
    ConflictSignal,
    ConflictSummary,
    NodeValue,
    Resolution,
    ResolutionStatus,
    ResolutionStrategy,
    SpanFieldReport,
)
from .protocols import (
    AuthorityLookup,
    ConflictStore,
    SignalEmitter,
    TrustLookup,
)
from .resolver import ConflictResolver

# Module-level convenience aliases matching contract function names
ingest = ConflictDetector.ingest
flush = ConflictDetector.flush
resolve = ConflictResolver.resolve
submit_human_review = ConflictResolver.submit_human_review
get_unresolved = ConflictResolver.get_unresolved
has_blocking_conflicts = ConflictResolver.has_blocking_conflicts
get_summary = ConflictResolver.get_summary
verify_log_integrity = ConflictResolver.verify_log_integrity

__all__ = [
    # Enums
    "ResolutionStatus",
    "ResolutionStrategy",
    "ConflictErrorCode",
    # Models
    "NodeValue",
    "Resolution",
    "ConflictRecord",
    "ConflictResolverConfig",
    "ConflictSignal",
    "SpanFieldReport",
    "ConflictSummary",
    # Protocols
    "TrustLookup",
    "AuthorityLookup",
    "SignalEmitter",
    "ConflictStore",
    # Classes
    "ConflictDetector",
    "ConflictResolver",
    # Errors
    "ConflictResolutionError",
    "ConflictStoreError",
    "ConflictNotFoundError",
    "ConflictConfigError",
    # Functions
    "ingest",
    "flush",
    "resolve",
    "submit_human_review",
    "get_unresolved",
    "has_blocking_conflicts",
    "get_summary",
    "verify_log_integrity",
    "load_config",
]
