"""Consistency analyzer package."""

from .analyzer import analyze_batch, analyze_span
from .models import (
    AdapterObservation,
    AnalysisPair,
    AnalysisPairList,
    ConsistencyAnalysisError,
    ConsistencyFinding,
    ConsistencyFindingList,
    ConsistencyOutcome,
    FieldSet,
    FindingSeverity,
    NodeAuditClaim,
    OptionalAdapterObservation,
    OptionalNodeAuditClaim,
    OptionalTimestamp,
)
from .store import FindingStore

# Module-level store instance for the persist/get_by_node/get_by_span/
# has_high_severity free functions required by the contract.
_default_store = FindingStore()


def persist(finding: ConsistencyFinding) -> None:
    """Append a finding to the default in-memory store."""
    _default_store.persist(finding)


def get_by_node(node_id: str) -> ConsistencyFindingList:
    """Retrieve findings for *node_id* from the default store."""
    return _default_store.get_by_node(node_id)


def get_by_span(span_id: str) -> ConsistencyFindingList:
    """Retrieve findings for *span_id* from the default store."""
    return _default_store.get_by_span(span_id)


def has_high_severity(
    node_id: str,
    since: OptionalTimestamp = None,
) -> bool:
    """Check for HIGH severity findings in the default store."""
    return _default_store.has_high_severity(node_id, since=since)


__all__ = [
    "FieldSet",
    "ConsistencyOutcome",
    "FindingSeverity",
    "AdapterObservation",
    "NodeAuditClaim",
    "ConsistencyFinding",
    "OptionalNodeAuditClaim",
    "OptionalAdapterObservation",
    "AnalysisPair",
    "AnalysisPairList",
    "ConsistencyFindingList",
    "OptionalTimestamp",
    "ConsistencyAnalysisError",
    "analyze_span",
    "analyze_batch",
    "persist",
    "get_by_node",
    "get_by_span",
    "has_high_severity",
    "FindingStore",
]
