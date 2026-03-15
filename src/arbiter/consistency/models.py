"""Pydantic v2 models and enums for the consistency analyzer package."""

from __future__ import annotations

from enum import Enum
from typing import NewType

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ConsistencyOutcome",
    "FindingSeverity",
    "NodeId",
    "SpanId",
    "TraceId",
    "FieldSet",
    "AdapterObservation",
    "NodeAuditClaim",
    "ConsistencyFinding",
    "AnalysisPair",
    "AnalysisPairList",
    "ConsistencyFindingList",
    "OptionalNodeAuditClaim",
    "OptionalAdapterObservation",
    "OptionalTimestamp",
    "ConsistencyAnalysisError",
]

NodeId = NewType("NodeId", str)
SpanId = NewType("SpanId", str)
TraceId = NewType("TraceId", str)

FieldSet = frozenset[str]
OptionalTimestamp = str | None

# ── Enums ──────────────────────────────────────────────


class ConsistencyOutcome(str, Enum):
    """Outcome of comparing adapter observation against node audit claim."""

    CONSISTENT = "CONSISTENT"
    INCONSISTENT = "INCONSISTENT"
    MISSING_CLAIM = "MISSING_CLAIM"
    MISSING_OBSERVATION = "MISSING_OBSERVATION"


class FindingSeverity(str, Enum):
    """Severity level for a consistency finding."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# ── Frozen models ──────────────────────────────────────


class AdapterObservation(BaseModel):
    """Adapter ground-truth observation of a span's I/O fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    span_id: SpanId = Field(..., min_length=1)
    trace_id: TraceId = Field(..., min_length=1)
    node_id: NodeId = Field(..., min_length=1)
    observed_fields: frozenset[str]
    timestamp: str


class NodeAuditClaim(BaseModel):
    """Node self-reported audit event declaring accessed/produced fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    span_id: SpanId = Field(..., min_length=1)
    trace_id: TraceId = Field(..., min_length=1)
    node_id: NodeId = Field(..., min_length=1)
    claimed_fields: frozenset[str]
    timestamp: str


class ConsistencyFinding(BaseModel):
    """Result of comparing one adapter observation against one node audit claim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1)
    node_id: NodeId
    span_id: SpanId
    trace_id: TraceId
    outcome: ConsistencyOutcome
    severity: FindingSeverity
    observed_fields: frozenset[str]
    claimed_fields: frozenset[str]
    unexplained_fields: frozenset[str]
    overclaimed_fields: frozenset[str]
    analyzed_at: str
    details: str | None = None


class AnalysisPair(BaseModel):
    """Paired observation and claim for batch analysis."""

    model_config = ConfigDict(extra="forbid")

    observation: AdapterObservation | None = None
    claim: NodeAuditClaim | None = None


# Type aliases
OptionalNodeAuditClaim = NodeAuditClaim | None
OptionalAdapterObservation = AdapterObservation | None
AnalysisPairList = list[AnalysisPair]
ConsistencyFindingList = list[ConsistencyFinding]


class ConsistencyAnalysisError(Exception):
    """Raised for malformed or invalid inputs to analysis functions."""

    def __init__(self, node_id: str, span_id: str, detail: str) -> None:
        self.node_id = node_id
        self.span_id = span_id
        self.detail = detail
        super().__init__(detail)
