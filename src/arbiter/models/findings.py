"""Finding models for consistency, access, and taint analysis. All frozen and strict."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .enums import DataTier, FindingSeverity
from .types import AuthorityDomain, NodeId, UtcDatetime

__all__ = [
    "ConsistencyFinding",
    "AccessFinding",
    "TaintFinding",
    "ConflictRecord",
    "StigmerySignal",
]


class ConsistencyFinding(BaseModel):
    """A finding from consistency analysis between adapter ground truth and node self-reports."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    node: NodeId
    severity: FindingSeverity
    field: str
    adapter_value: str
    claimed_value: str
    detail: str


class AccessFinding(BaseModel):
    """A finding from access audit analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    node: NodeId
    severity: FindingSeverity
    data_tier: DataTier
    authority_domain: AuthorityDomain
    violation_type: str
    detail: str


class TaintFinding(BaseModel):
    """A finding from taint/data-flow analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    source_node: NodeId
    sink_node: NodeId
    severity: FindingSeverity
    data_tier: DataTier
    path: list[NodeId]
    detail: str


class ConflictRecord(BaseModel):
    """A record of a detected conflict between nodes or authority claims."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    conflict_id: str
    nodes: list[NodeId] = Field(min_length=2)
    authority_domain: AuthorityDomain
    conflict_type: str
    detail: str
    resolved: bool


class StigmerySignal(BaseModel):
    """A stigmergic coordination signal for indirect communication between Arbiter components."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    signal_id: str
    source_node: NodeId
    signal_type: str
    payload: dict[str, object]
    ttl_seconds: int = Field(ge=1)
