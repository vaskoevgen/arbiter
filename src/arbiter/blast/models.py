"""Pydantic v2 models and enums for the blast radius package."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import NewType, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "DataTier",
    "ActionCategory",
    "NodeId",
    "NodeMetadata",
    "AccessGraphEdge",
    "AccessGraph",
    "NodeBlastDetail",
    "TraversalResult",
    "ClassificationResult",
    "SoakParams",
    "BlastResult",
    "HumanGateNotifier",
    "DATA_TIER_SEVERITY",
    "ACTION_SEVERITY",
]

NodeId = NewType("NodeId", str)

# ── Enums ──────────────────────────────────────────────


class DataTier(str, Enum):
    """Data classification tier with total severity order."""

    PUBLIC = "PUBLIC"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    AUTH = "AUTH"
    COMPLIANCE = "COMPLIANCE"


class ActionCategory(str, Enum):
    """Blast radius action classification with total severity order."""

    AUTO_MERGE = "AUTO_MERGE"
    SOAK = "SOAK"
    HUMAN_GATE = "HUMAN_GATE"


# Severity orderings (higher index == more severe)
DATA_TIER_SEVERITY: dict[DataTier, int] = {
    DataTier.PUBLIC: 0,
    DataTier.PII: 1,
    DataTier.FINANCIAL: 2,
    DataTier.AUTH: 3,
    DataTier.COMPLIANCE: 4,
}

ACTION_SEVERITY: dict[ActionCategory, int] = {
    ActionCategory.AUTO_MERGE: 0,
    ActionCategory.SOAK: 1,
    ActionCategory.HUMAN_GATE: 2,
}

# ── Frozen models ──────────────────────────────────────


class NodeMetadata(BaseModel):
    """Immutable metadata for a single node in the access graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: NodeId = Field(..., min_length=1)
    data_tier: DataTier
    trust_score: float = Field(..., ge=0.0, le=1.0)
    authorized_tiers: list[DataTier]
    is_authoritative: bool


class AccessGraphEdge(BaseModel):
    """A directed edge in the access graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: NodeId
    target: NodeId


class AccessGraph(BaseModel):
    """Mutable access graph with adjacency list and node metadata."""

    model_config = ConfigDict(extra="forbid")

    adjacency: dict[NodeId, list[NodeId]] = Field(default_factory=dict)
    metadata: dict[NodeId, NodeMetadata] = Field(default_factory=dict)


class NodeBlastDetail(BaseModel):
    """Per-node detail within a blast radius result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: NodeId
    data_tier: DataTier
    trust_score: float
    is_authoritative: bool
    is_authorized_for_tier: bool
    node_action: ActionCategory
    depth: int = Field(..., ge=0)


class TraversalResult(BaseModel):
    """Result of BFS traversal of the access graph from an origin node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    origin: NodeId
    reachable_nodes: frozenset[NodeId]
    node_details: list[NodeBlastDetail]
    highest_data_tier: DataTier
    max_depth_reached: int
    cycle_detected: bool


class ClassificationResult(BaseModel):
    """Result of blast radius classification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: ActionCategory
    legal_flag: bool
    contributing_nodes: list[NodeId]


class SoakParams(BaseModel):
    """Parameters for soak duration computation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    base_durations: dict[DataTier, timedelta]
    target_requests: float = Field(..., gt=0.0)
    observed_rate_rps: float = Field(..., gt=0.0)
    low_trust_threshold: float = Field(default=0.3, ge=0.0, le=1.0)


class BlastResult(BaseModel):
    """Complete blast radius evaluation result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    origin_node: NodeId
    reachable_nodes: frozenset[NodeId]
    highest_data_tier: DataTier
    action: ActionCategory
    legal_flag: bool
    soak_duration: timedelta | None = None
    per_node_details: list[NodeBlastDetail]
    computed_at: datetime
    cycle_detected: bool
    max_depth_reached: int
    contributing_nodes: list[NodeId]


@runtime_checkable
class HumanGateNotifier(Protocol):
    """Protocol for human gate webhook dispatch."""

    def notify(self, result: BlastResult) -> None: ...
