"""Pydantic models for the conflict resolver."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResolutionStatus(StrEnum):
    """Lifecycle status of a conflict record."""

    DETECTED = "DETECTED"
    AUTHORITY_RESOLVED = "AUTHORITY_RESOLVED"
    TRUST_RESOLVED = "TRUST_RESOLVED"
    UNRESOLVABLE = "UNRESOLVABLE"
    HUMAN_REVIEWED = "HUMAN_REVIEWED"


class ResolutionStrategy(StrEnum):
    """Which step of the three-step protocol resolved the conflict."""

    AUTHORITY = "AUTHORITY"
    TRUST_ARBITRATION = "TRUST_ARBITRATION"
    HUMAN = "HUMAN"


class ConflictErrorCode(StrEnum):
    """Machine-readable error codes for conflict resolver errors."""

    CONFLICT_NOT_FOUND = "CONFLICT_NOT_FOUND"
    CONFLICT_ALREADY_RESOLVED = "CONFLICT_ALREADY_RESOLVED"
    INVALID_EXECUTION_ID = "INVALID_EXECUTION_ID"
    WINDOW_TIMEOUT_EXPIRED = "WINDOW_TIMEOUT_EXPIRED"
    TRUST_LOOKUP_FAILED = "TRUST_LOOKUP_FAILED"
    AUTHORITY_LOOKUP_FAILED = "AUTHORITY_LOOKUP_FAILED"
    SIGNAL_EMISSION_FAILED = "SIGNAL_EMISSION_FAILED"
    STORE_WRITE_FAILED = "STORE_WRITE_FAILED"
    STORE_READ_FAILED = "STORE_READ_FAILED"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    INVALID_CONFIG = "INVALID_CONFIG"
    INVALID_HUMAN_REVIEW = "INVALID_HUMAN_REVIEW"
    DUPLICATE_SPAN = "DUPLICATE_SPAN"
    TIER_LOOKUP_FAILED = "TIER_LOOKUP_FAILED"
    EMPTY_COMPETING_VALUES = "EMPTY_COMPETING_VALUES"
    NO_CONFLICT_DETECTED = "NO_CONFLICT_DETECTED"


class NodeValue(BaseModel):
    """A node's reported value with snapshotted trust score."""

    model_config = ConfigDict(frozen=True)

    node_id: str = Field(min_length=1)
    value_serialized: str
    trust_score_snapshot: float = Field(ge=0.0, le=1.0)
    is_authoritative: bool
    span_id: str


class Resolution(BaseModel):
    """Outcome of conflict resolution."""

    model_config = ConfigDict(frozen=True)

    strategy: ResolutionStrategy
    winner_node_id: str
    resolved_at: str
    rationale: str
    reviewed_by: str | None = None


class ConflictRecord(BaseModel):
    """A single conflict instance. Append-only."""

    conflict_id: str
    execution_id: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    field: str = Field(min_length=1)
    data_tier: str
    competing_values: list[NodeValue]
    detected_at: str
    status: ResolutionStatus
    resolution: Resolution | None = None
    blocks_deploy: bool


class ConflictResolverConfig(BaseModel):
    """Configuration for the conflict resolver."""

    window_timeout_seconds: float = Field(ge=0.1, le=3600.0)
    authority_override_floor: float = Field(default=0.4, ge=0.0, le=1.0)
    trust_delta_threshold: float = Field(default=0.2, ge=0.0, le=1.0)
    checkpoint_interval: int = Field(default=100, ge=1, le=100000)
    conflict_log_path: str = Field(min_length=1)
    protected_tiers: list[str] = Field(default_factory=list)


class ConflictSignal(BaseModel):
    """Signal emitted to Stigmergy for unresolvable conflicts."""

    model_config = ConfigDict(frozen=True)

    signal_type: str = "conflict_unresolvable"
    conflict_id: str
    execution_id: str
    domain: str
    field: str
    competing_node_ids: list[str]
    max_trust_score: float
    trust_delta: float
    weight: float = 1.0
    emitted_at: str
    blocks_deploy: bool


class SpanFieldReport(BaseModel):
    """Extracted field report from an OTLP span -- input to detector."""

    model_config = ConfigDict(frozen=True)

    span_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    field: str = Field(min_length=1)
    value_serialized: str
    reported_at: str


class ConflictSummary(BaseModel):
    """Summary statistics for CLI and reporting."""

    total_conflicts: int
    unresolved_count: int
    authority_resolved_count: int
    trust_resolved_count: int
    human_reviewed_count: int
    deploy_blocking_count: int
    domains_affected: list[str]
