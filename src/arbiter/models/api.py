"""HTTP API request/response models for Arbiter endpoints."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .enums import BlastTier, DataTier, FindingSeverity, TrustTier
from .findings import AccessFinding, ConsistencyFinding, TaintFinding
from .types import NodeId, SequenceNumber, TrustScore

__all__ = [
    "ErrorResponse",
    "TrustScoreRequest",
    "TrustScoreResponse",
    "BlastRadiusRequest",
    "BlastRadiusResponse",
    "FindingsRequest",
    "FindingsResponse",
    "HealthResponse",
]


class ErrorResponse(BaseModel):
    """Standard HTTP API error response.

    Machine-readable error_code plus human-readable message plus optional details
    including the offending node/field/domain.
    """

    error_code: str
    message: str
    details: dict[str, str]


class TrustScoreRequest(BaseModel):
    """HTTP API request to query a node's trust score."""

    model_config = ConfigDict(extra="forbid")

    node: NodeId


class TrustScoreResponse(BaseModel):
    """HTTP API response containing a node's trust score and tier."""

    node: NodeId
    score: TrustScore
    tier: TrustTier
    ledger_sequence: SequenceNumber


class BlastRadiusRequest(BaseModel):
    """HTTP API request to compute blast radius for a node."""

    model_config = ConfigDict(extra="forbid")

    node: NodeId
    max_depth: int = Field(default=10, ge=1, le=100)


class BlastRadiusResponse(BaseModel):
    """HTTP API response containing blast radius analysis results."""

    node: NodeId
    blast_tier: BlastTier
    affected_nodes: list[NodeId]
    affected_data_tiers: list[DataTier]
    depth_reached: int


class FindingsRequest(BaseModel):
    """HTTP API request to query findings."""

    model_config = ConfigDict(extra="forbid")

    node: NodeId = ""  # type: ignore[assignment]
    severity_min: FindingSeverity = FindingSeverity.INFO
    limit: int = Field(default=100, ge=1, le=1000)


class FindingsResponse(BaseModel):
    """HTTP API response containing queried findings."""

    consistency_findings: list[ConsistencyFinding]
    access_findings: list[AccessFinding]
    taint_findings: list[TaintFinding]
    total_count: int


class HealthResponse(BaseModel):
    """HTTP API response for health check endpoint."""

    status: str
    version: str
    ledger_sequence: SequenceNumber
    uptime_seconds: float
