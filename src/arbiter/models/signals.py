"""Signal and classification models. Feedback reports, claims, and classification rules."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .enums import DataTier
from .types import NodeId, UtcDatetime

__all__ = [
    "FeedbackReportSection",
    "FeedbackReport",
    "Claim",
    "ClassificationRule",
    "ValidationErrorDetail",
]


class FeedbackReportSection(BaseModel):
    """A single section within a feedback report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    section_name: str
    content: str
    findings_count: int = Field(ge=0)
    metadata: dict[str, str]


class FeedbackReport(BaseModel):
    """A complete feedback report containing multiple sections."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    report_id: str
    sections: list[FeedbackReportSection]
    total_findings: int = Field(ge=0)
    generated_by: NodeId


class Claim(BaseModel):
    """Generic wrapper for self-reported data from a node.

    Marks data as a claim (not ground truth). Node self-reports must be verified
    against the adapter layer.
    """

    source_node: NodeId
    claimed_at: UtcDatetime
    claim_type: str
    payload: dict[str, object]
    verified: bool
    verification_ts: str = ""


class ClassificationRule(BaseModel):
    """A field classification rule from the classification registry.

    Uses fnmatch or regex patterns. First matching rule wins.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field_pattern: str
    data_tier: DataTier
    is_regex: bool
    description: str


class ValidationErrorDetail(BaseModel):
    """Detailed information about a single validation error."""

    field: str
    value: str
    constraint: str
    message: str
