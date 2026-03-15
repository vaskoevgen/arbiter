"""Taint detection models: TaintResult and CanaryEntry."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "TaintResult",
    "CanaryEntry",
]


class CanaryEntry(BaseModel):
    """A single canary record in the corpus.

    Canary fingerprints are structurally valid for their tier, globally unique
    per injection run, and impossible to appear in real data by coincidence
    (they contain embedded UUIDs).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., min_length=1, description="Unique canary identifier.")
    fingerprint: str = Field(
        ..., min_length=1, description="The canary string to search for in responses."
    )
    classification: str = Field(
        ..., min_length=1, description="Data tier this canary represents (e.g., PII, FINANCIAL)."
    )
    run_id: str = Field(..., min_length=1, description="The injection run that created this canary.")
    injected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of injection.",
    )
    active: bool = Field(default=True, description="Whether this canary is still active.")


class TaintResult(BaseModel):
    """Result of scanning a response for canary taint.

    If escaped is True, a canary fingerprint was found in a response
    from a node not authorized to access the canary's data tier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    escaped: bool = Field(..., description="True if a canary was found in unauthorized output.")
    canary_id: str = Field(default="", description="ID of the escaped canary, if any.")
    classification: str = Field(default="", description="Data tier of the escaped canary.")
    node: str = Field(default="", description="Node that produced the tainted output.")
    fingerprint: str = Field(default="", description="The fingerprint that was detected.")
