"""Canary record model. Synthetic test data with UUID v4 fingerprint validation."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from .enums import DataTier
from .types import NodeId, UtcDatetime

__all__ = [
    "CanaryRecord",
]

_UUID_V4_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


class CanaryRecord(BaseModel):
    """A record of a canary (synthetic test data) injection and its status.

    Canary fingerprints must contain an embedded UUID v4 making them recognizable
    as synthetic and impossible in real data.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    canary_id: str
    fingerprint: str
    data_tier: DataTier
    target_node: NodeId
    triggered: bool
    triggered_at: str = ""
    triggered_by_node: str = ""

    @field_validator("fingerprint")
    @classmethod
    def _fingerprint_contains_uuid_v4(cls, v: str) -> str:
        if not _UUID_V4_RE.search(v):
            raise ValueError(
                "Canary fingerprint must contain a UUID v4 segment"
            )
        return v
