"""Trust ledger models. Immutable, append-only ledger entries and checkpoints."""

from __future__ import annotations

from typing import Union

from pydantic import BaseModel, ConfigDict, Field

from .enums import TrustEventType
from .types import NodeId, SequenceNumber, Sha256Hex, TrustScore, UtcDatetime

__all__ = [
    "TrustLedgerEntry",
    "LedgerCheckpoint",
    "LedgerLine",
]


class TrustLedgerEntry(BaseModel):
    """A single immutable trust event in the append-only ledger.

    The ledger is treated like a financial ledger -- no updates, no deletes.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    node: NodeId
    event: TrustEventType
    weight: float = Field(ge=-1.0, le=1.0)
    score_before: TrustScore
    score_after: TrustScore
    sequence_number: SequenceNumber
    detail: str


class LedgerCheckpoint(BaseModel):
    """SHA-256 checksum line inserted into the JSONL ledger after every N entries.

    Used for integrity verification of the append-only ledger.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: UtcDatetime
    sequence_number: SequenceNumber
    checksum: Sha256Hex
    entry_count: int = Field(ge=1)


LedgerLine = Union[TrustLedgerEntry, LedgerCheckpoint]
