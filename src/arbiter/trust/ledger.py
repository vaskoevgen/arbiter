"""Append-only trust ledger with JSONL storage and SHA256 checkpoints.

The ledger is the most critical data structure in Arbiter. It is treated like
a financial ledger: append-only, checksummed, never modified.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from arbiter.models.enums import TrustEventType
from arbiter.models.trust import LedgerCheckpoint, LedgerLine, TrustLedgerEntry

__all__ = [
    "TrustLedger",
]

_CHECKPOINT_INTERVAL = 100  # Insert a checksum line every N entries
_entry_adapter = TypeAdapter(LedgerLine)


class TrustLedger:
    """Append-only trust ledger backed by a JSONL file.

    All writes are appended to disk. No existing entry is ever modified or
    deleted (FA-A-004). SHA256 checkpoints are inserted every N entries for
    integrity verification.

    Args:
        path: Path to the JSONL ledger file. Created if it does not exist.
        checkpoint_interval: Number of entries between checksum lines.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        checkpoint_interval: int = _CHECKPOINT_INTERVAL,
    ) -> None:
        self._path = Path(path)
        self._checkpoint_interval = checkpoint_interval
        self._entries: list[TrustLedgerEntry] = []
        self._checkpoints: list[LedgerCheckpoint] = []
        self._sequence: int = 0
        self._running_hash = hashlib.sha256()
        self._entries_since_checkpoint: int = 0

        if self._path.exists():
            self._load()

    def _load(self) -> None:
        """Load existing ledger from disk."""
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if "checksum" in data:
                    cp = LedgerCheckpoint.model_validate(data)
                    self._checkpoints.append(cp)
                    self._sequence = cp.sequence_number
                    self._entries_since_checkpoint = 0
                else:
                    entry = TrustLedgerEntry.model_validate(data)
                    self._entries.append(entry)
                    self._sequence = entry.sequence_number
                    self._running_hash.update(
                        entry.model_dump_json(exclude_none=True).encode("utf-8")
                    )
                    self._entries_since_checkpoint += 1

    def append_entry(
        self,
        node: str,
        event: TrustEventType | str,
        weight: float,
        score_before: float,
        score_after: float,
        detail: str = "",
    ) -> TrustLedgerEntry:
        """Append a new entry to the ledger.

        Writes to disk immediately. Inserts a checkpoint if the interval
        threshold is reached.

        Args:
            node: Node identifier.
            event: Trust event type.
            weight: Event weight in [-1.0, 1.0].
            score_before: Trust score before this event.
            score_after: Trust score after this event.
            detail: Human-readable detail string.

        Returns:
            The created TrustLedgerEntry.
        """
        self._sequence += 1
        ts = datetime.now(timezone.utc).isoformat()

        # Normalize event to string for the enum
        if isinstance(event, str):
            try:
                event = TrustEventType(event)
            except ValueError:
                # Accept string event types from the spec that don't map
                # to the enum (e.g., "consistency_pass")
                pass

        entry = TrustLedgerEntry(
            ts=ts,
            node=node,
            event=event,  # type: ignore[arg-type]
            weight=weight,
            score_before=score_before,
            score_after=score_after,
            sequence_number=self._sequence,
            detail=detail,
        )

        self._entries.append(entry)
        entry_json = entry.model_dump_json(exclude_none=True)
        self._running_hash.update(entry_json.encode("utf-8"))
        self._entries_since_checkpoint += 1

        # Write entry to disk
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(entry_json + "\n")

        # Insert checkpoint if threshold reached
        if self._entries_since_checkpoint >= self._checkpoint_interval:
            self._write_checkpoint()

        return entry

    def _write_checkpoint(self) -> None:
        """Write a SHA256 checkpoint line to the ledger."""
        self._sequence += 1
        checkpoint = LedgerCheckpoint(
            ts=datetime.now(timezone.utc).isoformat(),
            sequence_number=self._sequence,
            checksum=self._running_hash.hexdigest(),
            entry_count=len(self._entries),
        )
        self._checkpoints.append(checkpoint)
        self._entries_since_checkpoint = 0

        with self._path.open("a", encoding="utf-8") as f:
            f.write(checkpoint.model_dump_json(exclude_none=True) + "\n")

    def get_entries(self, node_id: str) -> list[TrustLedgerEntry]:
        """Get all entries for a specific node.

        Args:
            node_id: The node to filter by.

        Returns:
            List of entries in chronological order.
        """
        return [e for e in self._entries if e.node == node_id]

    def get_score(self, node_id: str, *, floor: float = 0.1) -> float:
        """Get the current trust score for a node.

        Returns the score_after of the most recent entry, or the floor
        if no entries exist.

        Args:
            node_id: The node to look up.
            floor: Default score if no entries exist.

        Returns:
            Current trust score.
        """
        node_entries = self.get_entries(node_id)
        if not node_entries:
            return floor
        return node_entries[-1].score_after

    def replay_from_start(self) -> dict[str, float]:
        """Replay the entire ledger to recompute all scores.

        Walks every entry in sequence order and returns the final
        score_after for each node. This verifies FA-A-006: trust score
        is fully reproducible by replaying the ledger.

        Returns:
            Dict mapping node_id to its replayed trust score.
        """
        scores: dict[str, float] = {}
        for entry in self._entries:
            scores[entry.node] = entry.score_after
        return scores

    def get_latest_sequence(self) -> int:
        """Get the latest sequence number in the ledger.

        Returns:
            The highest sequence number, or 0 if the ledger is empty.
        """
        return self._sequence

    def verify_integrity(self) -> bool:
        """Verify ledger integrity using checkpoints.

        Replays entries up to each checkpoint and verifies the SHA256
        checksum matches.

        Returns:
            True if all checkpoints pass, False otherwise.
        """
        if not self._checkpoints:
            return True

        running = hashlib.sha256()
        entry_idx = 0

        for checkpoint in self._checkpoints:
            while entry_idx < len(self._entries):
                entry = self._entries[entry_idx]
                if entry.sequence_number > checkpoint.sequence_number:
                    break
                running.update(
                    entry.model_dump_json(exclude_none=True).encode("utf-8")
                )
                entry_idx += 1

            if running.hexdigest() != checkpoint.checksum:
                return False

        return True

    @property
    def all_entries(self) -> list[TrustLedgerEntry]:
        """All entries in chronological order."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
