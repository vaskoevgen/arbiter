"""Protocol classes for dependency injection."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import ConflictRecord, ConflictSignal


@runtime_checkable
class TrustLookup(Protocol):
    """Protocol for trust score lookup."""

    def lookup_trust_score(self, node_id: str) -> float: ...


@runtime_checkable
class AuthorityLookup(Protocol):
    """Protocol for authority registry lookup."""

    def is_authoritative(self, node_id: str) -> bool: ...


@runtime_checkable
class SignalEmitter(Protocol):
    """Protocol for stigmergy signal emission."""

    def emit_signal(self, signal: ConflictSignal) -> None: ...


@runtime_checkable
class ConflictStore(Protocol):
    """Protocol for conflict persistence. Append-only JSONL with checksums."""

    def append(self, record: ConflictRecord) -> None: ...

    def load_all(self) -> list[ConflictRecord]: ...

    def verify_checksums(self) -> bool: ...
