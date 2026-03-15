"""Query and summary methods for the conflict resolver."""

from __future__ import annotations

from .errors import ConflictNotFoundError, ConflictStoreError
from .models import (
    ConflictErrorCode,
    ConflictRecord,
    ConflictResolverConfig,
    ConflictSummary,
    ResolutionStatus,
)
from .protocols import ConflictStore


class ConflictQueryMixin:
    """Query methods shared by ConflictResolver. Requires _store and _config."""

    _store: ConflictStore
    _config: ConflictResolverConfig

    def get_unresolved(self, domain: str = "") -> list[ConflictRecord]:
        """Return unresolved conflicts, optionally filtered by domain."""
        records = _load_all(self._store)
        unresolved = {ResolutionStatus.DETECTED, ResolutionStatus.UNRESOLVABLE}
        filtered = [
            r for r in records
            if r.status in unresolved and (not domain or r.domain == domain)
        ]
        filtered.sort(key=lambda r: r.detected_at, reverse=True)
        return filtered

    def has_blocking_conflicts(self, domain: str) -> bool:
        """Check whether any unresolved conflicts block deployment."""
        records = _load_all(self._store)
        unresolved = {ResolutionStatus.DETECTED, ResolutionStatus.UNRESOLVABLE}
        return any(
            r.domain == domain and r.blocks_deploy and r.status in unresolved
            for r in records
        )

    def get_summary(self) -> ConflictSummary:
        """Return aggregate conflict statistics."""
        records = _load_all(self._store)
        unresolved = {ResolutionStatus.DETECTED, ResolutionStatus.UNRESOLVABLE}

        authority_count = sum(
            1 for r in records
            if r.status == ResolutionStatus.AUTHORITY_RESOLVED
        )
        trust_count = sum(
            1 for r in records
            if r.status == ResolutionStatus.TRUST_RESOLVED
        )
        human_count = sum(
            1 for r in records
            if r.status == ResolutionStatus.HUMAN_REVIEWED
        )
        unresolved_list = [r for r in records if r.status in unresolved]
        deploy_blocking = sum(1 for r in unresolved_list if r.blocks_deploy)
        domains = sorted({r.domain for r in unresolved_list})

        return ConflictSummary(
            total_conflicts=len(records),
            unresolved_count=len(unresolved_list),
            authority_resolved_count=authority_count,
            trust_resolved_count=trust_count,
            human_reviewed_count=human_count,
            deploy_blocking_count=deploy_blocking,
            domains_affected=domains,
        )

    def verify_log_integrity(self) -> bool:
        """Verify SHA256 checksums in the conflict log."""
        try:
            return self._store.verify_checksums()
        except Exception as exc:
            raise ConflictStoreError(
                message=f"Store read failed: {exc}",
                error_code=ConflictErrorCode.STORE_READ_FAILED,
            ) from exc


def _load_all(store: ConflictStore) -> list[ConflictRecord]:
    """Load all records with error wrapping."""
    try:
        return store.load_all()
    except Exception as exc:
        raise ConflictStoreError(
            message=f"Store read failed: {exc}",
            error_code=ConflictErrorCode.STORE_READ_FAILED,
        ) from exc


def find_conflict(store: ConflictStore, conflict_id: str) -> ConflictRecord:
    """Find a conflict by ID in the store."""
    records = _load_all(store)
    for record in reversed(records):
        if record.conflict_id == conflict_id:
            return record
    raise ConflictNotFoundError(
        message=f"Conflict '{conflict_id}' not found",
        error_code=ConflictErrorCode.CONFLICT_NOT_FOUND,
        conflict_id=conflict_id,
    )


def persist(store: ConflictStore, record: ConflictRecord) -> None:
    """Append record to the conflict store with error wrapping."""
    try:
        store.append(record)
    except Exception as exc:
        raise ConflictStoreError(
            message=(
                f"Store write failed for conflict "
                f"'{record.conflict_id}': {exc}"
            ),
            error_code=ConflictErrorCode.STORE_WRITE_FAILED,
            context={"conflict_id": record.conflict_id},
        ) from exc
