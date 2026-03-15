"""Conflict resolver: three-step protocol and human review."""

from __future__ import annotations

from datetime import datetime, timezone

from .errors import ConflictResolutionError
from .models import (
    ConflictErrorCode,
    ConflictRecord,
    ConflictResolverConfig,
    ConflictSignal,
    Resolution,
    ResolutionStatus,
    ResolutionStrategy,
)
from .protocols import ConflictStore, SignalEmitter
from .queries import ConflictQueryMixin, find_conflict, persist


class ConflictResolver(ConflictQueryMixin):
    """Three-step conflict resolution with query/summary capabilities."""

    def __init__(
        self,
        config: ConflictResolverConfig,
        store: ConflictStore,
        signal_emitter: SignalEmitter,
    ) -> None:
        self._config = config
        self._store = store
        self._signal_emitter = signal_emitter

    def resolve(self, conflict: ConflictRecord) -> ConflictRecord:
        """Run the three-step conflict resolution protocol."""
        self._validate_resolvable(conflict)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Authority check
        result = self._try_authority(conflict, now_iso)
        if result is not None:
            return result

        # Step 2: Trust arbitration (top-2 delta)
        result = self._try_trust(conflict, now_iso)
        if result is not None:
            return result

        # Step 3: Unresolvable
        return self._mark_unresolvable(conflict, now_iso)

    def submit_human_review(
        self,
        conflict_id: str,
        winner_node_id: str,
        reviewed_by: str,
        rationale: str,
    ) -> ConflictRecord:
        """Record a human review decision for an UNRESOLVABLE conflict."""
        conflict = find_conflict(self._store, conflict_id)

        if conflict.status != ResolutionStatus.UNRESOLVABLE:
            raise ConflictResolutionError(
                message=(
                    f"Conflict '{conflict_id}' has invalid status "
                    f"'{conflict.status}' for human review "
                    f"(expected UNRESOLVABLE)"
                ),
                error_code=ConflictErrorCode.INVALID_HUMAN_REVIEW,
                context={
                    "conflict_id": conflict_id,
                    "current_status": conflict.status,
                },
            )

        node_ids = {nv.node_id for nv in conflict.competing_values}
        if winner_node_id not in node_ids:
            raise ConflictResolutionError(
                message=(
                    f"Winner node '{winner_node_id}' is not among "
                    f"competing nodes for conflict '{conflict_id}'"
                ),
                error_code=ConflictErrorCode.INVALID_HUMAN_REVIEW,
                context={
                    "conflict_id": conflict_id,
                    "winner_node_id": winner_node_id,
                },
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        reviewed = conflict.model_copy(
            update={
                "status": ResolutionStatus.HUMAN_REVIEWED,
                "blocks_deploy": False,
                "resolution": Resolution(
                    strategy=ResolutionStrategy.HUMAN,
                    winner_node_id=winner_node_id,
                    resolved_at=now_iso,
                    rationale=rationale,
                    reviewed_by=reviewed_by,
                ),
            }
        )
        persist(self._store, reviewed)
        return reviewed

    # ------------------------------------------------------------------
    # Private resolution steps
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_resolvable(conflict: ConflictRecord) -> None:
        if conflict.status != ResolutionStatus.DETECTED:
            raise ConflictResolutionError(
                message=(
                    f"Conflict '{conflict.conflict_id}' already resolved "
                    f"(status={conflict.status})"
                ),
                error_code=ConflictErrorCode.CONFLICT_ALREADY_RESOLVED,
                context={
                    "conflict_id": conflict.conflict_id,
                    "current_status": conflict.status,
                },
            )
        if len(conflict.competing_values) < 2:
            raise ConflictResolutionError(
                message=(
                    f"Conflict '{conflict.conflict_id}' has fewer than 2 "
                    f"competing values"
                ),
                error_code=ConflictErrorCode.EMPTY_COMPETING_VALUES,
                context={"conflict_id": conflict.conflict_id},
            )

    def _try_authority(
        self, conflict: ConflictRecord, now_iso: str,
    ) -> ConflictRecord | None:
        authoritative = [
            nv for nv in conflict.competing_values if nv.is_authoritative
        ]
        if len(authoritative) != 1:
            return None
        auth_node = authoritative[0]
        if auth_node.trust_score_snapshot <= self._config.authority_override_floor:
            return None
        resolved = conflict.model_copy(
            update={
                "status": ResolutionStatus.AUTHORITY_RESOLVED,
                "resolution": Resolution(
                    strategy=ResolutionStrategy.AUTHORITY,
                    winner_node_id=auth_node.node_id,
                    resolved_at=now_iso,
                    rationale=(
                        f"Authority check: node '{auth_node.node_id}' "
                        f"is authoritative with trust "
                        f"{auth_node.trust_score_snapshot:.3f} > floor "
                        f"{self._config.authority_override_floor:.3f}"
                    ),
                    reviewed_by="",
                ),
            }
        )
        persist(self._store, resolved)
        return resolved

    def _try_trust(
        self, conflict: ConflictRecord, now_iso: str,
    ) -> ConflictRecord | None:
        sorted_vals = sorted(
            conflict.competing_values,
            key=lambda nv: nv.trust_score_snapshot,
            reverse=True,
        )
        top, second = sorted_vals[0], sorted_vals[1]
        delta = top.trust_score_snapshot - second.trust_score_snapshot
        if delta <= self._config.trust_delta_threshold:
            return None
        resolved = conflict.model_copy(
            update={
                "status": ResolutionStatus.TRUST_RESOLVED,
                "resolution": Resolution(
                    strategy=ResolutionStrategy.TRUST_ARBITRATION,
                    winner_node_id=top.node_id,
                    resolved_at=now_iso,
                    rationale=(
                        f"Trust arbitration: node '{top.node_id}' trust "
                        f"{top.trust_score_snapshot:.3f} vs "
                        f"'{second.node_id}' trust "
                        f"{second.trust_score_snapshot:.3f}, delta "
                        f"{delta:.3f} > threshold "
                        f"{self._config.trust_delta_threshold:.3f}"
                    ),
                    reviewed_by="",
                ),
            }
        )
        persist(self._store, resolved)
        return resolved

    def _mark_unresolvable(
        self, conflict: ConflictRecord, now_iso: str,
    ) -> ConflictRecord:
        sorted_vals = sorted(
            conflict.competing_values,
            key=lambda nv: nv.trust_score_snapshot,
            reverse=True,
        )
        top, second = sorted_vals[0], sorted_vals[1]
        delta = top.trust_score_snapshot - second.trust_score_snapshot
        blocks = conflict.data_tier in self._config.protected_tiers
        node_ids = [nv.node_id for nv in conflict.competing_values]

        resolved = conflict.model_copy(
            update={
                "status": ResolutionStatus.UNRESOLVABLE,
                "blocks_deploy": blocks,
                "resolution": Resolution(
                    strategy=ResolutionStrategy.HUMAN,
                    winner_node_id="",
                    resolved_at=now_iso,
                    rationale=(
                        f"Unresolvable: no single authority, trust delta "
                        f"{delta:.3f} <= threshold "
                        f"{self._config.trust_delta_threshold:.3f}. "
                        f"Competing nodes: {', '.join(node_ids)}"
                    ),
                    reviewed_by="",
                ),
            }
        )

        signal = ConflictSignal(
            conflict_id=conflict.conflict_id,
            execution_id=conflict.execution_id,
            domain=conflict.domain,
            field=conflict.field,
            competing_node_ids=node_ids,
            max_trust_score=top.trust_score_snapshot,
            trust_delta=delta,
            weight=1.0,
            emitted_at=now_iso,
            blocks_deploy=blocks,
        )

        try:
            self._signal_emitter.emit_signal(signal)
        except Exception as exc:
            raise ConflictResolutionError(
                message=(
                    f"Signal emission failed for conflict "
                    f"'{conflict.conflict_id}': {exc}"
                ),
                error_code=ConflictErrorCode.SIGNAL_EMISSION_FAILED,
                context={"conflict_id": conflict.conflict_id},
            ) from exc

        persist(self._store, resolved)
        return resolved
