"""Conflict detector: windowed span buffering and conflict detection."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .errors import ConflictResolutionError, ConflictStoreError
from .models import (
    ConflictErrorCode,
    ConflictRecord,
    ConflictResolverConfig,
    NodeValue,
    ResolutionStatus,
    SpanFieldReport,
)
from .protocols import AuthorityLookup, ConflictStore, TrustLookup


class _BufferEntry:
    """Internal buffer entry for a single span report."""

    __slots__ = ("span_report", "ingested_at")

    def __init__(self, span_report: SpanFieldReport) -> None:
        self.span_report = span_report
        self.ingested_at: float = time.monotonic()


class ConflictDetector:
    """Windowed conflict detector.

    Buffers SpanFieldReports by (execution_id, domain, field). On window
    close (lazy timeout or explicit flush), detects conflicts when 2+
    distinct values exist.
    """

    def __init__(
        self,
        config: ConflictResolverConfig,
        trust_lookup: TrustLookup,
        authority_lookup: AuthorityLookup,
        store: ConflictStore,
        field_classifier: Callable[..., str] | None = None,
    ) -> None:
        self._config = config
        self._trust_lookup = trust_lookup
        self._authority_lookup = authority_lookup
        self._store = store
        self._field_classifier = field_classifier

        # Buffer: key = (execution_id, domain, field)
        # Value = list of _BufferEntry
        self._buffer: dict[tuple[str, str, str], list[_BufferEntry]] = {}

        # Dedup set: (node_id, span_id)
        self._seen_spans: set[tuple[str, str]] = set()

    def ingest(self, span_report: SpanFieldReport) -> list[ConflictRecord]:
        """Ingest a span field report; return newly detected conflicts."""
        # Dedup by (node_id, span_id)
        dedup_key = (span_report.node_id, span_report.span_id)
        if dedup_key in self._seen_spans:
            return []
        self._seen_spans.add(dedup_key)

        buf_key = (
            span_report.execution_id,
            span_report.domain,
            span_report.field,
        )
        self._buffer.setdefault(buf_key, []).append(_BufferEntry(span_report))

        # Check for expired windows (lazy timeout)
        return self._close_expired_windows()

    def flush(self) -> list[ConflictRecord]:
        """Force-close all open windows. Return detected conflicts."""
        results: list[ConflictRecord] = []
        keys = list(self._buffer.keys())
        for key in keys:
            entries = self._buffer.pop(key, [])
            conflict = self._evaluate_window(key, entries)
            if conflict is not None:
                results.append(conflict)
        self._seen_spans.clear()
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _close_expired_windows(self) -> list[ConflictRecord]:
        """Close any windows whose timeout has elapsed."""
        now = time.monotonic()
        timeout = self._config.window_timeout_seconds
        results: list[ConflictRecord] = []
        expired_keys: list[tuple[str, str, str]] = []

        for key, entries in self._buffer.items():
            if entries and (now - entries[0].ingested_at) >= timeout:
                expired_keys.append(key)

        for key in expired_keys:
            entries = self._buffer.pop(key, [])
            conflict = self._evaluate_window(key, entries)
            if conflict is not None:
                results.append(conflict)

        return results

    def _evaluate_window(
        self,
        key: tuple[str, str, str],
        entries: list[_BufferEntry],
    ) -> ConflictRecord | None:
        """Evaluate a closed window for conflicts."""
        execution_id, domain, field = key

        # Collect distinct values
        distinct_values: dict[str, list[_BufferEntry]] = {}
        for entry in entries:
            val = entry.span_report.value_serialized
            distinct_values.setdefault(val, []).append(entry)

        if len(distinct_values) < 2:
            return None

        # Build NodeValue list with trust/authority snapshots
        competing: list[NodeValue] = []
        for entry in entries:
            sr = entry.span_report
            try:
                trust = self._trust_lookup.lookup_trust_score(sr.node_id)
            except Exception as exc:
                raise ConflictResolutionError(
                    message=(
                        f"Trust lookup failed for node '{sr.node_id}': {exc}"
                    ),
                    error_code=ConflictErrorCode.TRUST_LOOKUP_FAILED,
                    context={"node_id": sr.node_id},
                ) from exc

            try:
                authoritative = self._authority_lookup.is_authoritative(
                    sr.node_id
                )
            except Exception as exc:
                raise ConflictResolutionError(
                    message=(
                        f"Authority lookup failed for node "
                        f"'{sr.node_id}': {exc}"
                    ),
                    error_code=ConflictErrorCode.AUTHORITY_LOOKUP_FAILED,
                    context={"node_id": sr.node_id},
                ) from exc

            competing.append(
                NodeValue(
                    node_id=sr.node_id,
                    value_serialized=sr.value_serialized,
                    trust_score_snapshot=trust,
                    is_authoritative=authoritative,
                    span_id=sr.span_id,
                )
            )

        # Determine data tier (degraded mode on failure)
        data_tier = ""
        if self._field_classifier is not None:
            try:
                data_tier = self._field_classifier(domain, field)
            except Exception:
                data_tier = ""

        conflict_id = str(uuid.uuid4())
        blocks_deploy = (
            data_tier in self._config.protected_tiers
        )

        record = ConflictRecord(
            conflict_id=conflict_id,
            execution_id=execution_id,
            domain=domain,
            field=field,
            data_tier=data_tier,
            competing_values=competing,
            detected_at=datetime.now(timezone.utc).isoformat(),
            status=ResolutionStatus.DETECTED,
            resolution=None,
            blocks_deploy=blocks_deploy,
        )

        try:
            self._store.append(record)
        except Exception as exc:
            raise ConflictStoreError(
                message=(
                    f"Store write failed for conflict "
                    f"'{conflict_id}': {exc}"
                ),
                error_code=ConflictErrorCode.STORE_WRITE_FAILED,
                context={"conflict_id": conflict_id},
            ) from exc

        return record
