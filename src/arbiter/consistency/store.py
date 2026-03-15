"""In-memory + JSONL finding store for consistency findings.

Append-only. Queryable by node_id, span_id. JSONL serialization uses
sorted field arrays and ISO 8601 UTC timestamps.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    ConsistencyAnalysisError,
    ConsistencyFinding,
    ConsistencyFindingList,
    FindingSeverity,
    NodeId,
    OptionalTimestamp,
    SpanId,
)

__all__ = ["FindingStore"]


def _finding_to_jsonl_dict(finding: ConsistencyFinding) -> dict[str, Any]:
    """Serialize a finding to a JSON-compatible dict with sorted fields."""
    return {
        "schema_version": finding.schema_version,
        "node_id": finding.node_id,
        "span_id": finding.span_id,
        "trace_id": finding.trace_id,
        "outcome": finding.outcome.value,
        "severity": finding.severity.value,
        "observed_fields": sorted(finding.observed_fields),
        "claimed_fields": sorted(finding.claimed_fields),
        "unexplained_fields": sorted(finding.unexplained_fields),
        "overclaimed_fields": sorted(finding.overclaimed_fields),
        "analyzed_at": finding.analyzed_at,
        "details": finding.details,
    }


class FindingStore:
    """Append-only finding store backed by in-memory index and optional JSONL file.

    If *jsonl_path* is provided, findings are also appended to disk.
    Queries always use the in-memory index for speed.
    """

    def __init__(self, jsonl_path: Path | None = None) -> None:
        self._findings: list[ConsistencyFinding] = []
        self._by_node: dict[str, list[int]] = {}
        self._by_span: dict[str, list[int]] = {}
        self._jsonl_path = jsonl_path

    # ── Write ──────────────────────────────────────────

    def persist(self, finding: ConsistencyFinding) -> None:
        """Append a single finding to the store."""
        idx = len(self._findings)
        self._findings.append(finding)

        self._by_node.setdefault(finding.node_id, []).append(idx)
        self._by_span.setdefault(finding.span_id, []).append(idx)

        if self._jsonl_path is not None:
            try:
                data = _finding_to_jsonl_dict(finding)
                line = json.dumps(data, sort_keys=True)
            except (TypeError, ValueError) as exc:
                raise ConsistencyAnalysisError(
                    node_id=finding.node_id,
                    span_id=finding.span_id,
                    detail=(
                        f"Serialization failed for finding node "
                        f"{finding.node_id}, span {finding.span_id}: {exc}"
                    ),
                ) from exc
            try:
                with open(self._jsonl_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                raise ConsistencyAnalysisError(
                    node_id=finding.node_id,
                    span_id=finding.span_id,
                    detail=(
                        f"Failed to persist finding for node "
                        f"{finding.node_id}, span {finding.span_id}: {exc}"
                    ),
                ) from exc

    # ── Queries ────────────────────────────────────────

    def get_by_node(self, node_id: NodeId) -> ConsistencyFindingList:
        """All findings for *node_id*, oldest-first by analyzed_at."""
        indices = self._by_node.get(node_id, [])
        findings = [self._findings[i] for i in indices]
        findings.sort(key=lambda f: f.analyzed_at)
        return findings

    def get_by_span(self, span_id: SpanId) -> ConsistencyFindingList:
        """All findings for *span_id*, oldest-first by analyzed_at."""
        indices = self._by_span.get(span_id, [])
        findings = [self._findings[i] for i in indices]
        findings.sort(key=lambda f: f.analyzed_at)
        return findings

    def has_high_severity(
        self,
        node_id: NodeId,
        since: OptionalTimestamp = None,
    ) -> bool:
        """Check if any HIGH severity finding exists for *node_id*.

        Optionally filtered to findings at or after *since*.
        Timestamps are compared as ISO 8601 strings (lexicographic).
        """
        indices = self._by_node.get(node_id, [])
        for i in indices:
            f = self._findings[i]
            if f.severity != FindingSeverity.HIGH:
                continue
            if since is not None and f.analyzed_at < since:
                continue
            return True
        return False

    # ── Utilities ──────────────────────────────────────

    def __len__(self) -> int:
        return len(self._findings)
