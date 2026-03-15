"""Deterministic feedback report generator.

Produces reports with 7 required sections (FA-A-026):
  TRUST SUMMARY, CONSISTENCY, ACCESS, CONFLICTS, TAINT, BLAST RADIUS, OVERALL

Same inputs always produce the same output (FA-A-027).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "generate_report",
    "ReportData",
]


@dataclass(frozen=True)
class TrustEntry:
    """A single node's trust summary for the report."""

    node_id: str
    score: float
    tier: str
    authority_domains: list[str] = field(default_factory=list)
    flagged: bool = False


@dataclass(frozen=True)
class ConsistencyEntry:
    """A single node's consistency check result."""

    node_id: str
    verdict: str  # "PASS" or "WARN" or "FAIL"
    unexplained_count: int = 0
    details: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AccessEntry:
    """A single node's access audit result."""

    node_id: str
    verdict: str  # "PASS" or "WARN" or "VIOLATION"
    details: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConflictEntry:
    """A detected conflict between nodes."""

    field: str
    nodes: list[str] = field(default_factory=list)
    resolution: str = ""


@dataclass(frozen=True)
class TaintEntry:
    """A taint detection result."""

    canary_id: str = ""
    node: str = ""
    classification: str = ""
    escaped: bool = False


@dataclass(frozen=True)
class BlastRadiusEntry:
    """Blast radius computation for a proposed change."""

    node_id: str = ""
    version: str = ""
    trust_score: float = 0.0
    trust_tier: str = ""
    highest_tier: str = ""
    base_soak: str = ""
    trust_multiplier: float = 0.0
    volume_factor: float = 0.0
    computed_soak: str = ""
    human_gate_required: bool = False


@dataclass
class ReportData:
    """Input data for report generation. All fields are deterministic."""

    run_id: str = ""
    trust_entries: list[TrustEntry] = field(default_factory=list)
    consistency_entries: list[ConsistencyEntry] = field(default_factory=list)
    access_entries: list[AccessEntry] = field(default_factory=list)
    conflict_entries: list[ConflictEntry] = field(default_factory=list)
    taint_entries: list[TaintEntry] = field(default_factory=list)
    blast_radius: BlastRadiusEntry | None = None
    overall_verdict: str = ""
    overall_details: list[str] = field(default_factory=list)


def generate_report(
    run_id: str,
    *,
    data: ReportData | None = None,
) -> str:
    """Generate a deterministic feedback report for a given run.

    The report contains all 7 required sections per FA-A-026.
    Deterministic: same inputs always produce the same report (FA-A-027).

    Args:
        run_id: The run identifier for the report header.
        data: Optional ReportData providing content for each section.
            If None, generates an empty report with placeholder sections.

    Returns:
        The complete report as a formatted string.
    """
    if data is None:
        data = ReportData(run_id=run_id)

    sections: list[str] = []

    # Header
    sections.append(f"ARBITER REPORT -- run {run_id}")
    sections.append("")

    # Section 1: TRUST SUMMARY
    sections.append(_section_trust_summary(data.trust_entries))

    # Section 2: CONSISTENCY
    sections.append(_section_consistency(data.consistency_entries))

    # Section 3: ACCESS
    sections.append(_section_access(data.access_entries))

    # Section 4: CONFLICTS
    sections.append(_section_conflicts(data.conflict_entries))

    # Section 5: TAINT
    sections.append(_section_taint(data.taint_entries))

    # Section 6: BLAST RADIUS
    sections.append(_section_blast_radius(data.blast_radius))

    # Section 7: OVERALL
    sections.append(_section_overall(data.overall_verdict, data.overall_details))

    return "\n".join(sections)


def _section_trust_summary(entries: list[TrustEntry]) -> str:
    """Render the TRUST SUMMARY section."""
    lines = ["TRUST SUMMARY"]
    if not entries:
        lines.append("  No nodes registered.")
    else:
        for entry in sorted(entries, key=lambda e: e.node_id):
            domains = ", ".join(sorted(entry.authority_domains)) if entry.authority_domains else "none"
            flag = "  <- flag" if entry.flagged else ""
            lines.append(
                f"  {entry.node_id:<22} {entry.score:.2f}  {entry.tier:<14} "
                f"authoritative: {domains}{flag}"
            )
    lines.append("")
    return "\n".join(lines)


def _section_consistency(entries: list[ConsistencyEntry]) -> str:
    """Render the CONSISTENCY section."""
    lines = ["CONSISTENCY"]
    if not entries:
        lines.append("  No consistency checks performed.")
    else:
        for entry in sorted(entries, key=lambda e: e.node_id):
            lines.append(
                f"  {entry.node_id:<22} {entry.verdict:<8} "
                f"{entry.unexplained_count} unexplained fields"
            )
            for detail in entry.details:
                lines.append(f"                            {detail}")
    lines.append("")
    return "\n".join(lines)


def _section_access(entries: list[AccessEntry]) -> str:
    """Render the ACCESS section."""
    lines = ["ACCESS"]
    if not entries:
        lines.append("  No access audits performed.")
    else:
        for entry in sorted(entries, key=lambda e: e.node_id):
            lines.append(f"  {entry.node_id:<22} {entry.verdict}")
            for detail in entry.details:
                lines.append(f"                            {detail}")
    lines.append("")
    return "\n".join(lines)


def _section_conflicts(entries: list[ConflictEntry]) -> str:
    """Render the CONFLICTS section."""
    lines = ["CONFLICTS"]
    if not entries:
        lines.append("  none detected")
    else:
        for entry in entries:
            nodes_str = ", ".join(sorted(entry.nodes))
            lines.append(f"  field: {entry.field}  nodes: [{nodes_str}]")
            if entry.resolution:
                lines.append(f"    resolution: {entry.resolution}")
    lines.append("")
    return "\n".join(lines)


def _section_taint(entries: list[TaintEntry]) -> str:
    """Render the TAINT section."""
    lines = ["TAINT"]
    escapes = [e for e in entries if e.escaped]
    if not escapes:
        lines.append("  no canary escapes detected")
    else:
        for entry in escapes:
            lines.append(
                f"  ESCAPE: canary={entry.canary_id} node={entry.node} "
                f"tier={entry.classification}"
            )
    lines.append("")
    return "\n".join(lines)


def _section_blast_radius(entry: BlastRadiusEntry | None) -> str:
    """Render the BLAST RADIUS section."""
    lines = ["BLAST RADIUS"]
    if entry is None or not entry.node_id:
        lines.append("  No blast radius computation requested.")
    else:
        version_str = f" {entry.version}" if entry.version else ""
        lines.append(f"  (proposed: {entry.node_id}{version_str})")
        lines.append(f"  node trust: {entry.trust_score:.2f} ({entry.trust_tier})")
        if entry.highest_tier:
            lines.append(f"  tier: {entry.highest_tier}")
        if entry.base_soak:
            lines.append(
                f"  base soak: {entry.base_soak}  |  "
                f"trust multiplier: {entry.trust_multiplier:.2f}  |  "
                f"volume factor: {entry.volume_factor:.2f}"
            )
            lines.append(f"  computed soak: {entry.computed_soak}")
        gate_str = "required" if entry.human_gate_required else "not required"
        lines.append(f"  human gate: {gate_str}")
    lines.append("")
    return "\n".join(lines)


def _section_overall(verdict: str, details: list[str]) -> str:
    """Render the OVERALL section."""
    lines = ["OVERALL"]
    if not verdict:
        lines.append("  No overall verdict computed.")
    else:
        lines.append(f"  {verdict}")
        for detail in details:
            lines.append(f"  {detail}")
    return "\n".join(lines)
