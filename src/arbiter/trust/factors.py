"""Individual trust factor computations.

Each factor returns a float in [0.0, 1.0] (or exactly 0.0 for taint lock).
All factors are pure functions operating on ledger entries.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arbiter.models.trust import TrustLedgerEntry

__all__ = [
    "compute_age_factor",
    "compute_consistency_factor",
    "compute_taint_factor",
    "compute_review_factor",
    "compute_decay_factor",
]

# Default parameters
_DEFAULT_AGE_HALF_LIFE = 50  # clean cycles to reach ~0.5 growth
_DEFAULT_CONSISTENCY_WINDOW = 100  # rolling window size
_DEFAULT_DECAY_LAMBDA = 0.05


def compute_age_factor(
    entries: list[TrustLedgerEntry],
    *,
    floor: float = 0.1,
    half_life: int = _DEFAULT_AGE_HALF_LIFE,
) -> float:
    """Compute age factor from ledger entries.

    Grows with the number of clean deployment cycles (non-failure events).
    Uses a saturating curve: factor = 1.0 - (1.0 - floor) * exp(-cycles / half_life).

    Args:
        entries: Ledger entries for a single node.
        floor: Minimum factor value.
        half_life: Number of clean cycles to reach halfway to 1.0.

    Returns:
        Float in [floor, 1.0].
    """
    clean_events = {"consistency_pass", "human_approve", "AUDIT_PASS"}
    clean_cycles = sum(1 for e in entries if e.event in clean_events)

    if clean_cycles == 0:
        return floor

    factor = 1.0 - (1.0 - floor) * math.exp(-clean_cycles / half_life)
    return max(floor, min(1.0, factor))


def compute_consistency_factor(
    entries: list[TrustLedgerEntry],
    *,
    floor: float = 0.1,
    window: int = _DEFAULT_CONSISTENCY_WINDOW,
) -> float:
    """Compute consistency factor from ledger entries.

    Rolling weighted average of consistency checks. Each pass adds 1.0,
    each fail adds 0.0. Uses the last `window` consistency events.

    Args:
        entries: Ledger entries for a single node.
        floor: Minimum factor value.
        window: Number of recent consistency events to consider.

    Returns:
        Float in [floor, 1.0].
    """
    consistency_events = {
        "consistency_pass", "consistency_fail",
        "AUDIT_PASS", "AUDIT_FAIL", "CONSISTENCY_CHECK",
    }
    pass_events = {"consistency_pass", "AUDIT_PASS"}

    relevant = [e for e in entries if e.event in consistency_events]
    if not relevant:
        return floor

    # Take the last `window` events
    recent = relevant[-window:]
    if not recent:
        return floor

    # Weighted: more recent events matter more
    total_weight = 0.0
    weighted_sum = 0.0
    for i, entry in enumerate(recent):
        weight = 1.0 + i * 0.1  # linear weight increase for recency
        value = 1.0 if entry.event in pass_events else 0.0
        weighted_sum += value * weight
        total_weight += weight

    factor = weighted_sum / total_weight if total_weight > 0 else floor
    return max(floor, min(1.0, factor))


def compute_taint_factor(
    entries: list[TrustLedgerEntry],
    *,
    floor: float = 0.1,
) -> float:
    """Compute taint factor from ledger entries.

    Returns 0.0 if taint is locked (escape without subsequent unlock).
    Otherwise returns 1.0 (no taint penalty).

    A taint_escape sets the factor to 0.0. Only a taint_unlock resets it.
    This is a binary penalty -- partial recovery is not supported.

    Args:
        entries: Ledger entries for a single node.
        floor: Not used for taint (binary), kept for API consistency.

    Returns:
        0.0 if taint locked, 1.0 otherwise.
    """
    taint_locked = False
    taint_events = {"taint_escape", "TAINT_DETECTED", "CANARY_TRIGGERED"}
    unlock_events = {"taint_unlock"}

    for entry in entries:
        if entry.event in taint_events:
            taint_locked = True
        elif entry.event in unlock_events:
            taint_locked = False

    return 0.0 if taint_locked else 1.0


def compute_review_factor(
    entries: list[TrustLedgerEntry],
    *,
    floor: float = 0.1,
) -> float:
    """Compute review factor from ledger entries.

    Weighted by human review outcomes. Approvals increase the factor,
    rejections decrease it. Starts at floor and grows with clean reviews.

    Args:
        entries: Ledger entries for a single node.
        floor: Minimum factor value.

    Returns:
        Float in [floor, 1.0].
    """
    approve_events = {"human_approve", "MANUAL_OVERRIDE"}
    reject_events = {"human_reject"}

    approvals = sum(1 for e in entries if e.event in approve_events)
    rejections = sum(1 for e in entries if e.event in reject_events)

    total = approvals + rejections
    if total == 0:
        return floor

    # Ratio-based with saturation toward 1.0
    ratio = approvals / total
    factor = floor + (1.0 - floor) * ratio
    return max(floor, min(1.0, factor))


def compute_decay_factor(
    entries: list[TrustLedgerEntry],
    *,
    floor: float = 0.1,
    decay_lambda: float = _DEFAULT_DECAY_LAMBDA,
) -> float:
    """Compute decay factor from ledger entries.

    Trust decays toward the floor when a node is idle.
    Formula: exp(-lambda * idle_cycles).

    Idle cycles are counted as the number of decay events at the end
    of the entry list (consecutive, since last non-decay event).

    Args:
        entries: Ledger entries for a single node.
        floor: Minimum factor value.
        decay_lambda: Decay rate constant.

    Returns:
        Float in [floor, 1.0].
    """
    if not entries:
        return 1.0

    # Count consecutive idle/decay events from the tail
    decay_events = {"decay", "DECAY"}
    idle_cycles = 0
    for entry in reversed(entries):
        if entry.event in decay_events:
            idle_cycles += 1
        else:
            break

    if idle_cycles == 0:
        return 1.0

    factor = math.exp(-decay_lambda * idle_cycles)
    return max(floor, min(1.0, factor))
