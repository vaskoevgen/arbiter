"""Trust score computation engine.

Computes a node's trust score from its ledger entries using five multiplicative
factors: age, consistency, taint, review, and decay. The result is clamped to
[floor, 1.0]. Taint zeros the score immediately.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from arbiter.models.enums import TrustTier

from .factors import (
    compute_age_factor,
    compute_consistency_factor,
    compute_decay_factor,
    compute_review_factor,
    compute_taint_factor,
)

if TYPE_CHECKING:
    from arbiter.models.trust import TrustLedgerEntry

__all__ = [
    "compute_trust",
    "score_to_tier",
]

# Score-to-tier boundaries (inclusive lower, inclusive upper)
_TIER_BOUNDARIES: list[tuple[float, float, TrustTier]] = [
    (0.0, 0.25, TrustTier.PROBATIONARY),
    (0.26, 0.50, TrustTier.LOW),
    (0.51, 0.75, TrustTier.ESTABLISHED),
    (0.76, 0.90, TrustTier.HIGH),
    (0.91, 1.00, TrustTier.TRUSTED),
]


def compute_trust(
    node_id: str,
    ledger_entries: list[TrustLedgerEntry],
    *,
    floor: float = 0.1,
    decay_lambda: float = 0.05,
) -> float:
    """Compute trust score for a node from its ledger history.

    Formula: age * consistency * taint * review * decay, clamped to [floor, 1.0].
    If taint is locked (taint_factor == 0.0), the raw score is 0.0 and the
    result is clamped to floor only if floor > 0 -- but per spec, taint zeros
    the score, so we return 0.0 when tainted regardless of floor.

    Args:
        node_id: The node identifier (used for filtering if needed).
        ledger_entries: All ledger entries for this node, in chronological order.
        floor: Minimum trust score (default 0.1).
        decay_lambda: Decay rate constant (default 0.05).

    Returns:
        Trust score in [0.0, 1.0]. Returns 0.0 if taint-locked.
    """
    # Filter entries to this node
    entries = [e for e in ledger_entries if e.node == node_id]

    if not entries:
        return floor

    age = compute_age_factor(entries, floor=floor)
    consistency = compute_consistency_factor(entries, floor=floor)
    taint = compute_taint_factor(entries, floor=floor)
    review = compute_review_factor(entries, floor=floor)
    decay = compute_decay_factor(entries, floor=floor, decay_lambda=decay_lambda)

    # Taint zeros the score -- FA-A-007
    if taint == 0.0:
        return 0.0

    raw = age * consistency * taint * review * decay
    return max(floor, min(1.0, raw))


def score_to_tier(score: float) -> TrustTier:
    """Map a continuous trust score to its display tier.

    Display tiers are overlays on the continuous value -- all policy
    calculations must use the raw score, never the tier.

    Args:
        score: Trust score in [0.0, 1.0].

    Returns:
        The corresponding TrustTier.
    """
    for lower, upper, tier in _TIER_BOUNDARIES:
        if lower <= score <= upper:
            return tier
    # Edge case: score exactly 0.0 maps to PROBATIONARY
    return TrustTier.PROBATIONARY
