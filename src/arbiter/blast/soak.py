"""Soak duration computation.

Formula: base_duration(tier) * (2.0 - trust_score) * max(1.0, sqrt(target / rate))

Monotonic guarantees:
  FA-A-009: non-decreasing as trust_score decreases
  FA-A-010: non-decreasing as (target / rate) increases
"""

from __future__ import annotations

import math
from datetime import timedelta

from .models import DataTier, SoakParams

__all__ = ["compute_soak_duration"]

_EPSILON = 1e-9


def compute_soak_duration(
    tier: DataTier,
    trust_score: float,
    soak_params: SoakParams,
) -> timedelta:
    """Compute soak duration for a given tier and trust score.

    Returns a positive timedelta. observed_rate_rps is floored to 1e-9
    to prevent division by zero.
    """
    # Validate trust_score
    if math.isnan(trust_score) or math.isinf(trust_score):
        raise ValueError(f"Invalid trust_score: {trust_score}")

    # Look up base duration
    if tier not in soak_params.base_durations:
        raise KeyError(f"No base duration for tier {tier!r}")

    base: timedelta = soak_params.base_durations[tier]

    # Clamp trust_score to [0.0, 1.0]
    clamped = max(0.0, min(1.0, trust_score))

    # Floor observed rate
    rate = max(_EPSILON, soak_params.observed_rate_rps)

    trust_factor = 2.0 - clamped
    volume_factor = max(1.0, math.sqrt(soak_params.target_requests / rate))

    total_seconds = base.total_seconds() * trust_factor * volume_factor
    return timedelta(seconds=total_seconds)
