"""Taint scanner: scans response bodies for canary fingerprints.

Detects data leaks by checking if canary fingerprints appear in node
output where the node is not authorized for that data tier.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import TaintResult

if TYPE_CHECKING:
    from .corpus import CanaryCorpus

__all__ = [
    "scan_for_taint",
]


def scan_for_taint(
    response_body: str,
    canary_corpus: CanaryCorpus,
    *,
    node_id: str = "",
    authorized_tiers: set[str] | None = None,
) -> TaintResult:
    """Scan a response body for canary fingerprints indicating taint escape.

    Iterates over all active canaries in the corpus and checks if their
    fingerprint appears in the response body. If found and the node is not
    authorized for that tier, returns a TaintResult with escaped=True.

    Args:
        response_body: The raw response body string to scan.
        canary_corpus: The corpus of active canaries to search for.
        node_id: The node that produced this response (for reporting).
        authorized_tiers: Set of tier names this node is authorized for.
            If None, all canary matches are treated as escapes.

    Returns:
        TaintResult indicating whether a taint escape was detected.
    """
    if authorized_tiers is None:
        authorized_tiers = set()

    for canary in canary_corpus.get_active_canaries():
        if canary.fingerprint in response_body:
            # Check if the node is authorized for this canary's tier
            if canary.classification not in authorized_tiers:
                return TaintResult(
                    escaped=True,
                    canary_id=canary.id,
                    classification=canary.classification,
                    node=node_id,
                    fingerprint=canary.fingerprint,
                )

    return TaintResult(escaped=False)
