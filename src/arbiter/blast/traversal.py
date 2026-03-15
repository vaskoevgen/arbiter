"""BFS traversal of the access graph for blast radius computation."""

from __future__ import annotations

from collections import deque

from .errors import GraphInconsistencyError, NodeNotFoundError
from .models import (
    AccessGraph,
    ActionCategory,
    DataTier,
    NodeBlastDetail,
    NodeId,
    TraversalResult,
    DATA_TIER_SEVERITY,
)

__all__ = ["compute_blast_radius"]


def _classify_node_action(
    data_tier: DataTier,
    authorized_tiers: list[DataTier],
    trust_score: float,
    is_authoritative: bool,
    low_trust_threshold: float = 0.3,
) -> ActionCategory:
    """Quick per-node classification for traversal detail.

    Full classification logic lives in classification.py; this is a
    lightweight version used only to populate NodeBlastDetail.node_action
    during traversal so each detail is self-contained.
    """
    # Unauthorized tier -> HUMAN_GATE
    if data_tier not in authorized_tiers:
        return ActionCategory.HUMAN_GATE

    # Low trust authoritative -> HUMAN_GATE
    if is_authoritative and trust_score < low_trust_threshold:
        return ActionCategory.HUMAN_GATE

    if data_tier in (DataTier.FINANCIAL, DataTier.AUTH, DataTier.COMPLIANCE):
        return ActionCategory.HUMAN_GATE

    if data_tier == DataTier.PII:
        return ActionCategory.SOAK

    return ActionCategory.AUTO_MERGE


def compute_blast_radius(
    graph: AccessGraph,
    origin: NodeId,
    max_depth: int | None = None,
) -> TraversalResult:
    """Pure BFS traversal of the access graph from *origin*.

    Uses a visited-set to handle cycles efficiently (rabbit hole patch).
    Optionally bounded by *max_depth*.
    """
    # Validate inputs
    if max_depth is not None and max_depth < 0:
        raise ValueError(f"max_depth must be >= 0, got {max_depth}")

    if origin not in graph.metadata:
        raise NodeNotFoundError(origin)

    enqueued: set[NodeId] = set()
    reachable: set[NodeId] = set()
    details: list[NodeBlastDetail] = []
    cycle_detected = False
    max_depth_reached = 0
    highest_tier = graph.metadata[origin].data_tier

    # BFS queue: (node_id, depth)
    queue: deque[tuple[NodeId, int]] = deque()
    queue.append((origin, 0))
    enqueued.add(origin)

    while queue:
        node_id, depth = queue.popleft()

        meta = graph.metadata.get(node_id)
        if meta is None:
            raise GraphInconsistencyError(
                missing_node_id=node_id, referenced_by=node_id
            )

        reachable.add(node_id)

        if depth > max_depth_reached:
            max_depth_reached = depth

        if DATA_TIER_SEVERITY[meta.data_tier] > DATA_TIER_SEVERITY[highest_tier]:
            highest_tier = meta.data_tier

        is_authorized = meta.data_tier in meta.authorized_tiers
        node_action = _classify_node_action(
            meta.data_tier,
            meta.authorized_tiers,
            meta.trust_score,
            meta.is_authoritative,
        )

        details.append(
            NodeBlastDetail(
                node_id=node_id,
                data_tier=meta.data_tier,
                trust_score=meta.trust_score,
                is_authoritative=meta.is_authoritative,
                is_authorized_for_tier=is_authorized,
                node_action=node_action,
                depth=depth,
            )
        )

        # Expand neighbors only if within depth budget
        if max_depth is not None and depth >= max_depth:
            continue

        neighbors = graph.adjacency.get(node_id, [])
        for neighbor in neighbors:
            if neighbor not in graph.metadata:
                raise GraphInconsistencyError(
                    missing_node_id=neighbor, referenced_by=node_id
                )
            if neighbor in enqueued:
                # Back-edge: neighbor already processed means a true cycle.
                # Neighbor only enqueued (not yet processed) means convergence
                # (e.g. diamond), which is not a cycle.
                if neighbor in reachable:
                    cycle_detected = True
                continue
            enqueued.add(neighbor)
            queue.append((neighbor, depth + 1))

    return TraversalResult(
        origin=origin,
        reachable_nodes=frozenset(reachable),
        node_details=details,
        highest_data_tier=highest_tier,
        max_depth_reached=max_depth_reached,
        cycle_detected=cycle_detected,
    )
