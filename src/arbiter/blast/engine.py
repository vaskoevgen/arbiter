"""Orchestrator for blast radius evaluation, plus graph builder helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from .classification import classify_blast
from .errors import NodeNotFoundError, NotificationError
from .models import (
    AccessGraph,
    ActionCategory,
    BlastResult,
    HumanGateNotifier,
    NodeId,
    NodeMetadata,
    SoakParams,
)
from .soak import compute_soak_duration
from .traversal import compute_blast_radius

__all__ = ["evaluate_blast", "add_node", "add_edge"]


def evaluate_blast(
    graph: AccessGraph,
    origin: NodeId,
    soak_params: SoakParams,
    notifier: HumanGateNotifier | None = None,
    max_depth: int | None = None,
) -> BlastResult:
    """Orchestrate traversal, classification, soak, and notification.

    Primary entry point for blast radius evaluation.
    """
    traversal = compute_blast_radius(graph, origin, max_depth=max_depth)
    classification = classify_blast(traversal, soak_params)

    soak_duration = None
    if classification.action == ActionCategory.SOAK:
        soak_duration = compute_soak_duration(
            traversal.highest_data_tier,
            graph.metadata[origin].trust_score,
            soak_params,
        )

    computed_at = datetime.now(timezone.utc)

    result = BlastResult(
        origin_node=origin,
        reachable_nodes=traversal.reachable_nodes,
        highest_data_tier=traversal.highest_data_tier,
        action=classification.action,
        legal_flag=classification.legal_flag,
        soak_duration=soak_duration,
        per_node_details=traversal.node_details,
        computed_at=computed_at,
        cycle_detected=traversal.cycle_detected,
        max_depth_reached=traversal.max_depth_reached,
        contributing_nodes=classification.contributing_nodes,
    )

    # Fire notifier on HUMAN_GATE
    if classification.action == ActionCategory.HUMAN_GATE and notifier is not None:
        try:
            notifier.notify(result)
        except Exception as exc:
            raise NotificationError(
                origin_node=origin,
                action=ActionCategory.HUMAN_GATE.value,
                underlying_error=str(exc),
            ) from exc

    return result


def add_node(
    graph: AccessGraph,
    metadata: NodeMetadata,
) -> AccessGraph:
    """Add a node with its metadata to the access graph (builder pattern)."""
    graph.metadata[metadata.node_id] = metadata
    if metadata.node_id not in graph.adjacency:
        graph.adjacency[metadata.node_id] = []
    return graph


def add_edge(
    graph: AccessGraph,
    source: NodeId,
    target: NodeId,
) -> AccessGraph:
    """Add a directed edge from *source* to *target* (builder pattern)."""
    if source not in graph.metadata:
        raise NodeNotFoundError(source)
    if target not in graph.metadata:
        raise NodeNotFoundError(target)

    neighbors = graph.adjacency.setdefault(source, [])
    if target not in neighbors:
        neighbors.append(target)
    return graph
