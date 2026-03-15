"""Graph traversal primitives: neighbors, BFS, DFS."""

from __future__ import annotations

from collections import deque
from typing import Callable

from .errors import NodeNotFoundError, RegistryError
from .models import (
    Edge,
    GraphNode,
    NeighborEntry,
    RelationType,
    TraversalResult,
)
from .store import _require_snapshot

# Type alias for optional pruning predicate
TraversalPredicate = Callable[[GraphNode], bool]


def neighbors(node_id: str) -> list[NeighborEntry]:
    """Return direct outgoing neighbors for *node_id*."""
    snap = _require_snapshot()
    node = snap.access_graph.nodes.get(node_id)
    if node is None:
        raise NodeNotFoundError(
            message=f"Node '{node_id}' not found in access graph",
            error_code="NODE_NOT_FOUND",
            node_id=node_id,
        )
    result: list[NeighborEntry] = []
    for edge in node.edges:
        result.append(NeighborEntry(node_id=edge.target, edge=edge))
    return result


def bfs(
    start_node_id: str,
    max_depth: int = -1,
    relation_types: list[RelationType] | None = None,
    predicate: TraversalPredicate | None = None,
) -> TraversalResult:
    """Breadth-first traversal from *start_node_id*.

    Uses a visited set for cycle safety. Optional *max_depth* limits
    traversal depth (-1 = unlimited). Optional *relation_types* filters
    which edge types are followed. Optional *predicate* prunes subtrees
    when it returns False.
    """
    snap = _require_snapshot()
    nodes = snap.access_graph.nodes

    if start_node_id not in nodes:
        raise NodeNotFoundError(
            message=f"Node '{start_node_id}' not found in access graph",
            error_code="NODE_NOT_FOUND",
            node_id=start_node_id,
        )

    relation_set = set(relation_types) if relation_types else None

    visited_nodes: list[str] = []
    traversed_edges: list[Edge] = []
    depth_map: dict[str, int] = {}
    visited: set[str] = set()

    queue: deque[tuple[str, int]] = deque()
    queue.append((start_node_id, 0))
    visited.add(start_node_id)

    while queue:
        current_id, depth = queue.popleft()
        visited_nodes.append(current_id)
        depth_map[current_id] = depth

        current_node = nodes.get(current_id)
        if current_node is None:
            continue

        # Predicate check -- prune subtree if False
        if predicate is not None and not predicate(current_node):
            continue

        if max_depth >= 0 and depth >= max_depth:
            continue

        for edge in current_node.edges:
            if relation_set and edge.relation_type not in relation_set:
                continue
            if edge.target not in visited:
                visited.add(edge.target)
                traversed_edges.append(edge)
                queue.append((edge.target, depth + 1))

    return TraversalResult(
        visited_nodes=visited_nodes,
        traversed_edges=traversed_edges,
        depth_map=depth_map,
    )


def dfs(
    start_node_id: str,
    max_depth: int = -1,
    relation_types: list[RelationType] | None = None,
    predicate: TraversalPredicate | None = None,
) -> TraversalResult:
    """Depth-first traversal from *start_node_id*.

    Uses a visited set for cycle safety. Optional *max_depth* limits
    traversal depth (-1 = unlimited). Optional *relation_types* filters
    which edge types are followed. Optional *predicate* prunes subtrees
    when it returns False.
    """
    snap = _require_snapshot()
    nodes = snap.access_graph.nodes

    if start_node_id not in nodes:
        raise NodeNotFoundError(
            message=f"Node '{start_node_id}' not found in access graph",
            error_code="NODE_NOT_FOUND",
            node_id=start_node_id,
        )

    relation_set = set(relation_types) if relation_types else None

    visited_nodes: list[str] = []
    traversed_edges: list[Edge] = []
    depth_map: dict[str, int] = {}
    visited: set[str] = set()

    # Iterative DFS with explicit stack: (node_id, depth)
    stack: deque[tuple[str, int]] = deque()
    stack.append((start_node_id, 0))

    while stack:
        current_id, depth = stack.pop()

        if current_id in visited:
            continue
        visited.add(current_id)
        visited_nodes.append(current_id)
        depth_map[current_id] = depth

        current_node = nodes.get(current_id)
        if current_node is None:
            continue

        if predicate is not None and not predicate(current_node):
            continue

        if max_depth >= 0 and depth >= max_depth:
            continue

        # Push children in reverse order so left-most is processed first
        for edge in reversed(current_node.edges):
            if relation_set and edge.relation_type not in relation_set:
                continue
            if edge.target not in visited:
                traversed_edges.append(edge)
                stack.append((edge.target, depth + 1))

    return TraversalResult(
        visited_nodes=visited_nodes,
        traversed_edges=traversed_edges,
        depth_map=depth_map,
    )
