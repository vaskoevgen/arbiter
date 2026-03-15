"""Custom exceptions for the blast radius package."""

from __future__ import annotations

__all__ = [
    "NodeNotFoundError",
    "GraphInconsistencyError",
    "NotificationError",
]


class NodeNotFoundError(KeyError):
    """Raised when a node_id is not found in the access graph metadata."""

    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        super().__init__(f"Node not found in graph: {node_id!r}")


class GraphInconsistencyError(ValueError):
    """Raised when adjacency references a node that has no metadata entry."""

    def __init__(self, missing_node_id: str, referenced_by: str) -> None:
        self.missing_node_id = missing_node_id
        self.referenced_by = referenced_by
        super().__init__(
            f"Node {missing_node_id!r} referenced by {referenced_by!r} "
            f"has no metadata entry"
        )


class NotificationError(RuntimeError):
    """Raised when a HumanGateNotifier.notify() call fails."""

    def __init__(
        self,
        origin_node: str,
        action: str,
        underlying_error: str,
    ) -> None:
        self.origin_node = origin_node
        self.action = action
        self.underlying_error = underlying_error
        super().__init__(
            f"Notification failed for origin={origin_node!r}, "
            f"action={action}: {underlying_error}"
        )
