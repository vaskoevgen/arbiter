"""Blast radius & soak computation package."""

from pydantic import ValidationError

from .classification import classify_blast, classify_node
from .engine import add_edge, add_node, evaluate_blast
from .errors import GraphInconsistencyError, NodeNotFoundError, NotificationError
from .models import (
    AccessGraph,
    AccessGraphEdge,
    ActionCategory,
    BlastResult,
    ClassificationResult,
    DataTier,
    HumanGateNotifier,
    NodeBlastDetail,
    NodeId,
    NodeMetadata,
    SoakParams,
    TraversalResult,
)
from .soak import compute_soak_duration
from .traversal import compute_blast_radius

__all__ = [
    "DataTier",
    "ActionCategory",
    "NodeMetadata",
    "AccessGraphEdge",
    "AccessGraph",
    "NodeBlastDetail",
    "TraversalResult",
    "ClassificationResult",
    "SoakParams",
    "BlastResult",
    "HumanGateNotifier",
    "compute_blast_radius",
    "NodeNotFoundError",
    "GraphInconsistencyError",
    "classify_blast",
    "compute_soak_duration",
    "evaluate_blast",
    "NotificationError",
    "add_node",
    "ValidationError",
    "add_edge",
    "classify_node",
]
