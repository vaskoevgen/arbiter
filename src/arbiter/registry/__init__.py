"""Access graph registry: store, authority map, traversal, classification."""

from .classification import (
    classify_field,
    load_classification_registry,
    validate_classifications_against_graph,
)
from .errors import (
    AuthorityMismatchError,
    ClassificationRegistryError,
    DuplicateAuthorityError,
    InvalidGraphError,
    NodeNotFoundError,
    RegistryError,
)
from .models import (
    AccessGraph,
    AuthorityMap,
    ClassificationRegistry,
    ClassificationRule,
    DataClassificationTier,
    Edge,
    FindingSeverity,
    GraphNode,
    GraphSnapshot,
    NeighborEntry,
    RelationType,
    TraversalResult,
    ValidationFinding,
)
from .store import (
    build_authority_map,
    get_all_node_ids,
    get_authority,
    get_current_snapshot,
    get_domains_for_node,
    get_node,
    register_graph,
    register_graph_from_file,
)
from .traversal import bfs, dfs, neighbors

__all__ = [
    # Enums
    "DataClassificationTier",
    "FindingSeverity",
    "RelationType",
    # Models
    "Edge",
    "GraphNode",
    "AccessGraph",
    "AuthorityMap",
    "ClassificationRule",
    "ClassificationRegistry",
    "GraphSnapshot",
    "TraversalResult",
    "NeighborEntry",
    "ValidationFinding",
    # Errors
    "RegistryError",
    "DuplicateAuthorityError",
    "NodeNotFoundError",
    "AuthorityMismatchError",
    "InvalidGraphError",
    "ClassificationRegistryError",
    # Store functions
    "register_graph",
    "register_graph_from_file",
    "get_authority",
    "get_domains_for_node",
    "get_node",
    "get_all_node_ids",
    "get_current_snapshot",
    "build_authority_map",
    # Traversal
    "neighbors",
    "bfs",
    "dfs",
    # Classification
    "load_classification_registry",
    "validate_classifications_against_graph",
    "classify_field",
]
