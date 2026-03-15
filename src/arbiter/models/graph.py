"""Access graph models. AccessGraphNode is frozen; AccessGraph is mutable with integrity validation."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, model_validator

from .enums import DataTier, TrustTier
from .types import AuthorityDomain, NodeId

__all__ = [
    "AccessGraphNode",
    "AccessGraph",
]


class AccessGraphNode(BaseModel):
    """A node in the access graph representing a component/service.

    Edges are string-based NodeId references (adjacency list).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: NodeId
    data_access: list[DataTier]
    authority_domains: list[AuthorityDomain]
    edges: list[NodeId]
    trust_tier: TrustTier = TrustTier.PROBATIONARY
    metadata: dict[str, str] = {}


class AccessGraph(BaseModel):
    """Container for the full access graph.

    Mutable to allow incremental construction. Model validator ensures referential
    integrity: all edge targets must exist as keys in the nodes dict.
    """

    model_config = ConfigDict(extra="forbid")

    nodes: dict[NodeId, AccessGraphNode]
    version: str

    @model_validator(mode="after")
    def _check_referential_integrity(self) -> "AccessGraph":
        for node_id, node in self.nodes.items():
            if node.id != node_id:
                raise ValueError(
                    f"Node id '{node.id}' does not match its key '{node_id}' in the graph"
                )
            for edge_target in node.edges:
                if edge_target not in self.nodes:
                    raise ValueError(
                        f"Node '{node_id}' has edge to '{edge_target}' which does not exist "
                        f"in the graph"
                    )
        return self
