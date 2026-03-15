"""Pydantic models for the access graph registry."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DataClassificationTier(StrEnum):
    """Data classification tiers. Higher ordinal = more sensitive."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class FindingSeverity(StrEnum):
    """Severity levels for validation findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RelationType(StrEnum):
    """Edge relationship types in the access graph."""

    READS = "READS"
    WRITES = "WRITES"
    CALLS = "CALLS"
    DEPENDS_ON = "DEPENDS_ON"
    MANAGES = "MANAGES"


class Edge(BaseModel):
    """A directed edge in the access graph."""

    model_config = ConfigDict(frozen=True)

    target: str = Field(min_length=1)
    relation_type: RelationType


class GraphNode(BaseModel):
    """A node in the access graph representing a component/service."""

    model_config = ConfigDict(frozen=True)

    node_id: str = Field(min_length=1)
    authority_domains: list[str] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AccessGraph(BaseModel):
    """Complete access graph snapshot. Frozen with domain exclusivity validator."""

    model_config = ConfigDict(frozen=True)

    nodes: dict[str, GraphNode]
    graph_version: str
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_domain_exclusivity(self) -> AccessGraph:
        domain_owners: dict[str, list[str]] = {}
        for node_id, node in self.nodes.items():
            if node.node_id != node_id:
                raise ValueError(
                    f"Node id '{node.node_id}' does not match key '{node_id}'"
                )
            for edge in node.edges:
                if edge.target not in self.nodes:
                    raise ValueError(
                        f"Node '{node_id}' has edge to '{edge.target}' "
                        f"which does not exist in the graph"
                    )
            for domain in node.authority_domains:
                domain_owners.setdefault(domain, []).append(node_id)

        for domain, owners in domain_owners.items():
            if len(owners) > 1:
                from .errors import DuplicateAuthorityError

                raise DuplicateAuthorityError(
                    message=(
                        f"Domain '{domain}' claimed by multiple nodes: "
                        f"{', '.join(sorted(owners))}"
                    ),
                    error_code="C004",
                    domain=domain,
                    claiming_nodes=sorted(owners),
                )
        return self


class AuthorityMap(BaseModel):
    """Derived domain-to-node mapping. O(1) lookups by domain."""

    model_config = ConfigDict(frozen=True)

    domain_to_node: dict[str, str]
    node_to_domains: dict[str, list[str]]


class ClassificationRule(BaseModel):
    """A single classification rule from classifications.yaml."""

    model_config = ConfigDict(frozen=True)

    field_pattern: str = Field(min_length=1)
    tier: DataClassificationTier
    authoritative_node: str = Field(min_length=1)
    canary_pattern: str | None = None


class ClassificationRegistry(BaseModel):
    """Collection of classification rules."""

    model_config = ConfigDict(frozen=True)

    rules: list[ClassificationRule]
    source_path: str | None = None


class GraphSnapshot(BaseModel):
    """Atomic snapshot: validated AccessGraph + derived AuthorityMap."""

    model_config = ConfigDict(frozen=True)

    access_graph: AccessGraph
    authority_map: AuthorityMap


class TraversalResult(BaseModel):
    """Result from BFS or DFS traversal."""

    visited_nodes: list[str]
    traversed_edges: list[Edge]
    depth_map: dict[str, int]


class NeighborEntry(BaseModel):
    """A neighbor of a node: target node_id + connecting edge."""

    node_id: str
    edge: Edge


class ValidationFinding(BaseModel):
    """Finding from classification-vs-graph cross-validation (FA-A-030)."""

    severity: FindingSeverity
    rule_index: int
    field_pattern: str
    authoritative_node: str
    message: str
    error_code: str
