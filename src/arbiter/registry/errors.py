"""Error types for the registry package."""

from __future__ import annotations

from typing import Any


class RegistryError(Exception):
    """Base error for all registry errors."""

    def __init__(
        self,
        message: str,
        error_code: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        super().__init__(message)


class DuplicateAuthorityError(RegistryError):
    """Two or more nodes claim authority for the same domain (C004/FA-A-003)."""

    def __init__(
        self,
        message: str,
        error_code: str,
        domain: str,
        claiming_nodes: list[str],
    ) -> None:
        self.domain = domain
        self.claiming_nodes = claiming_nodes
        super().__init__(
            message=message,
            error_code=error_code,
            context={"domain": domain, "claiming_nodes": claiming_nodes},
        )


class NodeNotFoundError(RegistryError):
    """Referenced node_id does not exist in the access graph."""

    def __init__(
        self,
        message: str,
        error_code: str,
        node_id: str,
    ) -> None:
        self.node_id = node_id
        super().__init__(
            message=message,
            error_code=error_code,
            context={"node_id": node_id},
        )


class AuthorityMismatchError(RegistryError):
    """Classification rule's authoritative_node doesn't match graph (FA-A-030)."""

    def __init__(
        self,
        message: str,
        error_code: str,
        rule_index: int,
        authoritative_node: str,
        expected_domains: list[str],
    ) -> None:
        self.rule_index = rule_index
        self.authoritative_node = authoritative_node
        self.expected_domains = expected_domains
        super().__init__(
            message=message,
            error_code=error_code,
            context={
                "rule_index": rule_index,
                "authoritative_node": authoritative_node,
                "expected_domains": expected_domains,
            },
        )


class InvalidGraphError(RegistryError):
    """Access graph fails structural validation."""

    def __init__(
        self,
        message: str,
        error_code: str,
        details: list[str],
    ) -> None:
        self.details = details
        super().__init__(
            message=message,
            error_code=error_code,
            context={"details": details},
        )


class ClassificationRegistryError(RegistryError):
    """Classification registry YAML is malformed or fails schema validation."""

    def __init__(
        self,
        message: str,
        error_code: str,
        source_path: str,
        details: list[str],
    ) -> None:
        self.source_path = source_path
        self.details = details
        super().__init__(
            message=message,
            error_code=error_code,
            context={"source_path": source_path, "details": details},
        )
