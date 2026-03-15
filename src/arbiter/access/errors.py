"""Custom exceptions for the access auditor package.

Each error carries structured detail fields for machine-readable diagnostics.
"""

from __future__ import annotations

__all__ = [
    "SchemaWalkError",
    "RefResolutionError",
    "SchemaDepthExceededError",
    "ClassificationRegistryError",
    "ClassificationInputError",
    "ProfileComputationError",
    "AuditInputError",
    "LedgerWriteError",
    "GateConfigError",
]


class SchemaWalkError(ValueError):
    """Raised when the schema is not a dict or not a recognized type."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class RefResolutionError(ValueError):
    """Raised when a $ref resolver fails for a URI."""

    def __init__(self, ref_uri: str, detail: str) -> None:
        self.ref_uri = ref_uri
        self.detail = detail
        super().__init__(f"Failed to resolve $ref '{ref_uri}': {detail}")


class SchemaDepthExceededError(ValueError):
    """Raised when traversal depth exceeds max_depth."""

    def __init__(self, path: str, max_depth: int) -> None:
        self.path = path
        self.max_depth = max_depth
        super().__init__(
            f"Schema depth exceeded max_depth={max_depth} at path '{path}'"
        )


class ClassificationRegistryError(ValueError):
    """Raised for invalid classification registry entries."""

    def __init__(self, detail: str, **kwargs: object) -> None:
        self.detail = detail
        self.extra = kwargs
        super().__init__(detail)


class ClassificationInputError(ValueError):
    """Raised when classify_fields receives invalid input."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class ProfileComputationError(RuntimeError):
    """Raised when structural profile computation fails."""

    def __init__(self, node_id: str, detail: str, **kwargs: object) -> None:
        self.node_id = node_id
        self.detail = detail
        self.extra = kwargs
        super().__init__(f"Profile computation failed for node '{node_id}': {detail}")


class AuditInputError(ValueError):
    """Raised when audit inputs are inconsistent (e.g., node_id mismatch)."""

    def __init__(self, detail: str, **kwargs: object) -> None:
        self.detail = detail
        self.extra = kwargs
        super().__init__(detail)


class LedgerWriteError(RuntimeError):
    """Raised when a ledger write fails."""

    def __init__(self, node_id: str, detail: str) -> None:
        self.node_id = node_id
        self.detail = detail
        super().__init__(f"Ledger write failed for node '{node_id}': {detail}")


class GateConfigError(ValueError):
    """Raised for invalid gate configuration."""

    def __init__(self, detail: str, **kwargs: object) -> None:
        self.detail = detail
        self.extra = kwargs
        super().__init__(detail)
