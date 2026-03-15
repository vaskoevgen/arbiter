"""Error types for the conflicts package."""

from __future__ import annotations

from typing import Any


class ConflictResolutionError(Exception):
    """Error during conflict resolution."""

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


class ConflictStoreError(Exception):
    """Error from the conflict persistence store."""

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


class ConflictNotFoundError(ConflictResolutionError):
    """No conflict with the given conflict_id exists."""

    def __init__(
        self,
        message: str,
        error_code: str,
        conflict_id: str,
    ) -> None:
        self.conflict_id = conflict_id
        super().__init__(
            message=message,
            error_code=error_code,
            context={"conflict_id": conflict_id},
        )


class ConflictConfigError(Exception):
    """Error loading or validating conflict resolver config."""

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
