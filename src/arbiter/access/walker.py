"""OpenAPI response schema walker.

Pure DFS traversal with cycle detection, $ref resolution, and
allOf/anyOf/oneOf union flattening. Emits FieldEntry for every leaf field
and SchemaWarning for incomplete/missing schemas.
"""

from __future__ import annotations

from typing import Any, Callable

from .errors import RefResolutionError, SchemaDepthExceededError, SchemaWalkError
from .models import FieldEntry, SchemaWarning, WalkResult

__all__ = [
    "walk_response_schema",
]

# OpenAPI leaf types (no nested structure)
_LEAF_TYPES = {"string", "integer", "number", "boolean"}


def walk_response_schema(
    schema: dict[str, Any] | None,
    ref_resolver: Callable[[str], dict[str, Any]],
    root_path: str = "response",
    max_depth: int = 64,
) -> WalkResult:
    """DFS-traverse an OpenAPI response schema.

    Resolves $ref references via the provided resolver with cycle detection,
    flattens allOf/anyOf/oneOf with union semantics, and emits a FieldEntry
    for every leaf field.

    Args:
        schema: The OpenAPI response schema dict, or None.
        ref_resolver: Callable that resolves a $ref URI to a schema dict.
        root_path: Root path prefix for all field paths.
        max_depth: Maximum traversal depth (1-256).

    Returns:
        WalkResult with discovered fields and any warnings.

    Raises:
        SchemaWalkError: If schema is not a dict (after None-check).
        RefResolutionError: If ref_resolver raises for a $ref URI.
        SchemaDepthExceededError: If traversal depth exceeds max_depth.
    """
    fields: list[FieldEntry] = []
    warnings: list[SchemaWarning] = []

    # Handle None/empty schema
    if schema is None or schema == {}:
        warnings.append(
            SchemaWarning(
                code="INCOMPLETE_SCHEMA",
                path="",
                message="Schema is missing or empty.",
            )
        )
        return WalkResult(fields=fields, warnings=warnings)

    # Validate schema type
    if not isinstance(schema, dict):
        raise SchemaWalkError(
            f"schema must be a dict or None, got {type(schema).__name__}"
        )

    visited_refs: set[str] = set()
    _walk_node(
        schema, root_path, ref_resolver, fields, warnings,
        visited_refs, 0, max_depth,
    )

    return WalkResult(fields=fields, warnings=warnings)


def _walk_node(
    node: dict[str, Any],
    path: str,
    ref_resolver: Callable[[str], dict[str, Any]],
    fields: list[FieldEntry],
    warnings: list[SchemaWarning],
    visited_refs: set[str],
    depth: int,
    max_depth: int,
) -> None:
    """Recursively walk a schema node."""
    if depth > max_depth:
        raise SchemaDepthExceededError(path=path, max_depth=max_depth)

    # Handle $ref
    if "$ref" in node:
        ref_uri = node["$ref"]
        if ref_uri in visited_refs:
            warnings.append(
                SchemaWarning(
                    code="INCOMPLETE_SCHEMA",
                    path=ref_uri,
                    message=f"Circular $ref detected: {ref_uri}",
                )
            )
            return
        visited_refs.add(ref_uri)
        try:
            resolved = ref_resolver(ref_uri)
        except Exception as exc:
            raise RefResolutionError(ref_uri=ref_uri, detail=str(exc)) from exc
        if not isinstance(resolved, dict):
            warnings.append(
                SchemaWarning(
                    code="INCOMPLETE_SCHEMA",
                    path=ref_uri,
                    message=f"$ref '{ref_uri}' resolved to non-dict type.",
                )
            )
            return
        _walk_node(
            resolved, path, ref_resolver, fields, warnings,
            visited_refs, depth + 1, max_depth,
        )
        return

    # Handle allOf/anyOf/oneOf (union semantics)
    for combiner in ("allOf", "anyOf", "oneOf"):
        if combiner in node:
            sub_schemas = node[combiner]
            if isinstance(sub_schemas, list):
                for sub in sub_schemas:
                    if isinstance(sub, dict):
                        _walk_node(
                            sub, path, ref_resolver, fields, warnings,
                            visited_refs, depth + 1, max_depth,
                        )
            return

    schema_type = node.get("type", "")
    nullable = node.get("nullable", False)
    format_hint = node.get("format", "")

    # Leaf types
    if schema_type in _LEAF_TYPES:
        fields.append(
            FieldEntry(
                path=path,
                field_type=schema_type,
                nullable=nullable,
                format_hint=format_hint,
            )
        )
        return

    # Object type -- recurse into properties
    if schema_type == "object" or "properties" in node:
        properties = node.get("properties", {})
        if not properties:
            # Object with no properties is a warning
            warnings.append(
                SchemaWarning(
                    code="INCOMPLETE_SCHEMA",
                    path=path,
                    message=f"Object at '{path}' has no properties defined.",
                )
            )
            return
        for prop_name, prop_schema in sorted(properties.items()):
            child_path = f"{path}.{prop_name}"
            if isinstance(prop_schema, dict):
                _walk_node(
                    prop_schema, child_path, ref_resolver, fields, warnings,
                    visited_refs, depth + 1, max_depth,
                )

        # Handle additionalProperties if it's a schema
        additional = node.get("additionalProperties")
        if isinstance(additional, dict):
            _walk_node(
                additional, f"{path}.<additional>", ref_resolver, fields,
                warnings, visited_refs, depth + 1, max_depth,
            )
        return

    # Array type -- recurse into items
    if schema_type == "array":
        items = node.get("items")
        if items is None or not isinstance(items, dict):
            warnings.append(
                SchemaWarning(
                    code="INCOMPLETE_SCHEMA",
                    path=path,
                    message=f"Array at '{path}' has no items schema.",
                )
            )
            return
        _walk_node(
            items, f"{path}[]", ref_resolver, fields, warnings,
            visited_refs, depth + 1, max_depth,
        )
        return

    # Unknown or no type -- treat as leaf with empty type
    if not schema_type:
        # Could be a schema with just properties but no type
        if "properties" not in node:
            warnings.append(
                SchemaWarning(
                    code="INCOMPLETE_SCHEMA",
                    path=path,
                    message=f"Schema at '{path}' has no type specified.",
                )
            )
    else:
        warnings.append(
            SchemaWarning(
                code="INCOMPLETE_SCHEMA",
                path=path,
                message=f"Unknown schema type '{schema_type}' at '{path}'.",
            )
        )
