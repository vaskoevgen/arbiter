"""Classification registry loading, validation, and field matching."""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml
from pydantic import ValidationError

from .errors import (
    AuthorityMismatchError,
    ClassificationRegistryError,
    RegistryError,
)
from .models import (
    ClassificationRegistry,
    ClassificationRule,
    FindingSeverity,
    ValidationFinding,
)
from .store import _require_snapshot


def load_classification_registry(file_path: str) -> ClassificationRegistry:
    """Load and validate a ClassificationRegistry from a YAML file."""
    p = Path(file_path)

    if not p.exists():
        raise ClassificationRegistryError(
            message=f"Classification file not found: {file_path}",
            error_code="FILE_NOT_FOUND",
            source_path=file_path,
            details=["File not found"],
        )

    try:
        raw = p.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except Exception as exc:
        raise ClassificationRegistryError(
            message=f"Cannot parse YAML: {file_path}",
            error_code="YAML_PARSE_ERROR",
            source_path=file_path,
            details=[f"YAML parse error: {exc}"],
        ) from exc

    if not isinstance(data, dict):
        raise ClassificationRegistryError(
            message=f"Expected YAML dict, got {type(data).__name__}",
            error_code="SCHEMA_VALIDATION_ERROR",
            source_path=file_path,
            details=["Root element must be a mapping"],
        )

    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise ClassificationRegistryError(
            message="'rules' must be a list",
            error_code="SCHEMA_VALIDATION_ERROR",
            source_path=file_path,
            details=["'rules' key must contain a list"],
        )

    errors: list[str] = []
    rules: list[ClassificationRule] = []
    for idx, entry in enumerate(rules_raw):
        try:
            rules.append(ClassificationRule(**entry))
        except (ValidationError, TypeError) as exc:
            errors.append(f"Rule {idx}: {exc}")

    if errors:
        raise ClassificationRegistryError(
            message="Classification rules failed schema validation",
            error_code="SCHEMA_VALIDATION_ERROR",
            source_path=file_path,
            details=errors,
        )

    return ClassificationRegistry(rules=rules, source_path=file_path)


def validate_classifications_against_graph(
    classification_registry: ClassificationRegistry,
    strict: bool = True,
) -> list[ValidationFinding]:
    """Cross-validate classification rules against the current access graph.

    FA-A-030: every authoritative_node in a classification rule must exist in
    the graph and must declare authority for at least one domain.

    In strict mode, raises AuthorityMismatchError on the first CRITICAL finding.
    """
    snap = _require_snapshot()
    findings: list[ValidationFinding] = []

    for idx, rule in enumerate(classification_registry.rules):
        node_id = rule.authoritative_node

        # Check node exists
        if node_id not in snap.access_graph.nodes:
            finding = ValidationFinding(
                severity=FindingSeverity.CRITICAL,
                rule_index=idx,
                field_pattern=rule.field_pattern,
                authoritative_node=node_id,
                message=(
                    f"Authoritative node '{node_id}' in rule {idx} "
                    f"(pattern '{rule.field_pattern}') does not exist in "
                    f"the access graph"
                ),
                error_code="FA-A-030",
            )
            findings.append(finding)
            if strict:
                raise AuthorityMismatchError(
                    message=finding.message,
                    error_code="FA-A-030",
                    rule_index=idx,
                    authoritative_node=node_id,
                    expected_domains=[],
                )
            continue

        # Check node declares at least one authority domain
        domains = snap.authority_map.node_to_domains.get(node_id, [])
        if not domains:
            finding = ValidationFinding(
                severity=FindingSeverity.CRITICAL,
                rule_index=idx,
                field_pattern=rule.field_pattern,
                authoritative_node=node_id,
                message=(
                    f"Authoritative node '{node_id}' in rule {idx} "
                    f"(pattern '{rule.field_pattern}') exists but declares "
                    f"no authority domains"
                ),
                error_code="FA-A-030",
            )
            findings.append(finding)
            if strict:
                raise AuthorityMismatchError(
                    message=finding.message,
                    error_code="FA-A-030",
                    rule_index=idx,
                    authoritative_node=node_id,
                    expected_domains=[],
                )

    return findings


def classify_field(
    field_name: str,
    classification_registry: ClassificationRegistry,
) -> ClassificationRule | None:
    """Match a field name against classification rules. First match wins."""
    for rule in classification_registry.rules:
        if fnmatch.fnmatch(field_name, rule.field_pattern):
            return rule
    return None
