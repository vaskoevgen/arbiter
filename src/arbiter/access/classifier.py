"""Field classification and configuration loading.

Pure functions for matching field paths against the classification registry
and loading/validating gate and registry configurations.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from .errors import (
    ClassificationInputError,
    ClassificationRegistryError,
    GateConfigError,
)
from .models import (
    ClassificationRegistryEntry,
    ClassificationResult,
    ClassifiedField,
    DataTier,
    FieldEntry,
    GateConfig,
)

__all__ = [
    "classify_fields",
    "load_classification_registry",
    "load_gate_config",
]

# Pre-compiled regex cache (populated by load_classification_registry)
_regex_cache: dict[str, re.Pattern[str]] = {}


def classify_fields(
    fields: list[FieldEntry],
    registry_entries: list[ClassificationRegistryEntry],
) -> ClassificationResult:
    """Classify field entries against the classification registry.

    Matches each field path against the registry's fnmatch/regex patterns.
    Unmatched fields default to PUBLIC. If a field matches multiple patterns,
    the pattern yielding the highest DataTier wins.

    Args:
        fields: List of FieldEntry instances with non-empty paths.
        registry_entries: Classification registry entries with patterns and tiers.

    Returns:
        ClassificationResult with each field mapped to a DataTier.

    Raises:
        ClassificationRegistryError: Invalid regex pattern in registry.
        ClassificationInputError: FieldEntry with empty path.
    """
    classified: list[ClassifiedField] = []
    tier_set: set[DataTier] = set()

    for field_entry in fields:
        if not field_entry.path:
            raise ClassificationInputError("FieldEntry.path must not be empty")

        best_tier = DataTier.PUBLIC
        best_pattern = ""

        for reg_entry in registry_entries:
            matched = _match_pattern(
                field_entry.path, reg_entry.field_pattern, reg_entry.pattern_type
            )
            if matched and reg_entry.tier > best_tier:
                best_tier = reg_entry.tier
                best_pattern = reg_entry.field_pattern

        classified.append(
            ClassifiedField(
                path=field_entry.path,
                tier=best_tier,
                matched_pattern=best_pattern,
            )
        )
        tier_set.add(best_tier)

    return ClassificationResult(
        classified_fields=classified,
        tier_set=sorted(tier_set),
    )


def _match_pattern(field_path: str, pattern: str, pattern_type: str) -> bool:
    """Match a field path against a pattern.

    Args:
        field_path: The dot-separated field path.
        pattern: The fnmatch glob or regex pattern.
        pattern_type: Either 'fnmatch' or 'regex'.

    Returns:
        True if the pattern matches the field path.
    """
    if pattern_type == "fnmatch":
        return fnmatch.fnmatch(field_path, pattern)
    elif pattern_type == "regex":
        try:
            compiled = _regex_cache.get(pattern)
            if compiled is None:
                compiled = re.compile(pattern)
                _regex_cache[pattern] = compiled
            return compiled.search(field_path) is not None
        except re.error as exc:
            raise ClassificationRegistryError(
                f"Invalid regex pattern: {pattern!r}: {exc}",
                pattern=pattern,
            ) from exc
    return False


def load_classification_registry(
    registry_source: list[dict[str, Any]],
) -> list[ClassificationRegistryEntry]:
    """Load and validate classification registry entries.

    Pre-compiles regex patterns for performance. Validates all patterns
    are syntactically correct and all tiers are valid DataTier values.

    Args:
        registry_source: List of dicts, each with 'field_pattern', 'tier',
            and 'pattern_type' keys.

    Returns:
        List of validated ClassificationRegistryEntry instances.

    Raises:
        ClassificationRegistryError: For missing keys, invalid tiers,
            invalid pattern types, or un-compilable regex patterns.
    """
    entries: list[ClassificationRegistryEntry] = []

    for idx, raw in enumerate(registry_source):
        # Check required keys
        for key in ("field_pattern", "tier", "pattern_type"):
            if key not in raw:
                raise ClassificationRegistryError(
                    f"Entry at index {idx} is missing required key '{key}'",
                    entry_index=idx,
                    missing_key=key,
                )

        # Validate pattern_type
        pattern_type = raw["pattern_type"]
        if pattern_type not in ("fnmatch", "regex"):
            raise ClassificationRegistryError(
                f"Entry at index {idx} has invalid pattern_type: {pattern_type!r}",
                entry_index=idx,
                invalid_pattern_type=pattern_type,
            )

        # Validate tier
        tier_str = raw["tier"]
        try:
            tier = DataTier[tier_str] if isinstance(tier_str, str) else DataTier(tier_str)
        except (KeyError, ValueError) as exc:
            valid = [t.name for t in DataTier]
            raise ClassificationRegistryError(
                f"Entry at index {idx} has invalid tier: {tier_str!r}. "
                f"Valid tiers: {valid}",
                entry_index=idx,
                invalid_tier=tier_str,
                valid_tiers=valid,
            ) from exc

        # Validate regex patterns
        if pattern_type == "regex":
            try:
                compiled = re.compile(raw["field_pattern"])
                _regex_cache[raw["field_pattern"]] = compiled
            except re.error as exc:
                raise ClassificationRegistryError(
                    f"Entry at index {idx} has invalid regex: {raw['field_pattern']!r}: {exc}",
                    entry_index=idx,
                    pattern=raw["field_pattern"],
                ) from exc

        entries.append(
            ClassificationRegistryEntry(
                field_pattern=raw["field_pattern"],
                tier=tier,
                pattern_type=pattern_type,
                description=raw.get("description"),
            )
        )

    return entries


def load_gate_config(
    config_source: dict[str, Any],
) -> GateConfig:
    """Load and validate a GateConfig from a dict.

    Provides sensible defaults: block_on_codes=["C005"],
    assume_worst_on_incomplete=True.

    Args:
        config_source: Configuration dict.

    Returns:
        Validated GateConfig instance.

    Raises:
        GateConfigError: Invalid config type or invalid finding codes.
    """
    if not isinstance(config_source, dict):
        raise GateConfigError("config_source must be a dict")

    block_on_codes_raw = config_source.get("block_on_codes", ["C005"])
    assume_worst = config_source.get("assume_worst_on_incomplete", True)

    # Validate finding codes
    valid_codes = {"C005", "FA_A_015", "INCOMPLETE_SCHEMA"}
    block_on_codes: list[str] = []
    for code in block_on_codes_raw:
        code_str = str(code)
        if code_str not in valid_codes:
            raise GateConfigError(
                f"Invalid finding code: {code_str!r}. Valid codes: {sorted(valid_codes)}",
                invalid_code=code_str,
                valid_codes=sorted(valid_codes),
            )
        block_on_codes.append(code_str)

    return GateConfig(
        block_on_codes=block_on_codes,
        assume_worst_on_incomplete=assume_worst,
    )
