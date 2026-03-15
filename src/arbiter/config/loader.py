"""Configuration loading, validation, and generation for Arbiter.

Module-level ``_config`` singleton pattern.  Call ``load_config()`` to
initialise, ``get_config()`` to retrieve, and ``reset_config()`` to clear.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from . import models as _models
from .models import (
    ArbiterConfig,
    ConfigNotLoadedError,
    ConfigurationError,
    OptionalPath,
    ValidationErrorDetail,
)


__all__ = [
    "load_config",
    "get_config",
    "reset_config",
    "generate_default_config",
    "validate_config_file",
]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_config: ArbiterConfig | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_yaml(path: Path) -> dict[str, Any]:
    """Read and parse a YAML file.  Returns a dict (empty for empty files)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except PermissionError:
        raise ConfigurationError(
            config_path=str(path),
            message=f"Permission denied reading {path}",
        )

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            config_path=str(path),
            message=f"YAML parse error in {path}: {exc}",
        )

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigurationError(
            config_path=str(path),
            message=(
                f"Expected YAML mapping at top level in {path}, "
                f"got {type(data).__name__}"
            ),
        )
    return data


def _build_config(
    yaml_data: dict[str, Any], config_path: str
) -> ArbiterConfig:
    """Construct an ArbiterConfig from YAML data via custom settings source.

    Sets the module-level ``_yaml_source_data`` so that
    ``ArbiterConfig.settings_customise_sources`` can pick it up at the
    correct priority (below env vars, above defaults).
    """
    _models._yaml_source_data = yaml_data
    try:
        return ArbiterConfig()
    except (ValidationError, ValueError) as exc:
        errors: list[ValidationErrorDetail] = []
        if isinstance(exc, ValidationError):
            for err in exc.errors():
                field = ".".join(str(loc) for loc in err.get("loc", []))
                errors.append(
                    ValidationErrorDetail(
                        field=field,
                        message=err.get("msg", str(exc)),
                        value=str(err.get("input", "")),
                    )
                )
        raise ConfigurationError(
            config_path=config_path,
            message=f"Validation error in {config_path}: {exc}",
            validation_errors=errors,
        ) from exc
    finally:
        _models._yaml_source_data = {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(path: OptionalPath = None) -> ArbiterConfig:
    """Load, validate, and cache the Arbiter configuration.

    If *path* is ``None``, looks for ``arbiter.yaml`` in the current
    working directory.  If the resolved file does not exist, falls back
    to defaults (with env-var overrides).  Stores the result in the
    module-level singleton.

    Source priority: defaults -> YAML -> env vars.
    """
    global _config

    if path is None:
        resolved = Path(os.getcwd()) / "arbiter.yaml"
    else:
        resolved = Path(path)

    yaml_data: dict[str, Any] = {}
    if resolved.exists():
        yaml_data = _read_yaml(resolved)

    cfg = _build_config(yaml_data, str(resolved))
    _config = cfg
    return cfg


def get_config() -> ArbiterConfig:
    """Return the cached ArbiterConfig singleton.

    Raises ``ConfigNotLoadedError`` if ``load_config()`` has not been
    called (or ``reset_config()`` was called without a subsequent load).
    """
    if _config is None:
        raise ConfigNotLoadedError()
    return _config


def reset_config() -> None:
    """Reset the module-level singleton to ``None``.

    Primarily for test isolation.
    """
    global _config
    _config = None


def generate_default_config(path: str, overwrite: bool = False) -> None:
    """Generate an ``arbiter.yaml`` with all default values.

    Used by ``arbiter init``.  Will not overwrite an existing file
    unless *overwrite* is ``True``.
    """
    target = Path(path)

    if not target.parent.exists():
        raise ConfigurationError(
            config_path=path,
            message=f"Parent directory does not exist: {target.parent}",
        )

    if target.exists() and not overwrite:
        raise ConfigurationError(
            config_path=path,
            message=(
                f"File already exists at {path}. Use --force to overwrite."
            ),
        )

    defaults = ArbiterConfig()
    data = defaults.model_dump(mode="json")

    header = "# Arbiter configuration -- auto-generated defaults\n"
    body = yaml.dump(data, sort_keys=False, default_flow_style=False)

    try:
        target.write_text(header + body, encoding="utf-8")
    except PermissionError:
        raise ConfigurationError(
            config_path=path,
            message=f"Permission denied writing to {path}",
        )


def validate_config_file(path: str) -> ArbiterConfig:
    """Validate an existing ``arbiter.yaml`` without modifying the singleton.

    Returns the validated ``ArbiterConfig`` or raises
    ``ConfigurationError``.
    """
    target = Path(path)

    if not target.exists():
        raise ConfigurationError(
            config_path=path,
            message=f"Config file not found: {path}",
        )

    yaml_data = _read_yaml(target)
    return _build_config(yaml_data, path)
