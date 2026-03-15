"""Configuration loading for the conflict resolver."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from .errors import ConflictConfigError
from .models import ConflictResolverConfig


def load_config(config_path: str) -> ConflictResolverConfig:
    """Load and validate ConflictResolverConfig from a YAML file."""
    p = Path(config_path)

    if not p.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path}"
        )

    try:
        raw = p.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConflictConfigError(
            message=f"Invalid YAML in config file: {config_path}: {exc}",
            error_code="INVALID_CONFIG",
            context={"config_path": config_path},
        ) from exc

    if not isinstance(data, dict):
        raise ConflictConfigError(
            message=f"Config must be a YAML mapping, got {type(data).__name__}",
            error_code="INVALID_CONFIG",
            context={"config_path": config_path},
        )

    try:
        return ConflictResolverConfig(**data)
    except ValidationError as exc:
        raise ConflictConfigError(
            message=f"Invalid config values: {exc}",
            error_code="INVALID_CONFIG",
            context={
                "config_path": config_path,
                "validation_errors": exc.errors(),
            },
        ) from exc
