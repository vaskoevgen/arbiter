"""Pydantic v2 configuration models for the Arbiter system.

Defines all config sections, the root ArbiterConfig (BaseSettings),
and exception types for configuration errors.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional, Tuple, Type

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource


__all__ = [
    "DataClassificationTier",
    "RegistryConfig",
    "TrustConfig",
    "TaintLockTiersList",
    "SoakDurationsMap",
    "SoakConfig",
    "OtlpConfig",
    "ApiConfig",
    "ClassificationRegistryConfig",
    "HumanGateConfig",
    "LedgerConfig",
    "ArbiterConfig",
    "ConfigurationError",
    "ValidationErrorDetail",
    "ValidationErrorList",
    "ConfigNotLoadedError",
    "OptionalPath",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DataClassificationTier(StrEnum):
    """Data classification tiers used across the Arbiter system."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

TaintLockTiersList = list[DataClassificationTier]
OptionalPath = str | None
ValidationErrorList = list["ValidationErrorDetail"]


# ---------------------------------------------------------------------------
# Section models (all frozen for immutability)
# ---------------------------------------------------------------------------

class RegistryConfig(BaseModel):
    """Component/service registry configuration."""

    model_config = {"frozen": True}

    path: str = "./registry"
    append_only: bool = True


class TrustConfig(BaseModel):
    """Trust score computation, decay, and conflict thresholds."""

    model_config = {"frozen": True}

    floor: float = Field(default=0.10, ge=0.0, le=1.0)
    authority_override_floor: float = Field(default=0.40, ge=0.0, le=1.0)
    decay_lambda: float = Field(default=0.05, ge=0.0)
    conflict_trust_delta_threshold: float = Field(default=0.20, ge=0.0, le=1.0)
    taint_lock_tiers: TaintLockTiersList = Field(
        default_factory=lambda: [
            DataClassificationTier.RESTRICTED,
            DataClassificationTier.CRITICAL,
        ]
    )


class SoakDurationsMap(BaseModel):
    """Mapping from DataClassificationTier to base soak duration in seconds."""

    model_config = {"frozen": True}

    PUBLIC: int = Field(default=3600, ge=0)
    INTERNAL: int = Field(default=7200, ge=0)
    CONFIDENTIAL: int = Field(default=14400, ge=0)
    RESTRICTED: int = Field(default=28800, ge=0)
    CRITICAL: int = Field(default=86400, ge=0)


class SoakConfig(BaseModel):
    """Soak testing parameters -- duration and request volume gates per tier."""

    model_config = {"frozen": True}

    base_durations: SoakDurationsMap = Field(default_factory=SoakDurationsMap)
    target_requests: int = Field(default=1000, ge=1)


class OtlpConfig(BaseModel):
    """OpenTelemetry Protocol (OTLP) listener ports."""

    model_config = {"frozen": True}

    listen_port: int = Field(default=4317, ge=1, le=65535)
    http_port: int = Field(default=4318, ge=1, le=65535)


class ApiConfig(BaseModel):
    """Arbiter HTTP API server configuration."""

    model_config = {"frozen": True}

    port: int = Field(default=7700, ge=1, le=65535)


class ClassificationRegistryConfig(BaseModel):
    """Field classification registry configuration."""

    model_config = {"frozen": True}

    path: str = "./classification_registry.yaml"


class HumanGateConfig(BaseModel):
    """Human-in-the-loop approval gate configuration."""

    model_config = {"frozen": True}

    webhook_url: Optional[str] = None
    block_on_gate: bool = True


class LedgerConfig(BaseModel):
    """Trust ledger configuration (append-only JSONL with SHA256 checksums)."""

    model_config = {"frozen": True}

    checksum_interval: int = Field(default=100, ge=1)


# ---------------------------------------------------------------------------
# YAML settings source
# ---------------------------------------------------------------------------

class YamlSettingsSource(PydanticBaseSettingsSource):
    """Custom settings source that reads from pre-parsed YAML data.

    Sits between defaults (lowest) and env vars (higher) in the
    pydantic-settings source chain.
    """

    def __init__(
        self,
        settings_cls: Type[BaseSettings],
        yaml_data: dict[str, Any],
    ) -> None:
        super().__init__(settings_cls)
        self._yaml_data = yaml_data

    def get_field_value(
        self, field: Any, field_name: str
    ) -> Tuple[Any, str, bool]:
        val = self._yaml_data.get(field_name)
        return val, field_name, val is not None

    def __call__(self) -> dict[str, Any]:
        return {k: v for k, v in self._yaml_data.items()}


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------

# Module-level holder so ArbiterConfig can pick up YAML data during
# construction without needing init kwargs (which override env vars).
_yaml_source_data: dict[str, Any] = {}


class ArbiterConfig(BaseSettings):
    """Root configuration for the Arbiter system.

    Composes all section configs.  Extends Pydantic BaseSettings with
    frozen immutability and custom YAML settings source.

    Source priority: defaults -> YAML -> env vars (prefix=ARBITER_,
    nested delimiter=__).
    """

    model_config = {
        "frozen": True,
        "env_prefix": "ARBITER_",
        "env_nested_delimiter": "__",
    }

    config_version: int = Field(default=1, ge=1, le=1)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    soak: SoakConfig = Field(default_factory=SoakConfig)
    otlp: OtlpConfig = Field(default_factory=OtlpConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    classification_registry: ClassificationRegistryConfig = Field(
        default_factory=ClassificationRegistryConfig,
    )
    human_gate: HumanGateConfig = Field(default_factory=HumanGateConfig)
    ledger: LedgerConfig = Field(default_factory=LedgerConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        """Priority (highest first): env -> yaml -> defaults."""
        yaml_source = YamlSettingsSource(settings_cls, _yaml_source_data)
        return (
            env_settings,
            yaml_source,
            init_settings,
        )

    @model_validator(mode="after")
    def _check_cross_field_constraints(self) -> "ArbiterConfig":
        if self.trust.floor > self.trust.authority_override_floor:
            raise ValueError(
                f"trust.floor ({self.trust.floor}) must be "
                f"<= trust.authority_override_floor "
                f"({self.trust.authority_override_floor})"
            )
        return self


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------

class ValidationErrorDetail:
    """A single field-level validation error extracted from Pydantic."""

    __slots__ = ("field", "message", "value")

    def __init__(self, *, field: str, message: str, value: str) -> None:
        self.field = field
        self.message = message
        self.value = value

    def __repr__(self) -> str:
        return (
            f"ValidationErrorDetail(field={self.field!r}, "
            f"message={self.message!r}, value={self.value!r})"
        )


class ConfigurationError(Exception):
    """Wraps Pydantic ValidationError with file path context."""

    def __init__(
        self,
        *,
        config_path: str,
        message: str,
        validation_errors: ValidationErrorList | None = None,
    ) -> None:
        self.config_path = config_path
        self.message = message
        self.validation_errors: ValidationErrorList = validation_errors or []
        super().__init__(message)


class ConfigNotLoadedError(Exception):
    """Raised when get_config() is called before load_config()."""

    def __init__(
        self,
        message: str = (
            "Configuration not loaded. "
            "Call load_config() before get_config()."
        ),
    ) -> None:
        self.message = message
        super().__init__(message)
