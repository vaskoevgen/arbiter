"""Annotated type aliases for Arbiter. Constrained primitives with Pydantic validation."""

from typing import Annotated

from pydantic import AfterValidator, Field

__all__ = [
    "NodeId",
    "TrustScore",
    "Sha256Hex",
    "UtcDatetime",
    "AuthorityDomain",
    "SequenceNumber",
]

import re


def _validate_node_id(v: str) -> str:
    if not v:
        raise ValueError("NodeId must be non-empty")
    if len(v) > 255:
        raise ValueError("NodeId must be at most 255 characters")
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", v):
        raise ValueError("NodeId must match pattern [a-zA-Z0-9._-]+")
    return v


def _validate_trust_score(v: float) -> float:
    if v < 0.0 or v > 1.0:
        raise ValueError("TrustScore must be in [0.0, 1.0]")
    return v


def _validate_sha256_hex(v: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", v):
        raise ValueError("Sha256Hex must be exactly 64 lowercase hex characters")
    return v


def _validate_utc_datetime(v: str) -> str:
    if not v.endswith("Z") and not v.endswith("+00:00"):
        raise ValueError("UtcDatetime must end with 'Z' or '+00:00'")
    return v


def _validate_authority_domain(v: str) -> str:
    if not v:
        raise ValueError("AuthorityDomain must be non-empty")
    if len(v) > 255:
        raise ValueError("AuthorityDomain must be at most 255 characters")
    if not re.fullmatch(r"[a-zA-Z0-9._/-]+", v):
        raise ValueError("AuthorityDomain must match pattern [a-zA-Z0-9._/-]+")
    return v


def _validate_sequence_number(v: int) -> int:
    if v < 0:
        raise ValueError("SequenceNumber must be non-negative")
    return v


NodeId = Annotated[str, AfterValidator(_validate_node_id)]

TrustScore = Annotated[float, AfterValidator(_validate_trust_score)]

Sha256Hex = Annotated[str, AfterValidator(_validate_sha256_hex)]

UtcDatetime = Annotated[str, AfterValidator(_validate_utc_datetime)]

AuthorityDomain = Annotated[str, AfterValidator(_validate_authority_domain)]

SequenceNumber = Annotated[int, Field(ge=0), AfterValidator(_validate_sequence_number)]
