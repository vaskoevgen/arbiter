"""Taint detection: canary corpus management and response scanning."""

from .corpus import CanaryCorpus
from .models import CanaryEntry, TaintResult
from .scanner import scan_for_taint

__all__ = [
    "CanaryCorpus",
    "CanaryEntry",
    "TaintResult",
    "scan_for_taint",
]
