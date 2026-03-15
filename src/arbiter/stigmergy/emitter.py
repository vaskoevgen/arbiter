"""Stigmergy signal emitter.

Fire-and-forget POST to the stigmergy endpoint. Never blocks on failure.
Uses a 2-second timeout. If the endpoint is unavailable, the signal is
silently dropped (FA-A-023).
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

__all__ = [
    "emit_signal",
]

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 2
_DEFAULT_ENDPOINT: str | None = None


def configure_endpoint(endpoint: str | None) -> None:
    """Set the stigmergy endpoint URL.

    Args:
        endpoint: The base URL for the stigmergy service, or None to disable.
    """
    global _DEFAULT_ENDPOINT
    _DEFAULT_ENDPOINT = endpoint


def emit_signal(
    finding: dict[str, Any],
    *,
    endpoint: str | None = None,
) -> None:
    """Emit a finding as a stigmergy signal. Fire-and-forget.

    Constructs a normalized Signal object and POSTs it to the stigmergy
    endpoint. Uses a background thread to avoid blocking the caller.
    If the endpoint is unavailable or the POST fails, the failure is
    logged but never raised to the caller.

    Args:
        finding: The finding dict to emit. Must contain at minimum:
            - type: Finding type string (e.g., "consistency_violation")
            - node_id: The actor node
            - severity_score: Numeric weight
        endpoint: Override endpoint URL. Uses configured default if None.
    """
    target = endpoint or _DEFAULT_ENDPOINT
    if not target:
        logger.debug("Stigmergy endpoint not configured; signal dropped.")
        return

    signal = {
        "source": "arbiter",
        "type": finding.get("type", "unknown"),
        "actor": finding.get("node_id", ""),
        "content": finding,
        "weight": finding.get("severity_score", 0.0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Fire-and-forget in a daemon thread
    thread = threading.Thread(
        target=_post_signal,
        args=(target, signal),
        daemon=True,
    )
    thread.start()


def _post_signal(endpoint: str, signal: dict[str, Any]) -> None:
    """POST a signal to the stigmergy endpoint. Never raises.

    Args:
        endpoint: The full URL to POST to (e.g., http://host:port/signals).
        signal: The signal payload dict.
    """
    url = endpoint.rstrip("/") + "/signals"
    try:
        data = json.dumps(signal).encode("utf-8")
        req = Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req, timeout=_TIMEOUT_SECONDS)  # noqa: S310
    except (URLError, OSError, TimeoutError, ValueError) as exc:
        logger.debug("Stigmergy emission failed (fire-and-forget): %s", exc)
    except Exception as exc:  # noqa: BLE001
        # Catch-all: stigmergy must never block or crash the caller
        logger.debug("Stigmergy emission unexpected error: %s", exc)
