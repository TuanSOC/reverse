"""Structured logging with mandatory secret redaction (§32).

We never want credentials, tokens, or cookie values in logs. A structlog
processor scrubs known-sensitive keys and obviously-secret-looking values before
anything is rendered.
"""

from __future__ import annotations

import logging
import re
from collections.abc import MutableMapping
from typing import Any

import structlog

# Keys whose values must never be logged verbatim.
_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session",
    "authentication",
}

# Value patterns that look like secrets even under an innocent key.
_SECRETISH = re.compile(
    r"(bearer\s+[a-z0-9._\-]+)|(eyJ[a-zA-Z0-9._\-]{10,})",  # bearer / JWT
    re.IGNORECASE,
)

_REDACTED = "***REDACTED***"


def _mask(value: str) -> str:
    if len(value) <= 8:
        return _REDACTED
    return f"{value[:4]}…{_REDACTED}"


def redact_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor: redact sensitive keys and secret-looking values."""
    for key in list(event_dict):
        if key.lower() in _SENSITIVE_KEYS:
            event_dict[key] = _REDACTED
            continue
        val = event_dict[key]
        if isinstance(val, str) and _SECRETISH.search(val):
            event_dict[key] = _mask(val)
    return event_dict


def configure_logging(level: str = "INFO", *, json_output: bool = False) -> None:
    """Configure structlog + stdlib logging once, at process start."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", level=numeric)

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_processor,
            structlog.processors.StackInfoRenderer(),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(module: str, **bind: Any) -> structlog.stdlib.BoundLogger:
    """Return a bound logger tagged with the module name (and any extra keys)."""
    return structlog.get_logger().bind(module=module, **bind)
