"""Structured error hierarchy.

Errors are typed so the pipeline can decide whether a failure is fatal to a
single module (the normal case — the scan continues) or to the whole scan
(rare — e.g. storage is unavailable). Modules should raise ``ModuleError``
subclasses; the pipeline catches them and records a failed ``ModuleResult``
rather than propagating.
"""

from __future__ import annotations


class WebReconError(Exception):
    """Base class for all WebRecon errors."""


# --- Configuration / setup -------------------------------------------------


class ConfigError(WebReconError):
    """Invalid or inconsistent configuration."""


class StorageError(WebReconError):
    """Persistence layer failure. Usually fatal to the scan."""


# --- Scope / safety --------------------------------------------------------


class ScopeError(WebReconError):
    """Base for scope/safety violations."""


class OutOfScopeError(ScopeError):
    """A request/URL was rejected because it is outside the declared scope."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Out of scope: {url} ({reason})")


class SsrfBlockedError(ScopeError):
    """A request targeted a private/loopback/metadata address and was blocked."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"SSRF guard blocked {target}: {reason}")


# --- Module execution ------------------------------------------------------


class ModuleError(WebReconError):
    """A recoverable failure inside a single module. The scan continues."""


class ModuleTimeoutError(ModuleError):
    """A module exceeded its execution budget."""


class ModuleDependencyError(ModuleError):
    """A required upstream module did not produce usable output."""


class ScanCancelledError(WebReconError):
    """Raised when a scan is cancelled cooperatively."""
