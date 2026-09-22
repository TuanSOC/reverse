"""Scope engine — decides whether a URL may be requested (§4).

The crawler and every module ask the scope engine before touching a URL, so the
operator always knows the exact boundary being scanned. The engine is pure
(no I/O): host/path rules only. Network-address safety is a separate concern
handled by the SSRF guard.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.config import ScopeConfig, ScopeMode
from ..core.urls import is_subdomain_of, parse_url, same_registrable_domain


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeEngine:
    """Evaluates URLs against the configured scope for a given target host."""

    def __init__(self, base_host: str, base_origin: str, config: ScopeConfig) -> None:
        self.base_host = base_host.lower()
        self.base_origin = base_origin
        self.config = config

    def _host_in_scope(self, host: str) -> tuple[bool, str]:
        host = host.lower()
        # Explicit allow/deny lists take precedence.
        if host in {h.lower() for h in self.config.disallowed_hosts}:
            return False, "host explicitly disallowed"
        allow = {h.lower() for h in self.config.allowed_hosts}
        if host in allow or any(is_subdomain_of(host, h) for h in allow):
            return True, "host explicitly allowed"

        mode = self.config.mode
        if mode == ScopeMode.SAME_ORIGIN:
            # origin equality is checked in evaluate(); here host must match.
            return (host == self.base_host, "same-origin host match")
        if mode == ScopeMode.SAME_DOMAIN:
            return (
                same_registrable_domain(host, self.base_host),
                "same registrable domain",
            )
        if mode == ScopeMode.INCLUDE_SUBDOMAINS:
            return (
                is_subdomain_of(host, self.base_host),
                "host or subdomain of target",
            )
        return False, "unknown scope mode"

    def _path_in_scope(self, path: str) -> tuple[bool, str]:
        for excluded in self.config.exclude_paths:
            if path.startswith(excluded):
                return False, f"path excluded by {excluded!r}"
        if self.config.include_paths:
            if not any(path.startswith(inc) for inc in self.config.include_paths):
                return False, "path not in include list"
        return True, "path allowed"

    def evaluate(self, url: str) -> ScopeDecision:
        """Return an in/out-of-scope decision with a human-readable reason."""
        try:
            p = parse_url(url)
        except ValueError as exc:
            return ScopeDecision(False, f"unparseable URL: {exc}")

        if self.config.mode == ScopeMode.SAME_ORIGIN and p.origin != self.base_origin:
            # Still honor explicit allow-list before rejecting.
            allow = {h.lower() for h in self.config.allowed_hosts}
            if p.hostname not in allow and not any(
                is_subdomain_of(p.hostname, h) for h in allow
            ):
                return ScopeDecision(False, "different origin (same-origin mode)")

        host_ok, host_reason = self._host_in_scope(p.hostname)
        if not host_ok:
            return ScopeDecision(False, host_reason)
        path_ok, path_reason = self._path_in_scope(p.path)
        if not path_ok:
            return ScopeDecision(False, path_reason)
        return ScopeDecision(True, "in scope")

    def is_allowed(self, url: str) -> bool:
        return self.evaluate(url).allowed
