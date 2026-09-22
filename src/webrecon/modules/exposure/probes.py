"""Curated, content-verified probe definitions (pure data).

Each probe is a path plus a signature the *actual exposed file* would contain,
so a generic SPA/404 page that returns HTTP 200 for everything does not produce
a false positive. GET-only, non-destructive. Used only when ``config.probe`` is
explicitly enabled (§42 — kept at detection level, never exploitation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...core.enums import Severity


@dataclass(frozen=True)
class Probe:
    path: str
    name: str
    signature: re.Pattern[str]
    severity: Severity


SENSITIVE_PROBES: tuple[Probe, ...] = (
    Probe(".git/HEAD", "Exposed .git repository",
          re.compile(r"^ref:\s+refs/", re.M), Severity.HIGH),
    Probe(".git/config", "Exposed .git config",
          re.compile(r"\[core\]", re.I), Severity.HIGH),
    Probe(".env", "Exposed .env file",
          re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}="), Severity.HIGH),
    Probe(".svn/entries", "Exposed SVN metadata",
          re.compile(r"^\d+\s*$|svn://", re.M), Severity.MEDIUM),
    Probe("server-status", "Exposed Apache server-status",
          re.compile(r"Apache Server Status", re.I), Severity.MEDIUM),
    Probe("phpinfo.php", "Exposed phpinfo() page",
          re.compile(r"phpinfo\(\)|<title>PHP \d", re.I), Severity.MEDIUM),
    Probe("config.json", "Exposed config.json with secrets",
          re.compile(r'"(password|secret|api[_-]?key|token)"\s*:', re.I), Severity.HIGH),
    Probe("wp-config.php.bak", "Exposed wp-config backup",
          re.compile(r"DB_PASSWORD|DB_USER"), Severity.HIGH),
    Probe(".well-known/security.txt", "security.txt present",
          re.compile(r"(?i)contact:\s*"), Severity.INFORMATIONAL),
)

# HTTP methods that are risky to have enabled on a production server.
RISKY_METHODS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"}


def looks_like_html(body: str) -> bool:
    head = body[:2000].lower()
    return "<html" in head or "<!doctype html" in head
