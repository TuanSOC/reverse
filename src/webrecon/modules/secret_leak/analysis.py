"""Pure secret/API-key detection over text (no I/O) — unit-testable.

Detects a curated set of high-signal hardcoded credentials in JavaScript/HTML
source. Every match is returned *already masked* (first 4 + last 4 chars) so the
raw secret never enters a Finding, report, or the dashboard. Detection only.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from ...core.enums import Severity

# (kind, compiled pattern, severity, human label)
_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity, str], ...] = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL,
     "AWS access key ID"),
    ("google_api_key", re.compile(r"AIzaSy[0-9A-Za-z\-_]{33}"), Severity.MEDIUM,
     "Google/Firebase API key"),
    ("github_pat", re.compile(r"ghp_[0-9a-zA-Z]{36}"), Severity.HIGH,
     "GitHub personal access token"),
    ("stripe_secret_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), Severity.CRITICAL,
     "Stripe live secret key"),
    ("stripe_publishable_key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
     Severity.INFORMATIONAL, "Stripe live publishable key"),
    ("slack_webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+"
    ), Severity.HIGH, "Slack incoming webhook URL"),
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
    ), Severity.CRITICAL, "Private key block"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
     Severity.LOW, "JSON Web Token"),
)


# Well-known example/placeholder values that appear throughout documentation and
# are NOT real secrets — flagging them is a false positive.
_KNOWN_EXAMPLES: frozenset[str] = frozenset({
    "AKIAIOSFODNN7EXAMPLE",   # AWS docs canonical example access key
    "AKIAI44QH8DHBEXAMPLE",   # AWS docs example
})


def mask_secret(value: str) -> str:
    """Keep only the first 4 and last 4 characters; hide the middle."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}…{value[-4:]}"


@dataclass
class SecretHit:
    kind: str
    label: str
    severity: Severity
    masked: str
    offset: int
    fingerprint: str  # sha256 prefix of the raw value — stable, non-reversible


def _fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def find_secrets(text: str, cap_per_kind: int = 20) -> list[SecretHit]:
    """Return masked secret hits found in ``text``.

    Deduped by (kind, fingerprint-of-raw) so two distinct secrets that happen to
    share the same masked ends are both reported; the raw value never leaves this
    function — only its mask and a one-way fingerprint do.
    """
    hits: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    for kind, pat, sev, label in _PATTERNS:
        found = 0
        for m in pat.finditer(text):
            raw = m.group(0)
            if raw in _KNOWN_EXAMPLES:
                continue  # documented example key, not a real secret
            fp = _fingerprint(raw)
            key = (kind, fp)
            if key in seen:
                continue
            seen.add(key)
            hits.append(SecretHit(kind, label, sev, mask_secret(raw), m.start(), fp))
            found += 1
            if found >= cap_per_kind:
                break
    return hits
