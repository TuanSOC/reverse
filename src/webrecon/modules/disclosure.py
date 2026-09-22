"""Shared content-disclosure detection (pure, no I/O).

Scans already-fetched page/JS text for information that shouldn't be public:
email addresses, internal/private IPs, internal hostnames, and error/stack-trace
signatures. Passive — it only reads content the crawler already retrieved, and
values are reported conservatively (emails informational; internal hosts/IPs and
stack traces are the real leaks).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b"
)
INTERNAL_HOST = re.compile(r"\b[a-z0-9][a-z0-9.\-]*\.(?:local|internal|corp|lan|intranet)\b", re.I)
STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)"
    r"|Warning: .+ in .+\.php on line \d+"
    r"|Fatal error: "
    r"|System\.[A-Za-z.]+Exception"
    r"|at [\w.$]+\([\w.]+:\d+\)"
    r"|org\.springframework\."
    r"|ORA-\d{5}"
    r"|SQLSTATE\[)",
)
# Common example/placeholder emails to ignore.
_IGNORE_EMAILS = re.compile(r"@(example\.(com|org|net)|email\.com|domain\.com|sentry\.io)$", re.I)


@dataclass
class Disclosures:
    emails: set[str] = field(default_factory=set)
    private_ips: set[str] = field(default_factory=set)
    internal_hosts: set[str] = field(default_factory=set)
    has_stack_trace: bool = False

    def merge(self, other: Disclosures) -> None:
        self.emails |= other.emails
        self.private_ips |= other.private_ips
        self.internal_hosts |= other.internal_hosts
        self.has_stack_trace = self.has_stack_trace or other.has_stack_trace


def scan_disclosures(text: str) -> Disclosures:
    d = Disclosures()
    for m in EMAIL.finditer(text):
        e = m.group(0)
        if not _IGNORE_EMAILS.search(e):
            d.emails.add(e)
    d.private_ips = set(PRIVATE_IP.findall(text))
    d.internal_hosts = {h.lower() for h in INTERNAL_HOST.findall(text)}
    d.has_stack_trace = bool(STACK_TRACE.search(text))
    return d


def mask_email(email: str) -> str:
    name, _, dom = email.partition("@")
    shown = name[:2] if len(name) > 2 else name[:1]
    return f"{shown}***@{dom}"


def mask_value(value: str) -> str:
    """Mask an arbitrary sensitive value (token/secret/PII), keeping a short hint."""
    if "@" in value and "." in value.split("@")[-1]:
        return mask_email(value)
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}…***({len(value)} chars)"
