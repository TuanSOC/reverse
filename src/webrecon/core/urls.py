"""URL normalization + parsing helpers shared by target, scope, and crawler.

Deterministic and pure (no I/O) so they are trivially unit-testable. These
functions decide canonical form and host relationships; the network guard lives
separately in ``engine/ssrf_guard.py``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    hostname: str
    port: int
    path: str
    query: str
    fragment: str

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.hostname}:{self.port}"

    @property
    def base_url(self) -> str:
        # Omit the port when it is the scheme default, for a clean base URL.
        if self.port == DEFAULT_PORTS.get(self.scheme):
            return f"{self.scheme}://{self.hostname}"
        return f"{self.scheme}://{self.hostname}:{self.port}"


def parse_url(url: str) -> ParsedUrl:
    """Parse a URL into normalized components (lowercased scheme/host, default port)."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if not scheme:
        raise ValueError(f"URL has no scheme: {url!r}")
    hostname = (parts.hostname or "").lower()
    if not hostname:
        raise ValueError(f"URL has no host: {url!r}")
    port = parts.port or DEFAULT_PORTS.get(scheme, 0)
    path = parts.path or "/"
    return ParsedUrl(scheme, hostname, port, path, parts.query, parts.fragment)


def normalize_url(url: str, *, keep_fragment: bool = False, keep_query: bool = True) -> str:
    """Canonicalize a URL: lowercase scheme/host, drop default port, drop
    fragment (unless kept), collapse empty path to ``/``. Used for crawl
    deduplication (§7)."""
    p = parse_url(url)
    netloc = p.hostname
    if p.port != DEFAULT_PORTS.get(p.scheme):
        netloc = f"{p.hostname}:{p.port}"
    query = p.query if keep_query else ""
    fragment = p.fragment if keep_fragment else ""
    return urlunsplit((p.scheme, netloc, p.path or "/", query, fragment))


# Common multi-label public suffixes. Not the full PSL, but enough to stop the
# most common "sibling under a public suffix" scope-broadening (e.g. treating
# attacker.co.uk as same-domain as victim.co.uk). Extend as needed.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "com.cn", "net.cn", "org.cn",
        "gov.cn", "com.br", "net.br", "org.br", "gov.br", "co.in", "net.in", "org.in",
        "gen.in", "firm.in", "com.sg", "com.hk", "com.tw", "co.za", "org.za", "co.kr",
        "com.mx", "com.tr", "com.ar", "co.id", "com.my", "com.ph", "com.vn", "net.vn",
        "org.vn", "gov.vn", "edu.vn",
    }
)


def registrable_domain(hostname: str) -> str:
    """Best-effort registrable domain.

    Uses a curated multi-label public-suffix set so ``co.uk``-style suffixes take
    three labels; otherwise the last two. Still a heuristic (not the full Public
    Suffix List) but closes the common sibling-under-public-suffix case.
    """
    host = hostname.strip(".").strip("[]").lower()
    try:  # IP literals have no parent domain: 203.0.113.10 must not match 8.8.113.10
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def is_subdomain_of(candidate: str, base: str) -> bool:
    """True if ``candidate`` is ``base`` or a subdomain of it."""
    candidate = candidate.strip(".").lower()
    base = base.strip(".").lower()
    return candidate == base or candidate.endswith("." + base)


def same_registrable_domain(a: str, b: str) -> bool:
    return registrable_domain(a) == registrable_domain(b)
