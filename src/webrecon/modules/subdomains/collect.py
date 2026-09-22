"""Pure subdomain aggregation from observed sources (no I/O, no brute force).

We only collect hostnames the scan already saw — certificate SANs, crawled
links/assets, JavaScript URLs, and discovered endpoints — then keep those that
are subdomains of the target's registrable domain. This is passive intelligence,
not DNS brute-forcing (which would be aggressive and is intentionally omitted).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ...core.urls import registrable_domain


def _host_of(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if "://" in value:
        try:
            host = urlsplit(value).hostname
        except ValueError:
            return None
        return host.lower() if host else None
    # A bare hostname (e.g. a cert SAN); strip a leading wildcard.
    host = value.lstrip("*.").lower()
    return host if "." in host and "/" not in host and " " not in host else None


def collect_subdomains(base_host: str, candidates: list[str]) -> set[str]:
    """Return hostnames that are subdomains of ``base_host``'s registrable domain
    (excluding the base host itself)."""
    base = base_host.lower().strip(".")
    reg = registrable_domain(base)
    out: set[str] = set()
    for c in candidates:
        host = _host_of(c)
        if host is None or host == base:
            continue
        if host == reg or host.endswith("." + reg):
            out.add(host)
    return out
