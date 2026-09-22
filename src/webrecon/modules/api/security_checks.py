"""Pure API-surface security heuristics (no I/O) — open redirect + WebSocket.

All detection-only: we inspect URLs/parameters that were already discovered and
flag *candidates* for a developer to verify. Nothing is requested or exploited.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

# Query-parameter names commonly used to control a post-action redirect target.
OPEN_REDIRECT_PARAMS: frozenset[str] = frozenset({
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "return_to", "returnurl", "dest", "destination", "target_url", "goto",
    "callback", "continue", "forward",
})


def find_open_redirect_params(urls: list[str]) -> list[tuple[str, str]]:
    """Return (url, param) pairs whose query carries a redirect-like parameter."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        try:
            qs = parse_qs(urlsplit(url).query)
        except ValueError:
            continue
        for name in qs:
            if name.lower() in OPEN_REDIRECT_PARAMS:
                key = (url, name)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    return out


def insecure_websockets(ws_urls: list[str], page_is_https: bool) -> list[str]:
    """Return ws:// (cleartext) WebSocket URLs — flagged only on an HTTPS page."""
    if not page_is_https:
        return []
    seen: dict[str, None] = {}
    for url in ws_urls:
        if url.lower().startswith("ws://") and url not in seen:
            seen[url] = None
    return list(seen)
