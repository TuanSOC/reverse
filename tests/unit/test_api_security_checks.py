"""Unit tests for open-redirect + insecure-WebSocket heuristics."""

from __future__ import annotations

from webrecon.modules.api.security_checks import (
    find_open_redirect_params,
    insecure_websockets,
)


def test_open_redirect_params_found() -> None:
    urls = [
        "https://x.com/login?next=/dashboard",
        "https://x.com/go?url=https://evil.com",
        "https://x.com/page?id=5",  # not a redirect param
    ]
    hits = find_open_redirect_params(urls)
    params = {p for _, p in hits}
    assert params == {"next", "url"}


def test_open_redirect_case_insensitive_and_dedup() -> None:
    urls = ["https://x.com/a?ReturnUrl=/b", "https://x.com/a?ReturnUrl=/b"]
    hits = find_open_redirect_params(urls)
    assert len(hits) == 1
    assert hits[0][1] == "ReturnUrl"


def test_open_redirect_none_on_clean_urls() -> None:
    assert find_open_redirect_params(["https://x.com/", "https://x.com/p?q=1"]) == []


def test_insecure_websocket_flagged_on_https() -> None:
    ws = ["ws://x.com/socket", "wss://x.com/secure"]
    assert insecure_websockets(ws, page_is_https=True) == ["ws://x.com/socket"]


def test_insecure_websocket_ignored_on_http_page() -> None:
    # No mixed-content risk if the page itself is http://
    assert insecure_websockets(["ws://x.com/s"], page_is_https=False) == []


def test_secure_websocket_not_flagged() -> None:
    assert insecure_websockets(["wss://x.com/s"], page_is_https=True) == []
