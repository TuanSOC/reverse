"""URL parsing/normalization helpers (§7)."""

from __future__ import annotations

import pytest

from webrecon.core.urls import (
    is_subdomain_of,
    normalize_url,
    parse_url,
    registrable_domain,
    same_registrable_domain,
)


def test_parse_defaults_port_and_path() -> None:
    p = parse_url("HTTPS://Example.com/Path?a=1#frag")
    assert p.scheme == "https"
    assert p.hostname == "example.com"
    assert p.port == 443
    assert p.path == "/Path"
    assert p.query == "a=1"
    assert p.fragment == "frag"
    assert p.base_url == "https://example.com"
    assert p.origin == "https://example.com:443"


def test_parse_rejects_missing_scheme_or_host() -> None:
    with pytest.raises(ValueError):
        parse_url("example.com/path")


def test_normalize_drops_fragment_and_default_port() -> None:
    assert normalize_url("https://example.com:443/a#x") == "https://example.com/a"
    assert normalize_url("https://example.com/a#x", keep_fragment=True) == "https://example.com/a#x"
    assert normalize_url("https://example.com") == "https://example.com/"


def test_normalize_keeps_nondefault_port() -> None:
    assert normalize_url("http://example.com:8080/a") == "http://example.com:8080/a"


def test_registrable_and_subdomain() -> None:
    assert registrable_domain("a.b.example.com") == "example.com"
    assert is_subdomain_of("www.example.com", "example.com")
    assert not is_subdomain_of("evil-example.com", "example.com")
    assert same_registrable_domain("api.example.com", "www.example.com")
    assert not same_registrable_domain("example.com", "example.org")
