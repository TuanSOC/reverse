"""Set-Cookie parsing + value masking (§14)."""

from __future__ import annotations

from webrecon.modules.cookies.module import parse_set_cookie


def test_parses_flags_and_attributes() -> None:
    c = parse_set_cookie(
        "sid=abcdef123456; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Strict"
    )
    assert c is not None
    assert c.name == "sid"
    assert c.domain == ".example.com"
    assert c.path == "/"
    assert c.secure and c.http_only
    assert c.same_site == "Strict"
    assert c.looks_sensitive


def test_value_is_masked() -> None:
    c = parse_set_cookie("token=supersecretvalue")
    assert c is not None
    assert "supersecretvalue" not in c.masked_value
    assert c.masked_value.startswith("supe")


def test_short_value_fully_masked() -> None:
    c = parse_set_cookie("a=xy")
    assert c is not None and c.masked_value == "****"


def test_invalid_returns_none() -> None:
    assert parse_set_cookie("") is None
    assert parse_set_cookie("noequalsign") is None
