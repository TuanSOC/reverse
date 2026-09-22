"""Cookie prefix (__Host-/__Secure-) validation (§14)."""

from __future__ import annotations

from webrecon.modules.cookies.module import CookiesModule, parse_set_cookie


def _checks(set_cookie: str, *, is_https=True, base_host="example.com"):
    mod = CookiesModule()
    result = mod.new_result()
    cookie = parse_set_cookie(set_cookie)
    assert cookie is not None
    mod._analyze(result, cookie, "https://example.com", is_https, base_host)
    return {f.check_id for f in result.findings}


def test_secure_prefix_without_secure_flagged() -> None:
    assert "cookies.prefix.secure_violation" in _checks("__Secure-sid=x; Path=/")


def test_secure_prefix_with_secure_ok() -> None:
    assert "cookies.prefix.secure_violation" not in _checks("__Secure-sid=x; Secure; Path=/")


def test_host_prefix_violations() -> None:
    # Missing Secure, has Domain, non-root Path → violation.
    assert "cookies.prefix.host_violation" in _checks(
        "__Host-sid=x; Domain=example.com; Path=/app"
    )


def test_host_prefix_compliant_ok() -> None:
    assert "cookies.prefix.host_violation" not in _checks("__Host-sid=x; Secure; Path=/")
