"""Unit tests for the authentication-flow model (pure)."""

from __future__ import annotations

from webrecon.intel.auth_flow import build_auth_flow, classify_auth_endpoints


def _ep(url, method=None, obs="referenced"):
    return {"url": url, "method": method, "observation": obs}


def test_classify_roles() -> None:
    eps = classify_auth_endpoints([
        _ep("https://x/api/auth/login"), _ep("https://x/api/me"),
        _ep("https://x/logout"), _ep("https://x/static/app.js"),
    ])
    roles = {e.role for e in eps}
    assert roles == {"login", "identity", "logout"}  # app.js is not auth


def test_password_flow() -> None:
    f = build_auth_flow(
        [_ep("https://x/api/auth/login", "POST"), _ep("https://x/api/me")],
        has_login_form=True, has_session_cookie=True)
    assert f.kind == "password"
    assert f.confidence >= 0.8
    assert any("login form" in s.lower() for s in f.steps)
    assert any("session cookie" in s.lower() for s in f.steps)


def test_oauth_flow() -> None:
    f = build_auth_flow([
        _ep("https://x/oauth/authorize"), _ep("https://x/auth/callback"),
        _ep("https://x/oauth/token"), _ep("https://x/api/me"),
    ], has_login_form=False, has_session_cookie=False)
    assert f.kind == "oauth"
    assert any("authorization" in s.lower() for s in f.steps)
    assert any("callback" in s.lower() for s in f.steps)


def test_unknown_flow() -> None:
    f = build_auth_flow([_ep("https://x/api/products")],
                        has_login_form=False, has_session_cookie=False)
    assert f.kind == "unknown"


def test_endpoints_ordered_by_step() -> None:
    f = build_auth_flow([
        _ep("https://x/logout"), _ep("https://x/login"), _ep("https://x/me"),
    ], has_login_form=True, has_session_cookie=False)
    roles = [e.role for e in f.endpoints]
    assert roles.index("login") < roles.index("logout")
