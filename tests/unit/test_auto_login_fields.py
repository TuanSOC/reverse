"""Unit tests for auto-login field heuristics (pure, no browser)."""

from __future__ import annotations

from webrecon.engine.auto_login import (
    cookies_to_header,
    host_of,
    login_succeeded,
    rank_login_fields,
)


def test_rank_basic_user_then_password() -> None:
    f = rank_login_fields([
        {"type": "text", "name": "username"},
        {"type": "password", "name": "password"},
    ])
    assert f.username_index == 0 and f.password_index == 1


def test_rank_prefers_hinted_field_before_password() -> None:
    f = rank_login_fields([
        {"type": "text", "name": "search"},        # not a login hint
        {"type": "email", "name": "login_email"},  # hinted
        {"type": "password", "name": "pw"},
    ])
    assert f.username_index == 1 and f.password_index == 2


def test_rank_falls_back_to_nearest_textfield() -> None:
    f = rank_login_fields([
        {"type": "text", "name": "x"},
        {"type": "text", "name": "y"},
        {"type": "password", "name": "p"},
    ])
    assert f.username_index == 1  # nearest text before password


def test_rank_no_password() -> None:
    f = rank_login_fields([{"type": "text", "name": "q"}])
    assert f.password_index is None


def test_login_succeeded_password_gone() -> None:
    assert login_succeeded("https://x/login", "https://x/login", False) is True


def test_login_succeeded_url_left_login() -> None:
    assert login_succeeded("https://x/login", "https://x/dashboard", True) is True


def test_login_failed_still_on_login_with_password() -> None:
    assert login_succeeded("https://x/login", "https://x/login", True) is False
    # redirected but still a login/signin URL → not success
    assert login_succeeded("https://x/login", "https://x/signin?err=1", True) is False


def test_cookies_to_header_scopes_to_host() -> None:
    cookies = [
        {"name": "sess", "value": "abc", "domain": "target.com"},
        {"name": "sub", "value": "1", "domain": ".target.com"},
        {"name": "evil", "value": "x", "domain": "tracker.net"},  # dropped
    ]
    h = cookies_to_header(cookies, "app.target.com")
    assert "sess=abc" in h and "sub=1" in h and "evil" not in h


def test_host_of() -> None:
    assert host_of("https://App.Target.com/login") == "app.target.com"
    assert host_of("not a url") == ""
