"""Unit tests for forms_auth classification + hygiene heuristics."""

from __future__ import annotations

from webrecon.modules.crawler.models import DiscoveredForm
from webrecon.modules.forms_auth.analysis import classify_form


def _form(action, method="post", inputs=None, page_url="https://ex.com/p"):
    return DiscoveredForm(
        page_url=page_url, action=action, method=method, inputs=inputs or []
    )


def test_login_form_classified() -> None:
    f = _form("https://ex.com/login", inputs=[
        {"name": "username", "type": "text"},
        {"name": "password", "type": "password"},
    ])
    rep = classify_form(f)
    assert rep.kind == "login"
    assert rep.has_password is True
    assert rep.state_changing is True


def test_register_beats_login_on_confirm_password() -> None:
    f = _form("https://ex.com/signup", inputs=[
        {"name": "email", "type": "email"},
        {"name": "password", "type": "password"},
        {"name": "confirm-password", "type": "password"},
    ])
    assert classify_form(f).kind == "register"


def test_search_form_get_not_state_changing() -> None:
    f = _form("https://ex.com/search", method="get", inputs=[
        {"name": "q", "type": "search"},
    ])
    rep = classify_form(f)
    assert rep.kind == "search"
    assert rep.state_changing is False
    assert rep.csrf_missing is False  # GET search never flagged for CSRF


def test_payment_form_classified() -> None:
    f = _form("https://ex.com/pay", inputs=[
        {"name": "cardnumber", "type": "text"},
        {"name": "cvv", "type": "text"},
    ])
    assert classify_form(f).kind == "payment"


def test_csrf_missing_on_post_without_token() -> None:
    f = _form("https://ex.com/update", inputs=[
        {"name": "email", "type": "email"},
    ])
    assert classify_form(f).csrf_missing is True


def test_csrf_present_suppresses_flag() -> None:
    f = _form("https://ex.com/update", inputs=[
        {"name": "email", "type": "email"},
        {"name": "csrf_token", "type": "hidden"},
    ])
    rep = classify_form(f)
    assert rep.has_csrf_token is True
    assert rep.csrf_missing is False


def test_insecure_password_transport_over_http() -> None:
    f = _form("http://ex.com/login", inputs=[
        {"name": "user", "type": "text"},
        {"name": "password", "type": "password"},
    ])
    rep = classify_form(f)
    assert rep.insecure_password_transport is True


def test_secure_password_transport_over_https_not_flagged() -> None:
    f = _form("https://ex.com/login", inputs=[
        {"name": "password", "type": "password"},
    ])
    assert classify_form(f).insecure_password_transport is False


def test_password_autocomplete_on_flagged_when_absent() -> None:
    f = _form("https://ex.com/login", inputs=[
        {"name": "password", "type": "password", "autocomplete": None},
    ])
    assert classify_form(f).password_autocomplete_on is True


def test_password_autocomplete_off_not_flagged() -> None:
    f = _form("https://ex.com/login", inputs=[
        {"name": "password", "type": "password", "autocomplete": "new-password"},
    ])
    assert classify_form(f).password_autocomplete_on is False
