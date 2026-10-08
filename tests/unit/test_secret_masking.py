"""Unit: credentials never leave the process via the persisted/reported config."""

from __future__ import annotations

from webrecon.core.config import ScanConfig
from webrecon.core.context import ScanContext
from webrecon.reporting.json_report import build_report


def _cfg() -> ScanConfig:
    c = ScanConfig()
    c.auth.login_url = "https://ex.com/login"
    c.auth.username = "alice"
    c.auth.password = "S3cret!"
    c.http.cookie = "session=LIVECOOKIE"
    c.http.auth_headers = {"Authorization": "Bearer LIVETOKEN"}
    return c


def test_redacted_dump_masks_credentials_only() -> None:
    c = _cfg()
    d = c.redacted_dump()
    assert d["auth"]["password"] == "***"
    assert d["http"]["cookie"] == "***"
    assert d["http"]["auth_headers"] == {"Authorization": "***"}
    # non-secret settings survive (db_report reads scope back)
    assert d["auth"]["username"] == "alice"
    assert d["auth"]["login_url"] == "https://ex.com/login"
    assert "scope" in d and "rate" in d
    # the live config is untouched
    assert c.auth.password == "S3cret!" and c.http.cookie == "session=LIVECOOKIE"


def test_redacted_dump_scrubs_urls() -> None:
    c = ScanConfig()
    c.auth.login_url = "https://u:pw@ex.com/login?token=abc&next=/x"
    c.database_url = "postgresql+asyncpg://dbuser:dbpw@db.local/webrecon"
    d = c.redacted_dump()
    assert d["auth"]["login_url"] == "https://ex.com/login?token=*&next=*"
    assert "dbpw" not in d["database_url"] and "db.local" in d["database_url"]


def test_bare_env_vars_do_not_leak_into_config(monkeypatch) -> None:
    # Windows sets USERNAME; nested settings must only read WEBRECON_<SECTION>_*
    monkeypatch.setenv("USERNAME", "os-user")
    monkeypatch.setenv("PASSWORD", "os-pass")
    monkeypatch.setenv("COOKIE", "x=1")
    c = ScanConfig()
    assert c.auth.username is None and c.auth.password is None and c.http.cookie is None
    monkeypatch.setenv("WEBRECON_AUTH_USERNAME", "alice")
    assert ScanConfig().auth.username == "alice"


def test_redacted_dump_keeps_unset_values() -> None:
    d = ScanConfig().redacted_dump()
    assert d["auth"]["password"] is None
    assert d["http"]["cookie"] is None
    assert d["http"]["auth_headers"] == {}


def test_json_report_has_no_credentials() -> None:
    rep = build_report(ScanContext(config=_cfg()))
    blob = str(rep)
    for secret in ("S3cret!", "LIVECOOKIE", "LIVETOKEN"):
        assert secret not in blob
