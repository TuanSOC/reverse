"""apitest signatures + safe engine (unit)."""

from __future__ import annotations

import pytest

from webrecon.modules.apitest import signatures as sig
from webrecon.modules.apitest.safe_engine import SafeGetEngine, UnsafeMethodError


def test_db_error_signatures() -> None:
    assert sig.has_db_error("SQLSTATE[42000]: syntax error")
    assert sig.has_db_error("ORA-01756: quoted string not properly terminated")
    assert sig.has_db_error("You have an error in your SQL syntax; MySQL")
    assert not sig.has_db_error('{"results": [1,2,3]}')


def test_action_verb_and_sensitive_path() -> None:
    assert sig.is_action_verb("https://x/api/delete?id=1")
    assert sig.is_action_verb("https://x/api/user/logout")
    assert not sig.is_action_verb("https://x/api/users")
    assert sig.is_sensitive_path("https://x/api/admin/list")
    assert sig.is_sensitive_path("https://x/api/users")
    assert not sig.is_sensitive_path("https://x/api/catalog")


def test_looks_substantive_json() -> None:
    assert sig.looks_substantive_json("[1,2,3,4,5]", "application/json")
    assert sig.looks_substantive_json('{"a":1,"b":2,"c":3,"d":4,"e":5}', "application/json")
    assert not sig.looks_substantive_json('{"version":"1"}', "application/json")
    assert not sig.looks_substantive_json("<html>not json</html>", "text/html")


def test_find_sensitive_data_masks() -> None:
    body = '[{"email":"a@corp.io","token":"tok_secretvalue12345","password":"hunter2"}]'
    hits = sig.find_sensitive_data(body)
    kinds = {h["kind"] for h in hits}
    assert "key:token" in kinds or "key:password" in kinds
    # No raw secret value present in any masked sample.
    assert all("hunter2" not in str(h.get("sample")) for h in hits)


def test_is_introspection_result() -> None:
    assert sig.is_introspection_result('{"data":{"__schema":{"types":[{"name":"Q"}]}}}')
    assert not sig.is_introspection_result('{"data":null}')
    assert not sig.is_introspection_result("not json")
    assert not sig.is_introspection_result('{"data":{"user":{"id":1}}}')


async def test_safe_engine_refuses_non_get() -> None:
    class _Fake:
        async def get(self, url):  # noqa: D401
            return "ok"

    eng = SafeGetEngine(_Fake())  # type: ignore[arg-type]
    assert await eng.get("http://x") == "ok"
    assert await eng.request("GET", "http://x") == "ok"
    for m in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        with pytest.raises(UnsafeMethodError):
            await eng.request(m, "http://x")
