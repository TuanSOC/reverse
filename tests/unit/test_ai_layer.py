"""Unit: AI layer (G8) — context hygiene, citation enforcement, analyzers, key safety."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from webrecon.intel.ai import (
    AiError,
    GroqAnalyzer,
    StubAnalyzer,
    assemble_context,
    get_analyzer,
    load_env_file,
    parse_analysis,
)
from webrecon.intel.ai.context import MAX_ENDPOINTS, mask_query

_FAKE_KEY = "gsk_TESTKEY1234567890abcdef"


def _ctx(n_endpoints: int = 3):
    overview = {
        "target": {"base_url": "https://ex.com", "hostname": "ex.com"},
        "risk_level": "high", "ip_intel": None,
        "modules": [{"module": "crawler", "status": "success"},
                    {"module": "tls", "status": "failed"}],
        "technologies": [{"name": "nginx", "version": "1.25", "category": "web-server",
                          "confidence": "high"}],
    }
    endpoints = [
        {"url": f"https://ex.com/api/items?id={i}&token=s3cr3t", "method": "GET",
         "kind": "rest", "observation": "referenced" if i else "observed",
         "meta": {"discovery_status": "STATIC_ONLY" if i else "DYNAMIC_ONLY",
                  "params": [{"name": "id", "classification": "object_identifier"},
                             {"name": "token", "classification": "token"}]}}
        for i in range(n_endpoints)
    ]
    findings = [
        {"id": "f-low", "check_id": "headers.hsts", "name": "Missing HSTS", "severity": "low",
         "confidence": "high", "observation": "observed", "category": "transport",
         "module": "headers", "evidence": [{"url": "https://ex.com/"}]},
        {"id": "f-high", "check_id": "api.idor", "name": "IDOR candidate", "severity": "high",
         "confidence": "medium", "observation": "potential", "category": "access",
         "module": "api", "evidence": [{"url": "https://ex.com/api/items?id=1"}]},
    ]
    forms = [{"page_url": "https://ex.com/login", "action": "/login", "method": "post",
              "inputs": [{"name": "user", "type": "text", "value": "admin"},
                         {"name": "csrf", "type": "hidden", "value": "TOKENVALUE"}]}]
    auth = {"kind": "password", "confidence": 0.7, "steps": ["User submits the login form"],
            "has_login_form": True, "has_session_cookie": False,
            "endpoints": [{"role": "login", "url": "https://ex.com/login", "method": "POST",
                           "observation": "observed"}]}
    js = [{"url": "https://ex.com/app.js", "analyzed": True, "size": 10, "frameworks": ["react"],
           "endpoints": ["/api/items"], "ast_calls": [], "sourcemap_exposed": True,
           "reconstructed_files": 2, "secrets": 1}]
    return assemble_context("sid", overview=overview, findings=findings, endpoints=endpoints,
                            js_files=js, forms=forms, auth_flow=auth, page_count=4)


# -- context ---------------------------------------------------------------------


def test_mask_query_keeps_names_hides_values() -> None:
    assert mask_query("https://a/x?token=abc&q=1") == "https://a/x?token=*&q=*"
    assert mask_query("https://a/x") == "https://a/x"


def test_context_ids_ordering_and_hygiene() -> None:
    ctx = _ctx()
    ids = [i.id for i in ctx.items]
    assert {"X1", "S1", "T1", "E1", "F1", "J1", "M1", "A1"} <= set(ids)
    # findings ordered by severity: the high one is F1
    assert ctx.get("F1").data["check_id"] == "api.idor"
    # observed endpoints first
    assert ctx.get("E1").data["observation"] == "observed"
    blob = json.dumps(ctx.to_prompt_payload()) + json.dumps([i.to_dict() for i in ctx.items])
    assert "s3cr3t" not in blob            # query values masked everywhere
    assert "TOKENVALUE" not in blob and "admin" not in blob  # form values never forwarded
    assert "tls=failed" in ctx.get("S1").summary


def test_context_caps_endpoints() -> None:
    ctx = _ctx(n_endpoints=MAX_ENDPOINTS + 7)
    assert len(ctx.of_kind("endpoint")) == MAX_ENDPOINTS
    assert ctx.get("S1").data["truncated"]["endpoints"] is True


# -- citation enforcement ----------------------------------------------------------


def test_parse_drops_invented_evidence() -> None:
    ctx = _ctx()
    data = {
        "app_summary": {"text": "A shop", "evidence": ["X1", "Z99"]},
        "components": [{"text": "nginx", "evidence": ["T1"]},
                       {"text": "made up", "evidence": ["T42"]},
                       {"text": "no cite", "evidence": []},
                       "not a dict"],
        "gaps": {"text": "single object tolerated", "evidence": "S1"},
    }
    a = parse_analysis(data, ctx, provider="t", model="m")
    assert a.app_summary.evidence == ["X1"]          # invalid ID stripped, claim kept
    assert [c.text for c in a.sections["components"]] == ["nginx"]
    assert a.sections["gaps"][0].evidence == ["S1"]
    assert a.rejected_claims == 3
    assert a.cited_ids() <= ctx.ids
    snap = a.to_dict(ctx)["evidence"]
    assert set(snap) == a.cited_ids() and snap["T1"]["kind"] == "technology"


def test_parse_rejects_non_object() -> None:
    with pytest.raises(AiError):
        parse_analysis(["x"], _ctx(), provider="t", model="m")


def test_stub_is_grounded_and_deterministic() -> None:
    ctx = _ctx()
    a1 = asyncio.run(StubAnalyzer().analyze(ctx))
    a2 = asyncio.run(StubAnalyzer().analyze(ctx))
    assert a1.cited_ids() <= ctx.ids and a1.cited_ids()
    assert a1.to_dict()["sections"] == a2.to_dict()["sections"]
    assert any("IDOR" in c.text for c in a1.sections["attack_surface"])
    assert a1.sections["static_vs_observed"] and a1.sections["gaps"]


# -- Groq ------------------------------------------------------------------------


def test_groq_request_shape_and_parsing() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        content = json.dumps({"app_summary": {"text": "Site", "evidence": ["X1"]},
                              "components": [{"text": "nginx", "evidence": ["T1", "BOGUS"]}],
                              "attack_surface": [{"text": "invented", "evidence": ["E999"]}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    g = GroqAnalyzer(_FAKE_KEY, "openai/gpt-oss-120b", transport=httpx.MockTransport(handler))
    a = asyncio.run(g.analyze(_ctx()))
    assert seen["auth"] == f"Bearer {_FAKE_KEY}"
    body = seen["body"]
    assert body["model"] == "openai/gpt-oss-120b"
    assert body["response_format"] == {"type": "json_object"}
    assert body["reasoning_effort"] == "low"
    sent = body["messages"][1]["content"]
    assert "s3cr3t" not in sent and "TOKENVALUE" not in sent
    assert a.provider == "groq" and a.sections["components"][0].evidence == ["T1"]
    assert a.sections["attack_surface"] == [] and a.rejected_claims == 1
    assert _FAKE_KEY not in json.dumps(a.to_dict(_ctx()))
    assert _FAKE_KEY not in repr(g)


def test_groq_error_never_leaks_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": f"Invalid API Key {_FAKE_KEY}"}})

    g = GroqAnalyzer(_FAKE_KEY, transport=httpx.MockTransport(handler))
    with pytest.raises(AiError) as exc:
        asyncio.run(g.analyze(_ctx()))
    assert "401" in str(exc.value) and _FAKE_KEY not in str(exc.value)


def test_groq_bad_json_is_ai_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})

    g = GroqAnalyzer(_FAKE_KEY, transport=httpx.MockTransport(handler))
    with pytest.raises(AiError):
        asyncio.run(g.analyze(_ctx()))


# -- selection + env ---------------------------------------------------------------


def test_get_analyzer_selection(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)  # no .env here
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("WEBRECON_AI_PROVIDER", raising=False)
    assert isinstance(get_analyzer(), StubAnalyzer)
    with pytest.raises(AiError):
        get_analyzer("groq")  # no key
    with pytest.raises(AiError):
        get_analyzer("gpt-unknown")
    monkeypatch.setenv("GROQ_API_KEY", _FAKE_KEY)
    assert isinstance(get_analyzer(), GroqAnalyzer)
    assert isinstance(get_analyzer("stub"), StubAnalyzer)


def test_load_env_file_never_overrides(monkeypatch, tmp_path) -> None:
    env = tmp_path / ".env"
    env.write_text('# c\nGROQ_API_KEY="from_file"\nexport OTHER_X=1\n', encoding="utf-8")
    monkeypatch.setenv("GROQ_API_KEY", "from_env")
    monkeypatch.delenv("OTHER_X", raising=False)
    load_env_file(env)
    import os

    assert os.environ["GROQ_API_KEY"] == "from_env"
    assert os.environ["OTHER_X"] == "1"
    monkeypatch.delenv("OTHER_X")
