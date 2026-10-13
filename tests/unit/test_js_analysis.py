"""Static JS analysis + source map parsing (§8/§9)."""

from __future__ import annotations

from webrecon.modules.javascript.analysis import analyze_js
from webrecon.modules.javascript.sourcemap import parse_source_map

SAMPLE_JS = """
var base = "/api/v1/users";
fetch("/api/admin/settings");
var internal = "/internal/debug";
var ws = "wss://example.com/live";
var ga = "UA-12345-6";
var s3 = "https://my-bucket.s3.amazonaws.com/x";
var key = "AKIAIOSFODNN7EXAMPLE";
//# sourceMappingURL=app.js.map
"""


def test_extracts_endpoints_and_ws() -> None:
    a = analyze_js("https://ex.com/app.js", SAMPLE_JS)
    assert "/api/v1/users" in a.endpoints
    assert "/api/admin/settings" in a.endpoints
    assert "/internal/debug" in a.endpoints
    assert "wss://example.com/live" in a.websockets


def test_extracts_analytics_cloud_and_sourcemap() -> None:
    a = analyze_js("https://ex.com/app.js", SAMPLE_JS)
    assert "UA-12345-6" in a.analytics_ids
    assert any("s3.amazonaws.com" in c for c in a.cloud_refs)
    assert a.sourcemap_url == "app.js.map"


def test_secret_detected_and_masked() -> None:
    # A real-shaped key (AWS's documentation example AKIAIOSFODNN7EXAMPLE is ignored).
    a = analyze_js("https://ex.com/app.js", SAMPLE_JS + '\nvar k2="AKIAZZZZ1111WWWW2222";')
    kinds = {s.kind for s in a.secrets}
    assert "aws_access_key_id" in kinds
    # The raw key must never appear in the masked evidence.
    assert all("AKIAZZZZ1111WWWW2222" not in s.masked for s in a.secrets)
    assert analyze_js("u", 'var k="AKIAIOSFODNN7EXAMPLE";').secrets == []


def test_hash_is_stable() -> None:
    a1 = analyze_js("u", "abc")
    a2 = analyze_js("u", "abc")
    assert a1.sha256 == a2.sha256


def test_parse_source_map() -> None:
    info = parse_source_map('{"version":3,"sources":["a.js","b.js"],"sourceRoot":"src"}')
    assert info is not None
    assert info.sources_count == 2
    assert info.source_root == "src"
    assert info.source_paths == ["a.js", "b.js"]


def test_parse_non_sourcemap_returns_none() -> None:
    assert parse_source_map("{}") is None
    assert parse_source_map("not json") is None
