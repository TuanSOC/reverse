"""Subdomain aggregation + known-vulnerable-library rule."""

from __future__ import annotations

from webrecon.modules.security.rules import known_vulnerable_libraries
from webrecon.modules.subdomains.collect import collect_subdomains


def test_collect_subdomains_from_mixed_sources() -> None:
    base = "example.com"
    candidates = [
        "https://api.example.com/v1",
        "https://cdn.example.com/app.js",
        "*.staging.example.com",  # cert SAN wildcard
        "mail.example.com",
        "https://example.com/",  # base itself → excluded
        "https://evil.com/x",  # different domain → excluded
        "not a url",
    ]
    subs = collect_subdomains(base, candidates)
    assert subs == {"api.example.com", "cdn.example.com", "staging.example.com", "mail.example.com"}
    assert "example.com" not in subs and "evil.com" not in subs


def test_known_vulnerable_jquery() -> None:
    dets = [{"name": "jQuery", "version": "1.12.4", "confidence": "high"}]
    out = known_vulnerable_libraries(dets)
    assert out and out[0].check_id == "technology.vulnerable.jquery"
    assert "CVE" in out[0].description or "3.5.0" in out[0].description
    assert out[0].references


def test_known_vulnerable_lodash_high() -> None:
    out = known_vulnerable_libraries(
        [{"name": "Lodash", "version": "4.17.11", "confidence": "high"}]
    )
    assert out and out[0].severity.value == "high"


def test_up_to_date_library_not_flagged() -> None:
    assert known_vulnerable_libraries(
        [{"name": "jQuery", "version": "3.7.1", "confidence": "confirmed"}]
    ) == []


def test_no_version_or_low_confidence_ignored() -> None:
    assert known_vulnerable_libraries(
        [{"name": "jQuery", "version": None, "confidence": "high"}]
    ) == []
    assert known_vulnerable_libraries(
        [{"name": "jQuery", "version": "1.0.0", "confidence": "low"}]
    ) == []
