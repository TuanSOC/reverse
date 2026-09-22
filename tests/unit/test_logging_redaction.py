"""Secret redaction in logs (§32)."""

from __future__ import annotations

from webrecon.core.logging import redact_processor


def test_sensitive_keys_are_redacted() -> None:
    out = redact_processor(None, "info", {"authorization": "Bearer abc", "cookie": "s=1"})
    assert out["authorization"] == "***REDACTED***"
    assert out["cookie"] == "***REDACTED***"


def test_jwt_like_value_masked_even_under_innocent_key() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9payloadsignature"
    out = redact_processor(None, "info", {"note": jwt})
    assert out["note"] != jwt
    assert "REDACTED" in out["note"]


def test_plain_values_pass_through() -> None:
    out = redact_processor(None, "info", {"url": "https://example.com", "count": 3})
    assert out["url"] == "https://example.com"
    assert out["count"] == 3
