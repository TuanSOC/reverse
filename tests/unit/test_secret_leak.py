"""Unit tests for secret_leak detection + mandatory masking."""

from __future__ import annotations

from webrecon.core.enums import Severity
from webrecon.modules.secret_leak.analysis import find_secrets, mask_secret


def _kinds(text):
    return {h.kind for h in find_secrets(text)}


def test_mask_secret_keeps_only_ends() -> None:
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA…MPLE"
    assert mask_secret("short") == "****"  # too short → fully hidden


def test_aws_key_detected_and_masked() -> None:
    raw = "AKIAIOSFODNN7EXAMPLE"
    hits = find_secrets(f"const k = '{raw}';")
    assert len(hits) == 1
    h = hits[0]
    assert h.kind == "aws_access_key"
    assert h.severity == Severity.CRITICAL
    # the raw secret must never survive in the masked form
    assert raw not in h.masked
    assert h.masked.startswith("AKIA") and h.masked.endswith("MPLE")


def test_google_api_key_detected() -> None:
    raw = "AIzaSy" + "A" * 33
    hits = find_secrets(f"key={raw}")
    assert hits and hits[0].kind == "google_api_key"
    assert hits[0].severity == Severity.MEDIUM
    assert raw not in hits[0].masked


def test_github_pat_detected_high() -> None:
    raw = "ghp_" + "a1B2" * 9  # 36 chars after prefix
    hits = find_secrets(raw)
    assert hits and hits[0].kind == "github_pat"
    assert hits[0].severity == Severity.HIGH


def test_stripe_secret_critical_publishable_info() -> None:
    sk = "sk_live_" + "a" * 24
    pk = "pk_live_" + "b" * 24
    kinds = {h.kind: h.severity for h in find_secrets(f"{sk}\n{pk}")}
    assert kinds["stripe_secret_key"] == Severity.CRITICAL
    assert kinds["stripe_publishable_key"] == Severity.INFORMATIONAL


def test_slack_webhook_and_private_key() -> None:
    text = (
        "https://hooks.slack.com/services/T00000000/B11111111/abcdefXYZ\n"
        "-----BEGIN RSA PRIVATE KEY-----"
    )
    kinds = _kinds(text)
    assert "slack_webhook" in kinds
    assert "private_key" in kinds


def test_jwt_detected_low() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36"
    hits = find_secrets(jwt)
    assert hits and hits[0].kind == "jwt"
    assert hits[0].severity == Severity.LOW


def test_no_false_positive_on_clean_text() -> None:
    assert find_secrets("const greeting = 'hello world'; let x = 42;") == []


def test_dedup_repeated_secret() -> None:
    raw = "AKIAIOSFODNN7EXAMPLE"
    hits = find_secrets(f"{raw} ... {raw} ... {raw}")
    assert len(hits) == 1  # same masked value collapses
