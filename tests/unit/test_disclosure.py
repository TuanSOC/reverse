"""Content-disclosure detection (emails / IPs / internal hosts / traces)."""

from __future__ import annotations

from webrecon.modules.disclosure import mask_email, scan_disclosures
from webrecon.modules.security.rules import content_disclosure


def test_scan_finds_all_kinds() -> None:
    text = (
        "reach us at admin@acme.co or sales@acme.co ; internal host db.internal ; "
        "ip 10.0.0.5 and 192.168.1.9 ; System.NullReferenceException at X.Y(Z.cs:1)"
    )
    d = scan_disclosures(text)
    assert "admin@acme.co" in d.emails and "sales@acme.co" in d.emails
    assert "db.internal" in d.internal_hosts
    assert "10.0.0.5" in d.private_ips and "192.168.1.9" in d.private_ips
    assert d.has_stack_trace


def test_ignores_example_emails() -> None:
    d = scan_disclosures("noreply@example.com foo@sentry.io real@acme.io")
    assert "real@acme.io" in d.emails
    assert not any("example.com" in e or "sentry.io" in e for e in d.emails)


def test_mask_email() -> None:
    assert mask_email("administrator@acme.co") == "ad***@acme.co"


def test_rule_emits_expected_findings() -> None:
    d = scan_disclosures("a@acme.io host x.internal ip 10.1.1.1 Fatal error: boom")
    checks = {f.check_id for f in content_disclosure(d)}
    assert {
        "content.disclosure.emails",
        "content.disclosure.internal_host",
        "content.disclosure.private_ip",
        "content.disclosure.stack_trace",
    } <= checks


def test_rule_masks_emails_in_evidence() -> None:
    d = scan_disclosures("secretuser@acme.io")
    f = next(f for f in content_disclosure(d) if f.check_id == "content.disclosure.emails")
    assert "secretuser@acme.io" not in str(f.evidence[0].data)
