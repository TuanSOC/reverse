"""Unit tests for email-security DNS helpers (SPF/DMARC/DKIM)."""

from __future__ import annotations

from webrecon.modules.dns.analysis import (
    COMMON_DKIM_SELECTORS,
    dmarc_is_none,
    dmarc_policy,
    extract_dmarc,
    extract_spf,
    is_dkim_record,
    spf_is_permissive,
)


def test_spf_permissive_plusall() -> None:
    spf = extract_spf(['"v=spf1 include:_spf.example.com +all"'])
    assert spf is not None
    assert spf_is_permissive(spf) is True


def test_spf_hardfail_not_permissive() -> None:
    spf = extract_spf(['"v=spf1 include:_spf.example.com -all"'])
    assert spf is not None and spf_is_permissive(spf) is False


def test_dmarc_policy_extraction() -> None:
    assert dmarc_policy("v=DMARC1; p=none; rua=mailto:x@y.com") == "none"
    assert dmarc_policy("v=DMARC1; p=reject") == "reject"
    assert dmarc_policy("v=DMARC1; sp=quarantine") is None  # no p= tag


def test_dmarc_is_none() -> None:
    d = extract_dmarc(['"v=DMARC1; p=none"'])
    assert d is not None and dmarc_is_none(d) is True
    d2 = extract_dmarc(['"v=DMARC1; p=reject"'])
    assert d2 is not None and dmarc_is_none(d2) is False


def test_is_dkim_record() -> None:
    assert is_dkim_record('"v=DKIM1; k=rsa; p=MIGfMA0..."') is True
    assert is_dkim_record('"p=MIGfMA0GCSqGSIb3..."') is True
    assert is_dkim_record('"v=spf1 -all"') is False


def test_common_dkim_selectors_present() -> None:
    for sel in ("default", "google", "k1", "mail"):
        assert sel in COMMON_DKIM_SELECTORS
