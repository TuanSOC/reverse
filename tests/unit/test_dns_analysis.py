"""Pure DNS analysis helpers (§11)."""

from __future__ import annotations

from webrecon.modules.dns.analysis import extract_dmarc, extract_spf, spf_is_permissive


def test_extract_spf() -> None:
    txts = ['"some other txt"', "v=spf1 include:_spf.google.com -all"]
    assert extract_spf(txts) == "v=spf1 include:_spf.google.com -all"
    assert extract_spf(["nothing here"]) is None


def test_extract_dmarc() -> None:
    assert extract_dmarc(["v=DMARC1; p=reject"]) == "v=DMARC1; p=reject"
    assert extract_dmarc(["v=spf1 -all"]) is None


def test_spf_permissive() -> None:
    assert spf_is_permissive("v=spf1 +all")
    assert spf_is_permissive("v=spf1 all")
    assert not spf_is_permissive("v=spf1 include:x -all")
