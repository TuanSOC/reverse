"""Pure DNS analysis helpers (§11)."""

from __future__ import annotations

from webrecon.modules.dns.analysis import (
    extract_dmarc,
    extract_spf,
    spf_is_permissive,
    unquote_txt,
)


def test_extract_spf() -> None:
    txts = ['"some other txt"', "v=spf1 include:_spf.google.com -all"]
    assert extract_spf(txts) == "v=spf1 include:_spf.google.com -all"
    assert extract_spf(["nothing here"]) is None


def test_extract_spf_from_quoted_txt() -> None:
    # dnspython to_text() wraps TXT in quotes — must still be recognized.
    txts = ['"v=spf1 include:spf.efwd.registrar-servers.com ~all"']
    assert extract_spf(txts) == "v=spf1 include:spf.efwd.registrar-servers.com ~all"


def test_unquote_multichunk_txt() -> None:
    assert unquote_txt('"v=DKIM1; k=rsa; " "p=MIGfMA0"') == "v=DKIM1; k=rsa; p=MIGfMA0"
    assert unquote_txt("unquoted") == "unquoted"


def test_extract_dmarc() -> None:
    assert extract_dmarc(['"v=DMARC1; p=reject"']) == "v=DMARC1; p=reject"
    assert extract_dmarc(["v=spf1 -all"]) is None


def test_spf_permissive() -> None:
    assert spf_is_permissive("v=spf1 +all")
    assert spf_is_permissive("v=spf1 all")
    assert not spf_is_permissive("v=spf1 include:x -all")
