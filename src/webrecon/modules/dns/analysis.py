"""Pure DNS-record analysis helpers (no network) so they are unit-testable."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# dnspython renders TXT records in presentation form: one or more
# double-quoted, space-separated chunks (e.g. `"v=spf1 ..." "..."`). We must
# unquote + concatenate the chunks before matching, or "v=spf1"/"v=DMARC1"
# checks miss every real record because of the leading quote.
_TXT_CHUNK = re.compile(r'"((?:[^"\\]|\\.)*)"')


def unquote_txt(txt: str) -> str:
    """Return the logical TXT string, joining quoted chunks and unescaping."""
    chunks = _TXT_CHUNK.findall(txt)
    if not chunks:
        return txt.strip()
    return "".join(c.replace('\\"', '"').replace("\\\\", "\\") for c in chunks)


@dataclass
class DnsData:
    records: dict[str, list[str]] = field(default_factory=dict)  # type -> values
    spf: str | None = None
    dmarc: str | None = None
    caa: list[str] = field(default_factory=list)
    dangling_cnames: list[str] = field(default_factory=list)


def extract_spf(txt_records: list[str]) -> str | None:
    """Return the SPF record from a set of TXT records, if present."""
    for txt in txt_records:
        clean = unquote_txt(txt)
        if clean.lower().startswith("v=spf1"):
            return clean
    return None


def extract_dmarc(dmarc_txt: list[str]) -> str | None:
    for txt in dmarc_txt:
        clean = unquote_txt(txt)
        if clean.lower().startswith("v=dmarc1"):
            return clean
    return None


def spf_is_permissive(spf: str) -> bool:
    """A trailing ``+all`` (or bare ``all``) makes SPF effectively useless."""
    tokens = spf.lower().split()
    return "+all" in tokens or "all" in tokens
