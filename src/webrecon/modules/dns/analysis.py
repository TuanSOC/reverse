"""Pure DNS-record analysis helpers (no network) so they are unit-testable."""

from __future__ import annotations

from dataclasses import dataclass, field


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
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def extract_dmarc(dmarc_txt: list[str]) -> str | None:
    for txt in dmarc_txt:
        if txt.lower().startswith("v=dmarc1"):
            return txt
    return None


def spf_is_permissive(spf: str) -> bool:
    """A trailing ``+all`` (or bare ``all``) makes SPF effectively useless."""
    tokens = spf.lower().split()
    return "+all" in tokens or "all" in tokens
