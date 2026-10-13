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


# Selectors probed when hunting for a published DKIM key (the common defaults).
COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "google", "k1", "mail", "selector1", "selector2",
)


@dataclass
class DnsData:
    records: dict[str, list[str]] = field(default_factory=dict)  # type -> values
    spf: str | None = None
    dmarc: str | None = None
    caa: list[str] = field(default_factory=list)
    dangling_cnames: list[str] = field(default_factory=list)
    dkim_selectors: list[str] = field(default_factory=list)  # selectors that resolved


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


def dmarc_policy(dmarc: str) -> str | None:
    """Extract the ``p=`` policy value (none|quarantine|reject) from a DMARC record."""
    for tag in dmarc.split(";"):
        k, _, v = tag.strip().partition("=")
        if k.strip().lower() == "p":
            return v.strip().lower() or None
    return None


def dmarc_is_none(dmarc: str) -> bool:
    """True when DMARC is published but its policy is ``p=none`` (monitor only)."""
    return dmarc_policy(dmarc) == "none"


def is_dkim_record(txt: str) -> bool:
    """True when a TXT looks like a DKIM key record (v=DKIM1 or a p= public key)."""
    clean = unquote_txt(txt).lower()
    return "v=dkim1" in clean or "p=" in clean

async def resolve_state(resolver, name: str) -> str:
    """``"resolves"``, ``"nxdomain"`` (name does not exist) or ``"unknown"``.

    Timeouts / SERVFAIL / no nameservers are *unknown* — never evidence that a
    name is dangling. A name with records of other types (NoAnswer) exists.
    """
    import dns.exception
    import dns.resolver

    unknown = False
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            if await resolver.resolve(name, rtype):
                return "resolves"
        except dns.resolver.NXDOMAIN:
            return "nxdomain"
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.DNSException, Exception):  # noqa: BLE001 - never crash the scan
            unknown = True
    return "unknown" if unknown else "resolves"
