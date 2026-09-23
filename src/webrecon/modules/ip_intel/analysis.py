"""Pure IP-intelligence parsing/classification (no I/O) — unit-testable.

Parses the responses of two safe, read-only data sources:
- Team Cymru's DNS-based IP-to-ASN service (TXT records), and
- a public IP geolocation JSON API (e.g. ip-api.com).

Plus provider classification (which cloud/CDN an IP belongs to) and a
heuristic for detecting a CDN-fronted domain whose DNS still resolves to the
origin host (a "direct IP" exposure). No network access happens here.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..dns.analysis import unquote_txt

# AS-name / org substrings → normalized provider label.
_PROVIDER_MARKERS: tuple[tuple[str, str], ...] = (
    ("cloudflare", "Cloudflare"),
    ("amazon", "AWS"),
    ("aws", "AWS"),
    ("cloudfront", "CloudFront"),
    ("google", "GCP"),
    ("microsoft", "Azure"),
    ("azure", "Azure"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("digitalocean", "DigitalOcean"),
)

# Response-header signals that the *edge* is a given CDN/proxy.
_CDN_HEADER_SIGNALS: tuple[tuple[str, str, str], ...] = (
    # (header, substring-to-match (""=any value), provider)
    ("cf-ray", "", "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    ("x-amz-cf-id", "", "CloudFront"),
    ("x-served-by", "cache", "Fastly"),
    ("x-fastly-request-id", "", "Fastly"),
    ("x-akamai-transformed", "", "Akamai"),
    ("x-cache", "akamai", "Akamai"),
)


@dataclass
class IpIntel:
    ip: str
    ptr: str | None = None
    asn: str | None = None
    as_name: str | None = None
    prefix: str | None = None
    registry: str | None = None
    isp: str | None = None
    org: str | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    provider: str | None = None  # classified cloud/CDN owner of the IP, if any

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class IpIntelResult:
    ips: list[IpIntel] = field(default_factory=list)
    edge_cdn: str | None = None            # CDN detected on the HTTP edge
    origin_exposed: bool = False           # a resolved IP looks like the origin


def is_private_ip(ip: str) -> bool:
    """True for loopback/private/link-local/reserved addresses (skip these)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_unspecified or addr.is_multicast
    )


def reverse_pointer(ip: str) -> str | None:
    """The in-addr.arpa / ip6.arpa name used for a PTR (reverse DNS) query."""
    try:
        return ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return None


def cymru_origin_name(ip: str) -> str | None:
    """Team Cymru IP→ASN DNS name for an address (IPv4 and IPv6)."""
    rev = reverse_pointer(ip)
    if rev is None:
        return None
    if rev.endswith(".in-addr.arpa"):
        return rev[: -len(".in-addr.arpa")] + ".origin.asn.cymru.com"
    if rev.endswith(".ip6.arpa"):
        return rev[: -len(".ip6.arpa")] + ".origin6.asn.cymru.com"
    return None


def _fields(txt: str) -> list[str]:
    return [c.strip() for c in unquote_txt(txt).split("|")]


def parse_cymru_origin(txt: str) -> dict:
    """Parse an origin.asn.cymru.com TXT: ``AS | prefix | CC | registry | date``."""
    f = _fields(txt)
    return {
        "asn": f[0] if len(f) > 0 and f[0] else None,
        "prefix": f[1] if len(f) > 1 and f[1] else None,
        "country_code": f[2] if len(f) > 2 and f[2] else None,
        "registry": f[3] if len(f) > 3 and f[3] else None,
    }


def parse_cymru_asname(txt: str) -> dict:
    """Parse an asn.cymru.com TXT: ``AS | CC | registry | date | AS-name``."""
    f = _fields(txt)
    return {
        "asn": f[0] if len(f) > 0 and f[0] else None,
        "country_code": f[1] if len(f) > 1 and f[1] else None,
        "registry": f[2] if len(f) > 2 and f[2] else None,
        "as_name": f[4] if len(f) > 4 and f[4] else None,
    }


def _num(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_ipapi(data: dict) -> dict:
    """Normalize an ip-api.com JSON response into our IpIntel field names."""
    if not isinstance(data, dict) or data.get("status") == "fail":
        return {}
    return {
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName") or data.get("region"),
        "city": data.get("city"),
        "latitude": _num(data.get("lat")),
        "longitude": _num(data.get("lon")),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as_name": data.get("as") or data.get("asname"),
    }


def classify_provider(*signals: str | None) -> str | None:
    """Map an AS-name / ISP / org string to a known cloud/CDN provider label."""
    blob = " ".join(s for s in signals if s).lower()
    for marker, label in _PROVIDER_MARKERS:
        if marker in blob:
            return label
    return None


def cdn_from_headers(headers: dict[str, str]) -> str | None:
    """Detect a CDN/proxy on the HTTP edge from response headers."""
    lower = {k.lower(): (v or "") for k, v in headers.items()}
    for header, needle, provider in _CDN_HEADER_SIGNALS:
        val = lower.get(header)
        if val is None:
            continue
        if not needle or needle in val.lower():
            return provider
    return None


def detect_origin_exposure(edge_cdn: str | None, ip_provider: str | None) -> bool:
    """True when the edge is a CDN but the resolved IP is a *different, known* net.

    That means DNS handed us a direct/origin host instead of the CDN edge — the
    classic "bypass the WAF by hitting the origin IP" exposure. Conservative on
    both sides: we only assert exposure when a CDN edge is positively identified
    AND the resolved IP is classified to a *different known* provider. An unknown
    provider (ASN/geo lookup failed or rate-limited) is NOT treated as exposure —
    otherwise every CDN site would misfire whenever classification is unavailable.
    """
    if not edge_cdn or not ip_provider:
        return False
    return ip_provider != edge_cdn
