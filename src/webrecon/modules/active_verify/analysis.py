"""Pure probe-building + response-analysis for active verification (no I/O).

These helpers construct *benign canary* probes and decide, from a response,
whether a vulnerability is confirmed. Canaries are harmless markers — an
unresolvable ``.invalid`` URL for redirects and an inert ``<xss>`` marker for
reflection. Nothing here executes a payload or extracts data; it only proves a
class of bug exists so the finding can be upgraded from POTENTIAL to OBSERVED.
"""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Off-origin, non-resolving canary host (RFC 2606 .invalid never resolves).
REDIRECT_CANARY_HOST = "webrecon-oredir-canary.invalid"
_REDIRECT_CANARY_URL = f"https://{REDIRECT_CANARY_HOST}/"


def _token(url: str, param: str) -> str:
    """A short, deterministic marker unique to one (url, param) probe."""
    return hashlib.sha1(f"{url}|{param}".encode()).hexdigest()[:8]  # noqa: S324 - non-crypto id


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    qs = parse_qsl(parts.query, keep_blank_values=True)
    qs = [(k, value if k == param else v) for k, v in qs]
    if param not in [k for k, _ in qs]:
        qs.append((param, value))
    return urlunsplit(parts._replace(query=urlencode(qs)))


# ---- open redirect -------------------------------------------------------

def build_redirect_probe(url: str, param: str) -> str:
    """Return ``url`` with ``param`` set to the off-origin canary URL."""
    return _set_param(url, param, _REDIRECT_CANARY_URL)


def redirect_confirmed(status_code: int, location: str | None) -> bool:
    """True when a 3xx response redirects to our canary host (off-origin)."""
    if location is None or not (300 <= status_code < 400):
        return False
    loc = location.lower()
    return REDIRECT_CANARY_HOST in loc


# ---- reflected XSS -------------------------------------------------------

def xss_canary(url: str, param: str) -> str:
    """The inert reflection marker injected as a param value."""
    return f"wrx{_token(url, param)}<xss>"


def build_xss_probe(url: str, param: str) -> str:
    return _set_param(url, param, xss_canary(url, param))


def xss_reflected(body: str, content_type: str | None, url: str, param: str) -> bool:
    """True when the canary reflects *unencoded* in an HTML response.

    Encoded reflection (``&lt;xss&gt;``) is safe and is NOT flagged — only a
    verbatim ``<xss>`` in an HTML content type indicates the angle brackets
    survived, which is the precondition for reflected XSS.
    """
    if not content_type or "html" not in content_type.lower():
        return False
    return xss_canary(url, param) in body
