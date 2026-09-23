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

# Redirect bypass techniques — each payload, if reflected into Location, resolves
# (in a browser) to the off-origin canary host. Testing the whole family catches
# validators that block "http://evil" but miss scheme-relative / userinfo /
# backslash / double-encoded forms.
REDIRECT_VARIANTS: tuple[tuple[str, str], ...] = (
    ("absolute", _REDIRECT_CANARY_URL),                       # https://canary/
    ("scheme_relative", f"//{REDIRECT_CANARY_HOST}/"),        # //canary/
    ("backslash", f"/\\{REDIRECT_CANARY_HOST}/"),             # /\canary/  (\ → /)
    ("userinfo", f"https://trusted.example@{REDIRECT_CANARY_HOST}/"),  # user@canary
    ("double_encoded", f"%252f%252f{REDIRECT_CANARY_HOST}%252f"),  # //canary/ (2x enc)
)


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

def build_redirect_probe(url: str, param: str, payload: str = _REDIRECT_CANARY_URL) -> str:
    """Return ``url`` with ``param`` set to a redirect canary payload."""
    return _set_param(url, param, payload)


def effective_redirect_host(location: str) -> str | None:
    """The host a browser would actually navigate to for a Location value.

    Normalizes the bypass forms we probe: backslashes → slashes, scheme-relative
    ``//host``, and ``user@host`` userinfo. Percent-decodes once so a
    double-encoded payload that the server decoded once still resolves.
    """
    from urllib.parse import unquote

    loc = unquote(location.strip()).replace("\\", "/")
    # Drop a leading scheme ("https:") so scheme-relative and absolute align.
    if "://" in loc:
        loc = loc.split("://", 1)[1]
    elif loc.startswith("//"):
        loc = loc[2:]
    else:
        return None  # a same-site relative path ("/home") — not off-origin
    authority = loc.split("/", 1)[0]
    host = authority.rsplit("@", 1)[-1]      # strip userinfo
    host = host.split(":", 1)[0]             # strip port
    return host.lower() or None


def redirect_confirmed(status_code: int, location: str | None) -> bool:
    """True when a 3xx response redirects off-origin to our canary host."""
    if location is None or not (300 <= status_code < 400):
        return False
    host = effective_redirect_host(location)
    return host is not None and REDIRECT_CANARY_HOST in host


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
