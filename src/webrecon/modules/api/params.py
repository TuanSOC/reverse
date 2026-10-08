"""Pure parameter-intelligence classification (no I/O) — attack-surface insight.

Classifies a parameter by its *name* (and optional value shape) into a semantic
class with a confidence. This is intelligence only — it never exploits a
parameter; it tells the researcher what a parameter probably *is* so the attack
surface is understandable (e.g. an ``object_identifier`` hints at IDOR surface, a
``redirect`` at open-redirect surface).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Semantic classes (stable string ids used in storage/UI).
OBJECT_ID = "object_identifier"
USER_ID = "user_identifier"
REDIRECT = "redirect"
CALLBACK = "callback"
TOKEN = "token"  # noqa: S105 - class name, not a credential
FILE_PATH = "file_path"
URL_PARAM = "url"
SEARCH = "search"
PAGINATION = "pagination"
SORTING = "sorting"
FILTERING = "filtering"
AUTH = "authentication"
UNKNOWN = "unknown"

#: Classes that make a parameter security-relevant (IDOR, redirect, SSRF, …).
INTERESTING_PARAMS = frozenset({
    OBJECT_ID, USER_ID, REDIRECT, CALLBACK, TOKEN, FILE_PATH, URL_PARAM, AUTH,
})

# (class, confidence, name-regex). First match wins; order = specificity.
_RULES: tuple[tuple[str, float, re.Pattern[str]], ...] = (
    (REDIRECT, 0.9, re.compile(
        r"^(?:redirect(?:_?uri|_?url)?|return(?:_?to|url)?|next|dest(?:ination)?"
        r"|continue|goto|forward|target_?url)$", re.I)),
    (CALLBACK, 0.85, re.compile(r"^(?:callback|cb|jsonp)$", re.I)),
    (TOKEN, 0.88, re.compile(
        r"^(?:.*_?)?(?:token|jwt|api[_-]?key|apikey|secret|access[_-]?token"
        r"|refresh[_-]?token|auth[_-]?token|csrf|xsrf|nonce|signature|sig)$", re.I)),
    (AUTH, 0.75, re.compile(r"^(?:password|passwd|pwd|otp|code|session|sid|sessionid)$", re.I)),
    (USER_ID, 0.85, re.compile(
        r"^(?:user_?id|uid|account_?id|customer_?id|member_?id|owner_?id|username|email)$", re.I)),
    (OBJECT_ID, 0.8, re.compile(
        r"^(?:id|.*_id|.*Id|guid|uuid|ref|key|pk|object_?id|order_?id|item_?id"
        r"|product_?id|doc_?id|file_?id|post_?id)$", re.I)),
    (FILE_PATH, 0.8, re.compile(
        r"^(?:file|filename|filepath|path|dir|folder|document|attachment|download|upload)$", re.I)),
    (URL_PARAM, 0.7, re.compile(r"^(?:url|uri|link|href|src|source|image_?url|img)$", re.I)),
    (SEARCH, 0.75, re.compile(r"^(?:q|query|search|keyword|term|s|find)$", re.I)),
    (PAGINATION, 0.85, re.compile(
        r"^(?:page|page_?num|pagenumber|offset|limit|per_?page|page_?size|start|count|size)$",
        re.I)),
    (SORTING, 0.85, re.compile(
        r"^(?:sort|order|order_?by|sort_?by|direction|asc|desc)$", re.I)),
    (FILTERING, 0.7, re.compile(
        r"^(?:filter|category|type|status|state|tag|from|to|date|since)$", re.I)),
)

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


@dataclass
class ParamIntel:
    name: str
    classification: str
    confidence: float
    source: str = "query"  # query | path | json | form | header | cookie


def classify_param(name: str, value: str | None = None, source: str = "query") -> ParamIntel:
    """Classify one parameter by name (and optional sample value)."""
    nm = (name or "").strip()
    for cls, conf, pat in _RULES:
        if pat.match(nm):
            return ParamIntel(nm, cls, conf, source)

    # Value-shape fallbacks (weaker signal) when the name is uninformative.
    if value:
        v = value.strip()
        if _JWT.match(v):
            return ParamIntel(nm, TOKEN, 0.7, source)
        if _UUID.match(v):
            return ParamIntel(nm, OBJECT_ID, 0.6, source)
        if v.isdigit() and len(v) <= 12 and "id" in nm.lower():
            return ParamIntel(nm, OBJECT_ID, 0.55, source)
    return ParamIntel(nm, UNKNOWN, 0.3, source)


def classify_params(names, source: str = "query") -> list[ParamIntel]:
    """Classify a collection of parameter names (deduped, stable order)."""
    out: list[ParamIntel] = []
    seen: set[str] = set()
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(classify_param(n, source=source))
    return out
