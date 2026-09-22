"""Pure form classification + hygiene heuristics (no I/O).

Classifies discovered HTML forms by purpose and inspects them for CSRF-token
presence and password-field transport/autocomplete hygiene. All heuristic and
passive — the crawler already fetched these forms; nothing is submitted here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

# name/type substrings that hint at a form's purpose. Order matters: the first
# category whose cue set matches wins (payment/login before generic search).
_KIND_CUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("payment", ("card", "cardnumber", "cvv", "cvc", "creditcard", "cc-number")),
    ("reset", ("reset", "forgot", "recover", "new-password", "newpassword")),
    ("register", ("register", "signup", "sign-up", "confirm-password",
                  "confirmpassword", "repeat-password")),
    ("login", ("password", "passwd", "login", "signin", "sign-in", "username")),
    ("contact", ("message", "comment", "subject", "enquiry", "inquiry")),
    ("search", ("search", "query", "q", "keyword")),
)

# Hidden-input name cues that indicate an anti-CSRF token.
_CSRF_CUES = (
    "csrf", "xsrf", "authenticity_token", "__requestverificationtoken",
    "_token", "csrfmiddlewaretoken", "nonce", "anticsrf",
)


@dataclass
class FormReport:
    kind: str
    method: str
    action: str
    state_changing: bool
    has_password: bool
    has_csrf_token: bool
    csrf_missing: bool               # state-changing form w/o token
    insecure_password_transport: bool  # password posted over http://
    password_autocomplete_on: bool     # password field allows browser storage
    cues: list[str] = field(default_factory=list)


def _fields_blob(inputs: list[dict]) -> str:
    parts = []
    for i in inputs:
        parts.append(str(i.get("name") or ""))
        parts.append(str(i.get("type") or ""))
    return " ".join(parts).lower()


def classify_form(form) -> FormReport:
    """Classify one DiscoveredForm and compute its hygiene flags."""
    inputs = form.inputs or []
    blob = _fields_blob(inputs)
    method = (form.method or "get").lower()
    action = form.action or form.page_url or ""

    types = [str(i.get("type") or "").lower() for i in inputs]
    has_password = "password" in types

    kind = "other"
    matched: list[str] = []
    for name, cues in _KIND_CUES:
        hits = [c for c in cues if c in blob]
        if hits:
            kind = name
            matched = hits
            break
    if kind == "other" and method == "get":
        kind = "search"  # GET form with no strong cue → treat as search-like

    # A POST (or non-GET) form mutates server state; GET search forms don't.
    state_changing = method not in ("get", "")

    # CSRF token = a hidden input whose name matches a known token cue.
    has_csrf = any(
        str(i.get("type") or "").lower() == "hidden"
        and any(cue in str(i.get("name") or "").lower() for cue in _CSRF_CUES)
        for i in inputs
    )
    csrf_missing = state_changing and not has_csrf

    # Password over cleartext transport (action resolves to http://).
    scheme = urlparse(action).scheme.lower()
    insecure_pw = has_password and scheme == "http"

    # A password field that permits autocomplete storage on shared machines.
    pw_autocomplete_on = any(
        str(i.get("type") or "").lower() == "password"
        and str(i.get("autocomplete") or "").lower() in ("", "on")
        for i in inputs
    )

    return FormReport(
        kind=kind, method=method, action=action, state_changing=state_changing,
        has_password=has_password, has_csrf_token=has_csrf, csrf_missing=csrf_missing,
        insecure_password_transport=insecure_pw,
        password_autocomplete_on=has_password and pw_autocomplete_on,
        cues=matched,
    )
