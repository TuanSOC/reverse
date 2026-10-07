"""Authentication-flow model — detection only, from observed surface.

Reconstructs the likely authentication architecture (password login vs OAuth/OIDC)
from discovered auth endpoints, login forms, and session-cookie evidence. It never
submits credentials or attacks auth; it answers "what auth flow does this app
use?" so the researcher understands the architecture. Pure/testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# path-pattern → semantic auth role.
_ROLES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("login", re.compile(
        r"/(?:login|signin|sign-in|auth/login|sessions?|session/new)(?:/|$|\?)", re.I)),
    ("logout", re.compile(r"/(?:logout|signout|sign-out)(?:/|$|\?)", re.I)),
    ("register", re.compile(r"/(?:register|signup|sign-up)(?:/|$|\?)", re.I)),
    ("reset", re.compile(r"/(?:forgot|reset|recover|password)(?:/|$|\?)", re.I)),
    ("authorize", re.compile(
        r"/(?:oauth2?/authorize|authorize|connect/authorize)(?:/|$|\?)", re.I)),
    ("token", re.compile(r"/(?:oauth2?/token|token|connect/token)(?:/|$|\?)", re.I)),
    ("callback", re.compile(
        r"/(?:callback|auth/callback|oauth/callback|signin-oidc)(?:/|$|\?)", re.I)),
    ("identity", re.compile(
        r"/(?:me|whoami|profile|account|userinfo|session/current)(?:/|$|\?)", re.I)),
)

_STEP_ORDER = ["login", "authorize", "callback", "token", "identity", "logout"]


@dataclass
class AuthEndpoint:
    role: str
    url: str
    method: str | None
    observation: str


@dataclass
class AuthFlow:
    kind: str  # "oauth" | "password" | "unknown"
    confidence: float
    steps: list[str] = field(default_factory=list)       # human-ordered narrative
    endpoints: list[AuthEndpoint] = field(default_factory=list)
    has_login_form: bool = False
    has_session_cookie: bool = False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "confidence": round(self.confidence, 2),
            "steps": self.steps, "has_login_form": self.has_login_form,
            "has_session_cookie": self.has_session_cookie,
            "endpoints": [e.__dict__ for e in self.endpoints],
        }


def classify_auth_endpoints(endpoints: list[dict]) -> list[AuthEndpoint]:
    """Tag each endpoint URL with an auth role (first match wins), dedup by role+url."""
    out: list[AuthEndpoint] = []
    seen: set[tuple[str, str]] = set()
    for e in endpoints:
        url = e.get("url") or ""
        for role, pat in _ROLES:
            if pat.search(url):
                key = (role, url)
                if key not in seen:
                    seen.add(key)
                    out.append(AuthEndpoint(role, url, e.get("method"),
                                            e.get("observation", "referenced")))
                break
    return out


def build_auth_flow(
    endpoints: list[dict], *, has_login_form: bool, has_session_cookie: bool
) -> AuthFlow:
    """Build an auth-flow model from endpoints + login-form + session-cookie signals."""
    auth_eps = classify_auth_endpoints(endpoints)
    roles = {e.role for e in auth_eps}

    is_oauth = bool({"authorize", "callback"} & roles) or ("token" in roles and "callback" in roles)
    if is_oauth:
        kind = "oauth"
        conf = 0.6 + 0.1 * len({"authorize", "callback", "token"} & roles)
        steps = _oauth_steps(roles)
    elif has_login_form or {"login"} & roles:
        kind = "password"
        conf = 0.5 + (0.2 if has_login_form else 0) + (0.2 if has_session_cookie else 0)
        steps = _password_steps(roles, has_login_form, has_session_cookie)
    else:
        kind = "unknown"
        conf = 0.3
        steps = []

    # order endpoints by the canonical step order for display
    auth_eps.sort(key=lambda e: _STEP_ORDER.index(e.role) if e.role in _STEP_ORDER else 99)
    return AuthFlow(kind, min(conf, 1.0), steps, auth_eps, has_login_form, has_session_cookie)


def _password_steps(roles: set[str], has_form: bool, has_cookie: bool) -> list[str]:
    steps = []
    if has_form:
        steps.append("User submits the login form")
    if "login" in roles:
        steps.append("POST to the login endpoint")
    if has_cookie:
        steps.append("Server sets a session cookie")
    if "identity" in roles:
        steps.append("App fetches the current identity (/me)")
    if "logout" in roles:
        steps.append("Logout endpoint ends the session")
    return steps


def _oauth_steps(roles: set[str]) -> list[str]:
    steps = ["App redirects to the authorization endpoint"]
    if "authorize" in roles:
        steps.append("Identity provider authenticates the user")
    if "callback" in roles:
        steps.append("Provider redirects back to the callback")
    if "token" in roles:
        steps.append("App exchanges the code for a token")
    if "identity" in roles:
        steps.append("App fetches the user profile")
    return steps
