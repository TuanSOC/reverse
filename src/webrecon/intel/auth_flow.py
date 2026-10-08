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
    #: stable machine id per step (same order as ``steps``) so UIs can pick an
    #: icon / translation without parsing the English narrative
    step_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "confidence": round(self.confidence, 2),
            "steps": self.steps, "step_keys": self.step_keys,
            "has_login_form": self.has_login_form,
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
        keyed = _oauth_steps(roles)
    elif has_login_form or {"login"} & roles:
        kind = "password"
        conf = 0.5 + (0.2 if has_login_form else 0) + (0.2 if has_session_cookie else 0)
        keyed = _password_steps(roles, has_login_form, has_session_cookie)
    else:
        kind = "unknown"
        conf = 0.3
        keyed = []

    # order endpoints by the canonical step order for display
    auth_eps.sort(key=lambda e: _STEP_ORDER.index(e.role) if e.role in _STEP_ORDER else 99)
    return AuthFlow(kind, min(conf, 1.0), [text for _, text in keyed], auth_eps,
                    has_login_form, has_session_cookie, [key for key, _ in keyed])


def _password_steps(roles: set[str], has_form: bool, has_cookie: bool) -> list[tuple[str, str]]:
    steps = []
    if has_form:
        steps.append(("form", "User submits the login form"))
    if "login" in roles:
        steps.append(("login", "POST to the login endpoint"))
    if has_cookie:
        steps.append(("session", "Server sets a session cookie"))
    if "identity" in roles:
        steps.append(("identity", "App fetches the current identity (/me)"))
    if "logout" in roles:
        steps.append(("logout", "Logout endpoint ends the session"))
    return steps


def _oauth_steps(roles: set[str]) -> list[tuple[str, str]]:
    steps = [("redirect", "App redirects to the authorization endpoint")]
    if "authorize" in roles:
        steps.append(("authorize", "Identity provider authenticates the user"))
    if "callback" in roles:
        steps.append(("callback", "Provider redirects back to the callback"))
    if "token" in roles:
        steps.append(("token", "App exchanges the code for a token"))
    if "identity" in roles:
        steps.append(("identity", "App fetches the user profile"))
    return steps


# Name tokens that identify a session/auth cookie, and ones that never do.
_SESSION_TOKENS = frozenset({
    "session", "sessionid", "sess", "sessid", "sid", "jsessionid", "phpsessid",
    "auth", "authtoken", "token", "jwt", "logged", "access",
})
_NOT_SESSION_TOKENS = frozenset({"csrf", "csrftoken", "xsrf"})
# Framework names that are not token-shaped: Drupal SESS<hash>/SSESS<hash>,
# classic ASP ASPSESSIONID…, ASP.NET forms auth, ColdFusion CFID/CFTOKEN.
_SESSION_NAME = re.compile(
    r"^(?:s?sess[0-9a-f]{6,}|aspsessionid\w*|\.?aspxauth|cfid|cftoken)$", re.I)


def is_session_cookie(name: str) -> bool:
    """Does a cookie *name* look like a session/auth cookie?

    Matches whole name tokens (split on ``_ - .``) so ``visid_incap_1`` or
    ``consider`` do not match ``sid``, and CSRF cookies are never sessions.
    """
    if _SESSION_NAME.match(name or ""):
        return True
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")  # sessionToken
    tokens = {t for t in re.split(r"[_\-.]+", spaced.lower()) if t}
    if not tokens or tokens & _NOT_SESSION_TOKENS:
        return False
    return bool(tokens & _SESSION_TOKENS)


def auth_flow_from_rows(
    endpoints: list[dict], forms: list[dict], cookie_names: list[str]
) -> AuthFlow:
    """Build the auth-flow model from endpoint/form rows and cookie names."""
    has_login_form = any(
        str(i.get("type") or "").lower() == "password"
        for fm in forms for i in (fm.get("inputs") or [])
    )
    has_session_cookie = any(is_session_cookie(n or "") for n in cookie_names)
    return build_auth_flow(
        endpoints, has_login_form=has_login_form, has_session_cookie=has_session_cookie)
