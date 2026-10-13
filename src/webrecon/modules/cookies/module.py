"""Cookie flag analysis (§14).

Parses Set-Cookie headers from the primary response and flags missing Secure /
HttpOnly / SameSite protections, SameSite=None without Secure, overly broad
Domain, and cookie-prefix violations. Cookie **values are never stored or shown
in full** — they are masked (§14).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...core.enums import (
    Confidence,
    FindingCategory,
    ModuleStatus,
    Observation,
    Severity,
)
from ...core.models import Evidence, Finding, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ...core.urls import parse_url
from ..http.module import PRIMARY_RESPONSE_KEY

# Names that suggest a session/auth cookie (stricter expectations).
_SENSITIVE_HINTS = ("sess", "sid", "token", "auth", "jwt", "csrf", "xsrf")


@dataclass
class ParsedCookie:
    name: str
    value: str
    domain: str | None = None
    path: str | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    attributes: dict = field(default_factory=dict)

    @property
    def masked_value(self) -> str:
        if len(self.value) <= 4:
            return "****"
        return f"{self.value[:4]}…****"

    @property
    def looks_sensitive(self) -> bool:
        n = self.name.lower()
        return any(h in n for h in _SENSITIVE_HINTS)


def parse_set_cookie(header: str) -> ParsedCookie | None:
    """Parse a single Set-Cookie header value."""
    parts = [p.strip() for p in header.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    cookie = ParsedCookie(name=name.strip(), value=value.strip())
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "samesite":
            cookie.same_site = val or None
        elif key == "domain":
            cookie.domain = val
        elif key == "path":
            cookie.path = val
        else:
            cookie.attributes[key] = val or True
    return cookie


@default_registry.register
class CookiesModule(ScannerModule):
    name = "cookies"
    version = "0.1.0"
    requires = ("http",)
    description = "Analyze Set-Cookie flags (Secure/HttpOnly/SameSite/Domain)."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()

        resp = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        if resp is None:
            result.error = "no primary response"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        is_https = parse_url(resp.url).scheme == "https"
        base_host = parse_url(resp.url).hostname
        cookies = [c for raw in resp.set_cookie if (c := parse_set_cookie(raw))]
        result.data = {"cookie_count": len(cookies), "names": [c.name for c in cookies]}

        for c in cookies:
            self._analyze(result, c, resp.url, is_https, base_host)

        if ctx.storage is not None and cookies:
            await ctx.storage.save_cookies(ctx.scan_id, cookies)
        result.mark_finished(ModuleStatus.SUCCESS)
        return result

    def _analyze(self, result, c: ParsedCookie, url, is_https, base_host) -> None:
        ev_data = {
            "name": c.name,
            "value": c.masked_value,
            "domain": c.domain,
            "path": c.path,
            "secure": c.secure,
            "http_only": c.http_only,
            "same_site": c.same_site,
        }

        def add(check_id, name, severity, description, impact, recommendation):
            result.findings.append(
                Finding(
                    check_id=check_id,
                    name=name,
                    category=FindingCategory.COOKIES,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description=description,
                    impact=impact,
                    recommendation=recommendation,
                    evidence=[
                        Evidence(source=self.name, url=url, description=name, data=dict(ev_data))
                    ],
                )
            )

        if is_https and not c.secure:
            add(
                "cookies.secure.missing", f"Cookie '{c.name}' missing Secure",
                Severity.MEDIUM if c.looks_sensitive else Severity.LOW,
                "The cookie is set without the Secure attribute over HTTPS.",
                "The cookie can be sent over plaintext HTTP and intercepted.",
                "Add the Secure attribute so the cookie is only sent over HTTPS.",
            )
        if c.looks_sensitive and not c.http_only:
            add(
                "cookies.httponly.missing", f"Session cookie '{c.name}' missing HttpOnly",
                Severity.MEDIUM,
                "A session/auth-looking cookie is accessible to JavaScript.",
                "XSS can steal the cookie, enabling session hijacking.",
                "Add the HttpOnly attribute to session cookies.",
            )
        if c.same_site is None:
            add(
                "cookies.samesite.missing", f"Cookie '{c.name}' missing SameSite",
                Severity.LOW,
                "No SameSite attribute is set; browser defaults vary.",
                "May expose the cookie to cross-site request forgery.",
                "Set SameSite=Lax or Strict as appropriate.",
            )
        elif c.same_site.lower() == "none" and not c.secure:
            add(
                "cookies.samesite.none_insecure", f"Cookie '{c.name}' SameSite=None without Secure",
                Severity.MEDIUM,
                "SameSite=None requires Secure; without it the cookie is rejected/risky.",
                "Cross-site cookie sent without transport protection.",
                "Add Secure whenever SameSite=None is used.",
            )
        if c.domain and _domain_too_broad(c.domain, base_host):
            add(
                "cookies.domain.broad", f"Cookie '{c.name}' has a broad Domain",
                Severity.LOW,
                f"Domain={c.domain} widens the cookie to parent/sibling hosts.",
                "Broadens exposure of the cookie beyond the issuing host.",
                "Scope the cookie to the exact host or drop the Domain attribute.",
            )

        # Cookie name prefixes (RFC 6265bis) carry binding guarantees; a prefix
        # without its required attributes is silently ignored by browsers.
        name = c.name
        if name.startswith("__Secure-") and not c.secure:
            add(
                "cookies.prefix.secure_violation",
                f"'__Secure-' cookie '{name}' is not Secure",
                Severity.MEDIUM,
                "A '__Secure-'-prefixed cookie must set the Secure attribute.",
                "Browsers reject the cookie, potentially breaking the intended binding.",
                "Add the Secure attribute (and serve over HTTPS).",
            )
        if name.startswith("__Host-") and (not c.secure or c.domain or (c.path or "/") != "/"):
            add(
                "cookies.prefix.host_violation",
                f"'__Host-' cookie '{name}' breaks prefix rules",
                Severity.MEDIUM,
                "A '__Host-' cookie must be Secure, have no Domain, and Path=/.",
                "The binding guarantee is lost; browsers reject the cookie.",
                "Set Secure, remove Domain, and use Path=/.",
            )


def _domain_too_broad(domain: str, base_host: str) -> bool:
    d = domain.lstrip(".").lower()
    base = base_host.lower()
    # A Domain equal to the host is fine; a parent domain widens scope.
    return d != base and base.endswith("." + d)
