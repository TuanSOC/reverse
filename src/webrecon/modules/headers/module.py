"""Security-header analysis (§13).

Explains what each missing/weak header means, why it matters, and how to fix it —
never just "missing". Confidence is high (we observed the actual response), and
HSTS is only flagged as a real gap on HTTPS. Information-disclosure headers
(Server/X-Powered-By versions) are surfaced as low-severity findings.
"""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(frozen=True)
class HeaderCheck:
    header: str
    check_id: str
    name: str
    severity: Severity
    https_only: bool
    why: str
    fix: str
    reference: str


_CHECKS: tuple[HeaderCheck, ...] = (
    HeaderCheck(
        "content-security-policy", "headers.csp.missing", "Missing Content-Security-Policy",
        Severity.MEDIUM, False,
        "CSP is the primary defense against cross-site scripting and data injection.",
        "Define a restrictive Content-Security-Policy (start in report-only mode).",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
    ),
    HeaderCheck(
        "strict-transport-security", "headers.hsts.missing", "Missing Strict-Transport-Security",
        Severity.MEDIUM, True,
        "HSTS forces browsers to use HTTPS, preventing SSL-strip downgrade attacks.",
        "Send Strict-Transport-Security with a long max-age (and preload if applicable).",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    HeaderCheck(
        "x-content-type-options", "headers.xcto.missing", "Missing X-Content-Type-Options",
        Severity.LOW, False,
        "Without nosniff, browsers may MIME-sniff responses into an executable type.",
        "Send X-Content-Type-Options: nosniff.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    HeaderCheck(
        "x-frame-options", "headers.xfo.missing", "Missing X-Frame-Options",
        Severity.LOW, False,
        "Protects against clickjacking by controlling whether the page can be framed.",
        "Send X-Frame-Options: DENY/SAMEORIGIN, or a CSP frame-ancestors directive.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
    ),
    HeaderCheck(
        "referrer-policy", "headers.referrer.missing", "Missing Referrer-Policy",
        Severity.LOW, False,
        "Controls how much referrer information leaks to other origins.",
        "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    HeaderCheck(
        "permissions-policy", "headers.permissions.missing", "Missing Permissions-Policy",
        Severity.INFORMATIONAL, False,
        "Limits access to powerful browser features (camera, geolocation, etc.).",
        "Send a Permissions-Policy that disables features the site does not use.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
    HeaderCheck(
        "cross-origin-opener-policy", "headers.coop.missing", "Missing Cross-Origin-Opener-Policy",
        Severity.INFORMATIONAL, False,
        "COOP isolates the browsing context group, mitigating cross-origin attacks.",
        "Send Cross-Origin-Opener-Policy: same-origin where compatible.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    ),
    HeaderCheck(
        "cross-origin-resource-policy", "headers.corp.missing",
        "Missing Cross-Origin-Resource-Policy",
        Severity.INFORMATIONAL, False,
        "CORP restricts which origins can embed this resource.",
        "Send Cross-Origin-Resource-Policy: same-origin/same-site as appropriate.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    ),
)

# Headers that disclose implementation/version details.
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


@default_registry.register
class HeadersModule(ScannerModule):
    name = "headers"
    version = "0.1.0"
    requires = ("http",)
    description = "Analyze HTTP security headers with explanations."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()

        resp = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        if resp is None:
            result.error = "no primary response"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_https = parse_url(resp.url).scheme == "https"

        for check in _CHECKS:
            if check.https_only and not is_https:
                continue
            if check.header not in headers:
                result.findings.append(self._missing_finding(check, resp.url))

        for h in _DISCLOSURE_HEADERS:
            if h in headers and _has_version(headers[h]):
                result.findings.append(self._disclosure_finding(h, headers[h], resp.url))

        present = [c.header for c in _CHECKS if c.header in headers]
        result.data = {
            "present_security_headers": present,
            "missing_count": len([f for f in result.findings if f.check_id.endswith(".missing")]),
            "is_https": is_https,
        }
        result.mark_finished(ModuleStatus.SUCCESS)
        return result

    def _missing_finding(self, check: HeaderCheck, url: str) -> Finding:
        return Finding(
            check_id=check.check_id,
            name=check.name,
            category=FindingCategory.HEADERS,
            severity=check.severity,
            confidence=Confidence.HIGH,
            observation=Observation.OBSERVED,
            module=self.name,
            description=f"The response does not set the {check.header} header.",
            impact=check.why,
            recommendation=check.fix,
            references=[check.reference],
            evidence=[
                Evidence(
                    source=self.name,
                    url=url,
                    description=f"{check.header} absent from response headers",
                    data={"header": check.header, "value": None},
                )
            ],
        )

    def _disclosure_finding(self, header: str, value: str, url: str) -> Finding:
        return Finding(
            check_id=f"headers.disclosure.{header.replace('-', '_')}",
            name=f"Version disclosure via {header}",
            category=FindingCategory.HEADERS,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            observation=Observation.OBSERVED,
            module=self.name,
            description=f"The {header} header reveals software/version details.",
            impact="Version details help attackers match known vulnerabilities.",
            recommendation=f"Remove or genericize the {header} header.",
            evidence=[
                Evidence(
                    source=self.name,
                    url=url,
                    description=f"{header} header value",
                    data={"header": header, "value": value},
                )
            ],
        )


def _has_version(value: str) -> bool:
    """Heuristic: does the header value contain a version-like token?"""
    return any(ch.isdigit() for ch in value)
