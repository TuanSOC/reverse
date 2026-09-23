"""Opt-in active verification of open-redirect & reflected-XSS candidates.

Runs ONLY when ``config.active`` is set (``--active``), i.e. against a target
the operator is authorized to test. It upgrades passive *candidates* to
*confirmed* findings by sending benign canary probes through a GET-only,
scope-checked, SSRF-guarded, budget-capped engine and inspecting the response.

Safety contract (structural, not by convention):
- GET only (via :class:`SafeGetEngine`); no mutation, no data extraction.
- Canaries are inert: an unresolvable ``.invalid`` redirect target and an
  ``<xss>`` reflection marker — no script executes, nothing is exfiltrated.
- Hard request budget; only in-scope, same-origin URLs are probed.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

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
from ..api.security_checks import OPEN_REDIRECT_PARAMS
from ..apitest.safe_engine import SafeGetEngine
from ..javascript.module import JS_ANALYSIS_KEY
from .analysis import (
    REDIRECT_CANARY_HOST,
    build_redirect_probe,
    build_xss_probe,
    redirect_confirmed,
    xss_reflected,
)

MAX_REQUESTS = 40
MAX_CANDIDATES = 15


@default_registry.register
class ActiveVerifyModule(ScannerModule):
    name = "active_verify"
    version = "0.1.0"
    requires = ("api",)
    description = "Opt-in active verification of open-redirect & reflected-XSS (GET-only)."
    _budget = 0

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        if not ctx.config.active:
            result.data = {"skipped": "active testing disabled (use --active)"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result
        if ctx.http is None or ctx.target is None:
            result.data = {"skipped": "no HTTP engine / target"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        self._budget = 0
        engine = SafeGetEngine(ctx.http)
        candidates = self._candidates(ctx)

        redirect_hits = 0
        xss_hits = 0
        for url, param in candidates:
            if self._budget >= MAX_REQUESTS:
                result.data = {"budget_exhausted": True}
                break
            if param.lower() in OPEN_REDIRECT_PARAMS:
                if await self._check_redirect(engine, url, param, result):
                    redirect_hits += 1
            if await self._check_xss(engine, url, param, result):
                xss_hits += 1

        result.data = {
            "active": True,
            "candidates": len(candidates),
            "requests": self._budget,
            "open_redirect_confirmed": redirect_hits,
            "xss_reflected": xss_hits,
        }
        result.stats = {"requests": self._budget, "confirmed": redirect_hits + xss_hits}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("active_verify complete", requests=self._budget,
                 open_redirect=redirect_hits, xss=xss_hits)
        return result

    def _candidates(self, ctx) -> list[tuple[str, str]]:
        """In-scope URLs (with query params) to probe, deduped and capped."""
        urls: list[str] = []
        for e in ctx.shared.get("api_endpoints") or []:
            urls.append(e.url)
        inv = ctx.shared.get("inventory")
        if inv is not None:
            for page in inv.pages:
                urls.append(page.url)
                urls.extend(page.links)
        for a in ctx.shared.get(JS_ANALYSIS_KEY) or []:
            urls.extend(getattr(a, "urls", []))

        host = ctx.target.hostname
        out: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for url in urls:
            try:
                parts = urlsplit(url)
            except ValueError:
                continue
            if parts.hostname != host:  # same-origin only (scope also enforces)
                continue
            for name, _ in parse_qsl(parts.query, keep_blank_values=True):
                key = (url, name)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
                if len(out) >= MAX_CANDIDATES:
                    return out
        return out

    async def _check_redirect(self, engine, url: str, param: str, result) -> bool:
        probe = build_redirect_probe(url, param)
        try:
            self._budget += 1
            resp = await engine.get(probe, follow_redirects=False)
        except Exception:  # noqa: BLE001 - probe failures must not crash the scan
            return False
        location = resp.headers.get("location") or resp.headers.get("Location")
        if not redirect_confirmed(resp.status_code, location):
            return False
        result.findings.append(Finding(
            check_id="active.open_redirect.confirmed",
            name="Confirmed open redirect", category=FindingCategory.CONFIGURATION,
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            observation=Observation.OBSERVED, module=self.name,
            description=(
                f"Parameter {param!r} redirects off-origin to an attacker-controlled "
                "URL (verified with a benign canary target)."
            ),
            impact="Enables phishing/redirect attacks that abuse this domain's trust.",
            recommendation=(
                "Validate redirect targets against an allowlist of internal paths; "
                "reject absolute/off-origin URLs."
            ),
            evidence=[Evidence(
                source=self.name, url=url,
                description=f"canary redirect via {param!r}",
                data={"param": param, "status": resp.status_code,
                      "location": location, "canary": REDIRECT_CANARY_HOST},
            )],
        ))
        return True

    async def _check_xss(self, engine, url: str, param: str, result) -> bool:
        if self._budget >= MAX_REQUESTS:
            return False
        probe = build_xss_probe(url, param)
        try:
            self._budget += 1
            resp = await engine.get(probe)
        except Exception:  # noqa: BLE001 - probe failures must not crash the scan
            return False
        if not xss_reflected(resp.text, resp.content_type, url, param):
            return False
        result.findings.append(Finding(
            check_id="active.xss.reflected",
            name="Reflected input (potential XSS)", category=FindingCategory.VULNERABILITY,
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            observation=Observation.OBSERVED, module=self.name,
            description=(
                f"A canary injected via {param!r} is reflected unencoded in the HTML "
                "response — the precondition for reflected XSS."
            ),
            impact="Attacker-controlled markup may execute in a victim's browser.",
            recommendation=(
                "Context-encode all user input on output; apply a strict CSP. "
                "Confirm exploitability manually before remediation sign-off."
            ),
            evidence=[Evidence(
                source=self.name, url=url,
                description=f"unencoded reflection of canary via {param!r}",
                data={"param": param, "content_type": resp.content_type},
            )],
        ))
        return True
