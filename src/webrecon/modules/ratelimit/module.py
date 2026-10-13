"""Rate-limit & protection posture module.

Passive (always): report rate-limit quotas and WAF/protection layers advertised
in the responses the scan already received — zero extra requests.

Active (``--active`` only, authorized targets): a hard-capped burst-free probe —
up to :data:`MAX_PROBE_REQUESTS` sequential GETs to ONE already-observed endpoint,
through the normal rate limiter — to confirm whether throttling/blocking is
enforced at the scan's polite request rate. Detection-only: it establishes
presence/absence, never the exact threshold, and never attempts a bypass or a
flood (§1).
"""

from __future__ import annotations

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
from ..http.module import PRIMARY_RESPONSE_KEY
from .analysis import (
    RATE_LIMIT_STATUS,
    ProbeOutcome,
    classify_probe,
    detect_protection,
    parse_rate_limit,
)

#: Hard cap on active-probe requests to a single endpoint. Small on purpose:
#: this is detection, not stress-testing. Never raise without re-reviewing §1.
MAX_PROBE_REQUESTS = 12

_API_INVENTORY_KEY = "api_endpoints"


@default_registry.register
class RateLimitModule(ScannerModule):
    name = "ratelimit"
    version = "0.1.0"
    requires = ("http",)
    description = "Detect advertised rate limiting / WAF; optionally confirm enforcement."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        resp = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        if resp is None:
            result.data = {"skipped": "no primary response"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        advertised = self._passive(result, resp)

        probe: ProbeOutcome | None = None
        if ctx.config.active:
            probe = await self._active_probe(ctx, result, advertised, log)

        result.data = {
            "advertised": advertised is not None,
            "protection": detect_protection(resp.headers),
            "active_probe": probe.verdict if probe else None,
        }
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("ratelimit complete", advertised=advertised is not None,
                 probe=probe.verdict if probe else None)
        return result

    # -- passive ------------------------------------------------------------------

    def _passive(self, result: ModuleResult, resp) -> object | None:
        advertised = parse_rate_limit(resp.headers)
        if advertised is not None:
            result.findings.append(Finding(
                check_id="ratelimit.advertised",
                name="Rate limiting advertised", category=FindingCategory.CONFIGURATION,
                severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
                observation=Observation.OBSERVED, module=self.name,
                description=f"The server advertises rate limiting ({advertised.summary()}).",
                impact="Informational: a rate-limit policy is in place for this response.",
                recommendation="No action — documented for attack-surface context.",
                evidence=[Evidence(
                    source=self.name, url=resp.url, description="Rate-limit headers",
                    data={"headers_seen": advertised.headers_seen,
                          "limit": advertised.limit, "remaining": advertised.remaining,
                          "reset": advertised.reset, "policy": advertised.policy,
                          "retry_after": advertised.retry_after})],
            ))

        provider = detect_protection(resp.headers)
        if provider is not None:
            result.findings.append(Finding(
                check_id="ratelimit.protection.detected",
                name=f"Protection layer detected: {provider}",
                category=FindingCategory.CONFIGURATION, severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM, observation=Observation.OBSERVED, module=self.name,
                description=f"A WAF / bot-management / CDN edge was detected ({provider}).",
                impact="Informational: traffic is fronted by a protection layer, which "
                       "typically applies its own rate limiting and bot defenses.",
                recommendation="No action — useful context for the attack surface.",
                evidence=[Evidence(source=self.name, url=resp.url,
                                   description="Protection-layer header signal",
                                   data={"provider": provider})],
            ))
        return advertised

    # -- active (authorized / --active only) --------------------------------------

    async def _active_probe(
        self, ctx, result: ModuleResult, advertised, log
    ) -> ProbeOutcome | None:
        target_url = self._probe_target(ctx)
        if target_url is None or ctx.http is None:
            return None

        statuses: list[int] = []
        retry_after: str | None = None
        for _ in range(MAX_PROBE_REQUESTS):
            try:
                ctx.cancellation.raise_if_cancelled()
            except Exception:  # noqa: BLE001 - surfaces as a short probe, not a crash
                break
            try:
                r = await ctx.http.get(target_url)
            except Exception as exc:  # noqa: BLE001 - one failed hop ends the probe
                log.debug("ratelimit probe request failed", error=str(exc))
                break
            statuses.append(r.status_code)
            if r.status_code == RATE_LIMIT_STATUS:
                retry_after = {k.lower(): v for k, v in r.headers.items()}.get("retry-after")
                break

        outcome = classify_probe(statuses, retry_after)
        self._probe_findings(result, target_url, outcome, advertised)
        return outcome

    def _probe_target(self, ctx) -> str | None:
        """Pick ONE already-observed GET endpoint to probe, else the target base URL."""
        for ep in ctx.shared.get(_API_INVENTORY_KEY) or []:
            methods = {m.upper() for m in getattr(ep, "methods", set())}
            if (str(getattr(ep, "observation", "")) == "observed"
                    and getattr(ep, "in_scope", False)
                    and (not methods or "GET" in methods)
                    and "?" not in ep.url):
                return ep.url
        return getattr(ctx.target, "base_url", None)

    def _probe_findings(self, result, url, o: ProbeOutcome, advertised) -> None:
        ev = Evidence(source=self.name, url=url, description="Rate-limit probe",
                      data={"requests": o.requests, "statuses": o.statuses,
                            "verdict": o.verdict, "tripped_at": o.tripped_at,
                            "retry_after": o.retry_after})
        if o.verdict == "enforced":
            result.findings.append(Finding(
                check_id="ratelimit.enforced", name="Rate limiting enforced",
                category=FindingCategory.CONFIGURATION, severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                description=f"Throttling was observed on {url}: {o.detail}.",
                impact="Informational: the endpoint rate-limits repeated requests.",
                recommendation="No action — confirms a protective control is active.",
                evidence=[ev]))
        elif o.verdict == "blocked":
            result.findings.append(Finding(
                check_id="ratelimit.blocked", name="Request blocking observed",
                category=FindingCategory.CONFIGURATION, severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM, observation=Observation.OBSERVED, module=self.name,
                description=f"Requests to {url} began failing and did not recover: {o.detail}. "
                            "This may be a protection layer throttling or temporarily blocking "
                            "the scanner.",
                impact="Informational: a blocking/throttling control reacted to repeated requests.",
                recommendation="Expected for protected targets; lower --rate if scanning should "
                               "stay below the threshold.",
                evidence=[ev]))
        elif o.verdict == "none_observed" and advertised is None:
            result.findings.append(Finding(
                check_id="ratelimit.absent",
                name="No rate limiting observed",
                category=FindingCategory.CONFIGURATION, severity=Severity.LOW,
                confidence=Confidence.MEDIUM, observation=Observation.OBSERVED, module=self.name,
                description=f"{o.detail} on {url}, and no rate-limit headers were advertised. "
                            "The endpoint may accept unbounded automated requests.",
                impact="Endpoints without rate limiting are exposed to brute-force, credential "
                       "stuffing, scraping and resource-exhaustion abuse.",
                recommendation="Apply per-client/IP rate limiting (and account lockout / CAPTCHA "
                               "on authentication endpoints), and advertise RateLimit-* headers.",
                evidence=[ev]))
