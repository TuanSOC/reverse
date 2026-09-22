"""HTTP fetch + redirect/transport analysis (§5/§6).

Fetches the target's base URL through the shared engine, stores the primary
response on the context for downstream modules (crawler, headers, cookies,
technology), and raises findings for redirect/transport issues:

* the site is served over plain HTTP (no HTTPS);
* an HTTPS → HTTP downgrade occurs in the redirect chain;
* a cross-domain redirect (informational).
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
from ...core.urls import parse_url, same_registrable_domain
from ...engine.http_engine import HttpEngineError

# Key under which the primary response is published for downstream modules.
PRIMARY_RESPONSE_KEY = "primary_response"


@default_registry.register
class HttpModule(ScannerModule):
    name = "http"
    version = "0.1.0"
    requires = ("scope",)
    description = "Fetch the base URL; analyze redirects and transport security."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        if target is None or ctx.http is None:
            result.error = "target or http engine unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        ctx.cancellation.raise_if_cancelled()

        try:
            resp = await ctx.http.get(target.base_url)
        except HttpEngineError as exc:
            result.error = f"fetch failed: {exc}"
            result.mark_finished(ModuleStatus.FAILED)
            log.warning("base fetch failed", url=target.base_url, error=str(exc))
            return result

        ctx.shared[PRIMARY_RESPONSE_KEY] = resp

        result.data = {
            "final_url": resp.url,
            "status_code": resp.status_code,
            "content_type": resp.content_type,
            "content_length": resp.content_length,
            "elapsed_ms": round(resp.elapsed_ms, 1),
            "truncated": resp.truncated,
            "redirect_count": len(resp.redirect_chain),
            "redirect_chain": [
                {"url": h.url, "status": h.status_code, "location": h.location}
                for h in resp.redirect_chain
            ],
            "server": resp.headers.get("server"),
        }
        result.stats = {"requests": 1 + len(resp.redirect_chain)}

        self._analyze_transport(result, target.base_url, resp)
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info(
            "base fetched",
            status=resp.status_code,
            final_url=resp.url,
            redirects=len(resp.redirect_chain),
        )
        return result

    def _analyze_transport(self, result: ModuleResult, base_url: str, resp) -> None:
        base = parse_url(base_url)
        final = parse_url(resp.url)

        # 1) Plain HTTP with no upgrade to HTTPS.
        if final.scheme == "http":
            result.findings.append(
                Finding(
                    check_id="transport.https.missing",
                    name="Site served over plain HTTP",
                    category=FindingCategory.TRANSPORT,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description="The final response is served over unencrypted HTTP.",
                    impact="Traffic can be read or modified by a network attacker.",
                    recommendation=(
                        "Serve the site exclusively over HTTPS and redirect HTTP to HTTPS."
                    ),
                    references=[
                        "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security"
                    ],
                    evidence=[
                        Evidence(
                            source=self.name,
                            url=resp.url,
                            description="Final URL uses http scheme",
                            data={"final_url": resp.url, "scheme": final.scheme},
                        )
                    ],
                )
            )

        # 2) HTTPS -> HTTP downgrade anywhere in the redirect chain.
        for hop in resp.redirect_chain:
            hop_from = parse_url(hop.url)
            if hop.location:
                try:
                    hop_to = parse_url(str(_join(hop.url, hop.location)))
                except ValueError:
                    continue
                if hop_from.scheme == "https" and hop_to.scheme == "http":
                    result.findings.append(
                        Finding(
                            check_id="transport.https.downgrade",
                            name="HTTPS to HTTP downgrade in redirect chain",
                            category=FindingCategory.TRANSPORT,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            observation=Observation.OBSERVED,
                            module=self.name,
                            description="A redirect sends the client from HTTPS to plain HTTP.",
                            impact="Downgrades the connection to an interceptable channel.",
                            recommendation=(
                                "Never redirect from HTTPS to HTTP; keep the whole chain on HTTPS."
                            ),
                            evidence=[
                                Evidence(
                                    source=self.name,
                                    url=hop.url,
                                    description="Downgrade hop",
                                    data={"from": hop.url, "to": hop.location},
                                )
                            ],
                        )
                    )

        # 3) Cross-domain redirect (informational).
        if resp.redirect_chain and not same_registrable_domain(base.hostname, final.hostname):
            result.findings.append(
                Finding(
                    check_id="transport.redirect.cross_domain",
                    name="Redirect leaves the target's domain",
                    category=FindingCategory.INFORMATIONAL,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description=(
                        "The base URL ultimately redirects to a different registrable domain."
                    ),
                    impact="May indicate a parked domain, CDN, or an unexpected destination.",
                    recommendation="Confirm the destination domain is expected and in scope.",
                    evidence=[
                        Evidence(
                            source=self.name,
                            url=base_url,
                            description="Cross-domain redirect",
                            data={"from_host": base.hostname, "to_host": final.hostname},
                        )
                    ],
                )
            )


def _join(base: str, location: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base, location)
