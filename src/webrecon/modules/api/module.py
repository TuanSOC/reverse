"""API discovery module (§19).

Consolidates endpoint candidates discovered by the crawler (HTML links + any
non-HTML/JSON responses actually fetched), the JavaScript module (referenced
paths, absolute URLs, WebSockets), and the sitemap, into one deduplicated
inventory with honest ``observed | referenced | potential`` provenance. It does
**not** probe or replay endpoints — active confirmation is out of scope.
"""

from __future__ import annotations

from urllib.parse import urljoin

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
from ..javascript.module import JS_ANALYSIS_KEY
from .classify import Endpoint, EndpointAggregator, looks_like_api
from .security_checks import find_open_redirect_params, insecure_websockets

# Key under which the endpoint inventory is published.
API_INVENTORY_KEY = "api_endpoints"


@default_registry.register
class ApiDiscoveryModule(ScannerModule):
    name = "api"
    version = "0.1.0"
    # browser (opt-in) runs first so its network-observed endpoints can upgrade
    # referenced ones to observed; it skips cheaply when browser_mode is off.
    requires = ("crawler", "javascript", "browser")
    description = "Consolidate API/GraphQL/WebSocket endpoints (observed/referenced/potential)."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        if target is None:
            result.error = "target unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        agg = EndpointAggregator(base_host=target.hostname)
        base = target.base_url

        self._from_crawler(ctx, agg, base)
        self._from_javascript(ctx, agg, base)
        self._from_sitemap(ctx, agg)
        self._from_browser(ctx, agg)

        endpoints = agg.endpoints()
        ctx.shared[API_INVENTORY_KEY] = endpoints
        await self._persist(ctx, endpoints)

        by_obs = {"observed": 0, "referenced": 0, "potential": 0}
        by_kind = {"rest": 0, "graphql": 0, "websocket": 0}
        for e in endpoints:
            by_obs[str(e.observation)] += 1
            by_kind[e.kind] = by_kind.get(e.kind, 0) + 1

        result.data = {
            "total": len(endpoints),
            "by_observation": by_obs,
            "by_kind": by_kind,
            "in_scope": sum(1 for e in endpoints if e.in_scope),
            "endpoints": [
                {
                    "url": e.url,
                    "kind": e.kind,
                    "observation": str(e.observation),
                    "in_scope": e.in_scope,
                    "sources": sorted(e.sources),
                    "methods": sorted(e.methods),
                }
                for e in endpoints
            ],
        }
        result.stats = by_obs
        self._sensitive_finding(result, endpoints)
        self._open_redirect_findings(ctx, result, endpoints, base)
        self._websocket_findings(ctx, result, target)
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("api discovery complete", **by_obs)
        return result

    def _from_crawler(self, ctx, agg: EndpointAggregator, base: str) -> None:
        inv = ctx.shared.get("inventory")
        if inv is None:
            return
        for page in inv.pages:
            ctype = (page.content_type or "").lower()
            # A non-HTML JSON/XML response we actually fetched is an observed API.
            if page.status_code and page.status_code < 400 and (
                "json" in ctype or ("xml" in ctype and "html" not in ctype)
            ):
                agg.add(page.url, Observation.OBSERVED, "crawler")
            for link in page.links:
                if looks_like_api(link):
                    agg.add(link, Observation.REFERENCED, "crawler")

    def _from_javascript(self, ctx, agg: EndpointAggregator, base: str) -> None:
        analyses = ctx.shared.get(JS_ANALYSIS_KEY) or []
        for a in analyses:
            for path in a.endpoints:
                agg.add(urljoin(base, path), Observation.REFERENCED, "javascript")
            for url in a.urls:
                if looks_like_api(url):
                    agg.add(url, Observation.REFERENCED, "javascript")
            for ws in a.websockets:
                agg.add(ws, Observation.REFERENCED, "javascript")

    def _from_sitemap(self, ctx, agg: EndpointAggregator) -> None:
        inv = ctx.shared.get("inventory")
        if inv is None:
            return
        for url in inv.sitemap_urls:
            if looks_like_api(url):
                agg.add(url, Observation.REFERENCED, "sitemap")

    def _from_browser(self, ctx, agg: EndpointAggregator) -> None:
        # Endpoints the headless browser actually requested are OBSERVED (§20).
        for ep in ctx.shared.get("browser_endpoints") or []:
            method = ep.get("method")
            agg.add(ep["url"], Observation.OBSERVED, "browser", method=method)

    def _sensitive_finding(self, result: ModuleResult, endpoints: list[Endpoint]) -> None:
        sensitive = [e for e in endpoints if e.sensitive and e.in_scope]
        if not sensitive:
            return
        result.findings.append(
            Finding(
                check_id="api.sensitive_endpoints.referenced",
                name="Sensitive-looking endpoints referenced",
                category=FindingCategory.EXPOSURE,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                # These are referenced (in HTML/JS), not confirmed to exist.
                observation=Observation.REFERENCED,
                module=self.name,
                description="Endpoints with admin/internal/debug/graphql markers are referenced.",
                impact="Such endpoints may expose privileged functionality if reachable.",
                recommendation=(
                    "Confirm authorization/authn on these endpoints; do not expose them publicly."
                ),
                evidence=[
                    Evidence(
                        source=self.name,
                        url=e.url,
                        description=f"Referenced {e.kind} endpoint",
                        data={"url": e.url, "observation": str(e.observation),
                              "sources": sorted(e.sources)},
                    )
                    for e in sensitive[:20]
                ],
            )
        )

    def _open_redirect_findings(
        self, ctx, result: ModuleResult, endpoints: list[Endpoint], base: str
    ) -> None:
        # Collect every URL we know about that could carry a query string.
        urls: list[str] = [e.url for e in endpoints]
        inv = ctx.shared.get("inventory")
        if inv is not None:
            for page in inv.pages:
                urls.append(page.url)
                urls.extend(page.links)
        for a in ctx.shared.get(JS_ANALYSIS_KEY) or []:
            urls.extend(getattr(a, "urls", []))
        hits = find_open_redirect_params(urls)
        if not hits:
            return
        result.findings.append(
            Finding(
                check_id="api.open_redirect.candidate",
                name="Open-redirect parameter candidate",
                category=FindingCategory.CONFIGURATION, severity=Severity.LOW,
                confidence=Confidence.LOW, observation=Observation.POTENTIAL,
                module=self.name,
                description=(
                    "URLs expose redirect-like parameters (redirect/url/next/...) "
                    "that, if unvalidated, enable open redirects."
                ),
                impact="Attackers can craft links that bounce users to malicious sites.",
                recommendation=(
                    "Validate redirect targets against an allowlist of internal paths; "
                    "never redirect to a raw user-supplied URL."
                ),
                evidence=[
                    Evidence(source=self.name, url=url,
                             description=f"redirect-like param {param!r}",
                             data={"url": url, "param": param})
                    for url, param in hits[:20]
                ],
            )
        )

    def _websocket_findings(self, ctx, result: ModuleResult, target) -> None:
        ws_urls: list[str] = []
        for a in ctx.shared.get(JS_ANALYSIS_KEY) or []:
            ws_urls.extend(getattr(a, "websockets", []))
        insecure = insecure_websockets(ws_urls, target.scheme == "https")
        if not insecure:
            return
        result.findings.append(
            Finding(
                check_id="websocket.insecure_transport",
                name="Insecure WebSocket (ws://) on an HTTPS page",
                category=FindingCategory.TRANSPORT, severity=Severity.MEDIUM,
                confidence=Confidence.HIGH, observation=Observation.OBSERVED,
                module=self.name,
                description=(
                    "An HTTPS page references a cleartext ws:// WebSocket endpoint."
                ),
                impact=(
                    "WebSocket traffic is unencrypted and can be read/modified on the "
                    "wire; it also enables mixed-content and CSWSH exposure."
                ),
                recommendation=(
                    "Use wss:// and validate the Origin header server-side on the "
                    "WebSocket handshake to prevent cross-site hijacking (CSWSH)."
                ),
                evidence=[
                    Evidence(source=self.name, url=url, description="cleartext ws:// endpoint",
                             data={"url": url})
                    for url in insecure[:20]
                ],
            )
        )

    async def _persist(self, ctx, endpoints: list[Endpoint]) -> None:
        storage = ctx.storage
        if storage is None:
            return
        await storage.save_endpoints(ctx.scan_id, endpoints)
