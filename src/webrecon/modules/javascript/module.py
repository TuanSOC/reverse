"""JavaScript analysis module (§8/§9).

Downloads in-scope public JavaScript discovered by the crawler, statically
analyzes each file for endpoint/route/websocket/GraphQL strings, analytics and
cloud references, framework clues, and high-signal secret patterns, and checks
for exposed source maps. Extracted endpoints are published for the API-discovery
module (P7) classified as ``referenced`` — never asserted to exist.

Nothing downloaded is executed; JS is treated as inert text (threat T5).
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
from .analysis import JsAnalysis, analyze_js
from .sourcemap import parse_source_map

# High-severity secret kinds (credential material vs. lower-signal tokens).
_HIGH_SECRETS = {"aws_access_key_id", "private_key", "stripe_live_key", "github_pat"}

# Key under which JS analyses are published for the API-discovery module.
JS_ANALYSIS_KEY = "js_analysis"


@default_registry.register
class JavaScriptModule(ScannerModule):
    name = "javascript"
    version = "0.1.0"
    requires = ("crawler",)
    timeout_seconds = 120.0
    description = "Download + statically analyze in-scope JS; detect exposed source maps."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        inv = ctx.shared.get("inventory")
        if inv is None or ctx.http is None or ctx.scope is None:
            result.error = "crawler inventory / http unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        cfg = ctx.config.js
        script_urls = _unique(
            a.url for a in inv.assets if str(a.asset_type) == "script"
        )
        in_scope = [u for u in script_urls if ctx.scope.is_allowed(u)]
        selected = in_scope[: cfg.max_files]

        analyses: list[JsAnalysis] = []
        requests = 0
        for url in selected:
            try:
                ctx.cancellation.raise_if_cancelled()
            except Exception:  # noqa: BLE001
                break
            try:
                resp = await ctx.http.get(url)
                requests += 1
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the rest
                log.debug("js fetch failed", url=url, error=str(exc))
                continue
            if resp.status_code >= 400:
                continue
            analysis = analyze_js(url, resp.text, truncated=resp.truncated)
            # AST-based endpoint extraction (method + normalized path + line/col);
            # enriches the regex endpoints, degrades to [] if Node/acorn absent.
            from .ast_js import extract_calls
            analysis.ast_calls = [c.__dict__ for c in await extract_calls(resp.text)]
            analyses.append(analysis)

            disc = ctx.shared.get("disclosures")
            if disc is not None:
                from ..disclosure import scan_disclosures

                disc.merge(scan_disclosures(resp.text))

            if cfg.scan_secrets:
                self._secret_findings(result, analysis)
            if cfg.fetch_source_maps:
                requests += await self._check_source_map(ctx, result, url, analysis, log)

        ctx.shared[JS_ANALYSIS_KEY] = analyses

        result.data = {
            "files_analyzed": len(analyses),
            "in_scope_scripts": len(in_scope),
            "requests": requests,
            "total_endpoints": sum(len(a.endpoints) for a in analyses),
            "total_websockets": sum(len(a.websockets) for a in analyses),
            "graphql_referenced": any(a.graphql for a in analyses),
            "analytics_ids": _unique(i for a in analyses for i in a.analytics_ids),
            "cloud_refs": _unique(c for a in analyses for c in a.cloud_refs),
            "files": [
                {
                    "url": a.url,
                    "size": a.size,
                    "sha256": a.sha256,
                    "endpoints": len(a.endpoints),
                    "secrets": len(a.secrets),
                    "sourcemap": a.sourcemap_url,
                    "frameworks": a.framework_clues,
                }
                for a in analyses
            ],
        }
        result.stats = {"files": len(analyses), "requests": requests}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("js analyzed", files=len(analyses), endpoints=result.data["total_endpoints"])
        return result

    def _secret_findings(self, result: ModuleResult, analysis: JsAnalysis) -> None:
        for hit in analysis.secrets:
            high = hit.kind in _HIGH_SECRETS
            result.findings.append(
                Finding(
                    check_id=f"exposure.secret.{hit.kind}",
                    name=f"Possible {hit.kind.replace('_', ' ')} in JavaScript",
                    category=FindingCategory.EXPOSURE,
                    severity=Severity.HIGH if high else Severity.MEDIUM,
                    # Static string matches can be false positives (examples,
                    # placeholders) — never claim certainty.
                    confidence=Confidence.MEDIUM if high else Confidence.LOW,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description=f"A string matching {hit.kind} was found in public JavaScript.",
                    impact="If it is a real credential, it is exposed to anyone loading the site.",
                    recommendation=(
                        "Verify; if real, rotate the credential and remove it from client code."
                    ),
                    evidence=[
                        Evidence(
                            source=self.name,
                            url=analysis.url,
                            description="Masked secret match",
                            data={"kind": hit.kind, "match": hit.masked},
                        )
                    ],
                )
            )

    async def _check_source_map(self, ctx, result, js_url, analysis, log) -> int:
        """Follow an explicit sourceMappingURL, else probe <js>.map. Returns
        the number of extra requests made."""
        candidates = []
        if analysis.sourcemap_url and not analysis.sourcemap_url.startswith("data:"):
            candidates.append(urljoin(js_url, analysis.sourcemap_url))
        else:
            candidates.append(js_url + ".map")

        requests = 0
        for map_url in candidates:
            if not ctx.scope.is_allowed(map_url):
                continue
            try:
                resp = await ctx.http.get(map_url)
                requests += 1
            except Exception as exc:  # noqa: BLE001
                log.debug("sourcemap fetch failed", url=map_url, error=str(exc))
                continue
            if resp.status_code >= 400:
                continue
            info = parse_source_map(resp.text)
            if info is None:
                continue
            result.findings.append(
                Finding(
                    check_id="exposure.sourcemap.exposed",
                    name="Exposed JavaScript source map",
                    category=FindingCategory.EXPOSURE,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description=(
                        "A publicly reachable .map file reveals original source structure."
                    ),
                    impact=(
                        "Exposes original source paths and possibly full source, aiding analysis."
                    ),
                    recommendation="Do not deploy source maps publicly, or restrict access.",
                    evidence=[
                        Evidence(
                            source=self.name,
                            url=map_url,
                            description="Source map metadata",
                            data={
                                "sources_count": info.sources_count,
                                "source_root": info.source_root,
                                "has_sources_content": info.has_sources_content,
                                "sample_paths": info.source_paths[:10],
                            },
                        )
                    ],
                )
            )
            # Deep parse: reconstruct embedded original sources and scan them.
            if info.has_sources_content:
                await self._analyze_reconstructed(result, map_url, resp.text, analysis, log)
            break  # one map per JS file is enough
        return requests

    async def _analyze_reconstructed(self, result, map_url, map_text, analysis, log) -> None:
        """Reconstruct original sources from a .map and mine them for intel."""
        from ..secret_leak.analysis import find_secrets
        from .ast_js import extract_calls
        from .sourcemap import reconstruct_sources

        files = reconstruct_sources(map_text)
        if not files:
            return
        masked_secrets: list[dict] = []
        endpoints: list[dict] = []
        for path, content in files:
            for hit in find_secrets(content):  # already masked
                masked_secrets.append({"file": path, "kind": hit.kind, "match": hit.masked})
            for call in await extract_calls(content):
                endpoints.append({"file": path, "method": call.method, "url": call.url})
        # Feed reconstructed endpoints into the shared JS analysis for the api module.
        analysis.ast_calls = (analysis.ast_calls or []) + [
            {"kind": "sourcemap", "method": e["method"], "url": e["url"],
             "line": 0, "col": 0, "confidence": 0.75}
            for e in endpoints
        ]
        result.findings.append(
            Finding(
                check_id="exposure.sourcemap.reconstructed",
                name="Original source reconstructed from source map",
                category=FindingCategory.EXPOSURE, severity=Severity.MEDIUM,
                confidence=Confidence.HIGH, observation=Observation.OBSERVED,
                module=self.name,
                description=(
                    f"The source map embeds sourcesContent: {len(files)} original "
                    f"file(s) were reconstructed, yielding {len(endpoints)} endpoint "
                    f"reference(s) and {len(masked_secrets)} secret-like value(s)."
                ),
                impact=(
                    "Full pre-minified source (logic, routes, comments, and any "
                    "hardcoded secrets) is recoverable by anyone."
                ),
                recommendation=(
                    "Strip sourcesContent from production maps or do not deploy maps "
                    "publicly. Rotate any exposed secret."
                ),
                evidence=[Evidence(
                    source=self.name, url=map_url,
                    description="Reconstructed source analysis (secrets masked)",
                    data={"files": [f for f, _ in files][:20],
                          "secrets": masked_secrets[:20],
                          "endpoints": endpoints[:30]},
                )],
            )
        )
        log.info("sourcemap reconstructed", files=len(files),
                 endpoints=len(endpoints), secrets=len(masked_secrets))


def _unique(items) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it, None)
    return list(seen)
