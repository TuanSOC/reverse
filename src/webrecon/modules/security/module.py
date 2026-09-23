"""Security check engine (§21/§23).

Runs last. It contributes cross-module findings (mixed content, outdated
technology, directory listing) and then classifies the *entire* scan's findings
into a deterministic risk summary published for the report and dashboard. It does
not re-emit other modules' findings; it reads them from the context.
"""

from __future__ import annotations

from ...core.enums import ModuleStatus
from ...core.models import Evidence, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ..http.module import PRIMARY_RESPONSE_KEY
from . import rules
from .risk import classify

# Modules whose findings/signals this engine correlates. They must have run
# first (even if some SKIP) so the risk summary covers the whole scan.
_UPSTREAM = (
    "headers", "cookies", "cors", "tls", "dns", "technology", "javascript",
    "api", "exposure", "subdomains", "apitest", "dom_security", "forms_auth",
    "ip_intel", "secret_leak", "active_verify",
)

RISK_SUMMARY_KEY = "risk_summary"


@default_registry.register
class SecurityModule(ScannerModule):
    name = "security"
    version = "0.1.0"
    requires = _UPSTREAM
    description = "Cross-module security rules + overall risk classification."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        # 1) Cross-module rule findings.
        result.findings.extend(self._cross_module_findings(ctx))

        # 2) Classify the whole scan (all modules' findings + ours).
        all_findings = ctx.all_findings() + result.findings
        summary = classify(all_findings)
        ctx.shared[RISK_SUMMARY_KEY] = summary

        result.data = {
            "risk_level": summary.level,
            "decisive_severity": summary.decisive_severity,
            "total_findings": summary.total,
            "by_severity": summary.by_severity,
            "by_confidence": summary.by_confidence,
            "by_category": summary.by_category,
            "cross_module_findings": [f.check_id for f in result.findings],
        }
        result.stats = {"risk_level": summary.level, "total_findings": summary.total}
        result.evidence.append(
            Evidence(
                source=self.name,
                url=ctx.target.base_url if ctx.target else None,
                description=f"Risk classified as {summary.level}",
                data=result.data,
            )
        )
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("risk classified", level=summary.level, findings=summary.total)
        return result

    def _cross_module_findings(self, ctx) -> list:
        findings = []
        resp = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        inv = ctx.shared.get("inventory")

        # Mixed content: needs the final page scheme + asset URLs.
        if resp is not None and inv is not None:
            asset_urls = [a.url for a in inv.assets]
            findings.extend(rules.mixed_content(resp.url, asset_urls))

        # Outdated / known-vulnerable technology: from the technology detections.
        tech_result = ctx.result_of("technology")
        if tech_result is not None:
            detections = tech_result.data.get("technologies", [])
            findings.extend(rules.outdated_technology(detections))
            findings.extend(rules.known_vulnerable_libraries(detections))

        # Directory listing: from crawled page titles.
        if inv is not None:
            titles = [(p.url, p.title or "") for p in inv.pages]
            findings.extend(rules.directory_listing(titles))

        # Content disclosure: emails / internal IPs / stack traces collected by
        # the crawler + javascript modules.
        disc = ctx.shared.get("disclosures")
        if disc is not None:
            findings.extend(rules.content_disclosure(disc))

        return findings
