"""Hardcoded secret / API-key leak module (v0.3.0).

Scans the retained JavaScript sources (``ctx.shared["js_analysis"]``) and the
primary HTML response for hardcoded credentials (AWS/Google/GitHub/Stripe/Slack/
private keys/JWTs). Findings always carry a *masked* value as evidence — the raw
secret is never stored or displayed. Passive: the crawler/js modules already
fetched this content; nothing is submitted or verified against a provider.
"""

from __future__ import annotations

from ...core.enums import (
    Confidence,
    FindingCategory,
    ModuleStatus,
    Observation,
)
from ...core.models import Evidence, Finding, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ..http.module import PRIMARY_RESPONSE_KEY
from ..javascript.module import JS_ANALYSIS_KEY
from .analysis import SecretHit, find_secrets


@default_registry.register
class SecretLeakModule(ScannerModule):
    name = "secret_leak"
    version = "0.1.0"
    requires = ("javascript", "crawler")
    description = "Detect hardcoded API keys/secrets in JS + HTML (masked evidence)."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        # (source-url, text) pairs to scan: each JS file + the primary HTML page.
        sources: list[tuple[str | None, str]] = []
        for a in ctx.shared.get(JS_ANALYSIS_KEY) or []:
            if getattr(a, "content", ""):
                sources.append((a.url, a.content))
        primary = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        if primary is not None and not primary.truncated:
            sources.append((primary.url, primary.text))

        if not sources:
            result.data = {"skipped": "no JS/HTML content to scan"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        by_kind: dict[str, int] = {}
        seen: set[tuple[str, str]] = set()  # dedup identical secret across files
        for url, text in sources:
            for hit in find_secrets(text):
                key = (hit.kind, hit.masked)
                if key in seen:
                    continue
                seen.add(key)
                by_kind[hit.kind] = by_kind.get(hit.kind, 0) + 1
                result.findings.append(self._finding(url, hit))

        result.data = {"sources_scanned": len(sources), "by_kind": by_kind}
        result.stats = {"secrets": sum(by_kind.values())}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("secret_leak complete", sources=len(sources), secrets=sum(by_kind.values()))
        return result

    def _finding(self, url: str | None, hit: SecretHit) -> Finding:
        return Finding(
            check_id=f"secret.{hit.kind}",
            name=f"Exposed {hit.label}",
            category=FindingCategory.EXPOSURE, severity=hit.severity,
            confidence=Confidence.HIGH, observation=Observation.OBSERVED,
            module=self.name,
            description=(
                f"A {hit.label} appears hardcoded in client-delivered source "
                f"({hit.masked})."
            ),
            impact=(
                "Anyone can read this secret from the public asset and may use it "
                "to access the associated account/service."
            ),
            recommendation=(
                "Revoke and rotate the credential immediately; move secrets to a "
                "server-side store and never ship them to the client."
            ),
            evidence=[Evidence(
                source=self.name, url=url,
                description=f"{hit.label} (masked)",
                data={"kind": hit.kind, "masked": hit.masked, "offset": hit.offset},
            )],
        )
