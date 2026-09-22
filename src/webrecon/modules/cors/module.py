"""CORS analysis from observed response headers (§15).

Passive only: we assess the Access-Control-* headers present on the primary
response. We do **not** send crafted Origin headers to probe reflection — that
active test is deliberately out of scope for this passive module (documented
limitation); a wildcard-with-credentials combination is still detectable and
flagged here.
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


@default_registry.register
class CorsModule(ScannerModule):
    name = "cors"
    version = "0.1.0"
    requires = ("http",)
    description = "Flag risky CORS header combinations (passive)."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()

        resp = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        if resp is None:
            result.error = "no primary response"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        headers = {k.lower(): v for k, v in resp.headers.items()}
        acao = headers.get("access-control-allow-origin")
        acac = (headers.get("access-control-allow-credentials") or "").lower() == "true"
        result.data = {
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "access_control_allow_methods": headers.get("access-control-allow-methods"),
        }

        if acao is None:
            result.mark_finished(ModuleStatus.SUCCESS)
            return result

        ev = Evidence(
            source=self.name,
            url=resp.url,
            description="Observed CORS headers",
            data=result.data,
        )

        if acao == "*" and acac:
            # Browsers reject this combo, but its presence signals misconfig intent.
            result.findings.append(
                Finding(
                    check_id="cors.wildcard_with_credentials",
                    name="CORS allows any origin with credentials",
                    category=FindingCategory.CORS,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description="ACAO is '*' while ACA-Credentials is true.",
                    impact="If honored, any origin could read authenticated responses.",
                    recommendation=(
                        "Never combine wildcard origin with credentials; echo a vetted allow-list."
                    ),
                    evidence=[ev],
                )
            )
        elif acao == "*":
            result.findings.append(
                Finding(
                    check_id="cors.wildcard_origin",
                    name="CORS allows any origin",
                    category=FindingCategory.CORS,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description="Access-Control-Allow-Origin is '*'.",
                    impact="Any site can read non-credentialed responses from this endpoint.",
                    recommendation=(
                        "Restrict to specific trusted origins if responses are non-public."
                    ),
                    evidence=[ev],
                )
            )
        elif acao.lower() == "null":
            result.findings.append(
                Finding(
                    check_id="cors.null_origin",
                    name="CORS allows the 'null' origin",
                    category=FindingCategory.CORS,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    observation=Observation.OBSERVED,
                    module=self.name,
                    description="Access-Control-Allow-Origin is 'null'.",
                    impact="Sandboxed iframes and some attacker contexts present a null origin.",
                    recommendation="Do not allow the null origin; use an explicit allow-list.",
                    evidence=[ev],
                )
            )

        result.mark_finished(ModuleStatus.SUCCESS)
        return result
