"""Target validation + normalization (§3).

First module in the pipeline. It parses and canonicalizes the input URL, runs it
through the SSRF guard (so an unsafe target is rejected before any other module
runs), and publishes a :class:`TargetInfo` onto the context for downstream use.
"""

from __future__ import annotations

from ...core.config import scrub_url
from ...core.enums import ModuleStatus
from ...core.errors import SsrfBlockedError
from ...core.models import Evidence, ModuleResult, TargetInfo
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ...core.urls import parse_url
from ...engine.ssrf_guard import SsrfGuard


@default_registry.register
class TargetModule(ScannerModule):
    name = "target"
    version = "0.1.0"
    requires = ()
    description = "Normalize and validate the input URL; SSRF pre-check."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        raw = ctx.shared.get("input_url")
        if not raw:
            result.error = "no input_url provided in context"
            result.mark_finished(ModuleStatus.FAILED)
            return result

        try:
            p = parse_url(raw)
        except ValueError as exc:
            result.error = f"invalid URL: {exc}"
            result.mark_finished(ModuleStatus.FAILED)
            return result

        guard = SsrfGuard(allow_private_targets=ctx.config.scope.allow_private_targets)
        try:
            resolved = await guard.check_url(raw)
        except SsrfBlockedError as exc:
            result.error = str(exc)
            result.evidence.append(
                Evidence(
                    source=self.name,
                    url=raw,
                    description="Target rejected by SSRF guard",
                    data={"reason": exc.reason},
                )
            )
            result.mark_finished(ModuleStatus.FAILED)
            log.warning("target blocked by ssrf guard", url=raw, reason=exc.reason)
            return result

        target = TargetInfo(
            input_url=scrub_url(raw),  # user:pass@ and query values never persisted
            scheme=p.scheme,
            hostname=p.hostname,
            port=p.port,
            base_url=p.base_url,
            origin=p.origin,
            path=p.path,
            query=p.query,
            fragment=p.fragment,
            resolved_ips=list(resolved.addresses),
        )
        ctx.target = target
        ctx.event("discovered", f"Target resolved: {target.base_url}", {
            "entity": "target", "url": target.base_url, "ips": target.resolved_ips,
        })
        result.data = target.model_dump(mode="json")
        result.evidence.append(
            Evidence(
                source=self.name,
                url=target.base_url,
                description="Normalized target",
                data={"origin": target.origin, "resolved_ips": target.resolved_ips},
            )
        )
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("target validated", base_url=target.base_url, ips=len(target.resolved_ips))
        return result
