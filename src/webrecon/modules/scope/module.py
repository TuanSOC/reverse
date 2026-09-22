"""Scope initialization (§4).

Builds the :class:`ScopeEngine` from the validated target + scope config and
attaches it to the context, so every later module and the HTTP engine share one
boundary. It also seeds the allowed-hosts list with the target host so the
operator can see the exact scope in the result.
"""

from __future__ import annotations

from ...core.enums import ModuleStatus
from ...core.models import Evidence, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ...engine.scope_engine import ScopeEngine


@default_registry.register
class ScopeModule(ScannerModule):
    name = "scope"
    version = "0.1.0"
    requires = ("target",)
    description = "Initialize the crawl/request scope boundary."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        if target is None:
            result.error = "target not available (target module failed)"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        engine = ScopeEngine(
            base_host=target.hostname,
            base_origin=target.origin,
            config=ctx.config.scope,
        )
        ctx.scope = engine

        scope_summary = {
            "mode": ctx.config.scope.mode.value,
            "base_host": target.hostname,
            "base_origin": target.origin,
            "allowed_hosts": ctx.config.scope.allowed_hosts,
            "disallowed_hosts": ctx.config.scope.disallowed_hosts,
            "include_paths": ctx.config.scope.include_paths,
            "exclude_paths": ctx.config.scope.exclude_paths,
            "max_depth": ctx.config.scope.max_depth,
            "max_pages": ctx.config.scope.max_pages,
            "max_requests": ctx.config.scope.max_requests,
            "allow_private_targets": ctx.config.scope.allow_private_targets,
        }
        result.data = scope_summary
        result.evidence.append(
            Evidence(
                source=self.name,
                url=target.base_url,
                description="Scope initialized",
                data=scope_summary,
            )
        )
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("scope initialized", mode=scope_summary["mode"], host=target.hostname)
        return result
