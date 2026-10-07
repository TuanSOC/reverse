"""The scan orchestrator (§29/§33).

Responsibilities:

* resolve the module dependency order from the registry;
* set up the shared engine stack (SSRF guard, rate limiter, HTTP engine);
* run each module in isolation — a per-module timeout plus a blanket
  ``except`` so one module's failure becomes a ``FAILED`` result, never an
  aborted scan;
* honor cooperative cancellation between (and inside) modules;
* report progress via a callback;
* persist results when a database is provided.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from ..core.config import ScanConfig
from ..core.context import CancellationToken, ScanContext
from ..core.enums import ModuleStatus
from ..core.errors import ScanCancelledError
from ..core.logging import get_logger
from ..core.models import ModuleResult
from ..core.registry import ScannerRegistry, default_registry
from ..engine.http_engine import HttpEngine
from ..engine.rate_limiter import RateLimiter
from ..engine.ssrf_guard import SsrfGuard
from ..storage.database import Database
from ..storage.repository import ScanRepository

# Default per-module execution budget when a module doesn't set its own.
DEFAULT_MODULE_TIMEOUT = 120.0

log = get_logger("pipeline")


@dataclass
class ScanProgress:
    module: str
    index: int
    total: int
    status: ModuleStatus


ProgressCallback = Callable[[ScanProgress], None]


class Pipeline:
    """Runs a full scan against a target URL."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        registry: ScannerRegistry = default_registry,
        db: Database | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.db = db
        self.progress = progress
        self.repo = ScanRepository(db) if db is not None else None

    async def run(
        self,
        input_url: str,
        *,
        selected: list[str] | None = None,
        scan_id: str | None = None,
        cancellation: CancellationToken | None = None,
    ) -> ScanContext:
        """Execute the scan and return the populated context."""
        ctx = ScanContext(config=self.config)
        if scan_id is not None:
            ctx.scan_id = scan_id
        if cancellation is not None:
            ctx.cancellation = cancellation
        ctx.shared["input_url"] = input_url
        selected = selected or (self.config.enabled_modules or None)
        order = self.registry.resolution_order(selected)
        total = len(order)
        log.info("scan starting", scan_id=ctx.scan_id, url=input_url, modules=order)
        ctx.event("scan", f"Scan started: {input_url}", {"url": input_url, "modules": order})

        guard = SsrfGuard(allow_private_targets=self.config.scope.allow_private_targets)
        rate = RateLimiter(self.config.rate)

        scan_persisted = False
        events_saved = 0  # timeline cursor: ctx.events[:events_saved] are persisted
        async with HttpEngine(self.config.http, rate, guard, scope=None) as http:
            ctx.http = http
            await self._auto_login(ctx, input_url)
            for index, name in enumerate(order):
                try:
                    ctx.cancellation.raise_if_cancelled()
                except ScanCancelledError:
                    self._emit(ScanProgress(name, index, total, ModuleStatus.CANCELLED))
                    log.warning("scan cancelled", scan_id=ctx.scan_id, at=name)
                    ctx.event("scan", f"Scan cancelled before {name}", {"at": name})
                    break

                ctx.current_module = name
                result = await self._run_module(ctx, name)
                ctx.results[name] = result
                self._record_module_events(ctx, result)
                ctx.current_module = None

                # Publish the scope engine into the HTTP engine once available,
                # so all subsequent requests are scope-gated.
                if ctx.scope is not None and http.scope is None:
                    http.scope = ctx.scope

                # Persist: create the scan row as soon as we have a valid target.
                # A storage error here must NOT abort the scan (§33) — log and
                # continue so remaining modules still run and finalize is reached.
                if self.repo is not None:
                    try:
                        if not scan_persisted and ctx.target is not None:
                            await self.repo.create_target_and_scan(
                                ctx.target, ctx.scan_id, self.config.model_dump(mode="json")
                            )
                            scan_persisted = True
                            # Expose the repository to modules for domain
                            # persistence now the scan row exists.
                            ctx.storage = self.repo
                        if scan_persisted:
                            await self.repo.save_module_result(ctx.scan_id, result)
                            pending = ctx.events[events_saved:]
                            await self.repo.save_events(ctx.scan_id, pending)
                            events_saved += len(pending)
                    except Exception as exc:  # noqa: BLE001 - persistence is best-effort
                        log.error("persistence failed", module=name, error=str(exc))

                self._emit(ScanProgress(name, index, total, result.status))

        overall = self._overall_status(ctx)
        ctx.event("scan", f"Scan finished: {overall}", {
            "status": overall, "findings": len(ctx.all_findings()),
            "events_dropped": ctx.events_dropped,
        })
        if self.repo is not None and scan_persisted:
            try:
                await self.repo.save_events(ctx.scan_id, ctx.events[events_saved:])
                await self.repo.finalize_scan(ctx.scan_id, overall)
            except Exception as exc:  # noqa: BLE001 - never fail the scan on finalize
                log.error("finalize failed", scan_id=ctx.scan_id, error=str(exc))
        log.info("scan finished", scan_id=ctx.scan_id, findings=len(ctx.all_findings()))
        return ctx

    async def _auto_login(self, ctx: ScanContext, input_url: str) -> None:
        """If credentials are configured, log in once and reuse the session.

        Captured cookies populate ``config.http.cookie`` (target-host scoped by
        the HTTP engine) so the crawler/active checks run authenticated. Any
        operator-supplied cookie is left untouched.
        """
        auth = self.config.auth
        if not auth.enabled or self.config.http.cookie:
            return
        from ..engine.auto_login import capture_session_cookies, host_of

        log.info("auto-login starting", login_url=auth.login_url)
        host = host_of(input_url) or host_of(auth.login_url or "")
        cookie = await capture_session_cookies(self.config, host, log)
        # Timeline data names the login URL only — never the cookie values.
        if cookie:
            self.config.http.cookie = cookie
            ctx.shared["authenticated"] = True
            log.info("auto-login session captured", cookie_count=cookie.count("="))
            ctx.event("auth", "Auto-login session captured",
                      {"login_url": auth.login_url, "authenticated": True})
        else:
            log.warning("auto-login did not capture a session; scanning unauthenticated")
            ctx.event("auth", "Auto-login failed; scanning unauthenticated",
                      {"login_url": auth.login_url, "authenticated": False})

    async def _run_module(self, ctx: ScanContext, name: str) -> ModuleResult:
        module_cls = self.registry.get(name)
        module = module_cls()
        timeout = module.timeout_seconds or DEFAULT_MODULE_TIMEOUT
        try:
            return await asyncio.wait_for(module.run(ctx), timeout=timeout)
        except TimeoutError:
            result = module.new_result()
            result.timed_out = True
            result.error = f"module timed out after {timeout}s"
            result.mark_finished(ModuleStatus.TIMEOUT)
            log.warning("module timeout", module=name, timeout=timeout)
            return result
        except ScanCancelledError:
            result = module.new_result()
            result.error = "cancelled"
            result.mark_finished(ModuleStatus.CANCELLED)
            return result
        except Exception as exc:  # noqa: BLE001 — isolation boundary (§33)
            result = module.new_result()
            result.error = f"{type(exc).__name__}: {exc}"
            result.mark_finished(ModuleStatus.FAILED)
            log.error("module crashed", module=name, error=str(exc))
            return result

    @staticmethod
    def _record_module_events(ctx: ScanContext, result: ModuleResult) -> None:
        """Timeline: one event per finding, then the module's completion."""
        for f in result.findings:
            ctx.event("finding", f.name, {
                "check_id": f.check_id, "severity": str(f.severity),
                "confidence": str(f.confidence), "observation": str(f.observation),
            })
        ctx.event("module", f"{result.module} {result.status}", {
            "status": str(result.status), "duration_ms": result.duration_ms,
            "findings": len(result.findings), "error": result.error,
        })

    def _emit(self, progress: ScanProgress) -> None:
        if self.progress is not None:
            try:
                self.progress(progress)
            except Exception:  # noqa: BLE001 — never let UI callbacks break a scan
                log.warning("progress callback raised", module=progress.module)

    @staticmethod
    def _overall_status(ctx: ScanContext) -> str:
        statuses = {r.status for r in ctx.results.values()}
        if ModuleStatus.CANCELLED in statuses:
            return "cancelled"
        if statuses <= {ModuleStatus.SUCCESS, ModuleStatus.SKIPPED}:
            return "success"
        if ModuleStatus.SUCCESS in statuses:
            return "partial"
        return "failed"
