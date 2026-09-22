"""Safe active API/DB assessment module (§21) — opt-in, detection-level only.

Runs only when ``config.active`` is set. Probes ONLY observed, in-scope, REST
endpoints that are not action-verbs, through a GET-only :class:`SafeGetEngine`,
under a hard request budget. Emits detection-level findings (DB error leakage,
sensitive-data exposure, broken-auth) with evidence — never exploitation. SQLi
susceptibility (Phase 2) and GraphQL introspection (Phase 3) extend this loop.
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
from . import signatures as sig
from .safe_engine import SafeGetEngine

MAX_REQUESTS = 200
MAX_PROBES_PER_ENDPOINT = 6


@default_registry.register
class ApiTestModule(ScannerModule):
    name = "apitest"
    version = "0.1.0"
    requires = ("api",)
    timeout_seconds = 90.0
    description = "Opt-in active API/DB assessment (GET-only, detection-level)."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        if not ctx.config.active:
            result.data = {"skipped": "active testing disabled (use --active)"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result
        endpoints = ctx.shared.get("api_endpoints") or []
        if ctx.http is None or not endpoints:
            result.data = {"skipped": "no http engine or endpoints"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        engine = SafeGetEngine(ctx.http)
        worklist = self._worklist(endpoints)
        self._budget = 0
        tested = 0

        for ep in worklist:
            if self._budget >= MAX_REQUESTS:
                result.data = result.data or {}
                result.data["budget_exhausted"] = True
                break
            probes = 0
            resp = await self._get(engine, ep.url)
            probes += 1
            if resp is None:
                continue
            tested += 1
            db_error = self._check_db_error(result, ep, resp)
            exposed = self._check_data_exposure(result, ep, resp, db_error)
            self._check_unauth(result, ep, resp, exposed)
            # Phase 2 hook: SQLi susceptibility uses the remaining probe budget.
            await self._check_sqli(engine, result, ep, resp, probes)

        result.data = {
            "active": True,
            "endpoints_tested": tested,
            "requests": self._budget,
            "findings": [f.check_id for f in result.findings],
            **(result.data or {}),
        }
        result.stats = {"endpoints_tested": tested, "requests": self._budget}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("apitest complete", tested=tested, requests=self._budget)
        return result

    # -- worklist ----------------------------------------------------------

    def _worklist(self, endpoints) -> list:
        out = []
        for e in endpoints:
            if str(getattr(e, "observation", "")) != str(Observation.OBSERVED):
                continue
            if not getattr(e, "in_scope", False) or getattr(e, "kind", "rest") != "rest":
                continue
            if sig.is_action_verb(e.url):
                continue
            out.append(e)
        return out

    async def _get(self, engine, url):
        if self._budget >= MAX_REQUESTS:
            return None
        try:
            resp = await engine.get(url)
            self._budget += 1
            return resp
        except Exception:  # noqa: BLE001 - a failed probe is a non-finding
            return None

    # -- checks ------------------------------------------------------------

    def _check_db_error(self, result, ep, resp) -> bool:
        if not sig.has_db_error(resp.text):
            return False
        result.findings.append(self._f(
            "apitest.db_error", "Database error leaked in API response",
            FindingCategory.EXPOSURE, Severity.MEDIUM, Confidence.HIGH,
            Observation.OBSERVED, ep.url,
            "The endpoint returned a database error message.",
            "Leaks DBMS type, query fragments, and schema hints.",
            "Return generic errors; disable verbose DB errors in production.",
            {"url": ep.url},
        ))
        return True

    def _check_data_exposure(self, result, ep, resp, db_error) -> bool:
        # Precedence: a DB-error body is reported as db_error only.
        if db_error:
            return False
        hits = sig.find_sensitive_data(resp.text)
        if not hits:
            return False
        secret_kind = any(not h["kind"].startswith("key:") for h in hits)
        result.findings.append(self._f(
            "apitest.data_exposure", "Sensitive data in API response",
            FindingCategory.EXPOSURE,
            Severity.HIGH if secret_kind else Severity.MEDIUM, Confidence.MEDIUM,
            Observation.OBSERVED, ep.url,
            "The API response contains secret/PII-looking fields or values.",
            "May expose credentials or personal data to unauthorized callers.",
            "Remove sensitive fields from responses; enforce authz + field filtering.",
            {"url": ep.url, "hits": hits[:20]},
        ))
        return True

    def _check_unauth(self, result, ep, resp, exposed) -> None:
        if resp.status_code >= 400:
            return
        if not sig.looks_substantive_json(resp.text, resp.content_type):
            return
        # Corroboration: only flag when data is exposed OR the path is sensitive.
        if not (exposed or sig.is_sensitive_path(ep.url)):
            return
        result.findings.append(self._f(
            "apitest.auth.unauth_access", "Possible unauthenticated data access",
            FindingCategory.CONFIGURATION, Severity.MEDIUM, Confidence.MEDIUM,
            Observation.POTENTIAL, ep.url,
            "A sensitive/data-bearing endpoint returned data without credentials.",
            "If this data should be protected, it is accessible without auth.",
            "Verify whether this endpoint must require authentication/authorization.",
            {"url": ep.url, "status": resp.status_code},
        ))

    async def _check_sqli(self, engine, result, ep, baseline, probes_used) -> None:
        """Phase 2 extends this; no-op in Phase 1."""
        return

    # -- helpers -----------------------------------------------------------

    def _f(self, cid, name, cat, sev, conf, obs, url, desc, impact, rec, data):
        return Finding(
            check_id=cid, name=name, category=cat, severity=sev, confidence=conf,
            observation=obs, module=self.name, description=desc, impact=impact,
            recommendation=rec,
            evidence=[Evidence(source=self.name, url=url, description=name, data=data)],
        )
