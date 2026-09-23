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
from . import differential as diff
from . import probes
from . import signatures as sig
from .safe_engine import SafeGetEngine

MAX_REQUESTS = 200
MAX_PROBES_PER_ENDPOINT = 9
MAX_DIFF_PROBES = 3  # structured input-validation probes per endpoint


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
            probes_used = 1  # the baseline GET below counts as the first probe
            resp = await self._get(engine, ep.url)
            if resp is None:
                continue
            tested += 1
            db_error = self._check_db_error(result, ep, resp)
            exposed = self._check_data_exposure(result, ep, resp, db_error)
            self._check_unauth(result, ep, resp, exposed)
            # Differential input-validation testing (structured inputs).
            probes_used = await self._check_input_validation(engine, result, ep, resp, probes_used)
            # Phase 2 hook: SQLi susceptibility uses the remaining probe budget.
            await self._check_sqli(engine, result, ep, resp, probes_used)

        # GraphQL introspection (read-only, GET) on graphql endpoints.
        await self._check_graphql(engine, result, endpoints)

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

    def _eligible(self, ep, kind: str) -> bool:
        """Shared probe gate: observed + in-scope + matching kind, and (for REST)
        not an action-verb endpoint. Used by both the REST loop and GraphQL pass."""
        if str(getattr(ep, "observation", "")) != str(Observation.OBSERVED):
            return False
        if not getattr(ep, "in_scope", False) or getattr(ep, "kind", "rest") != kind:
            return False
        if kind == "rest" and sig.is_action_verb(ep.url):
            return False
        return True

    def _worklist(self, endpoints) -> list:
        return [e for e in endpoints if self._eligible(e, "rest")]

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

    async def _check_input_validation(self, engine, result, ep, baseline, probes_used) -> int:
        """Send structured inputs and flag non-DB divergences (weak validation)."""
        params = sorted(getattr(ep, "params", set()))
        if not params:
            return probes_used
        param = params[0]  # one representative param keeps the request budget sane
        base = diff.ProbeResult(
            "baseline", baseline.status_code, baseline.elapsed_ms,
            len(baseline.body), sig.has_db_error(baseline.text),
        )
        results: list[diff.ProbeResult] = []
        for label, value in diff.DIFFERENTIAL_INPUTS[:MAX_DIFF_PROBES]:
            if probes_used + 1 > MAX_PROBES_PER_ENDPOINT or self._budget + 1 > MAX_REQUESTS:
                break
            resp = await self._get(engine, diff.build_probe_url(ep.url, param, value))
            probes_used += 1
            if resp is None:
                continue
            results.append(diff.ProbeResult(
                label, resp.status_code, resp.elapsed_ms, len(resp.body),
                sig.has_db_error(resp.text),
            ))
        anomalies = diff.analyze_differential(base, results)
        if anomalies:
            result.findings.append(self._f(
                "apitest.input_validation.weak",
                f"Weak input validation ({param})",
                FindingCategory.CONFIGURATION, Severity.LOW, Confidence.MEDIUM,
                Observation.POTENTIAL, ep.url,
                f"Structured inputs on '{param}' produced divergent responses "
                "(status/size/timing) versus the baseline, without a DB error — "
                "the endpoint does not appear to validate input types/bounds.",
                "Unvalidated input can cause errors, resource abuse, or feed other bugs.",
                "Validate type, length, and range server-side; reject malformed input "
                "with a consistent 400. Example (Python/pydantic): "
                "`class Q(BaseModel): id: int = Field(ge=1, le=10_000)`.",
                {"url": ep.url, "param": param, "anomalies": anomalies[:10]},
            ))
        return probes_used

    async def _check_sqli(self, engine, result, ep, baseline, probes_used) -> None:
        """Error-based SQLi susceptibility on captured query params (P2).

        For up to 3 params (staying within the per-endpoint probe budget), send
        `param='` then `param=''` and flag susceptibility only when the
        unbalanced quote triggers a DB error the balanced/baseline do not.
        """
        params = sorted(getattr(ep, "params", set()))
        if not params:
            return
        baseline_hit = sig.has_db_error(baseline.text)
        for param in params[:3]:
            if probes_used + 2 > MAX_PROBES_PER_ENDPOINT or self._budget + 2 > MAX_REQUESTS:
                return
            single_url, balanced_url = probes.quote_variants(ep.url, param)
            single = await self._get(engine, single_url)
            balanced = await self._get(engine, balanced_url)
            probes_used += 2
            if single is None or balanced is None:
                continue
            single_hit = sig.has_db_error(single.text)
            balanced_hit = sig.has_db_error(balanced.text)
            if probes.error_based_signal(baseline_hit, single_hit, balanced_hit):
                result.findings.append(self._f(
                    "apitest.sqli.susceptible",
                    f"Possible SQL injection ({param})",
                    FindingCategory.EXPOSURE, Severity.HIGH, Confidence.MEDIUM,
                    Observation.POTENTIAL, ep.url,
                    f"An unbalanced quote in '{param}' triggered a DB error that a "
                    "balanced quote did not — an error-based SQLi indicator.",
                    "If injectable, an attacker may read/alter database data. NOT confirmed.",
                    "Use parameterized queries / ORM bindings — never string-concat "
                    "SQL. Example (Python): "
                    "`cur.execute('SELECT * FROM t WHERE id=%s', (id,))`; verify manually.",
                    {"url": ep.url, "param": param, "signal": "error_based"},
                ))
                return  # one finding per endpoint is enough

    async def _check_graphql(self, engine, result, endpoints) -> None:
        from urllib.parse import quote

        for ep in endpoints:
            if not self._eligible(ep, "graphql"):
                continue
            url = f"{ep.url}?query={quote(sig.INTROSPECTION_QUERY)}"
            resp = await self._get(engine, url)
            if resp is None or resp.status_code >= 400:
                continue  # GET-only GraphQL rejected → skip gracefully
            if sig.is_introspection_result(resp.text):
                result.findings.append(self._f(
                    "apitest.graphql.introspection", "GraphQL introspection enabled",
                    FindingCategory.EXPOSURE, Severity.MEDIUM, Confidence.HIGH,
                    Observation.OBSERVED, ep.url,
                    "The GraphQL endpoint answers introspection queries.",
                    "Exposes the full schema (types/fields), aiding attackers.",
                    "Disable introspection in production or restrict it.",
                    {"url": ep.url},
                ))

    # -- helpers -----------------------------------------------------------

    def _f(self, cid, name, cat, sev, conf, obs, url, desc, impact, rec, data):
        return Finding(
            check_id=cid, name=name, category=cat, severity=sev, confidence=conf,
            observation=obs, module=self.name, description=desc, impact=impact,
            recommendation=rec,
            evidence=[Evidence(source=self.name, url=url, description=name, data=data)],
        )
