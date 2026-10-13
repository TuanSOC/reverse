"""Exposure module (§21) — misconfiguration detection, non-destructive.

Three checks, all GET/OPTIONS only:

1. **security.txt** (RFC 9116) — informational finding when absent.
2. **Risky HTTP methods** — an OPTIONS request; flags TRACE/PUT/DELETE/… if the
   ``Allow`` header advertises them.
3. **Sensitive-file exposure** (opt-in via ``config.probe``) — GETs a curated
   list of commonly-leaked files and flags one only when the response *content*
   matches that file's signature (so a generic 200 page isn't a false positive).

This is detection, not exploitation: it reports that a file is reachable; it
never downloads/exfiltrates repository contents or acts on them (§42).
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
from .probes import RISKY_METHODS, SENSITIVE_PROBES, looks_like_html


@default_registry.register
class ExposureModule(ScannerModule):
    name = "exposure"
    version = "0.1.0"
    requires = ("http",)
    timeout_seconds = 60.0
    description = "Well-known files, risky HTTP methods, opt-in sensitive-file probes."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        if target is None or ctx.http is None:
            result.error = "target/http unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        base = target.base_url.rstrip("/") + "/"
        stats = {"requests": 0}

        await self._check_security_txt(ctx, result, base, stats)
        await self._check_methods(ctx, result, target.base_url, stats)
        if ctx.config.probe:
            await self._probe_sensitive(ctx, result, base, stats, log)

        result.stats = stats
        result.data = {
            "probed": ctx.config.probe,
            "requests": stats["requests"],
            "exposures": [f.check_id for f in result.findings],
        }
        result.mark_finished(ModuleStatus.SUCCESS)
        return result

    async def _get(self, ctx, url, stats):
        try:
            resp = await ctx.http.get(url)
            stats["requests"] += 1
            return resp
        except Exception:  # noqa: BLE001 - a failed probe is a non-finding
            return None

    async def _check_security_txt(self, ctx, result, base, stats) -> None:
        for path in (".well-known/security.txt", "security.txt"):
            resp = await self._get(ctx, urljoin(base, path), stats)
            if resp and resp.status_code == 200 and "contact:" in resp.text.lower():
                return  # present — good, no finding
        result.findings.append(
            Finding(
                check_id="exposure.securitytxt.missing", name="No security.txt (RFC 9116)",
                category=FindingCategory.INFORMATIONAL, severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                description="No /.well-known/security.txt was found.",
                impact="Researchers have no documented channel to report vulnerabilities.",
                recommendation="Publish /.well-known/security.txt with a Contact field.",
                references=["https://www.rfc-editor.org/rfc/rfc9116"],
                evidence=[Evidence(
                    source=self.name, url=base, description="security.txt absent",
                    data={"paths_checked": [".well-known/security.txt", "security.txt"]})],
            )
        )

    async def _check_methods(self, ctx, result, base_url, stats) -> None:
        try:
            resp = await ctx.http.request("OPTIONS", base_url)
            stats["requests"] += 1
        except Exception:  # noqa: BLE001
            return
        allow = resp.headers.get("allow") or resp.headers.get("Allow") or ""
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & RISKY_METHODS)
        if risky:
            result.findings.append(
                Finding(
                    check_id="exposure.methods.risky",
                    name=f"Risky HTTP methods: {', '.join(risky)}",
                    category=FindingCategory.CONFIGURATION, severity=Severity.LOW,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description=f"Server advertises risky methods via Allow: {', '.join(risky)}.",
                    impact="TRACE enables XST; PUT/DELETE may allow tampering if unprotected.",
                    recommendation="Disable methods the app doesn't need (TRACE/TRACK/PUT/DELETE).",
                    evidence=[Evidence(
                        source=self.name, url=base_url, description="OPTIONS Allow header",
                        data={"allow": allow, "risky": risky})],
                )
            )

    async def _probe_sensitive(self, ctx, result, base, stats, log) -> None:
        for probe in SENSITIVE_PROBES:
            url = urljoin(base, probe.path)
            if ctx.scope is not None and not ctx.scope.is_allowed(url):
                continue
            resp = await self._get(ctx, url, stats)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text
            # Skip generic SPA/HTML pages unless the probe itself is HTML-ish.
            if looks_like_html(body) and probe.path not in ("phpinfo.php", "server-status"):
                continue
            if not probe.signature.search(body):
                continue
            info = probe.severity == Severity.INFORMATIONAL
            result.findings.append(
                Finding(
                    check_id=f"exposure.file.{probe.path.replace('/', '_').replace('.', '_')}",
                    name=probe.name, category=FindingCategory.EXPOSURE, severity=probe.severity,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description=("A well-known file is present." if info
                                 else f"A sensitive file is publicly reachable at {probe.path}."),
                    impact=("" if info
                            else "May leak source code, credentials, or internal configuration."),
                    recommendation=("" if info
                                    else f"Block public access to {probe.path}."),
                    evidence=[Evidence(
                        source=self.name, url=url, description="Reachable + signature match",
                        data={"path": probe.path, "status": resp.status_code})],
                )
            )
            log.info("exposure probe hit", path=probe.path)
