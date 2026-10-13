"""Passive subdomain discovery (§11-adjacent).

Aggregates subdomain hostnames the scan already observed (certificate SANs,
crawled links/assets, JavaScript URLs, discovered endpoints), then resolves each
via DNS to report which are live and flag referenced-but-unresolvable ones
(possible stale references / dangling). No brute-force enumeration; IP-literal
targets are skipped.
"""

from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver

from ...core.enums import (
    Confidence,
    FindingCategory,
    ModuleStatus,
    Observation,
    Severity,
)
from ...core.models import Evidence, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ..dns.analysis import resolve_state
from .collect import collect_subdomains


@default_registry.register
class SubdomainsModule(ScannerModule):
    name = "subdomains"
    version = "0.1.0"
    requires = ("target", "tls", "crawler", "javascript", "api")
    timeout_seconds = 45.0
    description = "Passive subdomain discovery from cert SAN / links / JS (+ resolve)."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        if target is None:
            result.error = "target unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result
        if _is_ip_literal(target.hostname):
            result.data = {"skipped": "IP-literal target"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        candidates = self._gather(ctx)
        subs = sorted(collect_subdomains(target.hostname, candidates))
        if not subs:
            result.data = {"discovered": 0}
            result.mark_finished(ModuleStatus.SUCCESS)
            return result

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6.0
        live: list[str] = []
        unresolved: list[str] = []  # NXDOMAIN only — timeouts are not "unresolved"
        sem = asyncio.Semaphore(10)  # sequential 6s lookups blew the module timeout

        async def _state(host: str) -> tuple[str, str]:
            async with sem:
                return host, await resolve_state(resolver, host)

        for host, state in await asyncio.gather(*(_state(h) for h in subs[:200])):
            if state == "resolves":
                live.append(host)
            elif state == "nxdomain":
                unresolved.append(host)

        ctx.shared["subdomains"] = {"live": live, "unresolved": unresolved}
        self._findings(result, target.hostname, live, unresolved)
        result.data = {"discovered": len(subs), "live": live, "unresolved": unresolved}
        result.stats = {"discovered": len(subs), "live": len(live)}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("subdomains", discovered=len(subs), live=len(live))
        return result

    def _gather(self, ctx) -> list[str]:
        out: list[str] = []
        tls = ctx.result_of("tls")
        if tls is not None:
            out.extend(tls.data.get("san", []) or [])
        inv = ctx.shared.get("inventory")
        if inv is not None:
            out.extend(p.url for p in inv.pages)
            out.extend(a.url for a in inv.assets)
            for p in inv.pages:
                out.extend(p.links)
        for a in ctx.shared.get("js_analysis", []) or []:
            out.extend(a.urls)
        for e in ctx.shared.get("api_endpoints", []) or []:
            out.append(e.url)
        return out

    async def _resolves(self, resolver, name: str) -> bool:
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                if await resolver.resolve(name, rtype):
                    return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except (dns.exception.DNSException, Exception):  # noqa: BLE001, S112 - try next rtype
                continue
        return False

    def _findings(self, result, base, live, unresolved) -> None:
        if live:
            result.findings.append(
                self._f(
                    "subdomains.discovered", f"{len(live)} subdomain(s) discovered",
                    Severity.INFORMATIONAL, Observation.OBSERVED,
                    "Subdomains of the target were found via cert SAN / links / JS.",
                    "Expands the attack surface to review.",
                    "Confirm each subdomain is intended to be public and is maintained.",
                    {"subdomains": live[:50]},
                )
            )
        if unresolved:
            result.findings.append(
                self._f(
                    "subdomains.unresolved",
                    f"{len(unresolved)} referenced subdomain(s) do not resolve",
                    Severity.LOW, Observation.POTENTIAL,
                    "Subdomains are referenced but currently do not resolve in DNS.",
                    "May indicate a stale reference or a dangling target open to takeover.",
                    "Verify each; remove stale references or reclaim the resource.",
                    {"subdomains": unresolved[:50]},
                )
            )

    def _f(self, cid, name, sev, obs, desc, impact, rec, data):
        from ...core.models import Finding

        return Finding(
            check_id=cid, name=name, category=FindingCategory.DNS, severity=sev,
            confidence=Confidence.MEDIUM, observation=obs, module=self.name,
            description=desc, impact=impact, recommendation=rec,
            evidence=[Evidence(source=self.name, url=None, description=name, data=data)],
        )


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
