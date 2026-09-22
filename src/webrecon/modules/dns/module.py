"""DNS intelligence module (§11).

Resolves the common record types, derives SPF/DMARC/CAA posture, and flags
*potential* dangling CNAMEs (a CNAME whose target does not resolve). It never
attempts a takeover — dangling records are surfaced as evidence only (§11).

IP-literal targets (e.g. a loopback lab host) are skipped: there is no domain to
query. All lookups are read-only DNS queries.
"""

from __future__ import annotations

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
from ...core.models import Evidence, Finding, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from .analysis import DnsData, extract_dmarc, extract_spf, spf_is_permissive

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


@default_registry.register
class DnsModule(ScannerModule):
    name = "dns"
    version = "0.1.0"
    requires = ("target",)
    timeout_seconds = 30.0
    description = "Resolve DNS records; SPF/DMARC/CAA posture; dangling-CNAME flags."

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
            result.data = {"skipped": "target is an IP literal (no domain to query)"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 8.0
        data = DnsData()
        host = target.hostname

        for rtype in _RECORD_TYPES:
            values = await self._query(resolver, host, rtype)
            if values:
                data.records[rtype] = values

        data.spf = extract_spf(data.records.get("TXT", []))
        data.caa = data.records.get("CAA", [])
        data.dmarc = extract_dmarc(await self._query(resolver, f"_dmarc.{host}", "TXT"))

        # Dangling CNAME: a CNAME target that fails to resolve.
        for cname in data.records.get("CNAME", []):
            tgt = cname.rstrip(".")
            if tgt and not await self._resolves(resolver, tgt):
                data.dangling_cnames.append(tgt)

        await self._persist(ctx, data)
        self._build_findings(result, host, data)

        result.data = {
            "records": data.records,
            "spf": data.spf,
            "dmarc": data.dmarc,
            "caa": data.caa,
            "dangling_cnames": data.dangling_cnames,
        }
        result.stats = {rtype: len(v) for rtype, v in data.records.items()}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("dns resolved", types=list(data.records), dangling=len(data.dangling_cnames))
        return result

    async def _query(self, resolver, name: str, rtype: str) -> list[str]:
        try:
            answer = await resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except (dns.exception.DNSException, Exception):  # noqa: BLE001 - never crash the scan
            return []
        return [r.to_text() for r in answer]

    async def _resolves(self, resolver, name: str) -> bool:
        for rtype in ("A", "AAAA", "CNAME"):
            if await self._query(resolver, name, rtype):
                return True
        return False

    def _build_findings(self, result: ModuleResult, host: str, data: DnsData) -> None:
        def ev(desc: str, d: dict) -> Evidence:
            return Evidence(source=self.name, url=None, description=desc, data=d)

        if data.records.get("MX") and not data.spf:
            result.findings.append(
                Finding(
                    check_id="dns.spf.missing", name="No SPF record",
                    category=FindingCategory.DNS, severity=Severity.LOW,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description="The domain has MX records but no SPF (v=spf1) TXT record.",
                    impact="Makes email spoofing of this domain easier.",
                    recommendation="Publish an SPF record listing authorized mail senders.",
                    evidence=[ev("No v=spf1 TXT found", {"mx": data.records.get("MX")})],
                )
            )
        elif data.spf and spf_is_permissive(data.spf):
            result.findings.append(
                Finding(
                    check_id="dns.spf.permissive", name="Permissive SPF (+all)",
                    category=FindingCategory.DNS, severity=Severity.LOW,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description="The SPF record ends in +all/all, allowing any sender.",
                    impact="Effectively disables SPF protection.",
                    recommendation="Use -all (hard fail) or ~all (soft fail).",
                    evidence=[ev("Permissive SPF", {"spf": data.spf})],
                )
            )
        if data.records.get("MX") and not data.dmarc:
            result.findings.append(
                Finding(
                    check_id="dns.dmarc.missing", name="No DMARC record",
                    category=FindingCategory.DNS, severity=Severity.LOW,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description="No DMARC (v=DMARC1) TXT record at _dmarc.<domain>.",
                    impact="No policy for handling spoofed mail; weakens anti-phishing.",
                    recommendation="Publish a DMARC record (start with p=none for monitoring).",
                    evidence=[ev("No _dmarc TXT", {"host": host})],
                )
            )
        for tgt in data.dangling_cnames:
            result.findings.append(
                Finding(
                    check_id="dns.cname.dangling", name="Potential dangling CNAME",
                    category=FindingCategory.DNS, severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM, observation=Observation.POTENTIAL,
                    module=self.name,
                    description=f"CNAME points to {tgt}, which does not resolve.",
                    impact=(
                        "If the target is an unclaimed service, it may be vulnerable to takeover."
                    ),
                    recommendation=(
                        "Remove the CNAME or reclaim the referenced resource. Verify manually."
                    ),
                    evidence=[ev("Unresolvable CNAME target", {"target": tgt})],
                )
            )

    async def _persist(self, ctx, data: DnsData) -> None:
        storage = ctx.storage
        if storage is None:
            return
        await storage.save_dns_records(ctx.scan_id, ctx.target.hostname, data.records)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
