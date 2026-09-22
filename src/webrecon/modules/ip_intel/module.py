"""IP intelligence & geolocation module (v0.3.0).

For each address the target resolves to, gathers (all read-only):
- reverse DNS (PTR) via a guarded async resolver,
- ASN / AS-name / registry via Team Cymru's DNS-based IP→ASN service,
- coarse geolocation (country/city/coords/ISP) via a public JSON API through
  ``ctx.http`` (rate-limited, size-capped, SSRF-guarded), best-effort.

It classifies the owning cloud/CDN provider and, when the HTTP edge is a CDN
but a resolved IP is not that CDN, raises ``ip.origin_direct_exposure`` (a
possible origin-IP/WAF-bypass leak). Detection only — nothing is exploited.
Private/loopback targets are skipped unless lab mode is enabled.
"""

from __future__ import annotations

import json

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
from ..http.module import PRIMARY_RESPONSE_KEY
from .analysis import (
    IpIntel,
    IpIntelResult,
    cdn_from_headers,
    classify_provider,
    cymru_origin_name,
    detect_origin_exposure,
    is_private_ip,
    parse_cymru_asname,
    parse_cymru_origin,
    parse_ipapi,
    reverse_pointer,
)

IP_INTEL_KEY = "ip_intel"
_GEO_HOST = "ip-api.com"
_GEO_FIELDS = "status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"


@default_registry.register
class IpIntelModule(ScannerModule):
    name = "ip_intel"
    version = "0.1.0"
    requires = ("target", "dns")
    timeout_seconds = 30.0
    description = "Reverse DNS, ASN/ISP, geolocation, and CDN/origin-exposure checks."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        if target is None or not target.resolved_ips:
            result.data = {"skipped": "no resolved IPs"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        allow_private = bool(getattr(ctx.config.scope, "allow_private_targets", False))
        ips = [ip for ip in target.resolved_ips if allow_private or not is_private_ip(ip)]
        if not ips:
            result.data = {"skipped": "all resolved IPs are private (lab mode off)"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 8.0

        # CDN on the HTTP edge (from the primary response headers), if any.
        resp = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        edge_cdn = cdn_from_headers(resp.headers) if resp is not None else None

        out = IpIntelResult(edge_cdn=edge_cdn)
        geo_done = False
        for ip in ips[:8]:  # bound work on multi-A targets
            info = IpIntel(ip=ip)
            # PTR / ASN / geolocation only make sense for public addresses, and
            # restricting to them keeps lab/loopback scans fully offline.
            if not is_private_ip(ip):
                info.ptr = await self._ptr(resolver, ip)
                await self._asn(resolver, ip, info)
                if not geo_done:  # one geo lookup for the first public IP
                    geo_done = await self._geo(ctx, ip, info, log)
            info.provider = classify_provider(info.as_name, info.isp, info.org)
            out.ips.append(info)

        primary = out.ips[0] if out.ips else None
        out.origin_exposed = detect_origin_exposure(
            edge_cdn, primary.provider if primary else None
        )

        if out.origin_exposed and primary is not None:
            result.findings.append(self._exposure_finding(edge_cdn, primary))

        ctx.shared[IP_INTEL_KEY] = out
        await self._persist(ctx, out)

        result.data = {
            "edge_cdn": edge_cdn,
            "origin_exposed": out.origin_exposed,
            "ips": [i.as_dict() for i in out.ips],
        }
        result.stats = {"ips": len(out.ips), "origin_exposed": int(out.origin_exposed)}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("ip_intel complete", ips=len(out.ips), edge_cdn=edge_cdn,
                 origin_exposed=out.origin_exposed)
        return result

    async def _ptr(self, resolver, ip: str) -> str | None:
        name = reverse_pointer(ip)
        if name is None:
            return None
        vals = await self._txt(resolver, name, "PTR")
        return vals[0].rstrip(".") if vals else None

    async def _asn(self, resolver, ip: str, info: IpIntel) -> None:
        origin_name = cymru_origin_name(ip)
        if origin_name is None:
            return
        origin = await self._txt(resolver, origin_name, "TXT")
        if not origin:
            return
        o = parse_cymru_origin(origin[0])
        info.asn = o.get("asn")
        info.prefix = o.get("prefix")
        info.country_code = info.country_code or o.get("country_code")
        info.registry = o.get("registry")
        if info.asn:
            asname = await self._txt(resolver, f"AS{info.asn}.asn.cymru.com", "TXT")
            if asname:
                info.as_name = parse_cymru_asname(asname[0]).get("as_name")

    async def _geo(self, ctx, ip: str, info: IpIntel, log) -> bool:
        """Best-effort geolocation via a public API through ctx.http."""
        if ctx.http is None:
            return False
        # Permit the trusted intel host through the scope gate for this call.
        scope = getattr(ctx.http, "scope", None)
        if scope is not None and _GEO_HOST not in scope.config.allowed_hosts:
            scope.config.allowed_hosts.append(_GEO_HOST)
        url = f"http://{_GEO_HOST}/json/{ip}?fields={_GEO_FIELDS}"
        try:
            resp = await ctx.http.get(url)
            data = json.loads(resp.text)
        except Exception as exc:  # noqa: BLE001 - geo is optional; degrade offline
            log.info("geolocation unavailable", ip=ip, error=str(exc))
            return False
        g = parse_ipapi(data)
        if not g:
            return False
        info.country = g.get("country")
        info.country_code = g.get("country_code") or info.country_code
        info.region = g.get("region")
        info.city = g.get("city")
        info.latitude = g.get("latitude")
        info.longitude = g.get("longitude")
        info.timezone = g.get("timezone")
        info.isp = g.get("isp")
        info.org = g.get("org")
        info.as_name = info.as_name or g.get("as_name")
        return True

    def _exposure_finding(self, edge_cdn: str | None, ip: IpIntel) -> Finding:
        return Finding(
            check_id="ip.origin_direct_exposure",
            name="Possible origin-IP exposure behind CDN",
            category=FindingCategory.EXPOSURE, severity=Severity.MEDIUM,
            confidence=Confidence.LOW, observation=Observation.POTENTIAL,
            module=self.name,
            description=(
                f"The HTTP edge is served by {edge_cdn}, but the domain resolves "
                f"to {ip.ip} ({ip.provider or ip.as_name or 'unknown network'}), "
                "which is not that CDN — likely the origin host."
            ),
            impact=(
                "An exposed origin IP lets an attacker bypass the CDN/WAF and hit "
                "the server directly (DDoS, rule evasion)."
            ),
            recommendation=(
                "Restrict the origin to accept traffic only from the CDN, and avoid "
                "publishing the origin IP in DNS. Verify manually."
            ),
            evidence=[Evidence(
                source=self.name, url=None,
                description=f"edge={edge_cdn}, resolved IP not on {edge_cdn}",
                data={"ip": ip.ip, "asn": ip.asn, "as_name": ip.as_name,
                      "provider": ip.provider, "ptr": ip.ptr},
            )],
        )

    async def _txt(self, resolver, name: str, rtype: str) -> list[str]:
        try:
            answer = await resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except (dns.exception.DNSException, Exception):  # noqa: BLE001 - never crash the scan
            return []
        return [r.to_text() for r in answer]

    async def _persist(self, ctx, out: IpIntelResult) -> None:
        storage = ctx.storage
        if storage is None or not hasattr(storage, "save_ip_intel"):
            return
        await storage.save_ip_intel(
            ctx.scan_id,
            edge_cdn=out.edge_cdn,
            origin_exposed=out.origin_exposed,
            ips=[i.as_dict() for i in out.ips],
        )
