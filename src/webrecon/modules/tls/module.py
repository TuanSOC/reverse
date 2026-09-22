"""TLS / certificate module (§12).

Establishes a TLS connection to the target (SSRF-guarded first), extracts the
leaf certificate and negotiated protocol, and flags expiry, hostname mismatch,
self-signed certs, and weak protocol versions. No traffic beyond the handshake
is sent; when there is no TLS server (e.g. a plain-HTTP lab host) the module
skips cleanly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import UTC, datetime

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
from ...engine.ssrf_guard import SsrfGuard
from .analysis import CertInfo, days_until, hostname_matches, parse_certificate

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
_WEAK_SIG_ALGOS = {"sha1", "md5", "md2"}
_NEAR_EXPIRY_DAYS = 30


@default_registry.register
class TlsModule(ScannerModule):
    name = "tls"
    version = "0.1.0"
    requires = ("target",)
    timeout_seconds = 30.0
    description = "Analyze the TLS certificate, validity, hostname, and protocol."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        if target is None:
            result.error = "target unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        host = target.hostname
        is_https = target.scheme == "https"
        port = target.port if is_https else 443

        # For a plain-HTTP IP-literal (typical lab host) an opportunistic 443
        # probe is not meaningful and can hang on filtered ports — skip it.
        if not is_https and _is_ip_literal(host):
            result.data = {"skipped": "plain-HTTP IP-literal target; no TLS probe"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        # Speculative HTTPS probe on an HTTP target gets a short timeout; an
        # explicit HTTPS target gets the full handshake budget.
        connect_timeout = 8.0 if is_https else 3.0

        # Reuse the SSRF guard so TLS cannot connect to an internal address.
        guard = SsrfGuard(allow_private_targets=ctx.config.scope.allow_private_targets)
        try:
            await guard.check_url(f"https://{host}:{port}/")
        except Exception as exc:  # noqa: BLE001
            result.error = f"blocked/unresolvable: {exc}"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        try:
            der, meta = await asyncio.to_thread(_fetch_cert, host, port, connect_timeout)
        except (OSError, ssl.SSLError) as exc:
            result.data = {"skipped": f"no TLS on {host}:{port} ({type(exc).__name__})"}
            result.mark_finished(ModuleStatus.SKIPPED)
            log.debug("tls connect failed", host=host, port=port, error=str(exc))
            return result

        info = parse_certificate(der)
        await self._persist(ctx, info)
        now = datetime.now(UTC)
        self._build_findings(result, host, info, meta, now)

        result.data = {
            "subject": info.subject,
            "issuer": info.issuer,
            "common_name": info.common_name,
            "san": info.san,
            "not_before": info.not_before.isoformat() if info.not_before else None,
            "not_after": info.not_after.isoformat() if info.not_after else None,
            "self_signed": info.self_signed,
            "protocol": meta.get("protocol"),
            "cipher": meta.get("cipher"),
            "verified": meta.get("verified", False),
        }
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("tls analyzed", host=host, protocol=meta.get("protocol"))
        return result

    def _build_findings(self, result, host, info: CertInfo, meta, now) -> None:
        def ev(desc, d) -> Evidence:
            return Evidence(source=self.name, url=f"https://{host}", description=desc, data=d)

        if info.not_after and info.not_after < now:
            result.findings.append(
                Finding(
                    check_id="tls.cert.expired", name="TLS certificate expired",
                    category=FindingCategory.TRANSPORT, severity=Severity.HIGH,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description="The certificate's validity period has ended.",
                    impact="Browsers reject the site; users see security errors.",
                    recommendation="Renew and deploy a valid certificate.",
                    evidence=[ev("Expired", {"not_after": info.not_after.isoformat()})],
                )
            )
        elif info.not_after and days_until(info.not_after, now) < _NEAR_EXPIRY_DAYS:
            result.findings.append(
                Finding(
                    check_id="tls.cert.near_expiry", name="TLS certificate near expiry",
                    category=FindingCategory.TRANSPORT, severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description="The certificate expires soon.",
                    impact="Risk of an outage if renewal is missed.",
                    recommendation="Renew before expiry; automate renewal.",
                    evidence=[ev("Near expiry", {"not_after": info.not_after.isoformat()})],
                )
            )

        if not hostname_matches(host, info):
            result.findings.append(
                Finding(
                    check_id="tls.cert.hostname_mismatch", name="Certificate hostname mismatch",
                    category=FindingCategory.TRANSPORT, severity=Severity.HIGH,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description=f"The certificate does not cover {host}.",
                    impact="Clients cannot verify they are talking to the right server.",
                    recommendation="Issue a certificate whose SAN includes the hostname.",
                    evidence=[
                        ev("Mismatch", {"host": host, "san": info.san, "cn": info.common_name})
                    ],
                )
            )

        if info.self_signed:
            result.findings.append(
                Finding(
                    check_id="tls.cert.self_signed", name="Self-signed certificate",
                    category=FindingCategory.TRANSPORT, severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description="The certificate is self-signed (issuer == subject).",
                    impact="Not trusted by browsers; enables trivial MITM if accepted.",
                    recommendation="Use a certificate from a trusted CA.",
                    evidence=[ev("Self-signed", {"issuer": info.issuer})],
                )
            )

        if info.sig_algo and info.sig_algo.lower() in _WEAK_SIG_ALGOS:
            result.findings.append(
                Finding(
                    check_id="tls.cert.weak_signature",
                    name=f"Weak certificate signature ({info.sig_algo})",
                    category=FindingCategory.TRANSPORT, severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description=f"The certificate is signed with {info.sig_algo}.",
                    impact="Weak signature hashes (SHA-1/MD5) are collision-prone and deprecated.",
                    recommendation="Re-issue the certificate with SHA-256 or stronger.",
                    evidence=[ev("Weak signature algorithm", {"sig_algo": info.sig_algo})],
                )
            )

        protocol = meta.get("protocol")
        if protocol in _WEAK_PROTOCOLS:
            result.findings.append(
                Finding(
                    check_id="tls.protocol.weak", name=f"Weak TLS protocol {protocol}",
                    category=FindingCategory.TRANSPORT, severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH, observation=Observation.OBSERVED, module=self.name,
                    description=f"The server negotiated {protocol}.",
                    impact="Deprecated protocols have known weaknesses.",
                    recommendation="Disable TLS < 1.2; prefer TLS 1.3.",
                    evidence=[ev("Weak protocol", {"protocol": protocol})],
                )
            )

    async def _persist(self, ctx, info: CertInfo) -> None:
        storage = ctx.storage
        if storage is None:
            return
        await storage.save_certificate(ctx.scan_id, info)


def _fetch_cert(host: str, port: int, timeout: float) -> tuple[bytes, dict]:
    """Blocking TLS handshake to fetch the leaf certificate + negotiation meta.

    Tries a verifying context first (to learn ``verified``); on verification
    failure it retries without verification purely to still read the presented
    certificate for analysis. No application data is ever sent.
    """
    meta: dict = {}
    verify_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=host) as ss:
                cipher = ss.cipher()
                meta["protocol"] = ss.version()
                meta["cipher"] = cipher[0] if cipher else None
                meta["verified"] = True
                return _require_cert(ss), meta
    except ssl.SSLCertVerificationError as exc:
        meta["verified"] = False
        meta["verify_error"] = str(exc)

    unverified = ssl._create_unverified_context()  # noqa: S323 - deliberate: read invalid cert  # type: ignore[attr-defined]
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with unverified.wrap_socket(sock, server_hostname=host) as ss:
            cipher = ss.cipher()
            meta["protocol"] = ss.version()
            meta["cipher"] = cipher[0] if cipher else None
            return _require_cert(ss), meta


def _require_cert(ss: ssl.SSLSocket) -> bytes:
    der = ss.getpeercert(binary_form=True)
    if der is None:
        raise ssl.SSLError("peer presented no certificate")
    return der


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
