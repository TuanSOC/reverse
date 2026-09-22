"""TLS finding logic exercised directly with synthetic certs (§12)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from webrecon.modules.tls.analysis import CertInfo
from webrecon.modules.tls.module import TlsModule

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def _findings(info: CertInfo, host="example.com", meta=None):
    mod = TlsModule()
    result = mod.new_result()
    mod._build_findings(result, host, info, meta or {"protocol": "TLSv1.3"}, NOW)
    return {f.check_id for f in result.findings}


def _cert(**kw) -> CertInfo:
    base = dict(
        subject="CN=example.com", issuer="CN=Some CA", common_name="example.com",
        san=["example.com", "www.example.com"],
        not_before=NOW - timedelta(days=30), not_after=NOW + timedelta(days=200),
        self_signed=False, sig_algo="sha256",
    )
    base.update(kw)
    return CertInfo(**base)


def test_valid_cert_has_no_findings() -> None:
    assert _findings(_cert()) == set()


def test_expired_cert() -> None:
    assert "tls.cert.expired" in _findings(_cert(not_after=NOW - timedelta(days=1)))


def test_near_expiry() -> None:
    assert "tls.cert.near_expiry" in _findings(_cert(not_after=NOW + timedelta(days=5)))


def test_hostname_mismatch() -> None:
    checks = _findings(_cert(san=["other.com"], common_name="other.com"))
    assert "tls.cert.hostname_mismatch" in checks


def test_self_signed() -> None:
    assert "tls.cert.self_signed" in _findings(_cert(self_signed=True))


def test_weak_protocol() -> None:
    checks = _findings(_cert(), meta={"protocol": "TLSv1.1"})
    assert "tls.protocol.weak" in checks


def test_weak_signature_algorithm() -> None:
    assert "tls.cert.weak_signature" in _findings(_cert(sig_algo="sha1"))
    assert "tls.cert.weak_signature" not in _findings(_cert(sig_algo="sha256"))
