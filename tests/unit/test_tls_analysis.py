"""Certificate parsing/evaluation (§12) using a locally generated cert."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from webrecon.modules.tls.analysis import (
    days_until,
    hostname_matches,
    parse_certificate,
)


def _make_cert(cn: str, sans: list[str], *, days_valid: int = 90) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_self_signed_and_san() -> None:
    der = _make_cert("example.com", ["example.com", "*.example.com"])
    info = parse_certificate(der)
    assert info.self_signed is True
    assert info.common_name == "example.com"
    assert "example.com" in info.san
    assert info.not_after is not None


def test_hostname_matching_including_wildcard() -> None:
    der = _make_cert("example.com", ["example.com", "*.example.com"])
    info = parse_certificate(der)
    assert hostname_matches("example.com", info)
    assert hostname_matches("www.example.com", info)  # wildcard
    assert not hostname_matches("deep.sub.example.com", info)  # wildcard = one label
    assert not hostname_matches("evil.com", info)


def test_days_until() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert round(days_until(datetime(2026, 1, 11, tzinfo=UTC), now)) == 10
