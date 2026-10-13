"""Pure certificate parsing/evaluation (no network) for unit-testability."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    common_name: str | None = None
    san: list[str] = field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    self_signed: bool = False
    serial: str | None = None
    sig_algo: str | None = None  # signature hash algorithm, e.g. "sha256"


def parse_certificate(der: bytes) -> CertInfo:
    """Parse a DER-encoded X.509 certificate into a CertInfo."""
    cert = x509.load_der_x509_certificate(der)
    sig_algo = None
    try:
        alg = cert.signature_hash_algorithm
        sig_algo = alg.name if alg is not None else None
    except Exception:  # noqa: BLE001 - exotic/unknown algorithms
        sig_algo = None
    info = CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        self_signed=cert.subject == cert.issuer,
        serial=format(cert.serial_number, "x"),
        sig_algo=sig_algo,
    )
    # Prefer timezone-aware accessors (cryptography >= 42).
    info.not_before = getattr(cert, "not_valid_before_utc", None) or _aware(cert.not_valid_before)
    info.not_after = getattr(cert, "not_valid_after_utc", None) or _aware(cert.not_valid_after)

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn:
        value = cn[0].value
        info.common_name = value.decode() if isinstance(value, bytes) else value
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.san = ext.value.get_values_for_type(x509.DNSName) + [
            str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        info.san = []
    return info


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def hostname_matches(host: str, info: CertInfo) -> bool:
    """Check the hostname against SAN (preferred) or CN, with wildcard support."""
    names = list(info.san) or ([info.common_name] if info.common_name else [])
    host = host.lower().rstrip(".")
    for name in names:
        if _name_matches(host, name.lower().rstrip(".")):
            return True
    return False


def _name_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        # Wildcard matches exactly one left-most label.
        suffix = pattern[1:]  # ".example.com"
        if not host.endswith(suffix):
            return False
        left = host[: -len(suffix)]
        return bool(left) and "." not in left
    return host == pattern


def days_until(dt: datetime, now: datetime) -> float:
    return (dt - now).total_seconds() / 86400.0
