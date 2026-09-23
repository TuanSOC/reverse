"""Pure differential-response analysis for input-validation testing (no I/O).

Sends a small set of *benign but structurally unusual* values for a parameter
(boundary sizes, encoded special characters, type-confusion shapes) and compares
each response against the baseline across three axes — HTTP status, body size,
and response time. A divergence that is NOT a database error indicates the
endpoint failed to validate its input (it crashed, reflected, or behaved
inconsistently). No payload is designed to exploit; this only *characterizes*
input handling. DB-error divergences are deliberately excluded (that is the
error-based SQLi check's job).
"""

from __future__ import annotations

from dataclasses import dataclass

# (label, raw value) — benign structured inputs. Percent-encoding of specials is
# left to the HTTP client; server-side decoding determines what actually lands.
DIFFERENTIAL_INPUTS: tuple[tuple[str, str], ...] = (
    ("boundary_long", "A" * 4096),        # oversized input
    ("boundary_negative", "-1"),          # negative where a positive int is likely
    ("boundary_overflow", "99999999999999999999"),  # out-of-range integer
    ("type_array", "[]"),                 # array/type confusion
    ("special_encoded", "%00%0a<>'\""),   # NUL/CRLF/markup/quote mix
)

# Response-size divergence must exceed this ratio (either direction) to flag.
_SIZE_RATIO = 3.0
# Timing divergence: slower than baseline by this factor AND above this floor.
_TIME_RATIO = 4.0
_TIME_FLOOR_MS = 1500.0


@dataclass
class ProbeResult:
    label: str
    status: int
    elapsed_ms: float
    body_len: int
    db_error: bool = False


def _size_diverges(baseline: int, other: int) -> bool:
    lo, hi = sorted((max(baseline, 1), max(other, 1)))
    return hi / lo >= _SIZE_RATIO


def analyze_differential(
    baseline: ProbeResult, probes: list[ProbeResult]
) -> list[dict[str, object]]:
    """Return input-validation anomalies (excluding DB-error divergences).

    Each anomaly names the probe label, the axis that diverged, and the
    before/after values so a report can cite concrete evidence.
    """
    anomalies: list[dict[str, object]] = []
    for p in probes:
        if p.db_error:
            continue  # a DB error is reported by the SQLi/db_error checks, not here
        # 1) Server error triggered by the input → handler didn't validate it.
        if p.status >= 500 and baseline.status < 500:
            anomalies.append({
                "label": p.label, "axis": "status",
                "baseline": baseline.status, "observed": p.status,
                "reason": "input triggered a server error (unhandled input)",
            })
            continue
        # 2) Status class flip (e.g. 200 → 400) between baseline and this input.
        if (baseline.status // 100) != (p.status // 100) and p.status < 500:
            anomalies.append({
                "label": p.label, "axis": "status",
                "baseline": baseline.status, "observed": p.status,
                "reason": "status class changed for a structured input",
            })
            continue
        # 3) Large body-size divergence (reflection / different code path).
        if _size_diverges(baseline.body_len, p.body_len):
            anomalies.append({
                "label": p.label, "axis": "body_size",
                "baseline": baseline.body_len, "observed": p.body_len,
                "reason": "response size diverged sharply",
            })
            continue
        # 4) Timing divergence (cautious: needs a large ratio AND absolute floor).
        if p.elapsed_ms >= _TIME_FLOOR_MS and p.elapsed_ms >= baseline.elapsed_ms * _TIME_RATIO:
            anomalies.append({
                "label": p.label, "axis": "time",
                "baseline": round(baseline.elapsed_ms), "observed": round(p.elapsed_ms),
                "reason": "response time diverged sharply",
            })
    return anomalies


def build_probe_url(base_url: str, param: str, value: str) -> str:
    """A GET URL setting ``param`` to ``value`` (raw; client percent-encodes)."""
    from urllib.parse import quote

    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{param}={quote(value, safe='')}"
