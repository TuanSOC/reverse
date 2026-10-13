"""Pure rate-limit / protection analysis (no I/O) — unit-testable.

Everything here reasons over response headers and already-observed status codes.
Sending the probe requests lives in :mod:`module`; this file only *interprets*.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Advertised rate-limit header families (IETF draft-ietf-httpapi-ratelimit +
# the common vendor variants). Lower-cased for matching.
_LIMIT_HEADERS = ("ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit")
_REMAINING_HEADERS = (
    "ratelimit-remaining", "x-ratelimit-remaining", "x-rate-limit-remaining")
_RESET_HEADERS = ("ratelimit-reset", "x-ratelimit-reset", "x-rate-limit-reset")
_POLICY_HEADERS = ("ratelimit-policy", "x-ratelimit-policy")
#: Retry-After is a throttling/backoff signal rather than a quota advertisement.
_BACKOFF_HEADERS = ("retry-after",)

_ALL_RL_HEADERS = (
    *_LIMIT_HEADERS, *_REMAINING_HEADERS, *_RESET_HEADERS, *_POLICY_HEADERS, *_BACKOFF_HEADERS)

# Protection-layer (WAF / bot-management / CDN-edge) response signals.
# (header, substring-to-match ("" = any value), provider).
_PROTECTION_SIGNALS: tuple[tuple[str, str, str], ...] = (
    ("cf-ray", "", "Cloudflare"),
    ("cf-mitigated", "", "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("x-amzn-waf-action", "", "AWS WAF"),
    ("server", "awselb", "AWS ELB"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    ("x-datadome", "", "DataDome"),
    ("x-sl-compstate", "", "StackPath"),
    ("server", "awswaf", "AWS WAF"),
)

# Status codes that indicate rate limiting / throttling / blocking.
RATE_LIMIT_STATUS = 429
_BLOCK_STATUS = frozenset({403, 503})


@dataclass
class RateLimitInfo:
    """Rate-limit quota advertised by a server via response headers."""

    limit: str | None = None
    remaining: str | None = None
    reset: str | None = None
    policy: str | None = None
    retry_after: str | None = None
    headers_seen: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.policy:
            return f"policy {self.policy}"
        if self.limit is not None:
            extra = f", {self.remaining} remaining" if self.remaining is not None else ""
            return f"limit {self.limit}{extra}"
        if self.retry_after is not None:
            return f"Retry-After {self.retry_after}"
        return "rate-limit headers present"


def _lower(headers: dict[str, str]) -> dict[str, str]:
    return {str(k).lower(): v for k, v in headers.items()}


def parse_rate_limit(headers: dict[str, str]) -> RateLimitInfo | None:
    """Return advertised rate-limit info, or ``None`` when no RL header is present."""
    h = _lower(headers)
    seen = [name for name in _ALL_RL_HEADERS if name in h]
    if not seen:
        return None

    def first(names: tuple[str, ...]) -> str | None:
        return next((h[n] for n in names if n in h), None)

    return RateLimitInfo(
        limit=first(_LIMIT_HEADERS), remaining=first(_REMAINING_HEADERS),
        reset=first(_RESET_HEADERS), policy=first(_POLICY_HEADERS),
        retry_after=first(_BACKOFF_HEADERS), headers_seen=seen,
    )


def detect_protection(headers: dict[str, str]) -> str | None:
    """Best-effort WAF / bot-management / CDN-edge provider from response headers."""
    h = _lower(headers)
    for header, needle, provider in _PROTECTION_SIGNALS:
        value = h.get(header)
        if value is not None and (not needle or needle in value.lower()):
            return provider
    return None


@dataclass
class ProbeOutcome:
    """Classification of a bounded active rate-limit probe over one endpoint."""

    requests: int
    statuses: list[int]
    verdict: str                 # enforced | none_observed | blocked | inconclusive
    tripped_at: int | None = None     # 1-based request index that first hit 429
    retry_after: str | None = None
    detail: str = ""


def classify_probe(statuses: list[int], retry_after: str | None = None) -> ProbeOutcome:
    """Interpret the status sequence from a bounded same-endpoint GET probe.

    Detection-only: establishes *whether* throttling/blocking occurred within the
    bounded request count — never the precise threshold, never a bypass.
    """
    n = len(statuses)
    if n == 0:
        return ProbeOutcome(0, [], "inconclusive", detail="no responses")

    tripped = next((i + 1 for i, s in enumerate(statuses) if s == RATE_LIMIT_STATUS), None)
    if tripped is not None:
        return ProbeOutcome(n, statuses, "enforced", tripped_at=tripped,
                            retry_after=retry_after,
                            detail=f"HTTP 429 after {tripped} request(s)")

    # A tail that turns to 403/503 and stays there looks like throttling/IP block.
    tail = statuses[-3:]
    if (len(tail) >= 3 and all(s in _BLOCK_STATUS for s in tail)
            and statuses[0] not in _BLOCK_STATUS):
        return ProbeOutcome(n, statuses, "blocked", retry_after=retry_after,
                            detail=f"responses switched to {tail[-1]} and did not recover")

    if all(200 <= s < 400 for s in statuses):
        return ProbeOutcome(n, statuses, "none_observed",
                            detail=f"{n} request(s) all succeeded; no 429/Retry-After")

    return ProbeOutcome(n, statuses, "inconclusive",
                        detail=f"mixed statuses {sorted(set(statuses))}")
