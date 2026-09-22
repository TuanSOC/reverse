"""Pure SQLi-susceptibility probe helpers (no I/O).

Error-based detection only: build `param='` (unbalanced) and `param=''`
(balanced) GET variants and decide susceptibility from whether a DB-error
signature appears with the unbalanced quote but not the balanced/baseline
responses. No boolean-diff, no time-based, no data extraction (red-team #6).
"""

from __future__ import annotations


def quote_variants(base_url: str, param: str) -> tuple[str, str]:
    """Return (url_single_quote, url_balanced_quote) for a param on a base URL.

    ``base_url`` is the endpoint URL with its query already stripped (see
    ``Endpoint.url``). The raw ``'`` is percent-encoded by the HTTP client;
    whether it reaches the DB depends on server-side decoding (documented
    limitation).
    """
    sep = "&" if "?" in base_url else "?"
    return (f"{base_url}{sep}{param}='", f"{base_url}{sep}{param}=''")


def error_based_signal(baseline_hit: bool, single_hit: bool, balanced_hit: bool) -> bool:
    """Susceptible iff the unbalanced quote triggers a DB error that the balanced
    quote and baseline do not."""
    return single_hit and not baseline_hit and not balanced_hit
