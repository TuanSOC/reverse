"""apitest SQLi probe helpers (unit)."""

from __future__ import annotations

from webrecon.modules.apitest.probes import error_based_signal, quote_variants


def test_quote_variants() -> None:
    s, b = quote_variants("https://x/api/search", "q")
    assert s == "https://x/api/search?q='"
    assert b == "https://x/api/search?q=''"


def test_quote_variants_with_existing_query() -> None:
    s, b = quote_variants("https://x/api/search?page=2", "q")
    assert s.endswith("&q='") and b.endswith("&q=''")


def test_error_based_signal_truth_table() -> None:
    assert error_based_signal(baseline_hit=False, single_hit=True, balanced_hit=False)
    # baseline already errors -> not a signal
    assert not error_based_signal(True, True, False)
    # balanced also errors -> generic error, not injection
    assert not error_based_signal(False, True, True)
    # single doesn't error -> nothing
    assert not error_based_signal(False, False, False)
