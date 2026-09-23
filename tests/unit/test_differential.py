"""Unit tests for differential input-validation analysis (pure)."""

from __future__ import annotations

from webrecon.modules.apitest.differential import (
    ProbeResult,
    analyze_differential,
    build_probe_url,
)


def _p(label, status=200, ms=50.0, blen=100, db=False):
    return ProbeResult(label, status, ms, blen, db)


def test_server_error_on_input_flagged() -> None:
    base = _p("baseline", status=200)
    out = analyze_differential(base, [_p("boundary_long", status=500)])
    assert len(out) == 1
    assert out[0]["axis"] == "status" and out[0]["observed"] == 500


def test_status_class_flip_flagged() -> None:
    base = _p("baseline", status=200)
    out = analyze_differential(base, [_p("type_array", status=400)])
    assert out and out[0]["axis"] == "status"


def test_db_error_divergence_excluded() -> None:
    # A DB-error response is NOT an input-validation finding here.
    base = _p("baseline", status=200)
    out = analyze_differential(base, [_p("special_encoded", status=500, db=True)])
    assert out == []


def test_body_size_divergence_flagged() -> None:
    base = _p("baseline", blen=100)
    out = analyze_differential(base, [_p("boundary_long", blen=5000)])
    assert out and out[0]["axis"] == "body_size"


def test_small_size_change_not_flagged() -> None:
    base = _p("baseline", blen=100)
    assert analyze_differential(base, [_p("x", blen=150)]) == []


def test_timing_needs_ratio_and_floor() -> None:
    base = _p("baseline", ms=50.0)
    # 200ms is 4x but below the 1500ms floor → not flagged
    assert analyze_differential(base, [_p("x", ms=200.0)]) == []
    # 3000ms is >4x and above floor → flagged
    out = analyze_differential(base, [_p("x", ms=3000.0)])
    assert out and out[0]["axis"] == "time"


def test_clean_endpoint_no_anomalies() -> None:
    base = _p("baseline", status=200, blen=100, ms=50.0)
    probes = [_p("boundary_long", 200, 60.0, 110),
              _p("type_array", 200, 55.0, 95)]
    assert analyze_differential(base, probes) == []


def test_build_probe_url_encodes_value() -> None:
    url = build_probe_url("https://x/api/item?id=1", "id", "<>'")
    assert "id=" in url and "<" not in url  # percent-encoded
