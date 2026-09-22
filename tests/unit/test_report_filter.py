"""Unit tests for the report min-severity filter helper."""

from __future__ import annotations

from webrecon.api.queries import filter_report_min_severity


def _rep() -> dict:
    return {
        "scan_id": "s1",
        "summary": {"total_findings": 4, "by_severity": {}, "modules_run": 3},
        "findings": [
            {"check_id": "a", "severity": "critical"},
            {"check_id": "b", "severity": "high"},
            {"check_id": "c", "severity": "medium"},
            {"check_id": "d", "severity": "low"},
        ],
    }


def test_filter_keeps_at_or_above_threshold() -> None:
    out = filter_report_min_severity(_rep(), "high")
    ids = {f["check_id"] for f in out["findings"]}
    assert ids == {"a", "b"}
    assert out["summary"]["total_findings"] == 2
    assert out["summary"]["by_severity"]["critical"] == 1
    assert out["summary"]["by_severity"]["high"] == 1
    assert out["summary"]["min_severity"] == "high"


def test_filter_medium_includes_medium() -> None:
    out = filter_report_min_severity(_rep(), "medium")
    assert {f["check_id"] for f in out["findings"]} == {"a", "b", "c"}


def test_unknown_severity_is_fail_open() -> None:
    out = filter_report_min_severity(_rep(), "bogus")
    assert len(out["findings"]) == 4  # nothing dropped


def test_original_report_not_mutated() -> None:
    rep = _rep()
    filter_report_min_severity(rep, "critical")
    assert len(rep["findings"]) == 4  # source untouched
    assert rep["summary"]["total_findings"] == 4
