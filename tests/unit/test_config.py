"""Defaults must be conservative and safe (§3/§34)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode


def test_defaults_are_conservative() -> None:
    cfg = ScanConfig()
    assert cfg.scope.allow_private_targets is False  # lab mode off by default (§3)
    assert cfg.rate.requests_per_second <= 5
    assert cfg.rate.concurrency <= 10
    assert cfg.http.max_response_bytes <= 50 * 1024 * 1024
    assert cfg.http.verify_tls is True
    assert cfg.scope.mode == ScopeMode.SAME_DOMAIN


def test_bounds_are_present() -> None:
    cfg = ScanConfig()
    assert cfg.scope.max_pages > 0
    assert cfg.scope.max_depth > 0
    assert cfg.scope.max_requests > 0


def test_from_toml(tmp_path) -> None:
    p = tmp_path / "webrecon.toml"
    p.write_text(
        '[scope]\nmode = "same-origin"\nmax_pages = 42\n'
        "[rate]\nrequests_per_second = 1.5\n"
        "[js]\nscan_secrets = false\n",
        encoding="utf-8",
    )
    cfg = ScanConfig.from_toml(p)
    assert cfg.scope.mode == ScopeMode.SAME_ORIGIN
    assert cfg.scope.max_pages == 42
    assert cfg.rate.requests_per_second == 1.5
    assert cfg.js.scan_secrets is False
    # unspecified values keep their conservative defaults
    assert cfg.scope.allow_private_targets is False


def test_from_toml_rejects_unknown_keys(tmp_path) -> None:
    import pytest
    from pydantic import ValidationError

    p = tmp_path / "bad.toml"
    p.write_text("[scope]\nbogus_key = 1\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        ScanConfig.from_toml(p)
