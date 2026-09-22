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
