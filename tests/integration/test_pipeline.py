"""End-to-end pipeline against the local mock site (§43 slice for P2)."""

from __future__ import annotations

from sqlalchemy import select

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.modules.http.module import PRIMARY_RESPONSE_KEY
from webrecon.pipeline import Pipeline
from webrecon.reporting.json_report import build_report
from webrecon.storage.database import Database
from webrecon.storage.models import FindingRecord, ModuleRun, Scan


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True  # loopback mock site
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 50
    cfg.http.verify_tls = False
    return cfg


ALL_MODULES = {
    "target", "scope", "http", "crawler", "dns", "tls", "headers", "cookies",
    "cors", "technology", "javascript", "browser", "exposure", "subdomains",
    "api", "security",
}


async def test_pipeline_runs_all_modules(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    assert set(ctx.results) == ALL_MODULES
    # Core path always succeeds; dns/tls/subdomains skip on a loopback IP
    # literal; browser skips because browser_mode is off in the lab config.
    for name in ("target", "scope", "http", "crawler", "headers", "cookies", "cors", "exposure"):
        assert ctx.results[name].status == ModuleStatus.SUCCESS, name
    for name in ("dns", "tls", "browser", "subdomains"):
        assert ctx.results[name].status == ModuleStatus.SKIPPED, name
    assert ctx.target is not None
    assert ctx.target.hostname == "127.0.0.1"
    assert PRIMARY_RESPONSE_KEY in ctx.shared
    assert ctx.shared[PRIMARY_RESPONSE_KEY].status_code == 200


async def test_pipeline_reports_http_finding_for_plain_http(mock_site: str) -> None:
    # The mock site is plain HTTP, so the transport.https.missing finding fires.
    ctx = await Pipeline(_lab_config()).run(mock_site)
    report = build_report(ctx)
    check_ids = {f["check_id"] for f in report["findings"]}
    assert "transport.https.missing" in check_ids
    # severity and confidence are independent, both present
    hsts = next(f for f in report["findings"] if f["check_id"] == "transport.https.missing")
    assert hsts["severity"] == "high"
    assert hsts["confidence"] == "high"


async def test_pipeline_persists_to_db(mock_site: str) -> None:
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    try:
        ctx = await Pipeline(_lab_config(), db=db).run(mock_site)
        async with db.session() as s:
            scans = (await s.execute(select(Scan))).scalars().all()
            assert len(scans) == 1
            assert scans[0].id == ctx.scan_id
            assert scans[0].status in {"success", "partial"}
            runs = (await s.execute(select(ModuleRun))).scalars().all()
            assert {r.module for r in runs} == ALL_MODULES
            findings = (await s.execute(select(FindingRecord))).scalars().all()
            assert any(f.check_id == "transport.https.missing" for f in findings)
    finally:
        await db.dispose()


async def test_persistence_failure_does_not_abort_scan(mock_site: str, monkeypatch) -> None:
    from webrecon.storage.repository import ScanRepository

    async def _boom(self, *a, **k):
        raise RuntimeError("db write failed")

    # Every module-result write fails, but the scan must still complete.
    monkeypatch.setattr(ScanRepository, "save_module_result", _boom)
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    try:
        ctx = await Pipeline(_lab_config(), db=db).run(mock_site)
        assert set(ctx.results) == ALL_MODULES  # all modules still ran
        assert ctx.results["security"].status == ModuleStatus.SUCCESS
    finally:
        await db.dispose()


async def test_progress_callback_invoked(mock_site: str) -> None:
    seen = []
    pipeline = Pipeline(_lab_config(), progress=lambda p: seen.append((p.module, p.status)))
    await pipeline.run(mock_site)
    seen_modules = [m for m, _ in seen]
    assert set(seen_modules) == ALL_MODULES
    # Dependencies must precede dependents in the emitted order.
    assert seen_modules.index("target") < seen_modules.index("scope")
    assert seen_modules.index("scope") < seen_modules.index("http")
    assert seen_modules.index("http") < seen_modules.index("crawler")
