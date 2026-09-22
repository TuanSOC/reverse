"""apitest integration against the mock vulnerable API (§21)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.pipeline import Pipeline


def _cfg(active: bool) -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    c.active = active
    return c


async def test_skipped_when_inactive(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=False)).run(mock_site)
    r = ctx.results["apitest"]
    assert r.status == ModuleStatus.SKIPPED
    assert r.stats.get("requests", 0) == 0  # no requests issued


async def test_active_finds_db_error_and_data_exposure(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    r = ctx.results["apitest"]
    assert r.status == ModuleStatus.SUCCESS
    checks = {f.check_id for f in r.findings}
    assert "apitest.db_error" in checks       # /api/db-error
    assert "apitest.data_exposure" in checks  # /api/users (token fields)
    assert "apitest.auth.unauth_access" in checks  # /api/users sensitive+data


async def test_public_benign_endpoint_not_flagged_unauth(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    r = ctx.results["apitest"]
    unauth_urls = [
        e.url for f in r.findings if f.check_id == "apitest.auth.unauth_access"
        for e in f.evidence
    ]
    # /api/config is small + non-sensitive -> must NOT be flagged.
    assert not any("/api/config" in (u or "") for u in unauth_urls)


async def test_db_error_body_yields_single_primary_finding(mock_site: str) -> None:
    # Precedence: a DB-error body is db_error only, not also data_exposure.
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    r = ctx.results["apitest"]
    dberr = [f for f in r.findings if f.check_id == "apitest.db_error"]
    for f in dberr:
        url = f.evidence[0].data.get("url", "")
        # No data_exposure finding should target the same db-error URL.
        assert not any(
            g.check_id == "apitest.data_exposure" and g.evidence[0].data.get("url") == url
            for g in r.findings
        )


async def test_sqli_susceptible_on_injectable_param(mock_site: str) -> None:
    # /api/search?q=1 was observed with param q; ' triggers a DB error, '' does not.
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    sqli = [f for f in ctx.results["apitest"].findings if f.check_id == "apitest.sqli.susceptible"]
    assert sqli, "expected a SQLi-susceptible finding on /api/search"
    f = sqli[0]
    assert str(f.severity) == "high" and str(f.confidence) == "medium"
    assert str(f.observation) == "potential"
    assert f.evidence[0].data.get("param") == "q"
    # Evidence carries the signal type, not extracted rows.
    assert f.evidence[0].data.get("signal") == "error_based"


async def test_sqli_not_flagged_without_params(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    sqli_urls = {
        f.evidence[0].data.get("url")
        for f in ctx.results["apitest"].findings
        if f.check_id == "apitest.sqli.susceptible"
    }
    # /api/users has no query params -> never a SQLi finding.
    assert not any((u or "").endswith("/api/users") for u in sqli_urls)


async def test_no_raw_secret_in_evidence(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    blob = str([f.model_dump() for f in ctx.results["apitest"].findings])
    assert "tok_abcdef123456" not in blob  # raw token from /api/users must be masked
