# Phase 1 — Security fixes (TDD)

## R1 · Secrets persisted in scans.config + JSON report (review #1)
- Add `ScanConfig.redacted_dump()` → `model_dump(mode="json")` with
  `auth.password`, `http.cookie`, every `http.auth_headers` value replaced by
  `"***"` when set (None/empty stays as is).
- Use it in `orchestrator.py` (create_target_and_scan) and
  `reporting/json_report.py:72`. Grep for other `config.model_dump` callers.
- Tests: pipeline with password/cookie/header set → DB `scans.config` and
  `build_report()` contain none of the raw values.

## R2 · Auto-login skips SSRF guard + scope (review #2)
- In `Pipeline._auto_login`: before launching the browser,
  `SsrfGuard(allow_private_targets).check_url(login_url)` and a same-site
  check vs the target host (equal, parent/child, or same parent domain after
  dropping the first label of a ≥3-label host). Refuse → log + `auth` event
  `{"authenticated": False, "reason": ...}`, scan continues.
- Pure helper `login_host_allowed(login_host, target_host)` in auto_login.py.
- Tests: helper table; pipeline with login_url on 169.254.169.254 / other site
  → no browser launch (monkeypatch capture fn to assert not called).

## R3 · Subdomain cookies leak to parent host (review #8)
- `cookies_to_header`: keep a cookie only if `host == dom` or
  `host.endswith("." + dom)` (browser semantics); drop child-domain cookies.
- Test: `sso.example.com` cookie not sent for `example.com`.
