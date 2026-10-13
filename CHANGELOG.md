# Changelog

All notable changes to WebRecon are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
semantic versioning.

## [Unreleased] — v0.4.0 intelligence + hardening

### Added
- Scan cleanup: delete a stored scan and everything it owns via
  `DELETE /api/scans/{id}`, `webrecon delete <id>`, and a trash button (two-click
  confirm) in the dashboard scan switcher.
- `ratelimit` module: passive rate-limit / WAF-protection posture detection
  (advertised `RateLimit-*`/`Retry-After` headers and Cloudflare/Sucuri/Imperva/
  AWS WAF edge signals, zero extra requests, on by default), plus an opt-in
  `--active` hard-capped (≤12 GET) probe that confirms whether an endpoint
  enforces throttling and flags endpoints with no observed rate limiting.
- Web application intelligence: JS AST endpoint extraction, parameter
  classification, source-map reconstruction, unified asset graph, auth-flow
  model, scan event timeline, attack-surface tree.
- Grounded AI analysis (`webrecon ai`, `scan --ai`, `/api/scans/{id}/ai`) via
  Groq or an offline stub; every claim cites evidence IDs.
- Dashboard: Home hub with next steps, EN/VI language toggle, Endpoint / JS /
  Auth-flow explorers, attack-surface tree, event timeline, AI panel, hash
  routing, mobile navigation, keyboard and screen-reader support.

- CLI read commands `webrecon findings | endpoints | assets | graph`
  (default: latest scan, `--json` for scripting).
- HTML / JSON / PDF reports now include Attack Surface, API Endpoints,
  Parameters and Authentication Flow sections (also for `--no-db` scans).

- Dashboard: searchable scan switcher (keyboard operable), auth-flow step
  pipeline with role/method badges.
- Dashboard: colored HTTP-method badges across Endpoints / Attack Surface /
  Timeline / Auth Flow, inline copy-URI in the endpoints table, and KPI cards
  with icons + coverage/confidence rings (SPEC.md visual items; no external fonts).
- `auth-flow` now returns `step_keys` alongside `steps` (stable ids for UIs).

### Security
- Credentials (password, cookies, auth headers) are masked in the stored scan
  config and in JSON reports.
- Auto-login refuses login URLs off the target's site or blocked by the SSRF
  guard; every request of the login browser is re-checked by the SSRF guard;
  subdomain cookies are no longer sent to the parent host.
- Nested config sections only read `WEBRECON_<SECTION>_*` environment
  variables (bare `USERNAME`/`PASSWORD`/`COOKIE` no longer leak in); login
  URLs and database URLs are scrubbed in the stored config and timeline.

### Changed
- Auto-login only accepts a login page on the target host or a parent/child
  domain of it (siblings such as `sso.example.com` for `app.example.com` are
  refused — scan `example.com` or use `--cookie` instead).

### Fixed
- Groq errors of any body shape no longer crash `scan --ai`; live progress
  reports completion before the AI step; bad AI providers fail fast.
- Node AST parser is killed on timeout; reconstructed sources parse
  concurrently; AST URL templates with an unresolved base are no longer stored
  as endpoints; session-cookie detection no longer matches `csrftoken` or
  `visid_*`; a hinted username field at index 0 is no longer skipped.

### Fixed (codebase-wide bug hunt)
- Browser + auto-login: every redirect hop is now checked against scope and the
  SSRF guard (Playwright skipped route handlers on redirects); the browser
  module also applies the SSRF guard, not just scope.
- Crawl no longer aborts on a malformed link (port out of range); crawler and
  JS analysis stop on a time budget and keep partial results; crawler timeout
  raised to 300s.
- Cancelled scans are recorded as `cancelled` (were `success`) and skip the
  post-scan AI step; cancelling a finished scan returns false.
- `webrecon scan` no longer crashes on Rich markup in target-derived finding
  names; credentials in the target URL are scrubbed from logs, timeline and DB.
- IP-literal targets no longer put other IPs in scope; open-redirect is only
  "confirmed" when the Location itself leaves the site; GraphQL responses with
  a non-object `data` no longer crash apitest; "unauthenticated access" is not
  reported on authenticated scans; plugin / `?ver=` versions no longer pollute
  library and CMS versions; trailing dots trimmed from versions.
- Deep URL paths no longer crash the attack surface / reports; malformed AI
  evidence is rejected instead of crashing; cookie names are persisted so the
  stored auth flow sees session cookies; findings load their evidence in one
  query; finding/evidence ids match between live and stored reports.
- TLS: IP SANs honoured and the connection uses the vetted address; DNS:
  only NXDOMAIN counts as dangling (timeouts no longer produce findings),
  subdomain lookups run concurrently; server-status probe can fire; request
  timing excludes rate-limit/backoff waits; site-wide forms reported once;
  consecutive robots.txt User-agent lines handled; AWS documentation key and
  duplicate JS/secret_leak secret findings removed.
- API timestamps carry a UTC offset (dashboard/CLI show local time);
  `min_severity` exports also trim the attack-surface tree; dashboard fixes for
  stale progress timers, dropped WebSockets, filters carried across scans,
  focus after navigation, light-theme badge contrast and remaining i18n strings.

## [0.3.0] — 2026-09-23

IP intelligence & deep security assessment.

### Added
- `ip_intel` module — reverse DNS, ASN/AS-name (Team Cymru DNS), geolocation,
  cloud/CDN classification, and CDN origin-IP exposure detection.
- `secret_leak` module — hardcoded AWS/Google/GitHub/Stripe/Slack/PEM/JWT
  detection across JS + all crawled HTML, with mandatory masking.
- `active_verify` module (opt-in `--active`) — canary-based **confirmation** of
  open-redirect and reflected-XSS candidates (GET-only, inert canaries, no
  payload execution or data extraction).
- Email deep checks (DKIM selector probing, DMARC `p=none`), open-redirect
  parameter candidates, insecure-WebSocket (`ws://` on HTTPS) detection.
- Dashboard: IP & Infrastructure widget, "Secrets & Leaks" quick filter; report
  IP Intelligence section; `report.{fmt}?min_severity=` filtering.

### Changed / fixed
- SPA framework detection (React/Vite) from bundle content + asset URLs.
- Browser navigation robustness (drop `networkidle`, survive goto timeout).
- Removed false positives: prototype-pollution shallow-copy, AWS example keys,
  origin-exposure on unknown provider.

## [0.1.0] — 2026-09-22

First MVP. A local-first, passive, scope-enforced website intelligence and
security assessment tool with a 14-module pipeline, dashboard, CLI, and reports.

### Added
- **Core** — typed models (independent severity/confidence, mandatory
  evidence, observed/referenced/potential provenance), SQLite storage,
  dependency-ordering module registry, config, secret-redacting logging.
- **Engine** — SSRF guard with a DNS-pinning network backend (rebinding-safe),
  scope engine, rate limiter, shared HTTP engine (per-hop guard, size caps).
- **Modules** — target, scope, http, crawler, dns, tls, headers, cookies,
  cors, technology, javascript, browser (Playwright), api, security.
- **Security engine** — cross-module rules (mixed content, outdated tech,
  directory listing) and deterministic, confidence-weighted risk classification.
- **Dashboard** — FastAPI backend + self-contained UI: overview, findings
  (filter/search), endpoints, technologies, pages, assets, forms, DNS/TLS,
  relationship graph, timeline diff, reports, live progress, cancel.
- **Reports** — JSON, autoescaped HTML, PDF (headless Chromium).
- **CLI** — `scan`, `serve`, `scans`, `report`, `modules`, `init-db`.
- **Tests** — 145+ unit/integration/security tests against a local mock site.

### Fixed
- SSRF DNS-rebinding TOCTOU (connection now pinned to the vetted IP).
- Quoted TXT records made SPF/DMARC detection miss real records.
- FastAPI server ran the pipeline with an empty module registry.
- Several smaller correctness/robustness issues from an adversarial review.

### Security
- No exploitation/brute-force/DoS capabilities by design. Dual-use features are
  kept at the detection/assessment/evidence level. See `docs/SECURITY.md` and
  `docs/THREAT_MODEL.md`.
