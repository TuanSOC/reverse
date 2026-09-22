# Changelog

All notable changes to WebRecon are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
semantic versioning.

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
