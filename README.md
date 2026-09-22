# WebRecon

**Local-first Website Intelligence & Security Assessment workstation.**

WebRecon takes a URL you **own or are explicitly authorized to test** and
performs passive, scope-enforced, non-destructive reconnaissance and security
assessment: recon → crawl → asset discovery → technology detection → JavaScript
analysis → API discovery → security analysis → evidence → risk classification →
report.

> ⚠️ **Authorized use only.** This tool is for owned assets, authorized
> penetration testing, security research on systems you may test, and
> local/CTF labs. It contains **no** exploitation, brute-force, credential,
> DoS, persistence, or evasion capabilities, and none will be added. Dual-use
> features are deliberately kept at the detection/assessment/evidence level.
> See [`docs/SECURITY.md`](docs/SECURITY.md) and
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Status

**MVP complete** — the full pipeline (14 modules) runs end-to-end with a
dashboard, CLI, and JSON/HTML/PDF reports. 136 tests pass; ruff + mypy clean.
Built module-by-module against a phased plan:

- **Phase 1 (core foundation)** ✅ — schemas, storage, module registry, config, logging, CLI.
- **Phase 2 (safety spine + HTTP engine)** ✅ — target validation, SSRF guard, scope
  engine, rate-limited/size-capped HTTP engine, pipeline orchestrator, and a working
  end-to-end `webrecon scan` against a local mock site.
- **Phase 3 (crawler + asset discovery)** ✅ — bounded scope/robots-gated BFS crawl,
  HTML link/asset/form/metadata extraction, robots.txt + sitemap.xml parsing, crawl
  graph edges, and a page/asset/form inventory persisted to SQLite.
- **Phase 4 (DNS / TLS / headers / cookies / CORS)** ✅ — five independent analysis
  modules producing evidence-backed findings: DNS records + SPF/DMARC + dangling-CNAME,
  TLS cert/validity/hostname/protocol, security-header gaps with explanations, cookie
  flag analysis (masked values), and CORS misconfiguration flags.
- **Phase 5 (technology fingerprinting)** ✅ — signature-based detection across
  headers, cookies, HTML, script URLs, and meta generator, with confidence scoring,
  version extraction, and per-detection evidence.
- **Phase 6 (JavaScript analysis + source maps)** ✅ — downloads in-scope JS, extracts
  endpoint/websocket/GraphQL/analytics/cloud references (classified `referenced`, never
  asserted), scans for masked secret patterns, and flags exposed `.js.map` source maps.
  Downloaded JS is never executed.
- **Phase 7 (API discovery)** ✅ — consolidates endpoints from the crawler, JavaScript,
  and sitemap into one deduplicated inventory with honest `observed / referenced /
  potential` provenance and REST/GraphQL/WebSocket classification. No endpoint is
  probed or replayed.
- **Phase 8 (security engine)** ✅ — cross-module rules (mixed content, outdated tech,
  directory listing) + deterministic, confidence-weighted risk classification.
- **Phase 9 (browser mode)** ✅ — opt-in Playwright render with in-browser scope
  enforcement, XHR/fetch/WebSocket observation, and screenshots.
- **Phase 10 (dashboard)** ✅ — FastAPI backend (`webrecon serve`) with a read API,
  background scans, live-progress WebSocket, and a self-contained dark dashboard
  (overview, findings, endpoints, technologies, pages, assets, DNS/TLS, graph).
- **Phase 11 (reports)** ✅ — JSON, autoescaped HTML (executive summary, scope,
  methodology, findings + evidence, technology, endpoints), and PDF via headless
  Chromium. `webrecon scan … --json --html --pdf`.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Architecture at a glance

Every scanner is an independent `ScannerModule` registered on a registry; the
pipeline resolves their dependency graph and runs each with a uniform result
envelope. A single scope-enforced, rate-limited, SSRF-guarded HTTP engine sits
in front of all network access, so no module can make an out-of-scope or
internal request.

```
ScanContext → ScopeEngine (gate) → HTTPEngine (shared, rate-limited)
      │
      └→ Pipeline → [Module.run(ctx)] → ModuleResult{status, evidence, findings}
                          │
                          ▼
                    SQLite storage → API / CLI / Reports
```

## Requirements

- Python ≥ 3.11 (developed on 3.14)
- Node ≥ 20 (for the dashboard, added in a later phase)

## Installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
webrecon version
webrecon modules                       # list registered scanner modules
webrecon scan https://example.com --depth 3 --max-pages 300 \
    --browser --json report.json --html report.html --pdf report.pdf
webrecon scans                         # list stored scans
webrecon report <scan-id> --html out.html   # regenerate a report from the DB
webrecon serve                         # open the dashboard at http://127.0.0.1:8000
```

For local lab targets (loopback/private), add `--allow-private`.
Full CLI reference: [`docs/CLI.md`](docs/CLI.md).

## Docker

```bash
docker build -t webrecon .
docker run --rm -p 8000:8000 -v webrecon_data:/data webrecon   # dashboard
docker run --rm -v webrecon_data:/data webrecon scan https://example.com --json /data/r.json
```

The image is based on the official Playwright Python image, so browser mode and
PDF export work out of the box. Scans persist in the `/data` volume.

## Development

```bash
pip install -e ".[dev,engine,browser,api,report]"
pytest                                  # run the test suite (157 tests)
pytest --cov=webrecon --cov-report=term-missing   # with coverage (~84%)
ruff check .                            # lint
mypy src                                # type-check
pre-commit install                      # optional: run lint/type on commit
```

CI (`.github/workflows/ci.yml`) runs lint + type-check + tests with a coverage
gate on Python 3.11–3.13. See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md),
[`docs/MODULES.md`](docs/MODULES.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT.
