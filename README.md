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

Early development — building module-by-module against a phased plan.

- **Phase 1 (core foundation)** ✅ — schemas, storage, module registry, config, logging, CLI.
- **Phase 2 (safety spine + HTTP engine)** ✅ — target validation, SSRF guard, scope
  engine, rate-limited/size-capped HTTP engine, pipeline orchestrator, and a working
  end-to-end `webrecon scan` against a local mock site.

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
webrecon init-db
webrecon modules                 # list registered scanner modules
webrecon scan https://example.com --depth 3 --max-pages 300
```

Full CLI reference: [`docs/CLI.md`](docs/CLI.md).

## Development

```bash
pytest            # run the test suite
ruff check .      # lint
mypy src          # type-check
```

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) and
[`docs/MODULES.md`](docs/MODULES.md).

## License

MIT.
