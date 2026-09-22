# WebRecon — Architecture

WebRecon is a **local-first, module-based** website intelligence and security
assessment tool. Its guiding constraint: everything is passive, scope-enforced,
and non-destructive, and safety is enforced *structurally* (a module physically
cannot make an out-of-scope or internal request) rather than by convention.

## Layered view

```
                ┌────────────────────────────────────────────┐
   CLI / API ── │                 Pipeline                    │
                │  resolve dep-graph · run modules · progress  │
                │  cancellation · per-module timeout · persist │
                └───────────────┬────────────────────────────┘
                                │  ScanContext
        ┌───────────────────────┴───────────────────────────┐
        │  Modules (independent ScannerModule subclasses)    │
        │  target · scope · dns · tls · http · crawler ·     │
        │  technology · javascript · api · security · …      │
        └───────────────────────┬───────────────────────────┘
                                │  every network call
        ┌───────────────────────┴───────────────────────────┐
        │  Engine:  ScopeEngine (gate) → HTTPEngine          │
        │           SSRF guard · rate limit · size caps      │
        └───────────────────────┬───────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │   Storage (SQLite)    │
                    └───────────────────────┘
```

## Core abstractions (`src/webrecon/core/`)

| Piece | File | Responsibility |
|---|---|---|
| `ScannerModule` | `module.py` | The single extension contract. Subclass + register = new capability. Declares `name`, `version`, `requires`, `timeout_seconds`. |
| `ScannerRegistry` | `registry.py` | Holds modules, topologically orders them by `requires`, rejects cycles/unknown deps. |
| `ScanContext` | `context.py` | Per-scan mutable state: config, target, prior results, shared inventory, cancellation token, engine/storage handles. |
| `ModuleResult` / `Finding` / `Evidence` | `models.py` | Uniform typed envelopes. A `Finding` **must** carry evidence; `severity` and `confidence` are independent axes. |
| enums | `enums.py` | Controlled vocabularies: `Severity`, `Confidence`, `Observation` (`observed`/`referenced`/`potential`), categories, asset/module status. |
| config | `config.py` | `ScanConfig` = scope + rate + http knobs. Conservative, safe defaults. |
| logging | `logging.py` | structlog + a redaction processor that scrubs secrets/tokens/cookies. |
| errors | `errors.py` | Typed hierarchy; module errors are recoverable (scan continues), storage errors are fatal. |

### The module contract

```python
class ScannerModule(ABC):
    name: str
    version: str = "0.1.0"
    requires: tuple[str, ...] = ()
    timeout_seconds: float | None = None
    async def run(self, ctx: ScanContext) -> ModuleResult: ...
```

The pipeline (Phase P2/P8) wraps `run()`: it enforces the timeout, catches
exceptions into a `FAILED` result, records timing, and persists. **A failing
module never crashes the scan** (§33).

### Result & evidence model

Every module returns a `ModuleResult` with `status`, timing, `error`, plus
`findings[]`, `evidence[]`, and free-form `data`. Every `Finding` names a stable
`check_id`, a `category`, a `severity` (impact), a `confidence` (certainty), an
`observation` provenance, and ≥1 `Evidence` item with the *actual observed
values*. This is validated at the schema level, so no module can emit an
evidence-free or malformed finding.

## Storage (`src/webrecon/storage/`)

SQLAlchemy 2.0 async models over SQLite (`aiosqlite`). Tables cover the full
inventory (§27): `targets, scans, module_runs, requests, responses, pages,
assets, technologies, dns_records, certificates, endpoints, forms, cookies,
findings, evidence`. Every row has a UUID PK, `created_at`, and (except roots) a
`scan_id`, so results are attributable and comparable across scans for the
timeline feature (§26).

## Safety spine (Phase P2)

`ScopeEngine` + SSRF guard sit in front of `HTTPEngine`. The guard resolves a
hostname, then rejects loopback / private / link-local / metadata (169.254.169.254)
/ reserved addresses and non-http(s) schemes unless `allow_private_targets` is
explicitly enabled (lab mode). The scope engine enforces same-origin /
same-domain / include-subdomains plus path include/exclude and the
max-depth/pages/requests budgets. Rate limiting is conservative by default and
backs off on HTTP 429.

## Phased implementation plan

| Phase | Scope | Depends on |
|---|---|---|
| **P1 ✅** | Core: schemas, storage, registry, config, logging, CLI wiring, tests | — |
| P2 | Target + Scope + HTTP engine + SSRF guard + rate limit | P1 |
| P3 | Crawler + asset discovery + redirect analysis | P2 |
| P4 | DNS ‖ TLS ‖ HTTP header/cookie/CORS analysis | P2 |
| P5 | Technology fingerprinting | P3, P4 |
| P6 | JavaScript analysis + source maps | P3 |
| P7 | API discovery (observed/referenced/potential) | P3, P6 |
| P8 | Security check engine + severity aggregation | P4–P7 |
| P9 | Browser mode (Playwright) | P3 |
| P10 | Dashboard (React/TS) ‖ P11 Reports ‖ P12 CLI scan | P8 |
| P13 | Test hardening + security tests | all |
| P14 | Final review + docs | all |

**MVP Definition of Done:** the full pipeline runs end-to-end against a bundled
local mock site, producing evidence-backed findings visible in dashboard + report,
with tests, error handling, logging, cancellation, scope enforcement, and rate
limiting throughout.
