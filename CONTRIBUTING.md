# Contributing to WebRecon

Thanks for your interest. WebRecon is a **passive, non-destructive** security
assessment tool — contributions must preserve that boundary.

## Ground rules

- **No offensive capabilities.** We do not accept brute-force, credential
  attacks, authentication bypass, automated exploitation, persistence, evasion,
  or denial-of-service features. Dual-use functionality stays at the
  detection/assessment/evidence level (see `docs/SECURITY.md`,
  `docs/THREAT_MODEL.md`).
- **Every finding needs real evidence.** `severity` and `confidence` are
  independent; endpoints/findings are classified `observed | referenced |
  potential`. Never assert something exists from a bare string match.
- **Tests use the local mock site**, never live third-party targets.

## Setup

```bash
python -m venv .venv && . .venv/Scripts/activate    # or source .venv/bin/activate
pip install -e ".[dev,engine,browser,api,report]"
python -m playwright install chromium               # for browser mode / PDF
```

## Before you push

```bash
ruff check .          # lint (also: ruff check . --fix)
mypy src              # type-check
pytest                # full suite
pytest --cov=webrecon --cov-report=term-missing   # with coverage
```

All three must be green. CI (`.github/workflows/ci.yml`) enforces the same.

## Adding a scanner module

A new capability is one `ScannerModule` subclass registered on
`core.registry.default_registry` (see `docs/DEVELOPMENT.md` for the full
pattern). No core changes required. Add unit tests for pure logic and an
integration test against the mock site.

## Commit style

Conventional-ish: `type(scope): summary` (e.g. `fix(dns): …`, `feat(api): …`).
Keep the diff focused; update `CHANGELOG.md` and the relevant `docs/` page.
