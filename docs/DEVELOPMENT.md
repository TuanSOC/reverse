# WebRecon — Development Guide

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

Optional feature groups (installed as their phases land):

```bash
pip install -e ".[dev,engine,browser,api,report]"
python -m playwright install chromium   # for browser mode (P9)
```

## Everyday commands

```bash
pytest                 # run all tests (asyncio auto-mode)
pytest tests/unit -q   # just unit tests
ruff check .           # lint
ruff check . --fix     # autofix
mypy src               # type-check
webrecon modules       # list registered scanner modules
```

## Layout

```
src/webrecon/
  core/       # models, config, registry, context, logging, errors
  storage/    # sqlalchemy models + async database
  engine/     # http engine, scope engine, rate limiter (P2)
  modules/    # one subpackage per scanner (P2+)
  pipeline/   # orchestrator (P2/P8)
  reporting/  # json/html/pdf exporters (P11)
  api/        # fastapi app + websockets (P10)
  cli/        # typer app
tests/
  unit/ integration/ security/ fixtures/
```

## Adding a scanner module (the only extension pattern)

1. Create `src/webrecon/modules/<name>/module.py`:

   ```python
   from webrecon.core.module import ScannerModule
   from webrecon.core.models import ModuleResult, Finding, Evidence
   from webrecon.core.registry import default_registry

   @default_registry.register
   class MyScanner(ScannerModule):
       name = "myscanner"
       version = "0.1.0"
       requires = ("http",)          # runs after the http module
       description = "One-line summary."

       async def run(self, ctx) -> ModuleResult:
           result = self.new_result()
           result.mark_started()
           # ... use ctx.http / ctx.scope; ctx.cancellation.raise_if_cancelled()
           result.mark_finished(ModuleStatus.SUCCESS)
           return result
   ```

2. Import it in `src/webrecon/modules/__init__.py` so it registers at load.
3. Add unit tests under `tests/unit/`, using local fixtures — never live sites.
4. `webrecon modules` should now list it in dependency order.

## Conventions

- Async everywhere for I/O; deterministic, testable pure functions for parsing.
- All target-derived data is untrusted (see `THREAT_MODEL.md`).
- Findings must carry real evidence; `severity` ≠ `confidence`.
- No new dependency if the stdlib/existing deps already solve it.
- Tests run against local fixtures/mock servers, not third-party sites.
