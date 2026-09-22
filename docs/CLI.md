# WebRecon — CLI Reference

```bash
webrecon --help
```

## Commands (Phase 1)

### `webrecon version`
Print the WebRecon version.

### `webrecon init-db [--database-url URL]`
Create the local scan database schema. Defaults to
`sqlite+aiosqlite:///webrecon.db`. Parent directories are created automatically.

### `webrecon modules`
List registered scanner modules in dependency order (name, version, requires,
description).

### `webrecon serve [--host H] [--port P] [--database-url URL]`
Launch the dashboard (FastAPI) at `http://host:port` (default 127.0.0.1:8000).
Reads scans from the database and can start new scans with live progress.

### `webrecon scan URL [options]`
Run a scan against a target you own or are authorized to test. The pipeline is
wired in the vertical-MVP phase; current options:

| Option | Default | Meaning |
|---|---|---|
| `--depth N` | 3 | Max crawl depth. |
| `--max-pages N` | 300 | Max pages to crawl. |
| `--browser` | off | Use the headless browser engine (P9). |
| `--json PATH` | — | Write a JSON report to PATH. |

Planned options as phases land: `--dns --tls --javascript --security --html
--pdf --concurrency --rate --scope-mode --allow-private`.

## Examples

```bash
webrecon init-db
webrecon scan https://example.com --depth 3 --max-pages 300
webrecon scan https://example.com --browser --json report.json
```

> Only scan assets you own or are explicitly authorized to test.
