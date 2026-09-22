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

### `webrecon scans [--database-url URL]`
List stored scans (id prefix, target, status, findings, created).

### `webrecon report SCAN_ID [--json P] [--html P] [--pdf P] [--database-url URL]`
Regenerate a report from a stored scan (accepts an 8-char id prefix). With no
export flag, prints a one-line risk summary.

## Extra `scan` options

| Option | Meaning |
|---|---|
| `--config PATH` | Load a base config from a TOML file (flags override). See `webrecon.example.toml`. |
| `--modules a,b` | Run only these modules (+ their deps). |
| `--allow-private` | Lab mode: permit private/loopback targets. |
| `--rate N` | Max requests/second. |
| `--concurrency N` | Max concurrent requests. |
| `--timeout S` | Per-request timeout. |
| `--no-robots` | Ignore robots.txt (authorized only). |
| `--probe` | Probe curated sensitive files (.git/.env/…), content-verified, GET-only. Authorized targets only. |
| `--html P` / `--pdf P` | Also write HTML / PDF report. |
| `--no-db` | Don't persist to the database. |

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
