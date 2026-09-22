# WebRecon — Threat Model

A scanner ingests hostile input (arbitrary HTML, JS, headers, DNS, TLS certs,
redirects) from the very targets it inspects. So the tool must treat **all
target-supplied data as untrusted** and protect *itself* and *the operator*.

## Assets to protect

1. The operator's host (no RCE, no arbitrary file write, no resource exhaustion).
2. The operator's network (no SSRF pivot into internal/localhost services).
3. Scan integrity (no injected/fabricated findings; evidence is real).
4. Secrets the tool touches (cookies, tokens) — never leaked to logs/reports.

## Trust boundaries

```
[ target: fully untrusted ] → HTTP engine → parsers → storage → reports/UI → [ operator ]
                              ^^^^^^^^^^^^   ^^^^^^^   defense-in-depth at each hop
```

## Threats & mitigations

| # | Threat | Vector | Mitigation |
|---|---|---|---|
| T1 | **SSRF** — target redirects/DNS point at internal services or cloud metadata | 30x redirect, DNS rebinding, `file://` | SSRF guard resolves and re-checks the IP on every hop; **a DNS-pinning network backend makes the connect itself the validation point** (connects only to a vetted IP, closing the rebinding TOCTOU) while TLS SNI/verification keep using the origin host; blocks private/loopback/link-local/metadata (incl. IPv4-mapped IPv6); non-http(s) schemes rejected; lab mode explicit but never clears metadata. |
| T2 | **Resource exhaustion / decompression bomb** | huge or gzip-bomb responses | Hard response-size cap (10 MiB), streamed reads with a decompressed-size ceiling, per-module timeouts. |
| T3 | **Stored XSS in report** | malicious title/URL/header rendered into HTML report | Escape all target-derived strings; CSP on the local dashboard; never `innerHTML` raw values. |
| T4 | **Path traversal / arbitrary write** | crafted filenames from sitemap/URLs used as output paths | Never derive filesystem paths from target data; sanitize export filenames; write only under an explicit output dir. |
| T5 | **Code execution** | evaluating target JS in-process | Static analysis only; JS executes solely inside sandboxed Playwright; no `eval`, no dynamic import of fetched content. |
| T6 | **SQL injection** | target strings into queries | SQLAlchemy ORM with bound parameters everywhere; no string-built SQL. |
| T7 | **Secret leakage** | tokens/cookies into logs or reports | Redaction processor in logging; cookie values masked in UI/reports. |
| T8 | **Runaway crawl / unintended DoS of target** | unbounded crawl, aggressive rate | Max depth/pages/requests, conservative rate limit, 429 backoff, per-host concurrency caps. |
| T9 | **Out-of-scope access** | following links to third-party domains | Scope engine gates every request before it is sent. |
| T10 | **Malformed input crash** | broken HTML/headers/cert | Defensive parsing; a module error becomes a `FAILED` result, never a scan crash. |

## Non-goals (accepted risks)

- Not hardened for multi-tenant/hostile-operator use — it is single-user local.
- Does not defend against a malicious operator scanning targets they are not
  authorized to scan; that is a policy/authorization concern, not a technical one.
