"""A tiny local HTTP site for integration tests.

Runs a stdlib threaded HTTP server on 127.0.0.1 with an ephemeral port, so tests
exercise the *real* HTTP engine, SSRF guard (in lab mode), rate limiter, and
redirect handling — without ever touching a third-party site (§37).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX_HTML = b"""<!doctype html>
<html><head><title>Mock Site</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="canonical" href="/">
<script src="/static/app.js"></script>
<script src="/wp-content/themes/mock/app.js"></script>
<script src="/static/jquery-1.12.4.min.js"></script>
</head>
<body>
<a href="/about">About</a>
<a href="/contact">Contact</a>
<a href="/admin">Admin</a>
<a href="/api/status">Status</a>
<a href="/api/users">Users</a>
<a href="/api/config">Config</a>
<a href="/api/db-error">DbErr</a>
<a href="/api/search?q=1">Search</a>
<a href="/graphql">GraphQL</a>
<a href="/redir?url=/home">Redir</a>
<a href="/echo?q=hi">Echo</a>
<a href="/api/item?id=1">Item</a>
<a href="https://third-party.example/out">External</a>
<form action="/search" method="get"><input name="q"></form>
</body></html>"""


APP_JS = b"""
var API_BASE = "/api/v1/users";
fetch("/api/admin/settings").then(r => r.json());
var socket = new WebSocket("wss://127.0.0.1/socket");
// AKIAIOSFODNN7EXAMPLE is AWS's public documentation example key (not a secret)
var awsKey = "AKIAIOSFODNN7EXAMPLE";
//# sourceMappingURL=app.js.map
"""

APP_JS_MAP = (
    b'{"version":3,"sources":["src/index.js","src/api/client.js"],'
    b'"sourceRoot":"","names":[],"mappings":"AAAA"}'
)


class _Handler(BaseHTTPRequestHandler):
    # Silence per-request logging to keep test output clean.
    def log_message(self, *args: object) -> None:  # noqa: D401
        return

    def _send(self, code: int, body: bytes, ctype: str = "text/html", extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE")  # TRACE is risky
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            # Deliberately missing security headers; a bare session cookie and a
            # wildcard CORS header, so the P4 analysis modules have findings.
            self._send(
                200,
                INDEX_HTML,
                extra={
                    "Set-Cookie": "sessionid=secretvalue123; Path=/",
                    "Access-Control-Allow-Origin": "*",
                    "Server": "nginx/1.25.3",
                    "X-Powered-By": "PHP/8.1.2",
                },
            )
        elif path == "/about":
            # Deliberate content disclosures for the disclosure detector.
            self._send(200, (
                b'<html><title>About</title>'
                b'Contact admin@mocklab.test - host db.internal - ip 10.0.0.5 - '
                b'System.NullReferenceException at Foo.Bar(Baz.cs:42) '
                b'<a href="/contact">C</a></html>'
            ))
        elif path == "/contact":
            self._send(200, b"<html><title>Contact</title></html>")
        elif path == "/admin":
            # Disallowed by robots.txt; the crawler should not fetch it.
            self._send(200, b"<html><title>Admin</title></html>")
        elif path == "/robots.txt":
            body = (
                "User-agent: *\nDisallow: /admin\n"
                f"Sitemap: http://{self.headers.get('Host', '127.0.0.1')}/sitemap.xml\n"
            ).encode()
            self._send(200, body, ctype="text/plain")
        elif path == "/sitemap.xml":
            host = self.headers.get("Host", "127.0.0.1")
            body = (
                '<?xml version="1.0"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<url><loc>http://{host}/</loc></url>"
                f"<url><loc>http://{host}/about</loc></url>"
                f"<url><loc>http://{host}/only-in-sitemap</loc></url>"
                "</urlset>"
            ).encode()
            self._send(200, body, ctype="application/xml")
        elif path == "/api/status":
            self._send(200, b'{"ok":true,"version":"1"}', ctype="application/json")
        elif path == "/graphql":
            q = self.path.split("?", 1)[1] if "?" in self.path else ""
            if "__schema" in q:
                self._send(
                    200, b'{"data":{"__schema":{"types":[{"name":"Query"}]}}}',
                    ctype="application/json",
                )
            else:
                self._send(200, b'{"data":null}', ctype="application/json")
        elif path == "/api/users":
            # Sensitive path + substantive JSON with token fields (data exposure).
            body = (
                b'[{"id":1,"email":"a@corp.io","token":"tok_abcdef123456","role":"admin"},'
                b'{"id":2,"email":"b@corp.io","token":"tok_bcdefg234567","role":"user"},'
                b'{"id":3,"email":"c@corp.io","token":"tok_cdefgh345678","role":"user"},'
                b'{"id":4,"email":"d@corp.io","token":"tok_defghi456789","role":"user"},'
                b'{"id":5,"email":"e@corp.io","token":"tok_efghij567890","role":"user"}]'
            )
            self._send(200, body, ctype="application/json")
        elif path == "/api/item":
            # Weak input validation: a well-formed small int → 200; any other
            # shape (oversized/non-numeric/array) crashes to 500 with a NON-DB
            # error body. Drives differential input-validation detection.
            from urllib.parse import parse_qs
            qstr = self.path.split("?", 1)[1] if "?" in self.path else ""
            raw = parse_qs(qstr).get("id", [""])[0]
            if raw == "":
                ok = True  # missing param → default listing (baseline is 200)
            else:
                try:
                    n = int(raw)
                    ok = 0 < n < 1000
                except ValueError:
                    ok = False
            if ok:
                self._send(200, b'{"id":1,"name":"widget"}', ctype="application/json")
            else:
                self._send(500, b'{"error":"internal server error"}', ctype="application/json")
        elif path == "/api/config":
            # Public, small, benign JSON -> must NOT trip unauth (low-FP control).
            self._send(200, b'{"version":"1","env":"prod"}', ctype="application/json")
        elif path == "/api/db-error":
            self._send(
                200, b'{"error":"SQLSTATE[42000]: syntax error near \'FROM\'"}',
                ctype="application/json",
            )
        elif path == "/api/search":
            # DB error only when the query carries an unbalanced quote (for P2).
            q = ""
            if "?" in self.path:
                q = self.path.split("?", 1)[1]
            from urllib.parse import unquote
            decoded = unquote(q)
            if decoded.count("'") % 2 == 1:
                self._send(
                    200, b'{"error":"SQLSTATE[42000]: unclosed quotation mark"}',
                    ctype="application/json",
                )
            else:
                self._send(200, b'{"results":[]}', ctype="application/json")
        elif path == "/.git/HEAD":
            # A deliberately-exposed .git for the opt-in sensitive-file probe.
            self._send(200, b"ref: refs/heads/master\n", ctype="text/plain")
        elif path == "/static/app.js":
            self._send(200, APP_JS, ctype="application/javascript")
        elif path == "/static/app.js.map":
            self._send(200, APP_JS_MAP, ctype="application/json")
        elif path == "/wp-content/themes/mock/app.js":
            self._send(200, b"console.log('wp theme');", ctype="application/javascript")
        elif path == "/static/jquery-1.12.4.min.js":
            self._send(200, b"/*! jQuery v1.12.4 */", ctype="application/javascript")
        elif path == "/redir":
            # Vulnerable open redirect: reflects the ?url= param into Location
            # (for active_verify's canary-based confirmation).
            from urllib.parse import parse_qs, unquote
            qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            dest = unquote(qs.get("url", ["/"])[0])
            self._send(302, b"", extra={"Location": dest})
        elif path == "/echo":
            # Reflects the ?q= param unencoded into the HTML body (reflected XSS).
            from urllib.parse import parse_qs, unquote
            qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            val = unquote(qs.get("q", [""])[0])
            self._send(200, f"<html><body><div>{val}</div></body></html>".encode())
        elif path == "/redirect":
            self._send(301, b"", extra={"Location": "/"})
        elif path == "/redirect-external":
            self._send(302, b"", extra={"Location": "https://third-party.example/"})
        elif path == "/redirect-metadata":
            # Redirect toward the cloud metadata IP — must be blocked per-hop.
            self._send(302, b"", extra={"Location": "http://169.254.169.254/latest/"})
        elif path == "/weird-headers":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Weird", "val\tue")
            self.send_header("Set-Cookie", "a=1")
            self.send_header("Set-Cookie", "b=2; Secure")  # duplicate header
            self.end_headers()
            self.wfile.write(b"<html><title>ok</title></html>")
        elif path == "/big":
            # 2 MiB body to exercise the response-size cap when configured small.
            self._send(200, b"A" * (2 * 1024 * 1024), ctype="application/octet-stream")
        elif path == "/set-cookie":
            self._send(200, b"ok", extra={"Set-Cookie": "session=secretvalue; Path=/"})
        else:
            self._send(404, b"<html><title>404</title></html>")


@contextmanager
def run_mock_site() -> Iterator[str]:
    """Start the mock site; yield its base URL; shut down on exit."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
