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
</head>
<body>
<a href="/about">About</a>
<a href="/contact">Contact</a>
<a href="/admin">Admin</a>
<a href="https://third-party.example/out">External</a>
<form action="/search" method="get"><input name="q"></form>
</body></html>"""


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
            self._send(200, b'<html><title>About</title><a href="/contact">C</a></html>')
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
        elif path == "/redirect":
            self._send(301, b"", extra={"Location": "/"})
        elif path == "/redirect-external":
            self._send(302, b"", extra={"Location": "https://third-party.example/"})
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
