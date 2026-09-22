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
<link rel="canonical" href="/">
<script src="/static/app.js"></script>
</head>
<body>
<a href="/about">About</a>
<a href="/contact">Contact</a>
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
            self._send(200, INDEX_HTML)
        elif path == "/about":
            self._send(200, b"<html><title>About</title></html>")
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
