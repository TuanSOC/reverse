"""FastAPI backend for the WebRecon dashboard (§28/§29).

Serves a read API over persisted scans, starts new scans in the background with
live progress over a WebSocket, and serves the single-file dashboard. It reuses
the same Pipeline + storage as the CLI, so the dashboard and CLI show identical
data.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from .. import modules as _modules  # noqa: F401  register all built-in scanner modules
from ..core.config import ScanConfig, ScopeMode
from ..core.context import CancellationToken
from ..core.logging import configure_logging
from ..pipeline import Pipeline, ScanProgress
from ..reporting.db_report import build_report_from_db
from ..reporting.html_report import render_html
from ..storage import init_db
from ..storage.database import Database
from . import queries

_STATIC = Path(__file__).parent / "static"


class StartScanRequest(BaseModel):
    url: str
    depth: int = 3
    max_pages: int = 300
    browser: bool = False
    allow_private: bool = False
    active: bool = False
    probe: bool = False
    scope_mode: str = "same-domain"
    cookie: str | None = None
    # extra request headers as a "Name: value" list (authenticated scan)
    headers: list[str] = []
    # auto-login: supply credentials and let a headless browser capture the session
    login_url: str | None = None
    login_user: str | None = None
    login_pass: str | None = None


def create_app(database_url: str = "sqlite+aiosqlite:///webrecon.db") -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        db = await init_db(database_url)
        app.state.db = db
        app.state.manager = _SimpleManager(db)
        yield
        await db.dispose()

    app = FastAPI(title="WebRecon", version="0.1.0", lifespan=lifespan)

    def db() -> Database:
        return app.state.db

    @app.get("/api/scans")
    async def scans() -> list[dict]:
        return await queries.list_scans(db())

    @app.post("/api/scans")
    async def start_scan(req: StartScanRequest) -> dict[str, Any]:
        scan_id = await app.state.manager.start(req)
        return {"scan_id": scan_id}

    @app.get("/api/scans/{scan_id}")
    async def overview(scan_id: str) -> dict:
        data = await queries.get_overview(db(), scan_id)
        if data is None:
            raise HTTPException(404, "scan not found")
        return data

    @app.get("/api/scans/{scan_id}/findings")
    async def findings(scan_id: str) -> list[dict]:
        return await queries.get_findings(db(), scan_id)

    @app.get("/api/scans/{scan_id}/assets")
    async def assets(scan_id: str) -> list[dict]:
        return await queries.get_assets(db(), scan_id)

    @app.get("/api/scans/{scan_id}/endpoints")
    async def endpoints(scan_id: str) -> list[dict]:
        return await queries.get_endpoints(db(), scan_id)

    @app.get("/api/scans/{scan_id}/pages")
    async def pages(scan_id: str) -> list[dict]:
        return await queries.get_pages(db(), scan_id)

    @app.get("/api/scans/{scan_id}/technologies")
    async def technologies(scan_id: str) -> list[dict]:
        return await queries.get_technologies(db(), scan_id)

    @app.get("/api/scans/{scan_id}/dns")
    async def dns(scan_id: str) -> list[dict]:
        return await queries.get_dns(db(), scan_id)

    @app.get("/api/scans/{scan_id}/certificates")
    async def certificates(scan_id: str) -> list[dict]:
        return await queries.get_certificates(db(), scan_id)

    @app.get("/api/scans/{scan_id}/forms")
    async def forms(scan_id: str) -> list[dict]:
        return await queries.get_forms(db(), scan_id)

    @app.get("/api/scans/{scan_id}/graph")
    async def graph(scan_id: str) -> dict:
        return await queries.get_graph(db(), scan_id)

    @app.get("/api/scans/{scan_id}/auth-flow")
    async def auth_flow(scan_id: str) -> dict:
        return await queries.get_auth_flow(db(), scan_id)

    @app.get("/api/scans/{scan_id}/diff")
    async def diff(scan_id: str, against: str) -> dict:
        return await queries.diff_scans(db(), scan_id, against)

    @app.get("/api/scans/{scan_id}/report.{fmt}")
    async def report(scan_id: str, fmt: str, min_severity: str | None = None):
        built = await build_report_from_db(db(), scan_id)
        if built is None:
            raise HTTPException(404, "scan not found")
        rep, extras = built
        if min_severity:
            rep = queries.filter_report_min_severity(rep, min_severity)
        if fmt == "json":
            return JSONResponse(rep)
        html = render_html(rep, extras)
        if fmt == "html":
            return HTMLResponse(html)
        if fmt == "pdf":
            from ..reporting.pdf_report import PdfUnavailableError, render_pdf_async

            try:
                pdf = await render_pdf_async(html)
            except PdfUnavailableError as exc:
                raise HTTPException(503, str(exc)) from exc
            return Response(
                pdf, media_type="application/pdf",
                headers={"Content-Disposition": f'inline; filename="{scan_id[:8]}.pdf"'},
            )
        raise HTTPException(400, "format must be json|html|pdf")

    @app.get("/api/scans/{scan_id}/screenshot")
    async def screenshot(scan_id: str):
        path = Path("scans/screenshots") / f"{scan_id}.png"
        if not path.exists():
            raise HTTPException(404, "no screenshot")
        return FileResponse(path, media_type="image/png")

    @app.post("/api/scans/{scan_id}/cancel")
    async def cancel(scan_id: str) -> dict:
        ok = app.state.manager.cancel(scan_id)
        return {"cancelled": ok}

    @app.websocket("/api/scans/{scan_id}/events")
    async def events(ws: WebSocket, scan_id: str) -> None:
        await ws.accept()
        manager = app.state.manager
        q = manager.subscribe(scan_id)
        try:
            for ev in manager.progress(scan_id):  # replay any buffered events
                await ws.send_json(ev)
            # If the scan already finished before this socket connected, emit the
            # terminal event immediately so the client doesn't hang waiting.
            status = manager.status.get(scan_id)
            if status and status != "running":
                await ws.send_json(
                    {"module": "_done", "status": status, "index": 0, "total": 0}
                )
            while True:
                ev = await q.get()
                await ws.send_json(ev)
        except WebSocketDisconnect:
            pass
        finally:
            manager.unsubscribe(scan_id, q)

    @app.get("/")
    async def index() -> FileResponse:
        # The dashboard is a single self-contained file that changes with every
        # release; tell the browser to always revalidate so a stale cached copy
        # never hides new UI (a bare 200 lets the browser serve an old shell).
        return FileResponse(
            _STATIC / "index.html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    return app


class _SimpleManager:
    """Runs scans in the background and streams progress by scan_id.

    Solves the chicken-and-egg (scan_id only known after the context is built)
    by generating the id up front and injecting it into the pipeline.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self._progress: dict[str, list[dict]] = {}
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self._cancels: dict[str, CancellationToken] = {}
        self.status: dict[str, str] = {}

    def cancel(self, scan_id: str) -> bool:
        token = self._cancels.get(scan_id)
        if token is not None and not token.cancelled:
            token.cancel()
            return True
        return False

    async def start(self, req: StartScanRequest) -> str:
        import uuid

        scan_id = str(uuid.uuid4())
        token = CancellationToken()
        self._cancels[scan_id] = token
        cfg = ScanConfig()
        cfg.scope.max_depth = req.depth
        cfg.scope.max_pages = req.max_pages
        cfg.scope.allow_private_targets = req.allow_private
        cfg.browser_mode = req.browser
        cfg.active = req.active
        cfg.probe = req.probe
        if req.login_url:
            cfg.auth.login_url = req.login_url
            cfg.auth.username = req.login_user
            cfg.auth.password = req.login_pass
        if req.cookie:
            cfg.http.cookie = req.cookie
        for h in req.headers:
            name, sep, value = h.partition(":")
            if sep and name.strip():
                cfg.http.auth_headers[name.strip()] = value.strip()
        try:
            cfg.scope.mode = ScopeMode(req.scope_mode)
        except ValueError:
            pass

        def on_progress(p: ScanProgress) -> None:
            ev = {"module": p.module, "index": p.index, "total": p.total, "status": str(p.status)}
            self._progress.setdefault(scan_id, []).append(ev)
            for q in list(self._subscribers.get(scan_id, [])):
                q.put_nowait(ev)

        pipeline = Pipeline(cfg, db=self.db, progress=on_progress)
        self.status[scan_id] = "running"
        asyncio.create_task(self._run(pipeline, req.url, scan_id, token))
        return scan_id

    async def _run(
        self, pipeline: Pipeline, url: str, scan_id: str, token: CancellationToken
    ) -> None:
        try:
            await pipeline.run(url, scan_id=scan_id, cancellation=token)
            self.status[scan_id] = "done"
        except Exception as exc:  # noqa: BLE001
            self.status[scan_id] = f"error: {exc}"
        finally:
            for q in list(self._subscribers.get(scan_id, [])):
                q.put_nowait({"module": "_done", "status": self.status.get(scan_id, "done"),
                              "index": 0, "total": 0})

    def progress(self, scan_id: str) -> list[dict]:
        return self._progress.get(scan_id, [])

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(scan_id, []).append(q)
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        subs = self._subscribers.get(scan_id, [])
        if q in subs:
            subs.remove(q)
