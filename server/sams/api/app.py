from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..context import AppContext
from . import admin, agents
from .deps import ensure_admin_token

log = logging.getLogger("sams")
STATIC = Path(__file__).resolve().parent.parent / "web" / "static"


def setup_siem(ctx: AppContext) -> None:
    from ..analysis import enrich_alert, resolve_asset_by_ip
    from ..siem import DetectionEngine, SIEMPipeline, load_rules
    extra = [Path(ctx.settings.siem.extra_rules_dir)] if ctx.settings.siem.extra_rules_dir else None
    engine = DetectionEngine(load_rules(extra), store=ctx.store)
    ctx.extras["siem_engine"] = engine
    ctx.extras["siem"] = SIEMPipeline(ctx.store, engine,
                                      resolve_asset=lambda ip, host="": resolve_asset_by_ip(ctx, ip, host),
                                      on_alert=lambda a: enrich_alert(ctx, a))


def create_app(ctx: AppContext, start_listeners: bool = True) -> FastAPI:
    syslog_handles: list[Any] = []

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        token = ensure_admin_token(ctx)
        if token:
            log.warning("=" * 72)
            log.warning("Generated admin token (shown once, store it safely):\n    %s", token)
            log.warning("=" * 72)
            print(f"\n  SAMS admin token (shown once): {token}\n", flush=True)
        s = ctx.settings.siem
        if start_listeners and ctx.extras.get("siem") and (s.syslog_udp_port or s.syslog_tcp_port):
            from ..siem import serve_syslog
            try:
                syslog_handles.extend(await serve_syslog(ctx.extras["siem"], s.syslog_bind, s.syslog_udp_port,
                                                         s.syslog_tcp_port))
                log.info("syslog listening on %s udp=%s tcp=%s", s.syslog_bind, s.syslog_udp_port, s.syslog_tcp_port)
            except OSError as exc:
                log.error("could not start syslog listener: %s", exc)
        yield
        if syslog_handles:
            from ..siem import stop_syslog
            await stop_syslog(syslog_handles)

    app = FastAPI(title="SuperAwesomeMagicalSecurity", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.ctx = ctx
    setup_siem(ctx)
    app.include_router(agents.router)
    app.include_router(admin.router)
    _mount_ai(app, ctx)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"ok": True, "version": __version__}

    if STATIC.exists():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(STATIC / "index.html")

    @app.exception_handler(Exception)
    async def unhandled(request, exc):  # pragma: no cover
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app


def _mount_ai(app: FastAPI, ctx: AppContext) -> None:
    if not ctx.settings.ai.enabled:
        return
    try:
        if ctx.settings.ai.openai_compat_endpoint:
            from ..ai.openai_compat import router as compat_router
            app.include_router(compat_router(ctx))
        from ..ai import api as ai_api  # dashboard "ask the analyst" endpoints
        app.include_router(ai_api.router(ctx))
    except ImportError as exc:
        log.info("AI endpoints disabled (%s). Install with: pip install 'sams[ai]'", exc)
    if ctx.settings.ai.mcp_http:
        try:
            from ..ai.mcp_server import mount_http
            app.state.mcp = mount_http(app, ctx, path="/mcp")   # manages its own session-manager lifespan
        except ImportError as exc:
            log.info("MCP endpoint disabled (%s)", exc)
