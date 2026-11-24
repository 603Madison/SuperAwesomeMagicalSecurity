"""MCP server exposing the SAMS tool registry to any MCP client
(Claude Desktop, Claude Code, LibreChat, Cursor, Open WebUI via mcpo, ...).

* ``run_stdio(ctx)``: stdio transport (``sams mcp`` / client-launched process)
* ``mount_http(app, ctx, path="/mcp")``: streamable HTTP on the SAMS FastAPI app, protected
  by bearer tokens (the admin token, ``settings.ai.mcp_tokens`` or ``ctx.extras["mcp_tokens"]``)

Write tools are only listed when ``ai.allow_write_tools`` is enabled and are annotated as
destructive so clients prompt the user before calling them.

Data sent over MCP is NOT pseudonymized: the MCP client decides which model sees it.
Use a local model in the client, or the built-in analyst with redaction, if that matters.
"""
from __future__ import annotations

import inspect
import json
import logging
import secrets
from contextlib import asynccontextmanager
from typing import Any, Optional

import anyio

from .tools import ToolDef, call_tool, list_tools

log = logging.getLogger("sams.ai.mcp")

INSTRUCTIONS = (
    "SuperAwesomeMagicalSecurity (SAMS) security posture data: assets, vulnerabilities and hardening findings, "
    "firewall policy, external exposure seen from the internet, SIEM events/alerts, attack paths and blast "
    "radius, and a prioritized remediation plan. Start with posture_summary or list_findings; use "
    "attack_paths / blast_radius to judge impact and remediation_plan for what to fix first."
)

_JSON_TYPES: dict[str, Any] = {"string": str, "integer": int, "number": float, "boolean": bool,
                               "array": list, "object": dict}


def _tool_fn(ctx: Any, td: ToolDef):
    """Build an async function whose signature mirrors the tool's JSON schema, so the MCP
    SDK validates arguments; the advertised schema is then replaced with the original one
    (descriptions, enums, defaults)."""
    from mcp.server.mcpserver.exceptions import ToolError

    props = td.input_schema.get("properties", {})
    required = set(td.input_schema.get("required", []))
    params = []
    annotations: dict[str, Any] = {}
    for name, spec in props.items():
        typ = _JSON_TYPES.get(spec.get("type", ""), Any)
        if name in required:
            params.append(inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, annotation=typ))
            annotations[name] = typ
        else:
            ann = Optional[typ]
            params.append(inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, annotation=ann, default=None))
            annotations[name] = ann

    async def fn(**kwargs: Any) -> str:
        args = {k: v for k, v in kwargs.items() if v is not None}
        try:
            result = await anyio.to_thread.run_sync(lambda: call_tool(ctx, td.name, args))
        except Exception as exc:   # surfaced to the client as an is_error tool result
            raise ToolError(str(exc)) from exc
        return json.dumps(result, default=str, indent=1)

    fn.__signature__ = inspect.Signature(params, return_annotation=str)  # type: ignore[attr-defined]
    fn.__annotations__ = {**annotations, "return": str}
    fn.__name__ = td.name
    fn.__doc__ = td.description
    return fn


def build_mcp(ctx: Any):
    """Return an ``mcp.server.mcpserver.MCPServer`` with SAMS tools, resources and prompts."""
    from mcp.server.mcpserver import MCPServer
    from mcp.server.mcpserver.tools.base import Tool
    from mcp_types import ToolAnnotations

    mcp_tools = []
    for td in list_tools(ctx):
        t = Tool.from_function(
            _tool_fn(ctx, td), name=td.name, description=td.description, structured_output=False,
            annotations=ToolAnnotations(
                title=td.name.replace("_", " ").title(),
                readOnlyHint=not td.write, destructiveHint=td.write, idempotentHint=not td.write,
                openWorldHint=False),
        )
        t.parameters = td.input_schema
        mcp_tools.append(t)

    from .. import __version__
    srv = MCPServer("sams", title="SuperAwesomeMagicalSecurity", instructions=INSTRUCTIONS,
                    version=__version__, tools=mcp_tools)

    async def _json(name: str, args: dict[str, Any]) -> str:
        result = await anyio.to_thread.run_sync(lambda: call_tool(ctx, name, args, include_write=False))
        return json.dumps(result, default=str, indent=1)

    @srv.resource("sams://posture", name="posture", mime_type="application/json",
                  description="Posture score, grades and finding counts")
    async def posture_resource() -> str:
        return await _json("posture_summary", {})

    @srv.resource("sams://findings/open", name="open_findings", mime_type="application/json",
                  description="Open findings, most severe first (top 200)")
    async def findings_resource() -> str:
        return await _json("list_findings", {"limit": 200})

    @srv.resource("sams://assets", name="assets", mime_type="application/json",
                  description="All assets with criticality and open finding counts")
    async def assets_resource() -> str:
        return await _json("list_assets", {"limit": 500})

    @srv.prompt(name="triage_alert", description="Triage a SIEM alert with context and blast radius")
    def triage_alert(alert_id: str) -> str:
        return (f"Triage SAMS alert {alert_id}. Call get_alert, then search_events for wider context, get_asset "
                "for the host and blast_radius on it. Give a verdict (likely benign / suspicious / likely "
                "malicious) with confidence and reasoning, containment steps if warranted, and follow-ups.")

    @srv.prompt(name="harden_host", description="Hardening plan for one host")
    def harden_host(asset_id: str) -> str:
        return (f"Build a hardening plan for SAMS asset {asset_id}. Use get_asset, list_findings (asset_id), "
                "blast_radius (what this host exposes if compromised) and attack_paths targeting it. Order "
                "steps by risk reduction; give exact commands/config with side effects and verification.")

    @srv.prompt(name="weekly_report", description="Weekly security report")
    def weekly_report() -> str:
        return ("Write this week's security report from SAMS: posture_summary, new/critical findings "
                "(list_findings), external_exposure, list_alerts (last 7 days via search_events where useful), "
                "attack_paths from the internet, and the top items of remediation_plan with owners/effort.")

    return srv


def run_stdio(ctx: Any) -> None:
    """Serve MCP over stdio. Logs must go to stderr: stdout carries the protocol."""
    logging.basicConfig(level=logging.WARNING)
    build_mcp(ctx).run("stdio")


# --------------------------------------------------------------------------- #
# Streamable HTTP mounted inside the SAMS FastAPI app
# --------------------------------------------------------------------------- #
def accepted_tokens(ctx: Any) -> list[str]:
    toks: list[str] = []
    s = getattr(ctx, "settings", None)
    if s is not None and s.admin_token:
        toks.append(s.admin_token)
    for src in (getattr(getattr(s, "ai", None), "mcp_tokens", None), (getattr(ctx, "extras", None) or {}).get("mcp_tokens")):
        if src:
            toks.extend(t for t in src if t)
    return toks


def check_bearer(ctx: Any, authorization: Optional[str]) -> bool:
    if not authorization or not authorization.lower().startswith("bearer "):
        return False
    presented = authorization[7:].strip()
    return any(secrets.compare_digest(presented.encode(), t.encode()) for t in accepted_tokens(ctx))


class _BearerAuth:
    """Minimal ASGI wrapper enforcing a bearer token before the MCP transport sees the request."""

    def __init__(self, app: Any, ctx: Any):
        self.app = app
        self.ctx = ctx

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if not check_bearer(self.ctx, headers.get("authorization")):
            body = json.dumps({"error": "unauthorized", "detail": "Bearer token required"}).encode()
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"www-authenticate", b'Bearer realm="sams-mcp"')]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


def mount_http(app: Any, ctx: Any, path: str = "/mcp") -> Any:
    """Serve MCP (streamable HTTP, stateless, JSON responses) at ``path`` on a FastAPI/Starlette app.

    The MCP session manager must run inside the app's lifespan, so the app's existing
    lifespan context is wrapped. Returns the MCPServer instance."""
    from mcp.server.streamable_http_manager import StreamableHTTPASGIApp
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.routing import Route

    srv = build_mcp(ctx)
    # builds the session manager; we route to it directly instead of mounting the sub-app so
    # that `path` matches exactly (no trailing-slash redirect) and auth wraps the transport.
    srv.streamable_http_app(
        streamable_http_path="/", stateless_http=True, json_response=True,
        # SAMS sits behind its own auth and usually a reverse proxy; Host-header pinning is left to
        # the proxy. Bearer auth above blocks DNS-rebinding style access from browsers.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host="0.0.0.0",
    )
    handler = _BearerAuth(StreamableHTTPASGIApp(srv.session_manager), ctx)
    for p in {path.rstrip("/") or "/", path.rstrip("/") + "/"}:
        app.router.routes.append(Route(p, endpoint=handler, include_in_schema=False))

    original = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(a: Any):
        async with original(a) as state:
            async with srv.session_manager.run():
                yield state

    app.router.lifespan_context = lifespan
    return srv


def main(argv: Optional[list[str]] = None) -> None:
    """``python -m sams.ai.mcp_server [--config sams.yaml]``: stdio MCP server for desktop clients."""
    import argparse

    from ..config import load_settings
    from ..context import AppContext

    ap = argparse.ArgumentParser(description="SAMS MCP server (stdio)")
    ap.add_argument("--config", help="path to sams.yaml (default: $SAMS_CONFIG or ./sams.yaml)")
    ns = ap.parse_args(argv)
    run_stdio(AppContext.create(load_settings(ns.config)))


if __name__ == "__main__":
    main()
