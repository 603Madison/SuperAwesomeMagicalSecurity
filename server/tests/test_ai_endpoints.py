"""OpenAI-compatible endpoint and MCP server tests (no network)."""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sams.ai.mcp_server import build_mcp, mount_http
from sams.ai.openai_compat import router
from sams.config import AIProviderSettings

from test_ai_support import ADMIN_TOKEN, FakeProvider, answer, call, make_ctx

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
PROVIDERS = [AIProviderSettings(name="claude", type="anthropic", model="claude-opus-5-5"),
             AIProviderSettings(name="local", type="ollama", model="llama3.1", locality="local")]


def _app(ctx, scripts):
    used = []

    def factory(name):
        used.append(name)
        return FakeProvider(scripts.pop(0) if scripts else [answer("default")], locality="local")

    app = FastAPI()
    app.include_router(router(ctx, provider_factory=factory))
    return app, used


# --------------------------------------------------------------------------- #
# OpenAI-compatible
# --------------------------------------------------------------------------- #
def test_models_and_auth(tmp_path):
    ctx = make_ctx(tmp_path, providers=PROVIDERS)
    app, _ = _app(ctx, [])
    c = TestClient(app)
    assert c.get("/v1/models").status_code == 401
    assert c.get("/v1/models", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ids = [m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]]
    assert ids == ["sams-analyst", "sams-analyst-claude", "sams-analyst-local"]
    ctx.extras["mcp_tokens"] = ["librechat-token"]
    assert c.get("/v1/models", headers={"Authorization": "Bearer librechat-token"}).status_code == 200


def test_chat_completion_non_streaming(tmp_path):
    ctx = make_ctx(tmp_path, providers=PROVIDERS)
    app, used = _app(ctx, [[call("list_findings", {"severity": "critical"}), answer("Patch **openssl** first.")]])
    c = TestClient(app)
    r = c.post("/v1/chat/completions", headers=AUTH, json={
        "model": "sams-analyst-local",
        "messages": [{"role": "system", "content": "Be brief."},
                     {"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"},
                     {"role": "user", "content": [{"type": "text", "text": "What should I fix?"}]}],
        "tools": [{"type": "function", "function": {"name": "ignored"}}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["object"] == "chat.completion" and body["model"] == "sams-analyst-local"
    assert body["choices"][0]["message"] == {"role": "assistant", "content": "Patch **openssl** first."}
    assert body["choices"][0]["finish_reason"] == "stop"
    assert body["usage"]["total_tokens"] > 0 and body["sams"]["tool_calls"] == ["list_findings"]
    assert used == ["local"]


def test_chat_completion_streaming(tmp_path):
    ctx = make_ctx(tmp_path, providers=PROVIDERS)
    app, used = _app(ctx, [[call("list_alerts", {}), answer("One open alert: brute force on web01.")]])
    c = TestClient(app)
    with c.stream("POST", "/v1/chat/completions", headers=AUTH, json={
            "model": "sams-analyst", "stream": True, "stream_options": {"include_usage": True},
            "messages": [{"role": "user", "content": "alerts?"}]}) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        lines = [l for l in r.iter_lines() if l]
    assert lines[-1] == "data: [DONE]"
    chunks = [json.loads(l[6:]) for l in lines[:-1]]
    assert chunks[0]["choices"][0]["delta"]["role"] == "assistant"
    content = "".join(ch["choices"][0]["delta"].get("content", "") for ch in chunks if ch["choices"])
    assert "`list_alerts`" in content and content.endswith("One open alert: brute force on web01.")
    assert any(ch["choices"] and ch["choices"][0]["finish_reason"] == "stop" for ch in chunks)
    assert chunks[-1]["usage"]["completion_tokens"] > 0
    assert used == [None]       # default provider


def test_chat_completion_errors(tmp_path):
    ctx = make_ctx(tmp_path, providers=PROVIDERS)
    app, _ = _app(ctx, [])
    c = TestClient(app)
    assert c.post("/v1/chat/completions", headers=AUTH,
                  json={"model": "gpt-4o", "messages": [{"role": "user", "content": "x"}]}).status_code == 404
    assert c.post("/v1/chat/completions", headers=AUTH,
                  json={"model": "sams-analyst-nope", "messages": [{"role": "user", "content": "x"}]}).status_code == 404
    assert c.post("/v1/chat/completions", headers=AUTH,
                  json={"model": "sams-analyst", "messages": []}).status_code == 400
    assert c.post("/v1/chat/completions", headers=AUTH, json={
        "model": "sams-analyst", "messages": [{"role": "assistant", "content": "x"}]}).status_code == 400


def test_no_tokens_configured_rejects(tmp_path):
    ctx = make_ctx(tmp_path, providers=PROVIDERS)
    ctx.settings.admin_token = None
    app, _ = _app(ctx, [])
    r = TestClient(app).get("/v1/models", headers=AUTH)
    assert r.status_code == 401 and "no API tokens" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# MCP
# --------------------------------------------------------------------------- #
def test_build_mcp_tools_resources_prompts(tmp_path):
    ctx = make_ctx(tmp_path)
    srv = build_mcp(ctx)

    async def run():
        tools = {t.name: t for t in await srv.list_tools()}
        assert {"posture_summary", "list_findings", "blast_radius", "attack_paths", "remediation_plan",
                "search_events", "get_alert", "firewall_overview", "external_exposure"} <= set(tools)
        assert "create_patch_task" not in tools
        lf = tools["list_findings"]
        assert lf.input_schema["properties"]["severity"]["enum"][-1] == "critical"
        assert lf.annotations.read_only_hint is True
        res = await srv.call_tool("list_findings", {"severity": "critical"})
        data = json.loads(res.content[0].text)
        assert data["total"] == 1 and data["findings"][0]["title"].startswith("openssl")
        resources = {str(r.uri) for r in await srv.list_resources()}
        assert {"sams://posture", "sams://findings/open", "sams://assets"} <= resources
        contents = list(await srv.read_resource("sams://posture"))
        assert json.loads(contents[0].content)["open_findings"] == 3
        prompts = {p.name for p in await srv.list_prompts()}
        assert prompts == {"triage_alert", "harden_host", "weekly_report"}
        got = await srv.get_prompt("triage_alert", {"alert_id": "7"})
        assert "alert 7" in got.messages[0].content.text

    asyncio.run(run())


def test_build_mcp_write_tools_when_enabled(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.extras["allow_write_tools"] = True

    async def run():
        tools = {t.name: t for t in await build_mcp(ctx).list_tools()}
        assert tools["create_patch_task"].annotations.destructive_hint is True
        assert tools["acknowledge_alert"].annotations.read_only_hint is False

    asyncio.run(run())


def _rpc(c, method, params=None, id_=1, headers=None):
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
         "MCP-Protocol-Version": "2025-06-18", **(headers if headers is not None else AUTH)}
    return c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}})


def test_mcp_over_streamable_http(tmp_path):
    ctx = make_ctx(tmp_path)
    app = FastAPI()

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    mount_http(app, ctx, "/mcp")
    with TestClient(app) as c:
        assert c.get("/healthz").json() == {"ok": True}
        assert _rpc(c, "tools/list", headers={}).status_code == 401
        init = _rpc(c, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "pytest", "version": "1"}})
        assert init.status_code == 200, init.text
        assert init.json()["result"]["serverInfo"]["name"] == "sams"
        listed = _rpc(c, "tools/list", id_=2)
        assert listed.status_code == 200, listed.text
        names = {t["name"] for t in listed.json()["result"]["tools"]}
        assert "posture_summary" in names and "create_patch_task" not in names
        called = _rpc(c, "tools/call", {"name": "list_assets", "arguments": {}}, id_=3)
        result = called.json()["result"]
        assert result.get("isError") in (None, False)
        assert json.loads(result["content"][0]["text"])["total"] == 2
        err = _rpc(c, "tools/call", {"name": "get_asset", "arguments": {"asset_id": "missing"}}, id_=4)
        assert err.json()["result"]["isError"] is True


def test_mcp_with_official_client(tmp_path):
    """End-to-end with the mcp client library over an in-process ASGI transport."""
    pytest.importorskip("mcp.client.streamable_http")
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    ctx = make_ctx(tmp_path)
    app = FastAPI()
    mount_http(app, ctx, "/mcp")

    async def run():
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://sams.test", headers=AUTH) as hc:
                async with streamable_http_client("http://sams.test/mcp", http_client=hc) as streams:
                    read, write = streams[0], streams[1]
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        assert "attack_paths" in {t.name for t in tools.tools}
                        res = await session.call_tool("posture_summary", {})
                        assert json.loads(res.content[0].text)["assets"] == 2

    try:
        asyncio.run(run())
    except TypeError as exc:   # client API differences across mcp versions
        pytest.skip(f"mcp client API mismatch: {exc}")
