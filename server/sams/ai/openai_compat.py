"""OpenAI-compatible chat endpoint backed by the SAMS analyst.

Lets LibreChat (custom endpoint), Open WebUI, Jan, Msty, Continue, or any OpenAI client
chat with the SAMS security analyst, which uses the SAMS tools behind the scenes.

    GET  /v1/models            -> sams-analyst (default provider) + sams-analyst-<provider name>
    POST /v1/chat/completions  -> OpenAI request/response shapes, incl. ``stream: true`` (SSE)

Auth: ``Authorization: Bearer <token>``; accepted tokens are the SAMS admin token plus
``settings.ai.mcp_tokens`` / ``ctx.extras["mcp_tokens"]`` (shared with the MCP endpoint).
Client-supplied ``tools`` are ignored: the analyst uses SAMS tools only.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable, Iterator, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse

from .analyst import AnalystResult, SecurityAnalyst
from .mcp_server import accepted_tokens, check_bearer
from .providers import LLMProvider, ProviderError, find_provider_settings, get_provider

ProviderFactory = Callable[[Optional[str]], LLMProvider]
MODEL_PREFIX = "sams-analyst"


def _default_factory(ctx: Any) -> ProviderFactory:
    cache: dict[str, LLMProvider] = {}

    def factory(name: Optional[str]) -> LLMProvider:
        ps = find_provider_settings(ctx.settings.ai, name)
        if ps.name not in cache:
            cache[ps.name] = get_provider(ps)
        return cache[ps.name]
    return factory


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") in ("text", None))
    return ""


def _error(status: int, message: str, typ: str = "invalid_request_error") -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"message": message, "type": typ, "code": status}})


def router(ctx: Any, provider_factory: Optional[ProviderFactory] = None, analyst_cls: type = SecurityAnalyst) -> APIRouter:
    factory = provider_factory or _default_factory(ctx)
    r = APIRouter(tags=["openai-compatible"])

    def auth(authorization: Optional[str] = Header(default=None)) -> None:
        if not accepted_tokens(ctx):
            raise HTTPException(status_code=401, detail="no API tokens configured (set admin_token or ai.mcp_tokens)")
        if not check_bearer(ctx, authorization):
            raise HTTPException(status_code=401, detail="invalid or missing bearer token",
                                headers={"WWW-Authenticate": "Bearer"})

    def _provider_names() -> list[str]:
        return [p.name for p in ctx.settings.ai.providers]

    @r.get("/v1/models", dependencies=[Depends(auth)])
    def models() -> dict[str, Any]:
        ids = [MODEL_PREFIX] + [f"{MODEL_PREFIX}-{n}" for n in _provider_names()]
        return {"object": "list",
                "data": [{"id": i, "object": "model", "created": 0, "owned_by": "sams"} for i in ids]}

    @r.post("/v1/chat/completions", dependencies=[Depends(auth)])
    def chat_completions(body: dict[str, Any]) -> Any:
        if not ctx.settings.ai.enabled:
            return _error(503, "AI features are disabled (ai.enabled: false)", "service_unavailable")
        model = str(body.get("model") or MODEL_PREFIX)
        if model == MODEL_PREFIX:
            pname: Optional[str] = None
        elif model.startswith(MODEL_PREFIX + "-"):
            pname = model[len(MODEL_PREFIX) + 1:]
            if ctx.settings.ai.providers and pname not in _provider_names():
                return _error(404, f"model {model!r} not found", "model_not_found")
        else:
            return _error(404, f"model {model!r} not found; use one of GET /v1/models", "model_not_found")

        messages = body.get("messages") or []
        if not isinstance(messages, list) or not messages:
            return _error(400, "messages must be a non-empty list")
        # last user message is the question; earlier user/assistant turns are history;
        # client system prompts are folded in as instructions to the analyst
        system_bits = [_text(m.get("content")) for m in messages if m.get("role") in ("system", "developer")]
        convo = [m for m in messages if m.get("role") in ("user", "assistant")]
        if not convo or convo[-1].get("role") != "user":
            return _error(400, "the last message must come from the user")
        question = _text(convo[-1].get("content"))
        if system_bits and any(system_bits):
            question = "Additional instructions from the chat client:\n" + "\n".join(b for b in system_bits if b) + \
                       "\n\n" + question
        history = [{"role": m["role"], "content": _text(m.get("content"))} for m in convo[:-1]]

        try:
            provider = factory(pname)
        except LookupError as exc:
            return _error(503, str(exc), "service_unavailable")
        analyst = analyst_cls(ctx, provider)
        cid = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        created = int(time.time())

        if body.get("stream"):
            show_progress = body.get("sams_progress", True)
            return StreamingResponse(_stream(analyst, question, history, cid, created, model, show_progress,
                                             bool((body.get("stream_options") or {}).get("include_usage"))),
                                     media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
        try:
            res = analyst.ask(question, history)
        except ProviderError as exc:
            return _error(502, str(exc), "upstream_error")
        return {
            "id": cid, "object": "chat.completion", "created": created, "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": res.text},
                         "finish_reason": "stop" if res.stop_reason != "max_tokens" else "length"}],
            "usage": _usage(res),
            "sams": {"provider": res.provider, "tool_calls": [c["name"] for c in res.tool_calls_log],
                     "iterations": res.iterations},
        }

    return r


def _usage(res: AnalystResult) -> dict[str, int]:
    p = int(res.usage.get("input_tokens", 0)) + int(res.usage.get("cache_read_input_tokens", 0)) + \
        int(res.usage.get("cache_creation_input_tokens", 0))
    c = int(res.usage.get("output_tokens", 0))
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}


def _chunk(cid: str, created: int, model: str, delta: dict[str, Any], finish: Optional[str] = None) -> str:
    payload = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
               "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
    return f"data: {json.dumps(payload)}\n\n"


def _stream(analyst: SecurityAnalyst, question: str, history: list[dict[str, Any]], cid: str, created: int,
            model: str, show_progress: bool, include_usage: bool) -> Iterator[str]:
    yield _chunk(cid, created, model, {"role": "assistant", "content": ""})
    final: Optional[AnalystResult] = None
    for ev in analyst.ask_stream(question, history):
        if ev["type"] == "tool_call" and show_progress:
            yield _chunk(cid, created, model, {"content": f"_Looking up `{ev['name']}`…_\n\n"})
        elif ev["type"] == "final":
            final = ev["result"]
            text = ev["text"] or ""
            # emit in modest pieces so clients render progressively
            for i in range(0, len(text), 400):
                yield _chunk(cid, created, model, {"content": text[i:i + 400]})
        elif ev["type"] == "error":
            yield _chunk(cid, created, model, {"content": f"\n\n**SAMS analyst error:** {ev['error']}"})
    yield _chunk(cid, created, model, {}, finish="stop")
    if include_usage and final is not None:
        payload = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
                   "choices": [], "usage": _usage(final)}
        yield f"data: {json.dumps(payload)}\n\n"
    yield "data: [DONE]\n\n"
