"""Provider request/response translation, driven through the real SDK clients with
mocked HTTP transports (no network)."""
from __future__ import annotations

import json

import httpx
import httpx2
import pytest

from sams.ai.analyst import SecurityAnalyst
from sams.ai.providers import (AnthropicProvider, ChatMessage, OllamaProvider, OpenAIProvider, ProviderError,
                               ToolSpec, available_providers, find_provider_settings, get_provider)
from sams.config import AIProviderSettings, AISettings

from test_ai_support import anthropic_stream, make_ctx

TOOLS = [ToolSpec("list_assets", "List assets", {"type": "object", "properties": {"kind": {"type": "string"}}})]


class Recorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests: list[dict] = []
        self.headers: list = []
        self.urls: list[str] = []

    def __call__(self, request):
        self.requests.append(json.loads(request.content) if request.content else {})
        self.headers.append(request.headers)
        self.urls.append(str(request.url))
        status, body, ctype = self.responses.pop(0)
        return (httpx2 if isinstance(request, httpx2.Request) else httpx).Response(
            status, content=body, headers={"content-type": ctype})


# --------------------------------------------------------------------------- #
# Anthropic
# --------------------------------------------------------------------------- #
def _anthropic(rec, **kw):
    settings = AIProviderSettings(name="claude", type="anthropic", model=kw.pop("model", "claude-opus-5-5"),
                                  api_key_env="SAMS_TEST_ANTHROPIC_KEY", **kw)
    return get_provider(settings, http_client=httpx2.Client(transport=httpx2.MockTransport(rec)))


def test_anthropic_tool_loop_replays_thinking(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMS_TEST_ANTHROPIC_KEY", "sk-ant-test")
    rec = Recorder([
        (200, anthropic_stream([
            {"type": "thinking", "thinking": "", "signature": "sig-abc"},
            {"type": "text", "text": "Let me look."},
            {"type": "tool_use", "id": "toolu_1", "name": "list_assets", "input": {"kind": "host"}},
            {"type": "tool_use", "id": "toolu_2", "name": "list_alerts", "input": {}},
        ], "tool_use"), "text/event-stream"),
        (200, anthropic_stream([{"type": "text", "text": "Two hosts, one alert."}], "end_turn"),
         "text/event-stream"),
    ])
    prov = _anthropic(rec)
    assert isinstance(prov, AnthropicProvider)
    ctx = make_ctx(tmp_path)
    res = SecurityAnalyst(ctx, prov, redact=False).ask("inventory?")
    assert res.text == "Two hosts, one alert."
    assert res.usage["output_tokens"] == 84 and res.usage["cache_read_input_tokens"] == 100

    first, second = rec.requests
    h = rec.headers[0]
    assert h.get("x-api-key") == "sk-ant-test" or h.get("authorization") == "Bearer sk-ant-test"
    assert "server-side-fallback-2026-07-01" in h.get("anthropic-beta", "")
    assert first["model"] == "claude-opus-5-5"
    assert first["fallbacks"] == "default"
    assert first["thinking"] == {"type": "adaptive"}
    assert first["output_config"] == {"effort": "high"}
    assert first["stream"] is True
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert first["cache_control"] == {"type": "ephemeral"}
    assert "temperature" not in first and "tool_choice" not in first
    assert all(t["eager_input_streaming"] is True for t in first["tools"])
    assert {t["name"] for t in first["tools"]} >= {"list_assets", "posture_summary"}

    msgs = second["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assistant = msgs[1]["content"]
    # assistant content replayed unchanged, thinking block (with signature) first
    assert assistant[0]["type"] == "thinking" and assistant[0]["signature"] == "sig-abc"
    assert [b["type"] for b in assistant] == ["thinking", "text", "tool_use", "tool_use"]
    results = msgs[2]["content"]
    assert [r["type"] for r in results] == ["tool_result", "tool_result"]      # one user message
    assert [r["tool_use_id"] for r in results] == ["toolu_1", "toolu_2"]
    assert json.loads(results[0]["content"])["total"] == 2


def test_anthropic_refusal_and_gateway_options(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMS_TEST_ANTHROPIC_KEY", "k")
    rec = Recorder([(200, anthropic_stream([], "refusal", stop_details={
        "type": "refusal", "category": "cyber", "explanation": "declined"}), "text/event-stream")])
    prov = _anthropic(rec, base_url="https://gateway.example/anthropic")
    turn = prov.chat("sys", [ChatMessage(role="user", content="hi")], TOOLS)
    assert turn.stop_reason == "refusal" and turn.refusal["category"] == "cyber"
    req = rec.requests[0]
    assert "fallbacks" not in req                                  # gateways: no beta params by default
    assert "eager_input_streaming" not in req["tools"][0]
    assert rec.urls[0].startswith("https://gateway.example/anthropic")


def test_anthropic_older_model_and_errors(monkeypatch):
    monkeypatch.setenv("SAMS_TEST_ANTHROPIC_KEY", "k")
    rec = Recorder([(401, json.dumps({"type": "error", "error": {"type": "authentication_error",
                                                                 "message": "bad key"}}).encode(), "application/json")])
    prov = _anthropic(rec, model="claude-haiku-4-5")
    params = prov.build_params("s", [ChatMessage(role="user", content="x")], TOOLS)
    assert "thinking" not in params and "output_config" not in params and "fallbacks" not in params
    with pytest.raises(ProviderError, match="authentication"):
        prov.chat("s", [ChatMessage(role="user", content="x")], TOOLS)


# --------------------------------------------------------------------------- #
# OpenAI / OpenAI-compatible
# --------------------------------------------------------------------------- #
def _oa_response(message: dict, finish: str) -> bytes:
    return json.dumps({"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-test",
                       "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                       "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}}).encode()


def test_openai_tool_loop(tmp_path, monkeypatch):
    monkeypatch.setenv("SAMS_TEST_OPENAI_KEY", "sk-test")
    rec = Recorder([
        (200, _oa_response({"role": "assistant", "content": None, "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "list_findings",
                                                              "arguments": "{\"severity\": \"critical\"}"}},
            {"id": "call_2", "type": "function", "function": {"name": "get_finding", "arguments": "{not json"}},
        ]}, "tool_calls"), "application/json"),
        (200, _oa_response({"role": "assistant", "content": "Patch openssl."}, "stop"), "application/json"),
    ])
    settings = AIProviderSettings(name="gpt", type="openai", model="gpt-test", api_key_env="SAMS_TEST_OPENAI_KEY")
    prov = get_provider(settings, http_client=httpx2.Client(transport=httpx2.MockTransport(rec)))
    assert isinstance(prov, OpenAIProvider)
    res = SecurityAnalyst(make_ctx(tmp_path), prov, redact=False).ask("top risk?")
    assert res.text == "Patch openssl." and res.usage == {"input_tokens": 22, "output_tokens": 6}
    first, second = rec.requests
    assert rec.headers[0]["authorization"] == "Bearer sk-test"
    assert first["messages"][0]["role"] == "system"
    assert first["max_completion_tokens"] == settings.max_tokens
    assert first["tools"][0]["type"] == "function" and "parameters" in first["tools"][0]["function"]
    roles = [m["role"] for m in second["messages"]]
    assert roles == ["system", "user", "assistant", "tool", "tool"]
    assert second["messages"][2]["tool_calls"][0]["id"] == "call_1"
    tool_msgs = second["messages"][3:]
    assert json.loads(tool_msgs[0]["content"])["total"] == 1
    assert tool_msgs[1]["content"].startswith("ERROR:") and "INVALID_JSON" in tool_msgs[1]["content"]


def test_openai_compatible_local_server_needs_no_key():
    rec = Recorder([(200, _oa_response({"role": "assistant", "content": "hi"}, "stop"), "application/json")])
    settings = AIProviderSettings(name="lmstudio", type="openai_compatible", model="qwen2.5-7b",
                                  base_url="http://lmstudio.local:1234/v1", locality="local")
    prov = get_provider(settings, http_client=httpx2.Client(transport=httpx2.MockTransport(rec)))
    turn = prov.chat("s", [ChatMessage(role="user", content="x")], [])
    assert turn.text == "hi" and turn.stop_reason == "end_turn"
    assert rec.urls[0] == "http://lmstudio.local:1234/v1/chat/completions"
    assert rec.requests[0]["max_tokens"] == settings.max_tokens and "tools" not in rec.requests[0]


# --------------------------------------------------------------------------- #
# Ollama
# --------------------------------------------------------------------------- #
def test_ollama_native_tools(tmp_path):
    rec = Recorder([
        (200, json.dumps({"model": "llama3.1", "done": True, "done_reason": "stop", "prompt_eval_count": 30,
                          "eval_count": 8, "message": {"role": "assistant", "content": "", "tool_calls": [
                              {"function": {"name": "list_alerts", "arguments": {"status": "open"}}}]}}).encode(),
         "application/json"),
        (200, json.dumps({"model": "llama3.1", "done": True, "done_reason": "stop",
                          "message": {"role": "assistant", "content": "1 open alert"}}).encode(), "application/json"),
    ])
    settings = AIProviderSettings(name="local", type="ollama", model="llama3.1", locality="local")
    prov = get_provider(settings, transport=httpx.MockTransport(rec))
    assert isinstance(prov, OllamaProvider)
    res = SecurityAnalyst(make_ctx(tmp_path), prov).ask("alerts?")
    assert res.text == "1 open alert" and res.tool_calls_log[0]["arguments"] == {"status": "open"}
    assert rec.urls[0] == "http://localhost:11434/api/chat"
    first, second = rec.requests
    assert first["stream"] is False and first["options"]["num_predict"] == settings.max_tokens
    assert first["tools"][0]["function"]["name"]
    tool_msg = second["messages"][-1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_name"] == "list_alerts"
    assert second["messages"][-2]["tool_calls"][0]["function"]["arguments"] == {"status": "open"}


def test_ollama_missing_model():
    rec = Recorder([(404, b'{"error":"model not found"}', "application/json")])
    prov = get_provider(AIProviderSettings(name="o", type="ollama", model="nope", base_url="http://gpu:11434/v1"),
                        transport=httpx.MockTransport(rec))
    with pytest.raises(ProviderError, match="ollama pull nope"):
        prov.chat("s", [ChatMessage(role="user", content="x")], [])
    assert rec.urls[0] == "http://gpu:11434/api/chat"


# --------------------------------------------------------------------------- #
# Factory helpers
# --------------------------------------------------------------------------- #
def test_factory_and_listing(monkeypatch):
    monkeypatch.delenv("SAMS_TEST_OPENAI_KEY", raising=False)
    ai = AISettings(default_provider="local", providers=[
        AIProviderSettings(name="gpt", type="openai", model="gpt-x", api_key_env="SAMS_TEST_OPENAI_KEY"),
        AIProviderSettings(name="local", type="ollama", model="llama3.1", locality="local"),
    ])
    assert find_provider_settings(ai).name == "local"
    assert find_provider_settings(ai, "gpt").name == "gpt"
    with pytest.raises(LookupError):
        find_provider_settings(ai, "missing")
    with pytest.raises(LookupError):
        find_provider_settings(AISettings())
    listing = {p["name"]: p for p in available_providers(ai)}
    assert listing["gpt"]["key_configured"] is False and listing["gpt"]["redacted"] is True
    assert listing["local"]["default"] is True and listing["local"]["redacted"] is False
    assert "sk-" not in json.dumps(listing)
    with pytest.raises(ValueError):
        get_provider(AIProviderSettings(name="x", type="watson", model="m"))
