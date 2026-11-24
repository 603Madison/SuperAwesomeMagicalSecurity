"""Shared helpers for the AI tests (imported by test_ai_*.py; contains no tests itself)."""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Callable, Optional

from sams.ai.providers import ChatMessage, ChatTurn, LLMProvider, ToolCall, ToolSpec
from sams.config import AIProviderSettings, AISettings, Settings
from sams.context import AppContext
from sams.crypto import Signer
from sams.db import Store
from sams.models import (Alert, Event, Finding, FindingCategory, HostInfo, Interface, Inventory, Listener, OSInfo,
                         Remediation, RemediationKind, Severity, User, utcnow)

ADMIN_TOKEN = "test-admin-token"


def make_ctx(tmp_path, providers: Optional[list[AIProviderSettings]] = None, **ai_kwargs: Any) -> AppContext:
    settings = Settings(data_dir=tmp_path, admin_token=ADMIN_TOKEN,
                        ai=AISettings(providers=providers or [], **ai_kwargs))
    ctx = AppContext(settings=settings, store=Store(":memory:"), signer=Signer.ephemeral())
    seed(ctx.store)
    return ctx


def seed(store: Store) -> None:
    store.upsert_asset("host_web01", "host", "web01.corp.example", criticality=4,
                       data={"hostname": "web01", "fqdn": "web01.corp.example"})
    store.upsert_asset("host_db01", "host", "db01", criticality=5)
    inv = Inventory(
        host=HostInfo(hostname="web01", fqdn="web01.corp.example",
                      os=OSInfo(id="ubuntu", version_id="22.04", pretty="Ubuntu 22.04.4 LTS")),
        interfaces=[Interface(name="eth0", addresses=["10.0.10.5/24"])],
        listeners=[Listener(port=22, process="sshd", user="root"),
                   Listener(port=5432, address="127.0.0.1", process="postgres", user="postgres")],
        users=[User(name="root", uid=0, is_admin=True), User(name="alice", uid=1000, is_admin=True),
               User(name="bob", uid=1001)],
    )
    store.save_inventory("host_web01", inv)
    f1 = Finding(asset_id="host_web01", category=FindingCategory.vulnerability, severity=Severity.critical,
                 title="openssl 3.0.2: 3 vulnerabilities", evidence={"vulns": [{"id": "CVE-2023-0286"}]},
                 remediation=Remediation(kind=RemediationKind.patch, summary="Upgrade openssl",
                                         commands=["apt-get install --only-upgrade openssl"], automatable=True))
    f2 = Finding(asset_id="host_web01", category=FindingCategory.hardening, severity=Severity.medium,
                 title="SSH password authentication enabled", evidence={"sshd": "PasswordAuthentication yes"})
    f3 = Finding(asset_id="host_db01", category=FindingCategory.exposure, severity=Severity.high,
                 title="PostgreSQL reachable from 10.0.10.5")
    store.replace_findings("test", "host_web01", [f1, f2])
    store.replace_findings("test", "host_db01", [f3])
    now = utcnow()
    store.insert_events([
        Event(timestamp=now - timedelta(minutes=5), host="web01", source="auth.log", category="authentication",
              action="ssh_failed", outcome="failure", user="alice", src_ip="203.0.113.7",
              message="Failed password for alice from 203.0.113.7 port 5555 ssh2"),
        Event(timestamp=now - timedelta(minutes=4), host="web01", source="auth.log", category="authentication",
              action="ssh_login", outcome="success", user="alice", src_ip="203.0.113.7",
              message="Accepted password for alice from 203.0.113.7 port 5556 ssh2"),
    ])
    store.insert_alert(Alert(rule_id="ssh_bruteforce_success", title="Login after brute force from 203.0.113.7",
                             severity=Severity.high, host="web01", asset_id="host_web01", group_key="203.0.113.7",
                             mitre=["T1110"], event_ids=[1, 2]))


class FakeProvider(LLMProvider):
    """Scripted provider. ``script`` is a list of ChatTurns or callables(messages) -> ChatTurn."""

    type = "fake"

    def __init__(self, script: list[Any], locality: str = "local", allow_sensitive: bool = False,
                 name: str = "fake"):
        super().__init__(AIProviderSettings(name=name, type="openai_compatible", model="fake-1",
                                            locality=locality, allow_sensitive=allow_sensitive))
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def chat(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> ChatTurn:
        self.calls.append({"system": system, "messages": [_snapshot(m) for m in messages],
                           "tools": [t.name for t in tools]})
        if not self.script:
            return ChatTurn(text="done", tool_calls=[], stop_reason="end_turn")
        step = self.script.pop(0)
        return step(messages) if callable(step) else step


def _snapshot(m: ChatMessage) -> dict[str, Any]:
    return {"role": m.role, "content": m.content,
            "tool_calls": [(c.name, c.arguments) for c in m.tool_calls],
            "tool_results": [(r.name, r.content, r.is_error) for r in m.tool_results]}


def call(name: str, args: dict[str, Any], cid: str = "c1") -> ChatTurn:
    return ChatTurn(text="", tool_calls=[ToolCall(cid, name, args)], stop_reason="tool_use",
                    usage={"input_tokens": 10, "output_tokens": 5})


def answer(text: str) -> ChatTurn:
    return ChatTurn(text=text, tool_calls=[], stop_reason="end_turn", usage={"input_tokens": 20, "output_tokens": 7})


def sse(events: list[dict[str, Any]]) -> bytes:
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def anthropic_stream(blocks: list[dict[str, Any]], stop_reason: str, model: str = "claude-opus-5-5",
                     stop_details: Optional[dict[str, Any]] = None) -> bytes:
    """Build an Anthropic Messages SSE stream for the given final content blocks."""
    ev: list[dict[str, Any]] = [{"type": "message_start", "message": {
        "id": "msg_test", "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 100, "output_tokens": 1,
                                                               "cache_read_input_tokens": 50}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "thinking":
            ev.append({"type": "content_block_start", "index": i,
                       "content_block": {"type": "thinking", "thinking": "", "signature": ""}})
            if b.get("thinking"):
                ev.append({"type": "content_block_delta", "index": i,
                           "delta": {"type": "thinking_delta", "thinking": b["thinking"]}})
            ev.append({"type": "content_block_delta", "index": i,
                       "delta": {"type": "signature_delta", "signature": b["signature"]}})
        elif b["type"] == "text":
            ev.append({"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}})
            ev.append({"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}})
        elif b["type"] == "tool_use":
            ev.append({"type": "content_block_start", "index": i, "content_block": {
                "type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}})
            ev.append({"type": "content_block_delta", "index": i,
                       "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}})
        ev.append({"type": "content_block_stop", "index": i})
    delta: dict[str, Any] = {"stop_reason": stop_reason, "stop_sequence": None}
    if stop_details:
        delta["stop_details"] = stop_details
    ev.append({"type": "message_delta", "delta": delta, "usage": {"output_tokens": 42}})
    ev.append({"type": "message_stop"})
    return sse(ev)


Responder = Callable[[Any], Any]
