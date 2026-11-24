"""Redactor, tool registry and analyst loop tests (no network)."""
from __future__ import annotations

import json

import pytest

from sams.ai.analyst import SecurityAnalyst
from sams.ai.providers import ChatTurn, ToolCall
from sams.ai.redact import Redactor, redactor_for_context
from sams.ai.tools import REGISTRY, ToolInputError, ToolNotAllowed, call_tool, cap, list_tools, validate_args

from test_ai_support import FakeProvider, answer, call, make_ctx


# --------------------------------------------------------------------------- #
# Redactor
# --------------------------------------------------------------------------- #
def test_redactor_round_trip_and_stability():
    r = Redactor(hostnames=["web01.corp.example", "db01"], usernames=["alice", "root"])
    text = ("alice logged into web01.corp.example (10.0.10.5/24) from 203.0.113.7; key SHA256:"
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG, mac 00:1A:2b:3c:4d:5e, mail alice@example.com, "
            "aws AKIA****WXYZ; root ran sudo on db01. openssl 3.0.2-0ubuntu1.10 on 127.0.0.1 and 0.0.0.0")
    red = r.redact(text)
    for secret in ("alice", "web01", "10.0.10.5", "203.0.113.7", "SHA256:abc", "00:1A", "example.com",
                   "AKIA", "db01"):
        assert secret not in red, (secret, red)
    assert "root" in red                              # system accounts are not identifying
    assert "3.0.2-0ubuntu1.10" in red                 # versions are not IPs
    assert "127.0.0.1" in red and "0.0.0.0" in red    # loopback / unspecified kept
    assert "PRIV-IP-1/24" in red and "PUB-IP-" in red
    # same value -> same token across calls
    assert r.redact("10.0.10.5") == r.redact("again 10.0.10.5").split()[-1]
    assert r.restore(red) == text.replace("00:1A:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e")


def test_redactor_objects_and_disabled():
    r = Redactor(hostnames=["host_web01"])
    obj = {"asset_id": "host_web01", "ips": ["192.168.1.10"], "n": 3, "host_web01": True}
    red = r.redact_obj(obj)
    assert "host_web01" not in json.dumps(red)
    assert r.restore_obj(red) == obj
    off = Redactor(enabled=False, hostnames=["host_web01"])
    assert off.redact_obj(obj) == obj


def test_redactor_for_context_learns_names(tmp_path):
    ctx = make_ctx(tmp_path)
    r = redactor_for_context(ctx, True)
    red = r.redact("web01 / web01.corp.example / host_db01 / alice / bob / root")
    assert "web01" not in red and "host_db01" not in red and "alice" not in red and "bob" not in red
    assert "root" in red


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
def test_registry_and_write_gating(tmp_path):
    ctx = make_ctx(tmp_path)
    names = {t.name for t in list_tools(ctx)}
    assert {"posture_summary", "list_findings", "blast_radius", "attack_paths", "search_events"} <= names
    assert "create_patch_task" not in names
    with pytest.raises(ToolNotAllowed):
        call_tool(ctx, "acknowledge_alert", {"alert_id": 1})
    ctx.extras["allow_write_tools"] = True
    assert "create_patch_task" in {t.name for t in list_tools(ctx)}
    assert call_tool(ctx, "acknowledge_alert", {"alert_id": 1})["status"] == "acknowledged"
    assert ctx.store.get_alert(1).status == "acknowledged"


def test_validate_args():
    schema = REGISTRY["list_findings"].input_schema
    out = validate_args(schema, {"limit": "5", "severity": "high"})
    assert out["limit"] == 5 and out["status"] == "open"
    with pytest.raises(ToolInputError):
        validate_args(schema, {"severity": "catastrophic"})
    with pytest.raises(ToolInputError):
        validate_args(schema, {"bogus": 1})
    with pytest.raises(ToolInputError):
        validate_args(REGISTRY["get_finding"].input_schema, {})
    with pytest.raises(ToolInputError, match="INVALID_JSON"):
        validate_args(schema, {"__invalid_input__": "{bad"})
    assert validate_args(schema, {"limit": 100000})["limit"] == 200   # clamped to maximum


def test_read_tools_against_store(tmp_path):
    ctx = make_ctx(tmp_path)
    s = call_tool(ctx, "posture_summary", {})
    assert s["open_findings"] == 3 and s["findings"]["by_severity"]["critical"] == 1
    assets = call_tool(ctx, "list_assets", {})
    assert assets["total"] == 2
    a = call_tool(ctx, "get_asset", {"asset_id": "host_web01"})
    inv = a["inventory"]
    assert inv["ip_addresses"] == ["10.0.10.5"]
    assert [l["port"] for l in inv["listeners"]] == [22] and inv["loopback_listeners"] == 1
    assert set(inv["admin_users"]) == {"root", "alice"}
    fs = call_tool(ctx, "list_findings", {"asset_id": "host_web01"})
    assert fs["findings"][0]["severity"] == "critical"
    full = call_tool(ctx, "get_finding", {"key": fs["findings"][0]["key"]})
    assert full["remediation"]["commands"]
    ev = call_tool(ctx, "search_events", {"src_ip": "203.0.113.7"})
    assert ev["count"] == 2
    al = call_tool(ctx, "get_alert", {"alert_id": 1})
    assert len(al["related_events"]) == 2
    assert call_tool(ctx, "list_alerts", {})["count"] == 1
    assert call_tool(ctx, "external_exposure", {})["note"] == "no completed external scan yet"
    assert call_tool(ctx, "firewall_overview", {})["devices"] == []
    assert call_tool(ctx, "list_agents", {})["agents"] == []
    with pytest.raises(ToolInputError):
        call_tool(ctx, "get_asset", {"asset_id": "nope"})


def test_graph_tools_when_engine_available(tmp_path):
    pytest.importorskip("sams.graph.engine")
    ctx = make_ctx(tmp_path)
    try:
        res = call_tool(ctx, "attack_paths", {})
    except RuntimeError as exc:       # engine present but not yet functional
        pytest.skip(str(exc))
    assert "paths" in res
    br = call_tool(ctx, "blast_radius", {"start": "host_web01"})
    assert "reachable" in br or "summary" in br


def test_cap_truncates_large_results():
    big = {"items": [{"i": i, "pad": "x" * 200} for i in range(1000)]}
    out = cap(big, max_chars=10000)
    assert len(json.dumps(out)) <= 10000
    assert "_truncated" in out["items"][-1]


# --------------------------------------------------------------------------- #
# Analyst loop
# --------------------------------------------------------------------------- #
def test_analyst_runs_tools_and_answers(tmp_path):
    ctx = make_ctx(tmp_path)
    prov = FakeProvider([
        ChatTurn(text="Checking.", tool_calls=[ToolCall("a", "posture_summary", {}),
                                               ToolCall("b", "list_findings", {"severity": "critical"})],
                 stop_reason="tool_use", usage={"input_tokens": 5, "output_tokens": 2}),
        answer("One critical finding: openssl."),
    ])
    res = SecurityAnalyst(ctx, prov).ask("What should I fix first?")
    assert res.text == "One critical finding: openssl."
    assert [c["name"] for c in res.tool_calls_log] == ["posture_summary", "list_findings"]
    assert res.usage == {"input_tokens": 25, "output_tokens": 9}
    # both results returned together in one tool message, after the assistant turn
    second = prov.calls[1]["messages"]
    assert [m["role"] for m in second] == ["user", "assistant", "tool"]
    assert len(second[2]["tool_results"]) == 2
    assert "create_patch_task" not in prov.calls[0]["tools"]


def test_analyst_reports_tool_errors(tmp_path):
    ctx = make_ctx(tmp_path)
    prov = FakeProvider([call("get_finding", {"key": "missing"}), call("no_such_tool", {}, "c2"),
                         call("acknowledge_alert", {"alert_id": 1}, "c3"), answer("sorry")])
    res = SecurityAnalyst(ctx, prov).ask("?")
    assert [c["is_error"] for c in res.tool_calls_log] == [True, True, True]
    results = [m for m in prov.calls[-1]["messages"] if m["role"] == "tool"]
    assert "no finding" in results[0]["tool_results"][0][1]
    assert "unknown tool" in results[1]["tool_results"][0][1]
    assert "write tools are disabled" in results[2]["tool_results"][0][1]
    assert ctx.store.get_alert(1).status == "open"


def test_analyst_iteration_cap(tmp_path):
    ctx = make_ctx(tmp_path)
    prov = FakeProvider([call("list_alerts", {}, f"c{i}") for i in range(10)])
    res = SecurityAnalyst(ctx, prov, max_iterations=3).ask("loop forever")
    assert res.iterations == 3 and res.stop_reason == "max_iterations"
    assert "Stopped after 3 tool iterations" in res.text


def test_analyst_refusal(tmp_path):
    ctx = make_ctx(tmp_path)
    prov = FakeProvider([ChatTurn(text="", tool_calls=[], stop_reason="refusal",
                                  refusal={"category": "cyber", "explanation": None})])
    res = SecurityAnalyst(ctx, prov).ask("x")
    assert res.stop_reason == "refusal" and "declined" in res.text and "cyber" in res.text


def test_analyst_max_tokens_does_not_run_truncated_tools(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.extras["allow_write_tools"] = True
    prov = FakeProvider([ChatTurn(text="", tool_calls=[ToolCall("t", "acknowledge_alert", {"alert_id": 1})],
                                  stop_reason="max_tokens"), answer("ok")])
    SecurityAnalyst(ctx, prov).ask("ack it")
    assert ctx.store.get_alert(1).status == "open"
    tool_msg = [m for m in prov.calls[1]["messages"] if m["role"] == "tool"][0]
    assert tool_msg["tool_results"][0][2] is True


def test_analyst_redaction_round_trip(tmp_path):
    ctx = make_ctx(tmp_path)
    seen_args: dict = {}

    def step2(messages):
        # the model only ever sees pseudonyms; it calls back with the token it saw
        tool_text = messages[-1].tool_results[0].content
        data = json.loads(tool_text)
        web = next(a for a in data["assets"] if a["criticality"] == 4)
        seen_args["id"] = web["id"]
        return call("get_asset", {"asset_id": web["id"]}, "c2")

    def step3(messages):
        content = messages[-1].tool_results[0].content
        assert "10.0.10.5" not in content and "web01" not in content and "alice" not in content
        ip_token = json.loads(content)["inventory"]["ip_addresses"][0]
        return answer(f"{seen_args['id']} at {ip_token} has user USER-1 with admin rights.")

    prov = FakeProvider([call("list_assets", {}), step2, step3], locality="cloud")
    res = SecurityAnalyst(ctx, prov).ask("Tell me about web01 at 10.0.10.5")
    first_user = prov.calls[0]["messages"][0]["content"]
    assert "web01" not in first_user and "10.0.10.5" not in first_user
    assert seen_args["id"].startswith("HOST-")
    # the tool received the real asset id, the user gets real names back
    assert res.tool_calls_log[1]["arguments"] == {"asset_id": "host_web01"}
    assert res.text.startswith("host_web01 at 10.0.10.5 has user ")
    assert "USER-" not in res.text or "alice" in res.text


def test_analyst_no_redaction_for_local_or_allowed(tmp_path):
    ctx = make_ctx(tmp_path)
    prov = FakeProvider([answer("hi")], locality="cloud", allow_sensitive=True)
    SecurityAnalyst(ctx, prov).ask("web01 10.0.10.5")
    assert prov.calls[0]["messages"][0]["content"] == "web01 10.0.10.5"


def test_ask_stream_events(tmp_path):
    ctx = make_ctx(tmp_path)
    prov = FakeProvider([call("list_alerts", {}), answer("All quiet.")])
    events = list(SecurityAnalyst(ctx, prov).ask_stream("alerts?"))
    kinds = [e["type"] for e in events]
    assert kinds == ["tool_call", "tool_result", "final"]
    assert events[-1]["text"] == "All quiet."


def test_history_is_normalized(tmp_path):
    ctx = make_ctx(tmp_path)
    prov = FakeProvider([answer("second")])
    SecurityAnalyst(ctx, prov).ask("follow-up", history=[
        {"role": "assistant", "content": "orphan greeting"},
        {"role": "user", "content": "first"}, {"role": "assistant", "content": "answer one"},
        {"role": "user", "content": [{"type": "text", "text": "dangling"}]},
    ])
    msgs = prov.calls[0]["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assert msgs[-1]["content"] == "dangling\n\nfollow-up"
