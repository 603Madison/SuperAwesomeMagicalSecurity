"""The SAMS security analyst: a provider-agnostic tool loop over the SAMS tool registry.

The loop is written by hand (rather than an SDK tool runner) because the same loop must
drive Anthropic, OpenAI-compatible and Ollama backends, and because every tool result
passes through the ``Redactor`` before it leaves for a cloud model while tool-call
arguments are restored on the way back in.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from .providers import ChatMessage, ChatTurn, LLMProvider, ProviderError, ToolResult, _add_usage
from .redact import Redactor, redactor_for_context
from .tools import ToolInputError, ToolNotAllowed, call_tool, tool_specs

log = logging.getLogger("sams.ai")

SYSTEM_PROMPT = """You are the security analyst built into SuperAwesomeMagicalSecurity (SAMS), a defensive \
platform that inventories hosts through agents, matches vulnerabilities, analyzes firewall policy (pfSense, \
OPNsense, UniFi), scans the perimeter from off-network probes, runs a SIEM, and models attack paths between \
systems. You work for the people who own and defend this environment.

How to work:
- Ground every statement in SAMS data. Use the tools to look things up before answering; do not rely on \
assumptions about the environment. If the data needed to answer is missing (no agent on a host, no firewall \
imported, no external scan yet), say so plainly and say what would provide it.
- Never invent findings, CVEs, hosts, IPs, or events. Quote identifiers exactly as tools return them: finding \
keys, asset ids, alert ids, CVE/GHSA/USN ids. Identifiers such as HOST-3, USER-1 or PRIV-IP-2 are privacy \
pseudonyms; use them as-is, they are translated back for the reader.
- Prioritize by real-world impact, not raw counts: what is reachable from the internet, what is known to be \
exploited (CISA KEV, high EPSS), what sits on an attack path to a critical asset, and what a single change \
fixes across many paths. Use attack_paths, blast_radius and remediation_plan for this.
- Give concrete, safe remediation: exact package upgrades, config lines, firewall rule changes for the vendor \
in use, and commands that can be copy-pasted. Point out side effects (service restarts, reboots, lockout risk \
when changing SSH or firewall rules) and suggest verification steps.
- When triaging alerts, weigh evidence for and against malicious activity, state a verdict (likely benign / \
suspicious / likely malicious) with confidence, and list next investigative or containment steps.
- Only change state (patch tasks, finding status, alert acknowledgement) when the user explicitly asks, and \
remind them that patch tasks still need approval in the SAMS UI.
- Be concise and structured: lead with the answer, then the evidence, then the actions. Use markdown tables \
for lists of hosts/findings when helpful.
"""


@dataclass
class AnalystResult:
    text: str
    tool_calls_log: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    stop_reason: str = "end_turn"
    iterations: int = 0
    provider: str = ""
    model: str = ""


class SecurityAnalyst:
    def __init__(self, ctx: Any, provider: LLMProvider, redact: Optional[bool] = None,
                 include_write_tools: Optional[bool] = None, max_iterations: Optional[int] = None,
                 system_prompt: str = SYSTEM_PROMPT):
        self.ctx = ctx
        self.provider = provider
        if redact is None:
            redact = provider.locality == "cloud" and not provider.settings.allow_sensitive
        self.redact_enabled = redact
        self.include_write_tools = include_write_tools
        self.max_iterations = max_iterations or getattr(ctx.settings.ai, "max_tool_iterations", 12)
        self.system_prompt = system_prompt

    # ------------------------------------------------------------------ #
    def _new_redactor(self) -> Redactor:
        return redactor_for_context(self.ctx, self.redact_enabled)

    def _history(self, history: Optional[list[dict[str, Any]]], redactor: Redactor) -> list[ChatMessage]:
        msgs: list[ChatMessage] = []
        for h in history or []:
            role = h.get("role")
            content = h.get("content") or ""
            if isinstance(content, list):   # OpenAI content parts
                content = "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
            if role in ("user", "assistant") and content:
                msgs.append(ChatMessage(role=role, content=redactor.redact(content)))
        # providers require alternating turns that start with the user
        while msgs and msgs[0].role != "user":
            msgs.pop(0)
        merged: list[ChatMessage] = []
        for m in msgs:
            if merged and merged[-1].role == m.role:
                merged[-1].content += "\n\n" + m.content
            else:
                merged.append(m)
        return merged

    def _run_tool(self, name: str, args: dict[str, Any], redactor: Redactor) -> tuple[str, bool, Any]:
        real_args = redactor.restore_obj(args)
        try:
            result = call_tool(self.ctx, name, real_args, include_write=self.include_write_tools)
            return json.dumps(redactor.redact_obj(result), default=str), False, real_args
        except (ToolInputError, ToolNotAllowed) as exc:
            return redactor.redact(f"Error: {exc}"), True, real_args
        except Exception as exc:  # a tool crashed: tell the model, keep the loop alive
            log.exception("tool %s failed", name)
            return redactor.redact(f"Error: tool {name} failed: {exc}"), True, real_args

    def run(self, question: str, history: Optional[list[dict[str, Any]]] = None,
            on_event: Optional[Any] = None) -> AnalystResult:
        """Run the tool loop. ``on_event(dict)`` receives progress events:
        ``{"type": "tool_call", "name", "arguments"}``, ``{"type": "tool_result", "name", "is_error"}``,
        ``{"type": "text", "text"}`` (intermediate assistant text)."""
        emit = on_event or (lambda e: None)
        redactor = self._new_redactor()
        tools = tool_specs(self.ctx, self.include_write_tools)
        messages = self._history(history, redactor)
        q = redactor.redact(question)
        if messages and messages[-1].role == "user":
            messages[-1].content += "\n\n" + q
        else:
            messages.append(ChatMessage(role="user", content=q))
        usage: dict[str, int] = {}
        log_calls: list[dict[str, Any]] = []
        last_text = ""
        turn: Optional[ChatTurn] = None
        iterations = 0
        capped = False
        while True:
            if iterations >= self.max_iterations:
                capped = True
                break
            iterations += 1
            turn = self.provider.chat(self.system_prompt, messages, tools)
            _add_usage(usage, turn.usage)
            messages.append(ChatMessage(role="assistant", content=turn.text, tool_calls=turn.tool_calls,
                                        raw=turn.raw, raw_provider=self.provider.key))
            if turn.text:
                last_text = turn.text
                if turn.tool_calls:
                    emit({"type": "text", "text": redactor.restore(turn.text)})
            if turn.stop_reason in ("refusal",) or (not turn.tool_calls and turn.stop_reason != "pause_turn"):
                break
            if turn.stop_reason == "pause_turn":
                continue
            results: list[ToolResult] = []
            for tc in turn.tool_calls:
                if turn.stop_reason == "max_tokens":
                    # a truncated tool input parses as a valid partial object: never run it
                    results.append(ToolResult(tc.id, tc.name, "Error: tool input was truncated (max_tokens); "
                                              "retry with a shorter call", True))
                    continue
                emit({"type": "tool_call", "name": tc.name, "arguments": redactor.restore_obj(tc.arguments)})
                content, is_error, real_args = self._run_tool(tc.name, tc.arguments, redactor)
                log_calls.append({"name": tc.name, "arguments": real_args, "is_error": is_error,
                                  "result_chars": len(content)})
                emit({"type": "tool_result", "name": tc.name, "is_error": is_error})
                results.append(ToolResult(tc.id, tc.name, content, is_error))
            messages.append(ChatMessage(role="tool", tool_results=results))

        stop = turn.stop_reason if turn else "end_turn"
        if stop == "refusal":
            note = "The model declined to continue this request"
            if turn and turn.refusal and turn.refusal.get("category"):
                note += f" (category: {turn.refusal['category']})"
            final = "\n\n".join(t for t in ((turn.text if turn else ""), note + ".") if t)
        elif capped:
            stop = "max_iterations"
            final = "\n\n".join(t for t in (last_text, (
                f"(Stopped after {self.max_iterations} tool iterations; the answer may be incomplete. "
                "Ask a narrower question or raise ai.max_tool_iterations.)")) if t)
        else:
            final = turn.text if turn else ""
        return AnalystResult(text=redactor.restore(final), tool_calls_log=log_calls, usage=usage,
                             stop_reason=stop, iterations=iterations,
                             provider=self.provider.name, model=self.provider.model)

    def ask(self, question: str, history: Optional[list[dict[str, Any]]] = None) -> AnalystResult:
        return self.run(question, history)

    def ask_stream(self, question: str, history: Optional[list[dict[str, Any]]] = None) -> Iterator[dict[str, Any]]:
        """Yield progress while the loop runs in a worker thread:
        ``tool_call`` / ``tool_result`` / ``text`` events, then ``{"type": "final", "text", "result"}``
        or ``{"type": "error", "error"}``. Provider responses are not token-streamed; the final
        answer arrives as one chunk."""
        q: queue.Queue[dict[str, Any]] = queue.Queue()

        def worker() -> None:
            try:
                res = self.run(question, history, on_event=q.put)
                q.put({"type": "final", "text": res.text, "result": res})
            except ProviderError as exc:
                q.put({"type": "error", "error": str(exc)})
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("analyst failed")
                q.put({"type": "error", "error": f"analyst failed: {exc}"})

        threading.Thread(target=worker, daemon=True, name="sams-analyst").start()
        while True:
            ev = q.get()
            yield ev
            if ev["type"] in ("final", "error"):
                return

    # ------------------------------------------------------------------ #
    # canned tasks
    # ------------------------------------------------------------------ #
    def explain_finding(self, key: str) -> AnalystResult:
        return self.ask(
            f"Explain finding `{key}` for a busy administrator. Look it up with get_finding, check the asset "
            "with get_asset, and use attack_paths/blast_radius to judge whether it is reachable or sits on an "
            "attack path. Cover: what it is, whether it is exploitable here and how urgent it is, the exact fix "
            "(commands/config), side effects, and how to verify the fix.")

    def triage_alert(self, alert_id: int) -> AnalystResult:
        return self.ask(
            f"Triage SIEM alert {alert_id}. Use get_alert for the alert and surrounding events, search_events for "
            "more context (same source IP / user / host over a wider window), get_asset for the host, and "
            "blast_radius on the affected host to state what an attacker could reach if this is a real "
            "compromise. Give a verdict (likely benign / suspicious / likely malicious) with confidence and "
            "reasoning, then immediate containment steps (if warranted) and follow-up investigation steps.")

    def executive_summary(self) -> AnalystResult:
        return self.ask(
            "Write an executive summary of the current security posture for leadership. Use posture_summary, "
            "attack_paths (from the internet), external_exposure, list_alerts and remediation_plan. Include: overall "
            "grade and trend-relevant counts, the top 3 risks in plain language with business impact, what is "
            "exposed to the internet, notable alerts, and the top 5 remediation actions ranked by risk reduction "
            "with rough effort. Keep it under 400 words.")

    def remediation_narrative(self, plan_item_id: str) -> AnalystResult:
        return self.ask(
            f"Using remediation_plan, find plan item `{plan_item_id}` and write a change plan for it: why it "
            "matters (which attack paths it breaks), affected assets, step-by-step implementation with exact "
            "commands/config, rollback, maintenance-window and side-effect notes, and verification steps.")
