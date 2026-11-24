"""Dashboard endpoints for the AI analyst (admin-authenticated)."""
from __future__ import annotations

import dataclasses
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..api.deps import require_admin
from .providers import ProviderError, available_providers


class AskBody(BaseModel):
    question: str = Field(..., min_length=1, max_length=20000)
    provider: Optional[str] = None
    history: list[dict[str, Any]] = Field(default_factory=list)


def _result(res: Any) -> dict:
    d = dataclasses.asdict(res)
    d["tool_calls"] = d.pop("tool_calls_log", [])
    return d


def router(ctx: Any) -> APIRouter:
    r = APIRouter(prefix="/api/v1/ai", dependencies=[Depends(require_admin)])

    def analyst(name: Optional[str]):
        from . import make_analyst
        try:
            return make_analyst(ctx, name)
        except (KeyError, ValueError, ProviderError) as exc:
            raise HTTPException(400, f"AI provider not available: {exc}") from exc

    def run(fn):
        try:
            return _result(fn())
        except ProviderError as exc:
            raise HTTPException(502, f"AI provider error: {exc}") from exc

    @r.get("/providers")
    def providers() -> dict:
        return {"providers": available_providers(ctx.settings.ai)}

    @r.post("/ask")
    def ask(body: AskBody) -> dict:
        history = [{"role": h.get("role"), "content": str(h.get("content", ""))} for h in body.history[-20:]
                   if h.get("role") in ("user", "assistant")]
        a = analyst(body.provider)
        return run(lambda: a.ask(body.question, history))

    @r.post("/findings/{key}/explain")
    def explain(key: str, provider: Optional[str] = None) -> dict:
        a = analyst(provider)
        return run(lambda: a.explain_finding(key))

    @r.post("/alerts/{alert_id}/triage")
    def triage(alert_id: int, provider: Optional[str] = None) -> dict:
        a = analyst(provider)
        return run(lambda: a.triage_alert(alert_id))

    @r.post("/summary")
    def summary(provider: Optional[str] = None) -> dict:
        a = analyst(provider)
        return run(lambda: a.executive_summary())

    return r
