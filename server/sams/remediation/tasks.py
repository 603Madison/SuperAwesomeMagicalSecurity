"""Agent task lifecycle: created (pending approval) -> approved (signed) -> sent -> succeeded/failed/rejected.

Tasks are signed at approval time so the signature (and expiry) reflect the
moment a human said yes. Agents only ever receive approved, signed tasks.
"""
from __future__ import annotations

import re
import secrets
from datetime import timedelta
from typing import Any, Optional

from ..models import Task, TaskAction, utcnow

PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$")


class TaskError(ValueError):
    pass


def validate_params(action: TaskAction, params: dict[str, Any]) -> dict[str, Any]:
    if action == TaskAction.patch:
        pkgs = params.get("packages") or []
        if not pkgs or not isinstance(pkgs, list):
            raise TaskError("patch requires a non-empty 'packages' list")
        bad = [p for p in pkgs if not isinstance(p, str) or not PKG_RE.match(p)]
        if bad:
            raise TaskError(f"invalid package names: {bad}")
        mgr = params.get("manager", "")
        if mgr and mgr not in ("dpkg", "apt", "rpm", "dnf", "yum", "zypper", "apk", "brew", "winget"):
            raise TaskError(f"unsupported manager {mgr}")
        return {"packages": sorted(set(pkgs)), "manager": mgr}
    if action == TaskAction.patch_all:
        return {"security_only": bool(params.get("security_only", True))}
    return {}


def create_task(ctx: Any, agent_id: str, action: str | TaskAction, params: Optional[dict] = None,
                dry_run: bool = True, approved: bool = False, ttl_hours: int = 24) -> Task:
    agent = ctx.store.get_agent(agent_id)
    if not agent or agent["kind"] != "host" or agent["revoked"]:
        raise TaskError(f"unknown or revoked host agent {agent_id}")
    act = TaskAction(action)
    t = Task(id=f"tsk_{secrets.token_hex(8)}", agent_id=agent_id, action=act,
             params=validate_params(act, params or {}), dry_run=dry_run,
             expires_at=utcnow() + timedelta(hours=ttl_hours), status="pending")
    if approved:
        _sign(ctx, t)
    ctx.store.save_task(t)
    return t


def _sign(ctx: Any, t: Task) -> None:
    t.status = "approved"
    t.expires_at = utcnow() + timedelta(hours=24)
    env = ctx.signer.sign({"id": t.id, "agent_id": t.agent_id, "action": t.action.value, "params": t.params,
                           "dry_run": t.dry_run, "expires_at": t.expires_at.isoformat()})
    t.signature = env["signature"]
    t.result = {"envelope": env}


def approve_task(ctx: Any, task_id: str) -> Task:
    t = ctx.store.get_task(task_id)
    if not t:
        raise TaskError("no such task")
    if t.status != "pending":
        raise TaskError(f"task is {t.status}")
    _sign(ctx, t)
    ctx.store.save_task(t)
    return t


def reject_task(ctx: Any, task_id: str) -> Task:
    t = ctx.store.get_task(task_id)
    if not t:
        raise TaskError("no such task")
    t.status = "rejected"
    ctx.store.save_task(t)
    return t


def tasks_for_agent(ctx: Any, agent_id: str) -> list[dict]:
    out = []
    now = utcnow()
    for t in ctx.store.list_tasks(agent_id=agent_id, status="approved"):
        if t.expires_at and t.expires_at < now:
            t.status = "expired"
            ctx.store.save_task(t)
            continue
        env = (t.result or {}).get("envelope")
        if env:
            out.append(env)
            t.status = "sent"
            ctx.store.save_task(t)
    return out


def record_result(ctx: Any, agent_id: str, task_id: str, status: str, output: str = "",
                  details: Optional[dict] = None) -> Task:
    t = ctx.store.get_task(task_id)
    if not t or t.agent_id != agent_id:
        raise TaskError("no such task for this agent")
    if status not in ("succeeded", "failed", "rejected"):
        raise TaskError("bad status")
    t.status = status
    t.result = {**(t.result or {}), "output": output[-65536:], "details": details or {}, "finished_at": utcnow().isoformat()}
    ctx.store.save_task(t)
    return t
