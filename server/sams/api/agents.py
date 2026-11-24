"""Endpoints used by host agents and external probes (see docs/ARCHITECTURE.md)."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..analysis import asset_id_for, process_inventory, record_inventory, run_vuln_scan
from ..external import claim_job, ingest_result
from ..models import ExternalScanResult, Inventory, utcnow
from ..remediation import tasks as tasks_mod
from .deps import get_ctx, require_host_agent, require_probe

router = APIRouter(prefix="/api/v1")


class EnrollRequest(BaseModel):
    token: str
    kind: str = "host"
    hostname: str = ""
    version: str = ""
    os: Any = None


@router.post("/enroll")
def enroll(req: EnrollRequest, ctx: Any = Depends(get_ctx)) -> dict:
    kind = ctx.store.consume_enroll_token(req.token)
    if kind is None or kind != req.kind:
        raise HTTPException(403, "invalid, expired or wrong-kind enrollment token")
    agent_id, key = ctx.store.create_agent(kind, req.hostname or kind, None, req.version,
                                           {"os": req.os} if req.os else {})
    return {"agent_id": agent_id, "agent_key": key, "server_public_key": ctx.signer.public_key_b64,
            "key_id": ctx.signer.key_id, "kind": kind}


# --------------------------------------------------------------------------- #
# host agents
# --------------------------------------------------------------------------- #
@router.get("/agent/config")
def agent_config(agent: dict = Depends(require_host_agent), ctx: Any = Depends(get_ctx)) -> dict:
    s = ctx.settings
    return {"collect_interval_seconds": s.agent_collect_interval, "log_sources": s.agent_log_sources,
            "server_time": utcnow().isoformat(), "server_version": __version__}


@router.post("/agent/inventory")
def agent_inventory(inv: Inventory, background: BackgroundTasks, agent: dict = Depends(require_host_agent),
                    ctx: Any = Depends(get_ctx)) -> dict:
    asset_id = agent["asset_id"] or asset_id_for(inv, agent["id"])
    if not agent["asset_id"]:
        ctx.store.set_agent_asset(agent["id"], asset_id, inv.agent_version)
    stats = record_inventory(ctx, asset_id, inv, agent["id"])
    background.add_task(run_vuln_scan, ctx, asset_id, inv)
    return {"asset_id": asset_id, "findings": stats["hardening"], "vuln_scan": "queued"}


class LogBatch(BaseModel):
    lines: list[dict] = Field(default_factory=list)


@router.post("/agent/logs")
def agent_logs(batch: LogBatch, agent: dict = Depends(require_host_agent), ctx: Any = Depends(get_ctx)) -> dict:
    pipeline = ctx.extras.get("siem")
    if pipeline is None:
        raise HTTPException(503, "SIEM not running")
    host = ctx.store.get_asset(agent["asset_id"])["name"] if agent["asset_id"] else agent["name"]
    n, alerts = pipeline.ingest_lines(batch.lines[:10000], host=host, asset_id=agent["asset_id"])
    return {"accepted": n, "alerts": len(alerts)}


@router.get("/agent/tasks")
def agent_tasks(agent: dict = Depends(require_host_agent), ctx: Any = Depends(get_ctx)) -> dict:
    return {"tasks": tasks_mod.tasks_for_agent(ctx, agent["id"])}


class TaskResult(BaseModel):
    status: str
    output: str = ""
    details: dict = Field(default_factory=dict)


@router.post("/agent/tasks/{task_id}/result")
def agent_task_result(task_id: str, res: TaskResult, background: BackgroundTasks,
                      agent: dict = Depends(require_host_agent), ctx: Any = Depends(get_ctx)) -> dict:
    try:
        t = tasks_mod.record_result(ctx, agent["id"], task_id, res.status, res.output, res.details)
    except tasks_mod.TaskError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"ok": True, "status": t.status}


# --------------------------------------------------------------------------- #
# external probes
# --------------------------------------------------------------------------- #
class Heartbeat(BaseModel):
    version: str = ""


@router.post("/probe/heartbeat")
def probe_heartbeat(hb: Heartbeat, request: Request, probe: dict = Depends(require_probe),
                    ctx: Any = Depends(get_ctx)) -> dict:
    seen = request.headers.get("x-forwarded-for", "").split(",")[0].strip() if ctx.settings.trust_proxy else ""
    seen = seen or (request.client.host if request.client else "")
    return {"seen_ip": seen, "server_time": utcnow().isoformat()}


@router.get("/probe/jobs/next")
def probe_next_job(probe: dict = Depends(require_probe), ctx: Any = Depends(get_ctx)):
    env = claim_job(ctx, probe["id"])
    if env is None:
        return Response(status_code=204)
    return {"job": env}


@router.post("/probe/jobs/{job_id}/result")
def probe_result(job_id: str, result: ExternalScanResult, probe: dict = Depends(require_probe),
                 ctx: Any = Depends(get_ctx)) -> dict:
    result.probe_id = probe["id"]
    result.job_id = job_id
    if not ctx.store.finish_external_job(job_id, probe["id"], result.model_dump(mode="json")):
        raise HTTPException(404, "job not claimed by this probe")
    return ingest_result(ctx, result)
