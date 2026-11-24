"""Administrative / dashboard API. All endpoints require the admin bearer token."""
from __future__ import annotations

import json
import re
from datetime import timedelta
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import __version__, external, posture
from ..analysis import refresh_graph_findings, run_vuln_scan
from ..models import FindingStatus, utcnow
from ..remediation import planner
from ..remediation import tasks as tasks_mod
from .deps import get_ctx, require_admin

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])


# --------------------------------------------------------------------------- #
# overview
# --------------------------------------------------------------------------- #
@router.get("/status")
def status(ctx: Any = Depends(get_ctx)) -> dict:
    p = posture.compute(ctx)
    siem = ctx.extras.get("siem")
    return {"version": __version__, "score": p["score"], "grade": p["grade"], "counts": p["counts"],
            "external_risk": p["external_risk"], "internet_attack_paths": p["internet_attack_paths"],
            "agents": len(ctx.store.list_agents("host")), "probes": len(ctx.store.list_agents("probe")),
            "firewalls": len(ctx.store.list_firewalls()),
            "open_alerts": len(ctx.store.list_alerts(status="open", limit=1000)),
            "siem": getattr(siem, "counters", None) if siem else None,
            "public_key": ctx.signer.public_key_b64}


@router.get("/posture")
def get_posture(ctx: Any = Depends(get_ctx)) -> dict:
    return posture.compute(ctx)


# --------------------------------------------------------------------------- #
# assets
# --------------------------------------------------------------------------- #
@router.get("/assets")
def list_assets(kind: Optional[str] = None, ctx: Any = Depends(get_ctx)) -> list[dict]:
    p = {h["asset_id"]: h for h in posture.compute(ctx, include_graph=False)["hosts"]}
    out = []
    for a in ctx.store.list_assets(kind):
        a["posture"] = p.get(a["id"])
        out.append(a)
    return out


def _inventory_summary(inv) -> dict:
    return {
        "host": inv.host.model_dump(), "collected_at": inv.collected_at, "ips": inv.ip_addresses(),
        "listeners": [l.model_dump() for l in inv.listeners if not l.is_loopback_only],
        "admins": [u.name for u in inv.users if u.is_admin],
        "users": len(inv.users), "packages": len(inv.packages),
        "credentials": [{"kind": c.kind, "owner": c.owner, "path": c.path, "encrypted": c.encrypted,
                         "targets": c.targets} for c in inv.credentials],
        "datastores": [d.model_dump() for d in inv.datastores],
        "sudo_rules": [r.model_dump() for r in inv.sudo_rules],
        "hardening": inv.hardening.model_dump(), "errors": inv.errors,
    }


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    a = ctx.store.get_asset(asset_id)
    if not a:
        raise HTTPException(404, "no such asset")
    inv = ctx.store.get_inventory(asset_id)
    a["inventory"] = _inventory_summary(inv) if inv else None
    a["findings"] = [f.model_dump(mode="json") for f in ctx.store.list_findings(asset_id=asset_id)]
    a["agents"] = [ag for ag in ctx.store.list_agents() if ag["asset_id"] == asset_id]
    return a


@router.get("/assets/{asset_id}/inventory")
def get_inventory(asset_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    inv = ctx.store.get_inventory(asset_id)
    if not inv:
        raise HTTPException(404, "no inventory")
    return inv.model_dump(mode="json")


class AssetPatch(BaseModel):
    criticality: Optional[int] = Field(None, ge=1, le=5)
    tags: Optional[list[str]] = None
    notes: Optional[str] = None


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: str, body: AssetPatch, ctx: Any = Depends(get_ctx)) -> dict:
    a = ctx.store.update_asset_meta(asset_id, body.criticality, body.tags,
                                    {"notes": body.notes} if body.notes is not None else None)
    if not a:
        raise HTTPException(404, "no such asset")
    ctx.invalidate()
    return a


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    ctx.store.delete_asset(asset_id)
    ctx.invalidate()
    return {"ok": True}


@router.post("/assets/{asset_id}/scan")
def rescan(asset_id: str, background: BackgroundTasks, ctx: Any = Depends(get_ctx)) -> dict:
    if not ctx.store.get_inventory(asset_id):
        raise HTTPException(404, "no inventory")
    background.add_task(run_vuln_scan, ctx, asset_id)
    return {"queued": True}


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #
@router.get("/findings")
def list_findings(asset_id: Optional[str] = None, category: Optional[str] = None, severity: Optional[str] = None,
                  status: Optional[str] = "open", limit: int = Query(1000, le=5000), ctx: Any = Depends(get_ctx)) -> list[dict]:
    fs = ctx.store.list_findings(asset_id=asset_id, status=status or None, category=category, severity=severity,
                                 limit=limit)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs.sort(key=lambda f: (order[f.severity.value], f.title))
    return [f.model_dump(mode="json") for f in fs]


@router.get("/findings/{key}")
def get_finding(key: str, ctx: Any = Depends(get_ctx)) -> dict:
    f = ctx.store.get_finding(key)
    if not f:
        raise HTTPException(404, "no such finding")
    return f.model_dump(mode="json")


class StatusBody(BaseModel):
    status: str
    reason: str = ""


@router.post("/findings/{key}/status")
def set_finding_status(key: str, body: StatusBody, ctx: Any = Depends(get_ctx)) -> dict:
    try:
        st = FindingStatus(body.status)
    except ValueError as exc:
        raise HTTPException(400, f"status must be one of {[s.value for s in FindingStatus]}") from exc
    if not ctx.store.set_finding_status(key, st):
        raise HTTPException(404, "no such finding")
    ctx.invalidate()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# attack graph
# --------------------------------------------------------------------------- #
@router.get("/graph")
def graph(ctx: Any = Depends(get_ctx)) -> dict:
    return ctx.graph().to_dict()


@router.get("/graph/blast-radius/{start:path}")
def blast_radius(start: str, min_likelihood: float = 0.05, ctx: Any = Depends(get_ctx)) -> dict:
    try:
        return ctx.graph().blast_radius(start, min_likelihood)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/graph/paths")
def attack_paths(source: str = "internet", target: Optional[str] = None, k: int = Query(5, le=25),
                 ctx: Any = Depends(get_ctx)) -> list[dict]:
    try:
        return ctx.graph().attack_paths(source, target, k)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/graph/refresh")
def graph_refresh(ctx: Any = Depends(get_ctx)) -> dict:
    return refresh_graph_findings(ctx)


# --------------------------------------------------------------------------- #
# remediation + tasks
# --------------------------------------------------------------------------- #
@router.get("/remediation/plan")
def plan(limit: int = Query(50, le=500), ctx: Any = Depends(get_ctx)) -> dict:
    return {"summary": planner.plan_summary(ctx), "items": planner.build_plan(ctx, limit)}


class TaskCreate(BaseModel):
    agent_id: Optional[str] = None
    asset_id: Optional[str] = None
    action: str
    params: dict = Field(default_factory=dict)
    dry_run: bool = True
    approve: bool = False


def _agent_for_asset(ctx: Any, asset_id: str) -> str:
    for ag in ctx.store.list_agents("host"):
        if ag["asset_id"] == asset_id and not ag["revoked"]:
            return ag["id"]
    raise HTTPException(404, f"no agent for asset {asset_id}")


@router.post("/tasks")
def create_task(body: TaskCreate, ctx: Any = Depends(get_ctx)) -> dict:
    agent_id = body.agent_id or (_agent_for_asset(ctx, body.asset_id) if body.asset_id else None)
    if not agent_id:
        raise HTTPException(400, "agent_id or asset_id required")
    try:
        t = tasks_mod.create_task(ctx, agent_id, body.action, body.params, body.dry_run, body.approve)
    except (tasks_mod.TaskError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return t.model_dump(mode="json")


@router.post("/findings/{key}/task")
def task_from_finding(key: str, dry_run: bool = True, ctx: Any = Depends(get_ctx)) -> dict:
    f = ctx.store.get_finding(key)
    if not f or not f.remediation or not f.remediation.automatable or not f.remediation.task:
        raise HTTPException(400, "finding has no automatable remediation")
    task = dict(f.remediation.task)
    action = task.pop("action")
    try:
        t = tasks_mod.create_task(ctx, _agent_for_asset(ctx, f.asset_id or ""), action, task, dry_run)
    except tasks_mod.TaskError as exc:
        raise HTTPException(400, str(exc)) from exc
    return t.model_dump(mode="json")


@router.get("/tasks")
def list_tasks(agent_id: Optional[str] = None, status: Optional[str] = None, ctx: Any = Depends(get_ctx)) -> list[dict]:
    out = []
    for t in ctx.store.list_tasks(agent_id, status):
        d = t.model_dump(mode="json")
        if d.get("result"):
            d["result"].pop("envelope", None)
        out.append(d)
    return out


@router.post("/tasks/{task_id}/approve")
def approve(task_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    try:
        return tasks_mod.approve_task(ctx, task_id).model_dump(mode="json", exclude={"result"})
    except tasks_mod.TaskError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/tasks/{task_id}/reject")
def reject(task_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    try:
        return tasks_mod.reject_task(ctx, task_id).model_dump(mode="json")
    except tasks_mod.TaskError as exc:
        raise HTTPException(400, str(exc)) from exc


# --------------------------------------------------------------------------- #
# agents / enrollment
# --------------------------------------------------------------------------- #
@router.get("/agents")
def agents(ctx: Any = Depends(get_ctx)) -> list[dict]:
    return ctx.store.list_agents()


@router.post("/agents/{agent_id}/revoke")
def revoke(agent_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    ctx.store.revoke_agent(agent_id)
    return {"ok": True}


class TokenCreate(BaseModel):
    kind: str = "host"
    label: str = ""
    uses: int = Field(1, ge=1, le=10000)
    ttl_hours: int = Field(24, ge=1, le=24 * 365)


@router.post("/tokens")
def token(body: TokenCreate, request: Request, ctx: Any = Depends(get_ctx)) -> dict:
    if body.kind not in ("host", "probe"):
        raise HTTPException(400, "kind must be host or probe")
    tok = ctx.store.create_enroll_token(body.kind, body.label, body.uses, body.ttl_hours)
    server = (ctx.settings.public_url or str(request.base_url)).rstrip("/")
    binary = "sams-agent" if body.kind == "host" else "sams-probe"
    out = {"token": tok, "kind": body.kind, "expires_in_hours": body.ttl_hours,
           "command": f"{binary} enroll --server {server} --token {tok}",
           "server_public_key": ctx.signer.public_key_b64}
    if body.kind == "host":
        out["install_command"] = f"curl -fsSL {server}/install.sh | sudo sh -s -- --token {tok}"
    return out


# --------------------------------------------------------------------------- #
# SIEM
# --------------------------------------------------------------------------- #
@router.get("/events")
def events(q: Optional[str] = None, host: Optional[str] = None, src_ip: Optional[str] = None,
           action: Optional[str] = None, user: Optional[str] = None, source: Optional[str] = None,
           since_minutes: Optional[int] = None, limit: int = Query(200, le=5000), ctx: Any = Depends(get_ctx)) -> list[dict]:
    since = utcnow() - timedelta(minutes=since_minutes) if since_minutes else None
    return [e.model_dump(mode="json") for e in ctx.store.search_events(q, host, src_ip, action, user, source,
                                                                       since, None, limit)]


@router.get("/events/stats")
def event_stats(since_minutes: int = 1440, group_by: str = "action", ctx: Any = Depends(get_ctx)) -> dict:
    try:
        return ctx.store.event_counts(utcnow() - timedelta(minutes=since_minutes), group_by)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


class IngestBody(BaseModel):
    host: str = ""
    lines: list[dict]


@router.post("/siem/ingest")
def siem_ingest(body: IngestBody, ctx: Any = Depends(get_ctx)) -> dict:
    pipeline = ctx.extras.get("siem")
    if pipeline is None:
        raise HTTPException(503, "SIEM not running")
    from ..analysis import resolve_asset_by_ip
    n, alerts = pipeline.ingest_lines(body.lines, host=body.host, asset_id=resolve_asset_by_ip(ctx, body.host, body.host))
    return {"accepted": n, "alerts": [a.model_dump(mode="json") for a in alerts]}


@router.get("/alerts")
def alerts(status: Optional[str] = None, limit: int = Query(200, le=2000), ctx: Any = Depends(get_ctx)) -> list[dict]:
    return [a.model_dump(mode="json") for a in ctx.store.list_alerts(status, limit)]


@router.get("/alerts/{alert_id}")
def alert(alert_id: int, ctx: Any = Depends(get_ctx)) -> dict:
    a = ctx.store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "no such alert")
    d = a.model_dump(mode="json")
    rows = []
    for eid in a.event_ids[:50]:
        r = ctx.store._q("SELECT data FROM events WHERE id=?", (eid,))
        if r:
            rows.append(json.loads(r[0]["data"]))
    d["events"] = rows
    return d


@router.post("/alerts/{alert_id}/status")
def alert_status(alert_id: int, body: StatusBody, ctx: Any = Depends(get_ctx)) -> dict:
    if body.status not in ("open", "acknowledged", "closed"):
        raise HTTPException(400, "status must be open, acknowledged or closed")
    if not ctx.store.set_alert_status(alert_id, body.status):
        raise HTTPException(404, "no such alert")
    return {"ok": True}


@router.get("/siem/rules")
def siem_rules(ctx: Any = Depends(get_ctx)) -> list[dict]:
    eng = ctx.extras.get("siem_engine")
    return [r.model_dump(mode="json") for r in getattr(eng, "rules", [])] if eng else []


# --------------------------------------------------------------------------- #
# firewalls
# --------------------------------------------------------------------------- #
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class FirewallCreate(BaseModel):
    id: str
    name: str
    vendor: str            # pfsense_api | opnsense_api | unifi | pfsense_xml | opnsense_xml | manual
    connection: dict = Field(default_factory=dict)


def _analyze_firewall(ctx: Any, device_id: str, cfg) -> dict:
    from ..firewall.analyzer import analyze
    aid = f"fw:{device_id}"
    ctx.store.upsert_asset(aid, "firewall", cfg.hostname or device_id,
                           {"vendor": cfg.vendor, "version": cfg.version, "wan_addresses": cfg.wan_addresses,
                            "rules": len(cfg.rules), "port_forwards": len(cfg.port_forwards),
                            "networks": [n.name for n in cfg.networks]})
    ctx.store.upsert_firewall(device_id, cfg.vendor, cfg.hostname or device_id, None, cfg.model_dump_json())
    stats = ctx.store.replace_findings("firewall", aid, analyze(cfg, aid))
    ctx.invalidate()
    refresh_graph_findings(ctx)
    return stats


@router.get("/firewalls")
def firewalls(ctx: Any = Depends(get_ctx)) -> list[dict]:
    out = []
    for fw in ctx.store.list_firewalls():
        cfg = fw.pop("config") or {}
        fw["summary"] = {"networks": [n.get("name") for n in cfg.get("networks", [])],
                         "rules": len(cfg.get("rules", [])), "port_forwards": len(cfg.get("port_forwards", [])),
                         "wan_addresses": cfg.get("wan_addresses", [])}
        fw["connection"] = {k: v for k, v in fw["connection"].items() if "secret" not in k and "password" not in k
                            or k.endswith("_env")}
        out.append(fw)
    return out


@router.get("/firewalls/{device_id}")
def firewall(device_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    fw = ctx.store.get_firewall(device_id)
    if not fw:
        raise HTTPException(404, "no such firewall")
    return fw


@router.post("/firewalls")
def add_firewall(body: FirewallCreate, ctx: Any = Depends(get_ctx)) -> dict:
    if not SAFE_ID.match(body.id):
        raise HTTPException(400, "id must match [A-Za-z0-9_.-]{1,64}")
    literal = [k for k, v in body.connection.items()
               if any(s in k.lower() for s in ("password", "secret", "api_key", "token")) and not k.endswith("_env")]
    if literal:
        raise HTTPException(400, f"store secrets in environment variables and reference them as <name>_env: {literal}")
    ctx.store.upsert_firewall(body.id, body.vendor, body.name, {**body.connection, "vendor": body.vendor})
    return {"ok": True}


@router.post("/firewalls/{device_id}/sync")
def sync_firewall(device_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    fw = ctx.store.get_firewall(device_id)
    if not fw:
        raise HTTPException(404, "no such firewall")
    from ..firewall import fetch_device
    try:
        cfg = fetch_device(fw["connection"])
    except Exception as exc:  # noqa: BLE001 -- surface vendor/API errors to the admin
        raise HTTPException(502, f"fetch failed: {exc}") from exc
    cfg.device_id = device_id
    return _analyze_firewall(ctx, device_id, cfg)


@router.post("/firewalls/{device_id}/import")
async def import_firewall(device_id: str, request: Request, vendor: Optional[str] = None,
                          ctx: Any = Depends(get_ctx)) -> dict:
    """Upload a pfSense/OPNsense config.xml or a UniFi JSON export as the request body."""
    if not SAFE_ID.match(device_id):
        raise HTTPException(400, "bad id")
    body = (await request.body()).decode("utf-8", "replace")
    if len(body) > 20_000_000:
        raise HTTPException(413, "too large")
    from ..firewall import normalize_unifi, parse_any_config
    try:
        if body.lstrip().startswith("{"):
            cfg = normalize_unifi(json.loads(body))
        else:
            cfg = parse_any_config(body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"could not parse config: {exc}") from exc
    cfg.device_id = device_id
    return _analyze_firewall(ctx, device_id, cfg)


@router.get("/firewalls/{device_id}/exposed")
def firewall_exposed(device_id: str, ctx: Any = Depends(get_ctx)) -> list[dict]:
    fw = ctx.store.get_firewall(device_id)
    if not fw or not fw.get("config"):
        raise HTTPException(404, "no config")
    from ..firewall.analyzer import exposed_services
    from ..firewall.model import FirewallConfig
    return exposed_services(FirewallConfig.model_validate(fw["config"]))


@router.post("/firewalls/{device_id}/evaluate")
def firewall_eval(device_id: str, src_ip: str = Body(...), dst_ip: str = Body(...), port: Optional[int] = Body(None),
                  proto: str = Body("tcp"), ctx: Any = Depends(get_ctx)) -> dict:
    fw = ctx.store.get_firewall(device_id)
    if not fw or not fw.get("config"):
        raise HTTPException(404, "no config")
    from ..firewall.model import FirewallConfig
    return FirewallConfig.model_validate(fw["config"]).evaluate(src_ip, dst_ip, port, proto).model_dump()


@router.delete("/firewalls/{device_id}")
def delete_firewall(device_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    ctx.store.delete_firewall(device_id)
    ctx.store.delete_asset(f"fw:{device_id}")
    ctx.invalidate()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# external (outside-in)
# --------------------------------------------------------------------------- #
class TargetBody(BaseModel):
    value: str
    note: str = ""


@router.get("/external/targets")
def ext_targets(ctx: Any = Depends(get_ctx)) -> dict:
    return {"targets": ctx.store.list_external_targets(), "suggested": external.suggest_targets(ctx)}


@router.post("/external/targets")
def ext_add(body: TargetBody, ctx: Any = Depends(get_ctx)) -> dict:
    try:
        return external.add_target(ctx, body.value, body.note)
    except external.ScopeError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/external/targets/{target_id}")
def ext_del(target_id: str, ctx: Any = Depends(get_ctx)) -> dict:
    ctx.store.delete_external_target(target_id)
    return {"ok": True}


class JobBody(BaseModel):
    ports: Optional[str] = None
    checks: Optional[list[str]] = None
    targets: Optional[list[str]] = None


@router.post("/external/jobs")
def ext_job(body: JobBody, ctx: Any = Depends(get_ctx)) -> dict:
    try:
        return {"job_id": external.create_job(ctx, body.ports, body.checks, body.targets)}
    except external.ScopeError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/external/jobs")
def ext_jobs(ctx: Any = Depends(get_ctx)) -> list[dict]:
    return ctx.store.list_external_jobs()
