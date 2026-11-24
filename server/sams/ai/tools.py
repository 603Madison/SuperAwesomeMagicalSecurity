"""The SAMS tool registry, shared by the analyst loop, the MCP server and the
OpenAI-compatible endpoint.

Each tool is ``handler(ctx: AppContext, args: dict) -> JSON-serializable`` plus a JSON
schema. Results are size-capped (long lists are truncated with a note) so a single call
cannot flood a model's context window.

Read tools are always available. Write tools (``write=True``) change state and are only
exposed when ``settings.ai.allow_write_tools`` (or ``ctx.extras["allow_write_tools"]``) is
true. Even then, patch tasks are created in ``pending`` state and still need a human to
approve them in the UI before an agent will receive them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Optional

from ..models import FindingStatus, Severity, utcnow
from .providers import ToolSpec

Handler = Callable[[Any, dict[str, Any]], Any]


@dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler
    write: bool = False

    def spec(self) -> ToolSpec:
        return ToolSpec(self.name, self.description, self.input_schema)


REGISTRY: dict[str, ToolDef] = {}


class ToolInputError(ValueError):
    """The model sent arguments that do not match the tool's schema."""


class ToolNotAllowed(PermissionError):
    pass


def tool(name: str, description: str, schema: Optional[dict[str, Any]] = None, write: bool = False):
    """Register a handler. ``schema`` is the JSON schema for the arguments object."""
    schema = schema or {"type": "object", "properties": {}}
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    schema.setdefault("additionalProperties", False)

    def deco(fn: Handler) -> Handler:
        REGISTRY[name] = ToolDef(name, description, schema, fn, write)
        return fn
    return deco


def write_tools_allowed(ctx: Any) -> bool:
    """True when ``settings.ai.allow_write_tools`` or ``ctx.extras["allow_write_tools"]`` is set."""
    settings = getattr(ctx, "settings", None)
    from_settings = bool(getattr(getattr(settings, "ai", None), "allow_write_tools", False))
    return from_settings or bool((getattr(ctx, "extras", None) or {}).get("allow_write_tools"))


def list_tools(ctx: Any, include_write: Optional[bool] = None) -> list[ToolDef]:
    allow = write_tools_allowed(ctx) if include_write is None else include_write
    return [t for t in REGISTRY.values() if allow or not t.write]


def tool_specs(ctx: Any, include_write: Optional[bool] = None) -> list[ToolSpec]:
    return [t.spec() for t in list_tools(ctx, include_write)]


# --------------------------------------------------------------------------- #
# argument validation (small JSON-schema subset: the shapes our tools use)
# --------------------------------------------------------------------------- #
_PY_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}


def validate_args(schema: dict[str, Any], args: Any) -> dict[str, Any]:
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ToolInputError("arguments must be a JSON object")
    if "__invalid_input__" in args:
        raise ToolInputError(json.dumps({"INVALID_JSON": str(args["__invalid_input__"])[:500]}))
    props: dict[str, Any] = schema.get("properties", {})
    out: dict[str, Any] = {}
    for key, val in args.items():
        if key not in props:
            if schema.get("additionalProperties", True) is False:
                raise ToolInputError(f"unknown argument {key!r}; allowed: {sorted(props)}")
            out[key] = val
            continue
        spec = props[key]
        typ = spec.get("type")
        if val is None:
            continue
        if typ == "integer" and isinstance(val, str) and val.strip().lstrip("-").isdigit():
            val = int(val)          # models sometimes quote numbers
        if typ == "number" and isinstance(val, str):
            try:
                val = float(val)
            except ValueError:
                pass
        if typ == "boolean" and isinstance(val, str) and val.lower() in ("true", "false"):
            val = val.lower() == "true"
        if typ == "array" and isinstance(val, str):
            val = [val]
        if typ in _PY_TYPES:
            ok = isinstance(val, _PY_TYPES[typ]) and not (typ in ("integer", "number") and isinstance(val, bool))
            if not ok:
                raise ToolInputError(f"argument {key!r} must be of type {typ}")
        if "enum" in spec and val not in spec["enum"]:
            raise ToolInputError(f"argument {key!r} must be one of {spec['enum']}")
        if typ == "integer":
            if "minimum" in spec and val < spec["minimum"]:
                val = spec["minimum"]
            if "maximum" in spec and val > spec["maximum"]:
                val = spec["maximum"]
        if typ == "array" and "items" in spec and spec["items"].get("type") == "string":
            if not all(isinstance(v, str) for v in val):
                raise ToolInputError(f"argument {key!r} must be a list of strings")
        out[key] = val
    for req in schema.get("required", []):
        if req not in out:
            raise ToolInputError(f"missing required argument {req!r}")
    for key, spec in props.items():
        if key not in out and "default" in spec:
            out[key] = spec["default"]
    return out


def call_tool(ctx: Any, name: str, args: Any, include_write: Optional[bool] = None) -> Any:
    t = REGISTRY.get(name)
    if t is None:
        raise ToolInputError(f"unknown tool {name!r}")
    if t.write and not (write_tools_allowed(ctx) if include_write is None else include_write):
        raise ToolNotAllowed(f"tool {name!r} changes state and write tools are disabled (ai.allow_write_tools)")
    clean = validate_args(t.input_schema, args)
    return cap(t.handler(ctx, clean))


# --------------------------------------------------------------------------- #
# result size capping
# --------------------------------------------------------------------------- #
def _jsonable(obj: Any) -> Any:
    return json.loads(json.dumps(obj, default=str))


def _cap_lists(obj: Any, n: int) -> Any:
    if isinstance(obj, dict):
        return {k: _cap_lists(v, n) for k, v in obj.items()}
    if isinstance(obj, list):
        items = [_cap_lists(v, n) for v in obj[:n]]
        if len(obj) > n:
            items.append({"_truncated": f"{len(obj) - n} more item(s) omitted; narrow the query or raise limit"})
        return items
    if isinstance(obj, str) and len(obj) > 2000:
        return obj[:2000] + "...[truncated]"
    return obj


def cap(obj: Any, max_chars: int = 24000) -> Any:
    obj = _jsonable(obj)
    for n in (200, 100, 50, 25, 10, 5):
        capped = _cap_lists(obj, n)
        if len(json.dumps(capped)) <= max_chars:
            return capped
    s = json.dumps(_cap_lists(obj, 3))
    return {"_truncated_json": s[:max_chars], "_note": "result too large; narrow the query"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
_SEV_ORDER = {s.value: s.weight for s in Severity}


def _finding_brief(f: Any) -> dict[str, Any]:
    return {
        "key": f.key, "asset_id": f.asset_id, "category": f.category.value, "severity": f.severity.value,
        "title": f.title, "status": f.status.value, "source": f.source,
        "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
        "remediation": f.remediation.summary if f.remediation else None,
        "automatable": bool(f.remediation and f.remediation.automatable),
    }


def _sort_findings(findings: list[Any]) -> list[Any]:
    return sorted(findings, key=lambda f: (-_SEV_ORDER.get(f.severity.value, 0), f.title))


def _counts(findings: list[Any]) -> dict[str, dict[str, int]]:
    by_sev: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
    return {"by_severity": by_sev, "by_category": by_cat}


def _graph(ctx: Any):
    try:
        return ctx.graph()
    except (ImportError, ModuleNotFoundError) as exc:
        raise RuntimeError("the attack-graph engine is not available in this build") from exc


def _event_brief(e: Any) -> dict[str, Any]:
    return {k: v for k, v in {
        "id": e.id, "timestamp": e.timestamp.isoformat(), "host": e.host, "source": e.source,
        "category": e.category, "action": e.action, "outcome": e.outcome, "severity": e.severity.value,
        "user": e.user, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port or None,
        "process": e.process, "message": e.message[:300],
    }.items() if v not in (None, "")}


def _alert_brief(a: Any) -> dict[str, Any]:
    return {"id": a.id, "rule_id": a.rule_id, "title": a.title, "severity": a.severity.value, "status": a.status,
            "created_at": a.created_at.isoformat(), "host": a.host, "asset_id": a.asset_id,
            "group_key": a.group_key, "mitre": a.mitre, "event_count": len(a.event_ids)}


_SECRETISH = ("password", "secret", "token", "api_key", "apikey", "key")


def _scrub_connection(conn: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in (conn or {}).items():
        lk = k.lower()
        if lk.endswith("_env"):
            out[k] = v          # an env var *name*, not a secret
        elif any(s in lk for s in _SECRETISH):
            out[k] = "***"
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------- #
# READ tools
# --------------------------------------------------------------------------- #
@tool("posture_summary",
      "Overall security posture: score/grade, per-host scores and counts of open findings by severity and "
      "category, assets, agents and open alerts. Call this first when asked how secure the environment is, "
      "what to worry about, or for any summary/report.")
def posture_summary(ctx: Any, args: dict[str, Any]) -> Any:
    findings = ctx.store.list_findings(status="open")
    out: dict[str, Any] = {
        "assets": len(ctx.store.list_assets()),
        "agents": len(ctx.store.list_agents()),
        "open_findings": len(findings),
        "findings": _counts(findings),
        "open_alerts": len(ctx.store.list_alerts(status="open")),
    }
    try:
        from ..posture import compute  # type: ignore[attr-defined]
        out["posture"] = compute(ctx)
    except (ImportError, AttributeError):
        out["posture"] = None
        out["note"] = "posture scoring module unavailable; counts only"
    return out


@tool("list_assets",
      "List assets SAMS knows about (hosts with agents, firewalls, external targets) with criticality "
      "(1 low .. 5 crown jewel), tags, last-seen time and open finding counts. Use to discover asset ids.",
      {"properties": {
          "kind": {"type": "string", "enum": ["host", "firewall", "external", "cloud"],
                   "description": "Only this asset kind"},
          "limit": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
      }})
def list_assets(ctx: Any, args: dict[str, Any]) -> Any:
    assets = ctx.store.list_assets(args.get("kind"))
    by_asset: dict[str, list[Any]] = {}
    for f in ctx.store.list_findings(status="open"):
        by_asset.setdefault(f.asset_id or "", []).append(f)
    out = []
    for a in assets[: args["limit"]]:
        fs = by_asset.get(a["id"], [])
        out.append({"id": a["id"], "kind": a["kind"], "name": a["name"], "criticality": a["criticality"],
                    "tags": a["tags"], "last_seen": a["last_seen"],
                    "open_findings": _counts(fs)["by_severity"]})
    return {"total": len(assets), "assets": out}


@tool("get_asset",
      "Details for one asset: OS, IP addresses, network listeners, admin users, sudo rules, credential "
      "counts, datastores, hardening highlights and open finding counts (a summary, not the raw inventory).",
      {"properties": {"asset_id": {"type": "string", "description": "Asset id from list_assets"}},
       "required": ["asset_id"]})
def get_asset(ctx: Any, args: dict[str, Any]) -> Any:
    a = ctx.store.get_asset(args["asset_id"])
    if not a:
        raise ToolInputError(f"no asset {args['asset_id']!r}; use list_assets")
    findings = ctx.store.list_findings(asset_id=a["id"], status="open")
    out: dict[str, Any] = {k: a[k] for k in ("id", "kind", "name", "criticality", "tags", "last_seen")}
    out["open_findings"] = _counts(findings)
    out["top_findings"] = [_finding_brief(f) for f in _sort_findings(findings)[:10]]
    inv = ctx.store.get_inventory(a["id"]) if a["kind"] == "host" else None
    if inv is None:
        out["data"] = a["data"]
        return out
    h = inv.hardening
    creds: dict[str, int] = {}
    for c in inv.credentials:
        creds[c.kind] = creds.get(c.kind, 0) + 1
    out["inventory"] = {
        "collected_at": inv.collected_at.isoformat(),
        "hostname": inv.host.hostname, "fqdn": inv.host.fqdn,
        "os": inv.host.os.pretty or f"{inv.host.os.name} {inv.host.os.version}".strip(),
        "kernel": inv.host.kernel, "arch": inv.host.arch, "virtualization": inv.host.virtualization,
        "ip_addresses": inv.ip_addresses(),
        "listeners": [{"proto": l.proto, "address": l.address, "port": l.port, "process": l.process,
                       "user": l.user, "package": l.package} for l in inv.listeners if not l.is_loopback_only],
        "loopback_listeners": sum(1 for l in inv.listeners if l.is_loopback_only),
        "packages": len(inv.packages),
        "admin_users": [u.name for u in inv.users if u.is_admin],
        "login_users": [u.name for u in inv.users if u.login_enabled],
        "empty_password_users": [u.name for u in inv.users if u.password_state == "empty"],
        "sudo_rules": [{"principal": r.principal, "commands": r.commands, "nopasswd": r.nopasswd}
                       for r in inv.sudo_rules],
        "authorized_keys": len(inv.authorized_keys),
        "credentials_by_kind": creds,
        "unencrypted_ssh_keys": sum(1 for c in inv.credentials if c.kind == "ssh_private_key" and c.encrypted is False),
        "known_hosts_targets": sorted({k.host for k in inv.known_hosts if k.host})[:50],
        "datastores": [{"kind": d.kind, "name": d.name, "port": d.port, "sensitivity": d.sensitivity}
                       for d in inv.datastores],
        "containers": [{"name": c.name, "image": c.image, "privileged": c.privileged} for c in inv.containers],
        "hardening": {
            "sshd_permit_root_login": h.sshd.permit_root_login, "sshd_password_auth": h.sshd.password_authentication,
            "host_firewall_enabled": h.firewall.enabled, "host_firewall_backend": h.firewall.backend,
            "auto_updates": h.auto_updates, "mac_framework": h.mac_framework,
            "disk_encryption": h.disk_encryption, "suid_binaries": len(h.suid_binaries),
            "world_writable": h.world_writable[:20], "pending_reboot": h.pending_reboot,
            "docker_socket": h.docker_socket,
        },
        "collector_errors": inv.errors[:10],
    }
    agents = [ag for ag in ctx.store.list_agents("host") if ag["asset_id"] == a["id"]]
    out["agents"] = [{"id": ag["id"], "version": ag["version"], "last_seen": ag["last_seen"],
                      "revoked": ag["revoked"]} for ag in agents]
    return out


@tool("list_findings",
      "Search security findings (vulnerabilities, hardening issues, exposed credentials, firewall weaknesses, "
      "external exposure, attack paths, detections), most severe first. Filter by asset, category, severity, status.",
      {"properties": {
          "asset_id": {"type": "string"},
          "category": {"type": "string", "enum": ["vulnerability", "hardening", "credential", "exposure", "firewall",
                                                  "external", "attack_path", "detection"]},
          "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
          "status": {"type": "string", "enum": ["open", "accepted", "fixed", "false_positive", "any"],
                     "default": "open"},
          "limit": {"type": "integer", "default": 25, "minimum": 1, "maximum": 200},
      }})
def list_findings(ctx: Any, args: dict[str, Any]) -> Any:
    status = None if args["status"] == "any" else args["status"]
    findings = ctx.store.list_findings(asset_id=args.get("asset_id"), status=status,
                                       category=args.get("category"), severity=args.get("severity"))
    ordered = _sort_findings(findings)
    return {"total": len(findings), "findings": [_finding_brief(f) for f in ordered[: args["limit"]]]}


@tool("get_finding",
      "Full detail of one finding by key: description, evidence (e.g. CVEs with CVSS/KEV/EPSS, rule ids, file "
      "paths) and remediation steps/commands.",
      {"properties": {"key": {"type": "string", "description": "Finding key"}}, "required": ["key"]})
def get_finding(ctx: Any, args: dict[str, Any]) -> Any:
    f = ctx.store.get_finding(args["key"])
    if f is None:
        raise ToolInputError(f"no finding {args['key']!r}")
    return f.model_dump(mode="json")


@tool("blast_radius",
      "Model a compromise: if this host (or graph node) were taken over, what other hosts, credentials, "
      "datastores and cloud identities could an attacker reach, how likely, and via which path. Use for "
      "'what happens if X is compromised' and when triaging alerts on a host.",
      {"properties": {
          "start": {"type": "string", "description": "Asset id (assumes root on that host) or attack-graph node id"},
          "min_likelihood": {"type": "number", "default": 0.05},
      }, "required": ["start"]})
def blast_radius(ctx: Any, args: dict[str, Any]) -> Any:
    return _graph(ctx).blast_radius(args["start"], min_likelihood=float(args["min_likelihood"]))


@tool("attack_paths",
      "Most likely attack paths from a source (default: the internet) to critical assets or to a specific "
      "target node/asset, with per-step technique, likelihood and evidence. Use to explain how an attacker "
      "would get in and which single fixes break the most paths.",
      {"properties": {
          "source": {"type": "string", "default": "internet", "description": "'internet', an asset id or node id"},
          "target": {"type": "string", "description": "Optional target asset/node id"},
          "k": {"type": "integer", "default": 5, "minimum": 1, "maximum": 20},
      }})
def attack_paths(ctx: Any, args: dict[str, Any]) -> Any:
    paths = _graph(ctx).attack_paths(source=args["source"], target=args.get("target"), k=args["k"])
    return {"count": len(paths), "paths": paths}


@tool("remediation_plan",
      "Prioritized remediation plan: actions ranked by how much attack-path risk they remove, with affected "
      "assets, linked findings, commands and whether an agent can apply them automatically.",
      {"properties": {"limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100}}})
def remediation_plan(ctx: Any, args: dict[str, Any]) -> Any:
    try:
        from ..remediation.planner import build_plan  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("remediation planner is not available in this build") from exc
    plan = build_plan(ctx, limit=args["limit"])
    return {"count": len(plan), "items": plan}


@tool("search_events",
      "Search SIEM events (auth logs, sudo, firewall logs, Windows events). Filters combine with AND; q is a "
      "substring match over the message. Default window: last 24 hours.",
      {"properties": {
          "q": {"type": "string", "description": "Free-text substring"},
          "host": {"type": "string"}, "src_ip": {"type": "string"}, "action": {"type": "string",
                                                                              "description": "e.g. ssh_failed, ssh_login, sudo, blocked"},
          "user": {"type": "string"}, "source": {"type": "string"},
          "since_minutes": {"type": "integer", "default": 1440, "minimum": 1, "maximum": 525600},
          "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 500},
      }})
def search_events(ctx: Any, args: dict[str, Any]) -> Any:
    since = utcnow() - timedelta(minutes=args["since_minutes"])
    events = ctx.store.search_events(q=args.get("q"), host=args.get("host"), src_ip=args.get("src_ip"),
                                     action=args.get("action"), user=args.get("user"), source=args.get("source"),
                                     since=since, limit=args["limit"])
    return {"count": len(events), "events": [_event_brief(e) for e in events]}


@tool("list_alerts",
      "List SIEM detection alerts (newest first) with rule, severity, host and MITRE ATT&CK techniques.",
      {"properties": {
          "status": {"type": "string", "enum": ["open", "acknowledged", "closed", "any"], "default": "open"},
          "limit": {"type": "integer", "default": 25, "minimum": 1, "maximum": 200},
      }})
def list_alerts(ctx: Any, args: dict[str, Any]) -> Any:
    status = None if args["status"] == "any" else args["status"]
    alerts = ctx.store.list_alerts(status=status, limit=args["limit"])
    return {"count": len(alerts), "alerts": [_alert_brief(a) for a in alerts]}


@tool("get_alert",
      "One alert in full plus the events around it (same host / source IP, the hour before the alert). "
      "Use when triaging an alert.",
      {"properties": {"alert_id": {"type": "integer"}}, "required": ["alert_id"]})
def get_alert(ctx: Any, args: dict[str, Any]) -> Any:
    a = ctx.store.get_alert(int(args["alert_id"]))
    if a is None:
        raise ToolInputError(f"no alert {args['alert_id']}")
    out = a.model_dump(mode="json")
    since = a.created_at - timedelta(hours=1)
    until = a.created_at + timedelta(minutes=10)
    related: list[Any] = []
    gk = a.group_key or ""
    if gk.count(".") == 3 or ":" in gk:
        related = ctx.store.search_events(src_ip=gk.split("|")[0], since=since, until=until, limit=50)
    if not related and a.host:
        related = ctx.store.search_events(host=a.host, since=since, until=until, limit=50)
    out["related_events"] = [_event_brief(e) for e in related]
    return out


@tool("firewall_overview",
      "Firewalls (pfSense, OPNsense, UniFi...): networks/segments, rule and port-forward counts, risky "
      "settings, firewall findings and services exposed to the internet through port forwards.")
def firewall_overview(ctx: Any, args: dict[str, Any]) -> Any:
    devices = []
    exposed: list[dict[str, Any]] = []
    for fw in ctx.store.list_firewalls():
        cfg = fw.get("config") or {}
        d = {"id": fw["id"], "vendor": fw["vendor"], "name": fw["name"], "fetched_at": fw["fetched_at"],
             "connection": _scrub_connection(fw.get("connection") or {})}
        if cfg:
            d.update({
                "networks": [{"name": n.get("name"), "cidrs": n.get("cidrs"), "vlan": n.get("vlan"),
                              "purpose": n.get("purpose"), "is_wan": n.get("is_wan")} for n in cfg.get("networks", [])],
                "rules": len(cfg.get("rules", [])),
                "disabled_rules": sum(1 for r in cfg.get("rules", []) if not r.get("enabled", True)),
                "port_forwards": len(cfg.get("port_forwards", [])),
                "settings": cfg.get("settings", {}),
            })
            exposed.extend(_exposed_services(cfg, fw["id"]))
        devices.append(d)
    findings = _sort_findings(ctx.store.list_findings(category="firewall", status="open"))
    return {"devices": devices, "exposed_services": exposed,
            "findings": [_finding_brief(f) for f in findings]}


def _exposed_services(cfg: dict[str, Any], device_id: str) -> list[dict[str, Any]]:
    try:
        from ..firewall.analyzer import exposed_services  # type: ignore[import-not-found]
        from ..firewall.model import FirewallConfig
        return [{**e, "device_id": device_id} for e in exposed_services(FirewallConfig.model_validate(cfg))]
    except Exception:
        out = []
        for pf in cfg.get("port_forwards", []):
            if not pf.get("enabled", True):
                continue
            ports = [f"{p['start']}-{p['end']}" if p["start"] != p["end"] else str(p["start"])
                     for p in pf.get("external_ports", [])]
            out.append({"device_id": device_id, "internal_ip": pf.get("internal_ip"),
                        "internal_port": pf.get("internal_port"), "external_ports": ports or ["any"],
                        "protocol": pf.get("protocol"), "source": pf.get("source"),
                        "description": pf.get("description")})
        return out


@tool("external_exposure",
      "What the off-network external probes saw from the internet in the latest scan: reachable targets, open "
      "ports, service banners, TLS/HTTP/DNS issues, plus mismatches between what the firewall config says is "
      "exposed and what is actually reachable.")
def external_exposure(ctx: Any, args: dict[str, Any]) -> Any:
    result = ctx.store.latest_external_result()
    out: dict[str, Any] = {"scope": [t["value"] for t in ctx.store.list_external_targets()]}
    if not result:
        out["note"] = "no completed external scan yet"
    else:
        out["scan"] = {
            "probe_id": result.get("probe_id"), "finished_at": result.get("finished_at"),
            "probe_public_ip": result.get("probe_public_ip"),
            "targets": [{
                "target": t.get("target"), "reachable": t.get("reachable"),
                "open_services": [{k: s.get(k) for k in ("port", "proto", "service", "product", "version")}
                                  for s in t.get("services", []) if s.get("state", "open") == "open"],
                "issues": t.get("issues", []), "dns": t.get("dns", {}),
            } for t in result.get("targets", [])],
        }
    discrepancies = None
    try:
        from .. import external as ext  # type: ignore[attr-defined]
        for fn_name in ("discrepancies", "compute_discrepancies", "find_discrepancies"):
            fn = getattr(ext, fn_name, None)
            if callable(fn):
                discrepancies = fn(ctx)
                break
    except Exception:
        discrepancies = None
    out["discrepancies"] = discrepancies
    out["findings"] = [_finding_brief(f) for f in
                       _sort_findings(ctx.store.list_findings(category="external", status="open"))]
    return out


@tool("list_agents",
      "Enrolled host agents and external probes with version, linked asset and last check-in. Use to find an "
      "agent_id or spot agents that stopped reporting.",
      {"properties": {"kind": {"type": "string", "enum": ["host", "probe"]}}})
def list_agents(ctx: Any, args: dict[str, Any]) -> Any:
    return {"agents": [{k: a[k] for k in ("id", "kind", "name", "asset_id", "version", "enrolled_at", "last_seen",
                                           "revoked")} for a in ctx.store.list_agents(args.get("kind"))]}


# --------------------------------------------------------------------------- #
# WRITE tools (gated)
# --------------------------------------------------------------------------- #
@tool("create_patch_task",
      "Queue a package-upgrade task for a host agent. Tasks are created PENDING and need human approval in the "
      "SAMS UI before the agent receives them; dry_run (default true) only simulates the upgrade. Only call "
      "when the user explicitly asks to patch.",
      {"properties": {
          "agent_id": {"type": "string"},
          "packages": {"type": "array", "items": {"type": "string"}, "description": "Package names to upgrade"},
          "manager": {"type": "string", "enum": ["dpkg", "apt", "rpm", "dnf", "yum", "apk", "zypper"],
                      "description": "Package manager (optional; agent auto-detects)"},
          "dry_run": {"type": "boolean", "default": True},
      }, "required": ["agent_id", "packages"]}, write=True)
def create_patch_task(ctx: Any, args: dict[str, Any]) -> Any:
    agent = ctx.store.get_agent(args["agent_id"])
    if not agent or agent["kind"] != "host" or agent["revoked"]:
        raise ToolInputError(f"no active host agent {args['agent_id']!r}; use list_agents")
    if not args["packages"]:
        raise ToolInputError("packages must not be empty")
    from ..remediation.tasks import create_task  # type: ignore[import-not-found]
    params: dict[str, Any] = {"packages": args["packages"]}
    if args.get("manager"):
        params["manager"] = args["manager"]
    t = create_task(ctx, args["agent_id"], "patch", params, dry_run=bool(args["dry_run"]))
    return {"task_id": t.id, "status": t.status, "dry_run": t.dry_run,
            "note": "Task requires approval in the SAMS UI before the agent will run it."}


@tool("set_finding_status",
      "Mark a finding as accepted risk, false positive, or re-open it. Only when the user explicitly asks.",
      {"properties": {
          "key": {"type": "string"},
          "status": {"type": "string", "enum": ["accepted", "false_positive", "open"]},
          "reason": {"type": "string", "description": "Why (recorded in the audit log)"},
      }, "required": ["key", "status", "reason"]}, write=True)
def set_finding_status(ctx: Any, args: dict[str, Any]) -> Any:
    ok = ctx.store.set_finding_status(args["key"], FindingStatus(args["status"]))
    if not ok:
        raise ToolInputError(f"no finding {args['key']!r}")
    audit = ctx.store.kv_get("audit:finding_status", [])
    audit.append({"key": args["key"], "status": args["status"], "reason": args["reason"],
                  "at": utcnow().isoformat(), "by": "ai"})
    ctx.store.kv_set("audit:finding_status", audit[-1000:])
    return {"key": args["key"], "status": args["status"]}


@tool("acknowledge_alert",
      "Acknowledge a SIEM alert (marks it as seen). Only when the user explicitly asks.",
      {"properties": {"alert_id": {"type": "integer"}}, "required": ["alert_id"]}, write=True)
def acknowledge_alert(ctx: Any, args: dict[str, Any]) -> Any:
    if not ctx.store.set_alert_status(int(args["alert_id"]), "acknowledged"):
        raise ToolInputError(f"no alert {args['alert_id']}")
    return {"alert_id": args["alert_id"], "status": "acknowledged"}
