"""Orchestration: what happens when new facts arrive."""
from __future__ import annotations

import hashlib
import logging
import threading
from typing import Any, Optional

from .graph.engine import INTERNET
from .hardening.checks import check_inventory
from .models import (Alert, Finding, FindingCategory, Inventory, Remediation, RemediationKind, Severity)

log = logging.getLogger("sams.analysis")
_vuln_lock = threading.Lock()


def asset_id_for(inv: Inventory, agent_id: Optional[str] = None) -> str:
    basis = inv.host.machine_id or agent_id or inv.host.fqdn or inv.host.hostname
    return "h_" + hashlib.sha256(basis.encode()).hexdigest()[:12]


def record_inventory(ctx: Any, asset_id: str, inv: Inventory, agent_id: Optional[str] = None) -> dict:
    ctx.store.upsert_asset(asset_id, "host", inv.host.hostname, {
        "os": inv.host.os.pretty or f"{inv.host.os.name} {inv.host.os.version}".strip(),
        "os_family": inv.host.os.family, "ips": inv.ip_addresses(), "agent_id": agent_id,
        "kernel": inv.host.kernel, "agent_version": inv.agent_version,
        "packages": len(inv.packages), "listeners": len(inv.listeners),
    })
    ctx.store.save_inventory(asset_id, inv)
    stats = {"hardening": ctx.store.replace_findings("hardening", asset_id, check_inventory(inv, asset_id))}
    ctx.invalidate()
    return stats


def run_vuln_scan(ctx: Any, asset_id: str, inv: Optional[Inventory] = None) -> dict:
    inv = inv or ctx.store.get_inventory(asset_id)
    if inv is None:
        return {"error": "no inventory"}
    try:
        from .vuln.scanner import VulnScanner
    except ImportError as exc:  # pragma: no cover
        return {"error": f"vuln engine unavailable: {exc}"}
    with _vuln_lock:
        scanner = ctx.extras.get("vuln_scanner")
        if scanner is None:
            scanner = ctx.extras["vuln_scanner"] = VulnScanner(ctx.settings)
        try:
            findings = scanner.scan(inv, asset_id)
        except Exception as exc:  # noqa: BLE001 -- network trouble must not lose the inventory
            log.warning("vuln scan failed for %s: %s", asset_id, exc)
            return {"error": str(exc)}
        stats = ctx.store.replace_findings("vuln.osv", asset_id, findings)
        stats["scan"] = getattr(scanner, "last_stats", {})
    ctx.invalidate()
    refresh_graph_findings(ctx)
    return stats


def process_inventory(ctx: Any, asset_id: str, inv: Inventory, agent_id: Optional[str] = None,
                      vuln: bool = True) -> dict:
    stats = record_inventory(ctx, asset_id, inv, agent_id)
    if vuln:
        stats["vuln"] = run_vuln_scan(ctx, asset_id, inv)
    else:
        refresh_graph_findings(ctx)
    return stats


def refresh_graph_findings(ctx: Any, min_likelihood: float = 0.05) -> dict:
    """Persist the most important internet attack paths as findings so they show up
    in dashboards, posture scores and reports like any other issue."""
    try:
        g = ctx.graph(refresh=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("graph build failed: %s", exc)
        return {"error": str(exc)}
    findings: list[Finding] = []
    for p in g.attack_paths(INTERNET, k=15, min_likelihood=min_likelihood):
        crit, like = p["target_criticality"], p["likelihood"]
        if crit < 3:
            continue
        score = crit * like
        sev = Severity.critical if score >= 2.5 else Severity.high if score >= 1.2 else Severity.medium if score >= 0.4 else Severity.low
        tgt = g.nodes[p["target"]]
        hops = " → ".join(n["label"] for n in p["nodes"])
        fixes = []
        for e in p["edges"]:
            for f in e["fixes"]:
                if f not in fixes:
                    fixes.append(f)
        findings.append(Finding(
            key=f"path:internet:{p['target']}", asset_id=tgt.asset_id, category=FindingCategory.attack_path,
            severity=sev, title=f"Internet attack path to {p['target_label']} ({round(100 * like)}% likely, {len(p['edges'])} steps)",
            description=hops, evidence={"path": p, "fixes": fixes},
            remediation=Remediation(kind=RemediationKind.manual,
                                    summary="Break the chain at any link; see the remediation plan for the most effective one",
                                    details="\n".join(f"- {g.fixes[f].title}" for f in fixes if f in g.fixes)),
            source="graph", tags=[e["technique"] for e in p["edges"]]))
    return ctx.store.replace_findings("graph", None, findings)


def enrich_alert(ctx: Any, alert: Alert) -> None:
    """Attach 'what is at risk if this host is compromised' to a SIEM alert."""
    if not alert.asset_id or alert.id is None:
        return
    try:
        br = ctx.graph().blast_radius(alert.asset_id)
    except KeyError:
        return
    except Exception as exc:  # noqa: BLE001
        log.debug("alert enrichment failed: %s", exc)
        return
    ctx.store.update_alert_context(alert.id, {"blast_radius": br["summary"], "containment": br["containment"][:5]})


def resolve_asset_by_ip(ctx: Any, ip: str, hostname: str = "") -> Optional[str]:
    cache = ctx.extras.setdefault("ip_asset_cache", {})
    if not cache or ip not in cache:
        cache.clear()
        for a in ctx.store.list_assets("host"):
            for i in a["data"].get("ips", []):
                cache[i] = a["id"]
            cache[a["name"].lower()] = a["id"]
    return cache.get(ip) or (cache.get(hostname.lower()) if hostname else None)
