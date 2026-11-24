"""Risk-ranked remediation planning.

Risk model (see docs/ARCHITECTURE.md):

    R = W_ext * risk_from(internet)
      + W_int * mean over hosts h of risk_from(an arbitrary unprivileged user on h)

where ``risk_from(s) = Σ_targets criticality(t) × P(best path s → t)``. The
internal term is the "assume breach" view: phishing, a malicious package or a
stolen laptop gives an attacker *some* account on *some* host. How far can
they get?

Each fix removes the graph edges that list it. We pick fixes greedily by
marginal risk reduction (lazy greedy: reductions only shrink as other fixes
are applied, so stale upper bounds are re-evaluated only when they reach the
top of the heap). Findings that don't sit on any attack path are appended
afterwards, ranked by severity × asset criticality ("hygiene").
"""
from __future__ import annotations

import heapq
from typing import Any, Optional

from ..graph.engine import ANY_USER, INTERNET, AttackGraph
from ..models import Finding, Remediation, RemediationKind, Severity
from ..posture import effective_weight

W_EXT = 3.0
W_INT = 1.0


def _sources(g: AttackGraph) -> tuple[list[str], dict[str, float]]:
    # "assume breach": an arbitrary account on every host, plus every interactive (phishable) user
    internal = [n for n, node in g.nodes.items()
                if n.endswith(f"#user:{ANY_USER}") or node.attrs.get("interactive")]
    weights = {INTERNET: W_EXT}
    for n in internal:
        weights[n] = W_INT / max(1, len(internal))
    return [INTERNET] + internal, weights


def _candidate_fixes(g: AttackGraph, sources: list[str]) -> set[str]:
    """Fixes on at least one best path to a target. Others can't change R."""
    cands: set[str] = set()
    for s in sources:
        prob, pred = g.dijkstra(s, 0.001)
        for n in prob:
            if g.nodes[n].criticality <= 0:
                continue
            cur, seen = n, set()
            while cur in pred and cur not in seen:
                seen.add(cur)
                e = pred[cur]
                cands.update(e.fixes)
                cur = e.src
    return cands


def _sev_from_share(share: float) -> Severity:
    if share >= 0.25:
        return Severity.critical
    if share >= 0.10:
        return Severity.high
    if share >= 0.03:
        return Severity.medium
    return Severity.low


def rank_fixes(g: AttackGraph, max_rounds: int = 25) -> tuple[float, list[dict]]:
    sources, weights = _sources(g)
    base = g.risk(sources, None, weights)
    cands = _candidate_fixes(g, sources)
    if base <= 0 or not cands:
        return base, []
    removed: set[str] = set()
    current = base
    heap: list[tuple[float, str, int]] = []
    single: dict[str, float] = {}
    for f in cands:
        red = base - g.risk(sources, {f}, weights)
        single[f] = red
        heapq.heappush(heap, (-red, f, 0))
    chosen: list[dict] = []
    rnd = 0
    while heap and rnd < max_rounds:
        negred, f, stamp = heapq.heappop(heap)
        if -negred <= 1e-9:
            break
        if stamp != rnd:  # stale bound -> re-evaluate against current state
            red = current - g.risk(sources, removed | {f}, weights)
            heapq.heappush(heap, (-red, f, rnd))
            continue
        removed.add(f)
        new = current - (-negred)
        chosen.append({"fix": f, "marginal_reduction": round(-negred, 4), "single_reduction": round(single[f], 4),
                       "risk_after": round(new, 4)})
        current = new
        rnd += 1
    chosen_keys = {c["fix"] for c in chosen}
    rest = sorted(((single[f], f) for f in cands if f not in chosen_keys and single[f] > 1e-9), reverse=True)
    for red, f in rest:
        chosen.append({"fix": f, "marginal_reduction": None, "single_reduction": round(red, 4), "risk_after": None})
    return base, chosen


def _fix_remediation(g: AttackGraph, key: str, finding: Optional[Finding]) -> Remediation:
    if finding and finding.remediation:
        return finding.remediation
    fx = g.fixes.get(key)
    kind = RemediationKind(fx.kind) if fx and fx.kind in RemediationKind.__members__ else RemediationKind.manual
    return Remediation(kind=kind, summary=fx.title if fx else key, details=fx.details if fx else "",
                       commands=fx.commands if fx else [])


def build_plan(ctx: Any, limit: int = 50) -> list[dict]:
    g: AttackGraph = ctx.graph()
    findings = {f.key: f for f in ctx.store.list_findings(status="open")}
    assets = {a["id"]: a for a in ctx.store.list_assets()}
    base, ranked = rank_fixes(g)
    plan: list[dict] = []
    used_findings: set[str] = set()
    for r in ranked:
        key = r["fix"]
        fx = g.fixes.get(key)
        fkey = fx.finding_key if fx and fx.finding_key in findings else (key if key in findings else None)
        finding = findings.get(fkey) if fkey else None
        red = r["single_reduction"]
        share = red / base if base else 0
        sev = _sev_from_share(share)
        if finding and finding.severity.weight > sev.weight:
            sev = finding.severity
        rem = _fix_remediation(g, key, finding)
        if fkey:
            used_findings.add(fkey)
        plan.append({
            "id": key, "title": rem.summary if not finding else (fx.title if fx else finding.title),
            "kind": rem.kind.value, "severity": sev.value,
            "asset_ids": fx.asset_ids if fx else ([finding.asset_id] if finding and finding.asset_id else []),
            "asset_names": [assets.get(a, {}).get("name", a) for a in (fx.asset_ids if fx else [])],
            # risk_reduction*: if this fix were done on its own. marginal_*: on top of the fixes ranked above it.
            "risk_reduction": round(red, 4), "risk_reduction_pct": round(100 * share, 1),
            "marginal_reduction_pct": (round(100 * r["marginal_reduction"] / base, 1)
                                       if r["marginal_reduction"] is not None and base else None),
            "finding_keys": [fkey] if fkey else [], "remediation": rem.model_dump(),
            "automatable": rem.automatable, "task": rem.task, "reason": "attack_path",
            "greedy": r["marginal_reduction"] is not None,
        })
    hygiene = []
    for f in findings.values():
        if f.key in used_findings or not f.remediation:
            continue
        crit = assets.get(f.asset_id or "", {}).get("criticality", 3)
        hygiene.append((effective_weight(f) * crit, f))
    hygiene.sort(key=lambda x: -x[0])
    for score, f in hygiene:
        rem = f.remediation
        assert rem is not None
        plan.append({
            "id": f.key, "title": f.title, "kind": rem.kind.value, "severity": f.severity.value,
            "asset_ids": [f.asset_id] if f.asset_id else [],
            "asset_names": [assets.get(f.asset_id or "", {}).get("name", f.asset_id)] if f.asset_id else [],
            "risk_reduction": 0.0, "risk_reduction_pct": 0.0, "marginal_reduction_pct": None, "finding_keys": [f.key],
            "remediation": rem.model_dump(), "automatable": rem.automatable, "task": rem.task,
            "reason": "hygiene", "greedy": False, "hygiene_score": score,
        })
    for i, item in enumerate(plan, 1):
        item["rank"] = i
    return plan[:limit]


def plan_summary(ctx: Any) -> dict:
    g: AttackGraph = ctx.graph()
    sources, weights = _sources(g)
    base = g.risk(sources, None, weights)
    ext = g.risk([INTERNET], None, None)
    return {"total_risk": round(base, 3), "external_risk": round(ext, 3), "sources": len(sources)}
