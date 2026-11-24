"""Posture scoring.

Host score: ``100 × exp(-D / 70)`` where D sums, per severity bucket, ``w × log2(1 + S/w)``
(w = critical 25, high 10, medium 4, low 1; S = the bucket's *effective* weight, which
discounts unpatchable and non-exploitable vulnerabilities). Diminishing returns keep a
host with hundreds of low-grade findings from flat-lining at zero, while every additional
serious finding still costs points.

Org score: the criticality-weighted mean of host scores, adjusted by how
reachable crown jewels are from the internet (attack-graph external risk).
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any


def grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


SEV_W = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


def effective_weight(f) -> float:
    """How much a finding should count. Vulnerabilities nobody can patch yet, and ones
    that are neither remotely exploitable, privilege escalations nor known-exploited,
    are real but less urgent than a misconfiguration you can fix today."""
    w = float(SEV_W[f.severity.value])
    if f.category.value == "vulnerability":
        ev = f.evidence or {}
        if not ev.get("actionable", True):
            w *= 0.25
        if not (ev.get("remote_exploitable") or ev.get("privesc") or ev.get("kev")):
            w *= 0.5
    return w


def _score(findings) -> float:
    """Diminishing returns per severity bucket: the 50th medium finding matters less than the
    first, but more criticals always lower the score. 1 fixable critical ≈ 70, 3 highs ≈ 75."""
    buckets: dict[str, float] = defaultdict(float)
    for f in findings:
        buckets[f.severity.value] += effective_weight(f)
    d = sum(SEV_W[s] * math.log2(1 + total / SEV_W[s]) for s, total in buckets.items() if SEV_W[s])
    return round(100 * math.exp(-d / 70.0), 1)


def compute(ctx: Any, include_graph: bool = True) -> dict:
    store = ctx.store
    assets = store.list_assets()
    findings = store.list_findings(status="open")
    by_asset: dict[str, list] = defaultdict(list)
    for f in findings:
        by_asset[f.asset_id or "_global"].append(f)
    hosts = []
    num = den = 0.0
    for a in assets:
        fs = by_asset.get(a["id"], [])
        s = _score(fs)
        counts = Counter(f.severity.value for f in fs)
        hosts.append({"asset_id": a["id"], "name": a["name"], "kind": a["kind"], "criticality": a["criticality"],
                      "score": s, "grade": grade(s), "counts": dict(counts), "findings": len(fs),
                      "last_seen": a["last_seen"]})
        num += s * a["criticality"]
        den += a["criticality"]
    if not assets:
        return {"score": None, "grade": "–", "hosts": [],
                "counts": {"severity": {}, "category": {}, "assets": 0, "open_findings": 0},
                "external_risk": None, "internet_attack_paths": 0,
                "note": "No data yet: enroll an agent, import a firewall config or run an external scan."}
    base = num / den if den else 100.0
    base *= _score(by_asset.get("_global", [])) / 100.0 if by_asset.get("_global") else 1.0
    ext_risk = None
    paths = 0
    if include_graph and assets:
        try:
            from .graph.engine import INTERNET
            g = ctx.graph()
            ext_risk = round(g.risk([INTERNET]), 3)
            paths = len(g.attack_paths(INTERNET, k=10, min_likelihood=0.05))
            # each unit of external risk (criticality × probability) costs up to 30 points
            base *= 1 - 0.3 * (1 - math.exp(-ext_risk / 5.0))
        except Exception:  # graph problems must never break scoring
            ext_risk = None
    sev = Counter(f.severity.value for f in findings)
    cat = Counter(f.category.value for f in findings)
    score = round(base, 1)
    hosts.sort(key=lambda h: h["score"])
    return {"score": score, "grade": grade(score), "hosts": hosts,
            "counts": {"severity": dict(sev), "category": dict(cat), "assets": len(assets), "open_findings": len(findings)},
            "external_risk": ext_risk, "internet_attack_paths": paths}
