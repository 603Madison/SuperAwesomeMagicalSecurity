"""Posture scoring.

Host score: ``100 × exp(-W / 60)`` where W sums open-finding weights
(critical 25, high 10, medium 4, low 1). One critical finding leaves ~66,
and the score never goes negative, so it degrades smoothly.

Org score: the criticality-weighted mean of host scores, adjusted by how
reachable crown jewels are from the internet (attack-graph external risk).
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any


def grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def _score(weight: float) -> float:
    return round(100 * math.exp(-weight / 60.0), 1)


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
        w = sum(f.severity.weight for f in fs)
        s = _score(w)
        counts = Counter(f.severity.value for f in fs)
        hosts.append({"asset_id": a["id"], "name": a["name"], "kind": a["kind"], "criticality": a["criticality"],
                      "score": s, "grade": grade(s), "counts": dict(counts), "findings": len(fs),
                      "last_seen": a["last_seen"]})
        num += s * a["criticality"]
        den += a["criticality"]
    base = num / den if den else 100.0
    global_w = sum(f.severity.weight for f in by_asset.get("_global", []))
    base *= math.exp(-global_w / 200.0)
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
