"""CVSS parsing and scoring helpers.

* CVSS v3.0 / v3.1 base score: the official v3.1 formula (incl. the v3.1
  ``Roundup`` definition, also used for 3.0 vectors -- differences are
  limited to floating point edge cases).
* CVSS v4.0: the official score needs the macrovector lookup table; we only
  extract metrics (AV etc.) and compute a documented *approximation*.
* Fallback severities from OSV: Ubuntu priority (``severity[type=Ubuntu]``),
  GHSA ``database_specific.severity``, Debian ``urgency``.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Optional

AV_NAMES = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def parse_vector(vector: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (vector or "").strip().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def roundup(x: float) -> float:
    """CVSS v3.1 Roundup: smallest number, to 1 decimal place, >= x."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _W["AV"][m["AV"]]
        ac = _W["AC"][m["AC"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        ui = _W["UI"][m["UI"]]
        c, i, a = _W["CIA"][m["C"]], _W["CIA"][m["I"]], _W["CIA"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def cvss4_approx_score(vector: str) -> Optional[float]:
    """Approximate CVSS v4.0 base score (NOT the official macrovector lookup).

    Good enough for ranking: maps the v4 metrics onto the v3.1 formula
    (VC/VI/VA -> C/I/A, AT:P treated like AC:H, subsequent-system impact
    treated as scope change)."""
    m = parse_vector(vector)
    if "AV" not in m:
        return None
    ac = "H" if m.get("AC") == "H" or m.get("AT") == "P" else "L"
    ui = "N" if m.get("UI", "N") == "N" else "R"
    sub = any(m.get(k) == "H" for k in ("SC", "SI", "SA"))
    v3 = (f"AV:{m['AV']}/AC:{ac}/PR:{m.get('PR', 'N')}/UI:{ui}/S:{'C' if sub else 'U'}/"
          f"C:{m.get('VC', 'N')}/I:{m.get('VI', 'N')}/A:{m.get('VA', 'N')}")
    return cvss3_base_score(v3)


def attack_vector(vector: str) -> str:
    return AV_NAMES.get(parse_vector(vector).get("AV", ""), "unknown")


# Text label -> representative score
_LABEL_SCORES = {
    "critical": 9.5, "high": 7.5, "important": 7.5, "moderate": 5.5, "medium": 5.5,
    "low": 3.0, "negligible": 1.0, "unimportant": 1.0,
}


@dataclass
class SeverityInfo:
    score: Optional[float] = None
    vector: str = ""
    version: str = ""            # "3.1", "3.0", "4.0", "label"
    attack_vector: str = "unknown"
    label: str = ""              # textual severity if that is all we have


def from_osv(vuln: dict[str, Any], affected: Optional[dict[str, Any]] = None) -> SeverityInfo:
    """Best severity information for an OSV record (and optionally the
    specific ``affected`` entry, which may carry its own severity)."""
    entries: list[dict] = list(vuln.get("severity") or [])
    if affected:
        entries += list(affected.get("severity") or [])
    best: Optional[SeverityInfo] = None
    labels: list[str] = []
    for e in entries:
        typ, score = (e.get("type") or "").upper(), str(e.get("score") or "")
        info: Optional[SeverityInfo] = None
        if typ == "CVSS_V3" or score.startswith("CVSS:3"):
            s = cvss3_base_score(score)
            if s is not None:
                info = SeverityInfo(s, score, score.split("/")[0].split(":")[-1] if score.startswith("CVSS:") else "3",
                                    attack_vector(score))
        elif typ == "CVSS_V4" or score.startswith("CVSS:4"):
            s = cvss4_approx_score(score)
            if s is not None:
                info = SeverityInfo(s, score, "4.0", attack_vector(score))
        elif typ == "CVSS_V2":
            continue   # too coarse; ignored
        else:
            labels.append(score.lower())
        if info and (best is None or (info.score or 0) > (best.score or 0)):
            best = info
    # textual fallbacks
    for holder in (vuln.get("database_specific") or {}, (affected or {}).get("database_specific") or {},
                   (affected or {}).get("ecosystem_specific") or {}):
        for key in ("severity", "urgency", "priority"):
            val = holder.get(key)
            if isinstance(val, str):
                labels.append(val.lower())
    if best is not None:
        if labels:
            best.label = labels[0]
        return best
    for lab in labels:
        for word, score in _LABEL_SCORES.items():
            if word in lab:
                return SeverityInfo(score=score, version="label", label=lab)
    return SeverityInfo()
