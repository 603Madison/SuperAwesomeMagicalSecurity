"""Package vulnerability scanner.

``VulnScanner.scan(inventory, asset_id)`` -> one ``Finding`` per vulnerable
package. For distro packages the unit is the *source* package (Debian/Ubuntu
source, Alpine origin): ``libssl3`` and ``openssl`` from the same source are a
single finding whose remediation upgrades all affected binary packages.

Matching modes (``settings.vuln.mode``):

* ``online``  -- api.osv.dev (package names + versions leave the network)
* ``offline`` -- only the local mirror (``sams vulndb sync``)
* ``hybrid``  -- local mirror for mirrored ecosystems, online for the rest

Online results are re-evaluated locally to compute fixed versions; where our
comparator is exact (dpkg/rpm/apk/PEP 440/SemVer) and it disagrees with the
API (typically RPM epoch omissions) the match is dropped.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

from ..config import Settings
from ..models import Finding, FindingCategory, Inventory, OSInfo, Package, Remediation, RemediationKind, Severity
from . import cvss, versions
from .ecosystems import EcosystemQuery, resolve
from .enrich import CVE_RE, ThreatIntel
from .osv import LocalOSVDB, OSVClient, evaluate

log = logging.getLogger(__name__)

_PRIVESC_RE = re.compile(r"privilege[s]? escalat|escalat\w* (?:of )?privilege|elevat\w* (?:of )?privilege|"
                         r"local root|gain root|root privileges|local (?:user|attacker)s? (?:could|can|may) .*root",
                         re.IGNORECASE)
_REMOTE_TEXT_RE = re.compile(r"remote(?:ly)? (?:attacker|code execution|unauthenticated)|remote attackers|"
                             r"via (?:a )?(?:crafted|malicious) (?:network|http|request|packet)", re.IGNORECASE)
_LOCAL_TEXT_RE = re.compile(r"local (?:user|attacker)s?", re.IGNORECASE)

_SEV_ORDER = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]


def _sev_max(a: Severity, b: Severity) -> Severity:
    return a if _SEV_ORDER.index(a) >= _SEV_ORDER.index(b) else b


@dataclass
class PackageVulns:
    query: EcosystemQuery
    installed_version: str
    binary_packages: list[str] = field(default_factory=list)
    vulns: list[dict[str, Any]] = field(default_factory=list)    # normalized vuln dicts (see _normalize)
    fixed_version: Optional[str] = None


def _aliases(vuln: dict) -> list[str]:
    out: list[str] = []
    for k in ("aliases", "upstream", "related"):
        for a in vuln.get(k) or []:
            if k == "related" and not CVE_RE.match(a):
                continue
            if a not in out and a != vuln.get("id"):
                out.append(a)
    if CVE_RE.match(vuln.get("id", "")):
        out.insert(0, vuln["id"])
    return out


_PRIMARY_PREFIXES = ("CVE-", "UBUNTU-CVE-", "DEBIAN-CVE-", "ALPINE-CVE-", "GHSA-")
_SECONDARY_PREFIXES = ("PYSEC-", "GO-", "RUSTSEC-", "MAL-")


def _id_rank(vid: str) -> int:
    if vid.startswith(_PRIMARY_PREFIXES):
        return 0
    if vid.startswith(_SECONDARY_PREFIXES):
        return 1
    return 2    # aggregate advisories: USN, DSA, DLA, RHSA, RLSA, ALSA, SUSE-SU ...


def dedupe(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop records whose CVEs are all already represented by a preferred record
    (e.g. a USN notice when every UBUNTU-CVE it covers matched too, or a PYSEC
    twin of a GHSA). Dropped ids are kept in ``related_ids`` of the survivor."""
    ordered = sorted(vulns, key=lambda v: (_id_rank(v["id"]), v["cvss_score"] is None, v["id"]))
    covered: dict[str, dict] = {}     # identifier -> kept record
    kept: list[dict[str, Any]] = []
    for v in ordered:
        ids = {v["id"], *v["aliases"]}
        cves = {a for a in ids if CVE_RE.match(a)}
        key_ids = cves or {v["id"]}
        if key_ids and all(k in covered for k in key_ids):
            owner = covered[sorted(key_ids)[0]]
            owner.setdefault("related_ids", [])
            if v["id"] not in owner["related_ids"]:
                owner["related_ids"].append(v["id"])
            # keep the most useful data from the duplicate
            if owner.get("fixed") is None and v.get("fixed"):
                owner["fixed"] = v["fixed"]
            continue
        kept.append(v)
        for k in ids:
            covered.setdefault(k, v)
    return kept


def _normalize(vuln: dict, affected: Optional[dict], fixed: Optional[str]) -> dict[str, Any]:
    sev = cvss.from_osv(vuln, affected)
    text = f"{vuln.get('summary', '')} {vuln.get('details', '')}"
    av, av_source = sev.attack_vector, "cvss" if sev.attack_vector != "unknown" else "unknown"
    if av == "unknown":
        if _REMOTE_TEXT_RE.search(text):
            av, av_source = "network", "text"
        elif _LOCAL_TEXT_RE.search(text) or _PRIVESC_RE.search(text):
            av, av_source = "local", "text"
    summary = (vuln.get("summary") or (vuln.get("details") or "").strip().split("\n")[0])[:300]
    if sev.score is not None:
        severity = Severity.from_cvss(sev.score)
    else:
        severity = Severity.medium
    return {
        "id": vuln.get("id"),
        "aliases": _aliases(vuln),
        "summary": summary,
        "cvss_score": sev.score,
        "cvss_vector": sev.vector,
        "severity": severity.value,
        "severity_source": sev.version or "none",
        "attack_vector": av,
        "attack_vector_source": av_source,
        "privesc_text": bool(_PRIVESC_RE.search(text)),
        "kev": False,
        "epss": None,
        "fixed": fixed,
        "published": vuln.get("published"),
    }


_MANAGER_COMMANDS = {
    "dpkg": "apt-get update && apt-get install --only-upgrade -y {pkgs}",
    "rpm": "dnf upgrade -y {pkgs}",
    "apk": "apk update && apk upgrade {pkgs}",
}


class VulnScanner:
    def __init__(self, settings: Settings, transport: Optional[httpx.BaseTransport] = None,
                 local_db: Optional[LocalOSVDB] = None):
        self.settings = settings
        self.mode = settings.vuln.mode
        cache = Path(settings.cache_dir)
        self.client = OSVClient(settings.vuln, cache, transport=transport)
        self.intel = ThreatIntel(settings.vuln, cache, transport=transport)
        self._local = local_db
        self._local_path = Path(settings.data_dir) / "osv.db"
        self.last_stats: dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    @property
    def local(self) -> Optional[LocalOSVDB]:
        if self._local is None and (self.mode in ("offline", "hybrid")) and self._local_path.exists():
            self._local = LocalOSVDB(self._local_path)
        return self._local

    def _use_local(self, ecosystem: str) -> bool:
        if self.mode == "online":
            return False
        if self.mode == "offline":
            return True
        db = self.local
        return db is not None and db.covers(ecosystem)

    # ------------------------------------------------------------------ #
    def scan_packages(self, packages: list[Package], os_info: OSInfo) -> list[PackageVulns]:
        stats = {"packages_total": len(packages), "packages_scanned": 0, "packages_unsupported": 0,
                 "packages_vulnerable": 0, "vulns_total": 0, "mode": self.mode, "errors": [],
                 "unsupported_managers": {}}
        # group installed binaries by (ecosystem, query name, version)
        groups: dict[tuple[str, str, str], PackageVulns] = {}
        for pkg in packages:
            qs = resolve(pkg, os_info)
            if qs is None:
                stats["packages_unsupported"] += 1
                stats["unsupported_managers"][pkg.manager] = stats["unsupported_managers"].get(pkg.manager, 0) + 1
                continue
            stats["packages_scanned"] += 1
            for q in qs:
                key = (q.ecosystem, q.name, q.version)
                pv = groups.get(key)
                if pv is None:
                    pv = groups[key] = PackageVulns(query=q, installed_version=pkg.version)
                if pkg.name not in pv.binary_packages:
                    pv.binary_packages.append(pkg.name)

        raw: dict[tuple[str, str, str], list[dict]] = {k: [] for k in groups}
        local_keys = [k for k in groups if self._use_local(k[0])]
        online_keys = [k for k in groups if k not in set(local_keys)]

        db = self.local
        if local_keys and db is None:
            stats["errors"].append("offline mode but no local OSV mirror; run `sams vulndb sync`")
        for k in local_keys:
            if db is not None:
                raw[k] = db.match(*k)

        if online_keys:
            try:
                id_lists = self.client.query_batch(list(online_keys))
                vulns = self.client.get_vulns(i for ids in id_lists for i in ids)
                for k, ids in zip(online_keys, id_lists):
                    raw[k] = [vulns[i] for i in ids if i in vulns]
            except Exception as exc:   # noqa: BLE001
                log.warning("OSV online query failed: %s", exc)
                stats["errors"].append(f"osv online: {exc}")

        results: list[PackageVulns] = []
        for k, pv in groups.items():
            eco, name, ver = k
            precise = versions.base_ecosystem(eco) in versions.PRECISE_ECOSYSTEMS
            seen: set[str] = set()
            for vuln in raw.get(k) or []:
                vid = vuln.get("id")
                if not vid or vid in seen:
                    continue
                affected, fixed, entry = evaluate(vuln, eco, name, ver)
                if affected is False and precise:
                    continue
                if vuln.get("withdrawn"):
                    continue
                seen.add(vid)
                pv.vulns.append(_normalize(vuln, entry, fixed))
            pv.vulns = dedupe(pv.vulns)
            if pv.vulns:
                results.append(pv)

        # RHEL: the same package queried for baseos + appstream -> merge
        merged: dict[tuple[str, str], PackageVulns] = {}
        for pv in results:
            mk = (pv.query.ecosystem.split("::")[0], pv.query.name)
            if mk in merged:
                ids = {v["id"] for v in merged[mk].vulns}
                merged[mk].vulns += [v for v in pv.vulns if v["id"] not in ids]
            else:
                merged[mk] = pv
        results = list(merged.values())

        self._enrich(results)
        for pv in results:
            fixes = [v["fixed"] for v in pv.vulns if v.get("fixed")]
            pv.fixed_version = versions.max_version(pv.query.ecosystem, fixes)
            pv.vulns.sort(key=lambda v: (not v["kev"], -(v["cvss_score"] or 0), v["id"]))
        stats["packages_vulnerable"] = len(results)
        stats["vulns_total"] = sum(len(pv.vulns) for pv in results)
        self.last_stats = stats
        return results

    def _enrich(self, results: list[PackageVulns]) -> None:
        cves = {a for pv in results for v in pv.vulns for a in v["aliases"] if CVE_RE.match(a)}
        if not cves:
            return
        kev = self.intel.kev()
        epss = self.intel.epss(cves)
        for pv in results:
            for v in pv.vulns:
                ids = [a for a in v["aliases"] if CVE_RE.match(a)]
                hits = [kev[c] for c in ids if c in kev]
                if hits:
                    v["kev"] = True
                    v["kev_info"] = hits[0]
                scores = [epss[c] for c in ids if c in epss]
                v["epss"] = max(scores) if scores else None

    # ------------------------------------------------------------------ #
    def scan(self, inv: Inventory, asset_id: str) -> list[Finding]:
        return [self.to_finding(pv, asset_id) for pv in self.scan_packages(inv.packages, inv.host.os)]

    def to_finding(self, pv: PackageVulns, asset_id: str) -> Finding:
        q = pv.query
        vulns = pv.vulns
        severity = Severity.info
        for v in vulns:
            severity = _sev_max(severity, Severity(v["severity"]))
        kev = any(v["kev"] for v in vulns)
        if kev:
            severity = Severity.critical
        scores = [v["cvss_score"] for v in vulns if v["cvss_score"] is not None]
        epss_vals = [v["epss"] for v in vulns if v["epss"] is not None]
        remote = any(v["attack_vector"] == "network" and ((v["cvss_score"] or 0) >= 7 or v["kev"]) for v in vulns)
        privesc = any(v["attack_vector"] == "local" and (v["privesc_text"] or v["kev"]) for v in vulns)
        n = len(vulns)
        title = f"{q.name} {pv.installed_version}: {n} vulnerabilit{'y' if n == 1 else 'ies'}"
        title += f" (fixed in {pv.fixed_version})" if pv.fixed_version else " (no fix available)"

        bins = pv.binary_packages or [q.binary_name]
        commands: list[str] = []
        if q.manager in _MANAGER_COMMANDS:
            commands.append(_MANAGER_COMMANDS[q.manager].format(pkgs=" ".join(bins)))
        elif q.manager in ("pypi", "pip") and pv.fixed_version:
            commands.append(f"pip install --upgrade '{q.binary_name}>={pv.fixed_version}'")
        elif q.manager == "npm" and pv.fixed_version:
            commands.append(f"npm install {q.binary_name}@{pv.fixed_version}")
        automatable = bool(pv.fixed_version) and q.manager in ("dpkg", "rpm", "apk")
        remediation = Remediation(
            kind=RemediationKind.patch,
            summary=(f"Upgrade {', '.join(bins)} to {pv.fixed_version} or later" if pv.fixed_version
                     else f"No fixed version published for {q.name}; mitigate or replace"),
            details="Fixes: " + ", ".join(v["id"] for v in vulns[:20]) + (" ..." if n > 20 else ""),
            commands=commands,
            automatable=automatable,
            task={"action": "patch", "manager": q.manager, "packages": bins} if automatable else None,
            effort="low" if automatable else "medium",
            references=[f"https://osv.dev/vulnerability/{v['id']}" for v in vulns[:10]],
        )
        top = vulns[:5]
        description = "\n".join(
            f"- {v['id']}{' [KEV]' if v['kev'] else ''} ({v['severity']}"
            f"{', CVSS ' + str(v['cvss_score']) if v['cvss_score'] is not None else ''}): {v['summary']}"
            for v in top)
        if n > 5:
            description += f"\n... and {n - 5} more"
        tags = [t for t, on in (("kev", kev), ("remote", remote), ("privesc", privesc)) if on]
        return Finding(
            key=f"vuln:{asset_id}:{q.manager}:{q.name}",
            asset_id=asset_id,
            category=FindingCategory.vulnerability,
            severity=severity,
            title=title,
            description=description,
            evidence={
                "package": q.name,
                "binary_packages": bins,
                "installed_version": pv.installed_version,
                "manager": q.manager,
                "ecosystem": q.ecosystem,
                "fixed_version": pv.fixed_version,
                "vulns": vulns,
                "max_cvss": max(scores) if scores else None,
                "remote_exploitable": remote,
                "privesc": privesc,
                "kev": kev,
                "max_epss": max(epss_vals) if epss_vals else None,
            },
            remediation=remediation,
            references=remediation.references,
            tags=tags,
            source="vuln.osv",
        )

    def close(self) -> None:
        self.client.close()
        self.intel.close()
        if self._local is not None:
            self._local.close()


def sync_ecosystems(settings: Settings, ecosystems: list[str], transport: Optional[httpx.BaseTransport] = None) -> dict:
    """Mirror OSV bulk data for the given top-level ecosystems (e.g. ``["Ubuntu", "Debian", "PyPI"]``).
    Returns ``{ecosystem: count | "error: ..."}``."""
    db = LocalOSVDB(Path(settings.data_dir) / "osv.db")
    client = OSVClient(settings.vuln, Path(settings.cache_dir), transport=transport)
    out: dict[str, Any] = {}
    try:
        for eco in ecosystems:
            try:
                out[eco] = db.sync(eco, client)
            except Exception as exc:   # noqa: BLE001
                log.warning("sync %s failed: %s", eco, exc)
                out[eco] = f"error: {exc}"
    finally:
        client.close()
        db.close()
    return out


def suggest_ecosystems(inventories: list[Inventory]) -> list[str]:
    """Top-level ecosystems worth mirroring for the given fleet."""
    out: set[str] = set()
    for inv in inventories:
        for pkg in inv.packages:
            qs = resolve(pkg, inv.host.os)
            for q in qs or []:
                out.add(versions.base_ecosystem(q.ecosystem))
    return sorted(out)
