"""Outside-in assessment: scope management, signed probe jobs, result analysis.

The probe runs *outside* the network (VPS / cloud, internet only). The server:

1. keeps an admin-curated scope of public assets we own (IPs, small CIDRs, hostnames);
2. issues signed jobs restricted to that scope;
3. turns probe observations into findings; and
4. compares the **outside view** with the **inside view** (firewall port forwards,
   host listeners). Discrepancies are often the most valuable findings: a port
   open that no rule explains, or a forward that is configured but dead.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import Any, Optional

from .firewall.model import FirewallConfig
from .models import (ExternalScanResult, Finding, FindingCategory, Remediation, RemediationKind, Severity,
                     utcnow)

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
TOP_PORTS_HINT = "top100"
RISKY_PORTS = {21: ("FTP", Severity.high), 23: ("Telnet", Severity.critical), 135: ("MS RPC", Severity.high),
               139: ("NetBIOS", Severity.critical), 445: ("SMB", Severity.critical), 1433: ("MS SQL", Severity.critical),
               2375: ("Docker API", Severity.critical), 2379: ("etcd", Severity.critical), 3306: ("MySQL", Severity.critical),
               3389: ("RDP", Severity.critical), 5432: ("PostgreSQL", Severity.critical), 5900: ("VNC", Severity.high),
               5985: ("WinRM", Severity.high), 6379: ("Redis", Severity.critical), 9200: ("Elasticsearch", Severity.critical),
               10250: ("Kubelet", Severity.critical), 11211: ("Memcached", Severity.high), 27017: ("MongoDB", Severity.critical),
               161: ("SNMP", Severity.high), 22: ("SSH", Severity.low)}


class ScopeError(ValueError):
    pass


def classify_target(value: str, max_hosts: int) -> str:
    v = value.strip().lower()
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        addr = None
    if addr is not None:
        if not addr.is_global:
            raise ScopeError(f"{v} is not a public address: external probes only scan internet-facing assets")
        return "ip"
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ScopeError(str(exc)) from exc
        if not net.is_global:
            raise ScopeError(f"{v} is not a public network")
        if net.num_addresses > max_hosts:
            raise ScopeError(f"{v} has {net.num_addresses} addresses; the limit is {max_hosts}")
        return "cidr"
    if HOST_RE.match(v):
        return "hostname"
    raise ScopeError(f"{value!r} is not an IP, CIDR or hostname")


def add_target(ctx: Any, value: str, note: str = "") -> dict:
    kind = classify_target(value, ctx.settings.external.max_cidr_hosts)
    return ctx.store.add_external_target(value.strip().lower(), kind, note)


def suggest_targets(ctx: Any) -> list[str]:
    """WAN addresses from firewall configs are natural scope candidates."""
    out = []
    for fw in ctx.store.list_firewalls():
        cfg = fw.get("config") or {}
        for ip in cfg.get("wan_addresses", []):
            try:
                if ipaddress.ip_address(ip).is_global:
                    out.append(ip)
            except ValueError:
                pass
    existing = {t["value"] for t in ctx.store.list_external_targets()}
    return sorted(set(out) - existing)


def create_job(ctx: Any, ports: Optional[str] = None, checks: Optional[list[str]] = None,
               targets: Optional[list[str]] = None) -> str:
    scope = [t["value"] for t in ctx.store.list_external_targets()]
    if targets:
        missing = [t for t in targets if t not in scope]
        if missing:
            raise ScopeError(f"targets not in scope: {missing}")
        scope = targets
    if not scope:
        raise ScopeError("external scope is empty; add targets first")
    s = ctx.settings.external
    job_doc = {"targets": scope, "ports": ports or s.default_ports,
               "checks": checks or ["tcp", "banner", "tls", "http", "dns", "udp"],
               "rate_per_sec": s.rate_per_sec}
    return ctx.store.create_external_job(job_doc)


def expand_ports(spec: str | list[int]) -> list[int] | str:
    if isinstance(spec, list):
        return spec
    if spec in ("top100", "top1000"):
        return spec  # the probe embeds these lists
    out: set[int] = set()
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return sorted(p for p in out if 0 < p < 65536)


def claim_job(ctx: Any, probe_id: str) -> Optional[dict]:
    job = ctx.store.claim_external_job(probe_id)
    if not job:
        return None
    scope = job["scope"]
    payload = {"job_id": job["id"], "probe_id": probe_id, "targets": scope["targets"],
               "ports": expand_ports(scope["ports"]), "checks": scope["checks"],
               "rate_per_sec": scope["rate_per_sec"],
               "expires_at": (utcnow() + timedelta(hours=ctx.settings.external.job_ttl_hours)).isoformat()}
    return ctx.signer.sign(payload)


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #
def _sev(s: str) -> Severity:
    try:
        return Severity(s)
    except ValueError:
        return Severity.medium


def analyze_result(ctx: Any, result: ExternalScanResult) -> dict[str, list[Finding]]:
    """Return findings grouped by asset id (one external asset per target)."""
    firewalls = [FirewallConfig.model_validate(f["config"]) for f in ctx.store.list_firewalls() if f.get("config")]
    wan_ips = {ip for fw in firewalls for ip in fw.wan_addresses}
    forwards: dict[int, list] = {}
    for fw in firewalls:
        for pf in fw.port_forwards:
            if not pf.enabled:
                continue
            for r in pf.external_ports or []:
                for p in range(r.start, min(r.end, r.start + 1024) + 1):
                    forwards.setdefault(p, []).append((fw, pf))
    out: dict[str, list[Finding]] = {}

    if result.probe_public_ip and result.probe_public_ip in wan_ips:
        aid = "ext:_probe"
        out.setdefault(aid, []).append(Finding(
            key=f"ext:probe_on_network:{result.probe_id}", asset_id=None, category=FindingCategory.external,
            severity=Severity.high, title="External probe is scanning from inside the network",
            description=f"The probe's egress IP {result.probe_public_ip} is one of your own WAN addresses, so it sees "
                        "the network from the inside (hairpin NAT) and results do not reflect what the internet sees.",
            remediation=Remediation(kind=RemediationKind.manual,
                                    summary="Run sams-probe on a host outside your network (cheap VPS / cloud function)"),
            source="external"))

    for t in result.targets:
        aid = f"ext:{t.target}"
        fs: list[Finding] = []
        is_wan = any(ip in wan_ips for ip in (t.resolved or [t.target]))
        for issue in t.issues:
            iid = issue.get("id", "issue")
            port = issue.get("port")
            fs.append(Finding(
                key=f"ext:{t.target}:{iid}:{port or ''}", asset_id=aid, category=FindingCategory.external,
                severity=_sev(issue.get("severity", "medium")), title=f"{t.target}: {issue.get('title', iid)}",
                description=issue.get("detail", ""), evidence={"target": t.target, "issue": issue},
                remediation=_remediation_for(iid, port, is_wan), source="external", tags=[iid]))
        for svc in t.services:
            if svc.state != "open":
                continue
            name, sev = RISKY_PORTS.get(svc.port, (None, None))
            explained = forwards.get(svc.port) if is_wan else None
            if not explained and is_wan and firewalls:
                fs.append(Finding(
                    key=f"ext:{t.target}:unexplained:{svc.port}", asset_id=aid, category=FindingCategory.external,
                    severity=Severity.high if svc.port not in (80, 443) else Severity.medium,
                    title=f"{t.target}:{svc.port} is open from the internet but no firewall rule explains it",
                    description="The external probe found this port open, but none of the imported firewall "
                                "configurations forward it. Common causes: a service on the firewall itself (admin UI, "
                                "VPN), UPnP-created mappings, an ISP router in front, or a stale config import.",
                    evidence={"service": svc.model_dump()},
                    remediation=Remediation(kind=RemediationKind.firewall,
                                            summary=f"Identify what answers on port {svc.port} and close it if unintended",
                                            details="Check UPnP leases, the firewall's own services, and any upstream device."),
                    source="external", tags=["discrepancy"]))
            if name and not any(i.get("port") == svc.port for i in t.issues):
                fs.append(Finding(
                    key=f"ext:{t.target}:exposed:{svc.port}", asset_id=aid, category=FindingCategory.external,
                    severity=sev or Severity.medium, title=f"{name} exposed to the internet on {t.target}:{svc.port}",
                    description=f"{name} is reachable from anywhere on the internet. Services like this are "
                                "continuously scanned and brute-forced; prefer a VPN or source-IP restriction.",
                    evidence={"service": svc.model_dump(), "forwards": [pf.description or pf.id for _, pf in explained or []]},
                    remediation=_remediation_for(f"exposed_{svc.port}", svc.port, is_wan), source="external",
                    tags=["exposure"]))
        out[aid] = fs

    # forwards configured but not observed open
    observed = {(ip, s.port) for t in result.targets for ip in (t.resolved or [t.target]) for s in t.services
                if s.state == "open"}
    scanned_ips = {ip for t in result.targets for ip in (t.resolved or [t.target])}
    for fw in firewalls:
        for pf in fw.port_forwards:
            if not pf.enabled:
                continue
            for ip in fw.wan_addresses:
                if ip not in scanned_ips:
                    continue
                for r in pf.external_ports[:1]:
                    if (ip, r.start) not in observed:
                        aid = f"ext:{ip}"
                        out.setdefault(aid, []).append(Finding(
                            key=f"ext:{ip}:stale_forward:{r.start}", asset_id=aid, category=FindingCategory.firewall,
                            severity=Severity.low,
                            title=f"Port forward {ip}:{r.start} → {pf.internal_ip} is configured but not reachable",
                            description="The external probe could not connect. If the service is gone, remove the "
                                        "forward so it can't be silently re-exposed later.",
                            evidence={"forward": pf.model_dump(), "firewall": fw.hostname},
                            remediation=Remediation(kind=RemediationKind.firewall,
                                                    summary=f"Remove stale port forward '{pf.description or pf.id}'"),
                            source="external", tags=["discrepancy"]))
    return out


def _remediation_for(issue_id: str, port: Optional[int], is_wan: bool) -> Remediation:
    iid = (issue_id or "").lower()
    if "tls" in iid or "cert" in iid:
        return Remediation(kind=RemediationKind.config, summary="Fix TLS configuration",
                           details="Disable TLS 1.0/1.1, use certificates from a trusted CA (e.g. Let's Encrypt) and "
                                   "renew automatically.")
    if "spf" in iid or "dmarc" in iid or "dkim" in iid:
        return Remediation(kind=RemediationKind.config, summary="Fix email authentication DNS records",
                           details="Publish SPF ending in -all (or ~all while testing) and a DMARC policy "
                                   "(p=quarantine or p=reject) with rua reporting.",
                           commands=['_dmarc  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@<your-domain>"'])
    if "axfr" in iid:
        return Remediation(kind=RemediationKind.config, summary="Disable zone transfers to arbitrary hosts",
                           details="Restrict AXFR to your secondary name servers (allow-transfer / TSIG).")
    if "header" in iid or "hsts" in iid:
        return Remediation(kind=RemediationKind.config, summary="Add HTTP security headers",
                           commands=['add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                                     'add_header X-Content-Type-Options nosniff always;',
                                     'add_header X-Frame-Options DENY always;'])
    if "admin" in iid or "panel" in iid or "login" in iid:
        return Remediation(kind=RemediationKind.firewall, summary="Remove the admin interface from the internet",
                           details="Firewall/router/NAS management must only be reachable from a management VLAN or "
                                   "over a VPN (WireGuard / Tailscale / OpenVPN).")
    if "resolver" in iid or "snmp" in iid or "upnp" in iid or "ntp" in iid:
        return Remediation(kind=RemediationKind.firewall, summary="Block this UDP service on the WAN interface",
                           details="Open resolvers / SNMP / SSDP are abused for amplification attacks and leak device details.")
    return Remediation(kind=RemediationKind.firewall,
                       summary=f"Restrict port {port} to trusted source IPs or a VPN" if port else "Review exposure",
                       details="If the service must be public, keep it patched and enforce strong authentication / MFA."
                       if is_wan else "")


def ingest_result(ctx: Any, result: ExternalScanResult) -> dict:
    grouped = analyze_result(ctx, result)
    stats = {"targets": len(result.targets), "findings": 0}
    for aid, fs in grouped.items():
        if aid == "ext:_probe":
            ctx.store.replace_findings("external.meta", None, fs)
        else:
            target = aid.split(":", 1)[1]
            ctx.store.upsert_asset(aid, "external", target, {"kind": "external"})
            ctx.store.replace_findings("external", aid, fs)
        stats["findings"] += len(fs)
    ctx.invalidate()
    return stats
