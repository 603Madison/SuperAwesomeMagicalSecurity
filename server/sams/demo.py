"""Demo / test environment: a small but realistic network.

    internet ──443──► web (10.0.2.10, nginx as www-data, KEV vuln, SUID find)
                        └─ root holds deploy's unencrypted SSH key FP_DEPLOY
    web ──22──► db (10.0.2.20, deploy has the key authorized + sudo NOPASSWD; postgres = crown jewel)
    laptop (10.0.1.50, alice in docker group, AWS keys on disk)
"""
from __future__ import annotations

from sams.config import Settings
from sams.context import AppContext
from sams.crypto import Signer
from sams.db import Store
from sams.firewall.model import FirewallConfig, Network, PortForward, PortRange, Rule
from sams.hardening.checks import check_inventory
from sams.models import (AuthorizedKey, Credential, Datastore, Finding, FindingCategory, Group, Hardening, HostInfo,
                         Interface, Inventory, Listener, OSInfo, Package, Remediation, RemediationKind, Severity,
                         SSHDConfig, SudoRule, User)

FP_DEPLOY = "SHA256:deployKEYfingerprintAAAAAAAAAAAAAAAAAAAAAAAAA"


def _host(name: str, ip: str, **kw) -> Inventory:
    return Inventory(host=HostInfo(hostname=name, os=OSInfo(family="linux", id="ubuntu", version_id="22.04")),
                     interfaces=[Interface(name="eth0", addresses=[f"{ip}/24"])], **kw)


def web() -> Inventory:
    return _host(
        "web", "10.0.2.10",
        listeners=[Listener(port=443, process="nginx", user="www-data", package="nginx"),
                   Listener(port=22, process="sshd", user="root", package="openssh-server")],
        packages=[Package(name="nginx", version="1.18.0-6ubuntu14", manager="dpkg")],
        users=[User(name="root", uid=0, login_enabled=True), User(name="www-data", uid=33, login_enabled=False)],
        credentials=[Credential(kind="ssh_private_key", owner="root", path="/root/.ssh/id_ed25519",
                                fingerprint=FP_DEPLOY, encrypted=False)],
        hardening=Hardening(sshd=SSHDConfig(present=True, password_authentication="no"),
                            suid_binaries=["/usr/bin/find", "/usr/bin/passwd"]),
    )


def db() -> Inventory:
    return _host(
        "db", "10.0.2.20",
        listeners=[Listener(port=5432, process="postgres", user="postgres"),
                   Listener(port=22, process="sshd", user="root")],
        users=[User(name="root", uid=0), User(name="deploy", uid=1001, groups=["sudo"]),
               User(name="postgres", uid=110, login_enabled=False)],
        authorized_keys=[AuthorizedKey(user="deploy", fingerprint=FP_DEPLOY, key_type="ssh-ed25519")],
        sudo_rules=[SudoRule(principal="deploy", nopasswd=True, commands=["ALL"])],
        datastores=[Datastore(kind="postgresql", name="customers", port=5432, owner="postgres",
                              sensitivity="restricted")],
        hardening=Hardening(sshd=SSHDConfig(present=True, password_authentication="no")),
    )


def laptop() -> Inventory:
    return _host(
        "laptop", "10.0.1.50",
        users=[User(name="alice", uid=1000, groups=["docker"])],
        groups=[Group(name="docker", members=["alice"])],
        credentials=[Credential(kind="aws", owner="alice", path="/home/alice/.aws/credentials",
                                identifier="AKIA****WXYZ", fingerprint="awsfp1")],
    )


def firewall() -> FirewallConfig:
    return FirewallConfig(
        device_id="fw1", vendor="pfsense", hostname="gw",
        networks=[Network(name="WAN", is_wan=True, cidrs=[]),
                  Network(name="LAN", cidrs=["10.0.1.0/24"], gateway_ip="10.0.1.1"),
                  Network(name="SERVERS", cidrs=["10.0.2.0/24"], gateway_ip="10.0.2.1")],
        rules=[Rule(id="lan-any", order=1, interface="LAN", action="allow"),
               Rule(id="srv-to-lan", order=1, interface="SERVERS", action="block", destination="LAN"),
               Rule(id="srv-any", order=2, interface="SERVERS", action="allow")],
        port_forwards=[PortForward(id="pf-web", internal_ip="10.0.2.10", internal_port=443,
                                   external_ports=[PortRange(start=443, end=443)], description="web")],
        wan_addresses=["203.0.113.5"],
    )


def nginx_vuln(asset_id: str) -> Finding:
    return Finding(key=f"vuln:{asset_id}:dpkg:nginx", asset_id=asset_id, category=FindingCategory.vulnerability,
                   severity=Severity.critical, title="nginx 1.18.0: 1 vulnerability", source="vuln.osv",
                   evidence={"package": "nginx", "remote_exploitable": True, "kev": True, "privesc": False,
                             "vulns": [{"id": "CVE-2099-0001", "attack_vector": "network", "kev": True}]},
                   remediation=Remediation(kind=RemediationKind.patch, summary="Upgrade nginx", automatable=True,
                                           task={"action": "patch", "manager": "dpkg", "packages": ["nginx"]}))


def populate(ctx: AppContext) -> None:
    crit = {"web": 3, "db": 5, "laptop": 2}
    for name, inv in (("web", web()), ("db", db()), ("laptop", laptop())):
        ctx.store.upsert_asset(name, "host", name, criticality=crit[name])
        ctx.store.save_inventory(name, inv)
        ctx.store.replace_findings("hardening", name, check_inventory(inv, name))
    ctx.store.replace_findings("vuln.osv", "web", [nginx_vuln("web")])
    ctx.store.upsert_firewall("fw1", "pfsense", "gw", {}, firewall().model_dump_json())
    ctx.invalidate()


def build_lab(tmp_path=None) -> AppContext:
    settings = Settings(data_dir=tmp_path or "/tmp/sams-test")
    ctx = AppContext(settings=settings, store=Store(":memory:"), signer=Signer.ephemeral())
    populate(ctx)
    return ctx


DEMO_AUTH_LOG = [
    *[f"Nov 24 03:1{i // 10}:{i % 10 * 5:02d} web sshd[{900 + i}]: Failed password for invalid user admin from 198.51.100.23 port {40000 + i} ssh2"
      for i in range(14)],
    "Nov 24 03:15:02 web sshd[1001]: Accepted password for deploy from 198.51.100.23 port 41022 ssh2",
    "Nov 24 03:16:40 web sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
    "Nov 24 03:18:11 web useradd[1201]: new user: name=backup2, UID=0, GID=0, home=/root, shell=/bin/bash",
]


def load_demo(ctx: AppContext) -> dict:
    """Populate a context with the demo network, firewall, external scan and some SIEM activity."""
    from .analysis import refresh_graph_findings
    from .external import ingest_result
    from .models import ExternalScanResult, ExternalService, ExternalTargetResult
    populate(ctx)
    ctx.store.add_external_target("203.0.113.5", "ip", "demo WAN address")
    ext = ExternalScanResult(probe_id="demo", probe_public_ip="192.0.2.77", targets=[ExternalTargetResult(
        target="203.0.113.5", resolved=["203.0.113.5"],
        services=[ExternalService(port=443, service="https", product="nginx", version="1.18.0",
                                  http={"status": 200, "server": "nginx/1.18.0",
                                        "missing_security_headers": ["strict-transport-security"]}),
                  ExternalService(port=8443, service="https", http={"login_page": "pfSense"})],
        issues=[{"id": "admin_panel_exposed", "severity": "high", "title": "pfSense login page exposed",
                 "detail": "The firewall's web GUI answers on 8443 from the internet.", "port": 8443},
                {"id": "missing_hsts", "severity": "low", "title": "HSTS header missing", "detail": "", "port": 443}])])
    ingest_result(ctx, ext)
    siem = ctx.extras.get("siem")
    alerts = 0
    if siem is not None:
        _, al = siem.ingest_lines([{"source": "auth.log", "line": l} for l in DEMO_AUTH_LOG], host="web", asset_id="web")
        alerts = len(al)
    refresh_graph_findings(ctx)
    return {"assets": len(ctx.store.list_assets()), "findings": len(ctx.store.list_findings()), "alerts": alerts}
