"""Shared data contracts for SuperAwesomeMagicalSecurity (SAMS).

Everything that crosses a module boundary is defined here:

* ``Inventory`` -- what an internal host agent reports (JSON produced by the Go
  agent in ``agent/``; field names are the wire format, keep them stable).
* ``ExternalScanResult`` -- what an off-network external probe reports.
* ``Finding`` / ``Remediation`` -- the unit of "something is wrong + how to fix it",
  produced by every analyzer (vulns, hardening, firewall, external, graph).
* ``Event`` / ``Alert`` -- SIEM records.
* ``FirewallConfig`` lives in ``sams.firewall.model`` (it is large) but findings
  from it use the same ``Finding`` type.

Rules: models are plain pydantic, no I/O. Unknown fields from agents are
ignored (forward compatible); missing fields get safe defaults.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


# --------------------------------------------------------------------------- #
# Severity / categories
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 4, "high": 10, "critical": 25}[self.value]

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        if score is None:
            return cls.medium
        if score >= 9.0:
            return cls.critical
        if score >= 7.0:
            return cls.high
        if score >= 4.0:
            return cls.medium
        if score > 0:
            return cls.low
        return cls.info


class FindingCategory(str, Enum):
    vulnerability = "vulnerability"      # vulnerable package / software
    hardening = "hardening"              # host misconfiguration
    credential = "credential"            # exposed / reusable secrets
    exposure = "exposure"                # service reachable from somewhere it shouldn't be
    firewall = "firewall"                # firewall policy weakness
    external = "external"                # seen from the internet by an external probe
    attack_path = "attack_path"          # derived from the attack graph
    detection = "detection"              # SIEM alert promoted to a finding


class FindingStatus(str, Enum):
    open = "open"
    accepted = "accepted"        # risk accepted
    fixed = "fixed"
    false_positive = "false_positive"


# --------------------------------------------------------------------------- #
# Remediation
# --------------------------------------------------------------------------- #
class RemediationKind(str, Enum):
    patch = "patch"                  # upgrade packages (agent can automate)
    config = "config"                # change a config file / setting
    firewall = "firewall"            # change firewall policy
    credential = "credential"        # rotate / remove / protect a credential
    access = "access"                # change group membership / sudo / authorized_keys
    manual = "manual"                # needs a human


class Remediation(_Model):
    kind: RemediationKind = RemediationKind.manual
    summary: str
    details: str = ""
    # Shell commands / config snippets a human can apply. Never auto-executed.
    commands: list[str] = Field(default_factory=list)
    # If the agent can apply this automatically, the task it should run.
    automatable: bool = False
    task: Optional[dict[str, Any]] = None   # e.g. {"action": "patch", "manager": "apt", "packages": [...]}
    effort: str = "low"                     # low | medium | high
    references: list[str] = Field(default_factory=list)


class Finding(_Model):
    """A single problem. ``key`` is a stable de-duplication key: the same issue
    found on the next scan must produce the same key so status (accepted /
    fixed) survives re-scans."""

    key: str = ""
    asset_id: Optional[str] = None          # host asset, firewall device, or external target
    category: FindingCategory
    severity: Severity
    title: str
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[Remediation] = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.open
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    source: str = ""                        # analyzer that produced it, e.g. "vuln.osv"

    def ensure_key(self) -> "Finding":
        if not self.key:
            raw = f"{self.asset_id}|{self.category.value}|{self.title}"
            self.key = hashlib.sha256(raw.encode()).hexdigest()[:24]
        return self


# --------------------------------------------------------------------------- #
# Inventory (agent wire format)
# --------------------------------------------------------------------------- #
class OSInfo(_Model):
    family: str = "linux"          # linux | darwin | windows | freebsd
    id: str = ""                   # os-release ID: ubuntu, debian, rhel, alpine, macos, windows
    id_like: list[str] = Field(default_factory=list)
    name: str = ""
    version: str = ""
    version_id: str = ""           # 22.04, 12, 9.3, 3.19
    codename: str = ""
    pretty: str = ""


class HostInfo(_Model):
    hostname: str
    fqdn: str = ""
    machine_id: str = ""
    os: OSInfo = Field(default_factory=OSInfo)
    kernel: str = ""
    arch: str = ""
    uptime_seconds: int = 0
    virtualization: str = ""       # kvm, docker, wsl, none...
    is_container: bool = False
    domain: str = ""               # AD domain if joined


class Interface(_Model):
    name: str
    mac: str = ""
    addresses: list[str] = Field(default_factory=list)   # CIDR notation, e.g. 10.0.0.5/24
    up: bool = True


class Listener(_Model):
    proto: str = "tcp"             # tcp | udp
    address: str = "0.0.0.0"       # bind address; 0.0.0.0 / :: = all interfaces
    port: int
    pid: int = 0
    process: str = ""
    user: str = ""                 # account the process runs as
    exe: str = ""
    package: str = ""              # package owning exe, if resolvable

    @property
    def is_loopback_only(self) -> bool:
        return self.address.startswith("127.") or self.address in ("::1", "localhost")


class Connection(_Model):
    """Established connection observed on the host -- evidence of a trust relationship."""
    proto: str = "tcp"
    local_address: str = ""
    local_port: int = 0
    remote_address: str
    remote_port: int
    state: str = "ESTABLISHED"
    process: str = ""
    user: str = ""


class Package(_Model):
    name: str
    version: str
    manager: str                   # dpkg | rpm | apk | brew | windows | pypi | npm | gem | go | cargo
    arch: str = ""
    source_name: str = ""          # Debian/Ubuntu source package (OSV matches on this)
    source_version: str = ""
    location: str = ""             # for language packages: site-packages / node_modules path


class User(_Model):
    name: str
    uid: int = -1
    gid: int = -1
    home: str = ""
    shell: str = ""
    groups: list[str] = Field(default_factory=list)
    login_enabled: bool = True     # has a real shell / not disabled
    password_state: str = "unknown"   # set | empty | locked | unknown
    is_admin: bool = False         # uid 0, member of sudo/wheel/admin/Administrators


class Group(_Model):
    name: str
    gid: int = -1
    members: list[str] = Field(default_factory=list)


class SudoRule(_Model):
    principal: str                 # "alice" or "%admin"
    runas: str = "ALL"
    commands: list[str] = Field(default_factory=lambda: ["ALL"])
    nopasswd: bool = False
    source: str = ""


class AuthorizedKey(_Model):
    user: str
    fingerprint: str               # SHA256:base64 (OpenSSH style)
    key_type: str = ""
    comment: str = ""
    options: str = ""              # from="...", command="..." restrictions
    file: str = ""


class Credential(_Model):
    """A credential *found* on the host. Agents never send secret material,
    only metadata and fingerprints."""
    kind: str                      # ssh_private_key | aws | gcp | azure | kube | docker | git | netrc
                                   # | pgpass | mysql | env_secret | history_secret | browser
    owner: str = ""                # local account that can read it
    path: str = ""
    fingerprint: str = ""          # ssh: SHA256 of public key; others: hash of identifier
    encrypted: Optional[bool] = None
    identifier: str = ""           # masked identifier (AKIA****WXYZ, user@host)
    targets: list[str] = Field(default_factory=list)   # hosts/IPs/URLs it is used against
    details: dict[str, Any] = Field(default_factory=dict)


class KnownHost(_Model):
    user: str
    host: str                      # hostname/IP, or "" if hashed
    hashed: bool = False
    key_type: str = ""


class Datastore(_Model):
    kind: str                      # postgresql | mysql | mongodb | redis | elasticsearch | mssql
                                   # | smb_share | nfs_export | sqlite | files | secrets_vault
    name: str = ""
    path: str = ""
    port: int = 0
    owner: str = ""                # account owning the data files/process
    sensitivity: str = "unknown"   # unknown | internal | confidential | restricted
    details: dict[str, Any] = Field(default_factory=dict)


class SSHDConfig(_Model):
    present: bool = False
    port: int = 22
    permit_root_login: str = ""          # yes | no | prohibit-password | forced-commands-only
    password_authentication: str = ""    # yes | no
    pubkey_authentication: str = ""
    permit_empty_passwords: str = ""
    x11_forwarding: str = ""
    max_auth_tries: int = 0
    allow_users: list[str] = Field(default_factory=list)


class HostFirewall(_Model):
    enabled: Optional[bool] = None
    backend: str = ""              # ufw | nftables | iptables | firewalld | windows | pf | alf
    default_inbound: str = ""      # accept | drop | reject
    rule_count: int = 0


class Hardening(_Model):
    sshd: SSHDConfig = Field(default_factory=SSHDConfig)
    firewall: HostFirewall = Field(default_factory=HostFirewall)
    suid_binaries: list[str] = Field(default_factory=list)
    world_writable: list[str] = Field(default_factory=list)       # sensitive world-writable paths
    writable_path_dirs: list[str] = Field(default_factory=list)   # dirs in root's PATH writable by non-root
    writable_root_cron: list[str] = Field(default_factory=list)   # scripts run by root writable by others
    auto_updates: Optional[bool] = None
    auto_updates_mechanism: str = ""
    sysctl: dict[str, str] = Field(default_factory=dict)
    mac_framework: str = ""          # selinux:enforcing | apparmor | none
    disk_encryption: Optional[bool] = None
    secure_boot: Optional[bool] = None
    docker_socket: dict[str, Any] = Field(default_factory=dict)   # {"exists": bool, "mode": "0660", "group": "docker"}
    pending_reboot: Optional[bool] = None
    av_enabled: Optional[bool] = None                             # Windows Defender etc.
    extra: dict[str, Any] = Field(default_factory=dict)


class Container(_Model):
    id: str
    name: str = ""
    image: str = ""
    privileged: bool = False
    mounts: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)


class Inventory(_Model):
    schema_version: int = 1
    agent_version: str = ""
    collected_at: datetime = Field(default_factory=utcnow)
    host: HostInfo
    interfaces: list[Interface] = Field(default_factory=list)
    listeners: list[Listener] = Field(default_factory=list)
    connections: list[Connection] = Field(default_factory=list)
    packages: list[Package] = Field(default_factory=list)
    users: list[User] = Field(default_factory=list)
    groups: list[Group] = Field(default_factory=list)
    sudo_rules: list[SudoRule] = Field(default_factory=list)
    authorized_keys: list[AuthorizedKey] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    known_hosts: list[KnownHost] = Field(default_factory=list)
    datastores: list[Datastore] = Field(default_factory=list)
    hardening: Hardening = Field(default_factory=Hardening)
    containers: list[Container] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def ip_addresses(self) -> list[str]:
        out = []
        for iface in self.interfaces:
            for cidr in iface.addresses:
                ip = cidr.split("/")[0]
                if ip.startswith("127.") or ip == "::1" or ip.startswith("fe80"):
                    continue
                out.append(ip)
        return out


# --------------------------------------------------------------------------- #
# External probe (off-network scanner) wire format
# --------------------------------------------------------------------------- #
class ExternalService(_Model):
    port: int
    proto: str = "tcp"
    state: str = "open"            # open | filtered | closed
    service: str = ""              # ssh | http | https | rdp | smb | ...
    banner: str = ""
    product: str = ""              # OpenSSH, nginx...
    version: str = ""
    tls: Optional[dict[str, Any]] = None    # {"versions": [...], "cert_subject", "cert_issuer", "not_after", "self_signed", "weak_ciphers": [...]}
    http: Optional[dict[str, Any]] = None   # {"status", "title", "server", "headers": {...}, "missing_security_headers": [...], "login_page": "pfsense"}


class ExternalTargetResult(_Model):
    target: str                    # IP or hostname as scoped
    resolved: list[str] = Field(default_factory=list)
    reachable: bool = True
    services: list[ExternalService] = Field(default_factory=list)
    dns: dict[str, Any] = Field(default_factory=dict)       # {"spf": "...", "dmarc": "...", "axfr_open": bool, "mx": [...]}
    issues: list[dict[str, Any]] = Field(default_factory=list)  # probe-side findings: {"id","severity","title","detail","port"}

    @field_validator("resolved", "services", "issues", mode="before")
    @classmethod
    def _none_list(cls, v: Any) -> Any:
        return [] if v is None else v

    @field_validator("dns", mode="before")
    @classmethod
    def _none_dict(cls, v: Any) -> Any:
        return {} if v is None else v


class ExternalScanResult(_Model):
    probe_id: str = ""
    job_id: str = ""
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime = Field(default_factory=utcnow)
    probe_public_ip: str = ""      # egress IP of the probe -- proves it is off-network
    targets: list[ExternalTargetResult] = Field(default_factory=list)

    @field_validator("targets", mode="before")
    @classmethod
    def _none_targets(cls, v: Any) -> Any:
        return [] if v is None else v


# --------------------------------------------------------------------------- #
# SIEM
# --------------------------------------------------------------------------- #
class Event(_Model):
    """Normalized security event. Field names loosely follow ECS."""
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=utcnow)
    received_at: datetime = Field(default_factory=utcnow)
    asset_id: Optional[str] = None
    host: str = ""
    source: str = ""               # auth.log | syslog | pfsense.filterlog | unifi | windows | agent | probe
    category: str = ""             # authentication | process | network | firewall | package | iam | file
    action: str = ""               # ssh_login | ssh_failed | sudo | user_created | blocked | allowed ...
    outcome: str = ""              # success | failure | unknown
    severity: Severity = Severity.info
    user: str = ""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    process: str = ""
    message: str = ""
    raw: str = ""
    fields: dict[str, Any] = Field(default_factory=dict)


class Alert(_Model):
    id: Optional[int] = None
    rule_id: str
    title: str
    severity: Severity
    created_at: datetime = Field(default_factory=utcnow)
    asset_id: Optional[str] = None
    host: str = ""
    description: str = ""
    event_ids: list[int] = Field(default_factory=list)
    group_key: str = ""            # what was aggregated (e.g. src_ip) for threshold rules
    mitre: list[str] = Field(default_factory=list)  # ATT&CK technique IDs
    status: str = "open"           # open | acknowledged | closed
    context: dict[str, Any] = Field(default_factory=dict)  # enrichment, e.g. blast radius summary


# --------------------------------------------------------------------------- #
# Agent tasks (server -> agent). Strict allowlist of actions, signed by server.
# --------------------------------------------------------------------------- #
class TaskAction(str, Enum):
    collect = "collect"            # re-run inventory now
    patch = "patch"                # upgrade specific packages
    patch_all = "patch_all"        # apply all security updates
    reboot_required_check = "reboot_required_check"


class Task(_Model):
    id: str
    agent_id: str
    action: TaskAction
    params: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = None
    status: str = "pending"        # pending | approved | sent | succeeded | failed | rejected | expired
    signature: str = ""            # base64 ed25519 over canonical JSON (see sams.crypto)
    result: Optional[dict[str, Any]] = None
