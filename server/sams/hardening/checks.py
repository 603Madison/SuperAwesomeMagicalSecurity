"""Host configuration checks over an agent ``Inventory``.

Each check is a small function returning findings. Checks only look at facts
the agent reported; they never guess. When a fact is unknown (``None``) the
check stays silent rather than raising a false positive.
"""
from __future__ import annotations

from typing import Callable, Iterable

from ..models import Finding, FindingCategory, Inventory, Remediation, RemediationKind, Severity

Check = Callable[[Inventory, str], Iterable[Finding]]
CHECKS: list[Check] = []

# SUID binaries that give a root shell / file write when SUID (GTFOBins subset)
GTFO_SUID = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "find", "vim", "vim.basic", "vi", "nano", "less", "more",
    "awk", "gawk", "mawk", "nmap", "python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "env",
    "cp", "mv", "tee", "dd", "tar", "zip", "rsync", "git", "docker", "busybox", "socat", "nc", "ncat", "openssl",
    "strace", "gdb", "taskset", "nice", "ionice", "stdbuf", "xargs", "time", "timeout", "flock", "install",
    "chmod", "chown", "ed", "sed", "systemctl", "journalctl", "make", "expect", "screen", "tmux", "rlwrap",
}
# Normal SUID binaries; anything else in system dirs is worth a look.
EXPECTED_SUID = {
    "sudo", "su", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "mount", "umount", "ping", "ping6",
    "pkexec", "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "chage", "expiry", "unix_chkpwd", "pam_timestamp_check", "newuidmap", "newgidmap", "at", "crontab",
    "Xorg.wrap", "snap-confine", "staprun", "mount.nfs", "mount.cifs", "traceroute6.iputils", "userhelper",
    "vmware-user-suid-wrapper", "sg", "doas",
}

SENSITIVE_DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
                      9200: "Elasticsearch", 11211: "Memcached", 1433: "MS SQL", 5984: "CouchDB",
                      2375: "Docker API (unauthenticated)", 2379: "etcd", 10250: "Kubelet", 8086: "InfluxDB"}


def check(fn: Check) -> Check:
    CHECKS.append(fn)
    return fn


def _f(asset_id: str, check_id: str, sev: Severity, title: str, desc: str, rem: Remediation | None = None,
       evidence: dict | None = None, category: FindingCategory = FindingCategory.hardening, suffix: str = "",
       refs: list[str] | None = None) -> Finding:
    return Finding(key=f"hard:{asset_id}:{check_id}{(':' + suffix) if suffix else ''}", asset_id=asset_id,
                   category=category, severity=sev, title=title, description=desc, remediation=rem,
                   evidence=evidence or {}, source="hardening", tags=[check_id], references=refs or [])


def _yes(v: str) -> bool:
    return (v or "").strip().lower() in ("yes", "true", "1", "on")


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
@check
def ssh_config(inv: Inventory, a: str):
    s = inv.hardening.sshd
    if not s.present:
        return
    listening = any(l.port == s.port and not l.is_loopback_only for l in inv.listeners)
    exposure = "and listening on the network" if listening else ""
    if s.permit_root_login.lower() == "yes":
        yield _f(a, "ssh_root_login", Severity.high, "SSH allows direct root login with a password",
                 f"sshd PermitRootLogin is 'yes' {exposure}. An attacker who guesses or reuses the root "
                 "password gets full control with no audit trail of which person logged in.",
                 Remediation(kind=RemediationKind.config, summary="Set PermitRootLogin to no (or prohibit-password)",
                             commands=["sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                                       "sshd -t && systemctl reload ssh || systemctl reload sshd"]),
                 {"permit_root_login": s.permit_root_login, "listening": listening})
    if _yes(s.password_authentication):
        yield _f(a, "ssh_password_auth", Severity.medium if listening else Severity.low,
                 "SSH password authentication is enabled",
                 "Passwords can be brute-forced or reused from breaches. Key-based authentication "
                 "(ideally with hardware-backed keys) removes this whole attack class.",
                 Remediation(kind=RemediationKind.config, summary="Disable PasswordAuthentication after deploying keys",
                             commands=["sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
                                       "sshd -t && systemctl reload ssh || systemctl reload sshd"],
                             details="Make sure every admin has a working key first, or you will lock yourself out."),
                 {"password_authentication": s.password_authentication, "listening": listening})
    if _yes(s.permit_empty_passwords):
        yield _f(a, "ssh_empty_passwords", Severity.critical, "SSH permits empty passwords",
                 "Accounts without a password can log in over SSH.",
                 Remediation(kind=RemediationKind.config, summary="Set PermitEmptyPasswords no",
                             commands=["sed -i 's/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config"]))
    if s.max_auth_tries and s.max_auth_tries > 6:
        yield _f(a, "ssh_max_auth_tries", Severity.low, f"SSH MaxAuthTries is high ({s.max_auth_tries})",
                 "A high MaxAuthTries lets attackers make more guesses per connection.",
                 Remediation(kind=RemediationKind.config, summary="Set MaxAuthTries 3-4"))


# --------------------------------------------------------------------------- #
# Accounts & privileges
# --------------------------------------------------------------------------- #
@check
def accounts(inv: Inventory, a: str):
    for u in inv.users:
        if u.password_state == "empty" and u.login_enabled:
            yield _f(a, "empty_password", Severity.critical, f"Account '{u.name}' has an empty password",
                     "Anyone with console or su access can become this user without a password.",
                     Remediation(kind=RemediationKind.access, summary=f"Lock or set a password for {u.name}",
                                 commands=[f"passwd -l {u.name}"]), {"user": u.name}, suffix=u.name)
        if u.uid == 0 and u.name != "root":
            yield _f(a, "uid0_alias", Severity.high, f"Non-root account '{u.name}' has UID 0",
                     "A second UID-0 account is a classic persistence technique and bypasses most audit tooling.",
                     Remediation(kind=RemediationKind.access, summary=f"Investigate and remove UID 0 from {u.name}"),
                     {"user": u.name}, suffix=u.name)


@check
def sudo_rules(inv: Inventory, a: str):
    for r in inv.sudo_rules:
        if r.nopasswd and any(c.strip().upper() == "ALL" for c in r.commands):
            yield _f(a, "sudo_nopasswd_all", Severity.medium,
                     f"'{r.principal}' can run any command as root without a password",
                     "If this account (or any process running as it) is compromised, the attacker is root "
                     "immediately. This is one of the most common privilege-escalation steps in real attack paths.",
                     Remediation(kind=RemediationKind.access, summary="Require a password for sudo, or scope NOPASSWD to specific commands",
                                 details=f"Edit {r.source or '/etc/sudoers'} with `visudo` and remove NOPASSWD, or "
                                         "restrict it to the exact commands automation needs."),
                     {"principal": r.principal, "source": r.source, "commands": r.commands}, suffix=r.principal)


@check
def docker_group(inv: Inventory, a: str):
    members = set()
    for g in inv.groups:
        if g.name == "docker":
            members.update(g.members)
    for u in inv.users:
        if "docker" in u.groups:
            members.add(u.name)
    members.discard("root")
    if members:
        yield _f(a, "docker_group", Severity.medium, f"{len(members)} user(s) in the docker group (root-equivalent)",
                 "Membership in the docker group allows mounting the host filesystem in a container: "
                 "it is equivalent to passwordless root.",
                 Remediation(kind=RemediationKind.access, summary="Remove users from the docker group; use rootless Docker or sudo",
                             commands=[f"gpasswd -d {m} docker" for m in sorted(members)]),
                 {"members": sorted(members)})
    sock = inv.hardening.docker_socket or {}
    mode = str(sock.get("mode", ""))
    if sock.get("exists") and mode and mode[-1] in "2367":
        yield _f(a, "docker_socket_world", Severity.critical, "Docker socket is world-writable",
                 "Any local user can control Docker and therefore become root.",
                 Remediation(kind=RemediationKind.config, summary="chmod 660 /var/run/docker.sock",
                             commands=["chmod 660 /var/run/docker.sock"]), {"socket": sock})


@check
def suid(inv: Inventory, a: str):
    dangerous, unusual = [], []
    for p in inv.hardening.suid_binaries:
        base = p.rsplit("/", 1)[-1]
        if base in GTFO_SUID:
            dangerous.append(p)
        elif base not in EXPECTED_SUID:
            unusual.append(p)
    if dangerous:
        yield _f(a, "suid_gtfobins", Severity.high, f"{len(dangerous)} SUID binaries allow trivial root escalation",
                 "These binaries are SUID root and can spawn shells or write files as root "
                 "(see GTFOBins). Any local user can become root.",
                 Remediation(kind=RemediationKind.config, summary="Remove the SUID bit",
                             commands=[f"chmod u-s {p}" for p in dangerous]),
                 {"binaries": dangerous}, refs=["https://gtfobins.github.io/"])
    if unusual:
        yield _f(a, "suid_unusual", Severity.low, f"{len(unusual)} unusual SUID binaries",
                 "SUID binaries outside the usual set expand the local attack surface; review whether each is needed.",
                 Remediation(kind=RemediationKind.manual, summary="Review and remove unneeded SUID bits"),
                 {"binaries": unusual[:50]})


@check
def writable_privileged_paths(inv: Inventory, a: str):
    h = inv.hardening
    if h.writable_root_cron:
        yield _f(a, "writable_root_cron", Severity.high, "Scripts executed by root are writable by other users",
                 "A non-root user can modify a script that root runs on a schedule. That is a reliable "
                 "privilege escalation.",
                 Remediation(kind=RemediationKind.config, summary="Make cron scripts owned by root and not group/world writable",
                             commands=[f"chown root:root {p} && chmod go-w {p}" for p in h.writable_root_cron]),
                 {"paths": h.writable_root_cron})
    if h.writable_path_dirs:
        yield _f(a, "writable_path", Severity.high, "Directories in root's PATH are writable by non-root users",
                 "Planting a binary with a common name in these directories hijacks commands run by root.",
                 Remediation(kind=RemediationKind.config, summary="Remove write permission for non-root users",
                             commands=[f"chmod go-w {p}" for p in h.writable_path_dirs]),
                 {"paths": h.writable_path_dirs})
    if h.world_writable:
        yield _f(a, "world_writable_sensitive", Severity.medium, "Sensitive files are world-writable",
                 "World-writable files under /etc and similar locations allow tampering with system configuration.",
                 Remediation(kind=RemediationKind.config, summary="Remove world write permission",
                             commands=[f"chmod o-w {p}" for p in h.world_writable[:50]]),
                 {"paths": h.world_writable[:100]})


# --------------------------------------------------------------------------- #
# System protections
# --------------------------------------------------------------------------- #
SYSCTL_EXPECT = {
    "kernel.randomize_va_space": ("2", Severity.medium, "ASLR is not fully enabled"),
    "kernel.kptr_restrict": ("1", Severity.low, "Kernel pointers are exposed to unprivileged users"),
    "kernel.dmesg_restrict": ("1", Severity.low, "Unprivileged users can read the kernel log"),
    "fs.protected_symlinks": ("1", Severity.low, "Symlink protections are disabled"),
    "fs.protected_hardlinks": ("1", Severity.low, "Hardlink protections are disabled"),
    "kernel.unprivileged_bpf_disabled": ("1", Severity.low, "Unprivileged eBPF is allowed"),
    "kernel.yama.ptrace_scope": ("1", Severity.low, "Any process can ptrace other processes of the same user"),
}


@check
def sysctls(inv: Inventory, a: str):
    bad = []
    for k, (want, sev, title) in SYSCTL_EXPECT.items():
        v = inv.hardening.sysctl.get(k)
        if v is None:
            continue
        try:
            ok = int(v) >= int(want)
        except ValueError:
            ok = v == want
        if not ok:
            bad.append((k, v, want, sev, title))
    if bad:
        sev = max((b[3] for b in bad), key=lambda s: s.weight)
        yield _f(a, "sysctl", sev, f"{len(bad)} kernel hardening settings are weak",
                 "; ".join(b[4] for b in bad) + ".",
                 Remediation(kind=RemediationKind.config, summary="Apply hardened sysctl values",
                             commands=[f"echo '{k} = {want}' >> /etc/sysctl.d/90-sams-hardening.conf" for k, _, want, _, _ in bad]
                             + ["sysctl --system"]),
                 {"settings": {k: {"current": v, "recommended": w} for k, v, w, _, _ in bad}})


@check
def host_firewall(inv: Inventory, a: str):
    fw = inv.hardening.firewall
    exposed = [l for l in inv.listeners if not l.is_loopback_only]
    if fw.enabled is False and exposed:
        yield _f(a, "host_firewall_off", Severity.medium,
                 f"No host firewall, with {len(exposed)} network-facing listeners",
                 "Without a host firewall every listening service is reachable by anything that can route to "
                 "this host, including a compromised neighbour. Host firewalls are the cheapest lateral-movement control.",
                 Remediation(kind=RemediationKind.config, summary="Enable a default-deny host firewall",
                             commands=["ufw default deny incoming", "ufw allow from <admin-subnet> to any port 22 proto tcp",
                                       "ufw enable"]),
                 {"listeners": [f"{l.process or '?'}:{l.port}/{l.proto}" for l in exposed[:30]]})


@check
def updates(inv: Inventory, a: str):
    h = inv.hardening
    if h.auto_updates is False:
        yield _f(a, "no_auto_updates", Severity.medium, "Automatic security updates are disabled",
                 "Most breaches exploit vulnerabilities with patches available for weeks or months.",
                 Remediation(kind=RemediationKind.config, summary="Enable unattended security upgrades",
                             commands=["apt-get install -y unattended-upgrades",
                                       "dpkg-reconfigure -f noninteractive unattended-upgrades"]
                             if inv.host.os.id in ("ubuntu", "debian") else
                             ["dnf install -y dnf-automatic", "systemctl enable --now dnf-automatic-install.timer"]))
    if h.pending_reboot:
        yield _f(a, "pending_reboot", Severity.low, "A reboot is pending to activate updates",
                 "Kernel or library updates are installed but not active until reboot.",
                 Remediation(kind=RemediationKind.manual, summary="Schedule a reboot"))


@check
def mac_framework(inv: Inventory, a: str):
    m = (inv.hardening.mac_framework or "").lower()
    if inv.host.os.family == "linux" and m in ("none", "selinux:disabled", "selinux:permissive", "apparmor:disabled"):
        yield _f(a, "mac_disabled", Severity.low, f"Mandatory access control is not enforcing ({m})",
                 "SELinux/AppArmor confine compromised services and limit what an exploited daemon can reach.",
                 Remediation(kind=RemediationKind.config, summary="Enable SELinux enforcing or AppArmor profiles"))


@check
def exposed_datastores(inv: Inventory, a: str):
    for l in inv.listeners:
        name = SENSITIVE_DB_PORTS.get(l.port)
        if not name or l.is_loopback_only:
            continue
        sev = Severity.critical if l.port in (2375, 2379, 10250) else Severity.medium
        yield _f(a, "datastore_network_bind", sev, f"{name} listening on all interfaces ({l.address}:{l.port})",
                 f"{name} accepts connections from the network. Unless remote clients need it, bind it to "
                 "localhost or restrict it with the host firewall, and make sure authentication is required.",
                 Remediation(kind=RemediationKind.config, summary=f"Bind {name} to 127.0.0.1 or firewall port {l.port}",
                             commands=[f"ufw deny {l.port}/tcp"]),
                 {"listener": l.model_dump()}, category=FindingCategory.exposure, suffix=str(l.port))


# --------------------------------------------------------------------------- #
# Credentials lying around
# --------------------------------------------------------------------------- #
@check
def credentials(inv: Inventory, a: str):
    for c in inv.credentials:
        if c.kind == "ssh_private_key" and c.encrypted is False:
            yield _f(a, "ssh_key_unencrypted", Severity.medium,
                     f"Unencrypted SSH private key for '{c.owner}' ({c.path})",
                     "Anyone who compromises this account (or root) can reuse this key against every host that "
                     "trusts it. Encrypt it with a passphrase or move to a hardware-backed key (FIDO2 / ssh-agent "
                     "with confirmation).",
                     Remediation(kind=RemediationKind.credential, summary="Add a passphrase or replace with a FIDO2 key",
                                 commands=[f"ssh-keygen -p -f {c.path}"]),
                     {"path": c.path, "owner": c.owner, "fingerprint": c.fingerprint, "targets": c.targets},
                     category=FindingCategory.credential, suffix=c.fingerprint or c.path)
        elif c.kind in ("aws", "gcp", "azure"):
            yield _f(a, f"cloud_creds_{c.kind}", Severity.medium,
                     f"Long-lived {c.kind.upper()} credentials stored on disk for '{c.owner}'",
                     "Static cloud keys on endpoints are frequently stolen and give direct access to cloud "
                     "resources. Prefer SSO / short-lived credentials (aws sso login, workload identity).",
                     Remediation(kind=RemediationKind.credential, summary="Replace static keys with short-lived SSO credentials"),
                     {"path": c.path, "owner": c.owner, "identifier": c.identifier},
                     category=FindingCategory.credential, suffix=c.path)
        elif c.kind == "history_secret":
            n = c.details.get("count", 0)
            yield _f(a, "history_secrets", Severity.medium,
                     f"Shell history for '{c.owner}' contains {n} command(s) with inline secrets",
                     "Passwords typed on the command line persist in history files and are read by attackers "
                     "during post-exploitation.",
                     Remediation(kind=RemediationKind.credential, summary="Rotate the exposed secrets and clear the history",
                                 commands=[f"shred -u {c.path}"]),
                     {"path": c.path, "owner": c.owner, "count": n}, category=FindingCategory.credential, suffix=c.path)
        elif c.kind in ("git", "netrc", "pgpass", "mysql", "docker"):
            yield _f(a, f"plaintext_creds_{c.kind}", Severity.low,
                     f"Plaintext {c.kind} credentials for '{c.owner}' ({c.path})",
                     "Credential files enable lateral movement to the systems they target.",
                     Remediation(kind=RemediationKind.credential, summary="Use a credential helper / secrets manager"),
                     {"path": c.path, "owner": c.owner, "targets": c.targets},
                     category=FindingCategory.credential, suffix=c.path)


@check
def containers(inv: Inventory, a: str):
    for c in inv.containers:
        risky_mounts = [m for m in c.mounts if any(x in m for x in ("docker.sock", ":/host", "/:/", "/etc:", "/root:"))]
        if c.privileged or risky_mounts:
            yield _f(a, "container_escape", Severity.high,
                     f"Container '{c.name or c.id[:12]}' can escape to the host",
                     "Privileged containers or containers with the Docker socket / host root mounted give "
                     "anyone who compromises the container full control of the host.",
                     Remediation(kind=RemediationKind.config, summary="Drop --privileged and sensitive host mounts"),
                     {"container": c.model_dump()}, suffix=c.id[:12])


def check_inventory(inv: Inventory, asset_id: str) -> list[Finding]:
    out: list[Finding] = []
    for fn in CHECKS:
        try:
            out.extend(fn(inv, asset_id))
        except Exception as exc:  # one broken check must not hide the others
            out.append(_f(asset_id, f"check_error_{fn.__name__}", Severity.info, f"Check {fn.__name__} failed",
                          str(exc)))
    return out
