"""Log line parsers -> normalized ``Event``.

Two entry points:

* ``parse_line(source, line, host, ts, asset_id)`` -- a line shipped by an agent
  (``auth.log``/``secure``/``syslog`` raw syslog lines, ``journald`` lines in the
  agent's ``<RFC3339> <host> <ident>[<pid>]: <msg>`` format, ``windows`` JSON
  lines, ``filterlog``...).
* ``parse_syslog(data, peer_ip)`` -- a raw syslog datagram/frame received by the
  syslog listener (RFC3164 / RFC5424 / bare).

Header parsing extracts timestamp, host, program ("ident") and pid; message
parsers (sshd, sudo, su, shadow-utils, pam, cron, logind, kernel firewall
logs, pfSense/OPNsense filterlog, UniFi, docker, Windows events) fill the
normalized fields. Unknown messages still produce a generic ``Event`` -- lines
are never dropped (``None`` only for blank input).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from ..models import Event, Severity, utcnow

# --------------------------------------------------------------------------- #
# header parsing
# --------------------------------------------------------------------------- #
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

_PRI_RE = re.compile(r"^<(\d{1,3})>")
# RFC3164: "Nov 24 10:00:01 host tag[pid]: msg" (day may be space padded)
_BSD_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
    r"(?:(?P<host>[^\s:\[]+)\s+)?(?P<rest>.*)$")
# RFC3339 / ISO timestamp prefix (journald format, rsyslog high-precision format)
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?:(?P<host>[^\s:\[]+)\s+)?(?P<rest>.*)$")
# RFC5424: "1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG"
_5424_RE = re.compile(
    r"^(?P<ver>\d{1,2})\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<rest>.*)$")
# "tag[pid]: msg" or "tag: msg"
_TAG_RE = re.compile(r"^(?P<ident>[A-Za-z0-9_.\-/()@]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$", re.S)

_SEVERITY_FROM_SYSLOG = {0: Severity.critical, 1: Severity.critical, 2: Severity.critical, 3: Severity.high,
                         4: Severity.medium, 5: Severity.low, 6: Severity.info, 7: Severity.info}


def _parse_iso(s: str) -> Optional[datetime]:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = s.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} ", s) else s
    # python <3.11 compat for "+0000"
    m = re.match(r"^(.*[+-]\d{2})(\d{2})$", s)
    if m and ":" not in s[-5:]:
        s = f"{m.group(1)}:{m.group(2)}"
    # truncate fractional seconds beyond microseconds
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _bsd_ts(mon: str, day: str, time_s: str, now: Optional[datetime] = None) -> Optional[datetime]:
    """RFC3164 timestamps carry no year: assume the current year, but a
    December timestamp seen in early January belongs to last year (and a
    timestamp more than a day in the future generally belongs to last year)."""
    now = now or utcnow()
    month = _MONTHS.get(mon)
    if not month:
        return None
    try:
        h, m, s = (int(x) for x in time_s.split(":"))
        dt = datetime(now.year, month, int(day), h, m, s, tzinfo=timezone.utc)
    except ValueError:
        return None
    if dt - now > timedelta(days=1):
        try:
            dt = dt.replace(year=now.year - 1)
        except ValueError:  # Feb 29
            dt = dt.replace(year=now.year - 1, day=28)
    return dt


class Header:
    __slots__ = ("ts", "host", "ident", "pid", "msg", "severity", "facility")

    def __init__(self) -> None:
        self.ts: Optional[datetime] = None
        self.host = ""
        self.ident = ""
        self.pid = 0
        self.msg = ""
        self.severity: Optional[Severity] = None
        self.facility: Optional[int] = None


def _split_tag(rest: str, h: Header) -> None:
    m = _TAG_RE.match(rest)
    if m and not rest.startswith("["):
        h.ident = m.group("ident")
        h.pid = int(m.group("pid")) if m.group("pid") else 0
        h.msg = m.group("msg")
    else:
        h.msg = rest


def parse_header(line: str, now: Optional[datetime] = None) -> Header:
    h = Header()
    s = line.strip("\r\n\x00 ")
    m = _PRI_RE.match(s)
    if m:
        pri = int(m.group(1))
        h.facility, sev = divmod(pri, 8)
        h.severity = _SEVERITY_FROM_SYSLOG.get(sev)
        s = s[m.end():]
    # RFC5424
    m = _5424_RE.match(s)
    if m and m.group("ver") == "1" and (m.group("ts") == "-" or _parse_iso(m.group("ts")) is not None):
        h.ts = _parse_iso(m.group("ts")) if m.group("ts") != "-" else None
        h.host = "" if m.group("host") == "-" else m.group("host")
        h.ident = "" if m.group("app") == "-" else m.group("app")
        procid = m.group("procid")
        h.pid = int(procid) if procid.isdigit() else 0
        rest = m.group("rest")
        # structured data: "-" or one/more [..] blocks
        if rest.startswith("-"):
            rest = rest[1:]
        else:
            while rest.startswith("["):
                depth_end = _sd_end(rest)
                if depth_end < 0:
                    break
                rest = rest[depth_end + 1:]
        rest = rest.lstrip()
        if rest.startswith("\ufeff"):
            rest = rest[1:]
        h.msg = rest
        return h
    m = _ISO_RE.match(s)
    if m:
        h.ts = _parse_iso(m.group("ts"))
        host = m.group("host") or ""
        rest = m.group("rest")
        # if what we took as host is actually "tag[pid]:"/"tag:", there was no host
        if host.endswith(":") or (not rest and host):
            rest = f"{host} {rest}".strip()
            host = ""
        h.host = host
        _split_tag(rest, h)
        return h
    m = _BSD_RE.match(s)
    if m:
        h.ts = _bsd_ts(m.group("mon"), m.group("day"), m.group("time"), now)
        host = m.group("host") or ""
        rest = m.group("rest")
        if host and _TAG_RE.match(host + " ") and rest == "":
            rest, host = host, ""
        h.host = host
        _split_tag(rest, h)
        return h
    _split_tag(s, h)
    return h


def _sd_end(s: str) -> int:
    """Index of the closing ']' of the leading SD-ELEMENT (handles escaped ])."""
    i, esc = 1, False
    while i < len(s):
        c = s[i]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif c == "]":
            return i
        i += 1
    return -1


# --------------------------------------------------------------------------- #
# message parsers
# --------------------------------------------------------------------------- #
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"

_SSHD_PATTERNS: list[tuple[re.Pattern, Callable[[re.Match], dict]]] = []


def _sshd(pattern: str):
    def deco(fn):
        _SSHD_PATTERNS.append((re.compile(pattern), fn))
        return fn
    return deco


@_sshd(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from " + _IP + r" port (?P<port>\d+)(?: \w+)?(?::\s*(?P<keytype>[\w-]+)(?: [\w-]+)? (?P<fp>SHA256:\S+))?")
def _ssh_accepted(m: re.Match) -> dict:
    d = {"category": "authentication", "action": "ssh_login", "outcome": "success", "user": m["user"],
         "src_ip": m["ip"], "src_port": int(m["port"]), "fields": {"method": m["method"]}}
    if m["fp"]:
        d["fields"]["key_fingerprint"] = m["fp"]
        d["fields"]["key_type"] = m["keytype"]
    if m["user"] == "root":
        d["severity"] = Severity.medium
        d["fields"]["root_login"] = True
    return d


@_sshd(r"^Failed (?P<method>\S+) for invalid user (?P<user>.*?) from " + _IP + r" port (?P<port>\d+)")
def _ssh_failed_invalid(m: re.Match) -> dict:
    return {"category": "authentication", "action": "ssh_invalid_user", "outcome": "failure", "user": m["user"],
            "src_ip": m["ip"], "src_port": int(m["port"]), "severity": Severity.low,
            "fields": {"method": m["method"], "invalid_user": True}}


@_sshd(r"^Failed (?P<method>\S+) for (?P<user>\S+) from " + _IP + r" port (?P<port>\d+)")
def _ssh_failed(m: re.Match) -> dict:
    return {"category": "authentication", "action": "ssh_failed", "outcome": "failure", "user": m["user"],
            "src_ip": m["ip"], "src_port": int(m["port"]), "severity": Severity.low,
            "fields": {"method": m["method"]}}


@_sshd(r"^Invalid user (?P<user>.*?) from " + _IP + r"(?: port (?P<port>\d+))?")
def _ssh_invalid(m: re.Match) -> dict:
    return {"category": "authentication", "action": "ssh_invalid_user", "outcome": "failure", "user": m["user"],
            "src_ip": m["ip"], "src_port": int(m["port"] or 0), "severity": Severity.low,
            "fields": {"invalid_user": True}}


@_sshd(r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from " + _IP + r" port (?P<port>\d+)")
def _ssh_maxauth(m: re.Match) -> dict:
    return {"category": "authentication", "action": "ssh_failed", "outcome": "failure", "user": m["user"],
            "src_ip": m["ip"], "src_port": int(m["port"]), "severity": Severity.medium,
            "fields": {"max_attempts_exceeded": True}}


@_sshd(r"^Connection (?:closed|reset) by (?:authenticating|invalid) user (?P<user>\S+) " + _IP + r" port (?P<port>\d+)(?: \[preauth\])?")
def _ssh_closed_auth(m: re.Match) -> dict:
    return {"category": "authentication", "action": "ssh_failed", "outcome": "failure", "user": m["user"],
            "src_ip": m["ip"], "src_port": int(m["port"]), "severity": Severity.low,
            "fields": {"preauth_disconnect": True}}


@_sshd(r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?")
def _ssh_pam_fail(m: re.Match) -> dict:
    return {"category": "authentication", "action": "ssh_auth_failure", "outcome": "failure",
            "user": m["user"] or "", "src_ip": m["ip"] or "", "severity": Severity.low, "fields": {"pam": True}}


@_sshd(r"^Did not receive identification string from " + _IP + r"(?: port (?P<port>\d+))?")
def _ssh_noident(m: re.Match) -> dict:
    return {"category": "network", "action": "ssh_probe", "outcome": "failure", "src_ip": m["ip"],
            "src_port": int(m["port"] or 0), "severity": Severity.low}


@_sshd(r"^(?:banner exchange|kex_exchange_identification|Bad protocol version identification|Unable to negotiate).*?" + r"(?:from |with )?" + r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})(?: port (?P<port>\d+))?")
def _ssh_proto_probe(m: re.Match) -> dict:
    return {"category": "network", "action": "ssh_probe", "outcome": "failure", "src_ip": m["ip"],
            "src_port": int(m["port"] or 0), "severity": Severity.low}


@_sshd(r"^Disconnected from (?:user |invalid user |authenticating user )?(?P<user>\S+) " + _IP + r" port (?P<port>\d+)")
def _ssh_disconnected(m: re.Match) -> dict:
    return {"category": "authentication", "action": "ssh_disconnect", "outcome": "unknown", "user": m["user"],
            "src_ip": m["ip"], "src_port": int(m["port"])}


@_sshd(r"^pam_unix\(sshd:session\): session (?P<state>opened|closed) for user (?P<user>\S+)")
def _ssh_session(m: re.Match) -> dict:
    return {"category": "session", "action": f"ssh_session_{m['state']}", "outcome": "success",
            "user": m["user"]}


def _parse_sshd(msg: str) -> Optional[dict]:
    for rx, fn in _SSHD_PATTERNS:
        m = rx.search(msg)
        if m:
            return fn(m)
    return None


_SUDO_CMD_RE = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<pre>.*?) ; )?TTY=(?P<tty>[^;]*) ; PWD=(?P<pwd>[^;]*) ; "
                          r"USER=(?P<target>[^;]*?) ;(?: GROUP=[^;]* ;)?(?: ENV=[^;]* ;)? COMMAND=(?P<cmd>.*)$")
_SHELLS = ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/sh", "/usr/bin/zsh", "/bin/dash",
           "/usr/bin/su", "/bin/su", "/usr/bin/fish")


def _parse_sudo(msg: str) -> Optional[dict]:
    m = _SUDO_CMD_RE.match(msg)
    if m:
        pre = m["pre"] or ""
        cmd = m["cmd"].strip()
        base = cmd.split()[0] if cmd else ""
        fields: dict[str, Any] = {"target_user": m["target"].strip(), "command": cmd, "tty": m["tty"].strip(),
                                  "pwd": m["pwd"].strip()}
        if "NOT in sudoers" in pre or "user NOT authorized" in pre or "command not allowed" in pre:
            return {"category": "iam", "action": "sudo_denied", "outcome": "failure", "user": m["user"],
                    "severity": Severity.medium, "fields": {**fields, "reason": pre.strip()}}
        if "incorrect password attempt" in pre:
            n = re.search(r"(\d+) incorrect password attempt", pre)
            fields["attempts"] = int(n.group(1)) if n else 1
            return {"category": "iam", "action": "sudo_failed", "outcome": "failure", "user": m["user"],
                    "severity": Severity.low, "fields": fields}
        fields["root_shell"] = base in _SHELLS or base.endswith("/su") or cmd in ("-s", "-i") \
            or bool(re.match(r"^(\S*/)?(bash|sh|zsh|su|dash|fish)(\s+-.*)?$", cmd))
        return {"category": "iam", "action": "sudo", "outcome": "success", "user": m["user"],
                "process": base, "severity": Severity.low if fields["root_shell"] else Severity.info,
                "fields": fields}
    m = re.search(r"pam_unix\(sudo:auth\): authentication failure;.*?(?:ruser=(?P<ruser>\S*))?.*?(?:user=(?P<user>\S+))?$", msg)
    if m:
        return {"category": "iam", "action": "sudo_failed", "outcome": "failure",
                "user": m["ruser"] or m["user"] or "", "severity": Severity.low}
    m = re.search(r"pam_unix\(sudo:session\): session (opened|closed) for user (\S+?)(?:\(uid=\d+\))? by (\S+?)(?:\(uid=\d+\))?$", msg)
    if m:
        return {"category": "session", "action": f"sudo_session_{m.group(1)}", "outcome": "success",
                "user": m.group(3), "fields": {"target_user": m.group(2)}}
    return None


def _parse_su(msg: str) -> Optional[dict]:
    m = re.search(r"pam_unix\(su(?:-l)?:session\): session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*?)(?:\(uid=\d+\))?$", msg)
    if m:
        return {"category": "iam", "action": "su", "outcome": "success", "user": m.group(2) or "",
                "fields": {"target_user": m.group(1)}, "severity": Severity.low if m.group(1) == "root" else Severity.info}
    m = re.search(r"pam_unix\(su(?:-l)?:auth\): authentication failure;.*?ruser=(\S*).*?user=(\S+)", msg)
    if m:
        return {"category": "iam", "action": "su_failed", "outcome": "failure", "user": m.group(1),
                "fields": {"target_user": m.group(2)}, "severity": Severity.low}
    m = re.search(r"FAILED (?:SU|su) (?:\(to (\S+)\) )?(\S+) on", msg)
    if m:
        return {"category": "iam", "action": "su_failed", "outcome": "failure", "user": m.group(2),
                "fields": {"target_user": m.group(1) or "root"}, "severity": Severity.low}
    m = re.search(r"\(to (\S+)\) (\S+) on", msg)
    if m:
        return {"category": "iam", "action": "su", "outcome": "success", "user": m.group(2),
                "fields": {"target_user": m.group(1)}}
    return None


ADMIN_GROUPS = {"sudo", "wheel", "admin", "adm", "root", "docker", "lxd", "administrators", "domain admins",
                "enterprise admins", "schema admins", "backup operators"}


def _parse_shadow_utils(ident: str, msg: str) -> Optional[dict]:
    m = re.search(r"new user: name=([^,\s]+), UID=(\d+)", msg)
    if m:
        return {"category": "iam", "action": "user_created", "outcome": "success", "user": m.group(1),
                "severity": Severity.medium if m.group(2) == "0" else Severity.low,
                "fields": {"uid": int(m.group(2))}}
    m = re.search(r"new group: name=([^,\s]+), GID=(\d+)", msg)
    if m:
        return {"category": "iam", "action": "group_created", "outcome": "success",
                "fields": {"group": m.group(1), "gid": int(m.group(2))}}
    m = re.search(r"(?:add|adding) '?([^'\s]+)'? to (?:shadow )?group '?([^'\s]+?)'?$", msg) or \
        re.search(r"user (\S+) added by \S+ to group (\S+)", msg) or \
        re.search(r"(?:add|adding) user '?([^'\s]+)'? to group '?([^'\s]+?)'?$", msg) or \
        re.search(r"members of group (\S+) set by \S+ to (\S+)", msg)
    if m:
        user, group = m.group(1), m.group(2)
        if msg.startswith("members of group"):
            group, user = m.group(1), m.group(2)
        if "shadow group" in msg:
            return {"category": "iam", "action": "group_member_added", "outcome": "success", "user": user,
                    "severity": Severity.info, "fields": {"group": group, "shadow": True}}
        admin = group.lower() in ADMIN_GROUPS
        return {"category": "iam", "action": "group_member_added", "outcome": "success", "user": user,
                "severity": Severity.high if admin else Severity.low,
                "fields": {"group": group, "admin_group": admin}}
    m = re.search(r"delete user '?([^'\s]+)'?", msg)
    if m:
        return {"category": "iam", "action": "user_deleted", "outcome": "success", "user": m.group(1),
                "severity": Severity.low}
    m = re.search(r"change user '?([^'\s]+)'? (\S+)", msg)
    if m:
        return {"category": "iam", "action": "user_modified", "outcome": "success", "user": m.group(1),
                "fields": {"change": m.group(2)}}
    m = re.search(r"pam_unix\(passwd:chauthtok\): password changed for (\S+)", msg) or \
        re.search(r"password (?:for '?(\S+?)'? )?changed(?: by '?(\S+?)'?)?$", msg)
    if m:
        user = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else "") or ""
        return {"category": "iam", "action": "password_changed", "outcome": "success", "user": user,
                "severity": Severity.medium if user == "root" else Severity.low}
    return None


_KV_RE = re.compile(r"\b([A-Z]{2,})=(\S*)")


def _parse_netfilter(msg: str) -> Optional[dict]:
    """Kernel netfilter LOG lines: UFW, plain iptables LOG prefixes, UniFi rule prefixes."""
    if "SRC=" not in msg or "DST=" not in msg:
        return None
    kv = dict(_KV_RE.findall(msg))
    prefix_m = re.search(r"\[([^\]]+)\]\s*IN=", msg) or re.search(r"(\S+)\s*IN=", msg)
    prefix = prefix_m.group(1).strip() if prefix_m else ""
    fields: dict[str, Any] = {"in_interface": kv.get("IN", ""), "out_interface": kv.get("OUT", ""),
                              "protocol": kv.get("PROTO", "").lower(), "prefix": prefix}
    action = "logged"
    up = prefix.upper()
    vendor = "iptables"
    if up.startswith("UFW "):
        vendor = "ufw"
        action = "blocked" if ("BLOCK" in up or "DENY" in up) else ("allowed" if "ALLOW" in up else "logged")
    else:
        # UniFi legacy: WAN_IN-2000-D / LAN_LOCAL-4000-A ; zone based: e.g. "Internal_External-1-A" / "...-B"/"-D"/"-R"
        um = re.match(r"^(?P<ruleset>[A-Za-z0-9_]+)-(?P<rule>[A-Za-z0-9]+)-(?P<act>[ADRB])$", prefix)
        if um:
            vendor = "unifi"
            fields["ruleset"] = um["ruleset"]
            fields["rule"] = um["rule"]
            action = "allowed" if um["act"] == "A" else "blocked"
        elif any(w in up for w in ("DROP", "BLOCK", "DENY", "REJECT")):
            action = "blocked"
        elif any(w in up for w in ("ACCEPT", "ALLOW", "PASS")):
            action = "allowed"
    fields["vendor"] = vendor
    d: dict[str, Any] = {"category": "firewall", "action": action,
                         "outcome": "failure" if action == "blocked" else "success",
                         "src_ip": kv.get("SRC", ""), "dst_ip": kv.get("DST", ""), "fields": fields}
    if kv.get("SPT", "").isdigit():
        d["src_port"] = int(kv["SPT"])
    if kv.get("DPT", "").isdigit():
        d["dst_port"] = int(kv["DPT"])
    return d


_FILTERLOG_PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp"}


def _parse_filterlog(msg: str) -> Optional[dict]:
    """pfSense/OPNsense filterlog CSV.

    Common: rule,subrule,anchor,tracker,interface,reason,action,direction,ipver,
    IPv4: tos,ecn,ttl,id,offset,flags,proto_id,proto_text,length,src,dst,
    IPv6: class,flowlabel,hoplimit,proto_text,proto_id,length,src,dst,
    then for tcp/udp: srcport,dstport,datalen[,tcpflags,...].
    """
    p = msg.strip().split(",")
    if len(p) < 9 or p[8] not in ("4", "6"):
        return None
    action_raw = p[6]
    fields: dict[str, Any] = {"rule_number": p[0], "rule_tracker": p[3], "interface": p[4], "reason": p[5],
                              "direction": p[7], "ip_version": int(p[8]), "vendor": "pf"}
    try:
        if p[8] == "4":
            proto = p[16].lower() if len(p) > 16 else ""
            src, dst = p[18], p[19]
            rest = p[20:]
        else:
            proto = p[12].lower() if len(p) > 12 else ""
            src, dst = p[15], p[16]
            rest = p[17:]
    except IndexError:
        return None
    if not proto:
        proto = _FILTERLOG_PROTO.get(p[17] if p[8] == "4" and len(p) > 17 else "", "")
    fields["protocol"] = proto
    action = {"pass": "allowed", "block": "blocked", "reject": "blocked", "match": "logged"}.get(action_raw, action_raw)
    d: dict[str, Any] = {"category": "firewall", "action": action,
                         "outcome": "failure" if action == "blocked" else "success",
                         "src_ip": src, "dst_ip": dst, "fields": fields}
    if proto in ("tcp", "udp") and len(rest) >= 2:
        if rest[0].isdigit():
            d["src_port"] = int(rest[0])
        if rest[1].isdigit():
            d["dst_port"] = int(rest[1])
        if proto == "tcp" and len(rest) >= 4:
            fields["tcp_flags"] = rest[3]
    return d


def _parse_logind(msg: str) -> Optional[dict]:
    m = re.search(r"New session (\S+) of user (\S+)\.", msg)
    if m:
        return {"category": "session", "action": "session_opened", "outcome": "success", "user": m.group(2),
                "fields": {"session": m.group(1)}}
    m = re.search(r"Removed session (\S+)\.", msg)
    if m:
        return {"category": "session", "action": "session_closed", "outcome": "success",
                "fields": {"session": m.group(1)}}
    return None


def _parse_cron(msg: str) -> Optional[dict]:
    m = re.search(r"\((\S+)\) CMD \((.*)\)\s*$", msg)
    if m:
        return {"category": "process", "action": "cron_exec", "outcome": "success", "user": m.group(1),
                "fields": {"command": m.group(2)}}
    m = re.search(r"pam_unix\(cron:session\): session (opened|closed) for user (\S+?)(?:\(uid=\d+\))?(?: by|$)", msg)
    if m:
        return {"category": "session", "action": f"cron_session_{m.group(1)}", "outcome": "success",
                "user": m.group(2)}
    return None


def _parse_docker(msg: str) -> Optional[dict]:
    if re.search(r"Daemon has completed initialization|API listen on", msg):
        return {"category": "process", "action": "docker_started", "outcome": "success"}
    m = re.search(r'container (\w+)\b.*?(?:image=([^\s,)]+))?', msg)
    if m and re.search(r"(?i)\b(create|start|die|kill|exec_start)\b", msg):
        act = re.search(r"(?i)\b(create|start|die|kill|exec_start)\b", msg).group(1).lower()
        return {"category": "process", "action": f"container_{act}", "outcome": "success",
                "fields": {"container": m.group(1), "image": m.group(2) or ""}}
    return None


def _parse_pam_generic(msg: str) -> Optional[dict]:
    m = re.search(r"pam_unix\((\S+?):auth\): authentication failure;.*?(?:rhost=(\S*))?(?:\s+user=(\S+))?\s*$", msg)
    if m:
        return {"category": "authentication", "action": "auth_failure", "outcome": "failure",
                "user": m.group(3) or "", "src_ip": m.group(2) or "", "severity": Severity.low,
                "fields": {"service": m.group(1)}}
    m = re.search(r"pam_unix\((\S+?):session\): session (opened|closed) for user (\S+?)(?:\(uid=\d+\))?(?: by|$)", msg)
    if m:
        return {"category": "session", "action": f"session_{m.group(2)}", "outcome": "success",
                "user": m.group(3), "fields": {"service": m.group(1)}}
    return None


# --------------------------------------------------------------------------- #
# windows
# --------------------------------------------------------------------------- #
_WIN_ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins",
                     "backup operators", "account operators", "server operators", "remote desktop users",
                     "dnsadmins", "group policy creator owners", "hyper-v administrators"}
_PS_SUSPICIOUS = re.compile(
    r"(?i)(-enc(?:odedcommand)?\s|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|"
    r"invoke-webrequest|net\.webclient|invoke-mimikatz|amsiutils|bypass|-nop\b|hidden|reflection\.assembly)")
_OFFICE = re.compile(r"(?i)\\(winword|excel|powerpnt|outlook|msaccess|mspub|onenote)\.exe$")
_SHELL_PROC = re.compile(r"(?i)\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)\.exe$")


def _dget(d: dict, *keys: str, default: Any = "") -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "-"):
            return d[k]
    return default


def _win_ts(v: Any) -> Optional[datetime]:
    """Windows timestamps: ISO 8601, or PowerShell ConvertTo-Json's "/Date(1700000000000)/"."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
    m = re.match(r"^/Date\((-?\d+)(?:[+-]\d{4})?\)/$", str(v))
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    return _parse_iso(str(v))


def _parse_windows(obj: dict) -> dict:
    eid = int(obj.get("EventID") or obj.get("Id") or obj.get("event_id") or 0)
    data = obj.get("Data") or obj.get("EventData") or {}
    if not isinstance(data, dict):
        data = {}
    user = _dget(data, "TargetUserName", "SubjectUserName", "AccountName")
    domain = _dget(data, "TargetDomainName", "SubjectDomainName")
    ip = _dget(data, "IpAddress", "SourceNetworkAddress")
    ip = "" if ip in ("::1", "127.0.0.1", "-") else ip
    port = _dget(data, "IpPort")
    fields: dict[str, Any] = {"event_id": eid, "provider": obj.get("Provider", ""), "domain": domain}
    d: dict[str, Any] = {"user": str(user), "src_ip": str(ip), "fields": fields, "category": "", "action": f"win_{eid}",
                         "outcome": "unknown"}
    if str(port).isdigit():
        d["src_port"] = int(port)
    if eid == 4624:
        fields["logon_type"] = int(_dget(data, "LogonType", default=0) or 0)
        d.update(category="authentication", action="win_logon", outcome="success")
    elif eid == 4625:
        fields["logon_type"] = int(_dget(data, "LogonType", default=0) or 0)
        fields["status"] = _dget(data, "Status", "SubStatus")
        d.update(category="authentication", action="win_logon_failed", outcome="failure", severity=Severity.low)
    elif eid == 4672:
        d.update(category="iam", action="win_special_privileges", outcome="success",
                 user=str(_dget(data, "SubjectUserName")))
    elif eid == 4720:
        d.update(category="iam", action="user_created", outcome="success", severity=Severity.medium,
                 user=str(_dget(data, "TargetUserName", "SamAccountName")))
        fields["created_by"] = _dget(data, "SubjectUserName")
    elif eid in (4728, 4732, 4756):
        group = str(_dget(data, "TargetUserName", "GroupName"))
        member = str(_dget(data, "MemberName", "MemberSid"))
        m = re.match(r"^CN=([^,]+)", member)
        if m:
            member = m.group(1)
        admin = group.lower() in _WIN_ADMIN_GROUPS
        fields.update(group=group, admin_group=admin, changed_by=_dget(data, "SubjectUserName"))
        d.update(category="iam", action="group_member_added", outcome="success", user=member,
                 severity=Severity.high if admin else Severity.low)
    elif eid == 4740:
        d.update(category="authentication", action="account_locked", outcome="failure", severity=Severity.medium,
                 user=str(_dget(data, "TargetUserName")))
        fields["caller_computer"] = _dget(data, "TargetDomainName")
    elif eid in (1102, 104):
        d.update(category="iam", action="audit_log_cleared", outcome="success", severity=Severity.critical,
                 user=str(_dget(data, "SubjectUserName")))
    elif eid in (7045, 4697):
        fields.update(service_name=_dget(data, "ServiceName"), image_path=_dget(data, "ImagePath", "ServiceFileName"),
                      start_type=_dget(data, "StartType"), account=_dget(data, "AccountName", "ServiceAccount"))
        d.update(category="process", action="service_installed", outcome="success", severity=Severity.medium,
                 process=str(fields["image_path"]), user=str(_dget(data, "SubjectUserName")))
    elif eid == 4688:
        proc = str(_dget(data, "NewProcessName"))
        parent = str(_dget(data, "ParentProcessName"))
        cmd = str(_dget(data, "CommandLine"))
        fields.update(command=cmd, parent_process=parent)
        sev = Severity.info
        if _OFFICE.search(parent) and _SHELL_PROC.search(proc):
            fields["office_spawned_shell"] = True
            sev = Severity.high
        if _PS_SUSPICIOUS.search(cmd):
            fields["suspicious_command"] = True
            sev = max(sev, Severity.medium, key=lambda s: s.weight)
        d.update(category="process", action="process_created", outcome="success", process=proc, severity=sev,
                 user=str(_dget(data, "SubjectUserName")))
    elif eid == 4104:
        script = str(_dget(data, "ScriptBlockText"))
        hits = sorted({h.lower().strip() for h in _PS_SUSPICIOUS.findall(script)})
        fields.update(script_block_id=_dget(data, "ScriptBlockId"), script_excerpt=script[:2000],
                      suspicious_patterns=hits, suspicious_command=bool(hits))
        d.update(category="process", action="powershell_script", outcome="success", process="powershell",
                 severity=Severity.high if hits else Severity.info)
    return d


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #
def _dispatch(ident: str, msg: str) -> Optional[dict]:
    i = ident.lower()
    base = i.rsplit("/", 1)[-1]
    if base in ("sshd", "sshd-session", "ssh"):
        return _parse_sshd(msg)
    if base == "sudo":
        return _parse_sudo(msg)
    if base in ("su", "su-l"):
        return _parse_su(msg)
    if base in ("useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod", "gpasswd", "passwd",
                "chpasswd", "adduser", "chage"):
        return _parse_shadow_utils(base, msg)
    if base == "filterlog":
        return _parse_filterlog(msg)
    if base in ("kernel", "ulogd", "ulogd2") or "SRC=" in msg:
        r = _parse_netfilter(msg)
        if r:
            return r
    if base in ("systemd-logind",):
        return _parse_logind(msg)
    if base in ("cron", "crond", "anacron"):
        return _parse_cron(msg)
    if base in ("dockerd", "docker", "containerd"):
        return _parse_docker(msg)
    # pam lines can come from many programs (login, gdm, polkit, ...)
    if "pam_unix(" in msg:
        return _parse_pam_generic(msg)
    if base in ("sshd",):
        return _parse_sshd(msg)
    return None


def _build(h: Header, parsed: Optional[dict], source: str, raw: str, host: str, asset_id: Optional[str],
           ts: Optional[datetime]) -> Event:
    fields = dict((parsed or {}).get("fields", {}))
    if h.ident:
        fields.setdefault("program", h.ident)
    if h.pid:
        fields.setdefault("pid", h.pid)
    sev = (parsed or {}).get("severity") or Severity.info
    ev = Event(
        timestamp=ts or h.ts or utcnow(),
        asset_id=asset_id,
        host=host or h.host,
        source=source,
        category=(parsed or {}).get("category", ""),
        action=(parsed or {}).get("action", "log"),
        outcome=(parsed or {}).get("outcome", ""),
        severity=sev,
        user=(parsed or {}).get("user", "") or "",
        src_ip=(parsed or {}).get("src_ip", "") or "",
        src_port=(parsed or {}).get("src_port", 0) or 0,
        dst_ip=(parsed or {}).get("dst_ip", "") or "",
        dst_port=(parsed or {}).get("dst_port", 0) or 0,
        process=(parsed or {}).get("process", "") or h.ident,
        message=h.msg if h.msg else raw,
        raw=raw[:65536],
        fields=fields,
    )
    return ev


def parse_line(source: str, line: str, host: str = "", ts: Optional[datetime] = None,
               asset_id: Optional[str] = None) -> Optional[Event]:
    """Parse one log line shipped by an agent (or any other line-oriented source)."""
    if line is None:
        return None
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return None
    src = (source or "").lower()

    if src in ("windows", "winevent", "windows-eventlog") or (raw.lstrip().startswith("{") and '"EventID"' in raw):
        try:
            obj = json.loads(raw)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            parsed = _parse_windows(obj)
            ev_ts = ts or _win_ts(obj.get("TimeCreated") or obj.get("TimeGenerated"))
            ev = Event(
                timestamp=ev_ts or utcnow(), asset_id=asset_id,
                host=host or str(obj.get("Computer", "") or obj.get("MachineName", "")),
                source=source or "windows", category=parsed["category"], action=parsed["action"],
                outcome=parsed["outcome"], severity=parsed.get("severity", Severity.info),
                user=parsed.get("user", ""), src_ip=parsed.get("src_ip", ""), src_port=parsed.get("src_port", 0),
                process=parsed.get("process", ""), message=str(obj.get("Message", ""))[:8192] or raw[:2000],
                raw=raw[:65536], fields=parsed["fields"])
            return ev

    h = parse_header(raw)
    if src == "filterlog" and not h.ident:
        h.ident = "filterlog"
    parsed = _dispatch(h.ident, h.msg) if h.msg else None
    if parsed is None and src == "filterlog":
        parsed = _parse_filterlog(h.msg or raw)
    if parsed is None and ("SRC=" in raw and "DST=" in raw):
        parsed = _parse_netfilter(h.msg or raw)
    ev = _build(h, parsed, source, raw, host, asset_id, ts)
    if parsed is None and h.severity is not None:
        ev.severity = h.severity if h.severity.weight >= Severity.high.weight else Severity.info
    return ev


def parse_syslog(data: bytes, peer_ip: str) -> Optional[Event]:
    """Parse a raw syslog message received from the network."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    text = text.strip("\r\n\x00 ")
    if not text:
        return None
    h = parse_header(text)
    parsed = _dispatch(h.ident, h.msg) if h.msg else None
    if parsed is None and "SRC=" in text and "DST=" in text:
        parsed = _parse_netfilter(h.msg or text)
    source = "syslog"
    if h.ident.lower() == "filterlog":
        source = "filterlog"
    elif parsed and parsed.get("fields", {}).get("vendor") == "unifi":
        source = "unifi"
    ev = _build(h, parsed, source, text, h.host or peer_ip, None, None)
    ev.fields.setdefault("peer_ip", peer_ip)
    if parsed is None and h.severity is not None:
        ev.severity = h.severity if h.severity.weight >= Severity.high.weight else Severity.info
    return ev
