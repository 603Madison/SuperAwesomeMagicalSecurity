"""Pseudonymization of environment identifiers before data leaves for a cloud LLM.

When a provider has ``locality: cloud`` and ``allow_sensitive: false`` (the default), the
analyst routes every message and tool result through a ``Redactor``:

* IP addresses (v4/v6, incl. CIDR suffixes) -> ``PRIV-IP-3`` / ``PUB-IP-1`` (keeps the
  private/public distinction, which matters for exposure analysis)
* MAC addresses -> ``MAC-1``; e-mail addresses -> ``EMAIL-1``
* SSH fingerprints (``SHA256:...``) -> ``KEY-1``; masked cloud key ids (``AKIA****WXYZ``) -> ``CRED-1``
* known hostnames / FQDNs / asset names / asset ids -> ``HOST-1``
* known local user names (excluding well-known system accounts) -> ``USER-1``

The mapping is stable for one conversation, so the model can reason about "HOST-2" across
tool results. Tokens coming back from the model (tool-call arguments, final answer) are
restored with ``restore`` / ``restore_obj`` so tools receive real identifiers and the user
reads real names. Vulnerability ids, package names, finding keys and ports pass through.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

# accounts whose names carry no sensitive information and are useful for analysis
SYSTEM_ACCOUNTS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
    "www-data", "backup", "list", "irc", "gnats", "nobody", "nogroup", "systemd-network",
    "systemd-resolve", "systemd-timesync", "messagebus", "syslog", "sshd", "_apt", "postgres", "mysql",
    "redis", "mongodb", "docker", "sudo", "wheel", "admin", "administrator", "administrators", "users",
    "staff", "adm", "dip", "plugdev", "lxd", "ubuntu", "ec2-user", "guest", "system", "localsystem",
    "nginx", "apache", "polkitd", "chrony", "ntp", "tss", "uuidd", "tcpdump", "dnsmasq", "avahi",
}

_IPV4 = r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/\d{1,2})?(?![\w.]*\d|[-~+]\w*[A-Za-z])"
_IPV6 = r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?(?![\w:])|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?(?:/\d{1,3})?(?![\w:])"
_MAC = r"(?<![\w:-])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![\w:-])"
_EMAIL = r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w-])"
_SSHFP = r"SHA256:[A-Za-z0-9+/]{20,}={0,2}"
_MASKED = r"(?<![\w*])[A-Z0-9]{3,6}\*{2,}[A-Za-z0-9]{2,6}(?![\w*])"

TOKEN_RE = re.compile(r"\b(PRIV-IP|PUB-IP|HOST|USER|EMAIL|MAC|KEY|CRED)-(\d+)\b")


class Redactor:
    def __init__(self, enabled: bool = True, hostnames: Iterable[str] = (), usernames: Iterable[str] = ()):
        self.enabled = enabled
        self._fwd: dict[str, str] = {}      # real -> token
        self._rev: dict[str, str] = {}      # token -> real
        self._counters: dict[str, int] = {}
        self._hosts: set[str] = set()
        self._users: set[str] = set()
        self._term_re: re.Pattern[str] | None = None
        self.add_hostnames(hostnames)
        self.add_usernames(usernames)

    # ------------------------------------------------------------------ #
    # registration of known identifiers
    # ------------------------------------------------------------------ #
    def add_hostnames(self, names: Iterable[str]) -> None:
        for n in names:
            n = (n or "").strip()
            if len(n) >= 3 and not TOKEN_RE.fullmatch(n) and n.lower() not in ("localhost", "unknown"):
                self._hosts.add(n)
                # also the short name of an FQDN
                if "." in n and not _looks_like_ip(n):
                    short = n.split(".", 1)[0]
                    if len(short) >= 3:
                        self._hosts.add(short)
        self._term_re = None

    def add_usernames(self, names: Iterable[str]) -> None:
        for n in names:
            n = (n or "").strip()
            if len(n) >= 3 and n.lower() not in SYSTEM_ACCOUNTS and not n.startswith("_") and not n.endswith("$"):
                self._users.add(n)
        self._term_re = None

    # ------------------------------------------------------------------ #
    def _token(self, kind: str, real: str) -> str:
        tok = self._fwd.get(real)
        if tok is None:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            tok = f"{kind}-{self._counters[kind]}"
            self._fwd[real] = tok
            self._rev[tok] = real
        return tok

    def _ip_token(self, m: re.Match[str]) -> str:
        raw = m.group(0)
        addr, _, prefix = raw.partition("/")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return raw
        if ip.is_loopback or ip.is_unspecified:
            return raw          # 127.0.0.1 / 0.0.0.0 / :: are semantics, not identity
        kind = "PRIV-IP" if _is_internal(ip) else "PUB-IP"
        tok = self._token(kind, addr)
        return f"{tok}/{prefix}" if prefix else tok

    def _terms(self) -> re.Pattern[str] | None:
        if self._term_re is None:
            terms = sorted(self._hosts | self._users, key=len, reverse=True)
            if not terms:
                return None
            alt = "|".join(re.escape(t) for t in terms)
            self._term_re = re.compile(rf"(?<![\w.-])(?:{alt})(?![\w-]|\.\w)")
        return self._term_re

    def _term_token(self, m: re.Match[str]) -> str:
        real = m.group(0)
        kind = "HOST" if real in self._hosts else "USER"
        return self._token(kind, real)

    # ------------------------------------------------------------------ #
    def redact(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        out = re.sub(_EMAIL, lambda m: self._token("EMAIL", m.group(0)), text)
        out = re.sub(_SSHFP, lambda m: self._token("KEY", m.group(0)), out)
        out = re.sub(_MASKED, lambda m: self._token("CRED", m.group(0)), out)
        out = re.sub(_MAC, lambda m: self._token("MAC", m.group(0).lower()), out)
        out = re.sub(_IPV4, self._ip_token, out)
        out = re.sub(_IPV6, self._ip_token, out)
        terms = self._terms()
        if terms is not None:
            out = terms.sub(self._term_token, out)
        return out

    def restore(self, text: str) -> str:
        if not self.enabled or not text or not self._rev:
            return text
        return TOKEN_RE.sub(lambda m: self._rev.get(m.group(0), m.group(0)), text)

    def redact_obj(self, obj: Any) -> Any:
        if not self.enabled:
            return obj
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, dict):
            return {(self.redact(k) if isinstance(k, str) else k): self.redact_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact_obj(v) for v in obj]
        return obj

    def restore_obj(self, obj: Any) -> Any:
        if not self.enabled:
            return obj
        if isinstance(obj, str):
            return self.restore(obj)
        if isinstance(obj, dict):
            return {(self.restore(k) if isinstance(k, str) else k): self.restore_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.restore_obj(v) for v in obj]
        return obj

    @property
    def mapping(self) -> dict[str, str]:
        """token -> real value (for audit/debugging; never send this to a model)."""
        return dict(self._rev)


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fc00::/7", "fe80::/10")]


def _is_internal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """RFC1918 / CGNAT / ULA / link-local -- i.e. addresses that are not reachable from the internet."""
    return any(ip.version == n.version and ip in n for n in _INTERNAL_NETS)


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.split("/")[0])
        return True
    except ValueError:
        return False


def redactor_for_context(ctx: Any, enabled: bool) -> Redactor:
    """Build a Redactor pre-loaded with every hostname / asset name / user name SAMS knows."""
    r = Redactor(enabled=enabled)
    if not enabled:
        return r
    hosts: set[str] = set()
    users: set[str] = set()
    try:
        for a in ctx.store.list_assets():
            hosts.add(a["name"])
            hosts.add(a["id"])
            for key in ("hostname", "fqdn"):
                if isinstance(a.get("data"), dict) and a["data"].get(key):
                    hosts.add(str(a["data"][key]))
        for inv in ctx.store.all_inventories().values():
            hosts.add(inv.host.hostname)
            if inv.host.fqdn:
                hosts.add(inv.host.fqdn)
            for u in inv.users:
                if u.login_enabled or u.is_admin or u.uid >= 1000:
                    users.add(u.name)
        for ag in ctx.store.list_agents():
            hosts.add(ag["name"])
        for fw in ctx.store.list_firewalls():
            hosts.add(fw["name"])
            hosts.add(fw["id"])
    except Exception:   # redaction must never break the analyst
        pass
    r.add_hostnames(h for h in hosts if h)
    r.add_usernames(users - hosts)
    return r
