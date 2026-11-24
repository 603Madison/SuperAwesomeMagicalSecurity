"""Live API clients for pfSense (REST API package v2) and OPNsense.

* pfSense: the community ``pfSense-pkg-RESTAPI`` v2 (``/api/v2/...``,
  ``X-API-Key`` header). Responses are wrapped as ``{"code", "status", "data"}``.
* OPNsense: rather than stitching many MVC endpoints together, download the
  full config backup (``/api/core/backup/download/this``, HTTP basic auth with
  the API key/secret) and parse it with the config.xml parser. This sees legacy
  *and* automation rules exactly as the firewall does.

Both clients take an optional ``transport`` (``httpx.MockTransport`` in tests).
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from .common import infer_purpose, ip_version_of, is_ip, network_cidr
from .model import Alias, FirewallConfig, Network, PortForward, PortRange, Rule
from .pfsense import parse_config_xml

_ACTIONS = {"pass": "allow", "block": "block", "reject": "reject"}


def _data(resp: httpx.Response) -> Any:
    resp.raise_for_status()
    body = resp.json()
    if isinstance(body, dict) and "data" in body:
        return body["data"]
    return body


def _norm_addr(value: Any) -> tuple[str, bool]:
    """pfrest v2 address strings: "any", "lan", "lan:ip", "(self)", "!10.0.0.0/8", alias names."""
    if value is None or value == "":
        return "any", False
    s = str(value).strip()
    neg = s.startswith("!")
    if neg:
        s = s[1:]
    if s.endswith(":ip"):
        s = s[:-3] + "ip"
    return s, neg


def _ports(value: Any, aliases: dict[str, Alias], raw: dict) -> list[PortRange]:
    if value in (None, "", "any"):
        return []
    s = str(value).strip()
    try:
        return PortRange.parse(s)
    except ValueError:
        alias = aliases.get(s)
        if alias and alias.type == "port":
            out: list[PortRange] = []
            for e in alias.entries:
                try:
                    out.extend(PortRange.parse(e))
                except ValueError:
                    pass
            if out:
                return out
        raw["_unresolved_port"] = s
        return [PortRange(start=0, end=0)]


def normalize_pfrest(interfaces: list[dict], rules: list[dict], port_forwards: list[dict],
                     aliases: list[dict], settings: Optional[dict] = None, device_id: str = "") -> FirewallConfig:
    """Normalize pfSense REST API v2 JSON objects into a FirewallConfig."""
    alias_objs = [Alias(name=a.get("name", ""), type=a.get("type", "host"),
                        entries=[str(e) for e in (a.get("address") or [])]) for a in aliases if a.get("name")]
    amap = {a.name: a for a in alias_objs}
    nets: list[Network] = []
    wan_addrs: list[str] = []
    for i in interfaces:
        ident = str(i.get("id") or i.get("if") or "")
        if not i.get("enable", True) and ident not in ("wan", "lan"):
            continue
        descr = i.get("descr") or ident.upper()
        is_wan = ident == "wan"
        ip = str(i.get("ipaddr") or "")
        cidrs, gw = [], ""
        if is_ip(ip) and i.get("subnet") not in (None, ""):
            c = network_cidr(ip, i["subnet"])
            if c:
                cidrs.append(c)
            gw = ip
            if is_wan:
                wan_addrs.append(ip)
        ip6 = str(i.get("ipaddrv6") or "")
        if is_ip(ip6) and i.get("subnetv6") not in (None, ""):
            c6 = network_cidr(ip6, i["subnetv6"])
            if c6:
                cidrs.append(c6)
            if is_wan:
                wan_addrs.append(ip6)
        nets.append(Network(name=descr, interface=ident, cidrs=cidrs, gateway_ip=gw, is_wan=is_wan,
                            purpose="wan" if is_wan else infer_purpose(descr)))
    out_rules: list[Rule] = []
    for idx, r in enumerate(rules):
        rtype = str(r.get("type", "pass")).lower()
        if rtype not in _ACTIONS:
            continue
        raw = dict(r)
        raw["ipprotocol"] = r.get("ipprotocol") or "inet"
        src, src_not = _norm_addr(r.get("source"))
        dst, dst_not = _norm_addr(r.get("destination"))
        ifaces = r.get("interface") or [""]
        if isinstance(ifaces, str):
            ifaces = [x for x in ifaces.split(",") if x]
        floating = bool(r.get("floating"))
        quick = bool(r.get("quick"))
        order = ((-1_000_000 if quick else 1_000_000) + idx) if floating else idx
        rid = str(r.get("tracker") or r.get("id", idx))
        for iface in ifaces:
            out_rules.append(Rule(
                id=rid if len(ifaces) == 1 else f"{rid}:{iface}", order=order,
                enabled=not r.get("disabled", False), action=_ACTIONS[rtype], interface=iface,
                direction=r.get("direction") or ("any" if floating else "in"),
                protocol=str(r.get("protocol") or "any").lower(), ip_version=ip_version_of(raw["ipprotocol"]),
                source=src, source_not=src_not, source_ports=_ports(r.get("source_port"), amap, raw),
                destination=dst, destination_not=dst_not,
                destination_ports=_ports(r.get("destination_port"), amap, raw),
                log=bool(r.get("log")), description=r.get("descr") or "", raw=raw,
            ))
    cfg = FirewallConfig(device_id=device_id, vendor="pfsense", networks=nets, aliases=alias_objs,
                         rules=out_rules, default_action={"*": "block"}, wan_addresses=wan_addrs,
                         settings=dict(settings or {}))
    fwds: list[PortForward] = []
    for idx, f in enumerate(port_forwards):
        target = str(f.get("target") or "")
        if not is_ip(target):
            alias = amap.get(target)
            targets = [e for e in (alias.entries if alias else []) if is_ip(e)]
        else:
            targets = [target]
        raw = dict(f)
        ext = _ports(f.get("destination_port"), amap, raw)
        local = str(f.get("local_port") or "")
        single = len(ext) == 1 and ext[0].start == ext[0].end
        internal_port = int(local) if local.isdigit() and (single or not ext) else (
            ext[0].start if (not local and single) else None)
        net = cfg.network_by_name(str(f.get("interface") or "wan"))
        src, src_not = _norm_addr(f.get("source"))
        dst, _ = _norm_addr(f.get("destination"))
        for t in targets:
            fwds.append(PortForward(
                id=str(f.get("id", idx)), enabled=not f.get("disabled", False),
                interface=net.name if net else str(f.get("interface") or "WAN"),
                protocol=str(f.get("protocol") or "tcp").lower(), external_address=dst,
                external_ports=ext, source=("!" + src) if src_not else src, internal_ip=t,
                internal_port=internal_port, description=f.get("descr") or "", raw=raw,
            ))
    cfg.port_forwards = fwds
    s = cfg.settings
    s.setdefault("webgui_protocol", "https")
    s.setdefault("webgui_port", 443 if s["webgui_protocol"] == "https" else 80)
    s.setdefault("antilockout", True)
    s.setdefault("ssh_enabled", False)
    s.setdefault("ssh_port", 22)
    s.setdefault("upnp_enabled", False)
    s.setdefault("upnp_interfaces", [])
    s.setdefault("remote_syslog", [])
    s.setdefault("log_default_block", True)
    s.setdefault("version", "")
    lan = cfg.network_by_name("lan")
    if s["antilockout"] and lan is not None:
        ports = [PortRange(start=int(s["webgui_port"]), end=int(s["webgui_port"]))]
        if s["ssh_enabled"]:
            ports.append(PortRange(start=int(s["ssh_port"]), end=int(s["ssh_port"])))
        cfg.rules.append(Rule(id="anti-lockout", order=-2_000_000, action="allow", interface="lan",
                              protocol="tcp", destination="lanip", destination_ports=ports,
                              description="Anti-Lockout Rule", raw={"builtin": True, "ipprotocol": "inet46"}))
    return cfg


class PfSenseAPIClient:
    """pfSense REST API v2 (pfSense-pkg-RESTAPI)."""

    def __init__(self, base_url: str, api_key: str, verify_tls: bool = True,
                 transport: Optional[httpx.BaseTransport] = None, device_id: str = "", timeout: float = 30.0):
        self.device_id = device_id
        self._client = httpx.Client(base_url=base_url.rstrip("/"), verify=verify_tls, transport=transport,
                                    timeout=timeout, headers={"X-API-Key": api_key, "Accept": "application/json"})

    def _get(self, path: str, optional: bool = False) -> Any:
        resp = self._client.get(path, params={"limit": 0} if not optional else None)
        if optional and resp.status_code >= 400:
            return None
        return _data(resp)

    def fetch(self) -> FirewallConfig:
        try:
            interfaces = self._get("/api/v2/interfaces") or []
            rules = self._get("/api/v2/firewall/rules") or []
            fwds = self._get("/api/v2/firewall/nat/port_forwards") or []
            aliases = self._get("/api/v2/firewall/aliases") or []
            settings: dict[str, Any] = {}
            webgui = self._get("/api/v2/system/webgui/settings", optional=True)
            if isinstance(webgui, dict):
                settings["webgui_protocol"] = webgui.get("protocol", "https")
                if str(webgui.get("port") or "").isdigit():
                    settings["webgui_port"] = int(webgui["port"])
                if "noantilockout" in webgui:
                    settings["antilockout"] = not bool(webgui.get("noantilockout"))
            ssh = self._get("/api/v2/services/ssh", optional=True)
            if isinstance(ssh, dict):
                settings["ssh_enabled"] = bool(ssh.get("enable"))
                if str(ssh.get("port") or "").isdigit():
                    settings["ssh_port"] = int(ssh["port"])
            syslog = self._get("/api/v2/status/logs/settings", optional=True)
            if isinstance(syslog, dict):
                servers = [syslog.get(k) for k in ("remoteserver", "remoteserver2", "remoteserver3")
                           if syslog.get(k)]
                settings["remote_syslog"] = servers if syslog.get("enableremotelogging", bool(servers)) else []
                settings["log_default_block"] = not bool(syslog.get("nologdefaultblock"))
            version = self._get("/api/v2/status/system", optional=True)
            if isinstance(version, dict):
                settings["version"] = version.get("system_version", {}).get("version", "") if isinstance(
                    version.get("system_version"), dict) else str(version.get("system_version", ""))
        finally:
            self._client.close()
        return normalize_pfrest(interfaces, rules, fwds, aliases, settings, device_id=self.device_id)


class OPNsenseAPIClient:
    """OPNsense: download the running config backup and parse it."""

    def __init__(self, base_url: str, key: str, secret: str, verify_tls: bool = True,
                 transport: Optional[httpx.BaseTransport] = None, device_id: str = "", timeout: float = 30.0):
        self.device_id = device_id
        self._client = httpx.Client(base_url=base_url.rstrip("/"), verify=verify_tls, transport=transport,
                                    timeout=timeout, auth=(key, secret))

    def fetch(self) -> FirewallConfig:
        try:
            resp = self._client.get("/api/core/backup/download/this")
            resp.raise_for_status()
        finally:
            self._client.close()
        return parse_config_xml(resp.content, vendor="opnsense", device_id=self.device_id)
