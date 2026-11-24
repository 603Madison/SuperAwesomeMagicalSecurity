"""pfSense / OPNsense ``config.xml`` parser.

Both products share the m0n0wall-derived config format, so one parser handles
both. OPNsense additions handled here: MVC aliases
(``OPNsense/Firewall/Alias``), "automation" filter rules
(``OPNsense/Firewall/Filter/rules``) and MVC syslog destinations.

Normalization notes
-------------------
* Network ``name`` is the interface description ("LAN", "IoT"); ``interface`` is
  the logical id (``lan``, ``wan``, ``opt1``). Rules keep the logical id, and
  ``FirewallConfig.network_by_name`` resolves either.
* Floating ``quick`` rules and OPNsense automation rules are evaluated before
  interface rules. Non-quick floating rules only apply when no interface rule
  matched, so they get a very high ``order``. Floating rules that list several
  interfaces become one ``Rule`` per interface.
* Port aliases are resolved at parse time (nested aliases too). A port alias that
  can't be resolved (URL tables) becomes port 0, which never matches. That is
  conservative and avoids false "any port" findings; it is recorded in ``raw``.
* The implicit anti-lockout rule (LAN -> LAN address on the webGUI/SSH ports)
  is materialised as a builtin rule unless ``noantilockout`` is set.
"""
from __future__ import annotations

import re
from typing import Optional
from xml.etree import ElementTree as ET

from .common import elem_to_dict, flag, infer_purpose, ip_version_of, is_ip, network_cidr, safe_xml_fromstring, text
from .model import Action, Alias, FirewallConfig, Network, PortForward, PortRange, Rule

_ACTIONS: dict[str, Action] = {"pass": "allow", "block": "block", "reject": "reject"}
_PORT_RX = re.compile(r"^\s*\d+(\s*[-:]\s*\d+)?(\s*,\s*\d+(\s*[-:]\s*\d+)?)*\s*$")


def detect_vendor(root: ET.Element) -> str:
    return "opnsense" if root.tag.lower() == "opnsense" else "pfsense"


def parse_any_config(xml_text: str | bytes, device_id: str = "") -> FirewallConfig:
    """Parse a pfSense or OPNsense backup, auto-detecting which from the root tag."""
    root = safe_xml_fromstring(xml_text)
    return _parse_root(root, detect_vendor(root), device_id)


def parse_config_xml(xml_text: str | bytes, vendor: str = "pfsense", device_id: str = "") -> FirewallConfig:
    root = safe_xml_fromstring(xml_text)
    return _parse_root(root, vendor, device_id)


# --------------------------------------------------------------------------- #
class _Ctx:
    def __init__(self, aliases: list[Alias]):
        self.aliases = {a.name: a for a in aliases}

    def resolve_ports(self, spec: str, raw: dict, _depth: int = 0) -> list[PortRange]:
        spec = (spec or "").strip()
        if not spec or spec.lower() == "any":
            return []
        if _PORT_RX.match(spec):
            return PortRange.parse(spec.replace(" ", ""))
        if _depth > 8:
            raw["_unresolved_port"] = spec
            return [PortRange(start=0, end=0)]
        alias = self.aliases.get(spec)
        if alias is None or alias.type not in ("port", "url_ports", "urltable_ports"):
            raw["_unresolved_port"] = spec
            return [PortRange(start=0, end=0)]
        out: list[PortRange] = []
        for entry in alias.entries:
            out.extend(self.resolve_ports(entry, raw, _depth + 1))
        if not out:
            raw["_unresolved_port"] = spec
            return [PortRange(start=0, end=0)]
        return out


def _norm_network_token(tok: str) -> str:
    """pfSense <network> tokens: lan, lanip, wanip, opt1, opt1ip, (self)."""
    return (tok or "").strip()


def _parse_endpoint(el: Optional[ET.Element], ctx: _Ctx, raw: dict) -> tuple[str, bool, list[PortRange]]:
    if el is None:
        return "any", False, []
    negate = el.find("not") is not None
    if el.find("any") is not None:
        addr = "any"
    elif el.find("network") is not None:
        addr = _norm_network_token(text(el, "network")) or "any"
    elif el.find("address") is not None:
        addr = text(el, "address") or "any"
    else:
        addr = "any"
    ports = ctx.resolve_ports(text(el, "port"), raw)
    return addr, negate, ports


def _aliases(root: ET.Element) -> list[Alias]:
    out: list[Alias] = []
    for a in root.findall("./aliases/alias"):
        name = text(a, "name")
        if not name:
            continue
        entries = [e for e in re.split(r"\s+", text(a, "address")) if e]
        out.append(Alias(name=name, type=text(a, "type", "host"), entries=entries))
    # OPNsense MVC aliases
    for a in root.findall("./OPNsense/Firewall/Alias/aliases/alias"):
        if text(a, "enabled", "1") == "0":
            continue
        name = text(a, "name")
        if not name:
            continue
        content = text(a, "content")
        entries = [e for e in re.split(r"[\s,]+", content) if e]
        out.append(Alias(name=name, type=text(a, "type", "host"), entries=entries))
    return out


def _networks(root: ET.Element) -> tuple[list[Network], list[str]]:
    vlans = {}
    for v in root.findall("./vlans/vlan"):
        try:
            vlans[text(v, "vlanif")] = int(text(v, "tag"))
        except ValueError:
            pass
    dhcpd = root.find("dhcpd")
    dhcp = {c.tag for c in (list(dhcpd) if dhcpd is not None else []) if c.find("enable") is not None}
    nets: list[Network] = []
    wan_addrs: list[str] = []
    ifaces = root.find("interfaces")
    if ifaces is None:
        return nets, wan_addrs
    for iface in ifaces:
        ident = iface.tag
        enabled = iface.find("enable") is not None and text(iface, "enable", "1") != "0"
        if not enabled and ident not in ("wan", "lan"):
            continue
        descr = text(iface, "descr") or ident.upper()
        is_wan = ident == "wan" or descr.lower().startswith("wan")
        ip = text(iface, "ipaddr")
        prefix = text(iface, "subnet")
        cidrs: list[str] = []
        gw = ""
        if is_ip(ip) and prefix:
            c = network_cidr(ip, prefix)
            if c:
                cidrs.append(c)
            gw = ip
        ip6 = text(iface, "ipaddrv6")
        prefix6 = text(iface, "subnetv6")
        if is_ip(ip6) and prefix6:
            c6 = network_cidr(ip6, prefix6)
            if c6:
                cidrs.append(c6)
        if is_wan:
            for a in (ip, ip6):
                if is_ip(a):
                    wan_addrs.append(a)
        phys = text(iface, "if")
        nets.append(Network(
            name=descr, interface=ident, cidrs=cidrs, gateway_ip=gw, vlan=vlans.get(phys),
            is_wan=is_wan, purpose="wan" if is_wan else infer_purpose(descr), dhcp=ident in dhcp,
        ))
    return nets, wan_addrs


def _legacy_rule(el: ET.Element, idx: int, ctx: _Ctx) -> list[Rule]:
    rtype = text(el, "type", "pass").lower()
    if rtype not in _ACTIONS:   # "match" rules (floating, traffic shaping) don't filter
        return []
    raw = elem_to_dict(el) or {}
    if not isinstance(raw, dict):
        raw = {}
    src, src_not, src_ports = _parse_endpoint(el.find("source"), ctx, raw)
    dst, dst_not, dst_ports = _parse_endpoint(el.find("destination"), ctx, raw)
    floating = text(el, "floating").lower() == "yes"
    quick = flag(el, "quick")
    direction = text(el, "direction", "in" if not floating else "any") or "in"
    if floating:
        order = (-1_000_000 + idx) if quick else (1_000_000 + idx)
    else:
        order = idx
    ifaces = [i.strip() for i in text(el, "interface").split(",") if i.strip()] or [""]
    rid = text(el, "tracker") or text(el, "id") or f"rule{idx}"
    raw["ipprotocol"] = text(el, "ipprotocol", "inet")
    rules = []
    for n, iface in enumerate(ifaces):
        rules.append(Rule(
            id=rid if len(ifaces) == 1 else f"{rid}:{iface}",
            order=order, enabled=el.find("disabled") is None, action=_ACTIONS[rtype], interface=iface,
            direction=direction, protocol=(text(el, "protocol") or "any").lower(),
            ip_version=ip_version_of(raw["ipprotocol"]),
            source=src, source_not=src_not, source_ports=src_ports,
            destination=dst, destination_not=dst_not, destination_ports=dst_ports,
            log=el.find("log") is not None, description=text(el, "descr"), raw=raw,
        ))
    return rules


def _opnsense_mvc_rule(el: ET.Element, idx: int, ctx: _Ctx) -> list[Rule]:
    action = text(el, "action", "pass").lower()
    if action not in _ACTIONS:
        return []
    raw = elem_to_dict(el) or {}
    if not isinstance(raw, dict):
        raw = {}
    raw["ipprotocol"] = text(el, "ipprotocol", "inet")
    try:
        seq = int(text(el, "sequence", str(idx)))
    except ValueError:
        seq = idx
    quick = text(el, "quick", "1") != "0"
    order = (-500_000 + seq) if quick else (900_000 + seq)
    ifaces = [i.strip() for i in text(el, "interface").split(",") if i.strip()] or [""]
    rid = el.get("uuid") or f"mvc{idx}"
    proto = (text(el, "protocol") or "any").lower()
    rules = []
    for iface in ifaces:
        rules.append(Rule(
            id=rid if len(ifaces) == 1 else f"{rid}:{iface}", order=order,
            enabled=text(el, "enabled", "1") != "0", action=_ACTIONS[action], interface=iface,
            direction=text(el, "direction", "in") or "in", protocol=proto, ip_version=ip_version_of(raw["ipprotocol"]),
            source=text(el, "source_net", "any") or "any", source_not=text(el, "source_not") == "1",
            source_ports=ctx.resolve_ports(text(el, "source_port"), raw),
            destination=text(el, "destination_net", "any") or "any",
            destination_not=text(el, "destination_not") == "1",
            destination_ports=ctx.resolve_ports(text(el, "destination_port"), raw),
            log=text(el, "log") == "1", description=text(el, "description"), raw=raw,
        ))
    return rules


def _port_forwards(root: ET.Element, cfg: FirewallConfig, ctx: _Ctx) -> list[PortForward]:
    out: list[PortForward] = []
    for idx, el in enumerate(root.findall("./nat/rule")):
        raw = elem_to_dict(el) or {}
        if not isinstance(raw, dict):
            raw = {}
        iface_id = text(el, "interface", "wan")
        net = cfg.network_by_name(iface_id)
        iface_name = net.name if net else iface_id
        target = text(el, "target")
        targets = [target] if is_ip(target) else (
            [e for e in (cfg._alias(target).entries if cfg._alias(target) else []) if is_ip(e)])
        if not targets:
            continue
        dst_el = el.find("destination")
        ext_ports = ctx.resolve_ports(text(dst_el, "port") if dst_el is not None else "", raw)
        src_addr, src_not, _ = _parse_endpoint(el.find("source"), ctx, raw)
        local = text(el, "local-port")
        internal_port: Optional[int] = None
        single_ext = len(ext_ports) == 1 and ext_ports[0].start == ext_ports[0].end
        if local.isdigit() and (single_ext or not ext_ports):
            internal_port = int(local)
        elif not local and single_ext:
            internal_port = ext_ports[0].start
        ext_addr, _, _ = _parse_endpoint(dst_el, ctx, raw)
        for t in targets:
            out.append(PortForward(
                id=f"nat{idx}" + (f":{t}" if len(targets) > 1 else ""),
                enabled=el.find("disabled") is None, interface=iface_name,
                protocol=(text(el, "protocol") or "tcp").lower(), external_address=ext_addr,
                external_ports=ext_ports, source=("!" + src_addr) if src_not else src_addr,
                internal_ip=t, internal_port=internal_port, description=text(el, "descr"), raw=raw,
            ))
    # 1:1 NAT exposes every port of the internal host
    for idx, el in enumerate(root.findall("./nat/onetoone")):
        raw = elem_to_dict(el) or {}
        internal = text(el.find("source") if el.find("source") is not None else None, "address")
        if not is_ip(internal.split("/")[0] if internal else ""):
            continue
        iface_id = text(el, "interface", "wan")
        net = cfg.network_by_name(iface_id)
        out.append(PortForward(
            id=f"1to1-{idx}", enabled=el.find("disabled") is None, interface=net.name if net else iface_id,
            protocol="any", external_address=text(el, "external") or "any", external_ports=[],
            source="any", internal_ip=internal.split("/")[0], internal_port=None,
            description=text(el, "descr") or "1:1 NAT", raw=raw if isinstance(raw, dict) else {},
        ))
    return out


def _settings(root: ET.Element, vendor: str) -> dict:
    s: dict = {}
    webgui = root.find("./system/webgui")
    proto = text(webgui, "protocol", "https") or "https"
    port = text(webgui, "port")
    s["webgui_protocol"] = proto
    s["webgui_port"] = int(port) if port.isdigit() else (443 if proto == "https" else 80)
    nal = webgui.find("noantilockout") if webgui is not None else None
    s["antilockout"] = not (nal is not None and (nal.text or "").strip() != "0")
    ssh = root.find("./system/ssh")
    ssh_on = False
    if ssh is not None:
        ssh_on = text(ssh, "enable").lower() in ("enabled", "yes", "1") or text(ssh, "enabled").lower() in ("enabled", "1", "yes")
    s["ssh_enabled"] = ssh_on
    sp = text(ssh, "port")
    s["ssh_port"] = int(sp) if sp.isdigit() else 22
    # UPnP: pfSense/OPNsense miniupnpd package
    upnp_on, upnp_ifaces = False, []
    for el in root.iter():
        if el.tag in ("miniupnpd", "upnp"):
            cfg_el = el.find("config") if el.find("config") is not None else el
            en = cfg_el.find("enable")
            if en is not None and (en.text or "on").strip().lower() in ("on", "yes", "1", "", "true"):
                upnp_on = True
                upnp_ifaces = [i for i in re.split(r"[,\s]+", text(cfg_el, "iface_array")) if i]
                break
    s["upnp_enabled"] = upnp_on
    s["upnp_interfaces"] = upnp_ifaces
    # remote syslog
    servers: list[str] = []
    syslog = root.find("syslog")
    if syslog is not None and (syslog.find("enable") is not None or syslog.find("remoteserver") is not None):
        if syslog.find("enable") is None or text(syslog, "enable", "1") != "0":
            for tag in ("remoteserver", "remoteserver2", "remoteserver3"):
                v = text(syslog, tag)
                if v:
                    servers.append(v)
    for d in root.findall("./OPNsense/Syslog/destinations/destination"):
        if text(d, "enabled", "1") == "1" and text(d, "hostname"):
            servers.append(f"{text(d, 'hostname')}:{text(d, 'port', '514')}")
    s["remote_syslog"] = servers
    s["log_default_block"] = not (syslog is not None and syslog.find("nologdefaultblock") is not None)
    s["version"] = text(root, "version")
    s["hostname"] = text(root, "./system/hostname")
    s["domain"] = text(root, "./system/domain")
    return s


def _parse_root(root: ET.Element, vendor: str, device_id: str) -> FirewallConfig:
    aliases = _aliases(root)
    ctx = _Ctx(aliases)
    networks, wan_addrs = _networks(root)
    settings = _settings(root, vendor)
    cfg = FirewallConfig(
        device_id=device_id, vendor=vendor, hostname=settings.get("hostname", ""),
        version=settings.get("version", ""), networks=networks, aliases=aliases,
        default_action={"*": "block"}, wan_addresses=wan_addrs, settings=settings,
    )
    rules: list[Rule] = []
    for idx, el in enumerate(root.findall("./filter/rule")):
        rules.extend(_legacy_rule(el, idx, ctx))
    for idx, el in enumerate(root.findall("./OPNsense/Firewall/Filter/rules/rule")):
        rules.extend(_opnsense_mvc_rule(el, idx, ctx))
    lan = cfg.network_by_name("lan")
    if settings["antilockout"] and lan is not None:
        ports = [PortRange(start=settings["webgui_port"], end=settings["webgui_port"])]
        if settings["webgui_protocol"] == "https" and settings["webgui_port"] != 80:
            ports.append(PortRange(start=80, end=80))   # http->https redirect listener
        if settings["ssh_enabled"]:
            ports.append(PortRange(start=settings["ssh_port"], end=settings["ssh_port"]))
        rules.append(Rule(
            id="anti-lockout", order=-2_000_000, action="allow", interface="lan", protocol="tcp",
            source="any", destination="lanip", destination_ports=ports,
            description="Anti-Lockout Rule", raw={"builtin": True, "ipprotocol": "inet46"},
        ))
    cfg.rules = rules
    cfg.port_forwards = _port_forwards(root, cfg, ctx)
    return cfg

