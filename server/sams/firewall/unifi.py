"""Ubiquiti UniFi Network adapter (legacy rulesets and zone-based firewall).

``UniFiClient.fetch()`` pulls the raw JSON from a UniFi OS console (UDM, UCG,
Cloud Key Gen2+, UniFi OS Server) or a legacy self-hosted controller.
``normalize_unifi(raw)`` turns it into a ``FirewallConfig``. It works equally on
offline JSON exports so analysis doesn't need live credentials.

Semantics modelled
------------------
Legacy (Network <= 8.x, or 9.x without migrating):
  * Rulesets ``LAN_IN`` / ``GUEST_IN`` / ``WAN_IN`` (+ ``*_LOCAL`` = traffic to
    the gateway itself, ``*_OUT`` = egress, ignored for reachability), ordered by
    ``rule_index``. ``LAN_IN`` applies to every non-guest internal network unless
    the rule names a source network.
  * Inter-VLAN traffic is **allowed by default**. Guest networks are blocked from
    RFC1918 destinations by built-in rules (except DNS/DHCP to the gateway).
    ``network_isolation_enabled`` blocks the network from/to other VLANs.
  * Rules that only match ``established``/``related``/``invalid`` states don't
    affect new connections. They are left out of ``rules`` and listed in
    ``settings["unifi_state_only_rules"]``.
Zone-based (Network 9.0+):
  * Zones (``internal``, ``external``, ``gateway``, ``vpn``, ``hotspot``, ``dmz``,
    custom) own networks. Policies match source zone (+ network/IP) to
    destination zone (+ network/IP/port) and are ordered by ``index``.
  * If the export contains no ``predefined`` policies, the default zone matrix
    is synthesised (see ``_zone_default``). It is an approximation of UniFi's
    shipped matrix, and custom zones are treated as "isolated, internet allowed".
"""
from __future__ import annotations

import ipaddress
from typing import Any, Optional

import httpx

from .common import RFC1918, infer_purpose, ip_version_of, is_ip, network_cidr
from .model import Action, Alias, FirewallConfig, Network, PortForward, PortRange, Rule

_LEGACY_ACTIONS: dict[str, Action] = {"accept": "allow", "drop": "block", "reject": "reject"}
_ZONE_ACTIONS: dict[str, Action] = {"ALLOW": "allow", "BLOCK": "block", "REJECT": "reject"}
_BUILTIN_ORDER = 30_000
_MATRIX_ORDER = 10_000_000


def _proto(p: Any) -> str:
    s = str(p or "all").lower()
    if s in ("all", "any", ""):
        return "any"
    return s.replace("tcp_udp", "tcp/udp")


def _ports(spec: Any) -> list[PortRange]:
    try:
        return PortRange.parse(spec if spec not in (None, "") else None)
    except ValueError:
        return [PortRange(start=0, end=0)]


def _subnet(ip_subnet: str) -> tuple[Optional[str], str]:
    """'192.168.1.1/24' -> ('192.168.1.0/24', '192.168.1.1')."""
    try:
        iface = ipaddress.ip_interface(ip_subnet)
    except ValueError:
        return None, ""
    return str(iface.network), str(iface.ip)


class _Normalizer:
    def __init__(self, raw: dict[str, Any], device_id: str):
        self.raw = raw
        self.cfg = FirewallConfig(device_id=device_id, vendor="unifi")
        self.net_by_id: dict[str, Network] = {}
        self.isolated: set[str] = set()
        self.port_groups: dict[str, list[PortRange]] = {}
        self.addr_groups: dict[str, str] = {}   # group id -> alias name
        self.state_only: list[str] = []

    # ------------------------------------------------------------------ #
    def groups(self) -> None:
        for g in self.raw.get("firewallgroup") or []:
            gid, gtype, name = g.get("_id", ""), g.get("group_type", ""), g.get("name") or g.get("_id", "")
            members = [str(m) for m in g.get("group_members") or []]
            if gtype == "port-group":
                ranges: list[PortRange] = []
                for m in members:
                    ranges.extend(_ports(m))
                self.port_groups[gid] = ranges
                self.cfg.aliases.append(Alias(name=name, type="port", entries=members))
            else:
                alias_name = name if name not in {a.name for a in self.cfg.aliases} else f"{name}-{gid[-6:]}"
                self.cfg.aliases.append(Alias(name=alias_name, type="network", entries=members))
                self.addr_groups[gid] = alias_name
        self.cfg.aliases.append(Alias(name="RFC1918", type="network", entries=list(RFC1918)))

    def networks(self) -> None:
        for n in self.raw.get("networkconf") or []:
            purpose = str(n.get("purpose", "")).lower()
            name = n.get("name") or n.get("_id", "")
            if purpose == "wan":
                ident = str(n.get("wan_networkgroup") or "WAN").lower()
                cidrs = []
                wan_ip = str(n.get("wan_ip") or "")
                if is_ip(wan_ip):
                    self.cfg.wan_addresses.append(wan_ip)
                    if n.get("wan_netmask"):
                        c = network_cidr(wan_ip, n["wan_netmask"])
                        if c:
                            cidrs.append(c)
                net = Network(name=name or "WAN", interface=ident, cidrs=cidrs,
                              gateway_ip=wan_ip if is_ip(wan_ip) else "", is_wan=True, purpose="wan")
            else:
                cidr, gw = _subnet(str(n.get("ip_subnet") or ""))
                if cidr is None:
                    continue   # vlan-only / L2 networks don't route through the gateway
                vendor_purpose = "guest" if purpose == "guest" else purpose
                net = Network(
                    name=name, interface=n.get("_id", name), cidrs=[cidr], gateway_ip=gw,
                    vlan=int(n["vlan"]) if n.get("vlan_enabled") and str(n.get("vlan", "")).isdigit() else None,
                    purpose="guest" if purpose == "guest" else infer_purpose(name, vendor_purpose),
                    dhcp=bool(n.get("dhcpd_enabled")),
                )
                if n.get("network_isolation_enabled"):
                    self.isolated.add(net.name)
            self.cfg.networks.append(net)
            if n.get("_id"):
                self.net_by_id[n["_id"]] = net
        if not any(n.is_wan for n in self.cfg.networks):
            self.cfg.networks.append(Network(name="WAN", interface="wan", is_wan=True, purpose="wan"))
        for h in self.raw.get("health") or []:
            if h.get("subsystem") == "wan" and is_ip(str(h.get("wan_ip") or "")):
                if h["wan_ip"] not in self.cfg.wan_addresses:
                    self.cfg.wan_addresses.append(h["wan_ip"])

    @property
    def internal(self) -> list[Network]:
        return [n for n in self.cfg.networks if not n.is_wan]

    @property
    def wans(self) -> list[Network]:
        return [n for n in self.cfg.networks if n.is_wan]

    # ------------------------------------------------------------------ #
    def settings(self) -> None:
        s: dict[str, Any] = {"webgui_protocol": "https", "webgui_port": 443, "antilockout": False,
                             "ssh_enabled": False, "ssh_port": 22, "upnp_enabled": False,
                             "upnp_interfaces": [], "remote_syslog": [], "log_default_block": False,
                             "version": str(self.raw.get("version", ""))}
        for st in self.raw.get("setting") or []:
            key = st.get("key")
            if key == "usg":
                s["upnp_enabled"] = bool(st.get("upnp_enabled"))
                if st.get("upnp_enabled"):
                    lan_ids = st.get("upnp_lan_network_ids") or st.get("upnp_network_ids") or []
                    s["upnp_interfaces"] = [self.net_by_id[i].name for i in lan_ids if i in self.net_by_id] or [
                        n.name for n in self.internal if n.purpose != "guest"]
            elif key == "mgmt":
                s["ssh_enabled"] = bool(st.get("x_ssh_enabled"))
            elif key in ("rsyslogd", "syslog") and st.get("enabled") and st.get("ip"):
                s["remote_syslog"].append(f"{st['ip']}:{st.get('port', 514)}")
        self.cfg.settings = s

    # ------------------------------------------------------------------ #
    def _endpoint(self, rule: dict, side: str) -> tuple[list[str], list[PortRange], str]:
        """Return (address specs, ports, network-name-if-scoped) for a legacy rule side."""
        ports: list[PortRange] = []
        addrs: list[str] = []
        scoped = ""
        net_id = rule.get(f"{side}_networkconf_id")
        if net_id and net_id in self.net_by_id:
            net = self.net_by_id[net_id]
            scoped = net.name
            if str(rule.get(f"{side}_networkconf_type", "NETv4")).upper().startswith("ADDR"):
                addrs.append(net.gateway_ip or net.name)
            else:
                addrs.append(net.name)
        if rule.get(f"{side}_address"):
            addrs.append(str(rule[f"{side}_address"]))
        for gid in rule.get(f"{side}_firewallgroup_ids") or []:
            if gid in self.port_groups:
                ports.extend(self.port_groups[gid])
            elif gid in self.addr_groups:
                addrs.append(self.addr_groups[gid])
        if rule.get(f"{side}_port"):
            ports.extend(_ports(rule[f"{side}_port"]))
        return addrs or ["any"], ports, scoped

    def legacy_rules(self) -> None:
        guests = [n for n in self.internal if n.purpose == "guest"]
        corp = [n for n in self.internal if n.purpose != "guest"]
        for r in self.raw.get("firewallrule") or []:
            ruleset = str(r.get("ruleset", "LAN_IN")).upper()
            action = _LEGACY_ACTIONS.get(str(r.get("action", "accept")).lower())
            if action is None:
                continue
            states = [r.get(k) for k in ("state_established", "state_related", "state_invalid")]
            if any(states) and not r.get("state_new"):
                self.state_only.append(r.get("name") or r.get("_id", ""))
                continue
            zone, _, direction = ruleset.partition("_")
            v6 = zone.endswith("V6")
            zone = zone.replace("V6", "")
            raw = dict(r)
            raw["ipprotocol"] = "inet6" if v6 else "inet"
            srcs, sports, src_scope = self._endpoint(r, "src")
            dsts, dports, _ = self._endpoint(r, "dst")
            if zone == "WAN":
                ingress = [n.name for n in self.wans]
            elif zone == "GUEST":
                ingress = [n.name for n in guests]
            else:
                ingress = [src_scope] if src_scope and src_scope in {n.name for n in corp} else [n.name for n in corp]
            if direction == "LOCAL" and dsts == ["any"]:
                dsts = ["(self)"]
            raw["chain"] = direction or "IN"
            dir_ = "out" if direction == "OUT" else "in"
            # *_LOCAL chains see only gateway-bound traffic and *_IN only forwarded
            # traffic. LOCAL rules sort first, and a built-in per-network LOCAL default
            # (below) catches the remaining gateway-bound traffic, so IN rules never see it.
            order = int(r.get("rule_index", 2000)) - (1_000_000 if direction == "LOCAL" else 0)
            base_id = r.get("_id") or r.get("name", "rule")
            multi = len(ingress) * len(srcs) * len(dsts) > 1
            for iface in ingress:
                for s in srcs:
                    for d in dsts:
                        self.cfg.rules.append(Rule(
                            id=f"{base_id}:{iface}" if multi else base_id,
                            order=order, enabled=bool(r.get("enabled", True)),
                            action=action, interface=iface, direction=dir_, protocol=_proto(r.get("protocol")),
                            ip_version=6 if v6 else 4,
                            source=s, source_ports=sports, destination=d, destination_ports=dports,
                            log=bool(r.get("logging")), description=r.get("name", ""), raw=raw,
                        ))
        # built-in LOCAL-chain defaults (gateway-bound traffic): corporate networks may
        # reach the gateway, guests only for DNS/DHCP, the internet not at all.
        local_order = -100_000
        for n in corp:
            self.cfg.rules.append(Rule(id=f"builtin:local:{n.name}", order=local_order, action="allow",
                                       interface=n.name, destination="(self)", description="Built-in: LAN_LOCAL default",
                                       raw={"builtin": True, "chain": "LOCAL"}))
        for g in guests:
            self.cfg.rules.append(Rule(id=f"builtin:guest-dns:{g.name}", order=local_order, action="allow",
                                       interface=g.name, protocol="tcp/udp", destination="(self)",
                                       destination_ports=[PortRange(start=53, end=53), PortRange(start=67, end=68)],
                                       description="Built-in: guest DNS/DHCP to gateway",
                                       raw={"builtin": True, "chain": "LOCAL"}))
            self.cfg.rules.append(Rule(id=f"builtin:guest-local:{g.name}", order=local_order + 1, action="block",
                                       interface=g.name, destination="(self)", description="Built-in: GUEST_LOCAL default",
                                       raw={"builtin": True, "chain": "LOCAL"}))
        for w in self.wans:
            self.cfg.rules.append(Rule(id=f"builtin:wan-local:{w.name}", order=local_order, action="block",
                                       interface=w.name, destination="(self)", description="Built-in: WAN_LOCAL default",
                                       raw={"builtin": True, "chain": "LOCAL"}))
        # built-ins: guest restrictions (forwarded traffic)
        for g in guests:
            self.cfg.rules.append(Rule(id=f"builtin:guest-isolation:{g.name}", order=_BUILTIN_ORDER, action="block",
                                       interface=g.name, destination="RFC1918",
                                       description="Built-in: guest to private networks", raw={"builtin": True}))
        self._isolation_rules()
        for n in self.internal:
            self.cfg.default_action[n.name] = "allow"
        for w in self.wans:
            self.cfg.default_action[w.name] = "block"
        self.cfg.default_action["*"] = "block"

    def _isolation_rules(self) -> None:
        for name in sorted(self.isolated):
            iso = self.cfg.network_by_name(name)
            if iso is None:
                continue
            for other in self.internal:
                if other.name == name:
                    continue
                for c in other.cidrs:
                    self.cfg.rules.append(Rule(
                        id=f"builtin:isolation:{name}->{other.name}", order=_BUILTIN_ORDER + 1, action="block",
                        interface=name, destination=c, description=f"Network isolation ({name})",
                        raw={"builtin": True}))
                for c in iso.cidrs:
                    self.cfg.rules.append(Rule(
                        id=f"builtin:isolation:{other.name}->{name}", order=_BUILTIN_ORDER + 1, action="block",
                        interface=other.name, destination=c, description=f"Network isolation ({name})",
                        raw={"builtin": True}))

    # ------------------------------------------------------------------ #
    # zone-based firewall
    # ------------------------------------------------------------------ #
    def zone_mode(self) -> bool:
        return bool(self.raw.get("zones")) or bool(self.raw.get("policies"))

    def _zone_key(self, z: dict) -> str:
        key = str(z.get("zone_key") or "").lower()
        return key or "custom"

    def zone_rules(self) -> None:
        zones = self.raw.get("zones") or []
        zone_by_id = {z.get("_id"): z for z in zones}
        net_zone: dict[str, dict] = {}
        for z in zones:
            for nid in z.get("network_ids") or []:
                if nid in self.net_by_id:
                    net = self.net_by_id[nid]
                    net.zone = z.get("name", "")
                    net_zone[net.name] = z
                    if self._zone_key(z) == "hotspot":
                        net.purpose = "guest"
                    elif self._zone_key(z) == "dmz":
                        net.purpose = "dmz"
        external = next((z for z in zones if self._zone_key(z) == "external"), None)
        for w in self.wans:
            if external:
                w.zone = external.get("name", "External")

        def zone_networks(z: dict) -> list[Network]:
            key = self._zone_key(z)
            if key == "external":
                return self.wans
            return [n for n in self.internal if net_zone.get(n.name) is z]

        def dest_specs(side: dict, z: Optional[dict]) -> tuple[list[str], bool]:
            target = str(side.get("matching_target", "ANY")).upper()
            if target == "IP":
                ips = [str(i) for i in side.get("ips") or []]
                return ips or ["any"], bool(side.get("match_opposite_ips"))
            if target == "NETWORK":
                names = [self.net_by_id[i].name for i in side.get("network_ids") or [] if i in self.net_by_id]
                return names or ["any"], False
            if z is None:
                return ["any"], False
            key = self._zone_key(z)
            if key == "external":
                return ["RFC1918"], True       # i.e. "not private" == the internet
            if key == "gateway":
                return ["(self)"], False
            alias = f"zone:{z.get('name', key)}"
            if not any(a.name == alias for a in self.cfg.aliases):
                self.cfg.aliases.append(Alias(name=alias, type="network",
                                              entries=[c for n in zone_networks(z) for c in n.cidrs]))
            return [alias], False

        def side_ports(side: dict) -> list[PortRange]:
            mt = str(side.get("port_matching_type", "ANY")).upper()
            if mt == "SPECIFIC":
                return _ports(side.get("port"))
            if mt == "OBJECT":
                return self.port_groups.get(side.get("port_group_id", ""), [PortRange(start=0, end=0)])
            return []

        has_predefined = False
        for p in self.raw.get("policies") or []:
            if p.get("predefined"):
                has_predefined = True
            action = _ZONE_ACTIONS.get(str(p.get("action", "ALLOW")).upper())
            if action is None:
                continue
            cstate = str(p.get("connection_state_type", "ALL")).upper()
            if cstate == "RESPOND_ONLY" or (cstate == "CUSTOM" and "NEW" not in [
                    str(x).upper() for x in p.get("connection_states") or []]):
                self.state_only.append(p.get("name") or p.get("_id", ""))
                continue
            src, dst = p.get("source") or {}, p.get("destination") or {}
            src_zone = zone_by_id.get(src.get("zone_id"))
            dst_zone = zone_by_id.get(dst.get("zone_id"))
            raw = dict(p)
            raw["ipprotocol"] = {"IPV4": "inet", "IPV6": "inet6"}.get(str(p.get("ip_version", "BOTH")).upper(), "inet46")
            src_target = str(src.get("matching_target", "ANY")).upper()
            if src_target == "NETWORK":
                ingress = [self.net_by_id[i] for i in src.get("network_ids") or [] if i in self.net_by_id]
                src_specs, src_not = ["any"], False
            else:
                ingress = zone_networks(src_zone) if src_zone else self.internal
                if src_target == "IP":
                    src_specs, src_not = [str(i) for i in src.get("ips") or []] or ["any"], bool(
                        src.get("match_opposite_ips"))
                else:
                    src_specs, src_not = ["any"], False
                    if src_target not in ("ANY", ""):
                        raw["_approximate_source"] = src_target   # CLIENT/MAC/REGION: zone-wide approximation
            dsts, dst_not = dest_specs(dst, dst_zone)
            dports = side_ports(dst)
            sports = side_ports(src)
            base_id = p.get("_id") or p.get("name", "policy")
            multi = len(ingress) * len(src_specs) * len(dsts) > 1
            for net in ingress:
                for s in src_specs:
                    for d in dsts:
                        self.cfg.rules.append(Rule(
                            id=f"{base_id}:{net.name}" if multi else base_id, order=int(p.get("index", 10000)),
                            enabled=bool(p.get("enabled", True)), action=action, interface=net.name,
                            protocol=_proto(p.get("protocol")), ip_version=ip_version_of(raw["ipprotocol"]),
                            source=s, source_not=src_not, source_ports=sports,
                            destination=d, destination_not=dst_not, destination_ports=dports,
                            log=bool(p.get("logging")), description=p.get("name", ""), raw=raw,
                        ))
        all_zones = list(zones) or []
        for net in self.cfg.networks:
            z = net_zone.get(net.name) if not net.is_wan else external
            skey = self._zone_key(z) if z else ("external" if net.is_wan else "internal")
            self.cfg.default_action[net.name] = _zone_default(skey, "external")
            if has_predefined or net.is_wan:
                continue
            for k, dz in enumerate(all_zones):
                dkey = self._zone_key(dz)
                if dkey == "external":
                    continue    # covered by default_action
                same = dz is z
                act = _zone_default(skey, dkey, same_zone=same)
                specs, neg = dest_specs({"matching_target": "ANY"}, dz)
                if skey == "hotspot" and dkey == "gateway":
                    # hotspot clients may use the gateway for DNS/DHCP (and the portal), nothing else
                    self.cfg.rules.append(Rule(
                        id=f"zone-default:{net.name}->{dz.get('name', dkey)}:dns", order=_MATRIX_ORDER + k,
                        action="allow", interface=net.name, protocol="tcp/udp", destination="(self)",
                        destination_ports=[PortRange(start=53, end=53), PortRange(start=67, end=68)],
                        description=f"Zone default: {z.get('name', skey) if z else skey} -> {dz.get('name', dkey)} DNS/DHCP",
                        raw={"builtin": True, "zone_default": True}))
                for spec in specs:
                    self.cfg.rules.append(Rule(
                        id=f"zone-default:{net.name}->{dz.get('name', dkey)}", order=_MATRIX_ORDER + k,
                        action=act, interface=net.name, destination=spec, destination_not=neg,
                        description=f"Zone default: {z.get('name', skey) if z else skey} -> {dz.get('name', dkey)}",
                        raw={"builtin": True, "zone_default": True},
                    ))
        self.cfg.default_action["*"] = "block"

    # ------------------------------------------------------------------ #
    def port_forwards(self) -> None:
        for idx, f in enumerate(self.raw.get("portforward") or []):
            fwd = str(f.get("fwd") or "")
            if not is_ip(fwd):
                continue
            src = str(f.get("src") or "any")
            if f.get("src_limiting_enabled") and f.get("src_firewall_group_id") in self.addr_groups:
                src = self.addr_groups[f["src_firewall_group_id"]]
            elif f.get("src_limiting_enabled") and f.get("src_limiting_type") == "ip" and f.get("src"):
                src = str(f["src"])
            ext = _ports(f.get("dst_port"))
            internal = str(f.get("fwd_port") or "")
            single = len(ext) == 1 and ext[0].start == ext[0].end
            iface = str(f.get("pfwd_interface") or "wan").lower()
            wan_names = [w.name for w in self.wans if iface in ("both", "all") or w.interface == iface] or [
                self.wans[0].name]
            for wn in wan_names:
                self.cfg.port_forwards.append(PortForward(
                    id=f.get("_id") or f"pf{idx}", enabled=bool(f.get("enabled", True)), interface=wn,
                    protocol=_proto(f.get("proto", "tcp_udp")), external_ports=ext, source=src,
                    external_address=str(f.get("destination_ip") or "any"), internal_ip=fwd,
                    internal_port=int(internal) if internal.isdigit() and (single or not ext) else None,
                    description=f.get("name", ""), raw=dict(f),
                ))


def _zone_default(src: str, dst: str, same_zone: bool = False) -> Action:
    """Approximation of UniFi's shipped zone matrix (Network 9.x)."""
    if src in ("internal", "vpn", "gateway"):
        return "allow"
    if src == "external":
        return "block"
    if src == "hotspot":
        return "allow" if dst == "external" or same_zone else "block"
    if src == "dmz":
        return "allow" if dst == "external" or same_zone else "block"
    # custom zones: internet + gateway allowed, isolated otherwise
    return "allow" if dst in ("external", "gateway") or same_zone else "block"


def normalize_unifi(raw: dict[str, Any], device_id: str = "") -> FirewallConfig:
    """Normalize raw UniFi JSON (see module docstring for the keys) into a FirewallConfig."""
    n = _Normalizer(raw, device_id)
    n.groups()
    n.networks()
    n.settings()
    if n.zone_mode():
        n.zone_rules()
        n.cfg.settings["firewall_mode"] = "zone"
    else:
        n.legacy_rules()
        n.cfg.settings["firewall_mode"] = "legacy"
    n.port_forwards()
    n.cfg.settings["unifi_state_only_rules"] = n.state_only
    n.cfg.settings["isolated_networks"] = sorted(n.isolated)
    n.cfg.hostname = str(raw.get("hostname", ""))
    return n.cfg


# --------------------------------------------------------------------------- #
class UniFiClient:
    """Read-only client for the UniFi Network application."""

    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 api_key: Optional[str] = None, site: str = "default", verify_tls: bool = False,
                 is_unifi_os: bool = True, transport: Optional[httpx.BaseTransport] = None,
                 device_id: str = "", timeout: float = 30.0):
        if not api_key and not (username and password):
            raise ValueError("UniFi needs either api_key or username+password")
        self.site = site
        self.device_id = device_id
        self.is_unifi_os = is_unifi_os
        self.username, self.password, self.api_key = username, password, api_key
        headers = {"Accept": "application/json"}
        if api_key:
            headers["X-API-KEY"] = api_key
        self._client = httpx.Client(base_url=base_url.rstrip("/"), verify=verify_tls, transport=transport,
                                    timeout=timeout, headers=headers)
        self.prefix = "/proxy/network" if is_unifi_os else ""

    def login(self) -> None:
        if self.api_key:
            return
        path = "/api/auth/login" if self.is_unifi_os else "/api/login"
        resp = self._client.post(path, json={"username": self.username, "password": self.password,
                                             "remember": False})
        if resp.status_code >= 400:
            raise PermissionError(f"UniFi login failed: HTTP {resp.status_code}")
        csrf = resp.headers.get("x-csrf-token") or resp.headers.get("x-updated-csrf-token")
        if csrf:
            self._client.headers["X-CSRF-Token"] = csrf
        token = resp.cookies.get("TOKEN") or resp.cookies.get("unifises")
        if token and not self._client.cookies.get("TOKEN") and not self._client.cookies.get("unifises"):
            self._client.cookies.set("TOKEN" if self.is_unifi_os else "unifises", token)

    def _get(self, path: str, optional: bool = False) -> list[dict]:
        resp = self._client.get(f"{self.prefix}/{path.lstrip('/')}")
        if resp.status_code in (401, 403) and not optional:
            raise PermissionError(f"UniFi API denied {path}: HTTP {resp.status_code}")
        if resp.status_code >= 400:
            if optional:
                return []
            resp.raise_for_status()
        upd = resp.headers.get("x-updated-csrf-token")
        if upd:
            self._client.headers["X-CSRF-Token"] = upd
        body = resp.json()
        if isinstance(body, dict):
            body = body.get("data", [])
        return body if isinstance(body, list) else []

    def fetch_raw(self) -> dict[str, Any]:
        s = self.site
        raw: dict[str, Any] = {}
        try:
            self.login()
            raw["networkconf"] = self._get(f"api/s/{s}/rest/networkconf")
            raw["firewallrule"] = self._get(f"api/s/{s}/rest/firewallrule", optional=True)
            raw["firewallgroup"] = self._get(f"api/s/{s}/rest/firewallgroup", optional=True)
            raw["portforward"] = self._get(f"api/s/{s}/rest/portforward", optional=True)
            raw["setting"] = self._get(f"api/s/{s}/rest/setting", optional=True)
            raw["health"] = self._get(f"api/s/{s}/stat/health", optional=True)
            zones = self._get(f"v2/api/site/{s}/firewall/zone", optional=True) or \
                self._get(f"v2/api/site/{s}/firewall/zones", optional=True)
            raw["zones"] = zones
            raw["policies"] = self._get(f"v2/api/site/{s}/firewall-policies", optional=True) if zones else []
        finally:
            self._client.close()
        return raw

    def fetch(self) -> FirewallConfig:
        return normalize_unifi(self.fetch_raw(), device_id=self.device_id)
