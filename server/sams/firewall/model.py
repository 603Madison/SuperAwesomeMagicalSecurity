"""Vendor-neutral firewall model.

Every adapter (pfSense, OPNsense, UniFi, ...) normalizes into ``FirewallConfig``.
The analyzer inspects it for weaknesses, and the attack graph calls
``FirewallConfig.evaluate()`` to decide whether traffic between two IPs is
permitted.

Semantics
---------
* ``networks`` are named segments ("LAN", "IoT", "WAN") with CIDRs.
* ``rules`` are evaluated per *ingress interface/zone* in ``order``; first match
  wins (pfSense/OPNsense/UniFi zone policies all behave this way after
  normalization). Rules with ``enabled=False`` are ignored by ``evaluate``.
* ``default_action`` per interface applies when nothing matches. pfSense: block
  on all interfaces except the ones with an explicit "allow LAN to any" rule
  (that is just a rule). UniFi legacy: inter-VLAN *allowed* by default.
* ``port_forwards`` (DNAT) expose internal hosts on WAN addresses.
* Addresses in rules: ``"any"``, a CIDR/IP, a network name ("LAN" == that
  network's CIDRs, "LAN address" == the firewall's own IP on it), or an alias
  name resolved via ``aliases``.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Action = Literal["allow", "block", "reject"]


class PortRange(BaseModel):
    start: int
    end: int

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end

    @classmethod
    def parse(cls, spec: str | int | None) -> list["PortRange"]:
        """Parse "22", "80,443", "1000-2000", "1000:2000", "any"/None -> list (empty = any)."""
        if spec is None:
            return []
        s = str(spec).strip().lower()
        if s in ("", "any", "*"):
            return []
        out = []
        for part in s.replace(" ", "").split(","):
            if not part:
                continue
            for sep in ("-", ":"):
                if sep in part:
                    a, b = part.split(sep, 1)
                    out.append(cls(start=int(a), end=int(b)))
                    break
            else:
                out.append(cls(start=int(part), end=int(part)))
        return out


class Network(BaseModel):
    name: str                       # "LAN", "IoT", "WAN", "DMZ"
    interface: str = ""             # vendor interface id (em1, lan, opt1, br20, zone id)
    cidrs: list[str] = Field(default_factory=list)
    gateway_ip: str = ""            # firewall's own address on this network
    vlan: Optional[int] = None
    zone: str = ""                  # zone name for zone-based firewalls
    is_wan: bool = False
    purpose: str = ""               # corporate | guest | iot | wan | vpn | dmz | mgmt
    dhcp: bool = False
    isolation: Optional[bool] = None   # UniFi "network isolation" / guest isolation


class Alias(BaseModel):
    name: str
    type: str = "host"              # host | network | port | url
    entries: list[str] = Field(default_factory=list)


class Rule(BaseModel):
    id: str = ""
    order: int = 0
    enabled: bool = True
    action: Action = "allow"
    interface: str = ""             # network name the rule is evaluated on (ingress), "" = floating/any
    direction: str = "in"           # in | out | any
    protocol: str = "any"           # any | tcp | udp | tcp/udp | icmp | ...
    source: str = "any"
    source_not: bool = False
    source_ports: list[PortRange] = Field(default_factory=list)
    destination: str = "any"
    destination_not: bool = False
    destination_ports: list[PortRange] = Field(default_factory=list)
    log: bool = False
    description: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)   # original vendor object for evidence

    def label(self) -> str:
        return self.description or self.id or f"rule#{self.order}"


class PortForward(BaseModel):
    id: str = ""
    enabled: bool = True
    interface: str = "WAN"
    protocol: str = "tcp"
    external_address: str = "any"     # WAN address / "any"
    external_ports: list[PortRange] = Field(default_factory=list)
    source: str = "any"               # restricted source, if any
    internal_ip: str
    internal_port: Optional[int] = None
    description: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    allowed: bool
    rule: Optional[str] = None        # label of matching rule, or "default"
    interface: str = ""
    confident: bool = True            # False when the model had to guess (unknown networks)


class FirewallConfig(BaseModel):
    device_id: str = ""
    vendor: str = ""                  # pfsense | opnsense | unifi | generic
    hostname: str = ""
    version: str = ""
    networks: list[Network] = Field(default_factory=list)
    aliases: list[Alias] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)
    port_forwards: list[PortForward] = Field(default_factory=list)
    default_action: dict[str, Action] = Field(default_factory=dict)  # per network name; "*" fallback
    wan_addresses: list[str] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)  # upnp, webgui_port, ssh_enabled, remote_logging, ...

    # ------------------------------------------------------------------ #
    # address resolution
    # ------------------------------------------------------------------ #
    def network_by_name(self, name: str) -> Optional[Network]:
        low = name.lower()
        for n in self.networks:
            if n.name.lower() == low or n.interface.lower() == low or (n.zone and n.zone.lower() == low):
                return n
        return None

    def network_for_ip(self, ip: str) -> Optional[Network]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best: tuple[int, Optional[Network]] = (-1, None)
        for n in self.networks:
            for c in n.cidrs:
                try:
                    net = ipaddress.ip_network(c, strict=False)
                except ValueError:
                    continue
                if addr.version == net.version and addr in net and net.prefixlen > best[0]:
                    best = (net.prefixlen, n)
        if best[1] is None:
            # anything not in an internal network is "the internet" from the WAN side
            wan = next((n for n in self.networks if n.is_wan), None)
            if wan is not None and not addr.is_private:
                return wan
        return best[1]

    def _alias(self, name: str) -> Optional[Alias]:
        for a in self.aliases:
            if a.name == name:
                return a
        return None

    def address_matches(self, spec: str, ip: str, _depth: int = 0) -> bool:
        """Does ``ip`` fall within rule address ``spec``?"""
        if _depth > 8:
            return False
        s = (spec or "any").strip()
        if s.lower() in ("any", "*", ""):
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # literal ip / cidr
        try:
            net = ipaddress.ip_network(s, strict=False)
            return addr.version == net.version and addr in net
        except ValueError:
            pass
        # ip range a-b
        if "-" in s and s.count(".") >= 6:
            a, b = s.split("-", 1)
            try:
                return ipaddress.ip_address(a.strip()) <= addr <= ipaddress.ip_address(b.strip())
            except ValueError:
                pass
        low = s.lower()
        # "<net> address" / "<net>ip" == firewall's own interface address
        for suffix in (" address", "ip", ":ip"):
            if low.endswith(suffix):
                n = self.network_by_name(s[: -len(suffix)].strip())
                if n and n.gateway_ip:
                    return n.gateway_ip == ip
        if low in ("(self)", "this firewall", "self"):
            gws = {n.gateway_ip for n in self.networks if n.gateway_ip} | set(self.wan_addresses)
            return ip in gws
        if low in ("wan address", "wanip"):
            return ip in self.wan_addresses
        # network name ("LAN", "lan net", "opt1")
        for suffix in (" net", " subnets", " subnet", ""):
            if low.endswith(suffix):
                n = self.network_by_name(s[: len(s) - len(suffix)].strip() if suffix else s)
                if n is not None:
                    if n.is_wan and not n.cidrs:
                        return not addr.is_private
                    return any(self.address_matches(c, ip, _depth + 1) for c in n.cidrs)
        alias = self._alias(s)
        if alias is not None:
            return any(self.address_matches(e, ip, _depth + 1) for e in alias.entries)
        return False

    @staticmethod
    def _proto_matches(rule_proto: str, proto: str) -> bool:
        rp = (rule_proto or "any").lower()
        if rp in ("any", "all", ""):
            return True
        return proto.lower() in rp.replace("/", ",").split(",")

    @staticmethod
    def _port_matches(ranges: list[PortRange], port: Optional[int]) -> bool:
        if not ranges:
            return True
        if port is None:
            return False
        return any(r.contains(port) for r in ranges)

    def rule_matches(self, rule: Rule, src_ip: str, dst_ip: str, port: Optional[int], proto: str) -> bool:
        if not self._proto_matches(rule.protocol, proto):
            return False
        src_ok = self.address_matches(rule.source, src_ip)
        if rule.source_not:
            src_ok = not src_ok
        dst_ok = self.address_matches(rule.destination, dst_ip)
        if rule.destination_not:
            dst_ok = not dst_ok
        if not (src_ok and dst_ok):
            return False
        if rule.destination_ports and proto.lower() in ("tcp", "udp"):
            return self._port_matches(rule.destination_ports, port)
        return True

    # ------------------------------------------------------------------ #
    # evaluation
    # ------------------------------------------------------------------ #
    def evaluate(self, src_ip: str, dst_ip: str, port: Optional[int] = None, proto: str = "tcp") -> Decision:
        """Would traffic from ``src_ip`` to ``dst_ip:port/proto`` pass this firewall?

        Traffic inside a single network never traverses the firewall, so it
        is allowed (unless the network is marked isolated, as with UniFi
        client/guest isolation).
        """
        src_net = self.network_for_ip(src_ip)
        dst_net = self.network_for_ip(dst_ip)
        if src_net is None and dst_net is None:
            return Decision(allowed=True, rule="not-routed-by-this-firewall", confident=False)
        if src_net is not None and dst_net is not None and src_net.name == dst_net.name:
            if src_net.isolation:
                return Decision(allowed=False, rule="client-isolation", interface=src_net.name)
            return Decision(allowed=True, rule="same-segment", interface=src_net.name)

        ingress = src_net.name if src_net is not None else "WAN"

        # inbound from the internet: must be port-forwarded (or target the firewall itself)
        if src_net is not None and src_net.is_wan and dst_net is not None and not dst_net.is_wan:
            for pf in self.port_forwards:
                if not pf.enabled or pf.internal_ip != dst_ip:
                    continue
                if not self._proto_matches(pf.protocol, proto):
                    continue
                tgt_port = pf.internal_port
                if port is not None and tgt_port is not None and tgt_port != port:
                    continue
                if port is not None and tgt_port is None and not self._port_matches(pf.external_ports, port):
                    continue
                if not self.address_matches(pf.source, src_ip):
                    continue
                return Decision(allowed=True, rule=f"port-forward:{pf.description or pf.id}", interface=ingress)
            # without a NAT rule private hosts are unreachable from WAN
            return Decision(allowed=False, rule="no-port-forward", interface=ingress)

        candidates = sorted(
            (r for r in self.rules if r.enabled and r.direction in ("in", "any")
             and (not r.interface or r.interface.lower() == ingress.lower()
                  or (src_net is not None and r.interface.lower() in (src_net.interface.lower(), (src_net.zone or "").lower())))),
            key=lambda r: r.order,
        )
        for r in candidates:
            if self.rule_matches(r, src_ip, dst_ip, port, proto):
                return Decision(allowed=(r.action == "allow"), rule=r.label(), interface=ingress)
        default = self.default_action.get(ingress, self.default_action.get("*", "block"))
        return Decision(allowed=(default == "allow"), rule="default", interface=ingress)
