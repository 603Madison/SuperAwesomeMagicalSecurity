"""Firewall policy analyzer.

``analyze(cfg, asset_id)`` inspects a normalized ``FirewallConfig`` and returns
``Finding`` objects. Each check has a stable ``check_id`` and finding keys look
like ``fw:<asset>:<check_id>:<rule_id>``, so accepted/fixed status survives
re-imports.

Reachability-style checks (segment-to-segment, egress, management UI) ask
``FirewallConfig.evaluate()`` about a representative host in each segment, so
they automatically take vendor defaults, aliases, rule order and built-ins
into account. Rule-structure checks (shadowing, broad ranges, logging) read
the rule list directly.

``exposed_services(cfg)`` lists everything reachable from the internet
according to the policy. The attack graph and the external-probe discrepancy
analysis consume it.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Optional

from ..models import Finding, FindingCategory, Remediation, RemediationKind, Severity
from .common import RFC1918, representative_host, trust_level
from .model import FirewallConfig, Network, PortRange, Rule, is_internal_ip

RISKY_PORTS: dict[int, tuple[str, Severity]] = {
    23: ("Telnet", Severity.critical),
    3389: ("RDP", Severity.critical),
    445: ("SMB", Severity.critical),
    139: ("NetBIOS/SMB", Severity.critical),
    3306: ("MySQL", Severity.critical),
    5432: ("PostgreSQL", Severity.critical),
    1433: ("Microsoft SQL Server", Severity.critical),
    27017: ("MongoDB", Severity.critical),
    6379: ("Redis", Severity.critical),
    9200: ("Elasticsearch", Severity.critical),
    11211: ("Memcached", Severity.critical),
    2375: ("Docker API (unencrypted)", Severity.critical),
    22: ("SSH", Severity.high),
    5900: ("VNC", Severity.high),
    161: ("SNMP", Severity.high),
    8080: ("HTTP alternate / admin UI", Severity.medium),
    8443: ("HTTPS alternate / admin UI", Severity.medium),
}

SELF_TOKENS = {"(self)", "self", "this firewall", "wanip", "wan address", "wan:ip"}
_PROBE_PORTS = [22, 80, 443, 445, 3389, 8080, 5432]
_EGRESS_PORTS = [25, 23, 4444, 6667]
_INTERNET_HOST = "198.51.100.25"      # TEST-NET-2: stands in for "somewhere on the internet"
_EXTERNAL_SRC = "203.0.113.77"         # TEST-NET-3: stands in for "an internet attacker"
_SEV_ORDER = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]


def _lower(sev: Severity) -> Severity:
    return _SEV_ORDER[max(0, _SEV_ORDER.index(sev) - 1)]


# --------------------------------------------------------------------------- #
# vendor-specific wording
# --------------------------------------------------------------------------- #
def _where(cfg: FirewallConfig, iface: str = "") -> str:
    net = cfg.network_by_name(iface) if iface else None
    label = net.name if net else (iface or "the interface")
    if cfg.vendor == "pfsense":
        return f"pfSense: Firewall > Rules > {label}"
    if cfg.vendor == "opnsense":
        return f"OPNsense: Firewall > Rules > {label}"
    if cfg.vendor == "unifi":
        if cfg.settings.get("firewall_mode") == "zone":
            return "UniFi Network: Settings > Security > Firewall (Zone-Based Policy Engine)"
        return f"UniFi Network: Settings > Security > Traffic & Firewall Rules ({label})"
    return f"firewall policy for {label}"


def _nat_where(cfg: FirewallConfig) -> str:
    return {"pfsense": "pfSense: Firewall > NAT > Port Forward",
            "opnsense": "OPNsense: Firewall > NAT > Port Forward",
            "unifi": "UniFi Network: Settings > Routing > Port Forwarding (or Security > Port Forwarding)",
            }.get(cfg.vendor, "the NAT / port-forward table")


def _syslog_where(cfg: FirewallConfig) -> str:
    return {"pfsense": "pfSense: Status > System Logs > Settings > Remote Logging Options",
            "opnsense": "OPNsense: System > Settings > Logging > Remote",
            "unifi": "UniFi Network: Settings > CyberSecure / System > Activity Logging (SIEM Server)",
            }.get(cfg.vendor, "the firewall's remote syslog settings")


# --------------------------------------------------------------------------- #
class _Analyzer:
    def __init__(self, cfg: FirewallConfig, asset_id: str):
        self.cfg = cfg
        self.asset_id = asset_id
        self.findings: list[Finding] = []
        self.internal = [n for n in cfg.networks if not n.is_wan and n.cidrs]
        self.wans = [n for n in cfg.networks if n.is_wan]

    # ------------------------------------------------------------------ #
    def add(self, check_id: str, rule_id: str, severity: Severity, title: str, description: str,
            evidence: dict[str, Any], remediation: Remediation, tags: Optional[list[str]] = None) -> None:
        f = Finding(
            key=f"fw:{self.asset_id}:{check_id}:{rule_id}", asset_id=self.asset_id,
            category=FindingCategory.firewall, severity=severity, title=title, description=description,
            evidence={"check_id": check_id, "vendor": self.cfg.vendor, **evidence}, remediation=remediation,
            tags=["firewall", check_id, *(tags or [])], source="firewall.analyzer",
        )
        self.findings.append(f)

    # ------------------------------------------------------------------ #
    def net_of(self, rule: Rule) -> Optional[Network]:
        return self.cfg.network_by_name(rule.interface) if rule.interface else None

    def is_wan_rule(self, rule: Rule) -> bool:
        n = self.net_of(rule)
        return (n is not None and n.is_wan) or rule.interface.lower() in ("wan", "wan2")

    def sample(self, net: Network) -> Optional[str]:
        for c in net.cidrs:
            if ":" in c:
                continue
            h = representative_host(c)
            if h and h == net.gateway_ip:
                h = str(ipaddress.ip_address(h) + 1)
            if h:
                return h
        return None

    @staticmethod
    def user_rules(rules: Iterable[Rule]) -> list[Rule]:
        return [r for r in rules if not r.raw.get("builtin")]

    @staticmethod
    def evidence_rule(rule: Rule) -> dict[str, Any]:
        raw = {k: v for k, v in rule.raw.items() if not str(k).startswith("_")}
        return {"rule_id": rule.id, "rule": rule.label(), "interface": rule.interface, "action": rule.action,
                "protocol": rule.protocol, "source": ("!" if rule.source_not else "") + rule.source,
                "destination": ("!" if rule.destination_not else "") + rule.destination,
                "destination_ports": [f"{p.start}-{p.end}" if p.start != p.end else str(p.start)
                                      for p in rule.destination_ports],
                "raw": raw}

    def is_any(self, spec: str, negated: bool = False) -> bool:
        return not negated and (spec or "any").strip().lower() in ("any", "*", "")

    def is_self(self, spec: str) -> bool:
        s = (spec or "").strip().lower()
        if s in SELF_TOKENS:
            return True
        return spec in self.cfg.wan_addresses

    # ------------------------------------------------------------------ #
    # spec resolution for shadow analysis
    # ------------------------------------------------------------------ #
    def resolve(self, spec: str, _depth: int = 0) -> Optional[list[ipaddress._BaseNetwork]]:
        """Resolve an address spec to networks. None = unknown/unresolvable."""
        s = (spec or "any").strip()
        if _depth > 8:
            return None
        try:
            return [ipaddress.ip_network(s, strict=False)]
        except ValueError:
            pass
        low = s.lower()
        if low in SELF_TOKENS or low.endswith("ip") or low.endswith(" address"):
            if low in SELF_TOKENS:
                return [ipaddress.ip_network(a) for a in self.cfg.self_addresses()]
            base = s[:-2] if low.endswith("ip") else s[: -len(" address")]
            n = self.cfg.network_by_name(base.rstrip(":"))
            if n and n.gateway_ip:
                return [ipaddress.ip_network(n.gateway_ip)]
        n = self.cfg.network_by_name(s)
        if n is not None and n.cidrs:
            return [ipaddress.ip_network(c, strict=False) for c in n.cidrs]
        alias = self.cfg._alias(s)
        if alias is not None:
            out: list[ipaddress._BaseNetwork] = []
            for e in alias.entries:
                r = self.resolve(e, _depth + 1)
                if r is None:
                    return None
                out.extend(r)
            return out
        return None

    def addr_covers(self, a: str, a_not: bool, b: str, b_not: bool) -> bool:
        if self.is_any(a, a_not):
            return True
        if a_not != b_not:
            return False
        if a.strip().lower() == b.strip().lower():
            return True
        if a_not:
            return False   # negations only compare equal
        ra, rb = self.resolve(a), self.resolve(b)
        if not ra or not rb:
            return False
        return all(any(nb.version == na.version and nb.subnet_of(na) for na in ra) for nb in rb)

    @staticmethod
    def ports_cover(a: list[PortRange], b: list[PortRange]) -> bool:
        if not a:
            return True
        if not b:
            return False
        return all(any(ra.start <= rb.start and rb.end <= ra.end for ra in a) for rb in b)

    @staticmethod
    def proto_covers(a: str, b: str) -> bool:
        pa, pb = (a or "any").lower(), (b or "any").lower()
        if pa in ("any", "all"):
            return True
        if pb in ("any", "all"):
            return False
        return set(pb.replace("/", ",").split(",")) <= set(pa.replace("/", ",").split(","))

    # ------------------------------------------------------------------ #
    # checks
    # ------------------------------------------------------------------ #
    def check_wan_allow_any(self) -> set[str]:
        flagged = set()
        for r in self.user_rules(self.cfg.rules):
            if not (r.enabled and r.action == "allow" and r.direction in ("in", "any") and self.is_wan_rule(r)):
                continue
            if self.is_any(r.source, r.source_not) and (self.is_any(r.destination, r.destination_not)
                                                        or self.is_self(r.destination)) \
                    and not r.destination_ports and r.protocol in ("any", "all", "tcp", "udp", "tcp/udp"):
                flagged.add(r.id)
                self.add("wan-allow-any", r.id, Severity.critical,
                         f"WAN rule allows any inbound traffic ({r.label()})",
                         "A rule on the internet-facing interface permits traffic from any source to "
                         f"{r.destination} on any port. Everything listening behind it (including the firewall's "
                         "own management services) is exposed to the whole internet.",
                         self.evidence_rule(r),
                         Remediation(kind=RemediationKind.firewall, summary="Delete or narrow the WAN allow-any rule",
                                     details=f"{_where(self.cfg, r.interface)}: remove '{r.label()}'. Expose "
                                             "individual services with port forwards restricted to known source "
                                             "addresses, or better, publish them through a VPN (WireGuard/"
                                             "Tailscale) so nothing is internet-facing.",
                                     effort="low"))
        return flagged

    def check_port_forwards(self) -> None:
        for pf in self.cfg.port_forwards:
            if not pf.enabled:
                continue
            net = self.cfg.network_by_name(pf.interface)
            if net is not None and not net.is_wan:
                continue
            open_src = self.is_any(pf.source)
            ports_ext = pf.external_ports
            candidates: dict[int, tuple[str, Severity]] = {}
            all_ports = not ports_ext
            for port, info in RISKY_PORTS.items():
                if all_ports or any(r.contains(port) for r in ports_ext) or pf.internal_port == port:
                    candidates[port] = info
            ev_base = {"forward_id": pf.id, "forward": pf.description or pf.id, "internal_ip": pf.internal_ip,
                       "internal_port": pf.internal_port, "protocol": pf.protocol, "source": pf.source,
                       "external_ports": [f"{r.start}-{r.end}" if r.start != r.end else str(r.start)
                                          for r in ports_ext] or ["any"],
                       "raw": {k: v for k, v in pf.raw.items() if not str(k).startswith("_")}}
            if all_ports:
                self.add("risky-port-forward", f"{pf.id}:all",
                         Severity.critical if open_src else Severity.high,
                         f"All ports of {pf.internal_ip} are exposed to the internet ({pf.description or pf.id})",
                         "A 1:1 NAT or any-port forward publishes every service on the internal host, including "
                         "ones that come up later.",
                         ev_base, Remediation(kind=RemediationKind.firewall,
                                              summary="Replace the any-port forward with specific service ports",
                                              details=f"{_nat_where(self.cfg)}: restrict '{pf.description or pf.id}' "
                                                      "to the exact ports needed, with a source restriction.",
                                              effort="low"))
                continue
            if not candidates and open_src:
                web = all(r.start in (80, 443) and r.end in (80, 443) for r in ports_ext)
                self.add("port-forward-unrestricted-source", pf.id, Severity.info if web else Severity.medium,
                         f"Port forward to {pf.internal_ip} accepts connections from any internet address",
                         f"'{pf.description or pf.id}' forwards {', '.join(ev_base['external_ports'])} to "
                         f"{pf.internal_ip} from any source. Every vulnerability in that service is reachable "
                         "by every scanner on the internet.",
                         ev_base, Remediation(kind=RemediationKind.firewall,
                                              summary="Limit the forward's source addresses or move it behind a VPN",
                                              details=f"{_nat_where(self.cfg)}: set a source alias/group of the "
                                                      "addresses that legitimately need access, or use a VPN.",
                                              effort="low"))
            for port, (svc, sev) in sorted(candidates.items()):
                severity = sev if open_src else _lower(sev)
                self.add("risky-port-forward", f"{pf.id}:{port}", severity,
                         f"{svc} (port {port}) on {pf.internal_ip} is port-forwarded to the internet",
                         f"'{pf.description or pf.id}' exposes {svc} on {pf.internal_ip} to "
                         f"{'any internet address' if open_src else 'source ' + pf.source}. {svc} is a "
                         "high-value target for brute force and exploitation, and should not be internet-facing.",
                         {**ev_base, "port": port, "service": svc},
                         Remediation(kind=RemediationKind.firewall,
                                     summary=f"Remove the {svc} port forward; reach it over a VPN instead",
                                     details=f"{_nat_where(self.cfg)}: delete or disable '{pf.description or pf.id}'"
                                             " and its associated filter rule. Provide remote access through "
                                             "WireGuard/OpenVPN/Tailscale, or at minimum restrict the source to "
                                             "known IPs.",
                                     effort="low"), tags=[svc.lower()])

    def check_mgmt_exposed(self, already: set[str]) -> None:
        s = self.cfg.settings
        mgmt_ports = {int(s.get("webgui_port", 443)): "web GUI"}
        if s.get("webgui_protocol") == "http":
            mgmt_ports[80] = "web GUI"
        if s.get("ssh_enabled"):
            mgmt_ports.setdefault(int(s.get("ssh_port", 22)), "SSH")
        for r in self.user_rules(self.cfg.rules):
            if r.id in already or not (r.enabled and r.action == "allow" and self.is_wan_rule(r)
                                       and r.direction in ("in", "any")):
                continue
            if not (self.is_self(r.destination) or self.is_any(r.destination, r.destination_not)):
                continue
            if r.protocol not in ("any", "all", "tcp", "tcp/udp"):
                continue
            hit = [(p, n) for p, n in mgmt_ports.items()
                   if not r.destination_ports or any(pr.contains(p) for pr in r.destination_ports)]
            if not hit:
                continue
            open_src = self.is_any(r.source, r.source_not)
            names = ", ".join(sorted({f"{n} ({p})" for p, n in hit}))
            self.add("wan-mgmt-exposed", r.id, Severity.critical if open_src else Severity.high,
                     f"Firewall management ({names}) reachable from the internet",
                     f"Rule '{r.label()}' on the WAN allows {'anyone' if open_src else r.source} to reach the "
                     "firewall's own management services. A compromised firewall gives an attacker every "
                     "network segment at once.",
                     {**self.evidence_rule(r), "management_ports": sorted(p for p, _ in hit)},
                     Remediation(kind=RemediationKind.firewall,
                                 summary="Block management access from WAN; administer over VPN or a mgmt VLAN",
                                 details=f"{_where(self.cfg, r.interface)}: delete '{r.label()}'. Restrict the "
                                         "web GUI/SSH to a management network and reach it remotely via VPN.",
                                 effort="low"))
        selfs = self.cfg.self_addresses()
        for pf in self.cfg.port_forwards:
            if pf.enabled and pf.internal_ip in selfs and (pf.internal_port in mgmt_ports or not pf.external_ports):
                self.add("wan-mgmt-exposed", f"nat:{pf.id}", Severity.critical,
                         "Port forward publishes the firewall's own management interface",
                         f"'{pf.description or pf.id}' forwards to the firewall's address {pf.internal_ip}.",
                         {"forward_id": pf.id, "internal_ip": pf.internal_ip, "internal_port": pf.internal_port},
                         Remediation(kind=RemediationKind.firewall, summary="Delete the forward to the firewall",
                                     details=f"{_nat_where(self.cfg)}: remove '{pf.description or pf.id}'.",
                                     effort="low"))

    def check_webgui_http(self) -> None:
        if self.cfg.settings.get("webgui_protocol") == "http":
            self.add("webgui-http", "webgui", Severity.medium, "Firewall web GUI is served over plain HTTP",
                     "Admin credentials and session cookies cross the network unencrypted, and anyone on a "
                     "reachable segment can capture or hijack an admin session.",
                     {"webgui_port": self.cfg.settings.get("webgui_port")},
                     Remediation(kind=RemediationKind.config, summary="Switch the web GUI to HTTPS",
                                 details="pfSense/OPNsense: System > Advanced > Admin Access > Protocol: HTTPS "
                                         "(and enable HSTS / the HTTP redirect).", effort="low"))

    def _pair_decisions(self, a: Network, b: Network, ports: list[int]) -> list[Any]:
        src, dst = self.sample(a), self.sample(b)
        if not src or not dst:
            return []
        return [self.cfg.evaluate(src, dst, p, "tcp") for p in ports]

    @staticmethod
    def _is_default(rule: Optional[str]) -> bool:
        return rule == "default" or (rule or "").startswith("Zone default")

    def check_segments(self) -> None:
        default_pairs: list[dict[str, Any]] = []
        worst_default = Severity.info
        for a in self.internal:
            for b in self.internal:
                if a.name == b.name:
                    continue
                decisions = self._pair_decisions(a, b, _PROBE_PORTS)
                if not decisions or not all(d.allowed for d in decisions):
                    continue
                rules = {d.rule for d in decisions}
                uphill = trust_level(a.purpose) < trust_level(b.purpose)
                untrusted_src = a.purpose in ("iot", "guest", "dmz")
                if all(self._is_default(r) for r in rules):
                    if trust_level(a.purpose) > trust_level(b.purpose) and not untrusted_src:
                        continue   # trusted -> less trusted is normal (e.g. LAN managing IoT)
                    default_pairs.append({"from": a.name, "to": b.name, "from_purpose": a.purpose,
                                          "to_purpose": b.purpose})
                    sev = Severity.high if (uphill or untrusted_src) else Severity.medium
                    worst_default = max(worst_default, sev, key=_SEV_ORDER.index)
                    continue
                if not uphill:
                    continue
                rule_label = next((r for r in rules if not self._is_default(r)), "")
                rule = next((r for r in self.cfg.rules if r.label() == rule_label), None)
                ev = {"from": a.name, "to": b.name, "from_purpose": a.purpose, "to_purpose": b.purpose,
                      "probed_ports": _PROBE_PORTS, "matched_rules": sorted(r for r in rules if r)}
                if rule:
                    ev.update(self.evidence_rule(rule))
                self.add("internal-any-any", f"{a.name}->{b.name}", Severity.high,
                         f"{a.name} ({a.purpose}) has unrestricted access to {b.name} ({b.purpose})",
                         f"Hosts on the lower-trust {a.name} segment can open connections to any port on the "
                         f"higher-trust {b.name} segment. A single compromised {a.purpose} device can attack "
                         f"every service on {b.name}.",
                         ev,
                         Remediation(kind=RemediationKind.firewall,
                                     summary=f"Block {a.name} -> {b.name} except explicitly needed services",
                                     details=f"{_where(self.cfg, a.interface or a.name)}: above '{rule_label}', add "
                                             f"'block {a.name} net -> {b.name} net' (and allow only the specific "
                                             "host:port pairs that are needed, such as a Home Assistant server "
                                             "reaching an IoT hub).",
                                     effort="medium"))
        if default_pairs:
            unifi = self.cfg.vendor == "unifi"
            zone = self.cfg.settings.get("firewall_mode") == "zone"
            if unifi and zone:
                fix = ("Create custom zones for IoT/Guest/DMZ networks (or move them into the Hotspot/DMZ "
                       "zones) and add Block policies from each lower-trust zone to Internal, keeping the "
                       "default 'allow return traffic' behaviour.")
            elif unifi:
                fix = ("Settings > Security > Traffic & Firewall Rules > LAN In: first add 'Allow established/"
                       "related' (states Established+Related), then 'Drop' rules from each IoT/Guest network to "
                       "RFC1918, or enable 'Network Isolation' on those networks.")
            else:
                fix = f"{_where(self.cfg)}: add explicit block rules between segments; don't rely on default allow."
            self.add("intervlan-default-allow", "default", worst_default,
                     "Inter-VLAN traffic is allowed by default",
                     "No rules separate these internal networks. The firewall's default policy lets them reach "
                     "each other on any port, so the VLANs provide no security boundary: "
                     + ", ".join(f"{p['from']}->{p['to']}" for p in default_pairs[:12])
                     + (" ..." if len(default_pairs) > 12 else ""),
                     {"pairs": default_pairs, "firewall_mode": self.cfg.settings.get("firewall_mode", "")},
                     Remediation(kind=RemediationKind.firewall, summary="Add inter-VLAN isolation rules",
                                 details=fix, effort="medium"))

    def check_untrusted_mgmt(self) -> None:
        s = self.cfg.settings
        ports = [int(s.get("webgui_port", 443))]
        if s.get("ssh_enabled"):
            ports.append(int(s.get("ssh_port", 22)))
        for a in self.internal:
            if a.purpose not in ("guest", "iot", "dmz"):
                continue
            src = self.sample(a)
            targets = [n.gateway_ip for n in self.internal if n.gateway_ip and ":" not in n.gateway_ip]
            if not src or not targets:
                continue
            reachable = [(t, p, d.rule) for t in targets for p in ports
                         for d in [self.cfg.evaluate(src, t, p, "tcp")] if d.allowed]
            if not reachable:
                continue
            self.add("untrusted-to-mgmt-ui", a.name, Severity.high if a.purpose == "guest" else Severity.medium,
                     f"{a.name} ({a.purpose}) can reach the firewall's management interface",
                     f"Devices on {a.name} can connect to the firewall's web GUI/SSH. Untrusted devices should "
                     "only reach the gateway for DNS/DHCP.",
                     {"network": a.name, "reachable": [{"ip": t, "port": p, "rule": r} for t, p, r in reachable]},
                     Remediation(kind=RemediationKind.firewall,
                                 summary=f"Block {a.name} -> firewall management ports",
                                 details=f"{_where(self.cfg, a.interface or a.name)}: add, near the top, "
                                         f"'allow DNS/DHCP to This Firewall' followed by 'block {a.name} net -> "
                                         "This Firewall (self)'.", effort="low"))

    def check_shadowing(self) -> None:
        groups: dict[str, list[Rule]] = {}
        for r in self.user_rules(self.cfg.rules):
            if r.enabled and r.direction in ("in", "any"):
                chain = str(r.raw.get("chain", "")) if isinstance(r.raw, dict) else ""
                groups.setdefault(f"{r.interface.lower()}|{chain}", []).append(r)
        for key, rules in groups.items():
            iface = key.split("|", 1)[0]
            rules.sort(key=lambda r: r.order)
            for i, r2 in enumerate(rules):
                for r1 in rules[:i]:
                    if r1.order == r2.order and r1.id.split(":")[0] == r2.id.split(":")[0]:
                        continue   # fan-out of one vendor rule
                    if not (self.proto_covers(r1.protocol, r2.protocol)
                            and self.addr_covers(r1.source, r1.source_not, r2.source, r2.source_not)
                            and self.addr_covers(r1.destination, r1.destination_not, r2.destination,
                                                 r2.destination_not)
                            and self.ports_cover(r1.destination_ports, r2.destination_ports)
                            and self.ports_cover(r1.source_ports, r2.source_ports)):
                        continue
                    if r1.ip_version is not None and r1.ip_version != r2.ip_version:
                        continue
                    if r1.action != r2.action:
                        self.add("shadowed-rule", r2.id, Severity.medium,
                                 f"Rule '{r2.label()}' never matches; it is shadowed by '{r1.label()}'",
                                 f"'{r1.label()}' ({r1.action}) comes first and matches everything '{r2.label()}' "
                                 f"({r2.action}) would. The later rule has no effect, so the intended "
                                 f"{'restriction' if r2.action != 'allow' else 'exception'} is not enforced.",
                                 {"shadowing_rule": self.evidence_rule(r1), **self.evidence_rule(r2)},
                                 Remediation(kind=RemediationKind.firewall,
                                             summary=f"Move '{r2.label()}' above '{r1.label()}' (or delete it)",
                                             details=f"{_where(self.cfg, iface)}: reorder so the more specific rule "
                                                     "comes first.", effort="low"))
                    else:
                        self.add("redundant-rule", r2.id, Severity.info,
                                 f"Rule '{r2.label()}' is redundant (covered by '{r1.label()}')",
                                 "Redundant rules make the policy harder to review and often hide mistakes.",
                                 {"covering_rule": self.evidence_rule(r1), **self.evidence_rule(r2)},
                                 Remediation(kind=RemediationKind.firewall, summary=f"Remove '{r2.label()}'",
                                             details=f"{_where(self.cfg, iface)}", effort="low"))
                    break

    def check_disabled(self) -> None:
        disabled = [r for r in self.user_rules(self.cfg.rules) if not r.enabled]
        if disabled:
            self.add("disabled-rules", "all", Severity.info, f"{len(disabled)} disabled firewall rule(s)",
                     "Disabled rules are clutter. Re-enabling one by accident can silently open access.",
                     {"rules": [{"id": r.id, "rule": r.label(), "interface": r.interface, "action": r.action}
                                for r in disabled[:50]]},
                     Remediation(kind=RemediationKind.firewall, summary="Review and delete unused disabled rules",
                                 details=_where(self.cfg), effort="low"))

    def check_logging(self) -> None:
        s = self.cfg.settings
        unlogged = [r for r in self.user_rules(self.cfg.rules)
                    if r.enabled and r.action in ("block", "reject") and self.is_wan_rule(r) and not r.log]
        default_unlogged = self.cfg.vendor in ("pfsense", "opnsense") and not s.get("log_default_block", True)
        if unlogged or default_unlogged:
            self.add("wan-block-no-log", "wan", Severity.low, "WAN block events are not logged",
                     "Without logs of blocked inbound traffic, scans and attacks against the perimeter are "
                     "invisible to the SIEM.",
                     {"rules": [r.label() for r in unlogged], "default_block_logged": not default_unlogged},
                     Remediation(kind=RemediationKind.config, summary="Enable logging on WAN block rules",
                                 details=f"{_where(self.cfg, 'wan')}: tick 'Log packets' on block rules; "
                                         "pfSense/OPNsense: Status > System Logs > Settings > 'Log packets "
                                         "matched from the default block rules'.", effort="low"))
        if not s.get("remote_syslog"):
            self.add("no-remote-syslog", "syslog", Severity.low, "Firewall logs are not forwarded to a SIEM",
                     "Logs kept only on the firewall are lost on reboot/rotation and can be wiped by an attacker "
                     "who gains access to it.",
                     {"remote_syslog": s.get("remote_syslog", [])},
                     Remediation(kind=RemediationKind.config, summary="Send firewall syslog to SAMS",
                                 details=f"{_syslog_where(self.cfg)}: add the SAMS server on UDP port 5514 "
                                         "(firewall + system events).", effort="low"))

    def check_upnp(self) -> None:
        s = self.cfg.settings
        if not s.get("upnp_enabled"):
            return
        ifaces = [self.cfg.network_by_name(i) for i in s.get("upnp_interfaces") or []]
        risky = [n.name for n in ifaces if n is not None and n.purpose in ("iot", "guest")]
        self.add("upnp-enabled", "upnp", Severity.high if risky else Severity.medium,
                 "UPnP/NAT-PMP is enabled" + (f" for untrusted networks ({', '.join(risky)})" if risky else ""),
                 "UPnP lets any device (or malware on it) open inbound port forwards without review. These "
                 "openings bypass the firewall policy and don't show up in the NAT table.",
                 {"upnp_interfaces": s.get("upnp_interfaces", []), "untrusted": risky},
                 Remediation(kind=RemediationKind.config, summary="Disable UPnP/NAT-PMP",
                             details={"pfsense": "Services > UPnP & NAT-PMP: uncheck Enable.",
                                      "opnsense": "Services > UPnP: uncheck Enable.",
                                      "unifi": "Settings > Internet > WAN > UPnP: off (Network 9: Settings > "
                                               "Routing / Internet > UPnP)."}.get(self.cfg.vendor,
                                                                                  "Disable UPnP on the gateway."),
                             effort="low"))

    def check_broad_ranges(self) -> None:
        for r in self.user_rules(self.cfg.rules):
            if not (r.enabled and r.action == "allow" and r.destination_ports):
                continue
            span = sum(p.end - p.start + 1 for p in r.destination_ports)
            if span > 1000:
                self.add("broad-port-range", r.id, Severity.medium,
                         f"Rule '{r.label()}' allows a broad port range ({span} ports)",
                         "Wide port ranges usually exist for convenience and expose services nobody intended "
                         "to publish.", self.evidence_rule(r),
                         Remediation(kind=RemediationKind.firewall, summary="Narrow the port range to what is needed",
                                     details=_where(self.cfg, r.interface), effort="low"))
        for pf in self.cfg.port_forwards:
            span = sum(p.end - p.start + 1 for p in pf.external_ports)
            if pf.enabled and span > 1000:
                self.add("broad-port-range", f"nat:{pf.id}", Severity.medium,
                         f"Port forward '{pf.description or pf.id}' publishes {span} ports",
                         "A large forwarded range exposes whatever happens to listen on those ports.",
                         {"forward_id": pf.id, "internal_ip": pf.internal_ip, "span": span},
                         Remediation(kind=RemediationKind.firewall, summary="Forward only the specific ports needed",
                                     details=_nat_where(self.cfg), effort="low"))

    def check_ipv6_parity(self) -> None:
        by_iface: dict[str, list[Rule]] = {}
        for r in self.user_rules(self.cfg.rules):
            if r.enabled and r.action == "allow" and r.direction in ("in", "any"):
                by_iface.setdefault(r.interface.lower(), []).append(r)

        def anyany(r: Rule) -> bool:
            return (self.is_any(r.source, r.source_not) and self.is_any(r.destination, r.destination_not)
                    and not r.destination_ports)

        for iface, rules in by_iface.items():
            v6 = [r for r in rules if anyany(r) and r.ip_version == 6]
            v4 = [r for r in rules if anyany(r) and r.ip_version in (4, None)]
            if v6 and not v4:
                r = v6[0]
                wan = self.is_wan_rule(r)
                self.add("ipv6-parity", r.id, Severity.high if wan else Severity.medium,
                         f"IPv6 is wide open on {iface or 'floating rules'} while IPv4 is restricted",
                         "The IPv6 policy allows any traffic where the IPv4 policy is restrictive. Hosts with "
                         "global IPv6 addresses bypass the IPv4 rules entirely.",
                         self.evidence_rule(r),
                         Remediation(kind=RemediationKind.firewall, summary="Mirror the IPv4 restrictions for IPv6",
                                     details=f"{_where(self.cfg, r.interface)}: replace '{r.label()}' with IPv6 "
                                             "rules equivalent to the IPv4 policy (or disable IPv6 on the segment).",
                                     effort="medium"))

    def check_egress(self) -> None:
        for a in self.internal:
            if a.purpose not in ("iot", "guest"):
                continue
            src = self.sample(a)
            if not src:
                continue
            decisions = [self.cfg.evaluate(src, _INTERNET_HOST, p, "tcp") for p in _EGRESS_PORTS]
            if decisions and all(d.allowed for d in decisions):
                self.add("untrusted-egress-unrestricted", a.name, Severity.low,
                         f"{a.name} ({a.purpose}) has unrestricted internet egress",
                         "Untrusted devices can connect out on any port (for example SMTP, IRC or reverse-shell "
                         "ports), which helps botnets and data exfiltration.",
                         {"network": a.name, "probed_ports": _EGRESS_PORTS},
                         Remediation(kind=RemediationKind.firewall,
                                     summary=f"Restrict {a.name} egress to the ports devices need (80/443/123/53)",
                                     details=_where(self.cfg, a.interface or a.name), effort="medium"))

    def check_guest_rfc1918(self) -> None:
        if self.cfg.vendor not in ("pfsense", "opnsense"):
            return
        private = [ipaddress.ip_network(c) for c in RFC1918]
        for a in self.internal:
            if a.purpose not in ("guest", "iot"):
                continue
            rules = [r for r in self.cfg.rules if r.enabled and r.interface.lower() in
                     (a.interface.lower(), a.name.lower())]
            protected = False
            for r in rules:
                res = self.resolve(r.destination) if r.destination else None
                covers_private = bool(res) and all(any(p.subnet_of(n) for n in res if n.version == 4) for p in private)
                if r.action in ("block", "reject") and not r.destination_not and covers_private:
                    protected = True
                if r.action == "allow" and r.destination_not and covers_private:
                    protected = True
            if protected:
                continue
            src = self.sample(a)
            reach = []
            for b in self.internal:
                if b.name == a.name:
                    continue
                dst = self.sample(b)
                if src and dst:
                    d = [self.cfg.evaluate(src, dst, p, "tcp") for p in _PROBE_PORTS]
                    if any(x.allowed for x in d):
                        reach.append(b.name)
            if not reach:
                continue
            self.add("guest-no-rfc1918-block", a.name, Severity.medium,
                     f"{a.name} ({a.purpose}) has no rule blocking private (RFC1918) destinations",
                     f"{a.name} can currently reach {', '.join(reach)}. The standard pattern for untrusted "
                     "segments is an early 'block to RFC1918' rule, so future networks are protected too.",
                     {"network": a.name, "reachable_networks": reach},
                     Remediation(kind=RemediationKind.firewall,
                                 summary=f"Add 'block {a.name} -> RFC1918' above the allow rules",
                                 details=f"{_where(self.cfg, a.interface)}: create an alias RFC1918 "
                                         "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), add 'pass DNS to "
                                         f"{a.name} address', then 'block {a.name} net -> RFC1918', then "
                                         f"'pass {a.name} net -> any'.", effort="low"))

    # ------------------------------------------------------------------ #
    def run(self) -> list[Finding]:
        flagged = self.check_wan_allow_any()
        self.check_port_forwards()
        self.check_mgmt_exposed(flagged)
        self.check_webgui_http()
        self.check_segments()
        self.check_untrusted_mgmt()
        self.check_shadowing()
        self.check_disabled()
        self.check_logging()
        self.check_upnp()
        self.check_broad_ranges()
        self.check_ipv6_parity()
        self.check_egress()
        self.check_guest_rfc1918()
        # de-duplicate on key (fan-out rules can trigger the same finding twice)
        seen: dict[str, Finding] = {}
        for f in self.findings:
            seen.setdefault(f.key, f)
        return list(seen.values())


def analyze(cfg: FirewallConfig, asset_id: str) -> list[Finding]:
    """Run every firewall policy check against ``cfg``."""
    return _Analyzer(cfg, asset_id).run()


# --------------------------------------------------------------------------- #
def _expand(ranges: list[PortRange], limit: int = 64) -> Optional[list[int]]:
    total = sum(r.end - r.start + 1 for r in ranges)
    if not ranges or total > limit:
        return None
    return [p for r in ranges for p in range(r.start, r.end + 1)]


def exposed_services(cfg: FirewallConfig) -> list[dict[str, Any]]:
    """Everything the policy makes reachable from the internet.

    Each entry: ``{"kind": "port_forward"|"firewall_service"|"routed", "internal_ip",
    "port" (int or None = any/large range), "port_ranges": [[start, end]], "external_ports",
    "proto", "source", "rule", "id"}``.
    """
    out: list[dict[str, Any]] = []
    wan_names = {n.name.lower() for n in cfg.networks if n.is_wan} | {n.interface.lower() for n in cfg.networks
                                                                     if n.is_wan} | {"wan"}
    for pf in cfg.port_forwards:
        if not pf.enabled or pf.interface.lower() not in wan_names:
            continue
        base = {"kind": "port_forward", "internal_ip": pf.internal_ip, "proto": pf.protocol, "source": pf.source,
                "rule": pf.description or pf.id, "id": pf.id,
                "external_ports": [[r.start, r.end] for r in pf.external_ports],
                "port_ranges": [[r.start, r.end] for r in pf.external_ports]}
        if pf.internal_port is not None:
            out.append({**base, "port": pf.internal_port, "port_ranges": [[pf.internal_port, pf.internal_port]]})
            continue
        ports = _expand(pf.external_ports)
        if ports is None:
            out.append({**base, "port": None})
        else:
            out.extend({**base, "port": p} for p in ports)
    a = _Analyzer(cfg, cfg.device_id)
    selfs = sorted(cfg.wan_addresses) or ["self"]
    for r in a.user_rules(cfg.rules):
        if not (r.enabled and r.action == "allow" and a.is_wan_rule(r) and r.direction in ("in", "any")):
            continue
        ports = _expand(r.destination_ports)
        entries: list[tuple[str, str]] = []
        if a.is_self(r.destination) or a.is_any(r.destination, r.destination_not):
            entries += [("firewall_service", ip) for ip in selfs]
        else:
            res = a.resolve(r.destination) or []
            for net in res:
                if not is_internal_ip(net.network_address) and str(net.network_address) not in cfg.self_addresses():
                    entries.append(("routed", str(net) if net.num_addresses > 1 else str(net.network_address)))
        for kind, ip in entries:
            base = {"kind": kind, "internal_ip": ip, "proto": r.protocol,
                    "source": ("!" if r.source_not else "") + r.source, "rule": r.label(), "id": r.id,
                    "external_ports": [[p.start, p.end] for p in r.destination_ports],
                    "port_ranges": [[p.start, p.end] for p in r.destination_ports]}
            if ports is None:
                out.append({**base, "port": None})
            else:
                out.extend({**base, "port": p} for p in ports)
    return out
