"""Parsing + reachability tests for the firewall adapters."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sams.firewall import normalize_unifi, parse_any_config, parse_config_xml
from sams.firewall.model import PortRange

F = Path(__file__).parent / "fixtures" / "firewall"
INTERNET = "198.51.100.200"


@pytest.fixture(scope="module")
def pf():
    return parse_any_config((F / "pfsense_weak.xml").read_bytes(), device_id="fw-pf")


@pytest.fixture(scope="module")
def pf_hard():
    return parse_any_config((F / "pfsense_hardened.xml").read_bytes(), device_id="fw-pf-h")


@pytest.fixture(scope="module")
def opn():
    return parse_any_config((F / "opnsense.xml").read_text(), device_id="fw-opn")


@pytest.fixture(scope="module")
def unifi():
    return normalize_unifi(json.loads((F / "unifi_legacy.json").read_text()), device_id="fw-u")


@pytest.fixture(scope="module")
def unifi_zone():
    return normalize_unifi(json.loads((F / "unifi_zone.json").read_text()), device_id="fw-z")


@pytest.fixture(scope="module")
def unifi_zone_hard():
    return normalize_unifi(json.loads((F / "unifi_zone_hardened.json").read_text()))


# --------------------------------------------------------------------------- #
# pfSense parsing
# --------------------------------------------------------------------------- #
def test_pfsense_networks(pf):
    assert pf.vendor == "pfsense" and pf.device_id == "fw-pf"
    names = {n.name: n for n in pf.networks}
    assert set(names) == {"WAN", "LAN", "IoT", "DMZ", "Guest"}       # disabled opt4 skipped
    assert names["WAN"].is_wan and names["WAN"].cidrs == ["203.0.113.8/29"]
    assert names["LAN"].cidrs == ["192.168.1.0/24"] and names["LAN"].gateway_ip == "192.168.1.1"
    assert names["LAN"].interface == "lan" and names["LAN"].dhcp
    assert names["IoT"].vlan == 20 and names["IoT"].purpose == "iot"
    assert names["Guest"].purpose == "guest" and names["DMZ"].purpose == "dmz"
    assert pf.wan_addresses == ["203.0.113.10"]


def test_pfsense_settings(pf):
    s = pf.settings
    assert s["webgui_protocol"] == "http" and s["webgui_port"] == 80
    assert s["ssh_enabled"] is True and s["antilockout"] is True
    assert s["upnp_enabled"] is True and s["upnp_interfaces"] == ["lan", "opt1"]
    assert s["remote_syslog"] == [] and s["log_default_block"] is False
    assert s["version"] == "23.3" and pf.hostname == "gw"


def test_pfsense_rules_and_aliases(pf):
    by_id = {r.id: r for r in pf.rules}
    high = by_id["3000000102"]
    assert high.destination_ports == [PortRange(start=10000, end=20000)]   # port alias resolved
    assert high.protocol == "tcp" and high.interface == "opt2"
    assert by_id["0100000103"].enabled is False
    assert by_id["1000000104"].raw["ipprotocol"] == "inet6"
    assert by_id["1000000101"].destination == "wanip"
    assert by_id["3000000101"].log is True and by_id["3000000101"].destination == "RFC1918"
    anti = by_id["anti-lockout"]
    assert anti.raw["builtin"] and {p.start for p in anti.destination_ports} == {80, 22}
    assert {a.name for a in pf.aliases} >= {"AdminHosts", "WebPorts", "HighPorts", "RFC1918"}


def test_pfsense_port_forwards(pf):
    fwd = {f.description: f for f in pf.port_forwards}
    assert fwd["RDP to desktop"].internal_ip == "192.168.1.50" and fwd["RDP to desktop"].internal_port == 3389
    ssh = fwd["SSH to NAS"]
    assert ssh.internal_port == 22 and ssh.external_ports == [PortRange(start=2222, end=2222)]
    assert ssh.interface == "WAN" and ssh.source == "any"
    assert fwd["Game server"].protocol == "udp"


def test_pfsense_reachability(pf):
    # internet -> port forwards
    assert pf.evaluate(INTERNET, "192.168.1.50", 3389).allowed
    assert pf.evaluate(INTERNET, "192.168.1.50", 3389).rule.startswith("port-forward")
    assert pf.evaluate(INTERNET, "192.168.1.20", 22).allowed            # 2222 -> 22
    assert not pf.evaluate(INTERNET, "192.168.1.50", 22).allowed
    assert not pf.evaluate(INTERNET, "192.168.1.10", 445).allowed
    # internet -> firewall itself: only the webgui rule
    assert pf.evaluate(INTERNET, "203.0.113.10", 80).allowed
    d = pf.evaluate(INTERNET, "203.0.113.10", 443)
    assert not d.allowed and d.rule == "default"
    # same segment
    assert pf.evaluate("192.168.1.10", "192.168.1.20", 445).rule == "same-segment"
    # IoT allow-all shadows the block
    d = pf.evaluate("192.168.20.10", "192.168.1.10", 445)
    assert d.allowed and d.rule == "IoT allow all"
    # DMZ blocked from private space, broad ports outbound only
    assert not pf.evaluate("172.16.50.10", "192.168.1.10", 22).allowed
    assert pf.evaluate("172.16.50.10", "8.8.8.8", 15000).allowed
    assert not pf.evaluate("172.16.50.10", "8.8.8.8", 25).allowed
    # LAN to its own gateway goes through rules (anti-lockout first)
    assert pf.evaluate("192.168.1.10", "192.168.1.1", 80).rule == "Anti-Lockout Rule"


def test_pfsense_hardened_reachability(pf_hard):
    assert pf_hard.evaluate("192.168.20.10", "192.168.20.1", 53, "udp").allowed
    assert not pf_hard.evaluate("192.168.20.10", "192.168.20.1", 443).allowed
    assert not pf_hard.evaluate("192.168.20.10", "192.168.1.10", 445).allowed
    assert pf_hard.evaluate("192.168.20.10", "8.8.8.8", 443).allowed
    assert not pf_hard.evaluate("192.168.20.10", "8.8.8.8", 25).allowed
    # web forward is source-restricted
    assert pf_hard.evaluate("198.51.100.7", "172.16.50.10", 443).allowed
    assert not pf_hard.evaluate("203.0.113.99", "172.16.50.10", 443).allowed


def test_floating_rules_and_negation():
    xml = """<pfsense><interfaces>
      <wan><enable/><if>em0</if><ipaddr>203.0.113.2</ipaddr><subnet>24</subnet></wan>
      <lan><enable/><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan></interfaces>
      <filter>
        <rule><type>pass</type><interface>lan</interface><source><network>lan</network></source>
          <destination><any/></destination><descr>allow lan</descr></rule>
        <rule><type>block</type><interface>wan,lan</interface><floating>yes</floating><quick>yes</quick>
          <direction>any</direction><protocol>tcp</protocol><source><any/></source>
          <destination><any/><port>25</port></destination><descr>no smtp</descr><tracker>77</tracker></rule>
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol><source><any/></source>
          <destination><not/><address>10.0.0.0/8</address><port>8080</port></destination><descr>neg</descr></rule>
      </filter></pfsense>"""
    cfg = parse_config_xml(xml)
    floats = [r for r in cfg.rules if r.description == "no smtp"]
    assert {r.interface for r in floats} == {"wan", "lan"} and all(r.order < 0 for r in floats)
    assert {r.id for r in floats} == {"77:wan", "77:lan"}
    d = cfg.evaluate("10.0.0.5", "8.8.8.8", 25)
    assert not d.allowed and d.rule == "no smtp"
    assert cfg.evaluate("10.0.0.5", "8.8.8.8", 443).allowed
    neg = next(r for r in cfg.rules if r.description == "neg")
    assert neg.destination_not and neg.destination == "10.0.0.0/8"


def test_xml_with_dtd_is_refused():
    evil = """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>
    <pfsense><system><hostname>&lol2;</hostname></system></pfsense>"""
    with pytest.raises(Exception):
        parse_any_config(evil)


# --------------------------------------------------------------------------- #
# OPNsense
# --------------------------------------------------------------------------- #
def test_opnsense_parse(opn):
    assert opn.vendor == "opnsense" and opn.hostname == "opn"
    assert opn.settings["webgui_port"] == 8443 and opn.settings["ssh_enabled"] is True
    assert opn.settings["remote_syslog"] == ["10.10.0.5:5514"]
    assert opn.wan_addresses == []                              # dhcp WAN
    names = {n.name: n for n in opn.networks}
    assert names["Cameras"].purpose == "iot" and names["Servers"].cidrs == ["10.20.0.0/24"]
    # MVC alias content split on newlines + MVC rule port alias
    web = next(r for r in opn.rules if r.id == "r-mvc-2")
    assert {(p.start, p.end) for p in web.destination_ports} == {(80, 80), (443, 443)}
    assert web.order < 0 and web.protocol == "tcp"
    # NAT target alias resolved
    assert opn.port_forwards[0].internal_ip == "10.20.0.15"


def test_opnsense_reachability(opn):
    # automation rule (evaluated before interface rules) blocks cameras -> LAN
    d = opn.evaluate("10.30.0.10", "10.10.0.10", 445)
    assert not d.allowed and d.rule == "Cameras cannot reach LAN"
    assert opn.evaluate("10.30.0.10", "10.20.0.10", 445).allowed
    assert opn.evaluate(INTERNET, "10.20.0.15", 5432).allowed


# --------------------------------------------------------------------------- #
# UniFi legacy
# --------------------------------------------------------------------------- #
def test_unifi_legacy_parse(unifi):
    names = {n.name: n for n in unifi.networks}
    assert "Transit" not in names                               # vlan-only skipped
    assert names["Default"].cidrs == ["192.168.1.0/24"] and names["Default"].gateway_ip == "192.168.1.1"
    assert names["IoT"].purpose == "iot" and names["IoT"].vlan == 30
    assert names["Guest WiFi"].purpose == "guest"
    assert names["Internet 1"].is_wan
    assert unifi.wan_addresses == ["203.0.113.5"]
    assert unifi.settings["firewall_mode"] == "legacy"
    assert unifi.settings["upnp_enabled"] and unifi.settings["ssh_enabled"]
    assert unifi.settings["unifi_state_only_rules"] == ["allow established/related"]
    assert unifi.settings["isolated_networks"] == ["Cameras"]
    mgmt = next(r for r in unifi.rules if r.id == "fr-1")
    assert mgmt.destination == "(self)" and {p.start for p in mgmt.destination_ports} == {22, 443}
    rdp = next(f for f in unifi.port_forwards if f.id == "pf-rdp")
    assert rdp.protocol == "tcp/udp" and rdp.internal_port == 3389


def test_unifi_legacy_reachability(unifi):
    d = unifi.evaluate("192.168.30.10", "192.168.1.10", 445)
    assert d.allowed and d.rule == "default"                  # inter-VLAN allowed by default
    assert unifi.evaluate("192.168.1.10", "192.168.30.10", 22).allowed
    assert not unifi.evaluate("192.168.40.10", "192.168.1.10", 445).allowed   # guest isolation
    assert unifi.evaluate("192.168.40.10", "8.8.8.8", 443).allowed
    assert unifi.evaluate("192.168.40.10", "192.168.40.1", 53, "udp").allowed
    assert not unifi.evaluate("192.168.40.10", "192.168.40.1", 443).allowed
    assert not unifi.evaluate("192.168.50.10", "192.168.1.10", 80).allowed    # network isolation
    assert not unifi.evaluate("192.168.1.10", "192.168.50.10", 80).allowed
    assert unifi.evaluate("192.168.50.10", "192.168.50.1", 443).allowed      # gateway still reachable
    assert unifi.evaluate(INTERNET, "203.0.113.5", 443).allowed               # WAN_LOCAL mgmt
    assert not unifi.evaluate(INTERNET, "203.0.113.5", 80).allowed
    assert unifi.evaluate(INTERNET, "192.168.1.50", 3389, "udp").allowed


# --------------------------------------------------------------------------- #
# UniFi zone-based
# --------------------------------------------------------------------------- #
def test_unifi_zone_reachability(unifi_zone):
    assert unifi_zone.settings["firewall_mode"] == "zone"
    nets = {n.name: n for n in unifi_zone.networks}
    assert nets["IoT"].zone == "Internal" and nets["Guest WiFi"].purpose == "guest"
    d = unifi_zone.evaluate("192.168.30.10", "192.168.1.20", 445)
    assert d.allowed and d.rule == "IoT to NAS SMB"
    d = unifi_zone.evaluate("192.168.30.10", "192.168.1.10", 22)
    assert d.allowed and d.rule.startswith("Zone default")
    assert not unifi_zone.evaluate("192.168.40.10", "192.168.1.10", 22).allowed
    assert unifi_zone.evaluate("192.168.40.10", "8.8.8.8", 443).allowed
    assert unifi_zone.evaluate("192.168.40.10", "192.168.40.1", 53, "udp").allowed
    assert not unifi_zone.evaluate("192.168.40.10", "192.168.40.1", 443).allowed
    assert unifi_zone.evaluate(INTERNET, "203.0.113.5", 443).allowed
    assert not unifi_zone.evaluate(INTERNET, "203.0.113.5", 22).allowed


def test_unifi_zone_custom_zone(unifi_zone_hard):
    assert not unifi_zone_hard.evaluate("192.168.30.10", "192.168.1.10", 445).allowed
    assert unifi_zone_hard.evaluate("192.168.30.10", "8.8.8.8", 443).allowed
    assert not unifi_zone_hard.evaluate("192.168.30.10", "8.8.8.8", 25).allowed
    assert unifi_zone_hard.evaluate("192.168.30.10", "192.168.30.1", 53, "udp").allowed
    assert not unifi_zone_hard.evaluate("192.168.30.10", "192.168.30.1", 443).allowed
    # trusted internal can still manage IoT
    assert unifi_zone_hard.evaluate("192.168.1.10", "192.168.30.10", 22).allowed


def test_rule_ip_version_is_respected(pf):
    v6 = next(r for r in pf.rules if r.description == "Allow IPv6 in")
    assert v6.ip_version == 6
    assert pf.rule_matches(v6, "2001:db8::1", "2001:db8:5::10", 22, "tcp")
    assert not pf.rule_matches(v6, INTERNET, "203.0.113.10", 22, "tcp")
    lan = next(r for r in pf.rules if r.description == "Default allow LAN to any rule")
    assert lan.ip_version == 4
    assert next(r for r in pf.rules if r.id == "anti-lockout").ip_version is None
