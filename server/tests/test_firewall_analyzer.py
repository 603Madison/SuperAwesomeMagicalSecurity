"""Analyzer checks fire on weak fixtures and stay quiet on hardened ones."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sams.firewall import analyze, exposed_services, normalize_unifi, parse_any_config
from sams.models import FindingCategory, RemediationKind, Severity

F = Path(__file__).parent / "fixtures" / "firewall"


def load(name: str):
    if name.endswith(".json"):
        return normalize_unifi(json.loads((F / name).read_text()), device_id=name)
    return parse_any_config((F / name).read_bytes(), device_id=name)


def by_check(findings):
    out: dict[str, list] = {}
    for f in findings:
        out.setdefault(f.evidence["check_id"], []).append(f)
    return out


EXPECTED = {
    "pfsense_weak.xml": {
        "wan-allow-any", "risky-port-forward", "port-forward-unrestricted-source", "wan-mgmt-exposed",
        "webgui-http", "internal-any-any", "untrusted-to-mgmt-ui", "shadowed-rule", "redundant-rule",
        "disabled-rules", "wan-block-no-log", "no-remote-syslog", "upnp-enabled", "broad-port-range",
        "ipv6-parity", "untrusted-egress-unrestricted", "guest-no-rfc1918-block",
    },
    "opnsense.xml": {"risky-port-forward", "wan-mgmt-exposed", "internal-any-any", "untrusted-to-mgmt-ui",
                     "untrusted-egress-unrestricted", "guest-no-rfc1918-block"},
    "unifi_legacy.json": {"intervlan-default-allow", "ipv6-parity", "no-remote-syslog",
                          "port-forward-unrestricted-source", "risky-port-forward", "untrusted-egress-unrestricted",
                          "untrusted-to-mgmt-ui", "upnp-enabled", "wan-allow-any", "wan-block-no-log",
                          "wan-mgmt-exposed"},
    "unifi_zone.json": {"intervlan-default-allow", "no-remote-syslog", "untrusted-egress-unrestricted",
                        "untrusted-to-mgmt-ui", "wan-mgmt-exposed"},
}


@pytest.mark.parametrize("fixture", sorted(EXPECTED))
def test_expected_checks_fire(fixture):
    findings = analyze(load(fixture), "fw1")
    assert set(by_check(findings)) == EXPECTED[fixture]


@pytest.mark.parametrize("fixture", ["pfsense_hardened.xml", "unifi_legacy_hardened.json",
                                     "unifi_zone_hardened.json"])
def test_hardened_configs_are_clean(fixture):
    findings = analyze(load(fixture), "fw1")
    assert findings == [], [(f.evidence["check_id"], f.title) for f in findings]


def test_finding_shape_and_keys():
    findings = analyze(load("pfsense_weak.xml"), "fw-asset")
    keys = [f.key for f in findings]
    assert len(keys) == len(set(keys))
    for f in findings:
        assert f.key.startswith(f"fw:fw-asset:{f.evidence['check_id']}:")
        assert f.category == FindingCategory.firewall and f.asset_id == "fw-asset"
        assert f.remediation is not None and f.remediation.kind in (RemediationKind.firewall, RemediationKind.config)
        assert f.source == "firewall.analyzer"
    # deterministic: same config -> same keys
    assert sorted(keys) == sorted(f.key for f in analyze(load("pfsense_weak.xml"), "fw-asset"))


def test_pfsense_weak_details():
    c = by_check(analyze(load("pfsense_weak.xml"), "fw1"))
    risky = {f.evidence["port"]: f for f in c["risky-port-forward"]}
    assert risky[3389].severity == Severity.critical and risky[3389].evidence["internal_ip"] == "192.168.1.50"
    assert risky[22].severity == Severity.high                         # 2222 -> 22 still flagged
    assert c["wan-mgmt-exposed"][0].severity == Severity.critical
    assert c["wan-mgmt-exposed"][0].evidence["management_ports"] == [80]
    pairs = {f.key.split(":")[-1] for f in c["internal-any-any"]}
    assert {"IoT->LAN", "Guest->LAN"} <= pairs
    assert "LAN->IoT" not in pairs                                     # downhill is fine
    shadow = c["shadowed-rule"][0]
    assert shadow.evidence["rule"] == "Block IoT to LAN"
    assert shadow.evidence["shadowing_rule"]["rule"] == "IoT allow all"
    assert c["upnp-enabled"][0].severity == Severity.high              # enabled on IoT
    assert c["broad-port-range"][0].evidence["rule"] == "DMZ high ports"
    unrestricted = {f.evidence["internal_ip"]: f.severity for f in c["port-forward-unrestricted-source"]}
    assert unrestricted == {"172.16.50.10": Severity.info, "192.168.1.40": Severity.medium}
    assert {f.key.split(":")[-1] for f in c["guest-no-rfc1918-block"]} == {"Guest", "IoT"}
    assert c["untrusted-to-mgmt-ui"][0].remediation.details.startswith("pfSense:")


def test_unifi_details():
    c = by_check(analyze(load("unifi_legacy.json"), "fw1"))
    default = c["intervlan-default-allow"][0]
    assert ("IoT", "Default") in {(p["from"], p["to"]) for p in default.evidence["pairs"]}
    assert all("Cameras" not in (p["from"], p["to"]) for p in default.evidence["pairs"])   # isolated
    assert "LAN In" in default.remediation.details
    assert c["wan-mgmt-exposed"][0].evidence["management_ports"] == [22, 443]
    zone = by_check(analyze(load("unifi_zone.json"), "fw1"))["intervlan-default-allow"][0]
    assert "zone" in zone.remediation.details.lower()


def test_exposed_services():
    exp = exposed_services(load("pfsense_weak.xml"))
    pf = {(e["internal_ip"], e["port"]) for e in exp if e["kind"] == "port_forward"}
    assert {("192.168.1.50", 3389), ("192.168.1.20", 22), ("172.16.50.10", 443), ("192.168.1.40", 27015)} == pf
    fw = [e for e in exp if e["kind"] == "firewall_service"]
    assert ("203.0.113.10", 80) in {(e["internal_ip"], e["port"]) for e in fw}
    assert any(e["port"] is None for e in fw)                          # the IPv6 allow-any rule
    ssh = next(e for e in exp if e["internal_ip"] == "192.168.1.20")
    assert ssh["external_ports"] == [[2222, 2222]] and ssh["source"] == "any"

    hard = exposed_services(load("pfsense_hardened.xml"))
    assert [(e["internal_ip"], e["port"], e["source"]) for e in hard if e["kind"] == "port_forward"] == [
        ("172.16.50.10", 443, "Partners")]

    u = exposed_services(load("unifi_legacy.json"))
    assert {(e["internal_ip"], e["port"]) for e in u if e["kind"] == "port_forward"} == {
        ("192.168.1.30", 32400), ("192.168.1.50", 3389)}
    assert {e["port"] for e in u if e["kind"] == "firewall_service" and e["port"]} == {22, 443}
