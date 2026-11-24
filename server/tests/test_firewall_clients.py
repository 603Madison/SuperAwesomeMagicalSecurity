"""Live API clients exercised against httpx.MockTransport."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest

from sams.firewall import (OPNsenseAPIClient, PfSenseAPIClient, UniFiClient, analyze, fetch_device,
                           normalize_unifi)

F = Path(__file__).parent / "fixtures" / "firewall"
LEGACY = json.loads((F / "unifi_legacy.json").read_text())
ZONE = json.loads((F / "unifi_zone.json").read_text())


def unifi_handler(raw: dict, zone_path: str = "zone", calls: list | None = None):
    rest = {"networkconf", "firewallrule", "firewallgroup", "portforward", "setting"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if calls is not None:
            calls.append((request.method, path))
        if path == "/api/auth/login":
            body = json.loads(request.content)
            if body != {"username": "ro", "password": "pw", "remember": False}:
                return httpx.Response(401)
            return httpx.Response(200, json={"ok": True},
                                  headers={"x-csrf-token": "csrf-1", "set-cookie": "TOKEN=tok123; Path=/; HttpOnly"})
        api_key_ok = request.headers.get("x-api-key") == "key-1"
        cookie_ok = "TOKEN=tok123" in request.headers.get("cookie", "") and \
            request.headers.get("x-csrf-token") == "csrf-1"
        if not (api_key_ok or cookie_ok):
            return httpx.Response(401, json={"meta": {"rc": "error", "msg": "api.err.LoginRequired"}})
        if not path.startswith("/proxy/network/"):
            return httpx.Response(404)
        tail = path[len("/proxy/network/"):]
        if tail.startswith("api/s/default/rest/"):
            name = tail.rsplit("/", 1)[-1]
            if name in rest:
                return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": raw.get(name, [])})
        if tail == "api/s/default/stat/health":
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": raw.get("health", [])})
        if tail == f"v2/api/site/default/firewall/{zone_path}" and raw.get("zones"):
            return httpx.Response(200, json=raw["zones"])
        if tail == "v2/api/site/default/firewall-policies" and raw.get("zones"):
            return httpx.Response(200, json=raw.get("policies", []))
        return httpx.Response(404, json={"error": "not found"})

    return handler


def test_unifi_login_flow_with_csrf():
    calls: list = []
    client = UniFiClient("https://unifi.example.com", username="ro", password="pw",
                         transport=httpx.MockTransport(unifi_handler(LEGACY, calls=calls)))
    cfg = client.fetch()
    assert calls[0] == ("POST", "/api/auth/login")
    assert sum(1 for c in calls if c[1] == "/api/auth/login") == 1
    expected = normalize_unifi(LEGACY)
    assert len(cfg.rules) == len(expected.rules) and len(cfg.port_forwards) == 2
    assert cfg.settings["firewall_mode"] == "legacy"
    assert cfg.wan_addresses == ["203.0.113.5"]
    assert {f.evidence["check_id"] for f in analyze(cfg, "u")} == {
        f.evidence["check_id"] for f in analyze(expected, "u")}


def test_unifi_bad_password():
    client = UniFiClient("https://unifi.example.com", username="ro", password="wrong",
                         transport=httpx.MockTransport(unifi_handler(LEGACY)))
    with pytest.raises(PermissionError):
        client.fetch()


def test_unifi_api_key_and_zone_fallback_path():
    calls: list = []
    client = UniFiClient("https://192.168.1.1", api_key="key-1",
                         transport=httpx.MockTransport(unifi_handler(ZONE, zone_path="zones", calls=calls)))
    cfg = client.fetch()
    assert not any(c[1] == "/api/auth/login" for c in calls)
    assert ("GET", "/proxy/network/v2/api/site/default/firewall/zone") in calls     # tried, 404
    assert cfg.settings["firewall_mode"] == "zone"
    assert any(r.description == "IoT to NAS SMB" for r in cfg.rules)


def test_unifi_requires_credentials():
    with pytest.raises(ValueError):
        UniFiClient("https://x")


# --------------------------------------------------------------------------- #
PFREST = {
    "/api/v2/interfaces": [
        {"id": "wan", "if": "em0", "descr": "WAN", "enable": True, "typev4": "static", "ipaddr": "203.0.113.10",
         "subnet": 29},
        {"id": "lan", "if": "em1", "descr": "LAN", "enable": True, "typev4": "static", "ipaddr": "10.0.0.1",
         "subnet": 24},
        {"id": "opt1", "if": "em2", "descr": "IOT", "enable": True, "typev4": "static", "ipaddr": "10.0.20.1",
         "subnet": 24},
    ],
    "/api/v2/firewall/rules": [
        {"id": 0, "type": "pass", "interface": ["lan"], "ipprotocol": "inet", "protocol": None, "source": "lan",
         "destination": "any", "descr": "Default allow LAN to any rule", "disabled": False, "log": False,
         "tracker": 100},
        {"id": 1, "type": "pass", "interface": ["opt1"], "ipprotocol": "inet", "protocol": None, "source": "opt1",
         "destination": "!lan", "descr": "IoT anything but LAN", "disabled": False, "tracker": 101},
        {"id": 2, "type": "pass", "interface": ["wan"], "ipprotocol": "inet", "protocol": "tcp", "source": "any",
         "destination": "wan:ip", "destination_port": "443", "descr": "admin from anywhere", "tracker": 102},
        {"id": 3, "type": "block", "interface": ["wan", "lan"], "floating": True, "quick": True,
         "direction": "any", "ipprotocol": "inet", "protocol": "tcp", "source": "any", "destination": "any",
         "destination_port": "BadPorts", "descr": "no bad ports", "tracker": 103},
    ],
    "/api/v2/firewall/nat/port_forwards": [
        {"id": 0, "interface": "wan", "ipprotocol": "inet", "protocol": "tcp", "source": "any",
         "destination": "wan:ip", "destination_port": "8443", "target": "NASHost", "local_port": "443",
         "descr": "NAS UI", "disabled": False},
    ],
    "/api/v2/firewall/aliases": [
        {"id": 0, "name": "NASHost", "type": "host", "address": ["10.0.0.20"]},
        {"id": 1, "name": "BadPorts", "type": "port", "address": ["23", "135:139"]},
    ],
}


def pfrest_handler(request: httpx.Request) -> httpx.Response:
    if request.headers.get("x-api-key") != "pf-key":
        return httpx.Response(401, json={"code": 401, "status": "unauthorized", "data": []})
    if request.url.path == "/api/v2/system/webgui/settings":
        return httpx.Response(200, json={"code": 200, "status": "ok", "data": {"protocol": "https", "port": "443"}})
    if request.url.path == "/api/v2/services/ssh":
        return httpx.Response(200, json={"code": 200, "status": "ok", "data": {"enable": True, "port": "22"}})
    data = PFREST.get(request.url.path)
    if data is None:
        return httpx.Response(404, json={"code": 404, "status": "not found", "data": []})
    return httpx.Response(200, json={"code": 200, "status": "ok", "response_id": "SUCCESS", "data": data})


def test_pfsense_rest_v2():
    cfg = PfSenseAPIClient("https://pf.example.com", "pf-key", transport=httpx.MockTransport(pfrest_handler),
                           device_id="pf1").fetch()
    assert cfg.device_id == "pf1" and cfg.vendor == "pfsense"
    assert {n.name for n in cfg.networks} == {"WAN", "LAN", "IOT"}
    iot = next(r for r in cfg.rules if r.description == "IoT anything but LAN")
    assert iot.destination == "lan" and iot.destination_not
    admin = next(r for r in cfg.rules if r.description == "admin from anywhere")
    assert admin.destination == "wanip"
    bad = [r for r in cfg.rules if r.description == "no bad ports"]
    assert {r.interface for r in bad} == {"wan", "lan"}
    assert {(p.start, p.end) for p in bad[0].destination_ports} == {(23, 23), (135, 139)}
    fwd = cfg.port_forwards[0]
    assert fwd.internal_ip == "10.0.0.20" and fwd.internal_port == 443
    assert any(r.id == "anti-lockout" for r in cfg.rules)
    assert cfg.settings["ssh_enabled"] is True
    # behaviour
    assert not cfg.evaluate("10.0.20.5", "10.0.0.5", 80).allowed
    assert cfg.evaluate("10.0.20.5", "8.8.8.8", 80).allowed
    assert not cfg.evaluate("10.0.0.5", "8.8.8.8", 137).allowed
    assert cfg.evaluate("198.51.100.1", "203.0.113.10", 443).allowed
    assert cfg.evaluate("198.51.100.1", "10.0.0.20", 443).allowed
    checks = {f.evidence["check_id"] for f in analyze(cfg, "pf1")}
    assert {"wan-mgmt-exposed", "risky-port-forward", "no-remote-syslog"} <= checks   # 8443 is an admin port


def test_pfsense_rest_bad_key():
    with pytest.raises(httpx.HTTPStatusError):
        PfSenseAPIClient("https://pf.example.com", "nope", transport=httpx.MockTransport(pfrest_handler)).fetch()


def test_opnsense_backup_download():
    xml = (F / "opnsense.xml").read_bytes()
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        if request.url.path != "/api/core/backup/download/this":
            return httpx.Response(404)
        expected = "Basic " + base64.b64encode(b"k:s").decode()
        if seen["auth"] != expected:
            return httpx.Response(401)
        return httpx.Response(200, content=xml, headers={"content-type": "application/xml"})

    cfg = OPNsenseAPIClient("https://opn.example.com", "k", "s", transport=httpx.MockTransport(handler),
                            device_id="o1").fetch()
    assert cfg.vendor == "opnsense" and cfg.device_id == "o1"
    assert cfg.port_forwards[0].internal_ip == "10.20.0.15"


# --------------------------------------------------------------------------- #
def test_fetch_device_resolves_env_secrets(monkeypatch):
    monkeypatch.setenv("UNIFI_RO_PASSWORD", "pw")
    cfg = fetch_device({"id": "dev-1", "vendor": "unifi", "url": "https://unifi.example.com", "username": "ro",
                        "password_env": "UNIFI_RO_PASSWORD"},
                       transport=httpx.MockTransport(unifi_handler(LEGACY)))
    assert cfg.device_id == "dev-1" and cfg.vendor == "unifi"


def test_fetch_device_missing_env(monkeypatch):
    monkeypatch.delenv("NOPE_KEY", raising=False)
    with pytest.raises(ValueError, match="NOPE_KEY"):
        fetch_device({"vendor": "pfsense_api", "url": "https://pf", "api_key_env": "NOPE_KEY"})
    with pytest.raises(ValueError, match="api_key_env"):
        fetch_device({"vendor": "pfsense_api", "url": "https://pf", "api_key": "literal-secret-ignored"})


def test_fetch_device_files():
    cfg = fetch_device({"id": "x", "vendor": "xml", "path": str(F / "opnsense.xml")})
    assert cfg.vendor == "opnsense" and cfg.device_id == "x"
    cfg = fetch_device({"vendor": "pfsense_xml", "path": str(F / "pfsense_weak.xml")})
    assert cfg.vendor == "pfsense"
    cfg = fetch_device({"vendor": "unifi_json", "path": str(F / "unifi_zone.json")})
    assert cfg.settings["firewall_mode"] == "zone"
    with pytest.raises(ValueError):
        fetch_device({"vendor": "cisco"})
