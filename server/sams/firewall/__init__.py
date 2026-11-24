"""Firewall integrations: vendor adapters -> ``FirewallConfig`` -> analyzer findings.

Supported sources (``connection["vendor"]``):

* ``pfsense_api``: pfSense REST API v2 (``url``, ``api_key_env``)
* ``opnsense_api``: OPNsense config backup API (``url``, ``key_env``, ``secret_env``)
* ``unifi``: UniFi Network (``url``, ``site``, ``username`` + ``password_env`` or ``api_key_env``,
  ``is_unifi_os``)
* ``pfsense_xml`` / ``opnsense_xml`` / ``xml``: a ``config.xml`` backup at ``path``
* ``unifi_json``: an offline UniFi JSON export at ``path``

Secrets are only ever read from the environment variables named in the
connection, never from literal values stored in the connection dict.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .analyzer import RISKY_PORTS, analyze, exposed_services
from .model import Alias, Decision, FirewallConfig, Network, PortForward, PortRange, Rule
from .pfsense import parse_any_config, parse_config_xml
from .pfsense_api import OPNsenseAPIClient, PfSenseAPIClient, normalize_pfrest
from .unifi import UniFiClient, normalize_unifi

__all__ = [
    "Alias", "Decision", "FirewallConfig", "Network", "PortForward", "PortRange", "Rule",
    "RISKY_PORTS", "analyze", "exposed_services", "fetch_device", "parse_any_config", "parse_config_xml",
    "normalize_pfrest", "normalize_unifi", "PfSenseAPIClient", "OPNsenseAPIClient", "UniFiClient",
]

VENDORS = ("pfsense_api", "opnsense_api", "unifi", "pfsense_xml", "opnsense_xml", "xml", "unifi_json")


def _secret(conn: dict[str, Any], env_key: str, required: bool = True) -> str | None:
    name = conn.get(env_key)
    if not name:
        if required:
            raise ValueError(f"connection is missing '{env_key}' (name of the environment variable holding it)")
        return None
    from ..config import env_secret
    value = env_secret(str(name))
    if value is None and required:
        raise ValueError(f"environment variable {name!r} (from {env_key}) is not set")
    return value


def fetch_device(connection: dict[str, Any], transport: Any = None) -> FirewallConfig:
    """Fetch and normalize a firewall's configuration described by ``connection``."""
    vendor = str(connection.get("vendor", "")).lower()
    device_id = str(connection.get("id", ""))
    verify = bool(connection.get("verify_tls", True))
    if vendor == "pfsense_api":
        cfg = PfSenseAPIClient(connection["url"], _secret(connection, "api_key_env") or "", verify_tls=verify,
                               transport=transport, device_id=device_id).fetch()
    elif vendor == "opnsense_api":
        cfg = OPNsenseAPIClient(connection["url"], _secret(connection, "key_env") or "",
                                _secret(connection, "secret_env") or "", verify_tls=verify,
                                transport=transport, device_id=device_id).fetch()
    elif vendor == "unifi":
        api_key = _secret(connection, "api_key_env", required=False)
        password = None if api_key else _secret(connection, "password_env")
        cfg = UniFiClient(connection["url"], username=connection.get("username"), password=password,
                          api_key=api_key, site=connection.get("site", "default"),
                          verify_tls=bool(connection.get("verify_tls", False)),
                          is_unifi_os=bool(connection.get("is_unifi_os", True)), transport=transport,
                          device_id=device_id).fetch()
    elif vendor in ("pfsense_xml", "opnsense_xml", "xml"):
        data = Path(connection["path"]).read_bytes()
        if vendor == "xml":
            cfg = parse_any_config(data, device_id=device_id)
        else:
            cfg = parse_config_xml(data, vendor=vendor.split("_")[0], device_id=device_id)
    elif vendor == "unifi_json":
        cfg = normalize_unifi(json.loads(Path(connection["path"]).read_text()), device_id=device_id)
    else:
        raise ValueError(f"unknown firewall vendor {vendor!r}; expected one of {', '.join(VENDORS)}")
    if not cfg.device_id:
        cfg.device_id = device_id
    return cfg
