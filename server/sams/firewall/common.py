"""Helpers shared by the firewall adapters and analyzer."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional
from xml.etree import ElementTree as ET

RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# purpose -> trust level (higher = more trusted). Used to decide whether an
# allowed flow between two internal segments goes "uphill" (bad) or "downhill".
TRUST = {"mgmt": 5, "corporate": 4, "vpn": 4, "dmz": 2, "iot": 1, "guest": 0, "wan": -1}

_PURPOSE_PATTERNS = [
    ("guest", re.compile(r"guest|visitor|hotspot|public", re.I)),
    ("iot", re.compile(r"iot|camera|cctv|cam\b|smart|things|tv\b|media|printer|nvr|sensor", re.I)),
    ("dmz", re.compile(r"dmz|perimeter|exposed", re.I)),
    ("mgmt", re.compile(r"mgmt|management|admin|infra|oob|ipmi|bmc", re.I)),
    ("vpn", re.compile(r"vpn|wireguard|\bwg\d*|openvpn|ovpn|ipsec|tailscale", re.I)),
    ("wan", re.compile(r"^wan|internet|isp|uplink", re.I)),
]


def infer_purpose(name: str, vendor_purpose: str = "") -> str:
    """Classify a segment. Name hints (IoT, DMZ, ...) beat vendor defaults,
    because UniFi calls every VLAN "corporate"."""
    for purpose, rx in _PURPOSE_PATTERNS:
        if rx.search(name or ""):
            return purpose
    vp = (vendor_purpose or "").lower()
    if vp in ("wan", "guest", "dmz", "iot", "mgmt", "vpn"):
        return vp
    if vp in ("remote-user-vpn", "site-vpn", "vpn-client"):
        return "vpn"
    return "corporate"


def trust_level(purpose: str) -> int:
    return TRUST.get(purpose or "corporate", 4)


def safe_xml_fromstring(text: str | bytes) -> ET.Element:
    """Parse semi-trusted XML (firewall backups) refusing DTDs/entities."""
    try:
        import defusedxml.ElementTree as DET  # type: ignore

        return DET.fromstring(text, forbid_dtd=True)
    except ImportError:  # pragma: no cover - defusedxml is optional
        raw = text.decode("utf-8", "replace") if isinstance(text, bytes) else text
        if re.search(r"<!(DOCTYPE|ENTITY)", raw, re.I):
            raise ValueError("refusing XML with DTD/entity declarations")
        return ET.fromstring(raw)


def elem_to_dict(el: Optional[ET.Element]) -> Any:
    """Convert an element tree to plain JSON-able data for evidence.

    Empty leaf elements (pfSense flags such as ``<disabled/>``) become ``True``.
    Repeated child tags become lists.
    """
    if el is None:
        return None
    children = list(el)
    if not children:
        text = (el.text or "").strip()
        return text if text else True
    out: dict[str, Any] = {}
    for c in children:
        v = elem_to_dict(c)
        if c.tag in out:
            if not isinstance(out[c.tag], list):
                out[c.tag] = [out[c.tag]]
            out[c.tag].append(v)
        else:
            out[c.tag] = v
    return out


def text(el: Optional[ET.Element], path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def flag(el: Optional[ET.Element], path: str) -> bool:
    """pfSense/OPNsense booleans: present-and-empty, "yes", "on", "1", "enabled" are true."""
    if el is None:
        return False
    found = el.find(path)
    if found is None:
        return False
    t = (found.text or "").strip().lower()
    return t in ("", "yes", "on", "1", "true", "enabled")


def network_cidr(ip: str, prefix: str | int) -> Optional[str]:
    try:
        return str(ipaddress.ip_interface(f"{ip}/{prefix}").network)
    except ValueError:
        return None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def representative_host(cidr: str) -> Optional[str]:
    """A plausible client address inside ``cidr`` that is not the network/gateway address."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if net.num_addresses <= 2:
        return str(net.network_address)
    offset = 10 if net.num_addresses > 12 else 1
    return str(net.network_address + offset)

def ip_version_of(ipprotocol: str) -> "int | None":
    """pfSense/OPNsense ``ipprotocol`` (inet/inet6/inet46) -> 4/6/None."""
    return {"inet": 4, "inet6": 6}.get((ipprotocol or "").lower())
