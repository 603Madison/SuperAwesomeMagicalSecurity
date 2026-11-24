"""Map installed packages to OSV ecosystems and query names.

OSV identifiers (verified against api.osv.dev):

* Debian:  ``Debian:12``              -- matched on *source* package name/version
* Ubuntu:  ``Ubuntu:22.04:LTS`` / ``Ubuntu:24.10`` -- source package (``Ubuntu:Pro:*`` is out of scope)
* Alpine:  ``Alpine:v3.19``           -- origin (source) package
* RHEL:    ``Red Hat:enterprise_linux:9::baseos`` and ``...::appstream`` -- binary rpm names
* Rocky:   ``Rocky Linux:9``; AlmaLinux: ``AlmaLinux:9``
* openSUSE: ``openSUSE:Leap 15.5``, ``openSUSE:Tumbleweed``
* language ecosystems: ``PyPI``, ``npm``, ``Go``, ``crates.io``, ``RubyGems``, ``Packagist``, ``NuGet``, ``Maven``

Unsupported (returns ``None``; counted as unscanned): brew, Windows programs,
Fedora, Amazon Linux, CentOS Stream, SLES modules, Kali and other rolling derivatives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..models import OSInfo, Package

UBUNTU_CODENAMES = {
    "trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
    "kinetic": "22.10", "lunar": "23.04", "mantic": "23.10", "noble": "24.04", "oracular": "24.10",
    "plucky": "25.04", "questing": "25.10", "resolute": "26.04",
}
DEBIAN_CODENAMES = {"stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13",
                    "forky": "14"}

LANGUAGE_ECOSYSTEMS = {
    "pypi": "PyPI", "pip": "PyPI", "npm": "npm", "go": "Go", "golang": "Go", "cargo": "crates.io",
    "crates": "crates.io", "gem": "RubyGems", "rubygems": "RubyGems", "composer": "Packagist",
    "nuget": "NuGet", "maven": "Maven",
}


@dataclass(frozen=True)
class EcosystemQuery:
    ecosystem: str        # OSV ecosystem string
    name: str             # name as OSV knows it (source package for deb/apk)
    version: str          # version to match
    manager: str          # installed package manager
    binary_name: str      # name of the installed package (for remediation)


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _major(version_id: str) -> str:
    return (version_id or "").split(".")[0]


def _ids(os_info: OSInfo) -> set[str]:
    return {os_info.id.lower(), *[x.lower() for x in os_info.id_like]}


def ubuntu_ecosystem(os_info: OSInfo) -> Optional[str]:
    vid = ""
    if os_info.id.lower() == "ubuntu":
        vid = os_info.version_id
    if not re.match(r"^\d{2}\.\d{2}$", vid or ""):
        vid = UBUNTU_CODENAMES.get((os_info.codename or "").lower(), "")
    if not vid:
        return None
    yy, mm = vid.split(".")
    lts = mm == "04" and int(yy) % 2 == 0
    return f"Ubuntu:{vid}:LTS" if lts else f"Ubuntu:{vid}"


def debian_ecosystem(os_info: OSInfo) -> Optional[str]:
    major = _major(os_info.version_id)
    if not (major.isdigit() and 7 <= int(major) <= 20):
        major = DEBIAN_CODENAMES.get((os_info.codename or "").lower(), "")
    return f"Debian:{major}" if major else None


_BINNMU = re.compile(r"\+b\d+$")


def resolve(pkg: Package, os_info: OSInfo) -> Optional[list[EcosystemQuery]]:
    """Return the OSV queries for an installed package, or ``None`` if the
    package's ecosystem is not supported by OSV / this mapper."""
    mgr = (pkg.manager or "").lower()
    ids = _ids(os_info)

    if mgr in LANGUAGE_ECOSYSTEMS:
        eco = LANGUAGE_ECOSYSTEMS[mgr]
        name = normalize_pypi(pkg.name) if eco == "PyPI" else pkg.name
        return [EcosystemQuery(eco, name, pkg.version, mgr, pkg.name)]

    if mgr == "dpkg":
        if os_info.id.lower() == "ubuntu" or "ubuntu" in ids:
            eco = ubuntu_ecosystem(os_info)
        elif "debian" in ids:
            eco = debian_ecosystem(os_info)
        else:
            eco = None
        if not eco:
            return None
        name = pkg.source_name or pkg.name
        version = pkg.source_version or _BINNMU.sub("", pkg.version)
        return [EcosystemQuery(eco, name, version, mgr, pkg.name)]

    if mgr == "apk":
        if "alpine" not in ids:
            return None
        parts = (os_info.version_id or "").split(".")
        if len(parts) < 2:
            return None
        eco = f"Alpine:v{parts[0]}.{parts[1]}"
        return [EcosystemQuery(eco, pkg.source_name or pkg.name, pkg.version, mgr, pkg.name)]

    if mgr == "rpm":
        osid = os_info.id.lower()
        major = _major(os_info.version_id)
        version = pkg.version
        if osid == "rhel" and major:
            return [EcosystemQuery(f"Red Hat:enterprise_linux:{major}::{repo}", pkg.name, version, mgr, pkg.name)
                    for repo in ("baseos", "appstream")]
        if osid == "rocky" and major:
            return [EcosystemQuery(f"Rocky Linux:{major}", pkg.name, version, mgr, pkg.name)]
        if osid == "almalinux" and major:
            return [EcosystemQuery(f"AlmaLinux:{major}", pkg.name, version, mgr, pkg.name)]
        if osid == "opensuse-leap" and os_info.version_id:
            return [EcosystemQuery(f"openSUSE:Leap {os_info.version_id}", pkg.name, version, mgr, pkg.name)]
        if osid == "opensuse-tumbleweed":
            return [EcosystemQuery("openSUSE:Tumbleweed", pkg.name, version, mgr, pkg.name)]
        return None

    return None


def ecosystem_matches(query_eco: str, affected_eco: str) -> bool:
    """Whether an ``affected[].package.ecosystem`` applies to our query ecosystem."""
    if query_eco == affected_eco:
        return True
    rh = "Red Hat:enterprise_linux:"
    if query_eco.startswith(rh) and affected_eco.startswith(rh):
        # baseos/appstream/crb split is a repo detail; same major release matches
        return query_eco[len(rh):].split(":")[0] == affected_eco[len(rh):].split(":")[0]
    return False


def name_matches(ecosystem: str, query_name: str, affected_name: str) -> bool:
    if ecosystem == "PyPI":
        return normalize_pypi(query_name) == normalize_pypi(affected_name)
    return query_name == affected_name
