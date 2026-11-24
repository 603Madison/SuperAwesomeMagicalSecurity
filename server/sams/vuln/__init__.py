"""Vulnerability engine: OSV matching (online or local mirror), CVSS, KEV/EPSS enrichment."""
from .scanner import PackageVulns, VulnScanner, suggest_ecosystems, sync_ecosystems

__all__ = ["VulnScanner", "PackageVulns", "sync_ecosystems", "suggest_ecosystems"]
