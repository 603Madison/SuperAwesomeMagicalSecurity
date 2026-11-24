"""Threat-intel enrichment: CISA KEV and FIRST EPSS.

Both are optional. Every network failure degrades to "no data" (with a
warning) and stale cache is preferred over nothing.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Iterable, Optional

import httpx

from ..config import VulnSettings

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class ThreatIntel:
    EPSS_BATCH = 100

    def __init__(self, settings: VulnSettings, cache_dir: Path, transport: Optional[httpx.BaseTransport] = None):
        self.settings = settings
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = settings.cache_ttl_hours * 3600
        self.http = httpx.Client(transport=transport, timeout=settings.timeout_seconds,
                                 headers={"User-Agent": "sams-vuln/0.1"}, follow_redirects=True)
        self._kev: Optional[dict[str, dict]] = None

    # ------------------------------------------------------------------ #
    def kev(self) -> dict[str, dict]:
        """CVE id -> {date_added, due_date, ransomware, vendor, product, name}."""
        if not self.settings.enrich:
            return {}
        if self._kev is not None:
            return self._kev
        path = self.cache_dir / "kev.json"
        raw: Optional[dict] = None
        fresh = path.exists() and time.time() - path.stat().st_mtime < self.ttl
        if fresh:
            try:
                raw = json.loads(path.read_text())
            except ValueError:
                raw = None
        if raw is None:
            try:
                r = self.http.get(self.settings.kev_url)
                r.raise_for_status()
                raw = r.json()
                path.write_text(json.dumps(raw))
            except Exception as exc:   # noqa: BLE001
                log.warning("KEV download failed: %s", exc)
                if path.exists():
                    try:
                        raw = json.loads(path.read_text())
                    except ValueError:
                        raw = None
        out: dict[str, dict] = {}
        for v in (raw or {}).get("vulnerabilities") or []:
            cve = v.get("cveID")
            if cve:
                out[cve] = {
                    "date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                    "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                    "vendor": v.get("vendorProject"), "product": v.get("product"),
                    "name": v.get("vulnerabilityName"),
                }
        self._kev = out
        return out

    # ------------------------------------------------------------------ #
    def epss(self, cves: Iterable[str]) -> dict[str, float]:
        """CVE id -> EPSS probability (0..1)."""
        if not self.settings.enrich:
            return {}
        wanted = sorted({c for c in cves if CVE_RE.match(c or "")})
        if not wanted:
            return {}
        path = self.cache_dir / "epss.json"
        try:
            cache: dict[str, dict] = json.loads(path.read_text()) if path.exists() else {}
        except ValueError:
            cache = {}
        now = time.time()
        missing = [c for c in wanted if c not in cache or now - cache[c].get("t", 0) > self.ttl]
        changed = False
        for i in range(0, len(missing), self.EPSS_BATCH):
            chunk = missing[i:i + self.EPSS_BATCH]
            try:
                r = self.http.get(self.settings.epss_api, params={"cve": ",".join(chunk)})
                r.raise_for_status()
                got = {d["cve"]: d for d in r.json().get("data") or [] if d.get("cve")}
            except Exception as exc:   # noqa: BLE001
                log.warning("EPSS lookup failed: %s", exc)
                break
            for c in chunk:
                d = got.get(c)
                cache[c] = {"t": now, "epss": float(d["epss"]) if d and d.get("epss") is not None else None,
                            "pct": float(d["percentile"]) if d and d.get("percentile") is not None else None}
            changed = True
        if changed:
            try:
                path.write_text(json.dumps(cache))
            except OSError:
                pass
        return {c: cache[c]["epss"] for c in wanted if c in cache and cache[c].get("epss") is not None}

    def close(self) -> None:
        self.http.close()
