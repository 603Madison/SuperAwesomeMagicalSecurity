"""OSV.dev access: online API client and an offline SQLite mirror.

* ``OSVClient`` -- ``/v1/querybatch`` + ``/v1/vulns/{id}`` with an on-disk
  cache, retries and bounded concurrency.
* ``LocalOSVDB`` -- mirror of the OSV bulk exports
  (``{osv_bulk}/{ecosystem}/all.zip``) for air-gapped / privacy-preserving
  matching. Matching follows the OSV schema evaluation rules.
* ``is_affected`` / ``fixed_for`` -- range evaluation shared by both paths.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import tempfile
import threading
import time
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import quote

import httpx

from ..config import VulnSettings
from . import versions
from .ecosystems import ecosystem_matches, name_matches, normalize_pypi

log = logging.getLogger(__name__)

Query = tuple[str, str, str]   # (ecosystem, name, version)


# --------------------------------------------------------------------------- #
# OSV range evaluation
# --------------------------------------------------------------------------- #
def _event_version(e: dict) -> tuple[str, str]:
    for k in ("introduced", "fixed", "last_affected", "limit"):
        if k in e:
            return k, str(e[k])
    return "", ""


def _sorted_events(ecosystem: str, events: list[dict]) -> list[tuple[str, str]]:
    evs = [_event_version(e) for e in events]
    evs = [(k, v) for k, v in evs if k]
    cmp = versions.comparator(ecosystem)

    def key_cmp(x: tuple[str, str], y: tuple[str, str]) -> int:
        # introduced "0" sorts first; otherwise by version, introduced before others on ties
        if x[1] == "0" and x[0] == "introduced":
            return -1 if not (y[1] == "0" and y[0] == "introduced") else 0
        if y[1] == "0" and y[0] == "introduced":
            return 1
        c = cmp(x[1], y[1])
        if c:
            return c
        order = {"introduced": 0, "last_affected": 1, "fixed": 2, "limit": 3}
        return order[x[0]] - order[y[0]]

    from functools import cmp_to_key
    return sorted(evs, key=cmp_to_key(key_cmp))


def range_affects(ecosystem: str, rng: dict, version: str) -> bool:
    if (rng.get("type") or "").upper() not in ("ECOSYSTEM", "SEMVER"):
        return False
    cmp = versions.comparator(ecosystem)
    events = _sorted_events(ecosystem, rng.get("events") or [])
    limits = [v for k, v in events if k == "limit"]
    if limits and "*" not in limits and not any(cmp(version, lim) < 0 for lim in limits):
        return False
    vulnerable = False
    for kind, ev in events:
        if kind == "introduced":
            if ev == "0" or cmp(version, ev) >= 0:
                vulnerable = True
        elif kind == "fixed":
            if cmp(version, ev) >= 0:
                vulnerable = False
        elif kind == "last_affected":
            if cmp(version, ev) > 0:
                vulnerable = False
    return vulnerable


def affected_entry_affects(ecosystem: str, affected: dict, version: str) -> bool:
    if version in (affected.get("versions") or []):
        return True
    return any(range_affects(ecosystem, r, version) for r in affected.get("ranges") or [])


def fixed_for(ecosystem: str, affected: dict, version: str) -> Optional[str]:
    """The lowest ``fixed`` version above ``version`` in any range that affects it."""
    cmp = versions.comparator(ecosystem)
    candidates: list[str] = []
    for rng in affected.get("ranges") or []:
        if (rng.get("type") or "").upper() not in ("ECOSYSTEM", "SEMVER"):
            continue
        for kind, ev in _sorted_events(ecosystem, rng.get("events") or []):
            if kind == "fixed" and cmp(ev, version) > 0:
                candidates.append(ev)
                break
    if not candidates:
        return None
    return min(candidates, key=versions.sort_key(ecosystem))


def matching_affected(vuln: dict, ecosystem: str, name: str) -> list[dict]:
    out = []
    for a in vuln.get("affected") or []:
        pkg = a.get("package") or {}
        if ecosystem_matches(ecosystem, pkg.get("ecosystem", "")) and name_matches(ecosystem, name, pkg.get("name", "")):
            out.append(a)
    return out


def evaluate(vuln: dict, ecosystem: str, name: str, version: str) -> tuple[Optional[bool], Optional[str], Optional[dict]]:
    """(affected?, fixed version, affected entry). ``affected`` is None when the
    record has no entry for this package (cannot judge)."""
    entries = matching_affected(vuln, ecosystem, name)
    if not entries:
        return None, None, None
    hit = [a for a in entries if affected_entry_affects(ecosystem, a, version)]
    if not hit:
        return False, None, entries[0]
    fixes = [f for f in (fixed_for(ecosystem, a, version) for a in hit) if f]
    fixed = versions.max_version(ecosystem, fixes) if fixes else None
    return True, fixed, hit[0]


# --------------------------------------------------------------------------- #
# Online client
# --------------------------------------------------------------------------- #
class OSVClient:
    BATCH = 1000

    def __init__(self, settings: VulnSettings, cache_dir: Path, transport: Optional[httpx.BaseTransport] = None,
                 max_workers: int = 8):
        self.settings = settings
        self.cache_dir = Path(cache_dir) / "osv"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = settings.cache_ttl_hours * 3600
        self.max_workers = max_workers
        self.http = httpx.Client(transport=transport, timeout=settings.timeout_seconds,
                                 headers={"User-Agent": "sams-vuln/0.1"}, follow_redirects=True)
        self._lock = threading.Lock()

    # -- caching ----------------------------------------------------------
    def _cache_path(self, kind: str, key: str) -> Path:
        h = hashlib.sha256(key.encode()).hexdigest()
        d = self.cache_dir / kind
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{h}.json"

    def _cache_get(self, kind: str, key: str) -> Any:
        p = self._cache_path(kind, key)
        try:
            if self.ttl > 0 and time.time() - p.stat().st_mtime < self.ttl:
                return json.loads(p.read_text())
        except (OSError, ValueError):
            pass
        return None

    def _cache_put(self, kind: str, key: str, value: Any) -> None:
        p = self._cache_path(kind, key)
        tmp = p.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(value))
            tmp.replace(p)
        except OSError as exc:
            log.debug("cache write failed: %s", exc)

    # -- http -------------------------------------------------------------
    def _request(self, method: str, url: str, **kw) -> httpx.Response:
        delay = 1.0
        last: Exception | None = None
        for attempt in range(4):
            try:
                r = self.http.request(method, url, **kw)
                if r.status_code == 429 or r.status_code >= 500:
                    last = httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
                else:
                    return r
            except httpx.TransportError as exc:
                last = exc
            if attempt < 3:
                time.sleep(delay)
                delay *= 2
        assert last is not None
        raise last

    def query_batch(self, queries: list[Query]) -> list[list[str]]:
        """Return vuln IDs per query (same order)."""
        results: list[Optional[list[str]]] = [None] * len(queries)
        todo: list[int] = []
        for i, q in enumerate(queries):
            cached = self._cache_get("q", "|".join(q))
            if cached is not None:
                results[i] = cached
            else:
                todo.append(i)
        for start in range(0, len(todo), self.BATCH):
            chunk = todo[start:start + self.BATCH]
            ids: dict[int, list[str]] = {i: [] for i in chunk}
            tokens: dict[int, Optional[str]] = {i: None for i in chunk}
            pending = list(chunk)
            while pending:
                body = {"queries": []}
                for i in pending:
                    eco, name, ver = queries[i]
                    qd: dict[str, Any] = {"package": {"ecosystem": eco, "name": name}, "version": ver}
                    if tokens[i]:
                        qd["page_token"] = tokens[i]
                    body["queries"].append(qd)
                r = self._request("POST", f"{self.settings.osv_api}/v1/querybatch", json=body)
                r.raise_for_status()
                res = r.json().get("results") or []
                nxt = []
                for i, item in zip(pending, res):
                    ids[i] += [v["id"] for v in (item or {}).get("vulns") or [] if v.get("id")]
                    tok = (item or {}).get("next_page_token")
                    if tok:
                        tokens[i] = tok
                        nxt.append(i)
                pending = nxt
            for i in chunk:
                uniq = sorted(set(ids[i]))
                results[i] = uniq
                self._cache_put("q", "|".join(queries[i]), uniq)
        return [r or [] for r in results]

    def get_vuln(self, vuln_id: str) -> Optional[dict]:
        cached = self._cache_get("v", vuln_id)
        if cached is not None:
            return cached
        r = self._request("GET", f"{self.settings.osv_api}/v1/vulns/{quote(vuln_id, safe='')}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
        self._cache_put("v", vuln_id, data)
        return data

    def get_vulns(self, ids: Iterable[str]) -> dict[str, dict]:
        ids = sorted(set(ids))
        out: dict[str, dict] = {}
        if not ids:
            return out

        def fetch(vid: str) -> tuple[str, Optional[dict]]:
            try:
                return vid, self.get_vuln(vid)
            except Exception as exc:   # noqa: BLE001 -- one bad record must not fail a scan
                log.warning("OSV fetch %s failed: %s", vid, exc)
                return vid, None

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for vid, data in pool.map(fetch, ids):
                if data:
                    out[vid] = data
        return out

    def download_bulk(self, ecosystem: str, dest: Path) -> Path:
        url = f"{self.settings.osv_bulk}/{quote(ecosystem, safe='')}/all.zip"
        with self.http.stream("GET", url, timeout=max(self.settings.timeout_seconds, 300)) as r:
            r.raise_for_status()
            with open(dest, "wb") as fh:
                for chunk in r.iter_bytes(1 << 20):
                    fh.write(chunk)
        return dest

    def close(self) -> None:
        self.http.close()


# --------------------------------------------------------------------------- #
# Offline mirror
# --------------------------------------------------------------------------- #
_LOCAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulns (id TEXT PRIMARY KEY, modified TEXT, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS affected (ecosystem TEXT NOT NULL, name TEXT NOT NULL, vuln_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS affected_pkg ON affected(ecosystem, name);
CREATE TABLE IF NOT EXISTS mirrored (ecosystem TEXT PRIMARY KEY, synced_at TEXT NOT NULL, count INTEGER NOT NULL);
"""


def _norm_name(ecosystem: str, name: str) -> str:
    return normalize_pypi(name) if versions.base_ecosystem(ecosystem) == "PyPI" else name


class LocalOSVDB:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_LOCAL_SCHEMA)

    def ecosystems(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._conn.execute("SELECT ecosystem FROM mirrored ORDER BY ecosystem")]

    def status(self) -> list[dict]:
        with self._lock:
            return [{"ecosystem": r[0], "synced_at": r[1], "count": r[2]}
                    for r in self._conn.execute("SELECT ecosystem, synced_at, count FROM mirrored ORDER BY ecosystem")]

    def covers(self, ecosystem: str) -> bool:
        return versions.base_ecosystem(ecosystem) in set(self.ecosystems())

    def import_zip(self, ecosystem: str, zip_path: Path) -> int:
        """Import an OSV bulk export. ``ecosystem`` is the top-level name
        (``Ubuntu``, ``PyPI``); rows are stored per full affected ecosystem."""
        base = versions.base_ecosystem(ecosystem)
        count = 0
        with zipfile.ZipFile(zip_path) as zf, self._lock:
            c = self._conn
            c.execute("BEGIN")
            try:
                c.execute("DELETE FROM affected WHERE ecosystem=? OR ecosystem LIKE ?", (base, base + ":%"))
                for info in zf.infolist():
                    if not info.filename.endswith(".json"):
                        continue
                    try:
                        vuln = json.loads(zf.read(info))
                    except ValueError:
                        continue
                    vid = vuln.get("id")
                    if not vid:
                        continue
                    raw = json.dumps(vuln, separators=(",", ":")).encode()
                    c.execute("INSERT INTO vulns(id, modified, data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE"
                              " SET modified=excluded.modified, data=excluded.data",
                              (vid, vuln.get("modified", ""), zlib.compress(raw, 6)))
                    seen = set()
                    for a in vuln.get("affected") or []:
                        pkg = a.get("package") or {}
                        eco, name = pkg.get("ecosystem", ""), pkg.get("name", "")
                        if versions.base_ecosystem(eco) != base or not name:
                            continue
                        key = (eco, _norm_name(eco, name))
                        if key in seen:
                            continue
                        seen.add(key)
                        c.execute("INSERT INTO affected(ecosystem, name, vuln_id) VALUES(?,?,?)", (*key, vid))
                    count += 1
                c.execute("INSERT INTO mirrored(ecosystem, synced_at, count) VALUES(?,?,?) ON CONFLICT(ecosystem)"
                          " DO UPDATE SET synced_at=excluded.synced_at, count=excluded.count",
                          (base, datetime.now(timezone.utc).isoformat(), count))
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
        return count

    def sync(self, ecosystem: str, client: OSVClient) -> int:
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "all.zip"
            client.download_bulk(versions.base_ecosystem(ecosystem), dest)
            return self.import_zip(ecosystem, dest)

    def get(self, vuln_id: str) -> Optional[dict]:
        with self._lock:
            r = self._conn.execute("SELECT data FROM vulns WHERE id=?", (vuln_id,)).fetchone()
        return json.loads(zlib.decompress(r[0])) if r else None

    def candidates(self, ecosystem: str, name: str) -> list[dict]:
        name = _norm_name(ecosystem, name)
        with self._lock:
            if ecosystem.startswith("Red Hat:enterprise_linux:"):
                major = ecosystem.split(":")[2]
                rows = self._conn.execute(
                    "SELECT DISTINCT v.data FROM affected a JOIN vulns v ON v.id=a.vuln_id"
                    " WHERE a.ecosystem LIKE ? AND a.name=?", (f"Red Hat:enterprise_linux:{major}::%", name)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT DISTINCT v.data FROM affected a JOIN vulns v ON v.id=a.vuln_id"
                    " WHERE a.ecosystem=? AND a.name=?", (ecosystem, name)).fetchall()
        return [json.loads(zlib.decompress(r[0])) for r in rows]

    def match(self, ecosystem: str, name: str, version: str) -> list[dict]:
        out = []
        for vuln in self.candidates(ecosystem, name):
            affected, _, _ = evaluate(vuln, ecosystem, name, version)
            if affected:
                out.append(vuln)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()
