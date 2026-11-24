"""SQLite persistence.

Deliberately small: a handful of tables holding JSON documents plus the
columns we filter on. SQLite in WAL mode handles a few thousand agents fine;
the ``Store`` interface is narrow so a Postgres implementation can be swapped
in later.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .models import Alert, Event, Finding, FindingStatus, Inventory, Task, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,              -- host | firewall | external | cloud
    name TEXT NOT NULL,
    criticality INTEGER NOT NULL DEFAULT 3,   -- 1 (low) .. 5 (crown jewel)
    tags TEXT NOT NULL DEFAULT '[]',
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,              -- host | probe
    asset_id TEXT,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    meta TEXT NOT NULL DEFAULT '{}',
    enrolled_at TEXT NOT NULL,
    last_seen TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT,
    uses_left INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS inventories (
    asset_id TEXT PRIMARY KEY,
    collected_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    key TEXT PRIMARY KEY,
    asset_id TEXT,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    data TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS findings_source ON findings(source, asset_id);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    asset_id TEXT,
    host TEXT,
    source TEXT,
    category TEXT,
    action TEXT,
    outcome TEXT,
    severity TEXT,
    user TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    message TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS events_host ON events(host);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    asset_id TEXT,
    host TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS firewall_devices (
    id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    name TEXT NOT NULL,
    connection TEXT NOT NULL DEFAULT '{}',  -- url, site, auth *reference* (env var name), verify_tls
    config TEXT,                            -- normalized FirewallConfig JSON
    fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tasks_agent ON tasks(agent_id, status);
CREATE TABLE IF NOT EXISTS external_targets (
    id TEXT PRIMARY KEY,
    value TEXT NOT NULL UNIQUE,      -- IP, CIDR (<= /24) or hostname we own
    kind TEXT NOT NULL,              -- ip | cidr | hostname | domain
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS external_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,            -- queued | claimed | done | failed
    created_at TEXT NOT NULL,
    claimed_by TEXT,
    claimed_at TEXT,
    finished_at TEXT,
    data TEXT NOT NULL               -- {"scope": signed scope doc, "result": ...}
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ #
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def _q(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(args)).fetchall()

    def _x(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(args))

    # ------------------------------------------------------------------ #
    # kv
    # ------------------------------------------------------------------ #
    def kv_get(self, key: str, default: Any = None) -> Any:
        rows = self._q("SELECT value FROM kv WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def kv_set(self, key: str, value: Any) -> None:
        self._x("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value, default=str)))

    # ------------------------------------------------------------------ #
    # assets
    # ------------------------------------------------------------------ #
    def upsert_asset(self, asset_id: str, kind: str, name: str, data: Optional[dict] = None,
                     criticality: Optional[int] = None, tags: Optional[list[str]] = None,
                     seen: bool = True) -> dict:
        now = _iso(utcnow())
        existing = self.get_asset(asset_id)
        if existing:
            merged = {**existing["data"], **(data or {})}
            self._x("UPDATE assets SET name=?, data=?, updated_at=?, last_seen=COALESCE(?, last_seen),"
                    " criticality=COALESCE(?, criticality), tags=COALESCE(?, tags) WHERE id=?",
                    (name, json.dumps(merged, default=str), now, now if seen else None, criticality,
                     json.dumps(tags) if tags is not None else None, asset_id))
        else:
            self._x("INSERT INTO assets(id,kind,name,criticality,tags,data,created_at,updated_at,last_seen)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (asset_id, kind, name, criticality or 3, json.dumps(tags or []),
                     json.dumps(data or {}, default=str), now, now, now if seen else None))
        return self.get_asset(asset_id)  # type: ignore[return-value]

    @staticmethod
    def _asset_row(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "kind": r["kind"], "name": r["name"], "criticality": r["criticality"],
                "tags": json.loads(r["tags"]), "data": json.loads(r["data"]),
                "created_at": r["created_at"], "updated_at": r["updated_at"], "last_seen": r["last_seen"]}

    def get_asset(self, asset_id: str) -> Optional[dict]:
        rows = self._q("SELECT * FROM assets WHERE id=?", (asset_id,))
        return self._asset_row(rows[0]) if rows else None

    def list_assets(self, kind: Optional[str] = None) -> list[dict]:
        if kind:
            rows = self._q("SELECT * FROM assets WHERE kind=? ORDER BY name", (kind,))
        else:
            rows = self._q("SELECT * FROM assets ORDER BY kind, name")
        return [self._asset_row(r) for r in rows]

    def update_asset_meta(self, asset_id: str, criticality: Optional[int] = None,
                          tags: Optional[list[str]] = None, data: Optional[dict] = None) -> Optional[dict]:
        a = self.get_asset(asset_id)
        if not a:
            return None
        if criticality is not None:
            self._x("UPDATE assets SET criticality=? WHERE id=?", (int(criticality), asset_id))
        if tags is not None:
            self._x("UPDATE assets SET tags=? WHERE id=?", (json.dumps(tags), asset_id))
        if data:
            merged = {**a["data"], **data}
            self._x("UPDATE assets SET data=? WHERE id=?", (json.dumps(merged, default=str), asset_id))
        return self.get_asset(asset_id)

    def delete_asset(self, asset_id: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM assets WHERE id=?", (asset_id,))
            c.execute("DELETE FROM inventories WHERE asset_id=?", (asset_id,))
            c.execute("DELETE FROM findings WHERE asset_id=?", (asset_id,))

    # ------------------------------------------------------------------ #
    # enrollment + agents
    # ------------------------------------------------------------------ #
    def create_enroll_token(self, kind: str = "host", label: str = "", uses: int = 1,
                            ttl_hours: Optional[int] = 24) -> str:
        token = secrets.token_urlsafe(24)
        exp = _iso(utcnow() + timedelta(hours=ttl_hours)) if ttl_hours else None
        self._x("INSERT INTO enroll_tokens(token_hash,kind,label,created_at,expires_at,uses_left) VALUES(?,?,?,?,?,?)",
                (hash_secret(token), kind, label, _iso(utcnow()), exp, uses))
        return token

    def consume_enroll_token(self, token: str) -> Optional[str]:
        """Returns the token kind if valid (and decrements uses), else None."""
        h = hash_secret(token)
        with self.tx() as c:
            r = c.execute("SELECT * FROM enroll_tokens WHERE token_hash=?", (h,)).fetchone()
            if not r or r["uses_left"] <= 0:
                return None
            if r["expires_at"] and datetime.fromisoformat(r["expires_at"]) < utcnow():
                return None
            c.execute("UPDATE enroll_tokens SET uses_left=uses_left-1 WHERE token_hash=?", (h,))
            return r["kind"]

    def create_agent(self, kind: str, name: str, asset_id: Optional[str], version: str = "",
                     meta: Optional[dict] = None) -> tuple[str, str]:
        agent_id = new_id("agt" if kind == "host" else "prb")
        key = secrets.token_urlsafe(32)
        self._x("INSERT INTO agents(id,kind,asset_id,name,key_hash,version,meta,enrolled_at,last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (agent_id, kind, asset_id, name, hash_secret(key), version, json.dumps(meta or {}),
                 _iso(utcnow()), _iso(utcnow())))
        return agent_id, key

    @staticmethod
    def _agent_row(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "kind": r["kind"], "asset_id": r["asset_id"], "name": r["name"],
                "version": r["version"], "meta": json.loads(r["meta"]), "enrolled_at": r["enrolled_at"],
                "last_seen": r["last_seen"], "revoked": bool(r["revoked"])}

    def authenticate_agent(self, agent_id: str, key: str) -> Optional[dict]:
        rows = self._q("SELECT * FROM agents WHERE id=? AND revoked=0", (agent_id,))
        if not rows:
            return None
        if not secrets.compare_digest(rows[0]["key_hash"], hash_secret(key)):
            return None
        self._x("UPDATE agents SET last_seen=? WHERE id=?", (_iso(utcnow()), agent_id))
        return self._agent_row(rows[0])

    def get_agent(self, agent_id: str) -> Optional[dict]:
        rows = self._q("SELECT * FROM agents WHERE id=?", (agent_id,))
        return self._agent_row(rows[0]) if rows else None

    def list_agents(self, kind: Optional[str] = None) -> list[dict]:
        rows = self._q("SELECT * FROM agents" + (" WHERE kind=?" if kind else "") + " ORDER BY name",
                       (kind,) if kind else ())
        return [self._agent_row(r) for r in rows]

    def set_agent_asset(self, agent_id: str, asset_id: str, version: str = "") -> None:
        self._x("UPDATE agents SET asset_id=?, version=COALESCE(NULLIF(?,''),version) WHERE id=?",
                (asset_id, version, agent_id))

    def revoke_agent(self, agent_id: str) -> None:
        self._x("UPDATE agents SET revoked=1 WHERE id=?", (agent_id,))

    # ------------------------------------------------------------------ #
    # inventory
    # ------------------------------------------------------------------ #
    def save_inventory(self, asset_id: str, inv: Inventory) -> None:
        self._x("INSERT INTO inventories(asset_id,collected_at,data) VALUES(?,?,?)"
                " ON CONFLICT(asset_id) DO UPDATE SET collected_at=excluded.collected_at, data=excluded.data",
                (asset_id, _iso(inv.collected_at), inv.model_dump_json()))

    def get_inventory(self, asset_id: str) -> Optional[Inventory]:
        rows = self._q("SELECT data FROM inventories WHERE asset_id=?", (asset_id,))
        return Inventory.model_validate_json(rows[0]["data"]) if rows else None

    def all_inventories(self) -> dict[str, Inventory]:
        return {r["asset_id"]: Inventory.model_validate_json(r["data"])
                for r in self._q("SELECT asset_id, data FROM inventories")}

    # ------------------------------------------------------------------ #
    # findings
    # ------------------------------------------------------------------ #
    def replace_findings(self, source: str, asset_id: Optional[str], findings: list[Finding]) -> dict:
        """Reconcile the full current set of findings from one analyzer for one
        asset: new ones are inserted, existing ones refreshed (keeping status
        and first_seen), and ones no longer reported are marked fixed."""
        now = utcnow()
        seen_keys = set()
        stats = {"new": 0, "updated": 0, "resolved": 0}
        with self.tx() as c:
            for f in findings:
                f.ensure_key()
                f.source = f.source or source
                f.asset_id = f.asset_id or asset_id
                seen_keys.add(f.key)
                r = c.execute("SELECT status, first_seen FROM findings WHERE key=?", (f.key,)).fetchone()
                if r:
                    status = r["status"]
                    if status == FindingStatus.fixed.value:
                        status = FindingStatus.open.value   # regression
                    f.status = FindingStatus(status)
                    f.first_seen = datetime.fromisoformat(r["first_seen"])
                    f.last_seen = now
                    c.execute("UPDATE findings SET severity=?, status=?, title=?, data=?, last_seen=?, category=?"
                              " WHERE key=?",
                              (f.severity.value, f.status.value, f.title, f.model_dump_json(), _iso(now),
                               f.category.value, f.key))
                    stats["updated"] += 1
                else:
                    f.first_seen = f.last_seen = now
                    c.execute("INSERT INTO findings(key,asset_id,category,severity,status,source,title,data,"
                              "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                              (f.key, f.asset_id, f.category.value, f.severity.value, f.status.value, f.source,
                               f.title, f.model_dump_json(), _iso(now), _iso(now)))
                    stats["new"] += 1
            if asset_id is None:
                rows = c.execute("SELECT key FROM findings WHERE source=? AND asset_id IS NULL AND status='open'",
                                 (source,)).fetchall()
            else:
                rows = c.execute("SELECT key FROM findings WHERE source=? AND asset_id=? AND status='open'",
                                 (source, asset_id)).fetchall()
            for r in rows:
                if r["key"] not in seen_keys:
                    c.execute("UPDATE findings SET status='fixed' WHERE key=?", (r["key"],))
                    stats["resolved"] += 1
        return stats

    def list_findings(self, asset_id: Optional[str] = None, status: Optional[str] = "open",
                      category: Optional[str] = None, severity: Optional[str] = None,
                      limit: int = 5000) -> list[Finding]:
        sql, args = "SELECT data, status FROM findings WHERE 1=1", []
        if asset_id:
            sql += " AND asset_id=?"; args.append(asset_id)
        if status:
            sql += " AND status=?"; args.append(status)
        if category:
            sql += " AND category=?"; args.append(category)
        if severity:
            sql += " AND severity=?"; args.append(severity)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self._q(sql, args):
            f = Finding.model_validate_json(r["data"])
            f.status = FindingStatus(r["status"])
            out.append(f)
        return out

    def get_finding(self, key: str) -> Optional[Finding]:
        rows = self._q("SELECT data, status FROM findings WHERE key=?", (key,))
        if not rows:
            return None
        f = Finding.model_validate_json(rows[0]["data"])
        f.status = FindingStatus(rows[0]["status"])
        return f

    def set_finding_status(self, key: str, status: FindingStatus) -> bool:
        cur = self._x("UPDATE findings SET status=? WHERE key=?", (status.value, key))
        return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # events / alerts
    # ------------------------------------------------------------------ #
    def insert_events(self, events: list[Event]) -> list[int]:
        ids = []
        with self.tx() as c:
            for e in events:
                cur = c.execute(
                    "INSERT INTO events(ts,asset_id,host,source,category,action,outcome,severity,user,src_ip,dst_ip,"
                    "message,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (_iso(e.timestamp), e.asset_id, e.host, e.source, e.category, e.action, e.outcome,
                     e.severity.value, e.user, e.src_ip, e.dst_ip, e.message,
                     e.model_dump_json(exclude={"id"})))
                e.id = cur.lastrowid
                ids.append(cur.lastrowid)
        return ids

    def search_events(self, q: Optional[str] = None, host: Optional[str] = None, src_ip: Optional[str] = None,
                      action: Optional[str] = None, user: Optional[str] = None, source: Optional[str] = None,
                      since: Optional[datetime] = None, until: Optional[datetime] = None,
                      limit: int = 200) -> list[Event]:
        sql, args = "SELECT id, data FROM events WHERE 1=1", []
        for col, val in (("host", host), ("src_ip", src_ip), ("action", action), ("user", user), ("source", source)):
            if val:
                sql += f" AND {col}=?"; args.append(val)
        if since:
            sql += " AND ts>=?"; args.append(_iso(since))
        if until:
            sql += " AND ts<=?"; args.append(_iso(until))
        if q:
            sql += " AND (message LIKE ? OR data LIKE ?)"; args += [f"%{q}%", f"%{q}%"]
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(min(limit, 5000))
        out = []
        for r in self._q(sql, args):
            e = Event.model_validate_json(r["data"])
            e.id = r["id"]
            out.append(e)
        return out

    def event_counts(self, since: datetime, group_by: str = "action") -> dict[str, int]:
        if group_by not in ("action", "source", "host", "category", "src_ip", "outcome"):
            raise ValueError("bad group_by")
        rows = self._q(f"SELECT {group_by} AS k, COUNT(*) AS n FROM events WHERE ts>=? GROUP BY {group_by}"
                       " ORDER BY n DESC LIMIT 50", (_iso(since),))
        return {(r["k"] or ""): r["n"] for r in rows}

    def insert_alert(self, a: Alert) -> int:
        cur = self._x("INSERT INTO alerts(rule_id,ts,severity,status,asset_id,host,data) VALUES(?,?,?,?,?,?,?)",
                      (a.rule_id, _iso(a.created_at), a.severity.value, a.status, a.asset_id, a.host,
                       a.model_dump_json(exclude={"id"})))
        a.id = cur.lastrowid
        return cur.lastrowid  # type: ignore[return-value]

    def list_alerts(self, status: Optional[str] = None, limit: int = 200) -> list[Alert]:
        sql, args = "SELECT id, status, data FROM alerts", []
        if status:
            sql += " WHERE status=?"; args.append(status)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self._q(sql, args):
            a = Alert.model_validate_json(r["data"])
            a.id, a.status = r["id"], r["status"]
            out.append(a)
        return out

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        rows = self._q("SELECT id, status, data FROM alerts WHERE id=?", (alert_id,))
        if not rows:
            return None
        a = Alert.model_validate_json(rows[0]["data"])
        a.id, a.status = rows[0]["id"], rows[0]["status"]
        return a

    def set_alert_status(self, alert_id: int, status: str) -> bool:
        return self._x("UPDATE alerts SET status=? WHERE id=?", (status, alert_id)).rowcount > 0

    def update_alert_context(self, alert_id: int, context: dict) -> None:
        a = self.get_alert(alert_id)
        if a:
            a.context.update(context)
            self._x("UPDATE alerts SET data=? WHERE id=?", (a.model_dump_json(exclude={"id"}), alert_id))

    def recent_alert_exists(self, rule_id: str, group_key: str, since: datetime) -> bool:
        rows = self._q("SELECT data FROM alerts WHERE rule_id=? AND ts>=?", (rule_id, _iso(since)))
        return any(json.loads(r["data"]).get("group_key") == group_key for r in rows)

    # ------------------------------------------------------------------ #
    # firewall devices
    # ------------------------------------------------------------------ #
    def upsert_firewall(self, device_id: str, vendor: str, name: str, connection: Optional[dict] = None,
                        config_json: Optional[str] = None) -> None:
        now = _iso(utcnow()) if config_json else None
        self._x("INSERT INTO firewall_devices(id,vendor,name,connection,config,fetched_at) VALUES(?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET vendor=excluded.vendor, name=excluded.name,"
                " connection=COALESCE(excluded.connection, connection),"
                " config=COALESCE(excluded.config, config), fetched_at=COALESCE(excluded.fetched_at, fetched_at)",
                (device_id, vendor, name, json.dumps(connection) if connection is not None else None,
                 config_json, now))

    def list_firewalls(self) -> list[dict]:
        return [{"id": r["id"], "vendor": r["vendor"], "name": r["name"],
                 "connection": json.loads(r["connection"] or "{}"),
                 "config": json.loads(r["config"]) if r["config"] else None, "fetched_at": r["fetched_at"]}
                for r in self._q("SELECT * FROM firewall_devices ORDER BY name")]

    def get_firewall(self, device_id: str) -> Optional[dict]:
        return next((f for f in self.list_firewalls() if f["id"] == device_id), None)

    def delete_firewall(self, device_id: str) -> None:
        self._x("DELETE FROM firewall_devices WHERE id=?", (device_id,))

    # ------------------------------------------------------------------ #
    # tasks
    # ------------------------------------------------------------------ #
    def save_task(self, t: Task) -> None:
        self._x("INSERT INTO tasks(id,agent_id,status,created_at,data) VALUES(?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data",
                (t.id, t.agent_id, t.status, _iso(t.created_at), t.model_dump_json()))

    def get_task(self, task_id: str) -> Optional[Task]:
        rows = self._q("SELECT data FROM tasks WHERE id=?", (task_id,))
        return Task.model_validate_json(rows[0]["data"]) if rows else None

    def list_tasks(self, agent_id: Optional[str] = None, status: Optional[str] = None, limit: int = 500) -> list[Task]:
        sql, args = "SELECT data FROM tasks WHERE 1=1", []
        if agent_id:
            sql += " AND agent_id=?"; args.append(agent_id)
        if status:
            sql += " AND status=?"; args.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        return [Task.model_validate_json(r["data"]) for r in self._q(sql, args)]

    # ------------------------------------------------------------------ #
    # external scope + jobs
    # ------------------------------------------------------------------ #
    def add_external_target(self, value: str, kind: str, note: str = "") -> dict:
        tid = new_id("ext")
        self._x("INSERT INTO external_targets(id,value,kind,note,created_at) VALUES(?,?,?,?,?)"
                " ON CONFLICT(value) DO UPDATE SET note=excluded.note",
                (tid, value, kind, note, _iso(utcnow())))
        return next(t for t in self.list_external_targets() if t["value"] == value)

    def list_external_targets(self) -> list[dict]:
        return [dict(r) for r in self._q("SELECT * FROM external_targets ORDER BY value")]

    def delete_external_target(self, target_id: str) -> None:
        self._x("DELETE FROM external_targets WHERE id=?", (target_id,))

    def create_external_job(self, scope: dict) -> str:
        jid = new_id("job")
        self._x("INSERT INTO external_jobs(id,status,created_at,data) VALUES(?,?,?,?)",
                (jid, "queued", _iso(utcnow()), json.dumps({"scope": scope})))
        return jid

    def claim_external_job(self, probe_id: str) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT * FROM external_jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if not r:
                return None
            c.execute("UPDATE external_jobs SET status='claimed', claimed_by=?, claimed_at=? WHERE id=?",
                      (probe_id, _iso(utcnow()), r["id"]))
            return {"id": r["id"], **json.loads(r["data"])}

    def finish_external_job(self, job_id: str, probe_id: str, result: dict, status: str = "done") -> bool:
        with self.tx() as c:
            r = c.execute("SELECT * FROM external_jobs WHERE id=?", (job_id,)).fetchone()
            if not r or r["claimed_by"] != probe_id:
                return False
            data = json.loads(r["data"])
            data["result"] = result
            c.execute("UPDATE external_jobs SET status=?, finished_at=?, data=? WHERE id=?",
                      (status, _iso(utcnow()), json.dumps(data, default=str), job_id))
            return True

    def list_external_jobs(self, limit: int = 50) -> list[dict]:
        out = []
        for r in self._q("SELECT * FROM external_jobs ORDER BY created_at DESC LIMIT ?", (limit,)):
            d = dict(r)
            d["data"] = json.loads(d["data"])
            out.append(d)
        return out

    def latest_external_result(self) -> Optional[dict]:
        rows = self._q("SELECT data FROM external_jobs WHERE status='done' ORDER BY finished_at DESC LIMIT 1")
        return json.loads(rows[0]["data"]).get("result") if rows else None
