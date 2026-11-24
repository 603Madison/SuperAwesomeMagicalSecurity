"""Ingestion pipeline: parse -> store -> detect -> store alerts -> notify."""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Callable, Optional

from ..models import Alert, Event
from .engine import DetectionEngine
from .parsers import _parse_iso, parse_line

log = logging.getLogger("sams.siem")

MAX_LINES_PER_BATCH = 10000
MAX_LINE_BYTES = 65536


class SIEMPipeline:
    """Thread-safe front door for log data.

    ``resolve_asset(host, ip) -> asset_id | None`` maps a hostname / sender IP
    to an asset. ``on_alert(alert)`` is invoked after each alert is stored
    (e.g. to enrich it with the attack-graph blast radius); exceptions from it
    are logged and swallowed.
    """

    def __init__(self, store: Any, engine: DetectionEngine,
                 resolve_asset: Optional[Callable[[str, str], Optional[str]]] = None,
                 on_alert: Optional[Callable[[Alert], None]] = None):
        self.store = store
        self.engine = engine
        self.resolve_asset = resolve_asset
        self.on_alert = on_alert
        self._lock = threading.Lock()
        self.counters = {"lines": 0, "events": 0, "alerts": 0, "rejected": 0}

    def _resolve(self, host: str, ip: str) -> Optional[str]:
        if not self.resolve_asset:
            return None
        try:
            return self.resolve_asset(host, ip)
        except Exception:
            log.exception("resolve_asset failed")
            return None

    def ingest_lines(self, lines: list[dict], host: str = "", asset_id: Optional[str] = None) -> tuple[int, list[Alert]]:
        """Ingest agent-shipped lines: ``[{"source": ..., "line": ..., "ts": RFC3339?}, ...]``.
        Returns (events accepted, alerts raised)."""
        events: list[Event] = []
        for item in lines[:MAX_LINES_PER_BATCH]:
            if not isinstance(item, dict):
                self.counters["rejected"] += 1
                continue
            line = item.get("line")
            if not isinstance(line, str):
                self.counters["rejected"] += 1
                continue
            if len(line) > MAX_LINE_BYTES:
                line = line[:MAX_LINE_BYTES]
            ts: Optional[datetime] = None
            if item.get("ts"):
                ts = _parse_iso(str(item["ts"]))
            ev = parse_line(str(item.get("source") or "syslog"), line, host=host, ts=ts, asset_id=asset_id)
            if ev is None:
                continue
            if ev.asset_id is None:
                ev.asset_id = self._resolve(ev.host, "")
            events.append(ev)
        self.counters["lines"] += min(len(lines), MAX_LINES_PER_BATCH)
        self.counters["rejected"] += max(0, len(lines) - MAX_LINES_PER_BATCH)
        alerts = self.ingest_events(events)
        return len(events), alerts

    def ingest_events(self, events: list[Event]) -> list[Alert]:
        if not events:
            return []
        with self._lock:
            if self.store is not None:
                self.store.insert_events(events)
            self.counters["events"] += len(events)
            alerts = self.engine.process(events)
            for a in alerts:
                if self.store is not None:
                    self.store.insert_alert(a)
            self.counters["alerts"] += len(alerts)
        for a in alerts:
            if self.on_alert:
                try:
                    self.on_alert(a)
                except Exception:
                    log.exception("on_alert hook failed for %s", a.rule_id)
        return alerts
