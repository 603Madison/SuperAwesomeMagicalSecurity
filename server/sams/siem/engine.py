"""Stateful detection engine.

``DetectionEngine.process(events)`` evaluates every enabled rule against a
batch of events (sorted by timestamp) and returns new ``Alert`` objects.
State (sliding windows, sequence progress, seen values) lives in memory and is
pruned as time advances. Window arithmetic uses *event* timestamps, so replaying
historical logs produces the same alerts as live ingestion.

De-duplication: once a rule fires for a group (e.g. ``src_ip=203.0.113.7``) it
is suppressed for ``suppress_seconds`` -- tracked in memory by event time and,
when a ``Store`` is given, also checked against stored alerts so restarts don't
re-alert.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from ..models import Alert, Event, utcnow
from .rules import Rule, get_field, _MISSING

MAX_EVENT_IDS = 100
MAX_NEW_VALUES_PER_GROUP = 10000
PRUNE_EVERY = 1000


def _ts(ev: Event) -> float:
    return ev.timestamp.timestamp()


def _group(rule_fields: list[str], ev: Event) -> Optional[tuple[str, dict[str, Any]]]:
    vals: dict[str, Any] = {}
    for f in rule_fields:
        v = get_field(ev, f)
        if v is _MISSING or v in ("", None):
            return None
        vals[f] = v
    key = ",".join(f"{k}={v}" for k, v in vals.items())
    return key, vals


_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_.]+)\}")


def render(template: str, ev: Event, group: dict[str, Any], extra: Optional[dict[str, Any]] = None) -> str:
    def sub(m: re.Match) -> str:
        name = m.group(1)
        if extra and name in extra:
            return str(extra[name])
        if name in group:
            return str(group[name])
        v = get_field(ev, name)
        if v is _MISSING or v in ("", None):
            return "?"
        return str(v)
    return _PLACEHOLDER.sub(sub, template)


@dataclass
class _SeqState:
    idx: int = 0
    step_hits: deque = field(default_factory=deque)   # (ts, event_id) for current step
    start: float = 0.0
    event_ids: list = field(default_factory=list)
    last_ts: float = 0.0


class DetectionEngine:
    def __init__(self, rules: list[Rule], store: Any = None, suppress_seconds: int = 3600):
        self.rules = [r for r in rules if r.enabled]
        self.store = store
        self.suppress_seconds = suppress_seconds
        # threshold: (rule_id, group_key) -> deque[(ts, event_id, distinct_value)]
        self._windows: dict[tuple[str, str], deque] = defaultdict(deque)
        # sequence: (rule_id, group_key) -> _SeqState
        self._seq: dict[tuple[str, str], _SeqState] = {}
        # new_value: rule_id -> group_key -> set(values); rule_id -> first ts seen
        self._seen: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self._learn_start: dict[str, float] = {}
        # suppression (event time): (rule_id, group_key) -> ts
        self._suppressed: dict[tuple[str, str], float] = {}
        self._processed = 0
        self._latest_ts = 0.0

    # ------------------------------------------------------------------ #
    def set_rules(self, rules: list[Rule]) -> None:
        self.rules = [r for r in rules if r.enabled]

    def stats(self) -> dict[str, int]:
        return {"rules": len(self.rules), "threshold_windows": len(self._windows),
                "sequences": len(self._seq), "processed": self._processed}

    # ------------------------------------------------------------------ #
    def process(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for ev in sorted(events, key=_ts):
            t = _ts(ev)
            self._latest_ts = max(self._latest_ts, t)
            for rule in self.rules:
                try:
                    a = self._eval(rule, ev, t)
                except Exception:  # a broken rule must never break ingestion
                    a = None
                if a is not None:
                    alerts.append(a)
            self._processed += 1
            if self._processed % PRUNE_EVERY == 0:
                self._prune()
        return alerts

    # ------------------------------------------------------------------ #
    def _eval(self, rule: Rule, ev: Event, t: float) -> Optional[Alert]:
        if rule.type == "match":
            if not rule.selects(ev):
                return None
            return self._fire(rule, ev, t, "", {}, [ev], {})
        if rule.type == "threshold":
            return self._eval_threshold(rule, ev, t)
        if rule.type == "sequence":
            return self._eval_sequence(rule, ev, t)
        if rule.type == "new_value":
            return self._eval_new_value(rule, ev, t)
        return None

    def _eval_threshold(self, rule: Rule, ev: Event, t: float) -> Optional[Alert]:
        th = rule.threshold
        assert th is not None
        if not rule.selects(ev):
            return None
        g = _group(th.group_by, ev)
        if g is None:
            return None
        gkey, gvals = g
        dval = None
        if th.distinct:
            dval = get_field(ev, th.distinct)
            if dval is _MISSING or dval in ("", None):
                return None
        win = self._windows[(rule.id, gkey)]
        win.append((t, ev.id, dval, ev))
        cutoff = t - th.window_seconds
        while win and win[0][0] < cutoff:
            win.popleft()
        if th.distinct:
            distinct_vals = {x[2] for x in win}
            n = len(distinct_vals)
        else:
            distinct_vals = set()
            n = len(win)
        if n < th.count:
            return None
        evs = [x[3] for x in win]
        extra = {"count": n, "window_seconds": th.window_seconds}
        ctx = {"count": n, "window_seconds": th.window_seconds,
               "first_event_at": evs[0].timestamp.isoformat(), "last_event_at": ev.timestamp.isoformat()}
        if th.distinct:
            ctx["distinct_field"] = th.distinct
            ctx["distinct_values"] = sorted(map(str, distinct_vals))[:50]
            ctx["distinct_count"] = n
        alert = self._fire(rule, ev, t, gkey, gvals, evs, ctx, extra)
        if alert is not None:
            win.clear()
        return alert

    def _eval_sequence(self, rule: Rule, ev: Event, t: float) -> Optional[Alert]:
        seq = rule.sequence
        assert seq is not None
        if (rule.match or rule.any_of) and not rule.selects(ev):
            return None
        g = _group(seq.group_by, ev)
        if g is None:
            return None
        gkey, gvals = g
        key = (rule.id, gkey)
        st = self._seq.get(key)
        if st is not None and st.idx > 0 and t - st.start > seq.within_seconds:
            st = None
            self._seq.pop(key, None)
        if st is None:
            if not seq.steps[0].matches(ev):
                return None
            st = _SeqState(start=t)
            self._seq[key] = st
        step = seq.steps[st.idx]
        if not step.matches(ev):
            # evidence of continued earlier-step activity (e.g. more failures) is kept
            if any(s.matches(ev) for s in seq.steps[: st.idx]) and len(st.event_ids) < MAX_EVENT_IDS:
                st.event_ids.append(ev.id)
                st.last_ts = t
            return None
        st.step_hits.append((t, ev.id))
        st.last_ts = t
        if st.idx == 0:
            cutoff = t - seq.within_seconds
            while st.step_hits and st.step_hits[0][0] < cutoff:
                st.step_hits.popleft()
            st.start = st.step_hits[0][0] if st.step_hits else t
        if len(st.step_hits) < step.count:
            return None
        st.event_ids.extend(eid for _, eid in st.step_hits)
        st.step_hits.clear()
        st.idx += 1
        if st.idx < len(seq.steps):
            return None
        self._seq.pop(key, None)
        ctx = {"steps": len(seq.steps), "within_seconds": seq.within_seconds,
               "duration_seconds": round(t - st.start, 3), "sequence_events": len(st.event_ids)}
        return self._fire(rule, ev, t, gkey, gvals, [ev], ctx, extra_ids=st.event_ids)

    def _eval_new_value(self, rule: Rule, ev: Event, t: float) -> Optional[Alert]:
        nv = rule.new_value
        assert nv is not None
        if not rule.selects(ev):
            return None
        g = _group(nv.group_by, ev)
        if g is None:
            return None
        gkey, gvals = g
        val = get_field(ev, nv.field)
        if val is _MISSING or val in ("", None):
            return None
        start = self._learn_start.setdefault(rule.id, t)
        seen = self._seen[rule.id][gkey]
        sval = str(val).lower()
        if sval in seen:
            return None
        if len(seen) < MAX_NEW_VALUES_PER_GROUP:
            seen.add(sval)
        if t - start < nv.learning_seconds:
            return None
        gvals = {**gvals, nv.field: val}
        return self._fire(rule, ev, t, f"{gkey},{nv.field}={val}" if gkey else f"{nv.field}={val}", gvals, [ev],
                          {"new_field": nv.field, "new_value": str(val), "known_values": len(seen) - 1})

    # ------------------------------------------------------------------ #
    def _suppressed_now(self, rule: Rule, gkey: str, t: float) -> bool:
        k = (rule.id, gkey)
        last = self._suppressed.get(k)
        if last is not None and t - last < self.suppress_seconds:
            return True
        if self.store is not None and self.suppress_seconds > 0:
            try:
                if self.store.recent_alert_exists(rule.id, gkey, utcnow() - timedelta(seconds=self.suppress_seconds)):
                    self._suppressed[k] = t
                    return True
            except Exception:
                pass
        return False

    def _fire(self, rule: Rule, ev: Event, t: float, gkey: str, gvals: dict[str, Any], evs: list[Event],
              ctx: dict[str, Any], extra: Optional[dict[str, Any]] = None,
              extra_ids: Optional[list] = None) -> Optional[Alert]:
        # match rules without group_by suppress per (rule, host, event-ish identity) to avoid floods
        skey = gkey or f"host={ev.host},user={ev.user},src_ip={ev.src_ip}"
        if self._suppressed_now(rule, skey, t):
            return None
        self._suppressed[(rule.id, skey)] = t
        ids: list[int] = []
        for i in list(extra_ids or []) + [e.id for e in evs]:
            if i is not None and i not in ids:
                ids.append(i)
        ids = ids[-MAX_EVENT_IDS:]
        hosts = {e.host for e in evs if e.host}
        assets = {e.asset_id for e in evs if e.asset_id}
        context = {"group": {k: str(v) for k, v in gvals.items()}, **ctx, "tags": rule.tags,
                   "event_timestamp": ev.timestamp.isoformat()}
        if len(hosts) > 1:
            context["hosts"] = sorted(hosts)
        return Alert(
            rule_id=rule.id,
            title=render(rule.title, ev, gvals, extra),
            severity=rule.severity,
            asset_id=ev.asset_id or (next(iter(assets)) if len(assets) == 1 else None),
            host=ev.host,
            description=render(rule.description, ev, gvals, extra) if rule.description else "",
            event_ids=ids,
            group_key=skey,
            mitre=list(rule.mitre),
            context=context,
        )

    # ------------------------------------------------------------------ #
    def _prune(self) -> None:
        now = self._latest_ts
        by_id = {r.id: r for r in self.rules}
        for key in list(self._windows):
            r = by_id.get(key[0])
            win = self._windows[key]
            ws = r.threshold.window_seconds if r and r.threshold else 0
            if not win or win[-1][0] < now - ws:
                del self._windows[key]
        for key in list(self._seq):
            r = by_id.get(key[0])
            st = self._seq[key]
            within = r.sequence.within_seconds if r and r.sequence else 0
            if st.last_ts < now - within:
                del self._seq[key]
        horizon = self.suppress_seconds
        for key in list(self._suppressed):
            if self._suppressed[key] < now - horizon:
                del self._suppressed[key]
