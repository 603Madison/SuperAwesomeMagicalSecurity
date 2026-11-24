import asyncio
from pathlib import Path

import pytest

from sams.db import Store
from sams.siem import DetectionEngine, SIEMPipeline, load_rules, parse_line
from sams.siem import syslog as syslog_mod
from sams.siem.syslog import bound_ports, serve_syslog, stop_syslog

FIX = Path(__file__).parent / "fixtures" / "siem"


def make_pipeline(**kw):
    store = Store(":memory:")
    return store, SIEMPipeline(store, DetectionEngine(load_rules(), store=store), **kw)


def test_ingest_lines_end_to_end():
    seen = []
    store, pipe = make_pipeline(resolve_asset=lambda host, ip: "asset-" + host if host else None,
                                on_alert=seen.append)
    lines = [{"source": "auth.log",
              "line": f"Nov 24 10:00:{i:02d} web01 sshd[1]: Failed password for root from 203.0.113.7 port {4000 + i} ssh2"}
             for i in range(12)]
    # BSD timestamps carry no year (inferred); give the journald line the same inferred day
    year = parse_line("auth.log", lines[0]["line"]).timestamp.year
    lines.append({"source": "journald", "line": f"{year}-11-24T10:00:30Z web01 sshd[2]: Accepted password for root from 203.0.113.7 port 5000 ssh2",
                  "ts": f"{year}-11-24T10:00:30Z"})
    lines.append({"source": "auth.log", "line": ""})              # blank: skipped
    lines.append({"source": "auth.log", "line": 12345})           # wrong type: rejected
    lines.append("garbage")                                       # not a dict: rejected
    n, alerts = pipe.ingest_lines(lines, host="web01", asset_id="a-web01")
    assert n == 13
    rule_ids = {a.rule_id for a in alerts}
    assert {"ssh_bruteforce", "ssh_bruteforce_success", "ssh_root_login"} <= rule_ids
    assert pipe.counters["rejected"] == 2
    stored = store.search_events(src_ip="203.0.113.7", limit=100)
    assert len(stored) == 13 and all(e.asset_id == "a-web01" and e.id for e in stored)
    assert {a.rule_id for a in store.list_alerts()} == rule_ids
    assert seen and all(a.id for a in seen)
    brute = next(a for a in alerts if a.rule_id == "ssh_bruteforce")
    assert brute.event_ids and all(isinstance(i, int) for i in brute.event_ids)
    assert brute.asset_id == "a-web01"


def test_ingest_resolves_asset_when_missing():
    store, pipe = make_pipeline(resolve_asset=lambda host, ip: "resolved" if host == "web01" else None)
    n, _ = pipe.ingest_lines([{"source": "auth.log", "line": "Nov 24 10:00:00 web01 CRON[1]: (root) CMD (true)"}])
    assert n == 1 and store.search_events()[0].asset_id == "resolved"


def test_on_alert_exception_is_swallowed():
    def boom(a):
        raise RuntimeError("x")
    store, pipe = make_pipeline(on_alert=boom)
    _, alerts = pipe.ingest_lines([{"source": "auth.log",
                                    "line": "Nov 24 10:00:00 web01 useradd[1]: new user: name=evil, UID=0, GID=0"}])
    assert alerts and store.list_alerts()


def test_alerts_deduplicated_across_batches():
    store, pipe = make_pipeline()
    line = {"source": "auth.log", "line": "Nov 24 10:00:00 web01 sudo:  bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh"}
    pipe.ingest_lines([line])
    pipe.ingest_lines([line])
    assert len([a for a in store.list_alerts() if a.rule_id == "sudo_denied"]) == 1


@pytest.mark.asyncio
async def test_syslog_udp_and_tcp(monkeypatch):
    monkeypatch.setattr(syslog_mod, "FLUSH_INTERVAL", 0.05)
    store, pipe = make_pipeline(resolve_asset=lambda host, ip: "fw-asset" if host == "fw.home" else None)
    handles = await serve_syslog(pipe, bind="127.0.0.1", udp_port=0, tcp_port=0)
    ports = bound_ports(handles)
    try:
        loop = asyncio.get_running_loop()
        # UDP
        transport, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=("127.0.0.1", ports["udp"]))
        for l in (FIX / "filterlog.log").read_text().splitlines():
            transport.sendto(l.encode())
        transport.close()
        # TCP: mix of octet-counted and newline-framed messages on one connection
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["tcp"])
        m1 = b"<4>Nov 24 10:06:01 UDM-Pro kernel: [WAN_IN-3010-D]IN=eth8 OUT=br0 SRC=198.51.100.77 DST=192.168.1.30 PROTO=TCP SPT=1 DPT=8443"
        m2 = b"<38>Nov 24 10:00:02 web01 sshd[5]: Failed password for bob from 203.0.113.99 port 22 ssh2"
        writer.write(str(len(m1)).encode() + b" " + m1)
        writer.write(m2 + b"\n")
        writer.write(b"<38>Nov 24 10:00:03 web01 app: no trailing newline")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        for _ in range(100):
            await asyncio.sleep(0.05)
            if len(store.search_events(limit=100)) >= 8:
                break
    finally:
        await stop_syslog(handles)
    evs = store.search_events(limit=100)
    assert len(evs) == 8
    fl = [e for e in evs if e.source == "filterlog"]
    assert len(fl) == 5 and all(e.asset_id == "fw-asset" for e in fl)
    assert any(e.source == "unifi" and e.dst_port == 8443 for e in evs)
    assert any(e.action == "ssh_failed" and e.src_ip == "203.0.113.99" for e in evs)
    assert any(e.message == "no trailing newline" for e in evs)


@pytest.mark.asyncio
async def test_syslog_tcp_rejects_oversized_frame():
    store, pipe = make_pipeline()
    handles = await serve_syslog(pipe, bind="127.0.0.1", udp_port=None, tcp_port=0)
    port = bound_ports(handles)["tcp"]
    collector = handles[-1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"999999 " + b"x" * 10)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout=2)   # server closes the connection
        assert data == b""
        writer.close()
    finally:
        await stop_syslog(handles)
    assert collector.stats["dropped_size"] == 1 and store.search_events() == []


def test_rate_limiter_drops_floods():
    store, pipe = make_pipeline()
    col = syslog_mod.SyslogCollector(pipe, rate_per_peer=1, burst=5)
    for _ in range(50):
        col.handle(b"<14>Nov 24 10:00:00 h app: x", "10.0.0.5")
    col.handle(b"<14>Nov 24 10:00:00 h app: y", "10.0.0.6")
    col.flush()
    assert col.stats["dropped_rate"] >= 44
    assert len(store.search_events(limit=100)) == 6
