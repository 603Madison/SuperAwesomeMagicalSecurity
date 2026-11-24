"""Syslog receivers (UDP + TCP) feeding the SIEM pipeline.

* UDP: one message per datagram (RFC 5426).
* TCP: RFC 6587 octet-counting (``<len> <msg>``) and non-transparent
  newline framing, auto-detected per frame.
* Messages > 64 KiB are truncated (UDP) or the connection is closed (TCP
  octet-count header claiming more).
* Per-peer token bucket rate limiting resists floods; excess messages are
  counted and dropped.
* Events are buffered and flushed to the pipeline every second or every 500
  events so the database sees batch transactions, not one per line.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from ..models import Event
from .parsers import parse_syslog

log = logging.getLogger("sams.siem.syslog")

MAX_MESSAGE = 65536
FLUSH_INTERVAL = 1.0
FLUSH_SIZE = 500


class _RateLimiter:
    def __init__(self, rate: float, burst: float):
        self.rate, self.burst = rate, burst
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, peer: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(peer, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._buckets[peer] = (tokens, now)
            return False
        self._buckets[peer] = (tokens - 1, now)
        if len(self._buckets) > 100000:
            self._buckets.clear()
        return True


class SyslogCollector:
    """Buffers parsed events and flushes them into the pipeline."""

    def __init__(self, pipeline: Any, rate_per_peer: float = 2000.0, burst: float = 5000.0):
        self.pipeline = pipeline
        self.limiter = _RateLimiter(rate_per_peer, burst)
        self._buf: list[Event] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._asset_cache: dict[tuple[str, str], tuple[float, Optional[str]]] = {}
        self.stats = {"received": 0, "dropped_rate": 0, "dropped_size": 0, "parsed": 0}

    def _asset(self, host: str, ip: str) -> Optional[str]:
        resolve = getattr(self.pipeline, "resolve_asset", None)
        if not resolve:
            return None
        key = (host, ip)
        hit = self._asset_cache.get(key)
        now = time.monotonic()
        if hit and now - hit[0] < 300:
            return hit[1]
        try:
            aid = resolve(host, ip)
        except Exception:
            aid = None
        if len(self._asset_cache) > 10000:
            self._asset_cache.clear()
        self._asset_cache[key] = (now, aid)
        return aid

    def handle(self, data: bytes, peer_ip: str) -> None:
        self.stats["received"] += 1
        if not self.limiter.allow(peer_ip):
            self.stats["dropped_rate"] += 1
            return
        if len(data) > MAX_MESSAGE:
            self.stats["dropped_size"] += 1
            data = data[:MAX_MESSAGE]
        try:
            ev = parse_syslog(data, peer_ip)
        except Exception:
            log.exception("syslog parse failed from %s", peer_ip)
            return
        if ev is None:
            return
        ev.asset_id = self._asset(ev.host, peer_ip)
        self.stats["parsed"] += 1
        self._buf.append(ev)
        if len(self._buf) >= FLUSH_SIZE:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            return
        batch, self._buf = self._buf, []
        try:
            self.pipeline.ingest_events(batch)
        except Exception:
            log.exception("pipeline ingest failed (%d events lost)", len(batch))

    async def run_flusher(self) -> None:
        try:
            while True:
                await asyncio.sleep(FLUSH_INTERVAL)
                if self._buf:
                    # ingestion touches sqlite; keep the event loop responsive
                    batch, self._buf = self._buf, []
                    await asyncio.get_running_loop().run_in_executor(None, self._ingest, batch)
        except asyncio.CancelledError:
            self.flush()
            raise

    def _ingest(self, batch: list[Event]) -> None:
        try:
            self.pipeline.ingest_events(batch)
        except Exception:
            log.exception("pipeline ingest failed (%d events lost)", len(batch))


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: SyslogCollector):
        self.collector = collector

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.collector.handle(data, addr[0])


async def _tcp_handler(collector: SyslogCollector, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    try:
        while True:
            first = await reader.read(1)
            if not first:
                break
            if first.isdigit():
                # octet counting: digits then SP then exactly N bytes
                digits = first
                while True:
                    c = await reader.readexactly(1)
                    if c == b" ":
                        break
                    if not c.isdigit() or len(digits) > 6:
                        raise ValueError("bad octet-count frame")
                    digits += c
                n = int(digits)
                if n > MAX_MESSAGE:
                    collector.stats["dropped_size"] += 1
                    raise ValueError("frame too large")
                msg = await reader.readexactly(n)
            else:
                try:
                    rest = await reader.readuntil(b"\n")
                except asyncio.LimitOverrunError:
                    collector.stats["dropped_size"] += 1
                    raise ValueError("line too long")
                except asyncio.IncompleteReadError as exc:
                    rest = exc.partial
                msg = first + rest
            msg = msg.rstrip(b"\r\n\x00")
            if msg:
                collector.handle(msg, peer_ip)
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve_syslog(pipeline: Any, bind: str = "0.0.0.0", udp_port: Optional[int] = 5514,
                       tcp_port: Optional[int] = 5514, collector: Optional[SyslogCollector] = None) -> list[Any]:
    """Start syslog listeners. Returns a list of handles (UDP transport,
    TCP ``asyncio.Server``, flusher task, and the ``SyslogCollector``); pass it
    to ``stop_syslog`` on shutdown. Port 0 picks an ephemeral port (see
    ``bound_ports``)."""
    loop = asyncio.get_running_loop()
    collector = collector or SyslogCollector(pipeline)
    handles: list[Any] = []
    if udp_port is not None:
        transport, _ = await loop.create_datagram_endpoint(lambda: _UDPProtocol(collector), local_addr=(bind, udp_port))
        handles.append(transport)
    if tcp_port is not None:
        server = await asyncio.start_server(lambda r, w: _tcp_handler(collector, r, w), bind, tcp_port,
                                            limit=MAX_MESSAGE + 16)
        handles.append(server)
    handles.append(asyncio.create_task(collector.run_flusher()))
    handles.append(collector)
    return handles


def bound_ports(handles: list[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in handles:
        if isinstance(h, asyncio.DatagramTransport):
            out["udp"] = h.get_extra_info("sockname")[1]
        elif isinstance(h, asyncio.AbstractServer):
            out["tcp"] = h.sockets[0].getsockname()[1]
    return out


async def stop_syslog(handles: list[Any]) -> None:
    for h in handles:
        if isinstance(h, asyncio.Task):
            h.cancel()
            try:
                await h
            except (asyncio.CancelledError, Exception):
                pass
        elif isinstance(h, asyncio.AbstractServer):
            h.close()
            await h.wait_closed()
        elif isinstance(h, asyncio.BaseTransport):
            h.close()
    for h in handles:
        if isinstance(h, SyslogCollector):
            h.flush()
