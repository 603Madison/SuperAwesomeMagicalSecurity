"""Attack graph construction and analysis.

See docs/ARCHITECTURE.md ("Attack graph model") for the node/edge vocabulary.

Every edge is backed by evidence an agent, firewall or probe actually reported,
and carries:

* ``likelihood``: rough probability an attacker holding ``src`` achieves ``dst``.
* ``technique``: MITRE ATT&CK technique id.
* ``fixes``: remediation keys that would remove the edge. Where a matching
  finding exists, the fix key *is* the finding key, so the remediation planner
  can tie risk reduction straight back to findings.

Path probability is the product of edge likelihoods (max-probability path, an
under-approximation of the true union probability that is easy to explain).
"""
from __future__ import annotations

import heapq
import ipaddress
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..config import Settings
from ..db import Store
from ..firewall.model import FirewallConfig
from ..models import Finding, Inventory, Listener

# --------------------------------------------------------------------------- #
# types
# --------------------------------------------------------------------------- #
INTERNET = "internet"
ANY_USER = "*"      # an arbitrary unprivileged account (e.g. gained by password guessing)


@dataclass
class Node:
    id: str
    kind: str                    # internet | foothold | netpos | cred | data | cloud | ext
    label: str
    asset_id: Optional[str] = None
    criticality: int = 0         # 0 = not a target; 1..5
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label, "asset_id": self.asset_id,
                "criticality": self.criticality, **({"attrs": self.attrs} if self.attrs else {})}


@dataclass
class Edge:
    src: str
    dst: str
    name: str                    # exploit_remote | ssh_key | sudo | docker_group | ... (stable vocabulary)
    technique: str
    likelihood: float
    description: str
    fixes: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def weight(self) -> float:
        return -math.log(max(min(self.likelihood, 0.999999), 1e-9))

    def to_dict(self) -> dict:
        return {"src": self.src, "dst": self.dst, "name": self.name, "technique": self.technique,
                "likelihood": round(self.likelihood, 4), "description": self.description,
                "fixes": self.fixes, "evidence": self.evidence}


@dataclass
class Fix:
    key: str
    kind: str                    # patch | config | access | credential | firewall | manual
    title: str
    asset_ids: list[str] = field(default_factory=list)
    details: str = ""
    commands: list[str] = field(default_factory=list)
    finding_key: Optional[str] = None


# MITRE ATT&CK technique ids used below
T_EXPLOIT_PUBLIC = "T1190"
T_EXPLOIT_REMOTE = "T1210"
T_BRUTE = "T1110"
T_VALID_ACCOUNTS = "T1078"
T_SSH = "T1021.004"
T_PRIV_KEYS = "T1552.004"
T_CREDS_FILES = "T1552.001"
T_SUDO = "T1548.003"
T_SUID = "T1548.001"
T_PRIVESC_EXPLOIT = "T1068"
T_ESCAPE = "T1611"
T_CRON = "T1053.003"
T_PATH = "T1574.007"
T_LOCAL_DATA = "T1005"
T_CLOUD = "T1078.004"

PROCESS_PACKAGE_HINTS = {
    "sshd": ["openssh-server", "openssh", "openssh-portable"],
    "nginx": ["nginx", "nginx-core", "nginx-common"],
    "apache2": ["apache2", "apache2-bin"], "httpd": ["httpd", "apache2"],
    "mysqld": ["mysql-server", "mysql-server-core-8.0", "mariadb-server", "mysql"],
    "mariadbd": ["mariadb-server", "mariadb-server-core"],
    "postgres": ["postgresql", "postgresql-14", "postgresql-15", "postgresql-16", "postgresql-17"],
    "named": ["bind9", "bind"], "smbd": ["samba"], "exim4": ["exim4", "exim4-daemon-light"],
    "master": ["postfix"], "dovecot": ["dovecot-core", "dovecot"], "vsftpd": ["vsftpd"],
    "proftpd": ["proftpd-basic", "proftpd"], "redis-server": ["redis-server", "redis"],
    "mongod": ["mongodb-org-server", "mongodb-server"], "cupsd": ["cups", "cups-daemon"],
    "dnsmasq": ["dnsmasq", "dnsmasq-base"], "rpcbind": ["rpcbind"], "squid": ["squid"],
    "haproxy": ["haproxy"], "memcached": ["memcached"], "xrdp": ["xrdp"], "vncserver": ["tigervnc"],
}
DATASTORE_PORTS = {5432: "postgresql", 3306: "mysql", 27017: "mongodb", 6379: "redis", 9200: "elasticsearch",
                   1433: "mssql", 5984: "couchdb", 11211: "memcached", 445: "smb_share", 2049: "nfs_export",
                   8086: "influxdb"}
AUTH_SERVICES = {22: "ssh", 3389: "rdp", 5900: "vnc", 23: "telnet", 21: "ftp", 5985: "winrm", 5986: "winrm"}
SENSITIVITY_CRIT = {"restricted": 5, "confidential": 4, "internal": 3, "unknown": 3}


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


# --------------------------------------------------------------------------- #
# Graph
# --------------------------------------------------------------------------- #
class AttackGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.out: dict[str, list[Edge]] = defaultdict(list)
        self.fixes: dict[str, Fix] = {}
        self.notes: list[str] = []
        self.add_node(Node(INTERNET, "internet", "Internet (external attacker)"))

    # ---- construction --------------------------------------------------- #
    def add_node(self, n: Node) -> Node:
        cur = self.nodes.get(n.id)
        if cur is None:
            self.nodes[n.id] = n
            return n
        cur.criticality = max(cur.criticality, n.criticality)
        return cur

    def add_edge(self, e: Edge) -> None:
        if e.src not in self.nodes or e.dst not in self.nodes or e.src == e.dst:
            return
        # keep only the strongest edge per (src, dst, name) but merge fixes
        for ex in self.out[e.src]:
            if ex.dst == e.dst and ex.name == e.name:
                for f in e.fixes:
                    if f not in ex.fixes:
                        ex.fixes.append(f)
                if e.likelihood > ex.likelihood:
                    ex.likelihood, ex.description, ex.evidence = e.likelihood, e.description, e.evidence
                return
        self.edges.append(e)
        self.out[e.src].append(e)

    def add_fix(self, fx: Fix) -> str:
        if fx.key not in self.fixes:
            self.fixes[fx.key] = fx
        else:
            for a in fx.asset_ids:
                if a not in self.fixes[fx.key].asset_ids:
                    self.fixes[fx.key].asset_ids.append(a)
        return fx.key

    # ---- queries -------------------------------------------------------- #
    def dijkstra(self, source: str, min_likelihood: float = 0.0,
                 removed_fixes: Optional[set[str]] = None) -> tuple[dict[str, float], dict[str, Edge]]:
        """Max-probability paths from ``source``. Returns (prob, predecessor edge)."""
        removed = removed_fixes or set()
        best: dict[str, float] = {source: 1.0}
        pred: dict[str, Edge] = {}
        heap = [(0.0, source)]
        floor = -math.log(min_likelihood) if min_likelihood > 0 else math.inf
        while heap:
            d, u = heapq.heappop(heap)
            if d > -math.log(best.get(u, 1e-300)) + 1e-12:
                continue
            for e in self.out.get(u, ()):
                if removed and any(f in removed for f in e.fixes):
                    continue
                nd = d + e.weight
                if nd > floor:
                    continue
                p = math.exp(-nd)
                if p > best.get(e.dst, 0.0) + 1e-12:
                    best[e.dst] = p
                    pred[e.dst] = e
                    heapq.heappush(heap, (nd, e.dst))
        return best, pred

    def _path(self, pred: dict[str, Edge], target: str) -> list[Edge]:
        path: list[Edge] = []
        cur = target
        seen = set()
        while cur in pred and cur not in seen:
            seen.add(cur)
            e = pred[cur]
            path.append(e)
            cur = e.src
        return list(reversed(path))

    def resolve_start(self, start: str) -> str:
        if start in self.nodes:
            return start
        for candidate in (f"host:{start}#root", f"host:{start}"):
            if candidate in self.nodes:
                return candidate
        # allow lookup by hostname label
        for n in self.nodes.values():
            if n.kind == "foothold" and n.attrs.get("privilege") == "root" and n.attrs.get("hostname") == start:
                return n.id
        raise KeyError(f"unknown node or asset: {start}")

    def targets(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.criticality > 0]

    def blast_radius(self, start: str, min_likelihood: float = 0.05) -> dict:
        src = self.resolve_start(start)
        prob, pred = self.dijkstra(src, min_likelihood)
        start_asset = self.nodes[src].asset_id
        start_is_root = self.nodes[src].attrs.get("privilege") == "root"
        reachable = []
        for nid, p in sorted(prob.items(), key=lambda kv: -kv[1]):
            if nid == src:
                continue
            n = self.nodes[nid]
            if n.kind == "netpos":
                continue
            if (n.kind == "foothold" and start_asset and n.asset_id == start_asset
                    and (start_is_root or n.attrs.get("privilege") != "root")):
                continue   # lateral moves between accounts on the start host are noise; escalation to root is not
            path = self._path(pred, nid)
            reachable.append({"node": nid, "kind": n.kind, "label": n.label, "asset_id": n.asset_id,
                              "criticality": n.criticality, "likelihood": round(p, 4), "hops": len(path),
                              "path": [e.to_dict() for e in path]})
        hosts = {r["asset_id"] for r in reachable if r["kind"] == "foothold" and r["asset_id"] != start_asset}
        rooted = {r["asset_id"] for r in reachable if r["kind"] == "foothold" and r["node"].endswith("#root")
                  and r["asset_id"] != start_asset}
        summary = {
            "hosts": len(hosts), "hosts_root": len(rooted),
            "datastores": sum(1 for r in reachable if r["kind"] == "data"),
            "credentials": sum(1 for r in reachable if r["kind"] == "cred"),
            "cloud": sum(1 for r in reachable if r["kind"] == "cloud"),
            "external_systems": sum(1 for r in reachable if r["kind"] == "ext"),
            "critical": [{"node": r["node"], "label": r["label"], "likelihood": r["likelihood"]}
                         for r in reachable if r["criticality"] >= 4][:25],
            "risk": round(sum(r["criticality"] * r["likelihood"] for r in reachable if r["criticality"]), 3),
        }
        # Which fixes would shrink this blast radius the most? (cheap: count reachable targets per fix on paths)
        fix_hits: dict[str, float] = defaultdict(float)
        for r in reachable:
            if not r["criticality"]:
                continue
            for e in r["path"]:
                for f in e["fixes"]:
                    fix_hits[f] += r["criticality"] * r["likelihood"]
        containment = [{"fix": k, "title": self.fixes[k].title if k in self.fixes else k, "score": round(v, 3)}
                       for k, v in sorted(fix_hits.items(), key=lambda kv: -kv[1])[:10]]
        return {"start": src, "start_label": self.nodes[src].label, "reachable": reachable,
                "summary": summary, "containment": containment}

    def attack_paths(self, source: str = INTERNET, target: Optional[str] = None, k: int = 5,
                     min_likelihood: float = 0.001) -> list[dict]:
        src = self.resolve_start(source)
        if target is not None:
            tgt = self.resolve_start(target)
            return [self._path_dict(src, tgt, p, l) for p, l in self.k_shortest(src, tgt, k)]
        prob, pred = self.dijkstra(src, min_likelihood)
        kind_rank = {"data": 3, "cloud": 2, "foothold": 1}
        cands = [(round(self.nodes[n].criticality * p, 4), kind_rank.get(self.nodes[n].kind, 0), n) for n, p in prob.items()
                 if n != src and self.nodes[n].criticality > 0
                 and self.nodes[n].asset_id != self.nodes[src].asset_id]
        cands.sort(reverse=True)
        out = []
        seen_assets: set[tuple] = set()
        for _, _, n in cands:
            node = self.nodes[n]
            key = (node.asset_id, node.kind)
            if key in seen_assets and node.kind == "foothold":
                continue
            seen_assets.add(key)
            out.append(self._path_dict(src, n, self._path(pred, n), prob[n]))
            if len(out) >= k:
                break
        return out

    def _path_dict(self, src: str, tgt: str, path: list[Edge], likelihood: float) -> dict:
        nodes = [src] + [e.dst for e in path]
        t = self.nodes[tgt]
        return {"source": src, "target": tgt, "target_label": t.label, "target_criticality": t.criticality,
                "likelihood": round(likelihood, 4),
                "nodes": [self.nodes[n].to_dict() for n in nodes], "edges": [e.to_dict() for e in path]}

    def k_shortest(self, src: str, tgt: str, k: int) -> list[tuple[list[Edge], float]]:
        """Yen's algorithm over max-probability paths."""
        prob, pred = self.dijkstra(src)
        if tgt not in prob:
            return []
        A: list[tuple[list[Edge], float]] = [(self._path(pred, tgt), prob[tgt])]
        B: list[tuple[float, int, list[Edge]]] = []
        counter = 0
        for _ in range(1, k):
            last = A[-1][0]
            for i in range(len(last)):
                spur = last[i].src
                root = last[:i]
                banned_edges = {id(p[0][i]) for p in A if len(p[0]) > i and p[0][:i] == root}
                banned_nodes = {e.src for e in root}
                sub = _SubGraph(self, banned_edges, banned_nodes)
                sp, spred = sub.dijkstra(spur)
                if tgt not in sp:
                    continue
                spur_path = self._path(spred, tgt)
                total = root + spur_path
                p = math.prod(e.likelihood for e in total)
                if any(total == x[0] for x in A) or any(total == x[2] for x in B):
                    continue
                counter += 1
                heapq.heappush(B, (-p, counter, total))
            if not B:
                break
            negp, _, path = heapq.heappop(B)
            A.append((path, -negp))
        return A

    def risk(self, sources: list[str], removed_fixes: Optional[set[str]] = None,
             weights: Optional[dict[str, float]] = None) -> float:
        total = 0.0
        for s in sources:
            prob, _ = self.dijkstra(s, 0.001, removed_fixes)
            w = (weights or {}).get(s, 1.0)
            sa = self.nodes[s].asset_id
            total += w * sum(self.nodes[n].criticality * p for n, p in prob.items()
                             if self.nodes[n].criticality and self.nodes[n].asset_id != sa)
        return total

    def to_dict(self) -> dict:
        return {"nodes": [n.to_dict() for n in self.nodes.values()],
                "edges": [e.to_dict() for e in self.edges],
                "fixes": {k: vars(v) for k, v in self.fixes.items()}, "notes": self.notes}


class _SubGraph:
    """View of an AttackGraph with some edges/nodes removed (for Yen's algorithm)."""

    def __init__(self, g: AttackGraph, banned_edges: set[int], banned_nodes: set[str]):
        self.g, self.be, self.bn = g, banned_edges, banned_nodes

    def dijkstra(self, source: str):
        best = {source: 1.0}
        pred: dict[str, Edge] = {}
        heap = [(0.0, source)]
        while heap:
            d, u = heapq.heappop(heap)
            if d > -math.log(best[u]) + 1e-12:
                continue
            for e in self.g.out.get(u, ()):
                if id(e) in self.be or e.dst in self.bn:
                    continue
                nd = d + e.weight
                p = math.exp(-nd)
                if p > best.get(e.dst, 0.0) + 1e-12:
                    best[e.dst] = p
                    pred[e.dst] = e
                    heapq.heappush(heap, (nd, e.dst))
        return best, pred


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #
class _Reach:
    """Network reachability between IPs using all known firewall configs."""

    def __init__(self, firewalls: list[FirewallConfig], assume_flat: bool):
        self.fws = firewalls
        self.assume_flat = assume_flat
        self._cache: dict[tuple, tuple[bool, bool, str]] = {}

    def check(self, src_ip: str, dst_ip: str, port: Optional[int], proto: str = "tcp") -> tuple[bool, bool, str]:
        """-> (allowed, confident, reason)"""
        key = (src_ip, dst_ip, port, proto)
        if key in self._cache:
            return self._cache[key]
        res: Optional[tuple[bool, bool, str]] = None
        for fw in self.fws:
            if fw.network_for_ip(src_ip) is None and fw.network_for_ip(dst_ip) is None:
                continue
            d = fw.evaluate(src_ip, dst_ip, port, proto)
            if not d.confident:
                continue
            res = (d.allowed, True, f"{fw.hostname or fw.vendor}: {d.rule}")
            if not d.allowed:
                break
        if res is None:
            try:
                same = ipaddress.ip_network(f"{src_ip}/24", strict=False) == ipaddress.ip_network(f"{dst_ip}/24", strict=False)
            except ValueError:
                same = False
            if same:
                res = (True, False, "same /24, no firewall data")
            else:
                res = (self.assume_flat, False, "no firewall data (assumed flat network)" if self.assume_flat
                       else "no firewall data (assumed segmented)")
        self._cache[key] = res
        return res


class GraphBuilder:
    def __init__(self, store: Store, settings: Settings):
        self.store = store
        self.settings = settings
        self.g = AttackGraph()
        self.assets = {a["id"]: a for a in store.list_assets("host")}
        self.inv: dict[str, Inventory] = {k: v for k, v in store.all_inventories().items() if k in self.assets}
        self.firewalls: list[FirewallConfig] = []
        for fw in store.list_firewalls():
            if fw.get("config"):
                try:
                    self.firewalls.append(FirewallConfig.model_validate(fw["config"]))
                except Exception as exc:  # noqa: BLE001
                    self.g.notes.append(f"firewall {fw['id']} config unreadable: {exc}")
        self.reach = _Reach(self.firewalls, settings.assume_flat_network)
        self.findings: dict[str, list[Finding]] = defaultdict(list)
        for f in store.list_findings(status="open"):
            if f.asset_id:
                self.findings[f.asset_id].append(f)
        self.ip_to_asset: dict[str, str] = {}
        self.name_to_asset: dict[str, str] = {}
        for aid, inv in self.inv.items():
            for ip in inv.ip_addresses():
                self.ip_to_asset.setdefault(ip, aid)
            for nm in {inv.host.hostname, inv.host.fqdn, inv.host.hostname.split(".")[0]}:
                if nm:
                    self.name_to_asset.setdefault(nm.lower(), aid)
        self.external = store.latest_external_result()

    # ---- helpers ----------------------------------------------------- #
    def crit(self, aid: str) -> int:
        return int(self.assets.get(aid, {}).get("criticality", 3))

    def host_label(self, aid: str) -> str:
        inv = self.inv.get(aid)
        return inv.host.hostname if inv else self.assets.get(aid, {}).get("name", aid)

    def foothold(self, aid: str, user: str) -> str:
        priv_root = user in ("root", "SYSTEM", "NT AUTHORITY\\SYSTEM") or user == ""
        nid = f"host:{aid}#root" if priv_root else f"host:{aid}#user:{user}"
        shown = "root" if priv_root else ("any local user" if user == ANY_USER else user)
        label = f"{self.host_label(aid)} ({shown})"
        # owning a crown-jewel host as root *is* the target; user-level footholds are not targets
        crit = self.crit(aid) if priv_root and self.crit(aid) >= 3 else 0
        self.g.add_node(Node(nid, "foothold", label, aid, crit,
                             {"privilege": "root" if priv_root else "user", "user": user,
                              "hostname": self.host_label(aid)}))
        netpos = f"host:{aid}"
        self.g.add_node(Node(netpos, "netpos", f"network position on {self.host_label(aid)}", aid))
        self.g.add_edge(Edge(nid, netpos, "network_position", "T1018", 1.0,
                             "Code execution on the host lets the attacker send traffic from it"))
        if not priv_root and f"host:{aid}#root" in self.g.nodes:
            self.g.add_edge(Edge(f"host:{aid}#root", nid, "become_user", "T1548", 1.0,
                                 "Root can act as any local user"))
        return nid

    def vuln_findings(self, aid: str) -> list[Finding]:
        return [f for f in self.findings.get(aid, []) if f.category.value == "vulnerability"]

    def listener_vulns(self, aid: str, l: Listener) -> list[Finding]:
        names = set()
        if l.package:
            names.add(l.package.lower())
        names.update(PROCESS_PACKAGE_HINTS.get(l.process, []))
        if not names:
            return []
        out = []
        for f in self.vuln_findings(aid):
            pkgs = {str(f.evidence.get("package", "")).lower()}
            pkgs.update(str(b).lower() for b in f.evidence.get("binary_packages") or [])
            if pkgs & names:
                out.append(f)
        return out

    @staticmethod
    def exploit_likelihood(f: Finding, remote: bool) -> float:
        ev = f.evidence
        if remote and not ev.get("remote_exploitable"):
            return 0.0
        if not remote and not ev.get("privesc"):
            return 0.0
        if ev.get("kev"):
            return 0.9
        epss = float(ev.get("max_epss") or 0)
        base = {"critical": 0.6, "high": 0.4, "medium": 0.2}.get(f.severity.value, 0.1)
        return min(0.95, max(base, epss))

    # ---- build --------------------------------------------------------- #
    def build(self) -> AttackGraph:
        for aid in self.inv:
            self.foothold(aid, "root")
        for aid, inv in self.inv.items():
            self._local(aid, inv)
        for aid, inv in self.inv.items():
            self._credentials(aid, inv)
        for aid, inv in self.inv.items():
            self._lateral_network(aid, inv)
            self._connections(aid, inv)
        self._internet()
        if not self.firewalls:
            self.g.notes.append("No firewall configuration imported: inter-host reachability is "
                                + ("assumed (flat network)." if self.settings.assume_flat_network else "unknown."))
        return self.g

    # local privilege structure ------------------------------------------- #
    def _local(self, aid: str, inv: Inventory) -> None:
        g = self.g
        root = f"host:{aid}#root"
        groups: dict[str, set[str]] = defaultdict(set)
        for gr in inv.groups:
            groups[gr.name].update(gr.members)
        for u in inv.users:
            for gname in u.groups:
                groups[gname].add(u.name)

        users = {u.name for u in inv.users if u.login_enabled and u.uid != 0} | {ANY_USER}
        interactive = {u.name for u in inv.users if u.login_enabled and (u.uid >= 1000 or u.uid < 0)
                       and u.shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")}
        users |= {l.user for l in inv.listeners if l.user and l.user != "root"}
        users |= {c.owner for c in inv.credentials if c.owner and c.owner != "root"}
        users |= {d.owner for d in inv.datastores if d.owner and d.owner != "root"}
        for u in sorted(users):
            nid = self.foothold(aid, u)
            if u in interactive:
                g.nodes[nid].attrs["interactive"] = True

        h = inv.hardening
        hkey = lambda cid, suffix="": f"hard:{aid}:{cid}" + (f":{suffix}" if suffix else "")  # noqa: E731
        generic: list[tuple[str, str, float, str, list[str], dict]] = []
        gtfo = [p for p in h.suid_binaries if p.rsplit("/", 1)[-1] in _gtfo()]
        if gtfo:
            generic.append(("suid", T_SUID, 0.9, f"SUID binary {gtfo[0]} spawns a root shell",
                            [g.add_fix(Fix(hkey("suid_gtfobins"), "config", f"Remove SUID bit from GTFOBins binaries on {self.host_label(aid)}", [aid],
                                           commands=[f"chmod u-s {p}" for p in gtfo], finding_key=hkey("suid_gtfobins")))],
                            {"binaries": gtfo}))
        if h.writable_root_cron:
            generic.append(("cron", T_CRON, 0.9, "Root cron job script is writable by other users",
                            [g.add_fix(Fix(hkey("writable_root_cron"), "config", f"Fix permissions of root cron scripts on {self.host_label(aid)}", [aid],
                                           finding_key=hkey("writable_root_cron")))], {"paths": h.writable_root_cron}))
        if h.writable_path_dirs:
            generic.append(("path_hijack", T_PATH, 0.6, "Writable directory in root's PATH",
                            [g.add_fix(Fix(hkey("writable_path"), "config", f"Fix PATH directory permissions on {self.host_label(aid)}", [aid],
                                           finding_key=hkey("writable_path")))], {"paths": h.writable_path_dirs}))
        sock = h.docker_socket or {}
        if sock.get("exists") and str(sock.get("mode", "0"))[-1:] in "2367":
            generic.append(("docker_socket", T_ESCAPE, 0.95, "World-writable Docker socket",
                            [g.add_fix(Fix(hkey("docker_socket_world"), "config", f"Restrict Docker socket on {self.host_label(aid)}", [aid],
                                           commands=["chmod 660 /var/run/docker.sock"], finding_key=hkey("docker_socket_world")))], sock))
        for f in self.vuln_findings(aid):
            p = self.exploit_likelihood(f, remote=False)
            if p > 0:
                generic.append(("privesc_vuln", T_PRIVESC_EXPLOIT, p,
                                f"Local privilege escalation vulnerability in {f.evidence.get('package')}",
                                [g.add_fix(Fix(f.key, "patch", f.title, [aid], finding_key=f.key))],
                                {"finding": f.key, "kev": f.evidence.get("kev", False)}))

        for u in sorted(users):
            src = f"host:{aid}#user:{u}"
            for name, tech, p, desc, fixes, ev in generic:
                g.add_edge(Edge(src, root, name, tech, p, desc, list(fixes), ev))
            if u == ANY_USER:
                continue
            # sudo
            for r in inv.sudo_rules:
                pr = r.principal
                applies = pr == u or (pr.startswith("%") and u in groups.get(pr[1:], set())) or pr == "ALL"
                if not applies:
                    continue
                all_cmds = any(c.strip().upper() == "ALL" or c.strip().endswith(("/bash", "/sh", "/su"))
                               for c in r.commands)
                if r.nopasswd and all_cmds:
                    p, desc = 0.95, f"sudo NOPASSWD ALL via '{pr}'"
                elif all_cmds:
                    p, desc = 0.6, f"sudo ALL via '{pr}' (password needed: capturable once the account is owned)"
                else:
                    p, desc = 0.25, f"sudo for specific commands via '{pr}' (may be abusable)"
                fix = g.add_fix(Fix(hkey("sudo_nopasswd_all", pr) if r.nopasswd and all_cmds else f"access:{aid}:sudo:{pr}",
                                    "access", f"Restrict sudo rights of '{pr}' on {self.host_label(aid)}", [aid],
                                    details=f"Edit {r.source or '/etc/sudoers'} with visudo.",
                                    finding_key=hkey("sudo_nopasswd_all", pr) if r.nopasswd and all_cmds else None))
                g.add_edge(Edge(src, root, "sudo", T_SUDO, p, desc, [fix],
                                {"rule": r.model_dump()}))
            if u in groups.get("docker", set()):
                fix = g.add_fix(Fix(hkey("docker_group"), "access", f"Remove users from docker group on {self.host_label(aid)}",
                                    [aid], commands=[f"gpasswd -d {u} docker"], finding_key=hkey("docker_group")))
                g.add_edge(Edge(src, root, "docker_group", T_ESCAPE, 0.95,
                                f"'{u}' is in the docker group (root-equivalent)", [fix]))
            for gname in ("lxd", "disk"):
                if u in groups.get(gname, set()):
                    fix = g.add_fix(Fix(f"access:{aid}:group:{gname}", "access",
                                        f"Remove users from the {gname} group on {self.host_label(aid)}", [aid],
                                        commands=[f"gpasswd -d {u} {gname}"]))
                    g.add_edge(Edge(src, root, f"{gname}_group", T_ESCAPE, 0.9,
                                    f"'{u}' is in the {gname} group (root-equivalent)", [fix]))

        # datastores on the host
        for d in inv.datastores:
            crit = max(SENSITIVITY_CRIT.get(d.sensitivity, 3), self.crit(aid))
            nid = f"data:{aid}:{d.kind}:{d.name or d.path or d.port}"
            g.add_node(Node(nid, "data", f"{d.kind} {d.name or d.path or d.port} on {self.host_label(aid)}", aid, crit,
                            {"kind": d.kind, "sensitivity": d.sensitivity}))
            g.add_edge(Edge(root, nid, "local_data", T_LOCAL_DATA, 1.0, "Root can read all local data"))
            if d.owner and d.owner != "root":
                g.add_edge(Edge(self.foothold(aid, d.owner), nid, "local_data", T_LOCAL_DATA, 1.0,
                                f"Data files are owned by '{d.owner}'"))

    # credentials ---------------------------------------------------------- #
    def _credentials(self, aid: str, inv: Inventory) -> None:
        g = self.g
        auth_index: dict[str, list[tuple[str, str]]] = defaultdict(list)   # fp -> [(asset, user)]
        for other, oinv in self.inv.items():
            for k in oinv.authorized_keys:
                auth_index[k.fingerprint].append((other, k.user))
        known_targets = {(kh.user, kh.host.lower()) for kh in inv.known_hosts if kh.host}

        for c in inv.credentials:
            owner_node = self.foothold(aid, c.owner or "root")
            if c.kind == "ssh_private_key":
                if not c.fingerprint:
                    continue
                cid = f"cred:ssh:{c.fingerprint}"
                g.add_node(Node(cid, "cred", f"SSH key {c.fingerprint[:20]}… ({c.owner}@{self.host_label(aid)})", None, 0,
                                {"kind": "ssh_private_key", "encrypted": c.encrypted}))
                enc = c.encrypted is not False
                fix_key = f"hard:{aid}:ssh_key_unencrypted:{c.fingerprint or c.path}"
                fixes = [] if enc else [g.add_fix(Fix(fix_key, "credential",
                                                      f"Protect SSH key {c.path} on {self.host_label(aid)} with a passphrase / FIDO2",
                                                      [aid], commands=[f"ssh-keygen -p -f {c.path}"], finding_key=fix_key))]
                g.add_edge(Edge(owner_node, cid, "steal_key", T_PRIV_KEYS, 0.35 if enc else 1.0,
                                "Encrypted key: passphrase must be captured (keylogger / agent hijack)" if enc
                                else "Unencrypted private key file readable by the account", fixes,
                                {"path": c.path}))
                if c.owner != "root":
                    g.add_edge(Edge(f"host:{aid}#root", cid, "steal_key", T_PRIV_KEYS, 0.5 if enc else 1.0,
                                    "Root can read every user's keys", fixes, {"path": c.path}))
                for tgt_asset, tgt_user in auth_index.get(c.fingerprint, []):
                    if tgt_asset == aid and tgt_user == c.owner:
                        continue
                    self._ssh_edge(aid, cid, tgt_asset, tgt_user, c.fingerprint, (c.owner, ""), known_targets)
                for t in c.targets:
                    if self._resolve(t) is None:
                        self._ext(cid, t, "ssh_key_target", T_SSH, 0.5,
                                  "Key is configured for this unmanaged host (ssh config / known_hosts)")
            elif c.kind in ("aws", "gcp", "azure", "kube", "docker"):
                ident = c.identifier or (c.targets[0] if c.targets else c.path)
                cid = f"cred:{c.kind}:{c.fingerprint or ident}"
                g.add_node(Node(cid, "cred", f"{c.kind} credential {ident} ({c.owner}@{self.host_label(aid)})", None, 0,
                                {"kind": c.kind}))
                fix_key = f"hard:{aid}:cloud_creds_{c.kind}:{c.path}" if c.kind in ("aws", "gcp", "azure") else \
                    f"hard:{aid}:plaintext_creds_{c.kind}:{c.path}"
                fix = g.add_fix(Fix(fix_key, "credential", f"Replace stored {c.kind} credential on {self.host_label(aid)}",
                                    [aid], finding_key=fix_key))
                g.add_edge(Edge(owner_node, cid, "steal_cloud_cred", T_CREDS_FILES, 1.0,
                                f"{c.kind} credentials stored in {c.path}", [fix]))
                targets = c.targets or [ident]
                for t in targets:
                    cloud = f"cloud:{c.kind}:{t}"
                    g.add_node(Node(cloud, "cloud", f"{c.kind} access: {t}", None, 4, {"kind": c.kind}))
                    g.add_edge(Edge(cid, cloud, "use_cloud_cred", T_CLOUD, 0.9,
                                    f"Credential grants {c.kind} access", [fix]))
            elif c.kind in ("pgpass", "mysql", "netrc", "git"):
                cid = f"cred:{c.kind}:{aid}:{c.path}"
                g.add_node(Node(cid, "cred", f"{c.kind} credentials {c.path} on {self.host_label(aid)}", None, 0,
                                {"kind": c.kind}))
                fix_key = f"hard:{aid}:plaintext_creds_{c.kind}:{c.path}"
                fix = g.add_fix(Fix(fix_key, "credential", f"Remove plaintext {c.kind} credentials on {self.host_label(aid)}",
                                    [aid], finding_key=fix_key))
                g.add_edge(Edge(owner_node, cid, "steal_creds", T_CREDS_FILES, 1.0, f"Plaintext credentials in {c.path}", [fix]))
                for t in c.targets:
                    host, _, port = t.partition(":")
                    tgt = self._resolve(host)
                    kind = {"pgpass": "postgresql", "mysql": "mysql"}.get(c.kind, c.kind)
                    if tgt:
                        dn = self._datastore_node(tgt, kind, int(port) if port.isdigit() else 0)
                        allowed, _, reason = self.reach.check(self._ip(aid), self._ip(tgt), int(port) if port.isdigit() else None)
                        if dn and allowed:
                            g.add_edge(Edge(cid, dn, "use_db_cred", T_VALID_ACCOUNTS, 0.9,
                                            f"Credentials target {t}", [fix], {"reach": reason}))
                    else:
                        self._ext(cid, t, "use_cred", T_VALID_ACCOUNTS, 0.8, f"Credentials target unmanaged system {t}")

    def _ssh_edge(self, src_aid: str, cid: str, tgt_aid: str, tgt_user: str, fp: str, owner: tuple[str, str],
                  known: set[tuple[str, str]]) -> None:
        tinv = self.inv[tgt_aid]
        port = tinv.hardening.sshd.port or 22
        allowed, confident, reason = self.reach.check(self._ip(src_aid), self._ip(tgt_aid), port)
        if not allowed:
            return
        tgt_node = self.foothold(tgt_aid, tgt_user)
        names = {self.host_label(tgt_aid).lower(), *tinv.ip_addresses()}
        # known_hosts shows the key owner actually logs in there -> the key almost certainly works
        p = 0.95 if any((owner[0], n.lower()) in known for n in names) else 0.85
        if not confident:
            p *= 0.9
        fix_auth = self.g.add_fix(Fix(f"access:{tgt_aid}:authorized_key:{tgt_user}:{fp}", "access",
                                      f"Review/remove key {fp[:20]}… from {tgt_user}@{self.host_label(tgt_aid)} authorized_keys",
                                      [tgt_aid], details="Restrict with from=\"<admin subnet>\" if the key is needed."))
        fixes = [fix_auth, self._fw_fix(src_aid, tgt_aid, port)]
        self.g.add_edge(Edge(cid, tgt_node, "ssh_key", T_SSH, p,
                             f"Key is authorized for {tgt_user}@{self.host_label(tgt_aid)} and port {port} is reachable",
                             fixes, {"reach": reason, "fingerprint": fp}))

    def _fw_fix(self, src_aid: str, dst_aid: str, port: int) -> str:
        src_ip, dst_ip = self._ip(src_aid), self._ip(dst_aid)
        seg = None
        for fw in self.firewalls:
            n = fw.network_for_ip(src_ip)
            if n is not None:
                seg = n.name
                break
        key = f"fw:{seg or src_ip}->{dst_ip}:{port}"
        title = (f"Firewall: block {seg or self.host_label(src_aid)} → {self.host_label(dst_aid)}:{port} "
                 "(allow only from admin hosts)")
        cmds = [f"# host firewall on {self.host_label(dst_aid)}:",
                f"ufw deny from {src_ip if not seg else '<' + seg + ' subnet>'} to any port {port} proto tcp"]
        return self.g.add_fix(Fix(key, "firewall", title, [dst_aid], commands=cmds))

    def _ip(self, aid: str) -> str:
        ips = self.inv[aid].ip_addresses()
        priv = [i for i in ips if ":" not in i]
        return (priv or ips or ["0.0.0.0"])[0]

    def _resolve(self, host: str) -> Optional[str]:
        h = host.lower().strip().strip("[]")
        if h.startswith("ssh://"):
            h = h[6:]
        h = h.split("@")[-1]
        return self.ip_to_asset.get(h) or self.name_to_asset.get(h) or self.name_to_asset.get(h.split(".")[0])

    def _ext(self, src: str, target: str, name: str, tech: str, p: float, desc: str) -> None:
        nid = f"ext:{target}"
        self.g.add_node(Node(nid, "ext", f"{target} (unmanaged)", None, 2))
        self.g.add_edge(Edge(src, nid, name, tech, p, desc))

    def _datastore_node(self, aid: str, kind: str, port: int) -> Optional[str]:
        inv = self.inv[aid]
        for d in inv.datastores:
            if d.kind == kind or (port and d.port == port):
                return f"data:{aid}:{d.kind}:{d.name or d.path or d.port}"
        # listener without a declared datastore: synthesize one
        for l in inv.listeners:
            if (port and l.port == port) or DATASTORE_PORTS.get(l.port) == kind:
                nid = f"data:{aid}:{kind}:{l.port}"
                self.g.add_node(Node(nid, "data", f"{kind} :{l.port} on {self.host_label(aid)}", aid, self.crit(aid)))
                self.g.add_edge(Edge(f"host:{aid}#root", nid, "local_data", T_LOCAL_DATA, 1.0, "Root can read all local data"))
                return nid
        return None

    # network lateral movement ------------------------------------------------ #
    def _lateral_network(self, tgt: str, inv: Inventory) -> None:
        listeners = [l for l in inv.listeners if not l.is_loopback_only and l.proto.startswith("tcp")]
        if not listeners:
            return
        for l in listeners:
            vulns = self.listener_vulns(tgt, l)
            exploits = [(f, self.exploit_likelihood(f, remote=True)) for f in vulns]
            exploits = [(f, p) for f, p in exploits if p > 0]
            ds_kind = DATASTORE_PORTS.get(l.port)
            if not exploits and not ds_kind:
                continue
            for src in self.inv:
                if src == tgt:
                    continue
                allowed, confident, reason = self.reach.check(self._ip(src), self._ip(tgt), l.port)
                if not allowed:
                    continue
                fw_fix = self._fw_fix(src, tgt, l.port)
                for f, p in exploits:
                    self.g.add_edge(Edge(f"host:{src}", self.foothold(tgt, l.user or "root"), "exploit_remote",
                                         T_EXPLOIT_REMOTE, p * (1.0 if confident else 0.9),
                                         f"{l.process or 'service'} on port {l.port} has a remotely exploitable "
                                         f"vulnerability ({f.evidence.get('package')})",
                                         [self.g.add_fix(Fix(f.key, "patch", f.title, [tgt], finding_key=f.key)), fw_fix],
                                         {"finding": f.key, "port": l.port, "reach": reason}))
                if ds_kind in ("redis", "memcached", "elasticsearch", "mongodb", "couchdb", "influxdb"):
                    # commonly deployed without authentication; reachable == readable unless proven otherwise
                    dn = self._datastore_node(tgt, ds_kind, l.port)
                    if dn:
                        auth_fix = self.g.add_fix(Fix(f"config:{tgt}:auth:{l.port}", "config",
                                                      f"Require authentication on {ds_kind} ({self.host_label(tgt)}:{l.port}) "
                                                      "and bind it to localhost if remote access isn't needed",
                                                      [tgt], finding_key=f"hard:{tgt}:datastore_network_bind:{l.port}"))
                        self.g.add_edge(Edge(f"host:{src}", dn, "unauth_datastore", T_EXPLOIT_REMOTE, 0.4,
                                             f"{ds_kind} on {self.host_label(tgt)}:{l.port} is network-reachable; often unauthenticated",
                                             [auth_fix, fw_fix], {"port": l.port, "reach": reason}))

    def _connections(self, aid: str, inv: Inventory) -> None:
        """An app that talks to a database almost always has its credentials on disk."""
        for c in inv.connections:
            kind = DATASTORE_PORTS.get(c.remote_port)
            if not kind or c.remote_address.startswith("127.") or c.remote_address == "::1":
                continue
            src = self.foothold(aid, c.user or "root")
            tgt = self.ip_to_asset.get(c.remote_address)
            if tgt and tgt != aid:
                dn = self._datastore_node(tgt, kind, c.remote_port)
                if dn:
                    fix = self.g.add_fix(Fix(f"credential:{aid}:dbclient:{c.remote_address}:{c.remote_port}", "credential",
                                             f"Use a least-privilege, vault-issued DB credential for {c.process or 'the app'} on "
                                             f"{self.host_label(aid)}", [aid]))
                    self.g.add_edge(Edge(src, dn, "db_client_creds", T_CREDS_FILES, 0.6,
                                         f"{c.process or 'process'} ({c.user or '?'}) is connected to {kind} on "
                                         f"{self.host_label(tgt)}; its credentials are likely readable",
                                         [fix], {"connection": c.model_dump()}))
            elif not tgt:
                self._ext(src, f"{c.remote_address}:{c.remote_port}", "db_client_creds", T_CREDS_FILES, 0.5,
                          f"{c.process or 'process'} talks to an unmanaged {kind}")

    # internet exposure --------------------------------------------------------- #
    def _internet(self) -> None:
        exposures: dict[tuple[str, int], dict] = {}
        # 1) firewall port forwards
        for fw in self.firewalls:
            for pf in fw.port_forwards:
                if not pf.enabled:
                    continue
                aid = self.ip_to_asset.get(pf.internal_ip)
                if not aid:
                    continue
                ports = [pf.internal_port] if pf.internal_port else [r.start for r in pf.external_ports if r.start == r.end]
                for port in ports:
                    exposures[(aid, port)] = {"via": f"port forward on {fw.hostname or fw.vendor}: {pf.description or pf.id}",
                                              "source": pf.source, "confirmed": None}
        # 2) hosts with public addresses and no firewall in front
        for aid, inv in self.inv.items():
            pub = [ip for ip in inv.ip_addresses() if not _is_private(ip)]
            covered = any(fw.network_for_ip(ip) is not None and not fw.network_for_ip(ip).is_wan  # type: ignore[union-attr]
                          for fw in self.firewalls for ip in pub)
            if pub and not covered:
                for l in inv.listeners:
                    if l.is_loopback_only or not l.proto.startswith("tcp"):
                        continue
                    if l.address in ("0.0.0.0", "::", "*", "") or l.address in pub:
                        hf = inv.hardening.firewall
                        exposures.setdefault((aid, l.port), {
                            "via": f"public address {pub[0]}", "source": "any", "confirmed": None,
                            "host_firewall": bool(hf.enabled)})
        # 3) external probe observations confirm or add exposure
        if self.external:
            wan_map = {}
            for fw in self.firewalls:
                for pf in fw.port_forwards:
                    for ip in fw.wan_addresses or ["*"]:
                        for r in pf.external_ports:
                            for p in range(r.start, min(r.end, r.start + 64) + 1):
                                wan_map[(ip, p)] = (pf.internal_ip, pf.internal_port or p)
            for t in self.external.get("targets", []):
                ips = t.get("resolved") or [t.get("target")]
                for svc in t.get("services", []):
                    if svc.get("state", "open") != "open":
                        continue
                    port = int(svc["port"])
                    for ip in ips:
                        aid, iport = self.ip_to_asset.get(ip), port
                        if not aid:
                            m = wan_map.get((ip, port)) or wan_map.get(("*", port))
                            if m:
                                aid, iport = self.ip_to_asset.get(m[0]), m[1]
                        if aid:
                            ex = exposures.setdefault((aid, iport), {"via": f"observed open by external probe on {ip}:{port}",
                                                                     "source": "any"})
                            ex["confirmed"] = True
                            ex["probe_service"] = svc.get("service") or svc.get("product")
        for (aid, port), ex in exposures.items():
            inv = self.inv.get(aid)
            if inv is None:
                continue
            l = next((x for x in inv.listeners if x.port == port and not x.is_loopback_only), None)
            if l is None:
                if ex.get("confirmed"):
                    self.g.notes.append(f"{self.host_label(aid)}:{port} is open from the internet but no "
                                        "matching listener was reported by the agent")
                continue
            factor = 1.0
            if ex.get("confirmed") is True:
                factor = 1.15
            if ex.get("host_firewall"):
                factor *= 0.5
            if ex.get("source") not in (None, "", "any"):
                factor *= 0.3   # source-restricted forward
            tgt = self.foothold(aid, l.user or "root")
            exposure_fix = self.g.add_fix(Fix(f"fw:internet->{aid}:{port}", "firewall",
                                              f"Stop exposing {self.host_label(aid)}:{port} ({l.process or 'service'}) to the internet "
                                              "(remove the port forward, restrict source IPs, or put it behind a VPN)",
                                              [aid]))
            evidence = {"port": port, **ex}
            vulns = [(f, self.exploit_likelihood(f, True)) for f in self.listener_vulns(aid, l)]
            for f, p in vulns:
                if p <= 0:
                    continue
                self.g.add_edge(Edge(INTERNET, tgt, "exploit_public", T_EXPLOIT_PUBLIC, min(0.99, p * factor),
                                     f"Internet-exposed {l.process or 'service'}:{port} has a remotely exploitable "
                                     f"vulnerability ({f.evidence.get('package')})",
                                     [self.g.add_fix(Fix(f.key, "patch", f.title, [aid], finding_key=f.key)), exposure_fix],
                                     {**evidence, "finding": f.key}))
            svc = AUTH_SERVICES.get(port)
            if svc == "ssh" and inv.hardening.sshd.password_authentication.lower() == "yes":
                self.g.add_edge(Edge(INTERNET, self.foothold(aid, "root") if inv.hardening.sshd.permit_root_login == "yes"
                                     else self.foothold(aid, ANY_USER), "brute_force", T_BRUTE, 0.05 * factor,
                                     "SSH with password authentication is exposed to the internet",
                                     [self.g.add_fix(Fix(f"hard:{aid}:ssh_password_auth", "config",
                                                         f"Disable SSH password authentication on {self.host_label(aid)}",
                                                         [aid], finding_key=f"hard:{aid}:ssh_password_auth")), exposure_fix],
                                     evidence))
            elif svc in ("rdp", "vnc", "telnet", "ftp", "winrm"):
                self.g.add_edge(Edge(INTERNET, self.foothold(aid, ANY_USER), "brute_force", T_BRUTE, 0.08 * factor,
                                     f"{svc.upper()} login exposed to the internet", [exposure_fix], evidence))
            ds = DATASTORE_PORTS.get(port)
            if ds:
                dn = self._datastore_node(aid, ds, port)
                if dn:
                    self.g.add_edge(Edge(INTERNET, dn, "unauth_datastore", T_EXPLOIT_PUBLIC, 0.5 * factor,
                                         f"{ds} reachable from the internet", [exposure_fix], evidence))
            # any exposed service is a (small) foothold risk even without a known vuln
            self.g.add_edge(Edge(INTERNET, tgt, "exposed_service", T_EXPLOIT_PUBLIC, 0.02 * factor,
                                 f"{l.process or 'service'}:{port} is reachable from the internet (no known "
                                 "vulnerability; residual risk of misconfiguration or 0-day)", [exposure_fix], evidence))


def _gtfo() -> set[str]:
    from ..hardening.checks import GTFO_SUID
    return GTFO_SUID


def build_graph(store: Store, settings: Settings) -> AttackGraph:
    return GraphBuilder(store, settings).build()
