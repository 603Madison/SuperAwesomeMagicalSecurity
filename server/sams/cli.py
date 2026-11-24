"""``sams`` command line."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import load_settings
from .context import AppContext


def _ctx(args) -> AppContext:
    settings = load_settings(args.config)
    if getattr(args, "data_dir", None):
        settings.data_dir = Path(args.data_dir)
    return AppContext.create(settings)


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_server(args) -> None:
    import uvicorn

    from .api.app import create_app
    ctx = _ctx(args)
    host = args.host or ctx.settings.listen
    port = args.port or ctx.settings.port
    kw: dict[str, Any] = {}
    if args.tls_cert:
        kw.update(ssl_certfile=args.tls_cert, ssl_keyfile=args.tls_key)
    elif host not in ("127.0.0.1", "localhost", "::1"):
        logging.getLogger("sams").warning("Serving without TLS on %s. Put a TLS reverse proxy in front or pass "
                                          "--tls-cert/--tls-key: agents send credentials to this server.", host)
    uvicorn.run(create_app(ctx), host=host, port=port, log_level="info", proxy_headers=ctx.settings.trust_proxy, **kw)


def cmd_token(args) -> None:
    ctx = _ctx(args)
    tok = ctx.store.create_enroll_token(args.kind, args.label, args.uses, args.ttl_hours)
    server = ctx.settings.public_url or "https://<sams-server>"
    binary = "sams-agent" if args.kind == "host" else "sams-probe"
    print(tok)
    print(f"\n  {binary} enroll --server {server} --token {tok}", file=sys.stderr)


def cmd_admin_token(args) -> None:
    from .api.deps import ensure_admin_token
    ctx = _ctx(args)
    ctx.store.kv_set("admin_token_hash", None)
    print(ensure_admin_token(ctx))


def cmd_analyze(args) -> None:
    """Offline: analyze one or more inventory JSON files (from `sams-agent collect`)."""
    from .analysis import asset_id_for, process_inventory
    from .models import Inventory
    from .posture import compute
    from .remediation.planner import build_plan
    ctx = _ctx(args)
    for f in args.files:
        inv = Inventory.model_validate_json(Path(f).read_text())
        aid = asset_id_for(inv)
        ctx.store.upsert_asset(aid, "host", inv.host.hostname)
        stats = process_inventory(ctx, aid, inv, vuln=not args.no_vuln)
        print(f"{inv.host.hostname} ({aid}): {json.dumps(stats, default=str)}", file=sys.stderr)
    p = compute(ctx)
    print(f"\nPosture: {p['score']} ({p['grade']})  open findings: {p['counts']['open_findings']}")
    for h in p["hosts"]:
        print(f"  {h['name']:<30} {h['score']:>5} {h['grade']}  {h['counts']}")
    print("\nTop remediations:")
    for item in build_plan(ctx, args.top):
        print(f"  {item['rank']:>2}. [{item['severity']:<8}] {item['title'][:100]}"
              + (f"  (-{item['risk_reduction_pct']}% risk)" if item["risk_reduction_pct"] else ""))


def cmd_findings(args) -> None:
    ctx = _ctx(args)
    for f in ctx.store.list_findings(asset_id=args.asset, category=args.category, severity=args.severity):
        print(f"[{f.severity.value:<8}] {f.category.value:<13} {f.asset_id or '-':<18} {f.title}")


def cmd_paths(args) -> None:
    ctx = _ctx(args)
    for p in ctx.graph().attack_paths(args.source, args.target, args.k):
        print(f"\n{p['likelihood']:.0%} → {p['target_label']} (criticality {p['target_criticality']})")
        for e in p["edges"]:
            print(f"   {e['technique']:<10} {e['likelihood']:.2f}  {e['description']}")


def cmd_blast(args) -> None:
    ctx = _ctx(args)
    br = ctx.graph().blast_radius(args.start, args.min_likelihood)
    if args.json:
        _print(br)
        return
    print(f"If {br['start_label']} is compromised:")
    _print(br["summary"])
    for r in br["reachable"][: args.limit]:
        print(f"  {r['likelihood']:.0%}  {r['kind']:<8} {r['label']}  ({r['hops']} steps)")
    print("\nBest containment actions:")
    for c in br["containment"][:5]:
        print(f"  - {c['title']}")


def cmd_plan(args) -> None:
    from .remediation.planner import build_plan
    ctx = _ctx(args)
    items = build_plan(ctx, args.limit)
    if args.json:
        _print(items)
        return
    for i in items:
        print(f"{i['rank']:>3}. [{i['severity']:<8}] {i['title'][:100]}")
        if i["risk_reduction_pct"]:
            print(f"       removes {i['risk_reduction_pct']}% of attack-path risk")
        for c in (i["remediation"].get("commands") or [])[:3]:
            print(f"       $ {c}")


def cmd_vulndb(args) -> None:
    from .vuln.scanner import sync_ecosystems, suggest_ecosystems
    ctx = _ctx(args)
    ecos = args.ecosystems or suggest_ecosystems(list(ctx.store.all_inventories().values()))
    if not ecos:
        print("No ecosystems given and no inventories to infer them from.", file=sys.stderr)
        sys.exit(2)
    _print(sync_ecosystems(ctx.settings, ecos))


def cmd_firewall_import(args) -> None:
    from .api.admin import _analyze_firewall
    from .firewall import normalize_unifi, parse_any_config
    ctx = _ctx(args)
    text = Path(args.file).read_text()
    cfg = normalize_unifi(json.loads(text)) if text.lstrip().startswith("{") else parse_any_config(text)
    cfg.device_id = args.id
    stats = _analyze_firewall(ctx, args.id, cfg)
    print(json.dumps(stats))
    for f in ctx.store.list_findings(asset_id=f"fw:{args.id}"):
        print(f"[{f.severity.value:<8}] {f.title}")


def cmd_external_target(args) -> None:
    from .external import add_target
    ctx = _ctx(args)
    for v in args.values:
        _print(add_target(ctx, v, args.note))


def cmd_external_job(args) -> None:
    from .external import create_job
    ctx = _ctx(args)
    print(create_job(ctx, args.ports))


def cmd_mcp(args) -> None:
    from .ai.mcp_server import run_stdio
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)   # stdout belongs to the MCP protocol
    run_stdio(_ctx(args))


def cmd_ask(args) -> None:
    from .ai.analyst import SecurityAnalyst
    from .ai.providers import get_provider
    ctx = _ctx(args)
    ai = ctx.settings.ai
    name = args.provider or ai.default_provider or (ai.providers[0].name if ai.providers else None)
    conf = next((p for p in ai.providers if p.name == name), None)
    if conf is None:
        print("No AI provider configured. Add one under `ai.providers` in sams.yaml (see docs/AI.md).", file=sys.stderr)
        sys.exit(2)
    res = SecurityAnalyst(ctx, get_provider(conf)).ask(" ".join(args.question))
    print(res.text)


def cmd_demo(args) -> None:
    from .demo import load_demo
    ctx = _ctx(args)
    _print(load_demo(ctx))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="sams", description="SuperAwesomeMagicalSecurity")
    ap.add_argument("--config", help="path to sams.yaml (default: $SAMS_CONFIG or ./sams.yaml)")
    ap.add_argument("--data-dir", help="override data directory")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("server", help="run the API server, dashboard, SIEM listeners and MCP endpoint")
    p.add_argument("--host"); p.add_argument("--port", type=int)
    p.add_argument("--tls-cert"); p.add_argument("--tls-key")
    p.set_defaults(fn=cmd_server)

    p = sub.add_parser("token", help="create an enrollment token for an agent or probe")
    p.add_argument("--kind", choices=["host", "probe"], default="host")
    p.add_argument("--label", default=""); p.add_argument("--uses", type=int, default=1)
    p.add_argument("--ttl-hours", type=int, default=24)
    p.set_defaults(fn=cmd_token)

    p = sub.add_parser("admin-token", help="generate a new admin API token (invalidates the old one)")
    p.set_defaults(fn=cmd_admin_token)

    p = sub.add_parser("analyze", help="offline analysis of inventory JSON files from `sams-agent collect`")
    p.add_argument("files", nargs="+"); p.add_argument("--no-vuln", action="store_true")
    p.add_argument("--top", type=int, default=15)
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("findings", help="list open findings")
    p.add_argument("--asset"); p.add_argument("--category"); p.add_argument("--severity")
    p.set_defaults(fn=cmd_findings)

    p = sub.add_parser("paths", help="show attack paths")
    p.add_argument("--source", default="internet"); p.add_argument("--target"); p.add_argument("-k", type=int, default=5)
    p.set_defaults(fn=cmd_paths)

    p = sub.add_parser("blast-radius", help="what an attacker gets if this asset/node is compromised")
    p.add_argument("start"); p.add_argument("--min-likelihood", type=float, default=0.05)
    p.add_argument("--limit", type=int, default=30); p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_blast)

    p = sub.add_parser("plan", help="risk-ranked remediation plan")
    p.add_argument("--limit", type=int, default=25); p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("vulndb", help="sync the local OSV mirror (offline / private vulnerability matching)")
    p.add_argument("ecosystems", nargs="*", help="e.g. 'Ubuntu:22.04:LTS' 'Debian:12' PyPI (default: inferred)")
    p.set_defaults(fn=cmd_vulndb)

    p = sub.add_parser("firewall-import", help="import a pfSense/OPNsense config.xml or UniFi JSON export")
    p.add_argument("id"); p.add_argument("file")
    p.set_defaults(fn=cmd_firewall_import)

    p = sub.add_parser("external-target", help="add public IPs / CIDRs / hostnames you own to the probe scope")
    p.add_argument("values", nargs="+"); p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_external_target)

    p = sub.add_parser("external-scan", help="queue an outside-in scan for enrolled probes")
    p.add_argument("--ports", default=None)
    p.set_defaults(fn=cmd_external_job)

    p = sub.add_parser("mcp", help="run the MCP server over stdio (Claude Desktop / Claude Code / LibreChat)")
    p.set_defaults(fn=cmd_mcp)

    p = sub.add_parser("ask", help="ask the AI security analyst a question")
    p.add_argument("question", nargs="+"); p.add_argument("--provider")
    p.set_defaults(fn=cmd_ask)

    p = sub.add_parser("demo", help="load a demo environment (for trying out the dashboard)")
    p.set_defaults(fn=cmd_demo)

    args = ap.parse_args(argv)
    if args.cmd != "mcp":
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args.fn(args)


if __name__ == "__main__":
    main()
