# SuperAwesomeMagicalSecurity (SAMS): Architecture

SAMS assesses the security posture of a home lab, small business or organization,
discovers attack paths, and recommends (and optionally applies) remediations.

```
                         INTERNET
   ┌───────────────┐        │          ┌──────────────────────────┐
   │ sams-probe    │  HTTPS │          │ AI providers (optional)  │
   │ (off-network, │────────┼─────┐    │ Anthropic / OpenAI /     │
   │  VPS / cloud) │  scans │     │    │ Ollama / OpenAI-compat   │
   └───────────────┘   ▼    │     │    └────────────▲─────────────┘
                   ┌────────┴──┐  │                 │
                   │ Firewall  │  │   DMZ           │
                   │ pfSense / │  │  ┌──────────────┴───────────────┐
                   │ OPNsense /│◄─┼──┤ sams-server (FastAPI+SQLite) │◄── MCP clients (Claude, LibreChat…)
                   │ UniFi     │ API │ vuln · graph · SIEM · fw ·   │◄── OpenAI-compatible chat UIs
                   └────┬──────┘  │  │ remediation · AI · web UI    │◄── syslog (UDP/TCP 5514)
                        │ LAN     │  └──────────────▲───────────────┘
             ┌──────────┼─────────┘                 │ HTTPS (agent pulls; signed tasks)
        ┌────┴───┐ ┌────┴───┐ ┌────────┐            │
        │sams-   │ │sams-   │ │sams-   │────────────┘
        │agent   │ │agent   │ │agent   │   inventory · logs · task results
        └────────┘ └────────┘ └────────┘
```

## Components

| Component | Language | Location | Role |
|---|---|---|---|
| `sams-server` | Python 3.11+ (FastAPI, SQLite) | `server/sams` | Control plane, analysis, API, UI, MCP |
| `sams-agent` | Go (stdlib only) | `agent/` | Host inventory, log shipping, signed patch tasks |
| `sams-probe` | Go (stdlib only) | `probe/` | Outside-in scanning from a host with internet only |

All analysis lives on the server. Agents and probes only collect facts and run
narrowly scoped, signed instructions. The attack graph needs the global view
to model lateral movement anyway, and this keeps endpoint code small and
auditable.

## Trust model

* **Enrollment**: an admin mints a one-time enrollment token (`sams token create --kind host|probe`).
  The agent exchanges it for `agent_id` + `agent_key` (stored hashed server-side) and
  **pins the server's Ed25519 public key**.
* **Agent → server auth**: `Authorization: Bearer <agent_id>:<agent_key>` on every call.
* **Server → agent instructions are signed** (`sams/crypto.py`). Envelope:
  `{"payload": b64(json bytes), "signature": b64(ed25519(payload bytes)), "key_id": "..."}`.
  Verifiers check the signature over the decoded bytes **before** parsing JSON.
* **Agents only execute an allowlist of actions** (`collect`, `patch`, `patch_all`,
  `reboot_required_check`). There is no "run arbitrary command" action, by design.
  Patching additionally requires `"allow_patching": true` in the agent's *local*
  config, so a compromised server alone cannot push package changes.
* **Probes only scan targets inside a signed scope document**, and the scope must
  come from the admin-maintained `external_targets` list (CIDRs capped at 256 hosts).
  Probes refuse private/reserved addresses because they live outside the network.
* **Secrets are never stored in the DB.** Firewall/AI credentials are referenced by
  environment-variable name. Agents never transmit secret material, only metadata
  and fingerprints (e.g. SSH key SHA256 fingerprints, masked AWS key IDs).

## Agent wire protocol (`/api/v1`)

| Method | Path | Body → Response |
|---|---|---|
| POST | `/enroll` | `{token, kind: "host"\|"probe", hostname, version, os}` → `{agent_id, agent_key, server_public_key, key_id}` |
| GET | `/agent/config` | → `{collect_interval_seconds, log_sources: [..], server_time}` |
| POST | `/agent/inventory` | `Inventory` JSON (see `server/sams/models.py`) → `{asset_id, findings}` |
| POST | `/agent/logs` | `{"lines": [{"source": "auth.log"\|"journald"\|"windows"\|..., "line": "...", "ts": "RFC3339?"}]}` → `{accepted, alerts}` |
| GET | `/agent/tasks` | → `{"tasks": [SignedEnvelope]}` payload = `{id, agent_id, action, params, dry_run, expires_at}` |
| POST | `/agent/tasks/{id}/result` | `{status: "succeeded"\|"failed"\|"rejected", output, details}` |

Log line conventions (parsed server-side by `sams/siem/parsers.py`):

* `auth.log` / `secure` / `syslog`: raw classic syslog lines (`Nov 24 10:00:01 host sshd[1]: ...`).
* `journald`: reconstructed as `<RFC3339 ts> <host> <ident>[<pid>]: <message>`.
* `windows`: one JSON object per line: `{"EventID":4625,"TimeCreated":"...","Provider":"...","Message":"...","Data":{...}}`.

## Probe wire protocol (`/api/v1/probe`)

| Method | Path | Body → Response |
|---|---|---|
| POST | `/probe/heartbeat` | `{version}` → `{seen_ip, server_time}` (the server tells the probe its public egress IP) |
| GET | `/probe/jobs/next` | → `204` or `{"job": SignedEnvelope}` payload = `{job_id, probe_id, targets: [str], ports: [int], checks: [str], rate_per_sec, expires_at}` |
| POST | `/probe/jobs/{job_id}/result` | `ExternalScanResult` JSON |

`checks` ⊆ `["tcp", "banner", "tls", "http", "dns", "udp"]`.

## Server modules

| Module | Entry points |
|---|---|
| `sams.models` | All shared pydantic contracts |
| `sams.db.Store` | SQLite persistence |
| `sams.vuln.scanner.VulnScanner` | `scan(inv, asset_id) -> list[Finding]`. One finding per vulnerable package, evidence lists each vuln with CVSS/attack vector/KEV/EPSS |
| `sams.hardening.checks` | `check_inventory(inv, asset_id) -> list[Finding]` |
| `sams.firewall` | adapters → `FirewallConfig`; `analyzer.analyze(cfg, asset_id) -> list[Finding]`; `FirewallConfig.evaluate()` for reachability |
| `sams.siem` | `parsers.parse_line`, `engine.DetectionEngine`, `syslog` listeners, `pipeline.ingest` |
| `sams.external` | scope → signed job, result → findings, inside/outside discrepancy analysis |
| `sams.graph` | attack graph build, blast radius, attack paths, choke points |
| `sams.remediation` | prioritized plan ranked by attack-path risk reduction, task creation |
| `sams.posture` | scores per host and org |
| `sams.ai` | provider adapters, tool registry, analyst loop, MCP server, OpenAI-compatible endpoint |

## Attack graph model

Nodes are *footholds* and *assets*:

* `internet`: the attacker's starting point for external paths
* `host:<asset>#user:<name>` / `host:<asset>#root`: code execution at a privilege level
* `cred:<fingerprint>`: a credential an attacker can steal
* `data:<asset>:<kind>:<name>`: a datastore
* `cloud:<kind>:<id>`: cloud/k8s/registry identities reachable through stolen credentials
* `ext:<ip>`: unmanaged hosts known only from SSH known_hosts / connections

Edges carry a `technique` (MITRE ATT&CK id), a success `likelihood` ∈ (0,1], and
`evidence`. Edges are evidence-based. Each one exists because of something an
agent, firewall, or probe actually observed:

| Edge | Evidence |
|---|---|
| internet → host#svcuser | port forward / WAN rule + listener + (vuln with AV:N → high likelihood) |
| host#X → host#Y (network exploit) | firewall permits X→Y:port and Y's listener package has an AV:N vuln |
| host#user → cred | credential file owned by user (root reads all) |
| cred(ssh) → host#user | key fingerprint present in target's `authorized_keys` + network reachability |
| host#user → host#root | sudo NOPASSWD / sudo / docker group / GTFOBins SUID / writable root cron / local privesc vuln |
| host#root → host#user | root can become anyone |
| host#(owner/root) → data | datastore on host |
| host#user → data (remote) | observed client connection to DB port / DB credential file targeting it |
| cred(cloud/kube) → cloud:… | credential grants access to a cloud identity |

Path likelihood is the product of edge likelihoods. Shortest paths use weights of
`-log(likelihood)`. Remediations map to the edges they remove, and the planner ranks
them greedily by how much **risk** they eliminate, where risk is the sum over
critical assets of `criticality × P(reach)` from the internet and from every host.
