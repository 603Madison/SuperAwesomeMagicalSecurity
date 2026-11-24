# 🛡️ SuperAwesomeMagicalSecurity (SAMS)

An all-in-one security posture platform for home labs, small businesses and organizations. It:

* **finds vulnerabilities**: every package on every host, matched against OSV, with CISA KEV and FIRST EPSS enrichment;
* **checks configuration**: SSH, sudo, SUID, cron, sysctl, host firewall, exposed databases, credentials left on disk;
* **audits firewall policy** for pfSense, OPNsense and UniFi: risky port forwards, WAN-exposed management, flat VLANs, shadowed rules, UPnP and more;
* **looks in from the outside**: off-network probes scan your public IPs and domains and compare what the internet sees with what your firewall says should be open;
* **models attack paths**: "if *this* machine were compromised, what data, credentials, cloud accounts and other machines could the attacker reach, and which single change cuts that off?";
* **runs a SIEM**: auth logs from agents plus syslog from firewalls, with 32 built-in detections (brute force, brute-force-then-success, backdoor accounts, port scans, Windows audit-log clearing, …). Every alert is enriched with the blast radius of the affected host;
* **plans and applies remediation**: fixes are ranked by how much attack-path risk they remove. Package updates can be pushed to agents as signed, human-approved tasks;
* **talks to AI tools**: Claude, OpenAI, Ollama and any OpenAI-compatible model through a built-in analyst. An **MCP server** serves Claude Desktop, Claude Code, LibreChat and Cursor, and an **OpenAI-compatible endpoint** serves LibreChat and Open WebUI.

```
 sams-probe (VPS, internet only) ──HTTPS──► sams-server (DMZ) ◄──HTTPS── sams-agent (every host)
                                              ▲   ▲   ▲
                     firewall API / config ───┘   │   └─── MCP / OpenAI-compatible clients
                     syslog (UDP/TCP 5514) ───────┘
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, wire protocols and attack-graph model,
and [docs/AI.md](docs/AI.md) for AI providers, MCP and LibreChat setup.

| Component | Language | Docs |
|---|---|---|
| `server/` | Python 3.11+, FastAPI, SQLite | this file |
| `agent/` | Go, stdlib only, single static binary (Linux, macOS, Windows) | [agent/README.md](agent/README.md) |
| `probe/` | Go, stdlib only | [probe/README.md](probe/README.md) |

## Try it in two minutes

```bash
python3 -m venv .venv && .venv/bin/pip install -e 'server[ai]'
.venv/bin/sams --data-dir ./data demo          # loads a small demo network with an attack path
SAMS_ADMIN_TOKEN=letmein .venv/bin/sams --data-dir ./data server --port 8443
# open http://127.0.0.1:8443 and sign in with "letmein"
```

Command-line equivalents:

```bash
sams --data-dir ./data paths                   # attack paths from the internet
sams --data-dir ./data blast-radius web        # what an attacker gets from host "web"
sams --data-dir ./data plan                    # risk-ranked remediation plan
```

Analyze a real machine without running a server:

```bash
cd agent && make && sudo ./bin/sams-agent-linux-amd64 collect > /tmp/inv.json
sams --data-dir ./scratch analyze /tmp/inv.json
```

## Deploying

### 1. Server (DMZ)

```bash
pip install './server[ai]'              # or: docker build -t sams server/
cp sams.example.yaml sams.yaml          # edit public_url, ports, AI providers
sams server --host 0.0.0.0 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

On first start the server prints a one-time **admin token**. It also creates an Ed25519 **signing key**
in `data_dir`; agents and probes pin it at enrollment, so back it up.

Recommended DMZ exposure (see [deploy/Caddyfile](deploy/Caddyfile)):

| From | To | Paths / ports |
|---|---|---|
| Internal hosts (agents) | server :443 | `/api/v1/enroll`, `/api/v1/agent/*` |
| Firewalls / switches | server UDP/TCP 5514 | syslog |
| **Internet** (probes) | server :443 | **only** `/api/v1/enroll` and `/api/v1/probe/*` |
| Admin network / VPN | server :443 | everything (UI, `/api/v1/*`, `/mcp`, `/v1/*`) |

### 2. Agents (every host you want assessed)

```bash
sams token --kind host                 # or "Agents → Create enrollment token" in the UI
sudo sams-agent enroll --server https://sams.dmz.example --token <token>
sudo systemctl enable --now sams-agent # unit file in agent/packaging/
```

Patching is **off by default** on each host. To allow approved patch tasks, set `"allow_patching": true`
in `/etc/sams-agent/config.json`. Even then, every task must be approved in the UI and signed by the server.

### 3. External probes (outside your network)

Run `sams-probe` on something that is **not** behind your firewall, such as a $5 VPS or a cloud VM. It only needs outbound internet.

```bash
sams token --kind probe
sams-probe enroll --server https://sams.example.com --token <token>
sams-probe run
```

Add your public IPs, small CIDRs or hostnames to the scope (UI → External, or `sams external-target 203.0.113.5`),
then queue a scan. The probe refuses anything not in the server-signed scope, any private address, and
anything larger than a /24. The server warns you if the probe turns out to be scanning from inside your own WAN IP.

### 4. Firewalls

| Platform | How |
|---|---|
| **UniFi** (UniFi OS consoles, legacy rules and zone-based firewall) | UI → Firewalls → *Connect*, vendor `unifi`, URL of the console, `api_key_env: UNIFI_API_KEY` (or `username` + `password_env`). Or upload a JSON export. |
| **pfSense** | Upload `config.xml` (Diagnostics → Backup & Restore), or install the [pfSense REST API package](https://github.com/jaredhendrickson13/pfsense-api) and connect with `api_key_env`. |
| **OPNsense** | Upload `config.xml`, or connect with an API key/secret (`key_env`, `secret_env`). SAMS downloads the config backup over the API. |

Secrets are never stored by SAMS: connection settings name environment variables, and the API refuses literal passwords.
Firewall configs feed the attack graph's reachability model, so with them SAMS knows the IoT VLAN *can't* reach the database, rather than assuming a flat network.

Send firewall logs to the SIEM: pfSense / OPNsense → *Status → System Logs → Settings → Remote logging* → `sams-server:5514`.
UniFi → *Settings → System → Remote Logging (syslog)* → `sams-server:5514`.

### 5. AI (optional)

```yaml
ai:
  default_provider: claude
  providers:
    - {name: claude, type: anthropic, model: claude-opus-5-5, api_key_env: ANTHROPIC_API_KEY}
    - {name: local, type: ollama, model: llama3.1:70b, base_url: http://ollama:11434, locality: local}
```

* Dashboard → **AI analyst**, or `sams ask "what should I fix first?"`
* **MCP**: `sams mcp` (stdio) or `https://sams/mcp` (streamable HTTP, bearer token)
* **LibreChat / Open WebUI**: add `https://sams/v1` as an OpenAI-compatible endpoint

Data sent to cloud providers is pseudonymized (hostnames, IPs, usernames, fingerprints) unless you set
`allow_sensitive: true`; local providers (`locality: local`) see real identifiers. Details in [docs/AI.md](docs/AI.md).

## Security model (short version)

* Agents run as root, so the server is a high-value target. To limit what a compromised server can do:
  * the agent action set is a fixed allowlist (inventory, patch, patch-all, reboot check), with **no remote shell**;
  * tasks are Ed25519-signed, expire and are replay-protected;
  * patching needs local opt-in on each host.
* Agents never send secret material, only metadata and fingerprints. For example, an SSH key is reported as its SHA256 fingerprint and whether it is encrypted.
* Probes only scan admin-approved, signed scope, and the probe client refuses private, reserved and oversized targets on its own.
* Every dashboard render escapes data from agents, logs and probes; it's all treated as hostile input.

## Development

```bash
cd server && ../.venv/bin/python -m pytest -q      # 226 tests
cd agent  && go test ./... && make all              # cross-compiles linux/darwin/windows
cd probe  && go test ./... && make cross
```

## Status and roadmap

This is a working foundation, not a finished product. Honest gaps:

* **Storage** is SQLite. It's fine for hundreds of hosts; Postgres is the next step for large fleets.
* **Agent platforms**: Linux is thorough; macOS and Windows collectors compile but are best-effort.
* **Windows / AD** attack paths (sessions, ACLs, Kerberoasting) are not modeled yet; the graph is Linux/SSH/cloud-credential-centric.
* **Remediation** auto-applies only package updates. Config fixes come with commands for a human to run.
* **Path probability** uses the single most likely path, a deliberate and explainable under-approximation.
* **SIEM** state, such as threshold windows, lives in memory. There's no auditd, web-server or macOS log parser yet.
* **Not yet:** multi-user RBAC, SSO, or HA.
