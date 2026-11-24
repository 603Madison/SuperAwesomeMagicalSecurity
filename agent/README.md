# sams-agent

The SuperAwesomeMagicalSecurity host agent. It is a single static Go binary,
built from the **standard library only** (no third-party modules), that:

* **inventories** the host: OS, packages (dpkg/rpm/apk/pip/npm/brew/Windows), listening
  services with owning process/user/package, established connections, users, groups,
  sudoers, SSH `authorized_keys`, discovered credentials (metadata only), `known_hosts`,
  datastores, hardening state and containers
* **ships security logs** (`/var/log/auth.log`, `/var/log/secure`, journald, Windows
  Security/System event logs) to the server's SIEM
* **executes signed tasks** from an allowlist (`collect`, `patch`, `patch_all`,
  `reboot_required_check`)

All analysis (vulnerability matching, attack paths, remediation) happens on the server.
See [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

## Build

```sh
make test          # go vet (linux/windows/darwin) + unit tests
make all           # bin/sams-agent-{linux-amd64,linux-arm64,darwin-arm64,windows-amd64.exe}
make build         # bin/sams-agent for the current platform
```

## Install & enroll (Linux)

```sh
install -m 0755 bin/sams-agent-linux-amd64 /usr/local/bin/sams-agent

# get a one-time token on the server:  sams token create --kind host
sams-agent enroll --server https://sams.dmz.example:8443 --token <TOKEN> \
    [--ca-file /path/to/ca.pem] [--allow-patching]

install -m 0644 packaging/sams-agent.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now sams-agent
```

Enrollment stores credentials and the **pinned server signing key** in
`/etc/sams-agent/config.json` (mode 0600). Override the path with `--config` or
`SAMS_AGENT_CONFIG`. Defaults on other platforms:
`C:\ProgramData\sams-agent\config.json` (Windows) and
`/Library/Application Support/sams-agent/config.json` (macOS).

## Commands

| Command | Description |
|---|---|
| `sams-agent enroll --server URL --token T [--ca-file PEM] [--insecure-skip-verify] [--allow-patching]` | Exchange a one-time token for agent credentials, pin the server key |
| `sams-agent run` | Main loop: inventory every interval (server-suggested, ≥5 min, jittered), ship logs every ~10 s, poll tasks every 60 s |
| `sams-agent collect [--pretty]` | Print one inventory as JSON to stdout. No server needed, so it's handy for audits and debugging |
| `sams-agent version` | Print version |

## Config file

```json
{
  "server_url": "https://sams.dmz.example:8443",
  "agent_id": "agt_…",
  "agent_key": "…",
  "server_public_key": "<base64 Ed25519>",
  "key_id": "…",
  "ca_file": "",
  "insecure_skip_verify": false,
  "allow_patching": false,
  "collect_interval_seconds": 0,
  "log_sources": [],
  "disable_logs": false,
  "sensitive_paths": ["/srv/finance"]
}
```

* `allow_patching`: **local opt-in** required before any `patch`/`patch_all` task runs.
* `collect_interval_seconds` / `log_sources`: local overrides of the server's suggestions.
  Log sources are absolute file paths, `journald` (security identifiers + kernel; kernel
  only if `auth.log`/`secure` is also tailed, to avoid duplicates), `journald:all`, or
  `windows`.
* `sensitive_paths`: extra paths reported as `files` datastores (crown-jewel data for the
  attack graph).

State lives next to the config: `log_state.json` (file offsets / Windows record IDs) and
`tasks_done.json` (executed task IDs, for replay protection).

## Security design

* **Signed tasks.** Every task is an Ed25519-signed envelope. The signature is checked over
  the exact payload bytes against the key pinned at enrollment *before* the JSON is parsed.
  The agent then checks `agent_id`, `expires_at` and the action allowlist. Executed task
  IDs are recorded, so replays are ignored.
* **No remote shell.** There is no "run command" action. Patch tasks pass validated package
  names (`^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$`) as argv to the package manager, never
  through a shell.
* **Patching is off by default** and can only be enabled on the host itself, so a
  compromised server cannot push package changes to hosts whose owners didn't opt in.
* **No secret material leaves the host.** Credential discovery reports the kind, owner,
  path, permissions, masked identifiers (`AKIA****MPLE`), targets and public-key
  fingerprints. Private keys are read only to detect encryption or derive the public half,
  and the buffer is zeroed afterwards. Shell history is reported as a match count only.
* TLS 1.2+ with an optional custom CA. `--insecure-skip-verify` exists for labs only.

## Platform support

| | Linux | macOS | Windows |
|---|---|---|---|
| OS / host info | full | sw_vers, ioreg | registry |
| Packages | dpkg, rpm, apk, pip, npm | Homebrew cellar, /Applications, pip, npm | Uninstall registry keys, hotfixes |
| Listeners | /proc/net + /proc/*/fd (process, user, owning package) | lsof | Get-NetTCPConnection (netstat fallback) |
| Connections | yes | – | – |
| Users / admin | passwd/group/shadow | dscl | Get-LocalUser / Administrators |
| sudoers | yes | yes | n/a |
| SSH keys / credentials | yes | yes | yes (`%USERPROFILE%`) |
| Hardening | sshd, ufw/nft/iptables, SUID, world-writable /etc, PATH, cron, auto-updates, sysctl, SELinux/AppArmor, docker.sock, reboot, Secure Boot, dm-crypt | sshd, ALF, FileVault, auto-update, SIP | firewall profiles, Defender, BitLocker, Secure Boot, Windows Update, RDP, SMB1 |
| Containers | Docker API | – | – |
| Logs | files + journald | files | Security/System event logs |
| Patching | apt, dnf/yum, zypper, apk | brew (non-root only) | winget |
