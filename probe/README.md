# sams-probe: external (outside-in) probe

`sams-probe` looks at your organization **from the internet, the way an attacker
would**. It runs on a machine that is completely *outside* your network (a $4/month
VPS, a cloud free-tier instance, a friend's connection) and has nothing but
internet access. It pulls signed scan jobs from `sams-server` (which typically lives
in your DMZ), scans only the public assets you put in scope, and reports what is
actually reachable. The server then compares that with what your firewall
configuration *says* should be exposed and with the inside view from host agents.

It is a single static Go binary built from the standard library only (no third-party
dependencies), it needs no root, and it uses no raw sockets.

## Why it must be off-network

Scanning your public IP from inside your LAN tells you almost nothing:

* **NAT hairpinning / loopback** makes port forwards look different (or invisible) from inside.
* **Firewall rules are interface-based.** LAN→WAN-address traffic hits different rules than
  internet→WAN traffic, so "it's closed when I test it" often means nothing.
* **Upstream filtering** (ISP blocks on 25/445, cloud security groups, CGNAT) only shows up
  from the outside.
* **DNS views differ**, e.g. split-horizon DNS and internal resolvers that answer what the
  internet never sees.

The probe sends a heartbeat and the server replies with the IP it saw the probe come from.
If that IP is private, or equals one of your WAN addresses, the probe logs a warning that it
is probably *not* outside. The server should raise this too.

## What it checks

| Check | What it does (no logins, no exploitation) |
|---|---|
| `tcp` | TCP connect scan (nmap top-100 / top-1000 lists plus high-risk ports such as 2375, 6379, 9200, 10250, 27017) |
| `banner` | Reads greetings (SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC, Telnet) and sends harmless probes: Redis `PING`, Memcached `version`, RDP X.224 connection request, PostgreSQL SSLRequest, HTTP `GET /` |
| `tls` | Supported TLS versions (1.0–1.3), weak cipher acceptance, certificate subject/issuer/SANs/expiry, self-signed, chain trust, hostname mismatch, key size |
| `http` | `GET /` (≤3 same-host redirects, 256 KB cap): status, title, server, security headers, directory listing, and admin/login fingerprints (pfSense, OPNsense, UniFi, Synology, QNAP, Proxmox, TrueNAS, ESXi/vCenter, Portainer, Webmin, Cockpit, phpMyAdmin, Kibana, Jenkins, MikroTik, FortiGate, SonicWall, Cisco ASA, OWA, GitLab, Grafana, Home Assistant, Nextcloud, Plex, generic routers). Plus benign `/version` calls for Docker/etcd APIs |
| `dns` | A/AAAA/MX/NS/TXT/CAA/CNAME, SPF and DMARC evaluation, zone-transfer (AXFR) test against each authoritative NS, dangling-CNAME (subdomain takeover) hint |
| `udp` | Open DNS resolver, SNMP v2c `public` (sysDescr only), NTP reachability, SSDP/UPnP on WAN |

Default checks for jobs and standalone scans are `tcp,banner,tls,http,dns`. `udp` is opt-in.

### Issue IDs reported

`scope_refused`, `telnet_exposed`, `ftp_exposed`, `smb_exposed`, `msrpc_exposed`, `rdp_exposed`,
`vnc_exposed`, `winrm_exposed`, `memcached_exposed`, `mongodb_exposed`, `elasticsearch_exposed`,
`database_exposed`, `redis_exposed`, `redis_unauthenticated`, `docker_api_exposed`, `etcd_exposed`,
`kubelet_exposed`, `kubernetes_api_exposed`, `rpc_nfs_exposed`, `ipmi_exposed`, `pptp_exposed`,
`mqtt_exposed`, `printer_exposed`, `amqp_exposed`, `rsync_exposed`, `ldap_exposed`, `ssh_exposed`,
`ssh_outdated`, `ssh_protocol_v1`, `admin_panel_exposed`, `vpn_portal_exposed`, `app_login_exposed`,
`http_login_cleartext`, `http_directory_listing`, `http_missing_hsts`, `http_missing_security_headers`,
`tls_legacy_protocol`, `tls_no_modern_protocol`, `tls_weak_cipher`, `tls_weak_key`, `tls_cert_expired`,
`tls_cert_expiring`, `tls_cert_self_signed`, `tls_hostname_mismatch`, `dns_spf_missing`,
`dns_spf_multiple`, `dns_spf_permissive`, `dns_dmarc_missing`, `dns_dmarc_none`, `dns_dmarc_partial`,
`dns_dmarc_invalid`, `dns_axfr_open`, `dns_dangling_cname`, `dns_open_resolver`, `snmp_public_community`,
`ntp_exposed`, `upnp_exposed`.

When an exposure rule's service answers without authentication (Redis `PING`, Memcached, an
Elasticsearch banner, the Docker/etcd `/version` endpoints), the severity is raised to `critical`.

## Safety rails

* **Scope is signed.** Jobs arrive as Ed25519-signed envelopes. The probe pins the server key at
  enrollment and verifies the signature over the raw payload bytes *before* parsing anything.
  It also checks that the job is addressed to its own probe ID and hasn't expired.
* **Public addresses only.** In `run` mode, targets that are (or resolve to) RFC1918, loopback,
  link-local, CGNAT, multicast, documentation or reserved space are refused and reported as
  `scope_refused`. A hostname with *any* private A/AAAA record is refused, which guards against
  DNS rebinding.
* **Bounded.** CIDRs above 256 addresses are refused. Connections are paced by a token bucket
  (`rate_per_sec`, default 200/s), concurrency is bounded, and every connection has a timeout.
  Jobs stop at `expires_at` or `--max-job-duration` (default 2h) and report partial results.
* **HTTP never leaves the target.** Connections are pinned to the scanned IP, and redirects to
  other hosts are not followed.

## Legal

Only scan systems you own or have **written authorization** to test. Port scanning third
parties may violate law or your provider's acceptable-use policy. Many VPS providers allow
scanning your own assets but react to complaints, so keep `rate_per_sec` modest and put
contact information in the probe host's reverse DNS or web page if you scan frequently.

## Deploying on a VPS

```sh
# on your workstation
make cross                       # bin/sams-probe-linux-amd64, -linux-arm64, -darwin-arm64, -windows-amd64.exe
scp bin/sams-probe-linux-amd64 vps:/tmp/sams-probe

# on the sams-server (DMZ): mint a one-time probe token and add scope
sams token create --kind probe
sams external add 203.0.113.10        # your WAN IP(s) / public hostnames

# on the VPS
sudo install -m 0755 /tmp/sams-probe /usr/local/bin/sams-probe
sudo install -m 0644 sams-probe.service /etc/systemd/system/   # from probe/packaging/
sudo systemctl daemon-reload
sudo systemd-run --wait --pty -p DynamicUser=yes -p StateDirectory=sams-probe \
  /usr/local/bin/sams-probe enroll --config /var/lib/sams-probe/config.json \
  --server https://sams.example.com:8443 --token <TOKEN>
sudo systemctl enable --now sams-probe
journalctl -u sams-probe -f
```

The unit runs under `DynamicUser` with `NoNewPrivileges`, `ProtectSystem=strict`, an empty
capability set, a syscall filter and only `AF_INET/AF_INET6/AF_UNIX` sockets. The state
directory (credentials) is mode 0700. Use `--ca-file` if the server uses a private CA.
`--insecure-skip-verify` exists for labs only.

The server needs to be reachable from the internet on its API port for the probe to
connect. Expose only `/api/v1/enroll` and `/api/v1/probe/*` through a reverse proxy, or allowlist
the VPS's IP on the firewall.

## Usage

```
sams-probe enroll --server URL --token TOKEN [--config PATH] [--ca-file PEM] [--insecure-skip-verify] [--name NAME]
sams-probe run    [--config PATH] [--poll 60s] [--once] [--max-job-duration 2h]
sams-probe scan   --target HOST[,HOST...] [--ports top100|top1000|all|1-1024|22,80]
                  [--checks tcp,banner,tls,http,dns,udp] [--rate 200] [--timeout 30m] [--json] [--allow-private]
sams-probe version
```

`scan` is standalone mode for an ad-hoc assessment without a server. `--json` prints an
`ExternalScanResult` document, the same shape the server ingests.
`--allow-private` is only available in standalone mode, for testing.

Config defaults to `~/.config/sams-probe/config.json` (override with `--config` or
`SAMS_PROBE_CONFIG`) and is written with mode 0600.

## Development

```sh
make vet test build     # go vet, unit + end-to-end tests (local TLS/HTTP/DNS fakes), build
make cross              # linux-amd64/arm64, darwin-arm64, windows-amd64
```
