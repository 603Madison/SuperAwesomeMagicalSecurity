# Running sams-server with podman

The server ships as one OCI image built from the repository's `Containerfile`. The image
also contains the Linux agent (binaries, `.deb`, `.rpm`) and probe binaries, and serves
them, so hosts install the agent straight from your server.

## Build

```bash
podman build -t localhost/sams:latest .
# behind a TLS-inspecting proxy, hand the build its CA (not baked into the image):
podman build --secret id=extra_ca,src=/path/to/proxy-ca.pem -t localhost/sams:latest .
```

## Run with systemd (Quadlet, recommended)

Rootless, as an unprivileged user on the DMZ host:

```bash
mkdir -p ~/.config/containers/systemd
cp deploy/podman/sams.container deploy/podman/sams-data.volume ~/.config/containers/systemd/
# edit SAMS_PUBLIC_URL in sams.container first
printf '%s' "$(openssl rand -base64 32)" | podman secret create sams-admin-token -
systemctl --user daemon-reload
systemctl --user start sams
loginctl enable-linger "$USER"       # keep running after logout
podman secret inspect --showsecret sams-admin-token --format '{{.SecretData}}'   # your admin token
```

`AutoUpdate=local` lets `podman auto-update` restart the service when you rebuild the image.

## Run with compose

```bash
printf '%s' "$(openssl rand -base64 32)" | podman secret create sams-admin-token -
cd deploy/podman && podman-compose up -d
```

## One-off

```bash
podman run -d --name sams -p 8443:8443 -p 5514:5514/udp -p 5514:5514/tcp \
  --read-only --tmpfs /tmp --cap-drop=all --security-opt=no-new-privileges \
  --secret sams-admin-token,type=env,target=SAMS_ADMIN_TOKEN \
  -e SAMS_PUBLIC_URL=https://sams.dmz.example:8443 \
  -v sams-data:/var/lib/sams:Z localhost/sams:latest
```

## Configuration

| How | What |
|---|---|
| Environment | `SAMS_PUBLIC_URL`, `SAMS_ADMIN_TOKEN`, `SAMS_VULN_MODE`, `SAMS_PORT`; any of them can be given as `<NAME>_FILE` pointing at a file |
| Config file | mount a `sams.yaml` (see `sams.example.yaml`) at `/etc/sams/sams.yaml` |
| Secrets | `podman secret create` then `Secret=<name>,type=env,target=<ENV>`; AI and firewall keys are referenced by env-var name in config (`api_key_env: ANTHROPIC_API_KEY`) |
| Data | volume at `/var/lib/sams`: SQLite DB, the Ed25519 signing key agents pin, caches. Back it up. |

Without `SAMS_ADMIN_TOKEN`, the server generates one on first start and prints it once: `podman logs sams`.

Run CLI commands inside the container, for example `podman exec -it sams sams token --kind host` or `podman exec sams sams plan`.

## Networking notes

* TLS: terminate it in a reverse proxy in front of the container (see `deploy/Caddyfile`), or mount a
  certificate and run `server --tls-cert ... --tls-key ...`.
* Syslog source addresses: rootless podman before v5 (slirp4netns) rewrites the source IP of published
  ports, so every firewall would look like the same host. `Network=pasta` (the default on podman 5) keeps
  real source addresses; rootful podman is unaffected.
* Ports 8443 and 5514 are unprivileged, so no extra capabilities are needed even rootless.

## Rootful on a VLAN (macvlan), with HTTPS origin

Hosts that put each container on its own VLAN run podman rootful (creating macvlan/ipvlan
interfaces needs host privileges). Confine it with a per-container user namespace instead:

```bash
sudo podman run -d --name=sams \
  --userns=auto:size=65536 --cap-drop=all --security-opt=no-new-privileges \
  --pids-limit=512 --memory=1g --read-only --tmpfs /tmp \
  --network dmz_vlan --ip 10.0.2.40 \
  -e SAMS_PUBLIC_URL=https://sams-agents.example.org -e SAMS_TRUST_PROXY=true \
  --secret sams-admin-token,type=env,target=SAMS_ADMIN_TOKEN \
  --secret sams-tls-key,type=mount,target=/etc/sams/tls.key,uid=10001,gid=10001,mode=0400 \
  -v /srv/podman/sams_data:/var/lib/sams:U \
  -v /srv/podman/sams_tls/tls.crt:/etc/sams/tls.crt:ro \
  --restart unless-stopped --label io.containers.autoupdate=local \
  localhost/sams:latest server --host 0.0.0.0 --port 8443 --tls-cert /etc/sams/tls.crt --tls-key /etc/sams/tls.key
```

* `--userns=auto` needs a subuid/subgid range for the `containers` user (`/etc/subuid`, `/etc/subgid`).
* The server needs **no** capabilities: the image already runs as UID 10001.
* `/etc/sams/tls.crt` and `/etc/sams/tls.key` exist as empty files in the image so they can be mount
  targets on a read-only root filesystem.
* On macvlan, `-p` is ignored. The container has its own IP, so syslog keeps real source addresses.
