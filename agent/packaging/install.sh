#!/bin/sh
# SuperAwesomeMagicalSecurity Linux agent installer.
#
# Served by sams-server at /install.sh with the server URL filled in:
#   curl -fsSL https://sams.example:8443/install.sh | sudo sh -s -- --token <enrollment-token>
#
# What it does (and nothing else):
#   1. downloads sams-agent for this CPU from the server and checks its SHA256
#   2. installs it to /usr/local/bin/sams-agent and a systemd unit
#   3. enrolls with the one-time token (pins the server's signing key)
#   4. enables and starts the service
# Re-running it upgrades the binary and keeps the existing enrollment.
set -eu

SERVER="__SAMS_SERVER__"
TOKEN=""
CA_FILE=""
INSECURE=0
ALLOW_PATCHING=0
NO_START=0
PREFIX=/usr/local/bin
CONFIG=/etc/sams-agent/config.json
UNIT=/etc/systemd/system/sams-agent.service

usage() {
    cat <<EOF
Usage: install.sh [options]
  --token TOKEN            one-time enrollment token (required for first install)
  --server URL             SAMS server URL (default: $SERVER)
  --ca-file PEM            trust this CA for the server's certificate
  --insecure-skip-verify   skip TLS verification (labs only)
  --allow-patching         let this host apply approved, signed patch tasks
  --no-start               install and enroll but do not start the service
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --token) TOKEN="${2:-}"; shift 2 ;;
        --server) SERVER="${2:-}"; shift 2 ;;
        --ca-file) CA_FILE="${2:-}"; shift 2 ;;
        --insecure-skip-verify) INSECURE=1; shift ;;
        --allow-patching) ALLOW_PATCHING=1; shift ;;
        --no-start) NO_START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo sh -s -- ...)"
[ "$(uname -s)" = "Linux" ] || die "this installer is for Linux"
case "$SERVER" in
    http://*|https://*) ;;
    *) die "--server must be an http(s) URL" ;;
esac
SERVER="${SERVER%/}"
case "$SERVER" in http://*) echo "warning: $SERVER is not HTTPS; the agent key and logs travel in clear text" >&2 ;; esac

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported CPU $(uname -m); build from source: https://github.com/603madison/superawesomemagicalsecurity/tree/main/agent" ;;
esac

if command -v curl >/dev/null 2>&1; then
    fetch() {
        set -- -fsSL --proto '=https,http' --retry 3 -o "$2" "$1"
        [ -n "$CA_FILE" ] && set -- --cacert "$CA_FILE" "$@"
        [ "$INSECURE" -eq 1 ] && set -- -k "$@"
        curl "$@"
    }
elif command -v wget >/dev/null 2>&1; then
    fetch() {
        set -- -q -O "$2" "$1"
        [ -n "$CA_FILE" ] && set -- --ca-certificate="$CA_FILE" "$@"
        [ "$INSECURE" -eq 1 ] && set -- --no-check-certificate "$@"
        wget "$@"
    }
else
    die "need curl or wget"
fi
command -v sha256sum >/dev/null 2>&1 || die "need sha256sum (coreutils)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

BIN="sams-agent-linux-$ARCH"
say "Downloading $BIN from $SERVER"
fetch "$SERVER/downloads/$BIN" "$TMP/$BIN" || die "download failed"
fetch "$SERVER/downloads/SHA256SUMS" "$TMP/SHA256SUMS" || die "checksum download failed"
( cd "$TMP" && grep " $BIN\$" SHA256SUMS | sha256sum -c - >/dev/null ) || die "checksum mismatch for $BIN"
say "Checksum OK"

install -d -m 0755 "$PREFIX"
install -m 0755 "$TMP/$BIN" "$PREFIX/sams-agent.new"
mv -f "$PREFIX/sams-agent.new" "$PREFIX/sams-agent"
say "Installed $PREFIX/sams-agent ($("$PREFIX/sams-agent" version 2>/dev/null || echo unknown version))"

HAVE_SYSTEMD=0
[ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && HAVE_SYSTEMD=1

if [ "$HAVE_SYSTEMD" -eq 1 ]; then
    cat > "$UNIT" <<EOF
[Unit]
Description=SuperAwesomeMagicalSecurity host agent
Documentation=https://github.com/603madison/superawesomemagicalsecurity
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/sams-agent run --config $CONFIG
Restart=always
RestartSec=10
# Root is needed to read /etc/shadow, other users' homes and /proc/*/fd,
# and to run the package manager when allow_patching is enabled.
User=root
Nice=10
IOSchedulingClass=idle
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi

if [ -f "$CONFIG" ]; then
    say "Already enrolled ($CONFIG exists); keeping the existing enrollment"
else
    [ -n "$TOKEN" ] || die "--token is required for the first install (create one in the SAMS UI under Agents)"
    set -- enroll --server "$SERVER" --token "$TOKEN" --config "$CONFIG"
    [ -n "$CA_FILE" ] && set -- "$@" --ca-file "$CA_FILE"
    [ "$INSECURE" -eq 1 ] && set -- "$@" --insecure-skip-verify
    [ "$ALLOW_PATCHING" -eq 1 ] && set -- "$@" --allow-patching
    "$PREFIX/sams-agent" "$@"
fi

if [ "$NO_START" -eq 1 ]; then
    say "Done. Start later with: systemctl enable --now sams-agent"
elif [ "$HAVE_SYSTEMD" -eq 1 ]; then
    systemctl enable sams-agent >/dev/null 2>&1
    systemctl restart sams-agent
    say "sams-agent is running. Logs: journalctl -u sams-agent -f"
else
    say "No systemd found. Start the agent with your init system:"
    echo "    $PREFIX/sams-agent run --config $CONFIG"
fi
