#!/bin/sh
# Runs after the .deb/.rpm installs. The agent is not started until it is enrolled.
set -e
install -d -m 0700 /etc/sams-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    if [ -f /etc/sams-agent/config.json ]; then
        systemctl try-restart sams-agent.service || true
    fi
fi
if [ ! -f /etc/sams-agent/config.json ]; then
    cat <<'MSG'

sams-agent installed. Enroll it, then start it:
    sudo sams-agent enroll --server https://<sams-server>:8443 --token <token>
    sudo systemctl enable --now sams-agent

MSG
fi
