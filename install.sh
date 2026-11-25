#!/usr/bin/env bash
# Install the Linux ops MCP server on an AlmaLinux 9/10 KVM host.
#   sudo ./install.sh ops.example.com
# Afterwards: point a Cloudflare Tunnel hostname at http://127.0.0.1:8765 (see README.md)
# and add the printed URL to Claude as a custom connector.
set -euo pipefail
HOST=${1:-}
if [[ -z $HOST && ! -f /etc/claude-ops/config.env ]]; then
  echo "usage: sudo ./install.sh <public hostname, e.g. ops.example.com>  (only needed on first install)" >&2
  exit 1
fi
SRC=$(cd "$(dirname "$0")" && pwd)

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

# Python >= 3.10 (mcp SDK requirement). AlmaLinux 9 ships 3.9 as python3, so use 3.12.
PY=$(command -v python3.12 || command -v python3.11 || true)
if [[ -z $PY ]]; then dnf install -y python3.12 python3.12-pip; PY=$(command -v python3.12); fi

id claude-ops &>/dev/null || useradd --system --home-dir /opt/claude-ops --shell /sbin/nologin claude-ops
install -d -o claude-ops -g claude-ops -m 0750 /opt/claude-ops /opt/claude-ops/work
install -d -o claude-ops -g claude-ops -m 0750 /var/log/claude-ops
install -d -o root -g claude-ops -m 0750 /etc/claude-ops

install -o root -g claude-ops -m 0644 "$SRC/ops_mcp.py" /opt/claude-ops/ops_mcp.py
"$PY" -m venv /opt/claude-ops/venv
/opt/claude-ops/venv/bin/pip install -q --upgrade pip
/opt/claude-ops/venv/bin/pip install -q -r "$SRC/requirements.txt"

if [[ ! -f /etc/claude-ops/config.env ]]; then
  TOKEN=$(openssl rand -hex 32)
  cat > /etc/claude-ops/config.env <<EOF
OPS_MCP_TOKEN=$TOKEN
OPS_MCP_PUBLIC_HOST=$HOST
OPS_MCP_PORT=8765
EOF
  chown root:claude-ops /etc/claude-ops/config.env; chmod 0640 /etc/claude-ops/config.env
fi
[[ -f /etc/claude-ops/admin-until ]] || { echo 0 > /etc/claude-ops/admin-until; chmod 0644 /etc/claude-ops/admin-until; }

install -m 0755 "$SRC/claude-ops-admin" /usr/local/sbin/claude-ops-admin
# sudo's secure_path on AlmaLinux/RHEL has no /usr/local/sbin, so `sudo claude-ops-admin` needs this link
ln -sf /usr/local/sbin/claude-ops-admin /usr/sbin/claude-ops-admin
install -o root -g root -m 0755 "$SRC/claude-ops-asterisk" /usr/local/sbin/claude-ops-asterisk
install -o root -g root -m 0755 "$SRC/claude-ops-audit" /usr/local/sbin/claude-ops-audit
visudo -cf "$SRC/claude-ops.sudoers"
install -m 0440 "$SRC/claude-ops.sudoers" /etc/sudoers.d/claude-ops
install -m 0644 "$SRC/claude-ops-mcp.service" /etc/systemd/system/claude-ops-mcp.service
systemctl daemon-reload
systemctl enable claude-ops-mcp.service
systemctl restart claude-ops-mcp.service
sleep 2
systemctl --no-pager --lines=5 status claude-ops-mcp.service || true

TOKEN=$(grep ^OPS_MCP_TOKEN= /etc/claude-ops/config.env | cut -d= -f2)
echo
echo "Installed. Local check (should print JSON with \"linux-ops\"):"
echo "  curl -s -m 5 -X POST http://127.0.0.1:8765/\$TOKEN/mcp -H 'Content-Type: application/json' \\"
echo "    -H 'Accept: application/json, text/event-stream' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}'"
HOST=${HOST:-$(grep ^OPS_MCP_PUBLIC_HOST= /etc/claude-ops/config.env | cut -d= -f2)}
echo "Connector URL: https://$HOST/${TOKEN:0:6}…(hidden)…/mcp"
echo "To show the full URL (contains the access key — don't paste it into chats or tickets):"
echo "    sudo grep ^OPS_MCP_TOKEN= /etc/claude-ops/config.env"
echo "Admin mode is OFF. Turn it on when needed:  sudo claude-ops-admin 2h"
