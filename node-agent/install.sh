#!/usr/bin/env bash
# Install / update the KVM node agent on a host (AlmaLinux 9/10).
#   ./install.sh            (run as root)
set -euo pipefail
SRC=$(cd "$(dirname "$0")" && pwd)
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

command -v virsh >/dev/null || { echo "install KVM/libvirt first" >&2; exit 1; }
rpm -q python3-libvirt >/dev/null || dnf install -y python3-libvirt
rpm -q xorriso >/dev/null || dnf install -y xorriso          # builds per-VM cloud-init seed disks


install -d -m 0750 /opt/kvm-node-agent /etc/kvm-node-agent
install -d -m 0700 /var/lib/kvm-node-agent /var/lib/kvm-node-agent/cloud-init
install -m 0644 "$SRC/agent.py" /opt/kvm-node-agent/agent.py

# System python (has the libvirt binding) + venv that can see system packages
[[ -x /opt/kvm-node-agent/venv/bin/python ]] || /usr/bin/python3 -m venv --system-site-packages /opt/kvm-node-agent/venv
/opt/kvm-node-agent/venv/bin/pip install -q --upgrade pip
/opt/kvm-node-agent/venv/bin/pip install -q -r "$SRC/requirements.txt"
/opt/kvm-node-agent/venv/bin/python -c "import libvirt" || { echo "libvirt python binding not visible in venv" >&2; exit 1; }

if [[ ! -f /etc/kvm-node-agent/config.env ]]; then
  cat > /etc/kvm-node-agent/config.env <<EOF
AGENT_TOKEN=$(openssl rand -hex 32)
NODE_ID=node-1
AGENT_PORT=8770
IMAGE_DIR=/var/lib/libvirt/images
TEMPLATE_DIR=/var/lib/libvirt/images/templates
SEED_DIR=/var/lib/kvm-node-agent/cloud-init
VM_NETWORK=network=default
VM_DEFAULT_USER=admin
EOF
  chmod 0600 /etc/kvm-node-agent/config.env
fi

# add settings introduced in later versions (existing values are never changed)
add_key(){ grep -q "^$1=" /etc/kvm-node-agent/config.env || echo "$1=$2" >> /etc/kvm-node-agent/config.env; }
add_key PUBLIC_BRIDGE ""
add_key PUBLIC_GATEWAY ""
add_key PUBLIC_PREFIX 29
add_key PUBLIC_DNS "1.1.1.1,8.8.8.8"
add_key PUBLIC_POOL ""

install -m 0644 "$SRC/kvm-node-agent.service" /etc/systemd/system/kvm-node-agent.service
systemctl daemon-reload
systemctl enable kvm-node-agent.service
systemctl restart kvm-node-agent.service
sleep 2
systemctl is-active kvm-node-agent.service

T=$(grep ^AGENT_TOKEN= /etc/kvm-node-agent/config.env | cut -d= -f2)
echo
echo "Health check:"
curl -s -m 5 -H "Authorization: Bearer $T" http://127.0.0.1:8770/health; echo
echo
echo "Agent token: ${T:0:6}…(hidden). Show it with:  grep ^AGENT_TOKEN= /etc/kvm-node-agent/config.env"
echo "Give it to the control plane as its AGENT_TOKEN secret (don't paste it into chats)."
