#!/usr/bin/env bash
# One-command setup of a KVM node on AlmaLinux / Rocky / RHEL 9 or 10.
#
#   sudo bash setup-node.sh --node-id node-2 \
#        [--bridge-nic eth1 --public-gateway 203.0.113.1 --public-prefix 27 --public-range 203.0.113.2-30] \
#        [--agent-host agent-2.example.com [--tunnel-name kvm-node-2]] \
#        [--mcp-host ops-2.example.com] [--yes]
#
# What it does (each step is skipped if already done, so it is safe to run again):
#   1. checks the OS and CPU virtualisation
#   2. installs KVM / libvirt / virt-install / guestfs-tools / xorriso and starts libvirt
#   3. downloads the AlmaLinux GenericCloud template (checksum verified)
#   4. optionally creates a VM bridge on a spare NIC (refuses a NIC that carries the host's IP or default route)
#   5. installs the KVM node agent and writes its node / public-network settings
#   6. optionally creates a Cloudflare Tunnel and routes the agent (and MCP) hostnames to it
#   7. optionally installs the Linux ops MCP
#   8. prints what to register in the control panel
set -euo pipefail

SRC=$(cd "$(dirname "$0")" && pwd)
NODE_ID="" BRIDGE_NIC="" BRIDGE="br-vm" GW="" PREFIX="" RANGE="" DNS="1.1.1.1,8.8.8.8"
AGENT_HOST="" TUNNEL="" MCP_HOST="" YES=0 IMAGE_URL="" TEMPLATE=""

usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do
  case $1 in
    --node-id) NODE_ID=$2; shift 2 ;;
    --bridge-nic) BRIDGE_NIC=$2; shift 2 ;;
    --bridge-name) BRIDGE=$2; shift 2 ;;
    --public-gateway) GW=$2; shift 2 ;;
    --public-prefix) PREFIX=$2; shift 2 ;;
    --public-range) RANGE=$2; shift 2 ;;
    --public-dns) DNS=$2; shift 2 ;;
    --agent-host) AGENT_HOST=$2; shift 2 ;;
    --tunnel-name) TUNNEL=$2; shift 2 ;;
    --mcp-host) MCP_HOST=$2; shift 2 ;;
    --image-url) IMAGE_URL=$2; shift 2 ;;
    --template-name) TEMPLATE=$2; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
confirm() { [[ $YES -eq 1 ]] && return 0; read -r -p "    $1 [y/N] " a; [[ $a =~ ^[Yy] ]]; }

[[ $EUID -eq 0 ]] || die "run as root (sudo bash setup-node.sh …)"
[[ -n $NODE_ID ]] || die "--node-id is required (e.g. --node-id node-2)"
[[ $NODE_ID =~ ^[a-z0-9-]{1,32}$ ]] || die "--node-id: lowercase letters, digits and - only"
if [[ -n $BRIDGE_NIC || -n $RANGE ]]; then
  [[ -n $BRIDGE_NIC && -n $GW && -n $PREFIX && -n $RANGE ]] || die "public network needs --bridge-nic, --public-gateway, --public-prefix and --public-range"
  [[ $RANGE =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]] || die "--public-range must look like 203.0.113.2-30"
  [[ $GW =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && $PREFIX =~ ^[0-9]{1,2}$ ]] || die "invalid --public-gateway / --public-prefix"
fi

# ------------------------------------------------------------------ 1. preflight
say "1/8 Checking the system"
. /etc/os-release
[[ $ID =~ ^(almalinux|rocky|rhel)$ ]] || die "supported: AlmaLinux / Rocky / RHEL (found $ID)"
MAJOR=${VERSION_ID%%.*}
[[ $MAJOR == 9 || $MAJOR == 10 ]] || die "supported: version 9 or 10 (found $VERSION_ID)"
ok "$PRETTY_NAME"
grep -qE '(vmx|svm)' /proc/cpuinfo || die "CPU virtualisation (VT-x/AMD-V) is not enabled: turn it on in the BIOS"
ok "CPU virtualisation available ($(nproc) threads, $(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1024 / 1024 )) GB RAM)"

# ------------------------------------------------------------------ 2. KVM
say "2/8 KVM and libvirt"
PKGS=(qemu-kvm libvirt virt-install guestfs-tools xorriso python3-libvirt git openssl curl)
MISSING=(); for p in "${PKGS[@]}"; do rpm -q "$p" &>/dev/null || MISSING+=("$p"); done
if [[ ${#MISSING[@]} -gt 0 ]]; then dnf install -y "${MISSING[@]}"; fi
ok "packages installed"
for d in qemu network nodedev nwfilter secret storage interface proxy; do
  for s in "" -ro -admin; do systemctl enable --now "virt${d}d${s}.socket" &>/dev/null || true; done
done
virsh -c qemu:///system net-info default &>/dev/null || die "libvirt network 'default' is missing"
virsh -c qemu:///system net-autostart default >/dev/null
virsh -c qemu:///system net-start default &>/dev/null || true
ok "libvirt running; NAT network 'default' active"
VAL=$(virt-host-validate qemu 2>&1 || true)
if grep -q FAIL <<<"$VAL"; then grep FAIL <<<"$VAL" | sed 's/^/    /'; warn "virt-host-validate reported failures (above)"; else ok "virt-host-validate: no failures"; fi

# ------------------------------------------------------------------ 3. template
say "3/8 OS template"
TPL_DIR=/var/lib/libvirt/images/templates
mkdir -p "$TPL_DIR"
TEMPLATE=${TEMPLATE:-almalinux-${MAJOR}-cloud}
IMAGE_URL=${IMAGE_URL:-https://repo.almalinux.org/almalinux/${MAJOR}/cloud/x86_64/images/AlmaLinux-${MAJOR}-GenericCloud-latest.x86_64.qcow2}
if [[ -f $TPL_DIR/$TEMPLATE.qcow2 ]]; then
  ok "$TEMPLATE.qcow2 already present"
else
  tmp=$(mktemp -d)
  curl -fL --retry 3 -o "$tmp/image.qcow2" "$IMAGE_URL"
  base=$(basename "$IMAGE_URL")
  if curl -fsSL -o "$tmp/CHECKSUM" "$(dirname "$IMAGE_URL")/CHECKSUM"; then
    want=$(grep -E "SHA256 \($base\)" "$tmp/CHECKSUM" | awk '{print $NF}' || true)
    have=$(sha256sum "$tmp/image.qcow2" | awk '{print $1}')
    if [[ -n $want ]]; then
      [[ $want == "$have" ]] || die "checksum mismatch for $base"
      ok "checksum verified"
    else
      warn "no checksum line for $base; skipped verification"
    fi
  else
    warn "no CHECKSUM file next to the image; skipped verification"
  fi
  qemu-img info "$tmp/image.qcow2" | grep -q 'file format: qcow2' || die "downloaded file is not qcow2"
  mv "$tmp/image.qcow2" "$TPL_DIR/$TEMPLATE.qcow2"; rm -rf "$tmp"
  ok "$TPL_DIR/$TEMPLATE.qcow2"
fi

# ------------------------------------------------------------------ 4. bridge
say "4/8 VM bridge for public IPs"
if [[ -z $BRIDGE_NIC ]]; then
  warn "skipped (no --bridge-nic): VMs can use the private NAT network only"
elif [[ -d /sys/class/net/$BRIDGE/bridge ]]; then
  ok "$BRIDGE already exists"
else
  [[ -e /sys/class/net/$BRIDGE_NIC ]] || die "NIC $BRIDGE_NIC not found (see: ip -br link)"
  if ip -4 -o addr show dev "$BRIDGE_NIC" | grep -q inet; then
    die "$BRIDGE_NIC has an IPv4 address: it carries host traffic. Use a spare NIC, or bridge it manually from the server console."
  fi
  if ip route show default | grep -qw "dev $BRIDGE_NIC"; then
    die "$BRIDGE_NIC carries the default route. Use a spare NIC."
  fi
  echo "    Will create bridge $BRIDGE on $BRIDGE_NIC (no host IP). The host's own network is not changed."
  confirm "Continue?" || die "cancelled"
  nmcli connection add type bridge ifname "$BRIDGE" con-name "$BRIDGE" ipv4.method disabled ipv6.method disabled bridge.stp no >/dev/null
  nmcli connection add type ethernet ifname "$BRIDGE_NIC" con-name "$BRIDGE-$BRIDGE_NIC" controller "$BRIDGE" port-type bridge >/dev/null
  nmcli -t -f NAME connection show | grep -qx "$BRIDGE_NIC" && nmcli connection modify "$BRIDGE_NIC" connection.autoconnect no || true
  nmcli connection up "$BRIDGE" >/dev/null && nmcli connection up "$BRIDGE-$BRIDGE_NIC" >/dev/null
  ok "$BRIDGE up on $BRIDGE_NIC"
fi

# ------------------------------------------------------------------ 5. node agent
say "5/8 KVM node agent"
bash "$SRC/node-agent/install.sh" >/tmp/node-agent-install.log 2>&1 || { cat /tmp/node-agent-install.log; die "agent install failed"; }
CFG=/etc/kvm-node-agent/config.env
set_key() { if grep -q "^$1=" "$CFG"; then sed -i "s#^$1=.*#$1=$2#" "$CFG"; else echo "$1=$2" >> "$CFG"; fi; }
expand_range() {   # 203.0.113.2-30  ->  203.0.113.2,203.0.113.3,…
  local net=${1%.*} last=${1##*.} a b
  a=${last%-*}; b=${last#*-}
  [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ && $a -le $b && $b -le 255 ]] || die "--public-range must look like 203.0.113.2-30"
  seq -s, -f "$net.%g" "$a" "$b"
}
set_key NODE_ID "$NODE_ID"
set_key TEMPLATE_DIR "$TPL_DIR"
if [[ -n $BRIDGE_NIC ]]; then
  POOL=$(expand_range "$RANGE")
  set_key PUBLIC_BRIDGE "$BRIDGE"; set_key PUBLIC_GATEWAY "$GW"; set_key PUBLIC_PREFIX "$PREFIX"
  set_key PUBLIC_DNS "$DNS"; set_key PUBLIC_POOL "$POOL"
fi
systemctl restart kvm-node-agent.service; sleep 2
T=$(grep ^AGENT_TOKEN= "$CFG" | cut -d= -f2)
HEALTH=$(curl -s -m 5 -H "Authorization: Bearer $T" http://127.0.0.1:8770/health || true)
[[ $HEALTH == *'"node"'* ]] || die "agent health check failed: $HEALTH"
ok "agent running on 127.0.0.1:8770 as $NODE_ID"

# ------------------------------------------------------------------ 6. tunnel
say "6/8 Cloudflare Tunnel"
add_ingress() {    # hostname service : insert before the catch-all rule if missing
  local host=$1 svc=$2 f=/etc/cloudflared/config.yml
  grep -q "hostname: $host\$" "$f" && { ok "ingress for $host already present"; return; }
  awk -v h="$host" -v s="$svc" '/^[[:space:]]*- service: http_status:404/ && !done {print "  - hostname: " h; print "    service: " s; done=1} {print}' "$f" > "$f.new"
  mv "$f.new" "$f"; ok "ingress $host -> $svc"
}
if [[ -z $AGENT_HOST ]]; then
  warn "skipped (no --agent-host)"
else
  if ! command -v cloudflared >/dev/null; then
    curl -fsSL https://pkg.cloudflare.com/cloudflared-ascii.repo -o /etc/yum.repos.d/cloudflared.repo
    dnf install -y cloudflared
  fi
  if [[ ! -f /etc/cloudflared/config.yml ]]; then
    TUNNEL=${TUNNEL:-kvm-$NODE_ID}
    [[ -f /root/.cloudflared/cert.pem ]] || { echo "    Open the link below in a browser and pick your domain:"; cloudflared tunnel login; }
    cloudflared tunnel info "$TUNNEL" &>/dev/null || cloudflared tunnel create "$TUNNEL"
    TID=$(cloudflared tunnel list -o json | python3 -c "import json,sys;print([t['id'] for t in json.load(sys.stdin) if t['name']=='$TUNNEL'][0])")
    mkdir -p /etc/cloudflared
    cp "/root/.cloudflared/$TID.json" "/etc/cloudflared/$TID.json"
    cat > /etc/cloudflared/config.yml <<EOF
tunnel: $TID
credentials-file: /etc/cloudflared/$TID.json
ingress:
  - service: http_status:404
EOF
    ok "tunnel $TUNNEL ($TID) created"
  fi
  TID=$(awk '/^tunnel:/{print $2}' /etc/cloudflared/config.yml)
  add_ingress "$AGENT_HOST" "http://127.0.0.1:8770"
  cloudflared tunnel route dns "$TID" "$AGENT_HOST" 2>&1 | tail -1 || true
  if [[ -n $MCP_HOST ]]; then
    add_ingress "$MCP_HOST" "http://127.0.0.1:8765"
    cloudflared tunnel route dns "$TID" "$MCP_HOST" 2>&1 | tail -1 || true
  fi
  systemctl is-enabled cloudflared &>/dev/null || cloudflared service install >/dev/null 2>&1 || true
  systemctl enable --now cloudflared >/dev/null 2>&1 || true
  systemctl restart cloudflared
  ok "cloudflared running"
fi

# ------------------------------------------------------------------ 7. MCP
say "7/8 Linux ops MCP (optional)"
if [[ -z $MCP_HOST ]]; then
  warn "skipped (no --mcp-host)"
else
  bash "$SRC/install.sh" "$MCP_HOST" >/tmp/linux-ops-install.log 2>&1 || { cat /tmp/linux-ops-install.log; die "MCP install failed"; }
  ok "MCP installed. Show the connector token with: grep ^OPS_MCP_TOKEN= /etc/claude-ops/config.env"
fi

# ------------------------------------------------------------------ 8. summary
say "8/8 Done. Register this node in the control panel"
cat <<EOF
    Node ID        : $NODE_ID
    Agent URL      : ${AGENT_HOST:+https://$AGENT_HOST}${AGENT_HOST:-"(none: no --agent-host given)"}
    Agent token    : grep ^AGENT_TOKEN= $CFG      (store it as the control plane's agent secret; don't paste it into chats)
    Template       : $TEMPLATE
    Public network : ${BRIDGE_NIC:+$BRIDGE on $BRIDGE_NIC, gw $GW/$PREFIX, pool $RANGE}${BRIDGE_NIC:-none (NAT only)}

    Still to do in your access layer: protect ${AGENT_HOST:-the agent hostname} so only the control plane can reach it
    (e.g. a Cloudflare Access app with a Service Auth policy for your control plane's service token).
EOF
