# Linux MCP + KVM node agent

Two small, independent services for an AlmaLinux 9/10 KVM host:

| Part | What it does |
|---|---|
| **Linux ops MCP** (repo root) | An [MCP](https://modelcontextprotocol.io) server so an AI assistant (e.g. Claude) can run *checked* commands on the host: read-only checks, a fixed security audit, and time-limited admin mode for setup work. |
| **KVM node agent** (`node-agent/`) | A small HTTP + WebSocket API on `127.0.0.1` that creates and controls VMs with libvirt, for a separate control panel to call. |

Both listen on localhost only. Expose them through an outbound tunnel (for example Cloudflare Tunnel), protected by an
access layer such as Cloudflare Access, and never through an open port.

## Quick start: set up a new KVM node with one command

```bash
git clone https://github.com/<you>/Linux-MCP.git /opt/Linux-MCP
sudo bash /opt/Linux-MCP/setup-node.sh --node-id node-2 \
     --bridge-nic eth1 --public-gateway 203.0.113.1 --public-prefix 27 --public-range 203.0.113.2-30 \
     --agent-host agent-2.example.com \
     --mcp-host ops-2.example.com          # optional
```

1. Checks the OS (AlmaLinux / Rocky / RHEL 9 or 10) and CPU virtualisation.
2. Installs KVM, libvirt, virt-install, guestfs-tools and xorriso, and starts libvirt and its NAT network.
3. Downloads the AlmaLinux GenericCloud image as a template, with its checksum verified.
4. Creates the VM bridge on a **spare** NIC (optional). It refuses a NIC that has the host's IP or default route.
5. Installs the KVM node agent and writes the node ID and public network settings.
6. Creates a Cloudflare Tunnel, or reuses the existing one, and routes the agent (and MCP) hostnames to it. The first
   run asks you to open a Cloudflare login link.
7. Installs the Linux ops MCP (optional).
8. Prints what to register in your control panel.

Every step is skipped when it's already done, so the script is safe to run again. Leave out the public-network options
for a NAT-only node, and `--agent-host` if you manage the tunnel yourself. `--yes` skips the bridge confirmation.

---

## Linux ops MCP

### Tools

| Tool | Purpose |
|---|---|
| `host_status` | Uptime, load, memory, disks, libvirt/VM summary |
| `run_check(command)` | One read-only command from an allowlist (no shell, no pipes) |
| `run_admin(command, reason)` | One setup command from an allowlist, **only while admin mode is on**; the reason is logged |
| `security_audit(section)` | Fixed root audit script: logins, users, ssh, persistence, processes, network, integrity, files |
| `write_file` / `read_file` | Files in the work directory only (configs, XML) |
| `recent_audit` | Recent entries of the MCP's own audit log |

### Safety model

- Commands are parsed with `shlex` and never run through a shell. `| ; & < > $ \`` and newlines are refused.
- **Allowlists** for read-only and admin commands. Network-changing commands (`nmcli` changes, `ip … set`, firewall
  changes …) are always refused: do those from the server's out-of-band console.
- Destructive `virsh` commands only work on VMs named `vm-test*`.
- **Admin mode is off by default.** The owner turns it on for a limited time on the host:
  `claude-ops-admin 2h` (max 8 h), `claude-ops-admin off`, `claude-ops-admin status`.
- Runs as an unprivileged `claude-ops` user. Root actions go through a sudoers file listing exact commands.
- Every call is logged to `/var/log/claude-ops/audit.jsonl`, and sudo to `/var/log/claude-ops/sudo.log`.
- The endpoint path contains a random 64-hex token (`/<token>/mcp`). Treat the full URL as a secret.

### Install

```bash
git clone https://github.com/<you>/Linux-MCP.git /opt/Linux-MCP
sudo bash /opt/Linux-MCP/install.sh ops.example.com     # the public hostname you'll route to it
```

The installer creates the user, venv, config (with a random token), sudoers, audit script and systemd unit, then prints
a masked connector URL. Show the full token on the host with `sudo grep ^OPS_MCP_TOKEN= /etc/claude-ops/config.env`.

Route the hostname to `http://127.0.0.1:8765` in your tunnel, then add `https://<hostname>/<token>/mcp` as a custom
connector in your MCP client.

---

## KVM node agent (`node-agent/`)

### Install / update

```bash
sudo bash /opt/Linux-MCP/node-agent/install.sh
```

- Installs `python3-libvirt` and `xorriso`, a venv, `/etc/kvm-node-agent/config.env` (random `AGENT_TOKEN`; the
  existing token is kept on updates) and the `kvm-node-agent` systemd service on `127.0.0.1:8770`.
- Every request needs `Authorization: Bearer <AGENT_TOKEN>`.
- `AGENT_FAKE=1` gives a libvirt-free test mode with in-memory VMs.

### API

| Endpoint | Purpose |
|---|---|
| `GET /health` | Node ID, libvirt/QEMU versions, public network settings |
| `GET /capacity` | CPUs, RAM, VM disk space, vCPU/RAM allocated, VM counts |
| `GET /templates` | OS images in `TEMPLATE_DIR` (`*.qcow2`) |
| `GET /vms`, `GET /vms/{id}` | VM list; detail with disks, IPs and VNC port |
| `POST /vms` | Create `{id, hostname, template, vcpu, ram_mb, disk_gb, ssh_keys[], public_ip?}`. Returns the generated login password once |
| `POST /vms/{id}/start\|shutdown\|reboot\|poweroff` | Power actions |
| `DELETE /vms/{id}` | Destroy, undefine and delete its disks and seed ISO (only `vm-…` names) |
| `WS /vms/{id}/console` | VNC bridge for noVNC |
| `WS /events` | Live stream of capacity and VM states every 3 s |

### How VMs are built

- A full qcow2 copy of the template is made, then resized (no backing chain).
- The agent builds its **own NoCloud seed ISO** per VM (label `cidata`, via `xorriso`) with `user-data`, `meta-data`
  and an optional `network-config`, and attaches it as a CD-ROM. It's removed when the VM is deleted.
- The VM gets UEFI, virtio, a QEMU guest agent channel, VNC on localhost, hot-plug headroom (max vCPUs,
  `maxMemory`) and autostart.
- **Private VMs** get one NIC on the libvirt NAT network (DHCP).
- **Public VMs** (`public_ip` set) get:
  - `eth0` on `PUBLIC_BRIDGE` with a static IP from `PUBLIC_POOL`, gateway `PUBLIC_GATEWAY`;
  - `eth1` on the NAT network with a static internal IP and no gateway, reserved in libvirt DHCP.

### Public network settings (`/etc/kvm-node-agent/config.env`)

| Key | Example | Meaning |
|---|---|---|
| `PUBLIC_BRIDGE` | `br-vm` or `direct:eth1` | Linux bridge on a NIC without a host IP, or macvtap on a NIC. Empty = disabled |
| `PUBLIC_GATEWAY` | `203.0.113.1` | Gateway of the VM subnet |
| `PUBLIC_PREFIX` | `27` | Prefix length |
| `PUBLIC_DNS` | `1.1.1.1,8.8.8.8` | Resolvers written into the VM |
| `PUBLIC_POOL` | `203.0.113.2,203.0.113.3,…` | The only addresses the agent will assign |

Example bridge on a spare NIC (doesn't touch the host's own connection):

```bash
nmcli connection add type bridge ifname br-vm con-name br-vm ipv4.method disabled ipv6.method disabled bridge.stp no
nmcli connection add type ethernet ifname eth1 con-name br-vm-eth1 controller br-vm port-type bridge
nmcli connection up br-vm && nmcli connection up br-vm-eth1
```

## License

Use at your own risk. Review the allowlists before running on your own hosts.
