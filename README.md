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
  `sudo claude-ops-admin 2h` (max 8 h), `claude-ops-admin off`, `claude-ops-admin status`. On older installs where
  sudo says "command not found", use the full path `sudo /usr/local/sbin/claude-ops-admin 2h` (re-running the
  installer adds a link so the short form works).
- Runs as an unprivileged `claude-ops` user. Root actions go through a sudoers file listing exact commands.
- Every call is logged to `/var/log/claude-ops/audit.jsonl`, and sudo to `/var/log/claude-ops/sudo.log`.
- The endpoint path contains a random 64-hex token (`/<token>/mcp`). Treat the full URL as a secret.

### Asterisk hosts (optional)

If Asterisk is installed, the same connector can look after it:

| What | How | Mode |
|---|---|---|
| Status | `asterisk -rx "pjsip show contacts"`, `pjsip show endpoint(s)/aor(s)/registrations/transports`, `core show channels`, `dialplan show [ctx]`, `module show like x` | read |
| Configs | `claude-ops-asterisk show-conf pjsip.conf`: passwords/secrets come back as `__KEEP_SECRET__` | read |
| Logs | `claude-ops-asterisk log 300` | read |
| Edit a config | `write_file` the edited file, then `claude-ops-asterisk install-conf <file> pjsip.conf`. The live file is backed up first; any `password = __KEEP_SECRET__` line keeps the existing value, so secrets never pass through the AI | admin |
| Undo | `claude-ops-asterisk restore-conf pjsip.conf` | admin |
| Reload | `asterisk -rx "pjsip reload"`, `dialplan reload`, `core reload`, `module reload <mod>`, `pjsip qualify <aor>` | admin |
| Test call | `asterisk -rx "channel originate PJSIP/<number>@<endpoint> application Playback hello-world"` or `… extension <exten>@<context>` | admin |

Shell-style CLI commands (`! …`), `core restart/stop`, `pjsip show auth(s)` and other originate forms are refused.
Backups are kept in `/var/lib/claude-ops/asterisk-backups/`.

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
| `POST /vms` | Create `{id, hostname, template, vcpu, ram_mb, disk_gb, ssh_keys[], public_ip?, async?}`. Returns the generated login password once. With `"async": true` it returns a job at once and builds in the background |
| `GET /jobs/{id}[?consume=1]` | Background job status (`running`/`done`/`failed`) and result. `consume=1` hands out a new VM's password once, then removes it |
| `GET /backups`, `GET /backups/{bk}` | Backups with status, progress, size, SHA-256; free space in `BACKUP_DIR` |
| `POST /vms/{id}/backups` | Start a backup `{note?}`. Running VMs: live copy (libvirt backup-begin, file systems frozen through the guest agent when available). Stopped VMs: `qemu-img convert` |
| `GET /backups/{bk}/download` | The qcow2 image (supports `Range`, so downloads can resume) |
| `POST /backups/{bk}/restore` | Job: shut the VM down, replace its disk with the backup, start it. `{vm_id}` restores onto another VM |
| `POST /backups/{bk}/restore-new` | Job: create a new VM from the backup (same body as `POST /vms`, new hostname and login) |
| `POST /backups/upload` | Start an image upload `{filename, size, note?}` |
| `PUT /backups/{bk}/chunk?offset=N` | Append up to 100 MB; a 409 reply says how many bytes the node already has, so uploads can resume |
| `POST /backups/{bk}/finish` | Job: check the image (formats qcow2, raw, vmdk, vhdx, vhd, vdi; images with backing files or external data are refused), convert to qcow2 |
| `DELETE /backups/{bk}` | Delete a backup |
| `POST /vms/{id}/start\|shutdown\|reboot\|poweroff` | Power actions |
| `GET /vms/{id}/ssh-keys` | SSH public keys of the VM's login user (read through the QEMU guest agent; VM must be running) |
| `POST` / `DELETE /vms/{id}/ssh-keys` | Add / remove keys `{keys: ["ssh-ed25519 AAAA… comment"]}`. Only plain OpenSSH public key lines are accepted (no options, no private keys). Works on running VMs without a reboot |
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

Backups are stored in `BACKUP_DIR` (the installer sets `/home/vm-backups`; change it in `config.env` to put backups on your largest disk), one folder per backup with `disk.qcow2`, `domain.xml` and `meta.json`. The installer creates it with the SELinux `virt_image_t` label. Jobs live in memory: if the agent restarts during a job, that job is reported as failed.

Example bridge on a spare NIC (doesn't touch the host's own connection):

```bash
nmcli connection add type bridge ifname br-vm con-name br-vm ipv4.method disabled ipv6.method disabled bridge.stp no
nmcli connection add type ethernet ifname eth1 con-name br-vm-eth1 controller br-vm port-type bridge
nmcli connection up br-vm && nmcli connection up br-vm-eth1
```

## License

Use at your own risk. Review the allowlists before running on your own hosts.
