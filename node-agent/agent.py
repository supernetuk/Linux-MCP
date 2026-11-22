"""
KVM node agent — runs on each KVM host and does the actual VM work for the portal Worker.

Listens on 127.0.0.1 only; reached through Cloudflare Tunnel (hostname protected by a Cloudflare
Access service token) and every request must also carry `Authorization: Bearer <AGENT_TOKEN>`.

Endpoints (JSON):
  GET    /health                       versions, node id
  GET    /capacity                     host CPU / RAM / disk / VM count
  GET    /templates                    OS templates available
  GET    /vms                          all VMs on this host
  GET    /vms/{id}                     one VM in detail
  POST   /vms                          create {id, hostname, template, vcpu, ram_mb, disk_gb, ssh_keys[]}
  POST   /vms/{id}/start|shutdown|reboot|poweroff
  DELETE /vms/{id}                     destroy + undefine + delete its disks
  WS     /vms/{id}/console             VNC (RFB) over WebSocket for noVNC
  WS     /events                       live stream: capacity + VM states every 3 s
  POST   /vms  {"async": true, …}       create in the background -> job
  GET    /jobs/{id}[?consume=1]         background job status/result (password handed out once)
  GET    /backups                       backups on this node + backup storage space
  POST   /vms/{id}/backups              start a backup (live if running) -> backup meta
  GET    /backups/{bid}[/download]      metadata, or the qcow2 image (Range supported)
  POST   /backups/{bid}/restore         overwrite the original VM's disk (VM is stopped, then started)
  POST   /backups/{bid}/restore-new     new VM from the backup (same spec as POST /vms) -> job
  DELETE /backups/{bid}

Set AGENT_FAKE=1 to run without libvirt (in-memory fake VMs) for local testing.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import shutil
import hashlib
import subprocess
import threading
import time
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

TOKEN = os.environ.get("AGENT_TOKEN", "")
NODE_ID = os.environ.get("NODE_ID", "node-1")
PORT = int(os.environ.get("AGENT_PORT", "8770"))
IMAGE_DIR = Path(os.environ.get("IMAGE_DIR", "/var/lib/libvirt/images"))
TEMPLATE_DIR = Path(os.environ.get("TEMPLATE_DIR", "/var/lib/libvirt/images/templates"))
SEED_DIR = Path(os.environ.get("SEED_DIR", "/var/lib/kvm-node-agent/cloud-init"))
NETWORK = os.environ.get("VM_NETWORK", "network=default")      # later: routed public network
FAKE = os.environ.get("AGENT_FAKE", "0") == "1"
DEFAULT_USER = os.environ.get("VM_DEFAULT_USER", "admin")
# Public IPv4 for VMs: a host bridge on a spare NIC (no host IP on it) + static addresses from a fixed pool.
# PUBLIC_BRIDGE: "br-vm" = a Linux bridge, or "direct:eth0" = macvtap on that NIC (no host network change;
# VMs reach the router directly, but host <-> VM traffic over the network doesn't work). Empty = disabled.
PUBLIC_BRIDGE = os.environ.get("PUBLIC_BRIDGE", "")
PUBLIC_GATEWAY = os.environ.get("PUBLIC_GATEWAY", "")            # e.g. 203.0.113.1
PUBLIC_PREFIX = int(os.environ.get("PUBLIC_PREFIX", "29"))
PUBLIC_DNS = [x.strip() for x in os.environ.get("PUBLIC_DNS", "1.1.1.1,8.8.8.8").split(",") if x.strip()]
INTERNAL_NET = os.environ.get("INTERNAL_NET", "default")          # libvirt network for internal IPs (GCP-style)
INTERNAL_RANGE = (200, 254)                                        # static internal IPs for public VMs: .200-.254
PUBLIC_POOL = {x.strip() for x in os.environ.get("PUBLIC_POOL", "").split(",") if x.strip()}   # allowed VM IPs

VM_ID = re.compile(r"^vm-[a-z0-9][a-z0-9-]{2,40}$")
HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
SSH_KEY = re.compile(r"^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]{40,4096}={0,3}( [^\x00-\x1f\x7f]{0,200})?$")
LIMITS = {"vcpu": (1, 16), "ram_mb": (512, 65536), "disk_gb": (10, 2000)}
STATES = {0: "nostate", 1: "running", 2: "blocked", 3: "paused", 4: "shutting-down", 5: "stopped",
          6: "crashed", 7: "suspended"}


class AgentError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


def run(argv: list[str], timeout: int = 600, stdin: str | None = None) -> str:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=stdin)
    if p.returncode != 0:
        raise AgentError(500, f"{argv[0]} failed: {(p.stderr or p.stdout).strip()[-800:]}")
    return p.stdout


# ------------------------------------------------------------------ backends

def _public_link_up() -> bool:
    if not PUBLIC_BRIDGE:
        return False
    if PUBLIC_BRIDGE.startswith("direct:"):
        nic = PUBLIC_BRIDGE.split(":", 1)[1]
        try:
            return Path(f"/sys/class/net/{nic}/operstate").read_text().strip() == "up"
        except OSError:
            return False
    return Path(f"/sys/class/net/{PUBLIC_BRIDGE}/bridge").exists()


GA_SSH_SCRIPT = '#!/bin/sh\n# Let the host\'s node agent add/remove SSH keys through the QEMU guest agent.\n# Some RHEL/AlmaLinux builds allow-list guest agent commands without the SSH key ones,\n# and SELinux needs virt_qemu_ga_read_ssh / virt_qemu_ga_manage_ssh for ~/.ssh/authorized_keys.\nfor f in /etc/sysconfig/qemu-ga /etc/sysconfig/qemu-guest-agent; do\n  if [ -f "$f" ] && grep -q \'^FILTER_RPC_ARGS="--allow-rpcs=\' "$f" && ! grep -q \'guest-ssh-add-authorized-keys\' "$f"; then\n    sed -i \'s/^FILTER_RPC_ARGS="--allow-rpcs=/&guest-ssh-get-authorized-keys,guest-ssh-add-authorized-keys,guest-ssh-remove-authorized-keys,/\' "$f"\n  fi\ndone\nif command -v setsebool >/dev/null 2>&1; then\n  setsebool -P virt_qemu_ga_read_ssh on 2>/dev/null || true\n  setsebool -P virt_qemu_ga_manage_ssh on 2>/dev/null || true\nfi\nsystemctl restart qemu-guest-agent 2>/dev/null || true\n'
GA_SSH_WRITE_FILES = ("write_files:\n  - path: /usr/local/sbin/ga-ssh-keys.sh\n"
                      "    permissions: '0755'\n    content: |\n"
                      + "".join("      " + ln + "\n" for ln in GA_SSH_SCRIPT.rstrip("\n").split("\n")))

SSH_KEY_RE = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
    r" [A-Za-z0-9+/]{40,4096}={0,3}( [^\x00-\x1f]{0,200})?$")


def clean_removal_keys(keys) -> list[str]:
    """Lines to remove: any single line already in authorized_keys (removing can't grant access)."""
    if not isinstance(keys, list) or not 1 <= len(keys) <= 20:
        raise AgentError(400, "keys must be a list of 1-20 key lines")
    out = []
    for k in keys:
        k = str(k).strip()
        if not k or len(k) > 16384 or any(c in k for c in "\n\r\x00"):
            raise AgentError(400, "each key must be one line")
        out.append(k)
    return out


def clean_ssh_keys(keys) -> list[str]:
    """Validate OpenSSH public key lines; refuse private keys and anything with options or newlines."""
    if not isinstance(keys, list) or not 1 <= len(keys) <= 20:
        raise AgentError(400, "keys must be a list of 1-20 public keys")
    out = []
    for k in keys:
        k = str(k).strip()
        if "PRIVATE KEY" in k:
            raise AgentError(400, "that is a PRIVATE key: never share it. Paste the public key (ssh-ed25519 / ecdsa-... / ssh-rsa ...)")
        if not SSH_KEY_RE.match(k):
            raise AgentError(400, "not a valid OpenSSH public key line: " + k[:40])
        out.append(k)
    return out


class LibvirtBackend:
    def __init__(self):
        import libvirt  # system package python3-libvirt (venv uses --system-site-packages)
        self.libvirt = libvirt
        self.conn = libvirt.open("qemu:///system")

    def _dom(self, vm_id: str):
        try:
            return self.conn.lookupByName(vm_id)
        except self.libvirt.libvirtError:
            raise AgentError(404, f"VM {vm_id} not found")

    def _ensure_conn(self):
        try:
            self.conn.getLibVersion()
        except Exception:
            self.conn = self.libvirt.open("qemu:///system")

    def health(self) -> dict:
        self._ensure_conn()
        v = self.conn.getLibVersion()
        h = self.conn.getVersion()
        fmt = lambda n: f"{n // 1000000}.{n // 1000 % 1000}.{n % 1000}"
        return {"node": NODE_ID, "libvirt": fmt(v), "qemu": fmt(h), "fake": False,
                "public_network": {"bridge": PUBLIC_BRIDGE or None, "gateway": PUBLIC_GATEWAY or None,
                                   "prefix": PUBLIC_PREFIX, "pool": sorted(PUBLIC_POOL),
                                   "bridge_up": _public_link_up()}}

    def capacity(self) -> dict:
        self._ensure_conn()
        model, mem_mb, cpus, *_ = self.conn.getInfo()
        free = self.conn.getFreeMemory() // (1024 * 1024)
        du = shutil.disk_usage(IMAGE_DIR)
        doms = self.conn.listAllDomains()
        alloc_cpu = sum(d.info()[3] for d in doms if d.isActive())
        alloc_mem = sum(d.info()[2] for d in doms if d.isActive()) // 1024
        return {"node": NODE_ID, "cpus": cpus, "ram_mb": mem_mb, "ram_free_mb": free,
                "disk_gb": round(du.total / 2**30), "disk_free_gb": round(du.free / 2**30),
                "vms_total": len(doms), "vms_running": sum(1 for d in doms if d.isActive()),
                "vcpu_allocated": alloc_cpu, "ram_allocated_mb": alloc_mem}

    def templates(self) -> list[dict]:
        out = []
        for f in sorted(TEMPLATE_DIR.glob("*.qcow2")):
            out.append({"id": f.stem, "file": f.name, "size_gb": round(f.stat().st_size / 2**30, 2)})
        return out

    # ---- internal IP (second NIC on the NAT network, static, no gateway, reserved in libvirt DHCP)
    def _internal_net(self):
        import xml.etree.ElementTree as ET
        net = self.conn.networkLookupByName(INTERNAL_NET)
        x = ET.fromstring(net.XMLDesc())
        ip_el = x.find("ip")
        base = ip_el.get("address").rsplit(".", 1)[0]
        hosts = {h.get("ip"): h.get("mac") for h in ip_el.findall("./dhcp/host")}
        return net, base, hosts

    def _reserve_internal_ip(self, mac: str) -> str:
        net, base, hosts = self._internal_net()
        used = set(hosts)
        try:
            used |= {l["ipaddr"] for l in (net.DHCPLeases() or [])}
        except self.libvirt.libvirtError:
            pass
        for n in range(INTERNAL_RANGE[1], INTERNAL_RANGE[0] - 1, -1):
            ip = f"{base}.{n}"
            if ip not in used:
                lv = self.libvirt
                net.update(lv.VIR_NETWORK_UPDATE_COMMAND_ADD_LAST, lv.VIR_NETWORK_SECTION_IP_DHCP_HOST, -1,
                           f"<host mac='{mac}' ip='{ip}'/>",
                           lv.VIR_NETWORK_UPDATE_AFFECT_LIVE | lv.VIR_NETWORK_UPDATE_AFFECT_CONFIG)
                return ip
        raise AgentError(507, "no free internal IP")

    def _release_internal_ips(self, macs: list[str]) -> None:
        try:
            net, base, hosts = self._internal_net()
        except Exception:
            return
        lv = self.libvirt
        for ip, mac in hosts.items():
            if mac and mac.lower() in {m.lower() for m in macs}:
                try:
                    net.update(lv.VIR_NETWORK_UPDATE_COMMAND_DELETE, lv.VIR_NETWORK_SECTION_IP_DHCP_HOST, -1,
                               f"<host mac='{mac}' ip='{ip}'/>",
                               lv.VIR_NETWORK_UPDATE_AFFECT_LIVE | lv.VIR_NETWORK_UPDATE_AFFECT_CONFIG)
                except lv.libvirtError:
                    pass

    @staticmethod
    def _seed_iso(vm_id: str) -> Path:
        return IMAGE_DIR / "seed" / f"{vm_id}-seed.iso"

    def _macs(self, d) -> list[str]:
        import xml.etree.ElementTree as ET
        return [m.get("address") for m in ET.fromstring(d.XMLDesc()).findall("./devices/interface/mac")]

    def _summary(self, d) -> dict:
        state, maxmem, mem, vcpus, cputime = d.info()
        return {"id": d.name(), "uuid": d.UUIDString(), "state": STATES.get(state, str(state)),
                "vcpu": vcpus, "ram_mb": mem // 1024, "managed": bool(VM_ID.match(d.name()))}

    def list(self) -> list[dict]:
        self._ensure_conn()
        return [self._summary(d) for d in self.conn.listAllDomains()]

    def get(self, vm_id: str) -> dict:
        self._ensure_conn()
        d = self._dom(vm_id)
        s = self._summary(d)
        import xml.etree.ElementTree as ET
        x = ET.fromstring(d.XMLDesc())
        disks = []
        for disk in x.findall("./devices/disk[@device='disk']"):
            src = disk.find("source")
            tgt = disk.find("target")
            if src is not None and tgt is not None:
                try:
                    cap, alloc, phys = d.blockInfo(tgt.get("dev"))
                    disks.append({"dev": tgt.get("dev"), "file": src.get("file"),
                                  "size_gb": round(cap / 2**30, 1), "used_gb": round(alloc / 2**30, 2)})
                except self.libvirt.libvirtError:
                    disks.append({"dev": tgt.get("dev"), "file": src.get("file")})
        vcpu_el = x.find("vcpu")
        g = x.find("./devices/graphics[@type='vnc']")
        ips = []
        if d.isActive():
            for src in (self.libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT,
                        self.libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE):
                try:
                    for name, iface in (d.interfaceAddresses(src) or {}).items():
                        if name == "lo":
                            continue
                        for a in iface.get("addrs") or []:
                            if not a["addr"].startswith("fe80"):
                                ips.append(a["addr"])
                    if ips:
                        break
                except self.libvirt.libvirtError:
                    continue
        s.update({
            "vcpu_max": int(vcpu_el.text) if vcpu_el is not None else s["vcpu"],
            "disks": disks, "ips": sorted(set(ips)),
            "vnc_port": int(g.get("port")) if g is not None and g.get("port", "-1").isdigit() else None,
            "autostart": bool(d.autostart()), "cpu_time_s": round(d.info()[4] / 1e9, 1),
        })
        return s

    def create(self, spec: dict, source: Path | None = None) -> dict:
        """Create a VM from a template, or from an existing disk image (restore-as-new / relocation)."""
        self._ensure_conn()
        vm_id = spec["id"]
        try:
            self.conn.lookupByName(vm_id)
            raise AgentError(409, f"{vm_id} already exists")
        except self.libvirt.libvirtError:
            pass
        if source is not None:
            tpl = source
            vsize_gb = -(-json.loads(run(["qemu-img", "info", "--output=json", str(source)]))["virtual-size"] // 2**30)
            spec["disk_gb"] = max(spec["disk_gb"], vsize_gb)       # never shrink a restored disk
        else:
            tpl = TEMPLATE_DIR / f"{spec['template']}.qcow2"
            if not tpl.is_file():
                raise AgentError(400, f"template {spec['template']} not found")
        free_mb = self.conn.getFreeMemory() // (1024 * 1024)
        if spec["ram_mb"] > free_mb - 2048:
            raise AgentError(507, f"not enough free RAM on {NODE_ID} ({free_mb} MB free)")
        if shutil.disk_usage(IMAGE_DIR).free / 2**30 < spec["disk_gb"] * 0.2 + 5:
            raise AgentError(507, f"not enough disk space on {NODE_ID}")

        disk = IMAGE_DIR / f"{vm_id}.qcow2"
        seed = SEED_DIR / vm_id
        seed_iso = self._seed_iso(vm_id)
        password = secrets.token_urlsafe(12)
        internal_ip = None
        mac2 = None
        try:
            # Full copy (no backing chain) so backups/restores never depend on the template file
            run(["qemu-img", "convert", "-O", "qcow2", str(tpl), str(disk)], timeout=7200)
            run(["qemu-img", "resize", str(disk), f"{spec['disk_gb']}G"])
            seed.mkdir(parents=True, exist_ok=True)
            net_args = ["--network", f"{NETWORK},model=virtio"]
            # meta-data: unique instance-id makes cloud-init treat this as a new instance
            (seed / "meta-data").write_text(
                f"instance-id: {vm_id}\nlocal-hostname: \"{spec['hostname'].split('.')[0]}\"\n")
            if spec.get("public_ip"):
                mac = "52:54:00:%02x:%02x:%02x" % tuple(secrets.token_bytes(3))
                mac2 = "52:54:00:%02x:%02x:%02x" % tuple(secrets.token_bytes(3))
                internal_ip = self._reserve_internal_ip(mac2)
                dns = ", ".join(PUBLIC_DNS)
                (seed / "network-config").write_text(
                    "version: 2\n"
                    "ethernets:\n"
                    "  primary:\n"
                    f"    match: {{macaddress: '{mac}'}}\n"
                    "    set-name: eth0\n"
                    f"    addresses: [{spec['public_ip']}/{PUBLIC_PREFIX}]\n"
                    f"    routes: [{{to: 0.0.0.0/0, via: {PUBLIC_GATEWAY}}}]\n"
                    f"    nameservers: {{addresses: [{dns}]}}\n"
                    "  internal:\n"                       # GCP-style internal IP: no gateway, no DNS
                    f"    match: {{macaddress: '{mac2}'}}\n"
                    "    set-name: eth1\n"
                    f"    addresses: [{internal_ip}/24]\n")
                if PUBLIC_BRIDGE.startswith("direct:"):
                    nic = PUBLIC_BRIDGE.split(":", 1)[1]
                    net_args = ["--network", f"type=direct,source={nic},source.mode=bridge,model=virtio,mac={mac}"]
                else:
                    net_args = ["--network", f"bridge={PUBLIC_BRIDGE},model=virtio,mac={mac}"]
                net_args += ["--network", f"network={INTERNAL_NET},model=virtio,mac={mac2}"]
            pw_hash = run(["openssl", "passwd", "-6", "-stdin"], stdin=password).strip()
            keys = "\n".join("      - " + json.dumps(k) for k in spec.get("ssh_keys") or [])
            (seed / "user-data").write_text(
                "#cloud-config\n"
                f"hostname: \"{spec['hostname'].split('.')[0]}\"\n"
                f"fqdn: \"{spec['hostname']}\"\n"
                "users:\n"
                f"  - name: {DEFAULT_USER}\n"
                "    groups: [wheel]\n"
                "    sudo: ALL=(ALL) ALL\n"
                "    shell: /bin/bash\n"
                "    lock_passwd: false\n"
                f"    passwd: {pw_hash}\n"
                + (f"    ssh_authorized_keys:\n{keys}\n" if keys else "")
                # chpasswd also sets the password when the user already exists (a VM started from a backup):
                # the users: module above only sets passwd when it creates the user.
                + "chpasswd:\n  expire: false\n  users:\n"
                f"    - {{name: {DEFAULT_USER}, password: '{pw_hash}', type: hash}}\n"
                + "ssh_pwauth: false\n"
                "disable_root: true\n"
                "growpart: {mode: auto, devices: ['/']}\n"
                + GA_SSH_WRITE_FILES
                + "runcmd:\n  - systemctl enable --now qemu-guest-agent\n"
                "  - [sh, /usr/local/sbin/ga-ssh-keys.sh]\n")
            # Our own NoCloud seed disk (volume label "cidata"), kept for the VM's lifetime.
            # (virt-install --cloud-init deletes its temporary ISO when it exits, which broke first boot.)
            files = [str(seed / f) for f in ("user-data", "meta-data", "network-config") if (seed / f).exists()]
            seed_iso.parent.mkdir(parents=True, exist_ok=True)
            run(["xorriso", "-as", "mkisofs", "-quiet", "-output", str(seed_iso), "-volid", "cidata",
                 "-joliet", "-rock", *files])
            os.chmod(seed_iso, 0o600)
            vmax = max(spec["vcpu"], min(16, self.conn.getInfo()[2]))
            maxmem = max(spec["ram_mb"] * 2, spec["ram_mb"] + 4096)
            run(["virt-install", "--name", vm_id, "--osinfo", "linux2022",
                 "--vcpus", f"{spec['vcpu']},maxvcpus={vmax}",
                 "--cpu", f"host-passthrough,cell0.id=0,cell0.cpus=0-{vmax - 1},cell0.memory={spec['ram_mb'] * 1024}",
                 "--memory", f"{spec['ram_mb']},maxMemory={maxmem},maxMemory.slots=4",
                 "--disk", f"{disk},bus=virtio,format=qcow2",
                 *net_args,
                 "--boot", "uefi",
                 "--channel", "unix,target.type=virtio,target.name=org.qemu.guest_agent.0",
                 "--graphics", "vnc,listen=127.0.0.1",
                 "--disk", f"path={seed_iso},device=cdrom,bus=sata,readonly=on",
                 "--import", "--noautoconsole"], timeout=300)
            self.conn.lookupByName(vm_id).setAutostart(1)
        except Exception:
            # clean up a half-created VM
            try:
                d = self.conn.lookupByName(vm_id)
                if d.isActive():
                    d.destroy()
                d.undefineFlags(self.libvirt.VIR_DOMAIN_UNDEFINE_NVRAM)
            except Exception:
                pass
            disk.unlink(missing_ok=True)
            seed_iso.unlink(missing_ok=True)
            if mac2:
                self._release_internal_ips([mac2])
            raise
        finally:
            shutil.rmtree(seed, ignore_errors=True)     # plain files removed; the hash lives only in the root-only seed ISO
        out = self.get(vm_id)
        out.update({"login_user": DEFAULT_USER, "initial_password": password,
                    "public_ip": spec.get("public_ip"), "internal_ip": internal_ip})
        return out

    def _guest_dom(self, vm_id: str):
        self._ensure_conn()
        d = self._dom(vm_id)
        if not d.isActive():
            raise AgentError(409, "start the VM first: SSH keys are set through the guest agent inside the running VM")
        return d

    def _ga_error(self, e) -> AgentError:
        msg = str(e)
        low = msg.lower()
        if "not connected" in low or "not responding" in low or "unable to connect" in low:
            return AgentError(409, "the VM's guest agent isn't answering yet (still booting?). Try again in a minute. (" + msg + ")")
        if "permission denied" in low:
            return AgentError(409, "SELinux inside the VM blocks the guest agent from the SSH key file. Fix it once inside the VM "
                                   "(web console): sudo setsebool -P virt_qemu_ga_read_ssh on; sudo setsebool -P virt_qemu_ga_manage_ssh on. "
                                   "VMs created from now on have this set automatically.")
        if "disabled" in low or "not allowed" in low or "not supported" in low or "unsupported" in low:
            return AgentError(409, "the guest agent inside this VM doesn't allow SSH key commands (" + msg + ")")
        # 409, not 5xx: Cloudflare replaces 502/504 bodies with its own page, which would hide this message
        return AgentError(409, "guest agent error: " + msg)

    def ssh_keys_get(self, vm_id: str) -> dict:
        d = self._guest_dom(vm_id)
        try:
            keys = d.authorizedSSHKeysGet(DEFAULT_USER, 0)
        except self.libvirt.libvirtError as e:
            raise self._ga_error(e)
        return {"user": DEFAULT_USER, "keys": [k for k in keys if k.strip()]}

    def ssh_keys_add(self, vm_id: str, keys: list[str]) -> dict:
        d = self._guest_dom(vm_id)
        try:
            d.authorizedSSHKeysSet(DEFAULT_USER, keys, self.libvirt.VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_APPEND)
        except self.libvirt.libvirtError as e:
            raise self._ga_error(e)
        return self.ssh_keys_get(vm_id)

    def ssh_keys_remove(self, vm_id: str, keys: list[str]) -> dict:
        d = self._guest_dom(vm_id)
        try:
            d.authorizedSSHKeysSet(DEFAULT_USER, keys, self.libvirt.VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_REMOVE)
        except self.libvirt.libvirtError as e:
            raise self._ga_error(e)
        return self.ssh_keys_get(vm_id)

    def action(self, vm_id: str, action: str) -> dict:
        self._ensure_conn()
        d = self._dom(vm_id)
        try:
            if action == "start":
                if not d.isActive():
                    d.create()
            elif action == "shutdown":
                if d.isActive():
                    d.shutdown()
            elif action == "reboot":
                if not d.isActive():
                    raise AgentError(409, "VM is not running")
                d.reboot()
            elif action == "poweroff":
                if d.isActive():
                    d.destroy()
        except self.libvirt.libvirtError as e:
            raise AgentError(500, str(e))
        return self._summary(d)

    def delete(self, vm_id: str) -> dict:
        self._ensure_conn()
        if not VM_ID.match(vm_id):
            raise AgentError(400, "only portal-managed VMs (vm-…) can be deleted")
        d = self._dom(vm_id)
        files = [f["file"] for f in self.get(vm_id)["disks"] if f.get("file")]
        macs = self._macs(d)
        if d.isActive():
            d.destroy()
        lv = self.libvirt
        d.undefineFlags(lv.VIR_DOMAIN_UNDEFINE_NVRAM | lv.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
                        | lv.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA | lv.VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA)
        self._release_internal_ips(macs)
        removed = []
        iso = self._seed_iso(vm_id)
        if iso.exists():
            iso.unlink()
            removed.append(str(iso))
        for f in files:
            p = Path(f).resolve()
            if p.parent == IMAGE_DIR.resolve() and p.name.startswith(vm_id) and p.suffix == ".qcow2":
                p.unlink(missing_ok=True)
                removed.append(str(p))
        return {"id": vm_id, "deleted": True, "removed_files": removed}

    def _do_backup(self, vm_id: str, bid: str) -> dict:
        import xml.etree.ElementTree as ET
        lv = self.libvirt
        conn = lv.open("qemu:///system")              # own connection for this thread
        target = _bk_dir(bid) / "disk.qcow2"
        try:
            d = conn.lookupByName(vm_id)
            (_bk_dir(bid) / "domain.xml").write_text(d.XMLDesc(lv.VIR_DOMAIN_XML_INACTIVE))
            x = ET.fromstring(d.XMLDesc())
            disks = x.findall("./devices/disk")
            main = next(dk for dk in disks if dk.get("device") == "disk")
            src = main.find("source").get("file")
            if d.isActive():
                parts = []
                for dk in disks:
                    dev = dk.find("target").get("dev")
                    if dk is main:
                        parts.append(f"<disk name='{dev}' backup='yes' type='file'><target file='{target}'/>"
                                     f"<driver type='qcow2'/></disk>")
                    else:
                        parts.append(f"<disk name='{dev}' backup='no'/>")
                frozen = False
                try:
                    d.fsFreeze()                     # consistent filesystems (guest agent); fine if it fails
                    frozen = True
                except lv.libvirtError:
                    pass
                try:
                    d.backupBegin(f"<domainbackup mode='push'><disks>{''.join(parts)}</disks></domainbackup>", None, 0)
                finally:
                    if frozen:
                        try:
                            d.fsThaw()
                        except lv.libvirtError:
                            pass
                while True:                           # wait for the push job, report progress
                    time.sleep(2)
                    try:
                        st = d.jobStats()
                    except lv.libvirtError:
                        st = {}
                    if not st or st.get("type", 0) == lv.VIR_DOMAIN_JOB_NONE:
                        break
                    total, done = st.get("disk_total") or st.get("data_total"), st.get("disk_processed") or st.get("data_processed")
                    if total:
                        m = read_meta(bid)
                        m["progress"] = min(99, int(done * 100 / total))
                        write_meta(bid, m)
                try:
                    st = d.jobStats(lv.VIR_DOMAIN_JOB_STATS_COMPLETED)
                    if st.get("type") == lv.VIR_DOMAIN_JOB_FAILED:
                        raise AgentError(500, st.get("errmsg") or "backup job failed")
                except lv.libvirtError:
                    pass
                run(["qemu-img", "check", str(target)], timeout=3600)
            else:
                run(["qemu-img", "convert", "-O", "qcow2", src, str(target)], timeout=14400)
            self._finish_backup(bid, target)
            return {"backup_id": bid}
        except Exception as e:
            self._fail_backup(bid, e.message if isinstance(e, AgentError) else str(e))
            raise
        finally:
            conn.close()

    def _do_restore(self, vm_id: str, bid: str) -> dict:
        import xml.etree.ElementTree as ET
        lv = self.libvirt
        conn = lv.open("qemu:///system")
        try:
            d = conn.lookupByName(vm_id)
            src = (_bk_dir(bid) / read_meta(bid)["file"])
            main = next(dk for dk in ET.fromstring(d.XMLDesc()).findall("./devices/disk") if dk.get("device") == "disk")
            disk = Path(main.find("source").get("file"))
            if d.isActive():                          # clean shutdown first, then force
                try:
                    d.shutdown()
                except lv.libvirtError:
                    pass
                for _ in range(45):
                    if not d.isActive():
                        break
                    time.sleep(2)
                if d.isActive():
                    d.destroy()
            tmp = disk.with_suffix(".restore.tmp")
            run(["qemu-img", "convert", "-O", "qcow2", str(src), str(tmp)], timeout=14400)
            os.replace(tmp, disk)                     # atomic swap; the old disk is gone only now
            d.create()
            return {"vm_id": vm_id, "backup_id": bid}
        finally:
            conn.close()

    def vnc_port(self, vm_id: str) -> int:
        port = self.get(vm_id).get("vnc_port")
        if not port:
            raise AgentError(409, "VM has no active VNC console (is it running?)")
        return port


FAKE_SLOW = os.environ.get("AGENT_FAKE_SLOW", "0") == "1"


class FakeBackend:
    """In-memory backend for local tests (AGENT_FAKE=1)."""

    def __init__(self):
        self.vms: dict[str, dict] = {"vm-test1": {"id": "vm-test1", "uuid": "fake", "state": "running",
                                                  "vcpu": 4, "ram_mb": 2048, "managed": True}}

    def health(self):
        return {"node": NODE_ID, "libvirt": "fake", "qemu": "fake", "fake": True}

    def capacity(self):
        return {"node": NODE_ID, "cpus": 32, "ram_mb": 63000, "ram_free_mb": 50000, "disk_gb": 70,
                "disk_free_gb": 50, "vms_total": len(self.vms),
                "vms_running": sum(v["state"] == "running" for v in self.vms.values()),
                "vcpu_allocated": sum(v["vcpu"] for v in self.vms.values() if v["state"] == "running"),
                "ram_allocated_mb": sum(v["ram_mb"] for v in self.vms.values() if v["state"] == "running")}

    def templates(self):
        return [{"id": "almalinux-10-cloud", "file": "almalinux-10-cloud.qcow2", "size_gb": 1.52}]

    def list(self):
        return list(self.vms.values())

    def get(self, vm_id):
        if vm_id not in self.vms:
            raise AgentError(404, f"VM {vm_id} not found")
        v = dict(self.vms[vm_id])
        v.update({"vcpu_max": 16, "disks": [{"dev": "vda", "size_gb": 30, "used_gb": 0.01}],
                  "ips": ["192.168.122.20"] if v["state"] == "running" else [], "vnc_port": None,
                  "autostart": True, "cpu_time_s": 1.0})
        return v

    def action(self, vm_id, action):
        v = self.get(vm_id)
        self.vms[vm_id]["state"] = {"start": "running", "shutdown": "stopped", "poweroff": "stopped",
                                    "reboot": "running"}[action]
        return self.vms[vm_id]

    def _fake_keys(self, vm_id):
        v = self.get(vm_id)
        if v["state"] != "running":
            raise AgentError(409, "start the VM first: SSH keys are set through the guest agent inside the running VM")
        return self.vms[vm_id].setdefault("ssh_keys", [])

    def ssh_keys_get(self, vm_id):
        return {"user": DEFAULT_USER, "keys": list(self._fake_keys(vm_id))}

    def ssh_keys_add(self, vm_id, keys):
        cur = self._fake_keys(vm_id)
        cur.extend(k for k in keys if k not in cur)
        return self.ssh_keys_get(vm_id)

    def ssh_keys_remove(self, vm_id, keys):
        cur = self._fake_keys(vm_id)
        cur[:] = [k for k in cur if k not in keys]
        return self.ssh_keys_get(vm_id)

    def delete(self, vm_id):
        self.get(vm_id)
        del self.vms[vm_id]
        return {"id": vm_id, "deleted": True, "removed_files": []}

    def vnc_port(self, vm_id):
        raise AgentError(409, "no console in fake mode")

    def _do_backup(self, vm_id, bid):
        time.sleep(1.5)
        target = _bk_dir(bid) / "disk.qcow2"
        target.write_bytes(b"QFI\xfb" + os.urandom(4096))
        self._finish_backup(bid, target)
        return {"backup_id": bid}

    def _do_restore(self, vm_id, bid):
        time.sleep(1.5)
        self.vms[vm_id]["state"] = "running"
        return {"vm_id": vm_id, "backup_id": bid}

    def create(self, spec, source=None):
        if spec["id"] in self.vms:
            raise AgentError(409, "exists")
        time.sleep(1.0 if FAKE_SLOW else 0)
        self.vms[spec["id"]] = {"id": spec["id"], "uuid": "fake", "state": "running", "vcpu": spec["vcpu"],
                                "public_ip": spec.get("public_ip"), "ram_mb": spec["ram_mb"], "managed": True}
        out = self.get(spec["id"])
        out.update({"login_user": DEFAULT_USER, "initial_password": "fake-password", "public_ip": spec.get("public_ip"),
                    "internal_ip": "192.168.122.254" if spec.get("public_ip") else None})
        return out


# ------------------------------------------------------------------ backups and background jobs

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/home/vm-backups"))
BK_ID = re.compile(r"^bk-[0-9]{14}-[0-9a-f]{6}$")
JOBS: dict[str, dict] = {}            # in memory: restore / restore-as-new jobs (results read once)
BUSY: set[str] = set()                # VMs with a backup/restore in progress
change_lock = threading.Lock()        # libvirt define/undefine from background threads


def _bk_dir(bid: str) -> Path:
    if not BK_ID.match(bid):
        raise AgentError(400, "bad backup id")
    return BACKUP_DIR / bid


def read_meta(bid: str) -> dict:
    f = _bk_dir(bid) / "meta.json"
    if not f.is_file():
        raise AgentError(404, f"backup {bid} not found")
    return json.loads(f.read_text())


def write_meta(bid: str, meta: dict) -> None:
    f = _bk_dir(bid) / "meta.json"
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=1))
    os.replace(tmp, f)


def list_backups() -> dict:
    out = []
    if BACKUP_DIR.is_dir():
        for d in sorted(BACKUP_DIR.iterdir(), reverse=True):
            if BK_ID.match(d.name) and (d / "meta.json").is_file():
                try:
                    m = json.loads((d / "meta.json").read_text())
                    if m.get("status") == "running" and m.get("pid") != os.getpid():
                        m.update(status="failed", error="agent restarted during backup")     # orphaned job
                        write_meta(d.name, m)
                    out.append({k: v for k, v in m.items() if k != "pid"})
                except (OSError, ValueError):
                    continue
    try:
        du = shutil.disk_usage(BACKUP_DIR)
        space = {"total_gb": round(du.total / 2**30), "free_gb": round(du.free / 2**30)}
    except OSError:
        space = {"total_gb": None, "free_gb": None}
    return {"node": NODE_ID, "dir": str(BACKUP_DIR), **space, "backups": out}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 2**20), b""):
            h.update(chunk)
    return h.hexdigest()


def new_job(kind: str, **info) -> dict:
    jid = f"job-{secrets.token_hex(6)}"
    JOBS[jid] = {"id": jid, "type": kind, "status": "running", "started": time.time(), **info}
    return JOBS[jid]


def run_job(job: dict, fn, *args) -> None:
    def worker():
        try:
            res = fn(*args)
            job.update(status="done", finished=time.time(), result=res or {})
        except AgentError as e:
            job.update(status="failed", finished=time.time(), error=e.message)
        except Exception as e:  # noqa: BLE001
            job.update(status="failed", finished=time.time(), error=f"{type(e).__name__}: {e}")
        finally:
            for k in ("vm_id", "new_vm_id"):
                BUSY.discard(job.get(k))
    threading.Thread(target=worker, daemon=True).start()


def mark_busy(vm_id: str) -> None:
    if vm_id in BUSY:
        raise AgentError(409, f"{vm_id} already has a backup or restore running")
    BUSY.add(vm_id)


class BackupMixin:
    """Backups as plain qcow2 images (+ domain XML + meta.json + sha256), restorable on any node."""

    def backup_start(self, vm_id: str, note: str = "") -> dict:
        info = self.get(vm_id)
        mark_busy(vm_id)
        try:
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            used = sum(d.get("used_gb", d.get("size_gb", 0)) or 0 for d in info.get("disks", []))
            if shutil.disk_usage(BACKUP_DIR).free / 2**30 < used * 1.1 + 5:
                raise AgentError(507, f"not enough space in {BACKUP_DIR}")
            bid = f"bk-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"
            d = _bk_dir(bid)
            d.mkdir(mode=0o711)
            os.chmod(d, 0o711)                     # qemu (svirt) writes the push-backup target in here
            meta = {"id": bid, "vm_id": vm_id, "node": NODE_ID, "status": "running", "progress": 0,
                    "kind": "live" if info["state"] == "running" else "offline", "note": note[:200],
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pid": os.getpid(),
                    "vm": {"vcpu": info.get("vcpu"), "ram_mb": info.get("ram_mb"),
                           "disk_gb": max([x.get("size_gb") or 0 for x in info.get("disks", [])] or [0])},
                    "file": "disk.qcow2"}
            write_meta(bid, meta)
        except Exception:
            BUSY.discard(vm_id)
            raise
        job = new_job("backup", vm_id=vm_id, backup_id=bid)
        run_job(job, self._do_backup, vm_id, bid)
        return {k: v for k, v in meta.items() if k != "pid"}

    def _finish_backup(self, bid: str, target: Path) -> None:
        meta = read_meta(bid)
        meta.update(status="ready", progress=100, size_bytes=target.stat().st_size, sha256=sha256_file(target),
                    finished=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        write_meta(bid, meta)

    def _fail_backup(self, bid: str, err: str) -> None:
        try:
            meta = read_meta(bid)
            meta.update(status="failed", error=err[:500])
            write_meta(bid, meta)
            (_bk_dir(bid) / "disk.qcow2").unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass

    def backup_delete(self, bid: str) -> dict:
        meta = read_meta(bid)
        if meta.get("status") in ("running", "processing"):
            raise AgentError(409, "backup still running")
        shutil.rmtree(_bk_dir(bid))
        return {"id": bid, "deleted": True}

    def backup_file(self, bid: str) -> tuple[Path, str]:
        meta = read_meta(bid)
        if meta.get("status") != "ready":
            raise AgentError(409, "backup is not ready")
        return _bk_dir(bid) / meta["file"], f"{meta['vm_id']}-{bid}.qcow2"

    def restore_start(self, bid: str, target: str | None = None) -> dict:
        meta = read_meta(bid)
        if meta.get("status") != "ready":
            raise AgentError(409, "backup is not ready")
        vm_id = target or meta["vm_id"]
        if not VM_ID.match(vm_id):
            raise AgentError(400, "can only restore onto VMs named vm-…")
        self.get(vm_id)                          # must exist here (else use restore-as-new)
        mark_busy(vm_id)
        job = new_job("restore", vm_id=vm_id, backup_id=bid)
        run_job(job, self._do_restore, vm_id, bid)
        return job

    # ---- uploads: an image from the admin's computer, sent in chunks (Cloudflare caps each request ~100 MB)
    UPLOAD_MAX = 2 * 2**40              # 2 TiB
    CHUNK_MAX = 100 * 2**20

    def upload_start(self, filename: str, size: int, note: str = "") -> dict:
        if not (0 < size <= self.UPLOAD_MAX):
            raise AgentError(400, "bad file size")
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(BACKUP_DIR).free < size * 2.2 + 5 * 2**30:      # upload + converted copy
            raise AgentError(507, f"not enough space in {BACKUP_DIR}")
        bid = f"bk-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"
        d = _bk_dir(bid)
        d.mkdir(mode=0o711)
        (d / "upload.part").touch(mode=0o600)
        name = re.sub(r"[^A-Za-z0-9._ -]", "_", filename)[:120] or "image"
        meta = {"id": bid, "vm_id": "upload", "node": NODE_ID, "status": "uploading", "progress": 0, "kind": "upload",
                "note": note[:200], "source_name": name, "expected_bytes": size, "received_bytes": 0,
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "file": "disk.qcow2"}
        write_meta(bid, meta)
        return meta

    def upload_chunk(self, bid: str, offset: int, data: bytes) -> dict:
        meta = read_meta(bid)
        if meta.get("status") != "uploading":
            raise AgentError(409, "upload is not open")
        part = _bk_dir(bid) / "upload.part"
        have = part.stat().st_size
        if offset != have:                       # lets the browser resume: it re-sends from `have`
            raise AgentError(409, f"offset mismatch: have {have}")
        if have + len(data) > meta["expected_bytes"]:
            raise AgentError(400, "more data than the declared size")
        with open(part, "ab") as f:
            f.write(data)
        meta["received_bytes"] = have + len(data)
        meta["progress"] = round(100 * meta["received_bytes"] / meta["expected_bytes"], 1)
        write_meta(bid, meta)
        return {"id": bid, "received_bytes": meta["received_bytes"]}

    def upload_finish(self, bid: str) -> dict:
        meta = read_meta(bid)
        part = _bk_dir(bid) / "upload.part"
        if meta.get("status") != "uploading":
            raise AgentError(409, "upload is not open")
        if part.stat().st_size != meta["expected_bytes"]:
            raise AgentError(409, f"incomplete: {part.stat().st_size} of {meta['expected_bytes']} bytes")
        meta.update(status="processing", progress=0)
        write_meta(bid, meta)
        job = new_job("upload", backup_id=bid)
        run_job(job, self._process_upload, bid)
        return job

    def _process_upload(self, bid: str) -> dict:
        d = _bk_dir(bid)
        part, out = d / "upload.part", d / "disk.qcow2"
        try:
            if FAKE:
                os.replace(part, out)
                vsize = 20 * 2**30
            else:
                # Inspect untrusted image. Refuse anything that points at other files on this host.
                info = json.loads(run(["qemu-img", "info", "--output", "json", str(part)], timeout=120))
                fmt = info.get("format")
                if fmt not in {"qcow2", "raw", "vmdk", "vhdx", "vpc", "vdi"}:
                    raise AgentError(400, f"unsupported image format: {fmt}")
                spec = (info.get("format-specific") or {}).get("data") or {}
                if info.get("backing-filename") or info.get("full-backing-filename") or spec.get("data-file") \
                        or fmt == "vmdk" and (spec.get("extents") and any(e.get("filename") != str(part) for e in spec["extents"])):
                    raise AgentError(400, "image refers to other files (backing file / external data) - not allowed")
                vsize = int(info.get("virtual-size") or 0)
                if not (2**30 <= vsize <= self.UPLOAD_MAX):
                    raise AgentError(400, "image virtual size must be between 1 GB and 2 TB")
                run(["qemu-img", "convert", "-f", fmt, "-O", "qcow2", str(part), str(out)], timeout=14400)
                part.unlink()
                run(["qemu-img", "check", "-f", "qcow2", str(out)], timeout=3600)
            meta = read_meta(bid)
            meta.update(status="ready", progress=100, size_bytes=out.stat().st_size, sha256=sha256_file(out),
                        finished=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        vm={"vcpu": 1, "ram_mb": 2048, "disk_gb": -(-vsize // 2**30)})
            write_meta(bid, meta)
            return {"backup_id": bid, "disk_gb": meta["vm"]["disk_gb"]}
        except Exception as e:  # noqa: BLE001
            msg = e.message if isinstance(e, AgentError) else f"{type(e).__name__}: {e}"
            meta = read_meta(bid)
            meta.update(status="failed", error=msg[:500])
            write_meta(bid, meta)
            part.unlink(missing_ok=True)
            out.unlink(missing_ok=True)
            raise

    def restore_new_start(self, bid: str, spec: dict) -> dict:
        meta = read_meta(bid)
        if meta.get("status") != "ready":
            raise AgentError(409, "backup is not ready")
        mark_busy(spec["id"])
        job = new_job("restore_new", backup_id=bid, new_vm_id=spec["id"], from_vm_id=meta["vm_id"])
        src = _bk_dir(bid) / meta["file"]

        def do():
            with change_lock:
                out = self.create(spec, source=src)
            return {"id": spec["id"], "login_user": out.get("login_user"), "initial_password": out.get("initial_password"),
                    "public_ip": out.get("public_ip"), "internal_ip": out.get("internal_ip"), "disk_gb": spec["disk_gb"]}
        run_job(job, do)
        return job


class Libvirt(BackupMixin, LibvirtBackend):
    pass


class Fake(BackupMixin, FakeBackend):
    pass


backend = Fake() if FAKE else Libvirt()
lock = asyncio.Lock()        # one libvirt change at a time on this host


# ------------------------------------------------------------------ HTTP layer

def authorised(headers) -> bool:
    got = headers.get("authorization", "")
    return bool(TOKEN) and hmac.compare_digest(got, f"Bearer {TOKEN}")


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def endpoint(fn):
    async def wrapper(request: Request):
        if not authorised(request.headers):
            return error(401, "unauthorised")
        try:
            return JSONResponse(await fn(request))
        except AgentError as e:
            return error(e.status, e.message)
        except Exception as e:  # noqa: BLE001
            return error(500, f"{type(e).__name__}: {e}")
    return wrapper


def vm_id_of(request: Request) -> str:
    vm_id = request.path_params["vm_id"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,60}", vm_id):
        raise AgentError(400, "bad VM id")
    return vm_id


@endpoint
async def health(request):
    return await asyncio.to_thread(backend.health)


@endpoint
async def capacity(request):
    return await asyncio.to_thread(backend.capacity)


@endpoint
async def templates(request):
    return {"templates": await asyncio.to_thread(backend.templates)}


@endpoint
async def list_vms(request):
    return {"vms": await asyncio.to_thread(backend.list)}


@endpoint
async def get_vm(request):
    return await asyncio.to_thread(backend.get, vm_id_of(request))


def validate_spec(body: dict) -> dict:
    spec = {}
    vm_id = str(body.get("id", ""))
    if not VM_ID.match(vm_id):
        raise AgentError(400, "id must look like vm-xxxxxxxx")
    spec["id"] = vm_id
    hostname = str(body.get("hostname") or vm_id).lower()
    if not HOSTNAME.match(hostname) or len(hostname) > 253:
        raise AgentError(400, "invalid hostname")
    spec["hostname"] = hostname
    spec["template"] = str(body.get("template", ""))
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", spec["template"]):
        raise AgentError(400, "invalid template")
    for k, (lo, hi) in LIMITS.items():
        try:
            v = int(body.get(k))
        except (TypeError, ValueError):
            raise AgentError(400, f"{k} required")
        if not lo <= v <= hi:
            raise AgentError(400, f"{k} must be {lo}–{hi}")
        spec[k] = v
    keys = body.get("ssh_keys") or []
    if not isinstance(keys, list) or len(keys) > 10 or not all(isinstance(k, str) and SSH_KEY.match(k.strip()) for k in keys):
        raise AgentError(400, "ssh_keys must be a list of public keys (ssh-ed25519 / ssh-rsa / ecdsa)")
    spec["ssh_keys"] = [k.strip() for k in keys]
    ip = str(body.get("public_ip") or "").strip()
    if ip:
        if not (PUBLIC_BRIDGE and PUBLIC_GATEWAY):
            raise AgentError(400, "public IPs are not enabled on this node (PUBLIC_BRIDGE / PUBLIC_GATEWAY not set)")
        if ip not in PUBLIC_POOL:
            raise AgentError(400, f"{ip} is not in this node's public IP pool")
        spec["public_ip"] = ip
    return spec


@endpoint
async def create_vm(request):
    body = await request.json()
    spec = validate_spec(body)
    if body.get("async"):                      # background job: the caller polls GET /jobs/{id}
        mark_busy(spec["id"])
        job = new_job("create", new_vm_id=spec["id"])

        def do():
            with change_lock:
                out = backend.create(spec)
            return {k: out.get(k) for k in ("id", "login_user", "initial_password", "public_ip", "internal_ip")}
        run_job(job, do)
        return public_job(job)
    async with lock:
        return await asyncio.to_thread(backend.create, spec)


def public_job(job: dict, consume: bool = False) -> dict:
    out = {k: v for k, v in job.items() if k != "result"}
    res = dict(job.get("result") or {})
    if res:
        out["result"] = res
        if consume and "initial_password" in res:     # hand the password out once
            job["result"].pop("initial_password", None)
    return out


@endpoint
async def get_job(request):
    jid = request.path_params["job_id"]
    job = JOBS.get(jid)
    if not job:
        raise AgentError(404, "job not found (finished long ago, or the agent restarted)")
    return public_job(job, consume=request.query_params.get("consume") == "1")


@endpoint
async def backups_list(request):
    return await asyncio.to_thread(list_backups)


@endpoint
async def backup_create(request):
    vm_id = vm_id_of(request)
    body = await request.json() if (await request.body()) else {}
    return await asyncio.to_thread(backend.backup_start, vm_id, str(body.get("note") or ""))


@endpoint
async def backup_delete(request):
    return await asyncio.to_thread(backend.backup_delete, request.path_params["bid"])


@endpoint
async def backup_restore(request):
    body = await request.json() if (await request.body()) else {}
    target = body.get("vm_id") or None
    return public_job(await asyncio.to_thread(backend.restore_start, request.path_params["bid"], target))


@endpoint
async def upload_start(request):
    body = await request.json()
    return await asyncio.to_thread(backend.upload_start, str(body.get("filename") or "image"),
                                   int(body.get("size") or 0), str(body.get("note") or ""))


@endpoint
async def upload_chunk(request):
    try:
        offset = int(request.query_params.get("offset", "-1"))
    except ValueError:
        raise AgentError(400, "bad offset")
    data = bytearray()
    async for piece in request.stream():
        data += piece
        if len(data) > backend.CHUNK_MAX:
            raise AgentError(413, "chunk too large")
    return await asyncio.to_thread(backend.upload_chunk, request.path_params["bid"], offset, bytes(data))


@endpoint
async def upload_finish(request):
    return public_job(await asyncio.to_thread(backend.upload_finish, request.path_params["bid"]))


@endpoint
async def backup_restore_new(request):
    body = await request.json()
    body.setdefault("template", "backup")
    spec = validate_spec(body)
    return public_job(await asyncio.to_thread(backend.restore_new_start, request.path_params["bid"], spec))


async def backup_download(request: Request):
    if not authorised(request.headers):
        return error(401, "unauthorised")
    try:
        path, name = await asyncio.to_thread(backend.backup_file, request.path_params["bid"])
    except AgentError as e:
        return error(e.status, e.message)
    return FileResponse(path, filename=name, media_type="application/octet-stream")


@endpoint
async def backup_meta(request):
    return await asyncio.to_thread(read_meta, request.path_params["bid"])


async def vm_action(request: Request):
    if not authorised(request.headers):
        return error(401, "unauthorised")
    action = request.path_params["action"]
    if action not in {"start", "shutdown", "reboot", "poweroff"}:
        return error(404, "unknown action")
    try:
        vm_id = vm_id_of(request)
        async with lock:
            return JSONResponse(await asyncio.to_thread(backend.action, vm_id, action))
    except AgentError as e:
        return error(e.status, e.message)


@endpoint
async def ssh_keys_get(request):
    return await asyncio.to_thread(backend.ssh_keys_get, vm_id_of(request))


@endpoint
async def ssh_keys_change(request):
    vm_id = vm_id_of(request)
    body = await request.json()
    removing = request.method == "DELETE"
    keys = clean_removal_keys(body.get("keys")) if removing else clean_ssh_keys(body.get("keys"))
    fn = backend.ssh_keys_remove if removing else backend.ssh_keys_add
    return await asyncio.to_thread(fn, vm_id, keys)


@endpoint
async def delete_vm(request):
    vm_id = vm_id_of(request)
    async with lock:
        return await asyncio.to_thread(backend.delete, vm_id)


async def console(ws: WebSocket):
    if not authorised(ws.headers):
        await ws.close(code=4401)
        return
    try:
        port = await asyncio.to_thread(backend.vnc_port, ws.path_params["vm_id"])
    except AgentError as e:
        await ws.accept()
        await ws.close(code=4409, reason=e.message[:100])
        return
    sub = ws.headers.get("sec-websocket-protocol", "")
    await ws.accept(subprotocol="binary" if "binary" in sub else None)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    async def ws_to_tcp():
        try:
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                data = msg.get("bytes") or (msg.get("text") or "").encode()
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)
        finally:
            try:
                await ws.close()
            except Exception:
                pass

    try:
        await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    except (WebSocketDisconnect, ConnectionError):
        pass


async def events(ws: WebSocket):
    """Live stream for the portal: host capacity + VM states every few seconds."""
    if not authorised(ws.headers):
        await ws.close(code=4401)
        return
    await ws.accept()
    interval = 3.0
    try:
        while True:
            try:
                cap, vms = await asyncio.gather(asyncio.to_thread(backend.capacity), asyncio.to_thread(backend.list))
                await ws.send_text(json.dumps({"type": "snapshot", "ts": time.time(), "capacity": cap, "vms": vms}))
            except AgentError as e:
                await ws.send_text(json.dumps({"type": "error", "error": e.message}))
            except (WebSocketDisconnect, RuntimeError):
                raise
            except Exception as e:  # noqa: BLE001
                await ws.send_text(json.dumps({"type": "error", "error": f"{type(e).__name__}: {e}"}))
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=interval)
                if msg["type"] == "websocket.disconnect":
                    break
            except asyncio.TimeoutError:
                pass
    except (WebSocketDisconnect, RuntimeError, ConnectionError):
        pass


app = Starlette(routes=[
    Route("/health", health),
    Route("/capacity", capacity),
    Route("/templates", templates),
    Route("/vms", list_vms, methods=["GET"]),
    Route("/vms", create_vm, methods=["POST"]),
    Route("/vms/{vm_id}", get_vm, methods=["GET"]),
    Route("/vms/{vm_id}", delete_vm, methods=["DELETE"]),
    Route("/jobs/{job_id}", get_job, methods=["GET"]),
    Route("/backups", backups_list, methods=["GET"]),
    Route("/backups/upload", upload_start, methods=["POST"]),
    Route("/backups/{bid}", backup_meta, methods=["GET"]),
    Route("/backups/{bid}/chunk", upload_chunk, methods=["PUT"]),
    Route("/backups/{bid}/finish", upload_finish, methods=["POST"]),
    Route("/backups/{bid}", backup_delete, methods=["DELETE"]),
    Route("/backups/{bid}/download", backup_download, methods=["GET", "HEAD"]),
    Route("/backups/{bid}/restore", backup_restore, methods=["POST"]),
    Route("/backups/{bid}/restore-new", backup_restore_new, methods=["POST"]),
    Route("/vms/{vm_id}/backups", backup_create, methods=["POST"]),
    Route("/vms/{vm_id}/ssh-keys", ssh_keys_get, methods=["GET"]),
    Route("/vms/{vm_id}/ssh-keys", ssh_keys_change, methods=["POST", "DELETE"]),
    Route("/vms/{vm_id}/{action}", vm_action, methods=["POST"]),
    WebSocketRoute("/vms/{vm_id}/console", console),
    WebSocketRoute("/events", events),
])

if __name__ == "__main__":
    import uvicorn
    if len(TOKEN) < 32:
        raise SystemExit("AGENT_TOKEN must be at least 32 characters")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning", timeout_graceful_shutdown=2)
