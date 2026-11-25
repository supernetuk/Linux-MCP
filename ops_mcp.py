"""
Linux ops MCP server — lets Claude run checked commands on a KVM host.

Safety model
- Commands are parsed with shlex and executed WITHOUT a shell (no pipes, redirects, globbing, $(...)).
- Every command must match an allowlist rule. Anything else is refused.
- Two levels:
    run_check  read-only commands, always available, run as the unprivileged `claude-ops` user
               (virsh uses the read-only libvirt connection).
    run_admin  setup/admin commands run via `sudo -n`, only while ADMIN MODE is on.
               Admin mode is switched on by a human with root (`sudo claude-ops-admin 2h`) and
               expires by itself. The server cannot switch it on.
- Destructive VM actions (destroy, undefine, delete storage, reset) are only allowed on test VMs
  whose name starts with `vm-test`. Customer VMs cannot be destroyed through this server.
- Network changes (nmcli modify/up/down, ip addr/link/route changes) are always refused —
  do them from the IPMI console so a mistake can't lock everyone out.
- Every call (allowed or refused) is appended to the audit log as one JSON line.
- Reached only through Cloudflare Tunnel; listens on 127.0.0.1. The MCP endpoint path contains a
  long random secret, and the Host header must match the public hostname.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

# ---------------------------------------------------------------- configuration

TOKEN = os.environ.get("OPS_MCP_TOKEN", "")
PUBLIC_HOST = os.environ.get("OPS_MCP_PUBLIC_HOST", "")          # e.g. ops.example.com
PORT = int(os.environ.get("OPS_MCP_PORT", "8765"))
ADMIN_FLAG = Path(os.environ.get("OPS_MCP_ADMIN_FLAG", "/etc/claude-ops/admin-until"))
AUDIT_LOG = Path(os.environ.get("OPS_MCP_AUDIT_LOG", "/var/log/claude-ops/audit.jsonl"))
WORK_DIR = Path(os.environ.get("OPS_MCP_WORK_DIR", "/opt/claude-ops/work"))
USE_SUDO = os.environ.get("OPS_MCP_USE_SUDO", "1") == "1"         # tests set 0
DRY_RUN = os.environ.get("OPS_MCP_DRY_RUN", "0") == "1"           # tests: don't execute

MAX_OUTPUT = 20_000
CHECK_TIMEOUT = 120
ADMIN_TIMEOUT = 1800

IMAGE_DIRS = ("/var/lib/libvirt/images/", "/backup/")
TEMPLATE_DIR = "/var/lib/libvirt/images/templates/"
TEST_VM = re.compile(r"^vm-test[a-z0-9-]*$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._@:+-]+$")
PKG_NAME = re.compile(r"^[A-Za-z0-9._+-]+$")
UNIT_NAME = re.compile(r"^(virt[a-z]*d(-ro|-admin)?\.(socket|service)|libvirtd\.(socket|service)|"
                       r"cloudflared(@[A-Za-z0-9_-]+)?\.service|cockpit\.socket|"
                       r"qemu-guest-agent\.service)$")
READ_UNIT = re.compile(r"^[A-Za-z0-9@._-]+\.(service|socket|timer|target)$")
SHELL_CHARS = re.compile(r"[|;&<>`$\n\\]")

READABLE_FILES = {
    "/etc/os-release", "/etc/redhat-release", "/proc/mdstat", "/proc/meminfo",
    "/proc/cpuinfo", "/proc/loadavg", "/proc/partitions", "/etc/fstab",
    "/etc/cloudflared/config.yml", "/etc/hosts",
}


class Refused(Exception):
    pass


# ---------------------------------------------------------------- helpers

def admin_mode_until() -> float:
    try:
        return float(ADMIN_FLAG.read_text().strip())
    except (OSError, ValueError):
        return 0.0


def admin_on() -> bool:
    return admin_mode_until() > time.time()


def audit(entry: dict) -> None:
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **entry}
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def under(path: str, roots: tuple[str, ...]) -> bool:
    real = os.path.realpath(path)
    return any(real == r.rstrip("/") or real.startswith(r) for r in roots)


def need_path(path: str, roots: tuple[str, ...], what: str = "path") -> None:
    if not path.startswith("/") or ".." in Path(path).parts or not under(path, roots):
        raise Refused(f"{what} {path!r} must be inside {', '.join(roots)}")


def parse(command: str) -> list[str]:
    if SHELL_CHARS.search(command):
        raise Refused("shell features (| ; & < > ` $ backslash, newlines) are not allowed — "
                      "send one plain command; it runs without a shell")
    try:
        argv = shlex.split(command)
    except ValueError as e:
        raise Refused(f"could not parse command: {e}")
    if not argv:
        raise Refused("empty command")
    argv[0] = os.path.basename(argv[0])
    return argv


def clip(text: str) -> str:
    if len(text) <= MAX_OUTPUT:
        return text
    half = MAX_OUTPUT // 2
    return text[:half] + f"\n… [{len(text) - MAX_OUTPUT} characters cut] …\n" + text[-half:]


@dataclass
class Plan:
    argv: list[str]          # what to execute (absolute binary resolved by PATH)
    sudo: bool


# ---------------------------------------------------------------- Asterisk rules

ASTERISK_HELPER = "/usr/local/sbin/claude-ops-asterisk"
AST_READ = [  # Asterisk CLI commands (given to `asterisk -rx`) that only show things
    ["core", "show", "version"], ["core", "show", "uptime"], ["core", "show", "settings"],
    ["core", "show", "channels"], ["core", "show", "channels", "concise"],
    ["core", "show", "channels", "verbose"], ["core", "show", "calls"],
    ["core", "show", "channel", None], ["core", "show", "hints"],
    ["pjsip", "show", "endpoints"], ["pjsip", "show", "endpoint", None],
    ["pjsip", "show", "aors"], ["pjsip", "show", "aor", None], ["pjsip", "show", "contacts"],
    ["pjsip", "show", "registrations"], ["pjsip", "show", "transports"],
    ["pjsip", "show", "identifies"], ["pjsip", "show", "channels"],
    ["pjsip", "show", "channelstats"], ["pjsip", "show", "version"],
    ["dialplan", "show"], ["dialplan", "show", None],
    ["module", "show"], ["module", "show", "like", None], ["rtp", "show", "settings"],
]
AST_ADMIN = [  # Asterisk CLI commands that change state (admin mode only)
    ["pjsip", "reload"], ["dialplan", "reload"], ["core", "reload"], ["logger", "reload"],
    ["module", "reload", None], ["module", "load", None], ["pjsip", "qualify", None],
    ["channel", "request", "hangup", None],
]
AST_SOUND = re.compile(r"^[A-Za-z0-9_/-]+$")
# PJSIP/<number>@<endpoint>  (straight to a trunk)  or  Local/<number>@<context>  (through the
# dialplan, so caller ID and other dialplan rules apply)
AST_DIAL = re.compile(r"^(PJSIP/\+?[0-9]{3,16}@[A-Za-z0-9._-]+|Local/\+?[0-9]{3,16}@[A-Za-z0-9_-]+)$")


def _match(words: list[str], pattern: list) -> bool:
    return len(words) == len(pattern) and all(
        p == w if p is not None else bool(SAFE_NAME.match(w)) for p, w in zip(pattern, words))


def asterisk_cli(args: list[str], admin: bool) -> Plan:
    """`asterisk -rx "<cli command>"` — the CLI command is checked word by word."""
    if len(args) != 2 or args[0] != "-rx":
        raise Refused('asterisk: use  asterisk -rx "<cli command>"')
    words = args[1].split()
    if any(_match(words, p) for p in AST_READ):
        return Plan(["asterisk", "-rx", " ".join(words)], sudo=True)
    if not admin:
        raise Refused("asterisk: read-only here is core/pjsip/dialplan/module show …; "
                      "reloads and test calls need run_admin")
    if any(_match(words, p) for p in AST_ADMIN):
        return Plan(["asterisk", "-rx", " ".join(words)], sudo=True)
    # test / campaign call:  channel originate PJSIP/<number>@<endpoint> application Playback <sound>
    #                        channel originate PJSIP/<number>@<endpoint> extension <exten>@<context>
    if words[:2] == ["channel", "originate"] and len(words) == 5 and AST_DIAL.match(words[2]) \
            and words[3] == "extension" and re.fullmatch(r"[A-Za-z0-9_+-]+@[A-Za-z0-9_-]+", words[4]):
        return Plan(["asterisk", "-rx", " ".join(words)], sudo=True)
    if words[:2] == ["channel", "originate"] and len(words) == 6 and AST_DIAL.match(words[2]) \
            and words[3] == "application" and words[4] in {"Playback", "Echo", "Wait"} \
            and AST_SOUND.match(words[5]):
        return Plan(["asterisk", "-rx", " ".join(words)], sudo=True)
    raise Refused("asterisk: allowed changes are pjsip/dialplan/core/logger reload, module "
                  "reload/load <mod>, pjsip qualify <aor>, channel request hangup <chan|all>, and "
                  "channel originate PJSIP/<number>@<endpoint> or Local/<number>@<context> (application Playback <sound> | "
                  "extension <exten>@<context>)")


def asterisk_helper(args: list[str], admin: bool) -> Plan:
    sub = args[:1]
    if sub in (["show-conf"], ["list-backups"], ["log"]) and len(args) <= 2:
        return Plan([ASTERISK_HELPER, *args], sudo=True)
    if admin and sub in (["install-conf"], ["restore-conf"]) and len(args) <= 3:
        return Plan([ASTERISK_HELPER, *args], sudo=True)
    raise Refused("claude-ops-asterisk: show-conf <x.conf> | list-backups | log [n] (read); "
                  "install-conf <workfile> <x.conf> | restore-conf <x.conf> (admin mode)")


# ---------------------------------------------------------------- read-only rules

VIRSH_READ = {
    "list", "dominfo", "domstate", "domifaddr", "domiflist", "domifstat", "vcpucount", "vcpuinfo",
    "dommemstat", "domblklist", "domblkinfo", "domblkstat", "domjobinfo", "version", "nodeinfo",
    "nodememstats", "nodecpustats", "capabilities", "domcapabilities", "net-list", "net-info",
    "net-dumpxml", "pool-list", "pool-info", "vol-list", "vol-info", "snapshot-list",
    "checkpoint-list", "dumpxml", "uri", "hostname", "sysinfo", "nwfilter-list", "iface-list",
    "domdisplay", "guestinfo", "domfsinfo",
}


def check_rule(argv: list[str]) -> Plan:
    cmd, args = argv[0], argv[1:]

    if cmd in {"lscpu", "free", "uptime", "uname", "lsblk", "df", "findmnt", "nproc",
               "getenforce", "sestatus", "lspci", "lsmod", "date", "whoami", "id", "hostname"}:
        if cmd == "hostname" and args:
            raise Refused("hostname: changing the hostname is not allowed")
        return Plan(argv, sudo=False)

    if cmd in {"cat", "head", "tail"}:
        files = [a for a in args if not a.startswith("-")]
        opts = [a for a in args if a.startswith("-")]
        if not files or any(o not in {"-n"} and not re.fullmatch(r"-n?\d+", o) for o in opts):
            raise Refused(f"{cmd}: only plain file reads (optionally -n N) are allowed")
        for f in files:
            if re.fullmatch(r"\d+", f):
                continue
            if f not in READABLE_FILES and not under(f, ("/var/log/claude-ops/", str(WORK_DIR) + "/")):
                raise Refused(f"{cmd}: {f} is not in the readable-file list")
        return Plan(argv, sudo=False)

    if cmd == "ip":
        allowed = [["-br", "addr"], ["-br", "a"], ["-br", "link"], ["addr"], ["a"], ["route"],
                   ["r"], ["-6", "route"], ["link"], ["neigh"], ["-s", "link"], ["-br", "addr", "show"],
                   ["addr", "show"], ["route", "show"], ["link", "show"]]
        if args in allowed:
            return Plan(argv, sudo=False)
        if len(args) == 3 and args[:2] in (["addr", "show"], ["link", "show"]) and SAFE_NAME.match(args[2]):
            return Plan(argv, sudo=False)
        raise Refused("ip: only show commands (ip -br addr, ip route, ip link) are allowed")

    if cmd == "nmcli":
        if args in (["device", "status"], ["dev", "status"], ["connection", "show"], ["con", "show"],
                    ["general", "status"], ["-t", "device", "status"]):
            return Plan(argv, sudo=False)
        raise Refused("nmcli: only `nmcli device status` / `nmcli connection show` are allowed. "
                      "Network changes must be done from the IPMI console.")

    if cmd == "virsh":
        sub = [a for a in args if not a.startswith("-")]
        if not sub or sub[0] not in VIRSH_READ:
            raise Refused(f"virsh: read-only subcommands only: {', '.join(sorted(VIRSH_READ))}")
        if any(a.startswith("--security-info") for a in args):
            raise Refused("virsh: --security-info is not allowed")
        clean = [a for a in args if a not in ("-r", "--readonly")]
        if "-c" in clean:
            raise Refused("virsh: the connection is fixed to qemu:///system (read-only)")
        return Plan(["virsh", "-r", "-c", "qemu:///system", *clean], sudo=False)

    if cmd == "virt-host-validate":
        return Plan(argv, sudo=False)

    if cmd == "systemctl":
        if args and args[0] in {"status", "is-active", "is-enabled", "is-failed", "show"}:
            units = args[1:]
            if not units or not all(READ_UNIT.match(u) or u in {"--no-pager", "-l"} for u in units):
                raise Refused("systemctl: give unit names like libvirtd.service")
            return Plan(["systemctl", *args, "--no-pager"] if "--no-pager" not in args else argv, sudo=False)
        if args[:1] == ["list-units"] or args[:1] == ["list-unit-files"] or args[:1] == ["--failed"]:
            return Plan(["systemctl", *args, "--no-pager"], sudo=False)
        raise Refused("systemctl: only status / is-active / is-enabled / list-units are read-only")

    if cmd == "journalctl":
        if "-u" not in args:
            raise Refused("journalctl: use `journalctl -u <unit> -n <lines>`")
        u = args[args.index("-u") + 1] if args.index("-u") + 1 < len(args) else ""
        n = args[args.index("-n") + 1] if "-n" in args and args.index("-n") + 1 < len(args) else "100"
        if not READ_UNIT.match(u) or not n.isdigit() or int(n) > 1000:
            raise Refused("journalctl: unit name required and at most -n 1000")
        return Plan(["journalctl", "-u", u, "-n", n, "--no-pager"], sudo=True)

    if cmd == "qemu-img":
        if args[:1] != ["info"] or len(args) < 2:
            raise Refused("qemu-img: only `qemu-img info <file>` is read-only")
        need_path(args[-1], IMAGE_DIRS, "image")
        return Plan(argv, sudo=True)

    if cmd == "dnf":
        if args[:2] == ["list", "installed"] or args in (["check-update"], ["repolist"]) \
                or (args[:1] == ["info"] and len(args) == 2 and PKG_NAME.match(args[1])):
            return Plan(argv, sudo=False)
        raise Refused("dnf: read-only is list installed / check-update / repolist / info <pkg>")

    if cmd == "podman":
        if args in (["ps"], ["ps", "-a"], ["ps", "--all"], ["images"], ["version"]):
            return Plan(argv, sudo=True)
        raise Refused("podman: only ps / images / version")

    if cmd == "firewall-cmd":
        if args in (["--list-all"], ["--state"], ["--get-active-zones"], ["--list-all-zones"]):
            return Plan(argv, sudo=True)
        raise Refused("firewall-cmd: only --list-all / --state / --get-active-zones")

    if cmd == "ss":
        if args in (["-tln"], ["-uln"], ["-tlnp"], ["-s"]):
            return Plan(argv, sudo=False)
        raise Refused("ss: only -tln / -uln / -s")

    if cmd == "asterisk":
        return asterisk_cli(args, admin=False)

    if cmd == "claude-ops-asterisk":
        return asterisk_helper(args, admin=False)

    raise Refused(f"{cmd!r} is not on the read-only allowlist")


# ---------------------------------------------------------------- admin rules

VIRSH_SAFE_WRITE = {
    "start", "shutdown", "reboot", "setvcpus", "update-memory-device", "blockresize",
    "domfsfreeze", "domfsthaw", "backup-begin", "domjobabort", "checkpoint-create-as",
    "define", "autostart", "net-start", "net-autostart", "pool-define-as", "pool-build",
    "pool-start", "pool-autostart", "pool-refresh", "suspend", "resume", "set-user-password",
    "domsetlaunchsecstate", "attach-device", "setmem", "setmaxmem",
}
VIRSH_TEST_ONLY = {"destroy", "undefine", "reset", "snapshot-delete", "checkpoint-delete",
                   "detach-device", "vol-delete"}
NETWORK_BLOCK = {"nmcli", "ip", "ifup", "ifdown", "nmtui", "route", "brctl", "ethtool"}


def domain_arg(args: list[str]) -> str | None:
    pos = [a for a in args[1:] if not a.startswith("-")]
    return pos[0] if pos else None


def admin_rule(argv: list[str]) -> Plan:
    cmd, args = argv[0], argv[1:]

    if cmd != "virsh" and _is_read(argv):          # read-only commands also work via run_admin
        return check_rule(argv)

    if cmd == "asterisk":
        return asterisk_cli(args, admin=True)

    if cmd == "claude-ops-asterisk":
        return asterisk_helper(args, admin=True)

    if cmd in NETWORK_BLOCK:
        raise Refused(f"{cmd}: network changes are never run through this server — "
                      "do them from the IPMI console")

    if cmd == "dnf":
        if args[:2] == ["install", "-y"] or args[:2] == ["-y", "install"]:
            pkgs = args[2:]
            if pkgs and all(PKG_NAME.match(p) for p in pkgs):
                return Plan(argv, sudo=True)
        if args[:2] in (["update", "-y"], ["-y", "update"]) and all(PKG_NAME.match(p) for p in args[2:]):
            return Plan(argv, sudo=True)
        raise Refused("dnf: `dnf install -y <pkgs>` or `dnf update -y [pkgs]` only (no remove)")

    if cmd == "systemctl":
        if args and args[0] in {"start", "stop", "restart", "enable", "disable", "reload"}:
            units = [a for a in args[1:] if a != "--now"]
            if units and all(UNIT_NAME.match(u) for u in units):
                return Plan(argv, sudo=True)
            raise Refused("systemctl: only libvirt (virt*d / libvirtd), cloudflared and "
                          "qemu-guest-agent units can be changed")
        if args[:1] == ["daemon-reload"]:
            return Plan(argv, sudo=True)
        raise Refused("systemctl: start/stop/restart/enable/disable/reload/daemon-reload only")

    if cmd == "virsh":
        clean = [a for a in args if a not in ("-c", "qemu:///system")]
        sub = [a for a in clean if not a.startswith("-")]
        if not sub:
            raise Refused("virsh: subcommand required")
        name = sub[0]
        if name in VIRSH_READ:
            return Plan(["virsh", "-c", "qemu:///system", *clean], sudo=True)
        if name in VIRSH_TEST_ONLY:
            dom = domain_arg(sub)
            if not dom or not TEST_VM.match(dom):
                raise Refused(f"virsh {name}: only allowed on test VMs named vm-test*")
            return Plan(["virsh", "-c", "qemu:///system", *clean], sudo=True)
        if name in VIRSH_SAFE_WRITE:
            for a in sub[1:]:
                if a.startswith("/") and not under(a, IMAGE_DIRS + (str(WORK_DIR) + "/",)):
                    raise Refused(f"virsh {name}: file {a} must be in {IMAGE_DIRS} or {WORK_DIR}")
            return Plan(["virsh", "-c", "qemu:///system", *clean], sudo=True)
        raise Refused(f"virsh {name}: not on the admin allowlist")

    if cmd == "virt-install":
        for i, a in enumerate(args):
            if a in {"--disk", "--cdrom", "--location"} and i + 1 < len(args):
                path = args[i + 1].split(",")[0].removeprefix("path=")
                if path.startswith("/"):
                    need_path(path, IMAGE_DIRS, "disk")
            if a == "--name" and i + 1 < len(args) and not SAFE_NAME.match(args[i + 1]):
                raise Refused("virt-install: invalid --name")
        return Plan(argv, sudo=True)

    if cmd == "virt-customize":
        if "-a" not in args:
            raise Refused("virt-customize: -a <image> required")
        need_path(args[args.index("-a") + 1], (TEMPLATE_DIR,), "image")
        return Plan(argv, sudo=True)

    if cmd == "qemu-img":
        if not args or args[0] not in {"create", "info", "convert", "resize", "check", "snapshot"}:
            raise Refused("qemu-img: create / info / convert / resize / check only")
        for a in args[1:]:
            if a.startswith("/"):
                need_path(a, IMAGE_DIRS, "image")
        return Plan(argv, sudo=True)

    if cmd == "mkdir":
        paths = [a for a in args if not a.startswith("-")]
        if not paths or any(a not in {"-p"} for a in args if a.startswith("-")):
            raise Refused("mkdir: `mkdir -p <dir>` only")
        for p in paths:
            need_path(p, IMAGE_DIRS + ("/opt/claude-ops/",), "directory")
        return Plan(argv, sudo=True)

    if cmd == "curl":
        if "-o" not in args:
            raise Refused("curl: download with -o <file> into the templates directory only")
        out = args[args.index("-o") + 1]
        need_path(out, (TEMPLATE_DIR,), "download target")
        urls = [a for a in args if a.startswith("http")]
        if len(urls) != 1 or not urls[0].startswith("https://"):
            raise Refused("curl: exactly one https:// URL")
        flags = [a for a in args if a.startswith("-") and a != "-o"]
        if any(f not in {"-f", "-L", "-fL", "-Lf", "-s", "-S", "-sS", "-fsSL", "--fail", "--location"}
               for f in flags):
            raise Refused("curl: only -f -L -s -S flags allowed")
        return Plan(argv, sudo=True)

    if cmd == "rm":
        paths = [a for a in args if not a.startswith("-")]
        if any(a not in {"-f"} for a in args if a.startswith("-")):
            raise Refused("rm: only `rm [-f] <file>` (no -r)")
        for p in paths:
            ok = under(p, ("/backup/staging/", str(WORK_DIR) + "/")) or \
                 (under(p, ("/var/lib/libvirt/images/",)) and os.path.basename(p).startswith("vm-test"))
            if not ok:
                raise Refused(f"rm: {p} — only files in /backup/staging, the work dir, or vm-test* disks")
        return Plan(argv, sudo=True)

    if cmd == "virt-host-validate":
        return Plan(argv, sudo=True)

    if cmd in {"cloud-localds"}:
        for a in args:
            if a.startswith("/"):
                need_path(a, IMAGE_DIRS + (str(WORK_DIR) + "/",), "file")
        return Plan(argv, sudo=True)

    raise Refused(f"{cmd!r} is not on the admin allowlist")


def _is_read(argv: list[str]) -> bool:
    try:
        check_rule(argv)
        return True
    except Refused:
        return False


# ---------------------------------------------------------------- execution

def execute(plan: Plan, timeout: int) -> dict:
    argv = (["sudo", "-n", "--"] if plan.sudo and USE_SUDO else []) + plan.argv
    if DRY_RUN:
        return {"exit_code": 0, "stdout": "DRY RUN: " + shlex.join(argv), "stderr": "", "duration_s": 0}
    start = time.time()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           cwd=str(WORK_DIR) if WORK_DIR.exists() else "/",
                           env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                                "LANG": "C.UTF-8", "LIBVIRT_DEFAULT_URI": "qemu:///system"})
        return {"exit_code": p.returncode, "stdout": clip(p.stdout), "stderr": clip(p.stderr),
                "duration_s": round(time.time() - start, 2)}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"timed out after {timeout}s",
                "duration_s": timeout}
    except FileNotFoundError:
        return {"exit_code": 127, "stdout": "", "stderr": f"{plan.argv[0]}: command not found",
                "duration_s": 0}


def format_result(cmd: str, res: dict) -> str:
    out = [f"$ {cmd}", f"exit code: {res['exit_code']}  ({res['duration_s']}s)"]
    if res["stdout"]:
        out += ["--- stdout ---", res["stdout"].rstrip()]
    if res["stderr"]:
        out += ["--- stderr ---", res["stderr"].rstrip()]
    return "\n".join(out)


# ---------------------------------------------------------------- MCP server

server = MCPServer(
    name="linux-ops",
    instructions=(
        "Tools for checking and setting up this KVM host. Use run_check for read-only "
        "commands. run_admin only works while the owner has switched admin mode on "
        "(`sudo /usr/local/sbin/claude-ops-admin 2h` on the host); always give a reason. Commands run without a "
        "shell: one plain command per call, no pipes or redirects. Network changes and destroying "
        "non-test VMs are refused by design. Files for configs/XML go in /opt/claude-ops/work via "
        "write_file. On Asterisk hosts: read configs with `claude-ops-asterisk show-conf pjsip.conf` "
        "(secrets come back as __KEEP_SECRET__; leave that marker in place when editing), write the "
        "edited file with write_file, then run_admin `claude-ops-asterisk install-conf <file> "
        "pjsip.conf` and `asterisk -rx \"pjsip reload\"`."
    ),
)


@server.tool()
def host_status() -> str:
    """Show this server's mode: whether admin mode is on and until when, plus allowed areas."""
    until = admin_mode_until()
    state = (f"ON until {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(until))}"
             if until > time.time() else "OFF (owner runs `sudo /usr/local/sbin/claude-ops-admin 2h` to enable)")
    return "\n".join([
        f"admin mode: {state}",
        f"work dir (write_file/read_file): {WORK_DIR}",
        f"image dirs: {', '.join(IMAGE_DIRS)}",
        "read-only commands: lscpu free uptime uname lsblk df findmnt nproc lspci lsmod sestatus, "
        "cat/head/tail of system info files, ip (show), nmcli device/connection show, virsh "
        "(read-only), virt-host-validate, systemctl status, journalctl -u, qemu-img info, "
        "dnf list/check-update/info, podman ps, firewall-cmd --list-all, ss -tln",
        "admin commands: dnf install/update, systemctl (libvirt/cloudflared units), virsh "
        "(destroy/undefine only on vm-test*), virt-install, virt-customize (templates), qemu-img, "
        "mkdir -p, curl -o templates, rm (staging/work/vm-test* only), cloud-localds",
        "asterisk (if installed): read: asterisk -rx \"pjsip show …|core show …|dialplan show …\", "
        "claude-ops-asterisk show-conf <x.conf> (secrets masked) | list-backups | log [n]; "
        "admin: asterisk -rx \"pjsip reload|dialplan reload|pjsip qualify <aor>|channel originate …\", "
        "claude-ops-asterisk install-conf <workfile> <x.conf> (auto backup; write "
        "`password = __KEEP_SECRET__` to keep the live secret) | restore-conf <x.conf>",
        "never: network changes, shells, deleting customer VMs",
    ])


@server.tool()
def run_check(command: str) -> str:
    """Run one read-only command on the KVM host (e.g. `lsblk`, `ip -br addr`, `virsh list --all`,
    `cat /etc/os-release`). No shell: no pipes, redirects or && chains."""
    try:
        plan = check_rule(parse(command))
    except Refused as e:
        audit({"tool": "run_check", "command": command, "result": "refused", "reason": str(e)})
        return f"REFUSED: {e}"
    res = execute(plan, CHECK_TIMEOUT)
    audit({"tool": "run_check", "command": command, "argv": plan.argv, "result": "ran",
           "exit_code": res["exit_code"], "duration_s": res["duration_s"]})
    return format_result(command, res)


@server.tool()
def run_admin(command: str, reason: str) -> str:
    """Run one setup/admin command with sudo (e.g. `dnf install -y qemu-kvm libvirt`,
    `virsh start vm-test1`). Only works while admin mode is ON. `reason` is required and logged."""
    if not reason or len(reason.strip()) < 5:
        return "REFUSED: give a short reason (it is written to the audit log)"
    if not admin_on():
        audit({"tool": "run_admin", "command": command, "reason": reason, "result": "refused",
               "why": "admin mode off"})
        return ("REFUSED: admin mode is OFF. Ask the owner to run `sudo /usr/local/sbin/claude-ops-admin 2h` "
                "on the host, then retry.")
    try:
        plan = admin_rule(parse(command))
    except Refused as e:
        audit({"tool": "run_admin", "command": command, "reason": reason, "result": "refused",
               "why": str(e)})
        return f"REFUSED: {e}"
    res = execute(plan, ADMIN_TIMEOUT)
    audit({"tool": "run_admin", "command": command, "reason": reason, "argv": plan.argv,
           "result": "ran", "exit_code": res["exit_code"], "duration_s": res["duration_s"]})
    return format_result(command, res)


AUDIT_SECTIONS = {"logins", "users", "ssh", "persistence", "processes", "network", "integrity", "files", "all"}


@server.tool()
def security_audit(section: str) -> str:
    """Read-only security audit (runs a fixed root-owned script; no admin mode needed).
    section: logins | users | ssh | persistence | processes | network | integrity | files | all
    (`integrity` runs rpm -Va and can take a few minutes; `all` excludes it)."""
    if section not in AUDIT_SECTIONS:
        return f"REFUSED: section must be one of {', '.join(sorted(AUDIT_SECTIONS))}"
    plan = Plan(["/usr/local/sbin/claude-ops-audit", section], sudo=True)
    res = execute(plan, ADMIN_TIMEOUT if section == "integrity" else 300)
    audit({"tool": "security_audit", "section": section, "result": "ran", "exit_code": res["exit_code"],
           "duration_s": res["duration_s"]})
    return format_result(f"claude-ops-audit {section}", res)


@server.tool()
def write_file(name: str, content: str) -> str:
    """Write a text file (VM XML, cloud-init user-data, backup XML…) into the work directory.
    `name` is a plain file name like `backup.xml` or `vm-test1/user-data`."""
    target = (WORK_DIR / name)
    if not under(str(target), (str(WORK_DIR) + "/",)) or len(content) > 200_000:
        audit({"tool": "write_file", "name": name, "result": "refused"})
        return f"REFUSED: files must stay inside {WORK_DIR} and be under 200 KB"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    audit({"tool": "write_file", "name": name, "bytes": len(content), "result": "written"})
    return f"written {target} ({len(content)} bytes)"


@server.tool()
def read_file(name: str) -> str:
    """Read a file from the work directory (or the audit log: `audit.jsonl`)."""
    target = AUDIT_LOG if name == "audit.jsonl" else (WORK_DIR / name)
    if target != AUDIT_LOG and not under(str(target), (str(WORK_DIR) + "/",)):
        return f"REFUSED: only files inside {WORK_DIR}"
    try:
        return clip(target.read_text())
    except OSError as e:
        return f"error: {e}"


@server.tool()
def recent_audit(lines: int = 30) -> str:
    """Show the last N audit-log entries (what was run, refused, by which tool)."""
    try:
        data = AUDIT_LOG.read_text().splitlines()
    except OSError:
        return "audit log is empty"
    return "\n".join(data[-max(1, min(lines, 500)):])


def build_app():
    if len(TOKEN) < 32:
        raise SystemExit("OPS_MCP_TOKEN must be set to a random string of at least 32 characters")
    hosts = ["127.0.0.1:*", "localhost:*"] + ([PUBLIC_HOST] if PUBLIC_HOST else [])
    return server.streamable_http_app(
        streamable_http_path=f"/{TOKEN}/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[]),
        host="127.0.0.1",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(build_app(), host="127.0.0.1", port=PORT, log_level="warning",
                timeout_graceful_shutdown=2)
