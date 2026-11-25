#!/usr/bin/env python3
"""OpenTofu `import {}` blocks and tfvars entries for Proxmox guests OpenTofu doesn't manage yet (GitHub issue #149).

    tofu_import_plan.py [--site NAME] [--guest NAME|VMID ...] [--write]

Reads the site's discovery/proxmox.json (proxmox_inventory.py --details, 0.61.0 or later) and its environment's
homelab.auto.tfvars (tofu/environments/<env>). For each guest that has no entry there yet it prints an import block
and a `vms` / `containers` entry for the template's modules, with what Proxmox has now: node, cores, memory, swap,
disks (size, datastore, extra_disks), bridge, VLAN tag, MAC address, static address and gateway, DNS (LXC), tags,
cpu_type, on_boot, protection, description, started, unprivileged and nesting, and what an older guest has that a
cloned one doesn't (0.62.0: sockets, NUMA, CPU flags, ballooning, disk cache/ssd/iothread/discard/backup, start
order, OS type, machine, no cloud-init drive or serial port, a CD-ROM, NIC firewall/MTU/queues, LXC features, mount
points and console; 0.63.0: further NICs as extra_nics). Above an entry a comment names what the first plan will
still change (the few settings the modules don't carry, e.g. disk I/O limits). A guest the modules can't represent
without a rebuild or lost hardware (passthrough, a root disk other than scsi0, UEFI, NICs or mount points numbered
with a gap, VLAN trunks, ...) gets no entry: it stays unmanaged, with a line for docs/decisions.md.

Read-only by default (stdout). --write creates or extends imports.tf in the environment and adds the entries inside
the `vms` / `containers` maps of homelab.auto.tfvars; it never changes an existing entry or import block. Then the
normal loop: tofu plan, review (1 to import per guest, no replace), the user's yes, apply, remove the import blocks.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

CONFIG_VERSION = 3          # proxmox_inventory.CONFIG_VERSION that carries cpu, protection, swap, DNS, hostname (2)
#                             and an LXC's console settings (3)
LXC_OS_TYPES = {"alpine", "archlinux", "centos", "debian", "devuan", "fedora", "gentoo", "nixos", "opensuse",
                "ubuntu", "unmanaged"}   # bpg operating_system.type
VM_OS_TYPES = {"l24", "l26", "other", "solaris", "w2k", "w2k3", "w2k8", "win7", "win8", "win10", "win11", "wvista",
               "wxp"}
DISK_FIELDS = ("discard", "iothread", "ssd", "cache", "backup")   # extra_disks fields of 0.62.0 (with disk_cache)
KEY_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$")   # a map key the modules use as name
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
VM_NIC_MODELS = {"virtio", "e1000", "e1000e", "rtl8139", "vmxnet3"}   # bpg network_device.model
VM_EXTRA_RE =re.compile(r"^(scsi([1-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5])$")
DISK_RE = re.compile(r"^(scsi|virtio|sata|ide)\d+$")
NO_TEMPLATE_FILE = "local:vztmpl/imported.tar.zst"   # placeholder: ignored after creation


# --- HCL text (tfvars, variables.tf) ---------------------------------------------------------------------------

def mask(text: str) -> str:
    """text with string contents and comments blanked (same length, newlines kept), so braces and `=` found in the
    result are structure."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] not in '"\n':
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = "_"
            i = j + 1
        elif c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out[i:j] = " " * (j - i)
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def closing(masked: str, open_at: int) -> int:
    """Index of the bracket closing the one at open_at (-1 if unbalanced)."""
    depth = 0
    for i in range(open_at, len(masked)):
        if masked[i] in "{[(":
            depth += 1
        elif masked[i] in "}])":
            depth -= 1
            if depth == 0:
                return i
    return -1


ASSIGN_RE = re.compile(r'("[^"\n]*"|[A-Za-z_][\w-]*)[ \t]*=(?!=)[ \t]*')


def assignments(text: str, masked: str, start: int, end: int) -> list[tuple[str, int, int]]:
    """[(name, value start, value end)] of the attributes directly inside text[start:end]: a {…} or […] value runs
    to its closing bracket (included), any other to the end of its line (a trailing comment left out)."""
    out, depth, i, line_start = [], 0, start, True
    while i < end:
        c = masked[i]
        if c == "\n":
            line_start = True
        elif c not in " \t\r":
            m = ASSIGN_RE.match(masked, i, end) if line_start and depth == 0 else None
            line_start = False
            if m:
                v = e = m.end()
                inner = 0     # the value ends at a newline outside its brackets, or at the enclosing block's bracket
                while e < end and not (masked[e] == "\n" and inner == 0):
                    if masked[e] in "{[(":
                        inner += 1
                    elif masked[e] in "}])":
                        if inner == 0:
                            break
                        inner -= 1
                    e += 1
                e = v + len(masked[v:e].rstrip())
                out.append((text[m.start(1):m.end(1)].strip('"'), v, e))
                i = e
                continue
            if c in "{[(":
                depth += 1
            elif c in "}])":
                depth -= 1
        i += 1
    return out


def top(text: str) -> tuple[str, dict[str, tuple[int, int]]]:
    masked = mask(text)
    return masked, {k: (s, e) for k, s, e in assignments(text, masked, 0, len(text))}


def read_tfvars(text: str) -> dict:
    """What the import plan needs from homelab.auto.tfvars: the VMIDs and keys it has, and the defaults."""
    masked, blocks = top(text)
    ids = {int(m.group(1)) for m in re.finditer(r"(?<![\w])vm_id[ \t]*=[ \t]*(\d+)", masked)}
    keys = {}
    for kind in ("vms", "containers"):
        s, e = blocks.get(kind, (0, 0))
        keys[kind] = {k for k, _, _ in assignments(text, masked, s + 1, e - 1)} if masked[s:s + 1] == "{" else set()
    d = {}
    s, e = blocks.get("defaults", (0, 0))
    if masked[s:s + 1] == "{":
        for k, vs, ve in assignments(text, masked, s + 1, e - 1):
            raw = text[vs:ve]
            try:
                d[k] = json.loads(raw) if raw.startswith(('"', "[")) else raw
            except ValueError:
                d[k] = raw
    return {"ids": ids, "keys": keys, "defaults": d, "has_defaults": "defaults" in blocks}


def entry_attributes(variables_tf: str) -> dict[str, set[str]]:
    """{vms|containers: attribute names} of the environment's variables.tf: an older repo lacks the newer ones."""
    masked = mask(variables_tf)
    out = {}
    for kind in ("vms", "containers"):
        m = re.search(r'variable[ \t]+"' + kind + r'"[ \t]*\{', variables_tf)
        if not m:
            continue
        o = masked.find("object(", m.end())
        b = masked.find("{", o) if o >= 0 else -1
        e = closing(masked, b) if b >= 0 else -1
        if e > b >= 0:
            out[kind] = {k for k, _, _ in assignments(variables_tf, masked, b + 1, e)}
    return out


# --- Proxmox config ---------------------------------------------------------------------------------------------

def options(value) -> tuple[str, dict[str, str]]:
    """'local-zfs:vm-101-disk-0,size=32G,ssd=1' → ('local-zfs:vm-101-disk-0', {size: 32G, ssd: 1})."""
    first, opts = "", {}
    for i, part in enumerate(str(value or "").split(",")):
        if "=" in part:
            k, v = part.split("=", 1)
            opts[k.strip()] = v.strip()
        elif i == 0:
            first = part.strip()
    return first, opts


def gib(size: str | None) -> float | None:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGT]?)", str(size or "").strip())
    if not m:
        return None
    return float(m.group(1)) * {"K": 1 / 1024**2, "M": 1 / 1024, "G": 1, "T": 1024, "": 1 / 1024**3}[m.group(2)]


def whole(x: float | None) -> int | None:
    return int(round(x)) if x is not None and abs(x - round(x)) < 1e-9 and x >= 1 else None


def flag(opts: dict, key: str) -> bool:
    return str(opts.get(key, "0")) in ("1", "on", "true")


def num(value, default: int) -> int:
    m = re.search(r"(?:^|current=)(\d+)", str(value or ""))
    return int(m.group(1)) if m else default


def tags(g: dict) -> list[str]:
    return sorted({t for t in re.split(r"[;, ]+", str(g.get("tags") or "")) if t and t != "tofu"})


def description(conf: dict) -> tuple[str | None, str | None]:
    """(description, note): the snapshot keeps the first 300 characters, marked untrusted."""
    d = conf.get("description")
    if d is None:
        return None, None
    d = str(d)
    d = d[len("[untrusted] "):] if d.startswith("[untrusted] ") else d
    if d.endswith("…") and len(d) >= 301:
        return None, "description: longer than the snapshot keeps; copy it from Proxmox or the plan replaces it"
    return d, None


def nets(conf: dict) -> list[str]:
    return sorted((k for k in conf if re.fullmatch(r"net\d+", k)), key=lambda k: int(k[3:]))


class Entry:
    def __init__(self, g: dict, kind: str, key: str):
        self.g, self.kind, self.key = g, kind, key
        self.attrs: list[tuple[str, object]] = []
        self.notes: list[str] = []       # what the first plan will still change
        self.blockers: list[str] = []    # why it can't be an entry

    def set(self, name: str, value):
        self.attrs.append((name, value))


def common(e: Entry, conf: dict):
    g = e.g
    desc, note = description(conf)
    if desc is not None:
        e.set("description", desc)
    if note:
        e.notes.append(note)
    t = tags(g)
    if t:
        e.set("tags", t)
    if g.get("status") != "running":
        e.set("started", False)
    if not flag(conf, "onboot"):
        e.set("on_boot", False)
    if flag(conf, "protection"):
        e.set("protection", True)
    if conf.get("startup"):
        names, start, parts = {"order": "order", "up": "up_delay", "down": "down_delay"}, {}, \
            str(conf["startup"]).split(",")
        for part in parts:   # [order=]N,up=N,down=N
            k, _, v = part.strip().rpartition("=")
            if k in ("", "order", "up", "down") and re.fullmatch(r"\d+", v):
                start[names[k or "order"]] = int(v)
        if len(start) == len(parts):
            e.set("startup", start)
        else:
            e.notes.append(f"startup {conf['startup']}: not order, up and down in seconds, the plan removes it")


def network(e: Entry, conf: dict, ctx: dict, nic: str, ip: str | None, gw: str | None, ip6: str | None,
            gw6: str | None = None, pos: int = 0, gw_elsewhere: bool = False):
    """bridge, vlan_id, mac_address, firewall, mtu, ipv4_* and ipv6_* of the NIC at position pos: the first one's
    as the entry's attributes, a later one's as an extra_nics item (returned). An extra NIC's gateways are its own
    (no defaults); a VM's has no cloud-init settings unless ipconfigN has an address (dhcp included). The first NIC
    without a gateway gets ipv4_gateway = "" (none) when another NIC has one (gw_elsewhere), else the default."""
    _, o = options(conf.get(nic))
    d, first, out = ctx["defaults"], pos == 0, {}
    if e.kind == "containers" and not first and o.get("name") != f"eth{pos}":
        out["name"] = o.get("name") or ""
    bridge = o.get("bridge")
    if bridge and bridge != d.get("bridge"):
        out["bridge"] = bridge
    if o.get("tag"):
        out["vlan_id"] = int(o["tag"])
    if o.get("trunks"):
        e.blockers.append(f"{nic} carries VLAN trunks ({o['trunks']}): the modules set one tag")
    mac = o.get("hwaddr") or next((v for k, v in o.items() if MAC_RE.match(v or "")), None)
    if mac:
        out["mac_address"] = mac
    if e.kind == "vms" and not first:
        model = next((k for k, v in o.items() if MAC_RE.match(v)), options(conf.get(nic))[0])
        if model not in VM_NIC_MODELS:
            e.blockers.append(f"{nic} model {model or 'unknown'}: not one the module knows")
        elif model != "virtio":
            out["model"] = model
    if flag(o, "firewall"):
        out["firewall"] = True
    for k in ("mtu", "queues") if e.kind == "vms" else ("mtu",):
        if re.fullmatch(r"\d+", o.get(k) or "") and int(o[k]) > 0:
            out[k] = int(o[k])
    if e.kind == "vms" and not first and flag(o, "link_down"):
        out["disconnected"] = True
    for k in ("rate",) + (("link_down",) if first or e.kind == "containers" else ()) + (
            ("queues",) if e.kind == "containers" else ()):
        if o.get(k) not in (None, "", "0"):
            e.notes.append(f"{nic} {k}={o[k]}: the modules don't set it, the plan removes it")
    if ip and ip not in ("dhcp", "manual"):
        out["ipv4_address"] = ip
        if gw and (gw != d.get("ipv4_gateway") or not first):
            out["ipv4_gateway"] = gw
        elif not gw and d.get("ipv4_gateway") and first and gw_elsewhere:
            out["ipv4_gateway"] = ""   # the default route is on another NIC: none here, not the default gateway
        elif not gw and d.get("ipv4_gateway") and first:
            e.notes.append("no gateway in Proxmox: the entry gets defaults.ipv4_gateway")
    elif ip == "dhcp" and e.kind == "vms" and not first:   # an extra VM NIC has no ipconfigN by default
        out["ipv4_address"] = "dhcp"
    elif ip == "manual" or (not ip and e.kind == "containers" and not first):
        e.notes.append(f"{nic} {'ip=manual' if ip else 'has no IPv4 setting'}: the modules set dhcp")
    if ip6 == "manual":
        e.notes.append(f"{nic} ip6=manual: the modules set no IPv6, the plan removes it")
    elif ip6:   # "auto" (SLAAC), "dhcp" or address/prefix, as the modules take it
        out["ipv6_address"] = ip6
        if ip6 not in ("auto", "dhcp"):
            if gw6 and (gw6 != d.get("ipv6_gateway") or not first):
                out["ipv6_gateway"] = gw6
            elif not gw6 and d.get("ipv6_gateway") and first:
                e.notes.append("no IPv6 gateway in Proxmox: the entry gets defaults.ipv6_gateway")
    if first:
        for k, v in out.items():
            e.set(k, v)
    return out


def nic_slots(e: Entry, conf: dict, what: str) -> list[str]:
    """The guest's netN keys; a blocker when they are not net0, net1, ... without a gap (the provider numbers the
    modules' NICs by position)."""
    n = nets(conf)
    if not n:
        e.blockers.append(f"no {what}: the module has at least one")
    elif n != [f"net{i}" for i in range(len(n))]:
        e.blockers.append(f"{what}s {', '.join(n)} have a gap: the module numbers them net0, net1, ... in list "
                          "order")
    return n


def vm_entry(g: dict, ctx: dict) -> Entry:
    conf, d = g.get("config") or {}, ctx["defaults"]
    e = Entry(g, "vms", g.get("name") or "")
    e.set("vm_id", g["vmid"])
    e.set("template_vm_id", g["vmid"])   # imported, not cloned: the module ignores `clone` after creation
    if g.get("node") and g["node"] != d.get("node"):
        e.set("node", g["node"])
    e.set("cores", num(conf.get("cores"), 1))
    e.set("memory_mib", num(conf.get("memory"), 512))
    sockets = num(conf.get("sockets"), 1)
    if sockets != 1:
        e.set("sockets", sockets)
    cputype, copts = options(conf.get("cpu"))
    cputype = copts.get("cputype", cputype) or "kvm64"
    e.set("cpu_type", cputype)
    if copts.get("flags"):
        e.set("cpu_flags", [f for f in copts["flags"].split(";") if f])
    if flag(conf, "numa"):
        e.set("numa", True)
    if re.fullmatch(r"\d+", str(conf.get("balloon") or "")) and int(conf["balloon"]) > 0:
        e.set("memory_floating_mib", int(conf["balloon"]))
    if str(conf.get("tablet", "1")) == "0":
        e.set("tablet_device", False)
    agent_on, aopts = options(conf.get("agent"))
    if agent_on != "1" and not flag(aopts, "enabled"):
        e.notes.append("guest agent off: the module turns it on")
    if flag(aopts, "fstrim_cloned_disks"):
        e.set("agent_trim", True)
    for k in ("type", "freeze-fs-on-backup"):
        if k in aopts:
            e.notes.append(f"agent {k}={aopts[k]}: the module doesn't set it")
    if (conf.get("scsihw") or "lsi") != "virtio-scsi-single":
        e.set("scsi_hardware", conf.get("scsihw") or "lsi")
    ostype = str(conf.get("ostype") or "other")
    if ostype not in VM_OS_TYPES:
        e.blockers.append(f"OS type {ostype}: not one the provider knows")
    elif ostype != "l26":
        e.set("os_type", ostype)
    if conf.get("bios") == "ovmf" or any(k.startswith("efidisk") for k in conf):
        e.blockers.append("UEFI (bios ovmf, EFI disk): the module has no EFI disk")
    if any(k.startswith("tpmstate") for k in conf):
        e.blockers.append("TPM state disk: the module has none")
    if conf.get("machine"):
        e.set("machine", str(conf["machine"]))
    passthrough = sorted(k for k in conf if re.fullmatch(r"(hostpci|usb)\d+", k))
    if passthrough:
        e.blockers.append("passthrough (" + ", ".join(passthrough) + "): the module has none")

    # disks: scsi0 is the root disk, scsi1-30 / virtio / sata are extra_disks, IDE holds CD-ROM or cloud-init
    datastore = d.get("datastore")
    if "scsi0" not in conf or "media=cdrom" in str(conf.get("scsi0")):
        first = next((k for k in sorted(conf, key=disk_order) if DISK_RE.match(k)
                      and "media=cdrom" not in str(conf[k])), None)
        e.blockers.append(f"root disk {first or 'none'}: the module's root disk is scsi0")
    else:
        vol, o = options(conf["scsi0"])
        store = vol.split(":", 1)[0]
        if store != datastore or ctx["node_datastores"] or not datastore:
            e.set("datastore", store)
        datastore = store
        size = whole(gib(o.get("size")))
        if size is None:
            e.blockers.append(f"scsi0 size {o.get('size')}: not a whole number of GiB")
        else:
            e.set("disk_gib", size)
        for k, v in disk_options(e, "scsi0", o, root=True).items():
            e.set(f"disk_{k}", v)
    extra, cloudinit, cdrom = [], False, None
    for k in sorted(conf, key=disk_order):
        if not DISK_RE.match(k) or k == "scsi0":
            continue
        vol, o = options(conf[k])
        if "cloudinit" in vol:
            cloudinit = True
            if k != "ide2":
                e.notes.append(f"cloud-init drive on {k}: the module keeps it on ide2")
            continue
        if o.get("media") == "cdrom":
            if k == "ide2":
                cdrom = vol or "none"
            else:
                e.notes.append(f"CD-ROM on {k}: the module has none, the plan removes it")
            continue
        if not VM_EXTRA_RE.match(k):
            e.blockers.append(f"disk on {k}: extra disks can be scsi1-30, virtio0-15 or sata0-5")
            continue
        size = whole(gib(o.get("size")))
        if size is None:
            e.blockers.append(f"{k} size {o.get('size')}: not a whole number of GiB")
            continue
        if o.get("format") not in (None, "raw"):
            e.blockers.append(f"{k} format {o['format']}: the module's extra disks are raw")
            continue
        disk = {"interface": k, "size_gib": size}
        store = vol.split(":", 1)[0]
        if store != datastore:
            disk["datastore"] = store
        disk.update(disk_options(e, k, o, root=False))
        extra.append(disk)
    if extra:
        e.set("extra_disks", extra)
    if not cloudinit:
        e.set("cloud_init_drive", False)   # its network and DNS settings come from the guest
        if cdrom:
            e.set("cdrom", cdrom)
    elif cdrom:
        e.notes.append(f"CD-ROM on ide2 ({cdrom}) next to a cloud-init drive: the module has no CD-ROM then")
    serials = sorted(k for k in conf if re.fullmatch(r"serial\d+", k))
    if not serials:
        e.set("serial_socket", False)
    elif serials != ["serial0"] or conf["serial0"] != "socket":
        e.notes.append(f"serial ports {', '.join(f'{k} {conf[k]}' for k in serials)}: the module has one, "
                       "serial0 socket")

    n = nic_slots(e, conf, "network device")
    if n:
        first, o = options(conf[n[0]])
        model = next((k for k, v in o.items() if MAC_RE.match(v)), first)
        if model != "virtio":
            e.blockers.append(f"{n[0]} model {model or 'unknown'}: the module sets virtio, the guest sees a new NIC")
        extra, ics = [], [options(conf.get(f"ipconfig{k[3:]}"))[1] for k in n]
        for pos, k in enumerate(n):
            ic = ics[pos]
            nic = network(e, conf, ctx, k, ic.get("ip"), ic.get("gw"), ic.get("ip6"), ic.get("gw6"), pos,
                          any(c.get("gw") for c in ics[1:]))
            if pos:
                extra.append(nic)
        if extra:
            e.set("extra_nics", extra)
        if cloudinit:
            servers = str(conf.get("nameserver") or "").split()
            if servers and servers != d.get("dns_servers"):
                e.notes.append("cloud-init DNS servers differ from defaults.dns_servers, which the module sets")
    common(e, conf)
    return e


def disk_order(k: str):
    m = re.fullmatch(r"([a-z]+)(\d+)", k)
    return (m.group(1), int(m.group(2))) if m else (k, 0)


CACHE_MODES = {"directsync", "writethrough", "writeback", "unsafe"}


def disk_options(e: Entry, k: str, o: dict, root: bool) -> dict:
    """The disk's options where they differ from the module's defaults (root disk: discard on, iothread, ssd; extra
    disks: discard on, iothread), as the entry's disk_* attributes or extra_disks fields."""
    out = {}
    if o.get("discard") != "on":
        out["discard"] = "ignore"
    if not flag(o, "iothread"):
        out["iothread"] = False
    if flag(o, "ssd") != root:
        out["ssd"] = flag(o, "ssd")
    if o.get("cache") in CACHE_MODES:
        out["cache"] = o["cache"]
    elif o.get("cache") not in (None, "none"):
        e.notes.append(f"{k} cache={o['cache']}: the module doesn't know it")
    if str(o.get("backup", "1")) == "0":
        out["backup"] = False
    if str(o.get("replicate", "1")) == "0":
        e.notes.append(f"{k} replicate=0: the module sets replicate=1")
    for kk in ("aio", "mbps_rd", "mbps_wr", "iops_rd", "iops_wr", "serial", "wwn", "ro"):
        if o.get(kk):
            e.notes.append(f"{k} {kk}={o[kk]}: the module doesn't set it")
    return out


MP_FLAGS = {"backup": "backup", "ro": "read_only", "acl": "acl", "quota": "quota", "replicate": "replicate",
            "shared": "shared"}


def mount_points(e: Entry, conf: dict) -> list[dict]:
    """The container's mp0, mp1, ... as mount_points entries (the module numbers them in list order)."""
    keys = sorted((k for k in conf if re.fullmatch(r"mp\d+", k)), key=lambda k: int(k[2:]))
    if keys != [f"mp{i}" for i in range(len(keys))]:
        e.blockers.append("mount points " + ", ".join(keys) + " have a gap: the module numbers them mp0, mp1, ... "
                          "in list order")
        return []
    out = []
    for k in keys:
        vol, o = options(conf[k])
        mp = {"volume": vol, "path": o.get("mp", "")}
        if not vol or not mp["path"].startswith("/"):
            e.blockers.append(f"{k} {conf[k]}: no volume or path")
            continue
        if "size" in o or not vol.startswith("/"):   # a volume (a host path: a bind mount, usually no size)
            size = whole(gib(o.get("size")))
            if size is None:
                e.blockers.append(f"{k} size {o.get('size')}: not a whole number of GiB")
                continue
            mp["size_gib"] = size
        for opt, name in MP_FLAGS.items():
            if opt in o:
                mp[name] = flag(o, opt)
        if o.get("mountoptions"):
            mp["mount_options"] = [m for m in o["mountoptions"].split(";") if m]
        for opt in sorted(set(o) - set(MP_FLAGS) - {"mp", "size", "mountoptions"}):
            e.notes.append(f"{k} {opt}={o[opt]}: the module doesn't set it")
        out.append(mp)
    return out


def lxc_entry(g: dict, ctx: dict) -> Entry:
    conf, d = g.get("config") or {}, ctx["defaults"]
    e = Entry(g, "containers", str(conf.get("hostname") or g.get("name") or ""))
    e.set("vm_id", g["vmid"])
    e.set("template_file_id", NO_TEMPLATE_FILE)   # imported: the module ignores it after creation
    ostype = str(conf.get("ostype") or "unmanaged")
    if ostype not in LXC_OS_TYPES:
        e.blockers.append(f"OS type {ostype}: not one the provider knows")
    elif ostype != "debian":
        e.set("os_type", ostype)
    if g.get("node") and g["node"] != d.get("node"):
        e.set("node", g["node"])
    if conf.get("cores") is None:
        e.notes.append("no core limit in Proxmox: the entry sets 1 core")
    e.set("cores", num(conf.get("cores"), 1))
    e.set("memory_mib", num(conf.get("memory"), 512))
    e.set("swap_mib", num(conf.get("swap"), 512))
    vol, o = options(conf.get("rootfs"))
    store = vol.split(":", 1)[0]
    default_store = d.get("lxc_datastore") or d.get("datastore")
    if store and (store != default_store or ctx["node_datastores"] or not default_store):
        e.set("datastore", store)
    size = whole(gib(o.get("size")))
    if size is None:
        e.blockers.append(f"rootfs size {o.get('size')}: not a whole number of GiB")
    else:
        e.set("disk_gib", size)
    for k in ("acl", "quota", "replicate"):   # mountoptions: the provider keeps them (no change in the plan)
        if o.get(k) and not (k == "replicate" and o[k] == "1"):
            e.notes.append(f"rootfs {k}={o[k]}: the module doesn't set it")
    mps = mount_points(e, conf)
    if mps:
        e.set("mount_points", mps)
    devs = sorted(k for k in conf if re.fullmatch(r"dev\d+", k))
    if devs:
        e.blockers.append("device passthrough (" + ", ".join(devs) + "): the module has none")
    if not flag(conf, "unprivileged"):
        e.set("unprivileged", False)
    if not conf.get("features"):      # no features line: the module would add one; nesting = false for an older
        e.set("nesting", False)       # template without the features attribute
        e.set("features", False)
    else:
        _, feats = options(conf.get("features"))
        if not flag(feats, "nesting"):
            e.set("nesting", False)
        for k, v in feats.items():
            if k in ("keyctl", "fuse", "mknod") and flag(feats, k):
                e.set(k, True)
            elif k == "mount" and v:
                e.set("mount_types", [t for t in v.split(";") if t])
            elif k not in ("nesting", "keyctl", "fuse", "mknod", "mount") and v not in ("0", ""):
                e.notes.append(f"feature {k}={v}: the module doesn't set it, the plan removes it")
    # the console block: else the first plan removes Proxmox's defaults from the state (tty, 2 ttys)
    e.set("console_mode", str(conf.get("cmode") or "tty"))
    if re.fullmatch(r"\d+", str(conf.get("tty") or "")) and int(conf["tty"]) != 2:
        e.set("tty_count", int(conf["tty"]))
    if str(conf.get("console", "1")) == "0":
        e.set("console", False)
    if conf.get("arch") not in (None, "amd64"):
        e.notes.append(f"arch {conf['arch']}: the module doesn't set it")
    n = nic_slots(e, conf, "network interface")
    if n:
        _, no = options(conf[n[0]])
        if no.get("name", "eth0") != "eth0":
            e.blockers.append(f"interface name {no.get('name')}: the module names the first one eth0")
        extra, nos = [], [options(conf[k])[1] for k in n]
        for pos, k in enumerate(n):
            no = nos[pos]
            nic = network(e, conf, ctx, k, no.get("ip"), no.get("gw"), no.get("ip6"), no.get("gw6"), pos,
                          any(c.get("gw") for c in nos[1:]))
            if pos:
                extra.append(nic)
        if extra:
            e.set("extra_nics", extra)
    servers = str(conf.get("nameserver") or "").split()
    if servers:
        e.set("dns_servers", servers)
    if conf.get("searchdomain"):
        e.set("dns_domain", str(conf["searchdomain"]))
    common(e, conf)
    return e


# --- output -----------------------------------------------------------------------------------------------------

def hcl(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(hcl(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {hcl(v)}" for k, v in value.items()) + " }"
    s = json.dumps(str(value), ensure_ascii=False)
    return s.replace("${", "$${").replace("%{", "%%{")   # no template sequences: Proxmox text stays literal


def one_line(text: str) -> str:
    """A note for a comment line: values from Proxmox must not start a new line of HCL."""
    return " ".join(str(text).split())


def render_entry(e: Entry, indent: str = "  ") -> str:
    lines = [f"{indent}# {e.g['vmid']} {e.key}" + (": imported as is" if not e.notes else
                                                    ": the first plan will also change")]
    lines += [f"{indent}#   - {one_line(n)}" for n in e.notes]
    lines.append(f"{indent}{hcl(e.key)} = {{")
    multi = [isinstance(v, list) and len(v) > 1 and all(isinstance(x, dict) for x in v) for _, v in e.attrs]
    width = 0
    for i, (n, v) in enumerate(e.attrs):
        if multi[i]:   # one object per line; like tofu fmt, the `=` of single-line runs around it align apart
            lines.append(f"{indent}  {n} = [")
            lines += [f"{indent}    {hcl(x)}," for x in v]
            lines.append(f"{indent}  ]")
            continue
        if i == 0 or multi[i - 1]:
            run = next((j for j in range(i, len(e.attrs)) if multi[j]), len(e.attrs))
            width = max(len(m) for m, _ in e.attrs[i:run])
        lines.append(f"{indent}  {n.ljust(width)} = {hcl(v)}")
    lines.append(f"{indent}}}")
    return "\n".join(lines)


def address(e: Entry) -> str:
    return (f'module.vm[{hcl(e.key)}].proxmox_virtual_environment_vm.this' if e.kind == "vms"
            else f'module.lxc[{hcl(e.key)}].proxmox_virtual_environment_container.this')


def render_import(e: Entry) -> str:
    return f'import {{\n  to = {address(e)}\n  id = "{e.g["node"]}/{e.g["vmid"]}"\n}}'


IMPORTS_HEADER = ("# Generated by tofu_import_plan.py: adopt existing Proxmox guests (references/proxmox.md,\n"
                  "# \"Importing existing resources\"). Plan until each guest shows 1 to import and no replace;\n"
                  "# after the apply, remove the blocks (or this file) and commit.\n")


def insert_entries(text: str, kind: str, entries: list[str]) -> str:
    """text with the entries added at the end of the `kind = { … }` map (a new map when there is none)."""
    body = "\n\n".join(entries) + "\n"
    masked, blocks = top(text)
    span = blocks.get(kind)
    if not span or masked[span[0]] != "{":
        sep = "" if text.endswith("\n\n") or not text else ("\n" if text.endswith("\n") else "\n\n")
        return text + sep + f"{kind} = {{\n{body}}}\n"
    open_at, close_at = span[0], span[1] - 1
    line_start = text.rfind("\n", 0, close_at) + 1
    if text[line_start:close_at].strip() == "" and line_start > open_at:
        gap = "" if text[open_at + 1:line_start].strip() == "" else "\n"
        return text[:line_start] + gap + body + text[line_start:]
    return text[:close_at].rstrip() + "\n" + body + text[close_at:]


# --- main -------------------------------------------------------------------------------------------------------

def plan(cfg: dict, site_name: str | None, wanted: list[str]) -> dict:
    root = Path(cfg["_root"])
    st = hmlib.site(cfg, site_name)
    env = hmlib.tofu_env(cfg, st["name"] or None)
    env_dir = root / "tofu" / "environments" / env
    tfvars = env_dir / "homelab.auto.tfvars"
    if not tfvars.is_file():
        raise hmlib.ConfigError(f"{tfvars.relative_to(root)} is missing (OpenTofu not set up for this site?).")
    snap = hmlib.site_part(hmlib.proxmox_snapshot_file(root), st, "proxmox_inventory.py --details")
    rerun = "proxmox_inventory.py --details" + (f" --site {st['name']}" if st["name"] else "")
    if not snap:
        raise hmlib.ConfigError(f"no Proxmox snapshot of site {hmlib.site_title(st)}: run {rerun}.")
    guests = snap.get("guests") or []
    if (snap.get("config_version") or 0) < CONFIG_VERSION or any(
            "config" not in g for g in guests if not g.get("template")):
        raise hmlib.ConfigError(f"the snapshot lacks guest configs this script copies (cpu type, protection, swap, "
                                f"DNS, an LXC's console): run {rerun} first.")
    text = tfvars.read_text()
    tv = read_tfvars(text)
    variables = env_dir / "variables.tf"
    supported = entry_attributes(variables.read_text()) if variables.is_file() else {}
    imports_file = env_dir / "imports.tf"
    imported = set(re.findall(r"^\s*to\s*=\s*(\S+)", imports_file.read_text(), re.M)) if imports_file.is_file() \
        else set()
    ctx = {"defaults": tv["defaults"], "node_datastores": "node_datastores" in tv["defaults"]}

    found, already, templates, entries, blocked = set(), [], 0, [], []
    used = {k: set(v) for k, v in tv["keys"].items()}
    for g in guests:
        ids = {str(g.get("vmid")), str(g.get("name") or "")}
        if wanted and not ids & set(wanted):
            continue
        found |= ids & set(wanted)
        if g.get("template"):
            templates += 1
            continue
        if g.get("vmid") in tv["ids"]:
            already.append(g)
            continue
        e = vm_entry(g, ctx) if g.get("type") == "vm" else lxc_entry(g, ctx)
        if not KEY_RE.match(e.key):
            e.blockers.insert(0, f"name {e.key!r} is not a valid map key / DNS name")
        elif e.key in used.get(e.kind, set()):
            e.blockers.insert(0, f"{e.kind} already has an entry named {e.key} (another VMID): rename one first")
        unsupported = [n for n, _ in e.attrs if e.kind in supported and n not in supported[e.kind]]
        if e.kind == "vms" and "disk_cache" not in supported.get("vms", {"disk_cache"}):   # extra disks: no options
            for n, v in e.attrs:
                if n == "extra_disks" and any(f in d for d in v for f in DISK_FIELDS):
                    unsupported.append("extra_disks options")
                    for d in v:
                        for f in DISK_FIELDS:
                            d.pop(f, None)
        if unsupported:
            attrs = dict(e.attrs)
            for n in unsupported:   # what an older template would change for the worse: no entry then
                why = {"mount_points": "the plan would remove them", "extra_nics": "the plan would remove the NICs",
                       "os_type": f"{attrs.get(n)} would become l26",
                       "machine": "the default i440fx changes the guest's PCI layout" if "q35" in str(
                           attrs.get(n)) else ""}.get(n)
                if why:
                    e.blockers.append(f"{n}: not in this environment's variables.tf (older template; "
                                      f"init_repo.py --sync-managed updates it), {why}")
            e.attrs = [(n, v) for n, v in e.attrs if n not in unsupported]
            e.notes.append(f"{', '.join(unsupported)}: not in this environment's variables.tf (older template; "
                           "init_repo.py --sync-managed updates it), so the plan changes it")
        if e.blockers:
            blocked.append(e)
            continue
        used.setdefault(e.kind, set()).add(e.key)
        entries.append(e)
    missing = [w for w in wanted if w not in found]
    return {"site": st, "env": env, "env_dir": env_dir, "tfvars": tfvars, "text": text, "imports_file": imports_file,
            "imported": imported, "entries": entries, "blocked": blocked, "already": already,
            "templates": templates, "missing": missing, "has_defaults": tv["has_defaults"], "root": root}


def report(p: dict) -> str:
    rel = p["env_dir"].relative_to(p["root"])
    title = hmlib.site_title(p["site"])
    out = [f"# Site {title}: environment {rel}",
           f"# {len(p['entries'])} guest(s) to import, {len(p['blocked'])} the modules can't represent, "
           f"{len(p['already'])} already in homelab.auto.tfvars" + (f", {p['templates']} template(s) skipped"
                                                                     if p["templates"] else "") + "."]
    if not p["has_defaults"]:
        out.append("# homelab.auto.tfvars has no `defaults` block yet: fill it from homelab.yaml before planning.")
    if p["entries"]:
        out.append("# Every first plan also adds the tag `tofu` and the default description where a guest has none,")
        out.append("# and shows import noise that sets nothing on Proxmox: vm_id, timeout_start, migrate.")
        out += ["", f"# --- {rel}/imports.tf ---"]
        out += [render_import(e) for e in p["entries"]]
        for kind in ("vms", "containers"):
            es = [e for e in p["entries"] if e.kind == kind]
            if es:
                out += ["", f"# --- {rel}/homelab.auto.tfvars, inside {kind} = {{ … }} ---"]
                out += ["\n\n".join(render_entry(e) for e in es)]
    if p["blocked"]:
        out += ["", "# --- Not importable: leave unmanaged, and record why in docs/decisions.md ---"]
        for e in p["blocked"]:
            kind = "VM" if e.kind == "vms" else "container"
            out.append(one_line(f"# - {kind} {e.g['vmid']} {e.key or '(no name)'}: " + "; ".join(e.blockers)))
    for w in p["missing"]:
        out.append(f"# --guest {w}: no such guest in the snapshot of site {title}.")
    return "\n".join(out) + "\n"


def write(p: dict) -> list[str]:
    done = []
    new = [e for e in p["entries"] if address(e) not in p["imported"]]
    if new:
        f = p["imports_file"]
        old = f.read_text() if f.is_file() else IMPORTS_HEADER
        hmlib.atomic_write(f, old.rstrip("\n") + "\n\n" + "\n\n".join(render_import(e) for e in new) + "\n")
        done.append(f"{f.relative_to(p['root'])}: {len(new)} import block(s)")
    text = p["text"]
    for kind in ("vms", "containers"):
        es = [render_entry(e) for e in p["entries"] if e.kind == kind]
        if es:
            text = insert_entries(text, kind, es)
            done.append(f"{p['tfvars'].relative_to(p['root'])}: {len(es)} entr{'y' if len(es) == 1 else 'ies'} "
                        f"in {kind}")
    if text != p["text"]:
        hmlib.atomic_write(p["tfvars"], text)
    return done


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--site", help="the site (sites: in homelab.yaml); default: the default site")
    ap.add_argument("--guest", action="append", default=[], metavar="NAME|VMID",
                    help="only this guest (repeatable)")
    ap.add_argument("--write", action="store_true",
                    help="write imports.tf and add the entries to homelab.auto.tfvars (never changes existing ones)")
    a = ap.parse_args(argv)
    try:
        cfg = hmlib.load_config()
        p = plan(cfg, a.site, a.guest)
    except hmlib.ConfigError as e:
        print(f"tofu_import_plan: {e}", file=sys.stderr)
        return 3
    print(report(p), end="")
    if a.write:
        done = write(p)
        if done:
            print("\nWrote " + "; ".join(done) + ".\nNext: tofu fmt, then plan with the read-only token "
                  "(references/proxmox.md \"Importing existing resources\") and review each guest's changes.")
        else:
            print("\nNothing to write.")
    return 1 if p["missing"] else 0


if __name__ == "__main__":
    sys.exit(main())
