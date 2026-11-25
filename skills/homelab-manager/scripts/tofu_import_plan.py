#!/usr/bin/env python3
"""OpenTofu `import {}` blocks and tfvars entries for Proxmox guests OpenTofu doesn't manage yet (GitHub issue #149).

    tofu_import_plan.py [--site NAME] [--guest NAME|VMID ...] [--write]

Reads the site's discovery/proxmox.json (proxmox_inventory.py --details, 0.61.0 or later) and its environment's
homelab.auto.tfvars (tofu/environments/<env>). For each guest that has no entry there yet it prints an import block
and a `vms` / `containers` entry for the template's modules, with what Proxmox has now: node, cores, memory, swap,
disks (size, datastore, extra_disks), bridge, VLAN tag, MAC address, static address and gateway, DNS (LXC), tags,
cpu_type, on_boot, protection, description, started, unprivileged and nesting. Above each entry a comment names
what the first plan will still change (settings the modules don't carry: sockets, NUMA, disk cache, start order,
...). A guest the modules can't represent without a rebuild or lost hardware (passthrough, several NICs, a root disk
other than scsi0, UEFI, a non-Linux OS type, LXC mount points, ...) gets no entry: it stays unmanaged, with a line
for docs/decisions.md.

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

CONFIG_VERSION = 2          # proxmox_inventory.CONFIG_VERSION that carries cpu, protection, swap, DNS, hostname
LXC_OS_TYPES = {"alpine", "archlinux", "centos", "debian", "devuan", "fedora", "gentoo", "nixos", "opensuse",
                "ubuntu", "unmanaged"}   # bpg operating_system.type
KEY_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$")   # a map key the modules use as name
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
VM_EXTRA_RE = re.compile(r"^(scsi([1-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5])$")
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
                v = m.end()
                if v < end and masked[v] in "{[":
                    e = closing(masked, v)
                    e = end if e < 0 or e >= end else e + 1
                else:
                    e = masked.find("\n", v, end)
                    e = v + len(masked[v:end if e < 0 else e].rstrip())
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
        e.notes.append(f"startup {conf['startup']}: the modules set no start order, the plan removes it")


def network(e: Entry, conf: dict, ctx: dict, nic: str, ip: str | None, gw: str | None, ip6: str | None):
    """bridge, vlan_id, mac_address, ipv4_address, ipv4_gateway of the guest's one NIC."""
    _, o = options(conf.get(nic))
    d = ctx["defaults"]
    bridge = o.get("bridge")
    if bridge and bridge != d.get("bridge"):
        e.set("bridge", bridge)
    if o.get("tag"):
        e.set("vlan_id", int(o["tag"]))
    if o.get("trunks"):
        e.blockers.append(f"{nic} carries VLAN trunks ({o['trunks']}): the modules set one tag")
    mac = o.get("hwaddr") or next((v for k, v in o.items() if MAC_RE.match(v or "")), None)
    if mac:
        e.set("mac_address", mac)
    if flag(o, "firewall"):
        e.notes.append(f"{nic} firewall=1: the modules turn the NIC's firewall off")
    for k in ("queues", "mtu", "rate", "link_down"):
        if o.get(k):
            e.notes.append(f"{nic} {k}={o[k]}: the modules don't set it, the plan removes it")
    if ip and ip not in ("dhcp", "manual"):
        e.set("ipv4_address", ip)
        if gw and gw != d.get("ipv4_gateway"):
            e.set("ipv4_gateway", gw)
        elif not gw and d.get("ipv4_gateway"):
            e.notes.append("no gateway in Proxmox: the entry gets defaults.ipv4_gateway")
    elif ip == "manual":
        e.notes.append(f"{nic} ip=manual: the modules set dhcp")
    if ip6:
        e.notes.append(f"IPv6 {ip6}: the modules have no IPv6 setting yet, the plan removes it")


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
        e.notes.append(f"sockets {sockets}: the module sets 1 socket, so the VM gets {num(conf.get('cores'), 1)} "
                       "vCPUs instead of " + str(sockets * num(conf.get("cores"), 1)))
    cputype, copts = options(conf.get("cpu"))
    cputype = copts.get("cputype", cputype) or "kvm64"
    e.set("cpu_type", cputype)
    if copts.get("flags"):
        e.notes.append(f"CPU flags {copts['flags']}: the module sets none")
    if flag(conf, "numa"):
        e.notes.append("numa=1: the module turns NUMA off")
    if conf.get("balloon") not in (None, "0"):
        e.notes.append(f"balloon {conf['balloon']}: the module sets no ballooning minimum")
    if str(conf.get("tablet", "1")) == "0":
        e.notes.append("tablet=0: the module leaves the provider's default USB tablet on")
    agent_on, aopts = options(conf.get("agent"))
    if agent_on != "1" and not flag(aopts, "enabled"):
        e.notes.append("guest agent off: the module turns it on")
    for k in ("fstrim_cloned_disks", "type", "freeze-fs-on-backup"):
        if k in aopts:
            e.notes.append(f"agent {k}={aopts[k]}: the module doesn't set it")
    if (conf.get("scsihw") or "lsi") != "virtio-scsi-single":
        e.notes.append(f"SCSI controller {conf.get('scsihw') or 'lsi (default)'}: the module sets virtio-scsi-single")
    if (conf.get("ostype") or "other") != "l26":
        e.blockers.append(f"OS type {conf.get('ostype') or 'other'}: the module sets l26 (Linux)")
    if conf.get("bios") == "ovmf" or any(k.startswith("efidisk") for k in conf):
        e.blockers.append("UEFI (bios ovmf, EFI disk): the module has no EFI disk")
    if any(k.startswith("tpmstate") for k in conf):
        e.blockers.append("TPM state disk: the module has none")
    machine = str(conf.get("machine") or "")
    if "q35" in machine:
        e.blockers.append(f"machine {machine}: the module sets none (i440fx), which changes the guest's PCI layout")
    elif machine:
        e.notes.append(f"machine {machine}: the module sets none, the VM gets the current i440fx at its next start")
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
        want = {"discard": "on", "iothread": "1", "ssd": "1"}
        for k, v in want.items():
            if str(o.get(k, "0")) != v:
                e.notes.append(f"scsi0 {k}={o.get(k, 'off')}: the module sets {k}={v}")
        disk_notes(e, "scsi0", o)
    extra, cloudinit = [], False
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
                e.notes.append(f"CD-ROM on ide2 ({vol or 'empty'}): the module puts its cloud-init drive there")
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
        extra.append(disk)
        for kk, v in {"discard": "on", "iothread": "1"}.items():
            if str(o.get(kk, "0")) != v:
                e.notes.append(f"{k} {kk}={o.get(kk, 'off')}: the module sets {kk}={v}")
        if flag(o, "ssd"):
            e.notes.append(f"{k} ssd=1: the module doesn't set ssd on extra disks")
        disk_notes(e, k, o)
    if extra:
        e.set("extra_disks", extra)
    if not cloudinit:
        e.notes.append("no cloud-init drive: the module adds one on ide2 (cloud-init in the guest, if installed, "
                       "would apply its network and DNS settings at the next boot)")
    if not any(str(conf.get(k, "")).startswith("socket") for k in conf if k.startswith("serial")):
        e.notes.append("no serial socket: the module adds serial0")

    n = nets(conf)
    if not n:
        e.blockers.append("no network device: the module has one")
    elif len(n) > 1:
        e.blockers.append(f"{len(n)} network devices ({', '.join(n)}): the module has one")
    else:
        first, o = options(conf[n[0]])
        model = next((k for k, v in o.items() if MAC_RE.match(v)), first)
        if model != "virtio":
            e.blockers.append(f"{n[0]} model {model or 'unknown'}: the module sets virtio, the guest sees a new NIC")
        idx = n[0][3:]
        _, ic = options(conf.get(f"ipconfig{idx}"))
        if n[0] != "net0":
            e.blockers.append(f"the only NIC is {n[0]}: the module's is net0")
        network(e, conf, ctx, n[0], ic.get("ip"), ic.get("gw"), ic.get("ip6"))
        if cloudinit:
            servers = str(conf.get("nameserver") or "").split()
            if servers and servers != d.get("dns_servers"):
                e.notes.append("cloud-init DNS servers differ from defaults.dns_servers, which the module sets")
    common(e, conf)
    return e


def disk_order(k: str):
    m = re.fullmatch(r"([a-z]+)(\d+)", k)
    return (m.group(1), int(m.group(2))) if m else (k, 0)


def disk_notes(e: Entry, k: str, o: dict):
    if o.get("cache") not in (None, "none"):
        e.notes.append(f"{k} cache={o['cache']}: the module sets no cache")
    for kk in ("backup", "replicate"):
        if str(o.get(kk, "1")) == "0":
            e.notes.append(f"{k} {kk}=0: the module sets {kk}=1")
    for kk in ("aio", "mbps_rd", "mbps_wr", "iops_rd", "iops_wr", "serial", "wwn", "ro"):
        if o.get(kk):
            e.notes.append(f"{k} {kk}={o[kk]}: the module doesn't set it")


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
    mps = sorted((k for k in conf if re.fullmatch(r"mp\d+", k)), key=lambda k: int(k[2:]))
    if mps:
        e.blockers.append("mount points (" + ", ".join(mps) + "): the module has none, the plan would remove them")
    devs = sorted(k for k in conf if re.fullmatch(r"dev\d+", k))
    if devs:
        e.blockers.append("device passthrough (" + ", ".join(devs) + "): the module has none")
    if not flag(conf, "unprivileged"):
        e.set("unprivileged", False)
    _, feats = options(conf.get("features"))
    if not flag(feats, "nesting"):
        e.set("nesting", False)
    for k, v in feats.items():
        if k != "nesting" and v not in ("0", ""):
            e.notes.append(f"feature {k}={v}: the module sets only nesting, the plan removes it")
    if conf.get("arch") not in (None, "amd64"):
        e.notes.append(f"arch {conf['arch']}: the module doesn't set it")
    n = nets(conf)
    if not n:
        e.blockers.append("no network interface: the module has one")
    elif len(n) > 1:
        e.blockers.append(f"{len(n)} network interfaces ({', '.join(n)}): the module has one")
    else:
        _, no = options(conf[n[0]])
        if no.get("name", "eth0") != "eth0":
            e.blockers.append(f"interface name {no.get('name')}: the module names it eth0")
        if n[0] != "net0":
            e.blockers.append(f"the only interface is {n[0]}: the module's is net0")
        network(e, conf, ctx, n[0], no.get("ip"), no.get("gw"), no.get("ip6"))
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
    width = max(len(n) for n, _ in e.attrs)
    lines.append(f"{indent}{hcl(e.key)} = {{")
    lines += [f"{indent}  {n.ljust(width)} = {hcl(v)}" for n, v in e.attrs]
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
                                f"DNS): run {rerun} first.")
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
        if unsupported:
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
        out.append("# and shows import noise that sets nothing on Proxmox: vm_id, timeout_start, an LXC's console.")
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
