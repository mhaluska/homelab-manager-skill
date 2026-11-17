#!/usr/bin/env python3
"""Draft Ansible inventory entries for existing Linux guests from discovery/proxmox.json (read-only).

    proxmox_to_inventory.py [--vlan 20 ...] [--range 10.0.20.0/24 ...] [--type vm|lxc] [--node pve1]
                            [--group onboarding] [--all-status] [--out FILE]

Needs a snapshot made with `proxmox_inventory.py --details` (guest config and reported IPs).
Prints a YAML draft (hosts with ansible_host, proxmox_vmid/node/kind) for review: it is never merged into
hosts.yml by itself. Skips templates, non-Linux guests (VM ostype win*/solaris/other), guests already in the
managed inventory (by name or address), stopped guests (unless --all-status) and guests without a usable IP,
and lists each with the reason as a comment.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
from drift_report import guest_addresses, load_ansible  # noqa: E402

LINUX_VM_OSTYPES = {"l26", "l24"}
# LXC ostypes are all Linux; "unmanaged" too (Proxmox just doesn't set it up)


def is_linux(g: dict) -> tuple[bool, str]:
    ostype = str((g.get("config") or {}).get("ostype") or "")
    if g.get("type") == "lxc":
        return True, ostype or "lxc"
    if not ostype:
        return True, "vm, ostype unknown"  # Proxmox's default for a VM is l26
    return ostype in LINUX_VM_OSTYPES, ostype


def vlans(g: dict) -> set[int]:
    return {int(t) for k, v in (g.get("config") or {}).items() if k.startswith("net")
            for t in re.findall(r"(?<![\w])tag=(\d+)", str(v))}


def pick_ip(g: dict, ranges: list) -> str | None:
    """IPv4 first, static config before reported; inside --range when given; never loopback/link-local."""
    cands = []
    for ip, src in guest_addresses(g)[0].items():
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified:
            continue
        if ranges and not any(a in n for n in ranges if n.version == a.version):
            continue
        cands.append((a.version != 4, src != "config", ip))
    return min(cands)[2] if cands else None


def host_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", (name or "").lower()).strip("-.") or "guest"


def plan(guests, managed: dict, a, ranges) -> tuple[dict[str, dict], list[str]]:
    known_names = {h.lower().split(".")[0] for h in managed}
    known_ips = {str(v.get("ansible_host") or "").lower() for v in managed.values()} - {""}
    hosts, skipped = {}, []
    for g in sorted(guests, key=lambda g: g.get("vmid") or 0):
        label = f"{g.get('vmid')} {g.get('name') or '?'}"
        if g.get("template"):
            continue
        if a.type and g.get("type") != a.type:
            continue
        if a.node and g.get("node") not in a.node:
            continue
        if a.vlan and not vlans(g) & set(a.vlan):
            continue
        linux, why = is_linux(g)
        if not linux:
            skipped.append(f"{label}: not Linux (ostype {why})")
            continue
        if g.get("status") != "running" and not a.all_status:
            skipped.append(f"{label}: {g.get('status')} (--all-status to include)")
            continue
        ip = pick_ip(g, ranges)
        if not ip:
            if ranges:
                continue  # not in the requested ranges (or no address known)
            skipped.append(f"{label}: no IP known (static config, guest agent or LXC interfaces)")
            continue
        name = host_name(g.get("name"))
        if name in known_names or ip.lower() in known_ips:
            skipped.append(f"{label}: already in the managed inventory")
            continue
        if name in hosts:
            name = f"{name}-{g.get('vmid')}"
        hosts[name] = {"ansible_host": ip, "proxmox_vmid": g.get("vmid"), "proxmox_node": g.get("node"),
                       "proxmox_kind": g.get("type"), "_os": why}
    return hosts, skipped


def to_yaml(hosts: dict[str, dict], skipped: list[str], group: str, source: str) -> str:
    out = [f"# DRAFT from {source} by proxmox_to_inventory.py — review, then add to",
           "# ansible/inventory/managed/hosts.yml. Probe the OS and Python first (references/ansible.md).",
           "all:", "  children:", f"    {group}:", "      hosts:" if hosts else "      hosts: {}"]
    for name, v in hosts.items():
        out.append(f"        {name}:  # {v['_os']}")
        out += [f"          {k}: {json.dumps(val)}" for k, val in v.items() if not k.startswith("_") and val is not None]
    if skipped:
        out += ["", "# Skipped:"] + [f"#   {s}" for s in skipped]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vlan", type=int, action="append", default=[], help="only guests with a NIC on this VLAN tag")
    ap.add_argument("--range", action="append", default=[], help="only guests with an address in this CIDR")
    ap.add_argument("--type", choices=("vm", "lxc"))
    ap.add_argument("--node", action="append", default=[])
    ap.add_argument("--group", default="onboarding", help="group for the drafted hosts (default: onboarding)")
    ap.add_argument("--all-status", action="store_true", help="include stopped guests")
    ap.add_argument("--out", help="write the draft here instead of stdout")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        ranges = [ipaddress.ip_network(r, strict=False) for r in a.range]
    except (hmlib.ConfigError, ValueError) as e:
        print(f"proxmox_to_inventory: {e}", file=sys.stderr)
        return 3
    root = Path(cfg["_root"])
    snap = root / "discovery" / "proxmox.json"
    if not snap.exists():
        print("proxmox_to_inventory: no discovery/proxmox.json — run proxmox_inventory.py --details first.",
              file=sys.stderr)
        return 4
    inv = json.loads(snap.read_text())
    guests = inv.get("guests") or []
    if guests and not any("config" in g for g in guests):
        print("proxmox_to_inventory: discovery/proxmox.json has no guest config — refresh it with "
              "proxmox_inventory.py --details.", file=sys.stderr)
        return 4
    managed, _ = load_ansible(root)
    hosts, skipped = plan(guests, managed, a, ranges)
    text = to_yaml(hosts, skipped, a.group, f"discovery/proxmox.json ({inv.get('collected_at', '?')})")
    if a.out:
        Path(a.out).write_text(text)
        print(f"Wrote {a.out}: {len(hosts)} host(s), {len(skipped)} skipped", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
