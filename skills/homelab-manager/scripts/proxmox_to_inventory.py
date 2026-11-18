#!/usr/bin/env python3
"""Draft Ansible inventory entries for existing Linux guests from discovery/proxmox.json (read-only).

    proxmox_to_inventory.py [--vlan 20|DMZ ...] [--range 10.0.20.0/24 ...] [--type vm|lxc] [--node pve1]
                            [--group onboarding] [--all-status] [--out FILE] [--site NAME]

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
from drift_report import load_ansible  # noqa: E402

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


def pick_ip(g: dict, ranges: list, preferred: list | None = None) -> str | None:
    """The address to reach the guest by (hmlib.rank_guest_addresses): on a NIC of its Proxmox config, inside
    `preferred` (the site's ranges and authorized_ranges), not a tunnel/bridge address, IPv4 first, never
    loopback/link-local. Only addresses inside --range (`ranges`) when given."""
    for a in hmlib.rank_guest_addresses(g, preferred):
        ip = ipaddress.ip_address(a["ip"])
        if not ranges or any(ip in n for n in ranges if n.version == ip.version):
            return a["ip"]
    return None


def host_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", (name or "").lower()).strip("-.") or "guest"


def plan(guests, managed: dict, a, ranges, preferred: list | None = None) -> tuple[dict[str, dict], list[str]]:
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
        ip = pick_ip(g, ranges, preferred)
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


def to_yaml(hosts: dict[str, dict], skipped: list[str], group: str, source: str, site_group: str = "") -> str:
    out = [f"# DRAFT from {source} by proxmox_to_inventory.py — review, then add to",
           "# ansible/inventory/managed/hosts.yml. Probe the OS and Python first (references/ansible.md).",
           "all:", "  children:", f"    {group}:", "      hosts:" if hosts else "      hosts: {}"]
    for name, v in hosts.items():
        out.append(f"        {name}:  # {v['_os']}")
        out += [f"          {k}: {json.dumps(val)}" for k, val in v.items() if not k.startswith("_") and val is not None]
    if site_group and hosts:   # the hosts' location: patching snapshots them on that site's Proxmox
        out += [f"    {site_group}:", "      hosts:"] + [f"        {name}:" for name in hosts]
    if skipped:
        out += ["", "# Skipped:"] + [f"#   {s}" for s in skipped]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vlan", action="append", default=[],
                    help="only guests with a NIC on this VLAN (tag, or name from network.vlans)")
    ap.add_argument("--range", action="append", default=[], help="only guests with an address in this CIDR")
    ap.add_argument("--type", choices=("vm", "lxc"))
    ap.add_argument("--node", action="append", default=[])
    ap.add_argument("--group", default="onboarding", help="group for the drafted hosts (default: onboarding)")
    ap.add_argument("--all-status", action="store_true", help="include stopped guests")
    ap.add_argument("--out", help="write the draft here instead of stdout")
    ap.add_argument("--site", help="draft from this site's snapshot (sites: in homelab.yaml) into its site_<name> group")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        ranges = [ipaddress.ip_network(r, strict=False) for r in a.range]
        site = hmlib.site(cfg, a.site)
        a.vlan = [hmlib.resolve_vlan(cfg, v, site["name"]) for v in a.vlan]
    except (hmlib.ConfigError, ValueError) as e:
        print(f"proxmox_to_inventory: {e}", file=sys.stderr)
        return 3
    root = Path(cfg["_root"])
    snap = hmlib.proxmox_snapshot_file(root, site["name"], site["default"])
    rel = snap.relative_to(root)
    if not snap.exists():
        print(f"proxmox_to_inventory: no {rel} — run proxmox_inventory.py --details"
              + (f" --site {site['name']}" if site["name"] else "") + " first.", file=sys.stderr)
        return 4
    inv = json.loads(snap.read_text())
    guests = inv.get("guests") or []
    if guests and not any("config" in g for g in guests):
        print(f"proxmox_to_inventory: {rel} has no guest config — refresh it with "
              "proxmox_inventory.py --details.", file=sys.stderr)
        return 4
    managed, _ = load_ansible(root)
    preferred = site["ranges"] + hmlib.scan_scope(cfg)[0]
    hosts, skipped = plan(guests, managed, a, ranges, preferred)
    text = to_yaml(hosts, skipped, a.group, f"{rel} ({inv.get('collected_at', '?')})",
                   hmlib.SITE_GROUP_PREFIX + site["name"] if site["name"] else "")
    if a.out:
        Path(a.out).write_text(text)
        print(f"Wrote {a.out}: {len(hosts)} host(s), {len(skipped)} skipped", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
