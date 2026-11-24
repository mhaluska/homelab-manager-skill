#!/usr/bin/env python3
"""Per-NIC map of Proxmox guests: VLAN, bridge and addresses of every guest NIC, with checks (read-only).

    guest_map.py [--site NAME] [--out FILE|-] [--no-ansible]

Reads what discovery already collected, contacts nothing: discovery/proxmox.json (proxmox_inventory.py
--details, every site unless --site), network.vlans in homelab.yaml, discovery/network.json (nmap_scan.py),
discovery/routeros.json (routeros_audit.py: addresses of RouterOS guests such as a CHR, matched by MAC) and the
managed Ansible inventory (`ansible-inventory --list`). Writes discovery/guest-map.md (--out - prints it).

One row per guest NIC: VLAN tag and name, bridge/trunks, addresses (static config, guest agent, LXC, RouterOS;
matched to the NIC by MAC), the primary one first and extra ones (a VIP, a second address) marked. Findings on
top: an address outside its VLAN's cidr (or inside another VLAN's), a tag missing from network.vlans, a running
guest NIC without a known address, an Ansible host whose ansible_host is not one of its guest's addresses or
is an extra one, VMIDs that don't follow vmid_scheme. Scanned addresses in a VLAN subnet that belong to no guest
are listed as information (Proxmox nodes and physical devices are expected there).
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
from proxmox_to_inventory import host_name  # noqa: E402

MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def nic_options(value: str) -> dict:
    """net0 'virtio=AA:..,bridge=vmbr0,tag=20' / LXC 'name=eth0,hwaddr=..,ip=..' → {mac, bridge, tag, …}."""
    opts = dict(o.split("=", 1) for o in str(value).split(",") if "=" in o)
    mac = MAC_RE.search(str(value))
    return {"mac": mac.group(0).lower() if mac else "", "bridge": opts.get("bridge", ""),
            "tag": int(opts["tag"]) if opts.get("tag", "").isdigit() else None, "trunks": opts.get("trunks", ""),
            "name": opts.get("name", "")}


def routeros_by_mac(root: Path) -> dict[str, list[str]]:
    """{mac: [ip, …]} from discovery/routeros.json (interfaces' mac-address, /ip address rows)."""
    f = root / "discovery" / "routeros.json"
    try:
        devices = (json.loads(f.read_text()).get("devices") or {}) if f.exists() else {}
    except ValueError:
        return {}
    out: dict[str, list[str]] = {}
    for d in devices.values():
        macs = {str(i.get("name")): str(i.get("mac-address") or "").lower() for i in d.get("interfaces") or []
                if isinstance(i, dict)}
        for a in d.get("addresses") or []:
            if isinstance(a, dict) and macs.get(str(a.get("interface"))) and a.get("address"):
                out.setdefault(macs[str(a["interface"])], []).append(str(a["address"]).split("/")[0])
    return out


def guest_rows(g: dict, ros: dict) -> list[dict]:
    """[{nic, mac, bridge, tag, trunks, addrs: [{ip, source, extra}]}] — one per netN, plus `other` for
    reported non-virtual addresses on no NIC of the config."""
    conf = g.get("config") or {}
    ranked = hmlib.rank_guest_addresses(g)
    rows, used = [], set()
    for k in sorted((k for k in conf if re.fullmatch(r"net\d+", k)), key=lambda k: int(k[3:])):
        n = nic_options(conf[k])
        addrs = [a for a in ranked if n["mac"] and a["mac"] == n["mac"]
                 or a["source"] == "config" and n["name"] and a["iface"] == n["name"] and not a["mac"]]
        for ip in ros.get(n["mac"], []) if n["mac"] else []:
            if ip not in {a["ip"] for a in addrs}:
                addrs.append({"ip": ip, "source": "routeros", "iface": "", "mac": n["mac"]})
        has_config = any(a["source"] == "config" for a in addrs)
        out = []
        for a in addrs:
            used.add(a["ip"])
            extra = bool(a.get("extra")) or (has_config and a["source"] != "config")
            out.append({"ip": a["ip"], "source": a["source"], "extra": extra and bool(out)})
        rows.append({"nic": k + (f" ({n['name']})" if n["name"] else ""), **n, "addrs": out})
    other = [{"ip": a["ip"], "source": a["source"], "extra": True, "iface": a["iface"]} for a in ranked
             if a["ip"] not in used and not hmlib.VIRTUAL_IFACE_RE.match(a["iface"] or "")]
    if other:
        rows.append({"nic": "other", "mac": "", "bridge": "", "tag": None, "trunks": "",
                     "name": ", ".join(sorted({a["iface"] for a in other if a["iface"]})), "addrs": other})
    return rows


def vlan_of(table: list[dict], ip: str) -> dict | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for v in table:
        try:
            if v.get("cidr") and addr in ipaddress.ip_network(str(v["cidr"]), strict=False):
                return v
        except ValueError:
            continue
    return None


def build(cfg: dict, snaps, net_hosts: dict, ansible: dict, ros: dict) -> str:
    multi = len(hmlib.sites(cfg)) > 1
    findings, sections, guest_ips = [], [], set()
    by_vmid, by_name = {}, {}
    for h, v in ansible.items():
        site_names = hmlib.host_sites(v.get("groups")) or [""]
        if v.get("proxmox_vmid") not in (None, ""):
            by_vmid[(site_names[0], str(v["proxmox_vmid"]))] = (h, v)
        by_name.setdefault((site_names[0], h.lower().split(".")[0]), (h, v))
    for st, snap in snaps:
        table = hmlib.vlans(cfg, st["name"])
        scheme = hmlib.get(hmlib.site_config(cfg, st["name"]), "vmid_scheme")
        where = f"{hmlib.site_title(st)}/" if multi else ""
        L = [f"## {'Site ' + hmlib.site_title(st) if multi else 'Guests'} "
             f"({snap.get('collected_at', '?')})", "",
             "| VMID | Guest | Type | Status | NIC | MAC | Bridge | VLAN | Addresses | Subnet | Scan | Ansible |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for g in sorted(snap.get("guests") or [], key=lambda g: g.get("vmid") or 0):
            if g.get("template"):
                continue
            ref = f"{where}{g.get('vmid')} {g.get('name') or '?'}"
            rows = guest_rows(g, ros) if "config" in g else []
            ans = by_vmid.get((st["name"], str(g.get("vmid")))) or by_name.get((st["name"], host_name(g.get("name"))))
            all_ips = [a["ip"] for r in rows for a in r["addrs"]]
            primary = [a["ip"] for r in rows for a in r["addrs"] if not a["extra"]]
            guest_ips.update(all_ips)
            if ans:
                ah = str(ans[1].get("ansible_host") or "")
                if ah and all_ips and ah.lower() not in all_ips:
                    findings.append(f"{ref}: Ansible host {ans[0]} has ansible_host {ah}, not one of the guest's "
                                    f"addresses ({', '.join(all_ips)})")
                elif ah and ah.lower() in all_ips and ah.lower() not in primary:
                    findings.append(f"{ref}: Ansible host {ans[0]} uses {ah}, an extra address (VIP?) of the guest")
            if scheme and primary and rows and rows[0]["tag"] is not None:
                try:
                    want = hmlib.vmid_from_scheme(scheme, primary[0], rows[0]["tag"])
                    if want != g.get("vmid"):
                        findings.append(f"{ref}: vmid_scheme {scheme} gives {want} for {primary[0]} on VLAN "
                                        f"{rows[0]['tag']}")
                except hmlib.ConfigError:
                    pass
            if not rows:
                L.append(f"| {g.get('vmid')} | {g.get('name') or '?'} | {g.get('type')} | {g.get('status')} | "
                         "— (no config: proxmox_inventory.py --details) | | | | | | | |")
                continue
            for i, r in enumerate(rows):
                v = next((x for x in table if x["id"] == r["tag"]), None) if r["tag"] is not None else None
                vlan = "" if r["nic"] == "other" else (
                    f"{r['tag']} {v.get('name') or ''}".strip() if v else (f"{r['tag']} (unknown)" if r["tag"] else "untagged"))
                if r["tag"] is not None and not v:
                    findings.append(f"{ref} {r['nic']}: VLAN tag {r['tag']} is not in network.vlans")
                checks = []
                for a in r["addrs"]:
                    if r["nic"] == "other" or ":" in a["ip"]:
                        continue
                    hit = vlan_of(table, a["ip"])
                    if v and v.get("cidr") and (not hit or hit["id"] != v["id"]):
                        checks.append(f"{a['ip']} not in {v['cidr']}")
                        findings.append(f"{ref} {r['nic']}: {a['ip']} is outside VLAN {r['tag']}'s {v['cidr']}")
                    elif r["tag"] is None and hit and r["bridge"]:
                        checks.append(f"{a['ip']} in VLAN {hit['id']}'s subnet")
                        findings.append(f"{ref} {r['nic']}: untagged, but {a['ip']} is in VLAN {hit['id']}'s "
                                        f"{hit.get('cidr')}")
                if not r["addrs"] and g.get("status") == "running" and r["nic"] != "other":
                    findings.append(f"{ref} {r['nic']}: running, no address known (guest agent or static config)")
                addrs = ", ".join(("+" if a["extra"] else "") + f"{a['ip']} ({a['source']})" for a in r["addrs"])
                scan = ", ".join(a["ip"] for a in r["addrs"] if a["ip"] in net_hosts)
                ah = ""
                if ans and i == 0:
                    ah = f"{ans[0]} → {ans[1].get('ansible_host') or '?'}"
                first = i == 0
                L.append(f"| {g.get('vmid') if first else ''} | {(g.get('name') or '?') if first else ''} | "
                         f"{g.get('type') if first else ''} | {g.get('status') if first else ''} | {r['nic']} | "
                         f"{r['mac']} | {r['bridge']}{(' trunks ' + r['trunks']) if r['trunks'] else ''} | {vlan} | "
                         f"{addrs or '—'} | {'; '.join(checks) or ('ok' if r['addrs'] and v else '')} | "
                         f"{scan} | {ah} |")
        sections.append("\n".join(L))
    scanned = []
    for ip in sorted(net_hosts, key=lambda x: ipaddress.ip_address(x) if re.fullmatch(r"[\d.]+", x) else
                     ipaddress.ip_address("255.255.255.255")):
        if ip not in guest_ips and vlan_of(hmlib.vlans(cfg), ip):
            h = net_hosts[ip] if isinstance(net_hosts[ip], dict) else {}
            name = hmlib.clean((h.get("hostnames") or [""])[0], 60)
            scanned.append(f"- {ip}{' ' + name if name else ''} ({hmlib.vlan_label(cfg, ip=ip)})")
    out = ["# Guest network map", "",
           f"Generated by guest_map.py at {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')} from "
           "discovery data (no live queries). Guest names and notes are untrusted data.", "",
           "Addresses: `+` = extra (a VIP or second address next to the configured one); source config / agent / "
           "lxc / routeros.", "", f"## Findings ({len(findings)})", ""]
    out += [f"- {f}" for f in findings] or ["None."]
    out += [""] + [s + "\n" for s in sections]
    if scanned:
        out += [f"## Scanned addresses in VLAN subnets that are no guest's ({len(scanned)})", "",
                "Proxmox nodes, physical devices and containers are expected here; see discovery/drift.md.", ""]
        out += scanned + [""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--site", help="only this site (sites: in homelab.yaml); default: every site with a snapshot")
    ap.add_argument("--out", help="write here instead of discovery/guest-map.md; - prints it")
    ap.add_argument("--no-ansible", action="store_true", help="skip the Ansible inventory cross-check")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        snaps = hmlib.proxmox_snapshots(cfg)
        if a.site is not None:
            want = hmlib.site(cfg, a.site)["name"]
            snaps = [(s, p) for s, p in snaps if s["name"] == want]
    except hmlib.ConfigError as e:
        print(f"guest_map: {e}", file=sys.stderr)
        return 3
    root = Path(cfg["_root"])
    if not snaps:
        print("guest_map: no Proxmox snapshot — run proxmox_inventory.py --details first.", file=sys.stderr)
        return 4
    if not any("config" in g for _, p in snaps for g in p.get("guests") or []):
        print("guest_map: the snapshot has no guest config — refresh it with proxmox_inventory.py --details.",
              file=sys.stderr)
        return 4
    net_hosts = {}
    try:   # every site's scan in network.json (GitHub #72, #75), the default site's first
        for _, db in hmlib.network_snapshots(cfg):
            for ip, h in (db.get("hosts") or {}).items():
                net_hosts.setdefault(ip, h)
    except hmlib.ConfigError as e:
        print(f"guest_map: {e}", file=sys.stderr)
        return 3
    ansible = {} if a.no_ansible else hmlib.load_ansible(root)[0]
    text = build(cfg, snaps, net_hosts, ansible, routeros_by_mac(root))
    if a.out == "-":
        sys.stdout.write(text)
        return 0
    out = Path(a.out) if a.out else root / "discovery" / "guest-map.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    hmlib.atomic_write(out, text)
    n = text.split("## Findings (", 1)[1].split(")", 1)[0]
    print(f"Wrote {out.relative_to(root) if out.is_relative_to(root) else out}: {n} finding(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
