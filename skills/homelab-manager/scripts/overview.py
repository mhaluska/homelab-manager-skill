#!/usr/bin/env python3
"""OVERVIEW.md: one readable page about the whole homelab, every site, with Mermaid maps (read-only).

    overview.py [--out FILE|-] [--check] [--no-ansible]

Renders what the repository already holds and contacts nothing (GitHub issue #87): homelab.yaml (sites,
network.vlans, clusters), discovery/proxmox.json (nodes, storage, guests, backup jobs), network.json (scanned
addresses), unifi.json, routeros.json, bmc.json, containers.json, qnap-containers.json, updates.json, the managed
Ansible inventory (`ansible-inventory --list`; --no-ansible skips it), discovery/drift.md and the newest
docs/security-audit-*.md. Network devices start from the inventory (routeros, unifi, bmc, qnap, appliances groups)
and are enriched from the discovery files; "Other scanned addresses" holds only addresses nothing in the repo names.
Writes OVERVIEW.md in the repository root (--out - prints it).

The output is deterministic (sorted, no "generated now" time; each source shows when it was collected), so a diff
shows only real changes: regenerate it after every verified change and commit it with that change.
--check renders without writing: exit 0 when OVERVIEW.md is current, 1 when stale, 2 when missing.
Strings from discovery (guest names, tags, banners) are untrusted: escaped for Markdown tables and Mermaid labels.
overview.redact: true in homelab.yaml (a repo that is shared or public) masks IPv4 addresses, MACs, the domain and
the Proxmox endpoint hosts.
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

STORAGE_WARN_PCT = 80
MEM_WARN_PCT = 85
MAP_COLUMNS = 5     # VLANs per column in a site map
STALE_DAYS = 7      # update data this much older than the newest check is marked stale
SOURCES = [  # (discovery file, what writes it)
    ("proxmox.json", "proxmox_inventory.py --details"), ("network.json", "nmap_scan.py"),
    ("unifi.json", "unifi-info.yml"), ("routeros.json", "routeros_audit.py"), ("bmc.json", "bmc-info.yml"),
    ("containers.json", "docker-containers.yml"), ("qnap-containers.json", "qnap-containers.yml"),
    ("updates.json", "check-updates.yml"),
]
# inventory groups whose hosts are network devices / appliances, first match names the kind
DEVICE_KINDS = [("routeros", "RouterOS"), ("unifi", "UniFi"), ("bmc", "BMC"), ("qnap", "QNAP NAS"),
                ("appliances", "Appliance")]
HOST_KINDS = [("proxmox_nodes", "Proxmox node")] + DEVICE_KINDS + [("windows", "Windows")]
CHECK_UPDATES_GROUPS = ("linux", "windows", "qnap", "proxmox_nodes")


# --------------------------------------------------------------------------- escaping

def cell(value) -> str:
    """A Markdown table cell from untrusted text: one line, no HTML, no table or link syntax."""
    s = hmlib.clean("" if value is None else value, 120) or ""
    s = re.sub(r"\s+", " ", s).strip()
    for a, b in (("\\", "\\\\"), ("|", "\\|"), ("<", "&lt;"), (">", "&gt;"), ("[", "\\["), ("]", "\\]"),
                 ("`", "\\`"), ("*", "\\*"), ("_", "\\_")):
        s = s.replace(a, b)
    return s or "–"


def label(value, limit: int = 40) -> str:
    """A Mermaid node label from untrusted text (it goes inside "…")."""
    s = re.sub(r"\s+", " ", hmlib.clean("" if value is None else value, limit) or "")
    return re.sub(r"[\"<>`{}\[\]|;#&]", "'", s).strip() or "?"


def table(head: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return out


def pct(used, size) -> float | None:
    return round(100 * used / size) if isinstance(used, (int, float)) and size else None


def redact(text: str, cfg: dict) -> str:
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", "x.x.x.x", text)
    text = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "xx:xx:xx:xx:xx:xx", text)
    names = {str(hmlib.get(cfg, "site.domain", "") or "")}
    for s in hmlib.sites(cfg):
        for ep in hmlib.endpoint_list((s.get("proxmox") or {}).get("endpoint")):
            m = re.match(r"^\w+://([^:/]+)", ep)
            if m:
                names.add(m.group(1))
    for n in sorted((n for n in names if len(n) > 2), key=len, reverse=True):
        text = text.replace(n, "redacted.example")
    return text


# --------------------------------------------------------------------------- data

def load_json(path: Path) -> dict:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def collected(doc: dict) -> str:
    """The newest collection time in a discovery file (top level, per site, per host)."""
    stamps = []

    def walk(x, depth=0):
        if isinstance(x, dict) and depth < 4:
            for k, v in x.items():
                if k in ("collected_at", "updated_at", "last_seen") and isinstance(v, str):
                    stamps.append(v)
                else:
                    walk(v, depth + 1)
    walk(doc)
    return max(stamps)[:16].replace("T", " ") if stamps else ""


def groups_of(v: dict) -> list[str]:
    return list(v.get("_groups_all") or v.get("groups") or [])


def kind_of(groups, kinds=HOST_KINDS) -> str:
    return next((k for g, k in kinds if g in groups), "")


def is_ip(s) -> bool:
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


def os_top(os) -> str:
    """The best nmap OS match, "name (accuracy%)"; network.json stores a list of {name, accuracy}."""
    if isinstance(os, list):
        best = sorted((m for m in os if isinstance(m, dict) and m.get("name")),
                      key=lambda m: -int(m.get("accuracy") or 0))
        return f"{best[0]['name']} ({best[0].get('accuracy')}%)" if best else ""
    return str(os or "")


def short_version(v) -> str:
    """pve-manager/9.1.11/8eac… → 9.1.11"""
    m = re.search(r"/(\d[\w.\-]*)", str(v or ""))
    return m.group(1) if m else str(v or "")


def stamp(v) -> str:
    return str(v or "")[:10]


def guest_net(g: dict, cfg: dict, site_name: str, prefer_ip: str | None = None,
              vl: list[dict] | None = None) -> tuple[str, int | None, str]:
    """(IP, VLAN tag, VLAN label) of one NIC of a guest (GitHub issue #97). prefer_ip (its inventory ansible_host)
    picks the NIC holding it, or the NIC whose VLAN's CIDR holds it when the snapshot has no addresses."""
    ip, tag = hmlib._guest_net(g, prefer_ip)
    if prefer_ip and ip != prefer_ip:
        tags = [n["tag"] for n in hmlib.guest_nics(g)]
        hit = next((v["id"] for v in vl or [] if v["id"] in tags and in_net(prefer_ip, v.get("cidr"))), None)
        if hit is not None or not any(n["ips"] for n in hmlib.guest_nics(g)):
            ip, tag = prefer_ip, hit if hit is not None else (tag if not tags else None)
    return ip or "", tag, hmlib.vlan_label(cfg, tag, ip, site_name) if (tag is not None or ip) else ""


def onboot(g: dict) -> str:
    v = (g.get("config") or {}).get("onboot")
    return "–" if v is None else ("yes" if str(v) in ("1", "true", "True") else "no")


def backup_uncovered(guests: list[dict], jobs: list[dict]) -> list[dict]:
    """Guests (no templates) in no enabled vzdump job."""
    covered = set()
    for j in jobs:
        if not j.get("enabled"):
            continue
        for g in guests:
            if j.get("node") and g.get("node") != j["node"]:
                continue
            if (j.get("all") and g["vmid"] not in (j.get("exclude") or [])) or g["vmid"] in (j.get("vmid") or []) \
                    or (j.get("pool") and g.get("pool") == j["pool"]):
                covered.add(g["vmid"])
    return [g for g in guests if g["vmid"] not in covered]


def in_net(ip: str, cidr) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return False


def job_name(j: dict, i: int) -> str:
    """A backup job's comment, or its id unless that is a generated hash (GitHub issue #97)."""
    jid = str(j.get("id") or "")
    if j.get("comment"):
        return str(j["comment"])
    return f"job {i}" if not jid or re.fullmatch(r"[0-9a-f]{20,}(:\d+)?|backup-[0-9a-f-]{20,}", jid) else jid


def job_guests(j: dict) -> str:
    if j.get("all"):
        ex = j.get("exclude") or []
        return "all" + (f" except {len(ex)}: " + ", ".join(map(str, ex[:6])) + (" …" if len(ex) > 6 else "") if ex else "")
    if j.get("pool"):
        return f"pool {j['pool']}"
    ids = j.get("vmid") or []
    return f"{len(ids)} listed"


# --------------------------------------------------------------------------- what the repo knows

class Known:
    """Addresses the repository can name (GitHub issue #96): inventory hosts, Proxmox node addresses, guest
    NICs, cluster VIPs, VLAN gateways, UniFi/RouterOS devices, NAS containers. First source wins."""

    def __init__(self):
        self.addr: dict[str, tuple[str, str]] = {}

    def add(self, ip, name, kind):
        ip = str(ip or "").split("/")[0].strip().lower()
        if ip and is_ip(ip) and ip not in self.addr:
            self.addr[ip] = (str(name), kind)

    def name(self, ip) -> str:
        return (self.addr.get(str(ip)) or ("", ""))[0]


def build_known(cfg: dict, docs: dict, managed: dict, snaps: list[dict]) -> Known:
    k = Known()
    for h, v in sorted(managed.items()):
        k.add(v.get("ansible_host"), h, kind_of(groups_of(v)) or "managed host")
        for extra in v.get("hm_extra_ips") or []:
            k.add(extra, h, kind_of(groups_of(v)) or "managed host")
    for px in snaps:
        for node, nets in sorted((px.get("networks") or {}).items()):
            for n in nets or []:
                k.add(n.get("cidr"), node, "Proxmox node")
        for g in px.get("guests") or []:
            for a in hmlib.guest_nic_addresses(g):
                k.add(a["ip"], g.get("name") or g.get("vmid"), "Proxmox guest")
    for c in hmlib.get(cfg, "clusters", []) or []:
        if isinstance(c, dict) and c.get("vip"):
            k.add(c["vip"], f"{c.get('name')} VIP", "cluster VIP")
    for v in hmlib.vlans(cfg):
        if is_ip(v.get("gw")):
            k.add(v["gw"], f"VLAN {v['id']} gateway", "gateway")
    for part in (hmlib_parts(docs["unifi.json"])):
        for d in part.get("devices") or []:
            k.add(d.get("ipAddress"), d.get("name") or d.get("model"), "UniFi")
    for host, d in (docs["routeros.json"].get("devices") or {}).items():
        ros_name = (hmlib.inventory_host(managed, host) or ((d.get("identity") or {}).get("name") or host,))[0]
        k.add(host, ros_name, "RouterOS")
        for a in d.get("addresses") or []:      # every interface address the audit read
            k.add(a.get("address"), ros_name, "RouterOS")
    for nas, d in (docs["qnap-containers.json"] or {}).items():
        for c in (d or {}).get("lxd") or [] if isinstance(d, dict) else []:
            k.add(str(c.get("ipv4") or "").split(" ")[0], f"{c.get('name')} (on {nas})", "NAS container")
    named = hmlib.known_devices(cfg)   # discovery.ignore_unmanaged entries with a name (GitHub issue #100)
    for e in named:
        k.add(e["ip"], e["name"], "known device")
    by_mac = {e["mac"]: e for e in named if e["mac"]}
    # an address whose nmap / ssh_probe hostname is a known host's name is that host's (another NIC)
    names = {n.lower(): kind for n, kind in k.addr.values()}
    for part in hmlib_parts(docs["network.json"]):
        for ip, h in sorted((part.get("hosts") or {}).items()):
            if str(h.get("mac") or "").lower() in by_mac:   # a known device at a new (DHCP) address
                k.add(ip, by_mac[str(h["mac"]).lower()]["name"], "known device")
                continue
            for hn in [(h.get("ssh_probe") or {}).get("hostname")] + list(h.get("hostnames") or []):
                short = str(hn or "").split(".")[0].lower()
                if short in names:
                    k.add(ip, short, names[short])
                    break
    return k


def hmlib_parts(doc: dict) -> list[dict]:
    """Per-site parts of a discovery file ({sites: {key: part}}) or the file itself when it has no sites."""
    sites = doc.get("sites")
    return [p for p in sites.values() if isinstance(p, dict)] if isinstance(sites, dict) else [doc]


def device_rows(cfg: dict, st: dict, docs: dict, managed: dict, net: dict, unifi: dict) -> list[dict]:
    """Network devices of a site (GitHub issue #94): inventory hosts in the device groups first, enriched from
    routeros.json, unifi.json, bmc.json, updates.json (QNAP) and nmap; then discovered devices not in the
    inventory."""
    ros = docs["routeros.json"].get("devices") or {}
    ros_by_name = {(d.get("identity") or {}).get("name"): (h, d) for h, d in ros.items()}
    udevs = list(unifi.get("devices") or [])
    bmc = docs["bmc.json"].get("hosts") or {}
    upd = docs["updates.json"].get("hosts") or {}
    scanned = net.get("hosts") or {}
    rows, used_ros, used_unifi = [], set(), set()
    for h, v in sorted(managed.items()):
        groups = groups_of(v)
        kind = kind_of(groups, DEVICE_KINDS)
        if not kind:
            continue
        s = hmlib.target_site(cfg, managed, h)
        if (s or {}).get("name", "") != st["name"] and not (s is None and st["default"]):
            continue
        addr = str(v.get("ansible_host") or "")
        r = {"kind": kind, "name": h, "model": "", "address": addr, "firmware": "", "state": "",
             "seen": stamp((scanned.get(addr) or {}).get("last_seen"))}
        if kind == "RouterOS":
            key, d = (addr, ros[addr]) if addr in ros else ros_by_name.get(h, (None, None))
            if d:
                used_ros.add(key)
                res, rb = d.get("resource") or {}, d.get("routerboard") or {}
                ident = (d.get("identity") or {}).get("name")
                r.update(model=rb.get("model") or res.get("board-name") or "", firmware=res.get("version") or "",
                         state=(f"{len(d['findings'])} audit findings" if d.get("findings") else "audited, no findings")
                         + f" ({stamp(d.get('collected_at'))})"
                         + (f", identity {ident}" if ident and ident != h else ""))
            else:
                r["state"] = "not audited (routeros_audit.py)"
        elif kind == "UniFi":
            d = next((d for d in udevs if d.get("ipAddress") == addr or d.get("name") == h), None)
            if d:
                used_unifi.add(id(d))
                r.update(model=d.get("model") or "", firmware=d.get("firmwareVersion") or "", state=d.get("state") or "")
            else:
                r["state"] = "no data (unifi-info.yml)"
        elif kind == "BMC":
            d = bmc.get(h)
            if d:
                bad = d.get("not_ok") or []
                r.update(model=d.get("model") or "", firmware=d.get("bmc_firmware") or "",
                         state=f"health {d.get('health') or '?'}, power {d.get('power_state') or '?'}"
                         + (f", not OK: {', '.join(map(str, bad))}" if bad else "") + f" ({stamp(d.get('collected_at'))})")
            else:
                r["state"] = "no data (bmc-info.yml)"
        elif kind == "QNAP NAS":
            d = upd.get(h) or {}
            fw = d.get("firmware") or {}
            r.update(model=fw.get("model") or "", firmware=d.get("os") or fw.get("version") or "",
                     state=(f"{d.get('pending')} app updates" if d.get("pending") else "up to date")
                     + f" ({stamp(d.get('collected_at'))})" if d else "no data (check-updates.yml)")
        else:
            r["model"] = os_top((scanned.get(addr) or {}).get("os"))
        rows.append(r)
    for d in sorted(udevs, key=lambda d: (str(d.get("name")), str(d.get("ipAddress")))):
        if id(d) not in used_unifi:
            rows.append({"kind": "UniFi", "name": d.get("name") or "", "model": d.get("model") or "",
                         "address": d.get("ipAddress") or "", "firmware": d.get("firmwareVersion") or "",
                         "state": (d.get("state") or "") + ", not in inventory",
                         "seen": stamp((scanned.get(d.get("ipAddress")) or {}).get("last_seen"))})
    for host, d in sorted(ros.items()):
        s = hmlib.site_of_address(cfg, host)
        if host in used_ros or not ((s or {}).get("name", "") == st["name"] or (s is None and st["default"])):
            continue
        res = d.get("resource") or {}
        rows.append({"kind": "RouterOS", "name": (d.get("identity") or {}).get("name") or host,
                     "model": (d.get("routerboard") or {}).get("model") or res.get("board-name") or "",
                     "address": host, "firmware": res.get("version") or "",
                     "state": f"{len(d.get('findings') or [])} audit findings, not in inventory",
                     "seen": stamp((scanned.get(host) or {}).get("last_seen"))})
    inventory = {str(v.get("ansible_host") or "") for v in managed.values()}
    for e in hmlib.known_devices(cfg):   # named in discovery.ignore_unmanaged (GitHub issue #100)
        if e["site"] != st["name"] or e["ip"] in inventory:
            continue
        h = scanned.get(e["ip"]) or next((h for h in scanned.values()
                                          if e["mac"] and str(h.get("mac") or "").lower() == e["mac"]), {})
        moved = h.get("ip") if h.get("ip") and h.get("ip") != e["ip"] else None
        rows.append({"kind": "Known device", "name": e["name"], "model": "", "address": e["ip"], "firmware": "",
                     "state": "not managed" + (f", MAC {e['mac']}" if e["mac"] else "")
                     + (f", seen at {moved}" if moved else ""), "seen": stamp(h.get("last_seen"))})
    return rows


# --------------------------------------------------------------------------- sections

def sources(root: Path, docs: dict) -> list[str]:
    rows = []
    for name, cmd in SOURCES:
        f = root / "discovery" / name
        rows.append([f"discovery/{name}", collected(docs[name]) or ("present, no time" if f.is_file() else "–"),
                     cmd if not f.is_file() else ""])
    for extra in ("drift.md", "guest-map.md"):
        rows.append([f"discovery/{extra}", "present" if (root / "discovery" / extra).is_file() else "–", ""])
    return ["## Sources", "", "When each source was last collected (UTC). Older data is less reliable; refresh it with the "
            "command shown when it is missing.", ""] + table(["File", "Collected", "Missing: run"], rows)


def site_map(st: dict, px: dict, vl: list[dict], guests_by: dict, gateways: dict, devices: list[dict],
             used: dict) -> list[str]:
    """Mermaid flowchart of one site (GitHub issue #93), roughly as wide as tall: Proxmox nodes on the left with
    guest counts per VLAN; VLANs grouped under their gateway (network.vlans[].gw), MAP_COLUMNS per column;
    devices grouped per VLAN by address; VLANs with no guests, addresses or devices folded into one node."""
    p = re.sub(r"\W", "_", st["name"] or "default")
    lines = ["```mermaid", "flowchart LR"]
    per_node = {}
    tags_used = set()
    for n in sorted(px.get("nodes") or [], key=lambda n: n.get("node") or ""):
        per_vlan: dict = {}
        for g in guests_by.get(n.get("node"), []):
            per_vlan[g["_tag"]] = per_vlan.get(g["_tag"], 0) + 1
        per_node[n.get("node")] = per_vlan
        tags_used |= set(per_vlan)
    dev_by_vlan: dict = {}
    for d in devices:
        vid = next((v["id"] for v in vl if d["address"] and in_net(d["address"], v.get("cidr"))), None)
        dev_by_vlan.setdefault(vid, []).append(d)
    active = [v for v in vl if v["id"] in tags_used or used.get(v["id"]) or v["id"] in dev_by_vlan]
    idle = [v for v in vl if v not in active]
    by_gw: dict = {}
    for v in active:
        by_gw.setdefault(gateways.get(v["id"]) or "", []).append(v)
    for i, (gw, vs) in enumerate(sorted(by_gw.items(), key=lambda x: (x[0] == "", x[0]))):
        if gw:
            lines.append(f'  subgraph {p}_g{i}["gateway {label(gw)}"]')
        for v in vs:
            text = " ".join(label(x) for x in (v.get("name"), v.get("cidr")) if x)
            lines.append(f'{"    " if gw else "  "}{p}_v{v["id"]}(["VLAN {v["id"]}{" " + text if text else ""}"])')
        for a, b in zip(vs, vs[MAP_COLUMNS:]):   # invisible links wrap the VLANs into columns (not one long strip)
            lines.append(f'{"    " if gw else "  "}{p}_v{a["id"]} ~~~ {p}_v{b["id"]}')
        if gw:
            lines.append("  end")
    known = {v["id"] for v in vl}
    for i, n in enumerate(sorted(px.get("nodes") or [], key=lambda n: n.get("node") or "")):
        per_vlan = per_node[n.get("node")]
        lines.append(f'  {p}_n{i}["Proxmox {label(n.get("node"))} ({sum(per_vlan.values())} guests)"]')
        for tag, count in sorted(per_vlan.items(), key=lambda x: (x[0] is None, x[0] or 0)):
            if tag is None:
                lines.append(f'  {p}_n{i} -->|"{count} untagged"| {p}_untagged(["untagged / native"])')
            else:
                if tag not in known:
                    lines.append(f'  {p}_v{tag}(["VLAN {tag} (not in network.vlans)"])')
                    known.add(tag)
                lines.append(f'  {p}_n{i} -->|"{count}"| {p}_v{tag}')
    for vid, ds in sorted(dev_by_vlan.items(), key=lambda x: (x[0] is None, x[0] or 0)):
        names = ", ".join(sorted(d["name"] for d in ds))
        node = f"{p}_d{vid if vid is not None else 'x'}"
        lines.append(f'  {node}["{len(ds)} device{"s" if len(ds) != 1 else ""}: {label(names, 80)}"]')
        if vid is not None:
            lines.append(f"  {p}_v{vid} -.- {node}")
    if idle:
        lines.append(f'  {p}_idle(["{len(idle)} VLANs without guests or addresses: '
                     f'{label(", ".join(str(v["id"]) for v in idle), 60)}"])')
    if len(lines) == 2:
        lines.append(f'  {p}_empty["no data yet"]')
    return lines + ["```"]


def sites_map(rows: list[tuple[dict, int, int, int]]) -> list[str]:
    lines = ["```mermaid", "flowchart LR"]
    for i, (st, nodes, guests, vlans) in enumerate(rows):
        lines.append(f'  s{i}["{label(hmlib.site_title(st) or "default", 60)}<br/>{nodes} nodes, {guests} guests, '
                     f'{vlans} VLANs"]')
    lines += [f"  s0 --- s{i}" for i in range(1, len(rows))]
    return lines + ["```"]


def site_section(cfg: dict, st: dict, docs: dict, managed: dict, known: Known) -> tuple[list[str], dict]:
    root = Path(cfg["_root"])
    title = hmlib.site_title(st) or "default"
    px = hmlib.site_part(hmlib.proxmox_snapshot_file(root), st) or {}
    net = hmlib.site_part(hmlib.network_file(root), st) or {}
    unifi = hmlib.site_part(hmlib.discovery_file(root, "unifi"), st) or {}
    vl = sorted(hmlib.vlans(cfg, st["name"]), key=lambda v: v["id"])
    guests = [g for g in px.get("guests") or [] if not g.get("template") and isinstance(g.get("vmid"), int)]
    templates = [g for g in px.get("guests") or [] if g.get("template")]
    guests_by: dict = {}
    for g in guests:
        prefer = str((managed.get(g.get("name")) or {}).get("ansible_host") or "") or None
        g["_ip"], g["_tag"], g["_vlan"] = guest_net(g, cfg, st["name"], prefer if is_ip(prefer) else None, vl)
        guests_by.setdefault(g.get("node"), []).append(g)
    devices = device_rows(cfg, st, docs, managed, net, unifi)
    stats = {"nodes": len(px.get("nodes") or []), "guests": len(guests), "vlans": len(vl), "warnings": []}

    out = [f"## Site: {cell(title)}", ""]
    facts = []
    if st["default"]:
        for k, name in (("site.domain", "domain"), ("network.gateway", "gateway"), ("network.dns_servers", "DNS")):
            v = hmlib.get(cfg, k)
            if v:
                facts.append(f"{name} {cell(', '.join(map(str, v)) if isinstance(v, list) else v)}")
    if st["ranges"]:   # a long list would be cut mid-address (GitHub issue #97)
        facts.append("ranges " + cell(", ".join(str(n) for n in st["ranges"])) if len(st["ranges"]) <= 4
                     else f"{len(st['ranges'])} address ranges (homelab.yaml)")
    if px:
        cl = px.get("cluster")
        facts.append(f"Proxmox VE {cell(px.get('version'))}, " + (
            f"cluster {cell(cl.get('name'))} (quorate: {'yes' if cl.get('quorate') else 'NO'})" if cl else "standalone"))
    if facts:
        out += ["; ".join(facts) + ".", ""]

    # network
    scanned = sorted((net.get("hosts") or {}).items(), key=lambda x: tuple(int(o) for o in x[0].split("."))
                     if re.fullmatch(r"\d+(\.\d+){3}", x[0]) else (999,))
    guest_ips = {g["_ip"] for g in guests if g["_ip"]}
    used, rows = {}, []
    for v in vl:
        addrs = {ip for ip, _ in scanned if in_net(ip, v.get("cidr"))} | {ip for ip in guest_ips if in_net(ip, v.get("cidr"))}
        used[v["id"]] = len(addrs)
        try:
            size = max(ipaddress.ip_network(str(v.get("cidr")), strict=False).num_addresses - 2, 1)
        except ValueError:
            size = None
        rows.append([v["id"], v.get("name"), v.get("cidr"), v.get("gw"),
                     len([g for g in guests if g["_tag"] == v["id"] or (g["_tag"] is None and g["_ip"]
                                                                          and in_net(g["_ip"], v.get("cidr")))]),
                     f"{len(addrs)}/{size}" if size else len(addrs)])
    gateways = {v["id"]: (known.addr.get(v["gw"], ("", ""))[0] if known.addr.get(v["gw"], ("", ""))[1] != "gateway"
                          else "") or v["gw"] if is_ip(v.get("gw")) else v.get("gw") for v in vl if v.get("gw")}
    out += ["### Map", ""] + site_map(st, px, vl, guests_by, gateways, devices, used) + [""]
    if vl:
        out += ["### Network", ""] + table(["VLAN", "Name", "CIDR", "Gateway", "Guests", "Addresses used"], rows) + [""]

    # Proxmox
    if px:
        rows = []
        for n in sorted(px.get("nodes") or [], key=lambda n: n.get("node") or ""):
            gs = guests_by.get(n.get("node"), [])
            p = pct(n.get("mem_used_gib"), n.get("mem_gib"))
            if p is not None and p >= MEM_WARN_PCT:
                stats["warnings"].append(f"{title}: node {n.get('node')} memory {p}%")
            addrs = [x.get("cidr") for x in (px.get("networks") or {}).get(n.get("node"), []) if x.get("cidr")]
            rows.append([n.get("node"), n.get("status"), short_version(n.get("pveversion")), n.get("kernel"), n.get("cpus"),
                         f"{n.get('mem_used_gib')}/{n.get('mem_gib')} GiB" + (f" ({p}%)" if p is not None else ""),
                         f"{sum(1 for g in gs if g.get('status') == 'running')}/{len(gs)}", ", ".join(sorted(addrs))])
        head = ["Node", "Status", "PVE", "Kernel", "CPUs", "Memory", "Guests running", "Addresses"]
        if not any(n.get("pveversion") or n.get("kernel") for n in px.get("nodes") or []):   # snapshot before 0.34.0
            head, rows = head[:2] + head[4:], [r[:2] + r[4:] for r in rows]
        out += ["### Proxmox nodes", ""] + table(head, rows) + [""]
        rows, seen = [], set()
        for s in sorted(px.get("storage") or [], key=lambda s: (s.get("storage") or "", s.get("node") or "")):
            key = s.get("storage") if s.get("shared") else (s.get("storage"), s.get("node"))
            if key in seen:
                continue
            seen.add(key)
            p = pct(s.get("used_gib"), s.get("size_gib"))
            if p is not None and p >= STORAGE_WARN_PCT:
                stats["warnings"].append(f"{title}: storage {s.get('storage')}"
                                         + ("" if s.get("shared") else f" on {s.get('node')}") + f" {p}% full")
            rows.append([s.get("storage"), "shared" if s.get("shared") else s.get("node"), s.get("type"),
                         f"{s.get('used_gib')}/{s.get('size_gib')} GiB", "–" if p is None else
                         f"{p}%" + (" ⚠" if p >= STORAGE_WARN_PCT else ""), s.get("content")])
        out += ["### Storage", ""] + table(["Storage", "Node", "Type", "Used", "Full", "Content"], rows) + [""]

        rows = [[g["vmid"], g.get("name"), g.get("type"), g.get("node"), g.get("status"), g.get("cpus"),
                 g.get("mem_gib"), g.get("disk_gib"), g["_vlan"], g["_ip"], onboot(g), "yes" if g.get("hastate") else "",
                 g.get("tags")] for g in sorted(guests, key=lambda g: g["vmid"])]
        out += ["### Guests", ""] + (table(["VMID", "Name", "Type", "Node", "Status", "vCPU", "RAM GiB", "Disk GiB", "VLAN",
                                            "IP", "Autostart", "HA", "Tags"], rows) if rows else ["No guests."])
        if templates:
            out += ["", f"Templates: {len(templates)} (" + ", ".join(cell(t.get("name")) for t in
                                                                    sorted(templates, key=lambda t: t["vmid"])) + ")."]
        if not any("config" in g for g in guests) and guests:
            out += ["", "VLAN, IP and autostart need `proxmox_inventory.py --details`."]
        out.append("")

        jobs = px.get("backup_jobs")
        out += ["### Backups", ""]
        if jobs is None:
            out += ["The backup jobs could not be read (the read-only token needs Sys.Audit on /).", ""]
        else:
            rows = [[job_name(j, i), "yes" if j.get("enabled") else "no", j.get("schedule"), j.get("storage"),
                     job_guests(j), j.get("node") or "all"]
                    for i, j in enumerate(sorted(jobs, key=lambda j: str(j.get("id"))), 1)]
            out += (table(["Job", "Enabled", "Schedule", "Storage", "Guests", "Node"], rows) if rows
                    else ["No scheduled backup jobs."])
            missing = backup_uncovered(guests, jobs)
            if missing:
                stats["warnings"].append(f"{title}: {len(missing)} guests in no enabled backup job")
                out += ["", f"In no enabled backup job ({len(missing)} of {len(guests)}): "
                        + ", ".join(f"{g['vmid']} {cell(g.get('name'))}" for g in sorted(missing, key=lambda g: g["vmid"]))
                        + "."]
            out.append("")

    # devices
    if devices:
        out += ["### Network devices", ""] + table(
            ["Kind", "Name", "Model", "Address", "Firmware", "State", "Last seen"],
            [[d["kind"], d["name"], d["model"], d["address"], d["firmware"], d["state"], d["seen"]] for d in devices]) + [""]
    other = [(ip, h) for ip, h in scanned if ip not in guest_ips and not known.name(ip)]
    named = len(scanned) - len([1 for ip, _ in scanned if ip in guest_ips]) - len(other)
    if other:
        out += ["### Other scanned addresses", "", "Addresses nmap found that nothing in this repository names"
                + (f" ({named} more belong to known hosts: Proxmox nodes, inventory hosts, guests, VIPs)" if named else "")
                + ". A known host's address on another network goes into its `hm_extra_ips` host variable.", ""]
        out += table(["Address", "Name", "Looks like", "OS", "Open ports", "Last seen"],
                     [[ip, (h.get("ssh_probe") or {}).get("hostname") or ", ".join(h.get("hostnames") or []),
                       h.get("device_type_guess"), os_top(h.get("os")), len(h.get("ports") or []), stamp(h.get("last_seen"))]
                      for ip, h in other]) + [""]
    return out, stats


def compose(c: dict) -> str:
    """Where a container's Compose project lives (GitHub issue #102): its working directory, else its project."""
    return str(c.get("compose_working_dir") or c.get("compose_project") or "")


def containers(cfg: dict, docs: dict, managed: dict) -> list[str]:
    rows = []
    for host, d in sorted((docs["containers.json"].get("hosts") or {}).items()):
        for c in sorted(d.get("containers") or [], key=lambda c: str(c.get("name"))):
            ports = c.get("ports")
            rows.append([host, d.get("site"), c.get("name"), c.get("image"),
                         ", ".join(map(str, ports)) if isinstance(ports, list) else ports, compose(c)])
        for k in d.get("kubernetes") or []:
            rows.append([host, d.get("site"), "Kubernetes", k if isinstance(k, str) else json.dumps(k, sort_keys=True), "", ""])
    for nas, d in sorted((docs["qnap-containers.json"] or {}).items()):   # GitHub issue #97
        if not isinstance(d, dict):
            continue
        site = (hmlib.target_site(cfg, managed, nas) or {}).get("name") if managed else ""
        for c in sorted(d.get("docker") or [], key=lambda c: str(c.get("name"))):
            nets = c.get("networks")
            rows.append([nas, site, c.get("name"), c.get("image"),
                         ", ".join(map(str, nets)) if isinstance(nets, list) else nets, compose(c)])
        for c in sorted(d.get("lxd") or [], key=lambda c: str(c.get("name"))):
            rows.append([nas, site, c.get("name"), f"LXD ({c.get('state') or '?'})", c.get("ipv4"), ""])
    if not rows:
        return []
    return ["## Containers", ""] + table(["Host", "Site", "Container", "Image", "Ports / network", "Compose"], rows) + [""]


def management(cfg: dict, managed: dict, note: str) -> list[str]:
    out = ["## Management", ""]
    if managed:
        groups: dict = {}
        for h, v in managed.items():
            for g in v.get("_groups_all") or v.get("groups") or []:
                if g not in ("all", "ungrouped"):
                    groups.setdefault(g, set()).add(h)
        out += ["Ansible groups (managed inventory):", ""]
        out += table(["Group", "Hosts", "Members"], [[g, len(hs), ", ".join(sorted(hs)[:12]) + (" …" if len(hs) > 12 else "")]
                                                    for g, hs in sorted(groups.items())]) + [""]
        approval = sorted(h for h, v in managed.items() if v.get("patch_requires_approval"))
        if approval:
            out += ["Critical hosts (patched one at a time, each with its own yes): " + ", ".join(cell(h) for h in approval)
                    + ".", ""]
    else:
        out += [f"Ansible inventory not read ({cell(note)}).", ""]
    cl = [c for c in hmlib.get(cfg, "clusters", []) or [] if isinstance(c, dict)]
    if cl:
        out += ["Clusters (changed one host at a time):", ""]
        out += table(["Name", "Ansible group", "Order", "Reboot", "VIP"],
                     [[c.get("name"), c.get("ansible_group"), c.get("order"), c.get("reboot"), c.get("vip")]
                      for c in sorted(cl, key=lambda c: str(c.get("name")))]) + [""]
    return out


def drift_summary(root: Path) -> str:
    """One line from discovery/drift.md (GitHub issue #97): its bold counts and unmanaged devices."""
    f = root / "discovery" / "drift.md"
    if not f.is_file():
        return ""
    text = f.read_text(errors="replace")
    counts: dict = {}
    for name, n in re.findall(r"\*\*([^*()]+?) \((\d+)\)\*\*", text):
        counts[name.strip()] = counts.get(name.strip(), 0) + int(n)
    dev = sum(int(n) for n in re.findall(r"^(\d+) device\(s\)", text, re.M))
    total = re.search(r"\*\*Total findings: (\d+)\*\*", text)
    when = re.search(r"^# Drift report — (.+)$", text, re.M)
    parts = [f"{n} {k[0].lower() + k[1:]}" for k, n in sorted(counts.items())]
    if dev:
        parts.append(f"{dev} network devices not in the inventory")
    if not (total or parts):
        return ""
    return (f"Drift{' (' + when.group(1).strip() + ')' if when else ''}: "
            + (f"{total.group(1)} findings" if total else "") + (" — " + "; ".join(parts) if parts else "") + ".")


def health(cfg: dict, root: Path, docs: dict, managed: dict, warnings: list[str]) -> list[str]:
    """Updates of every host that matters (GitHub issue #95): Proxmox nodes and critical hosts always, the rest
    when something is pending; inventory hosts without update data named; BMC, RouterOS, drift."""
    out = ["## Health", ""]
    upd = docs["updates.json"].get("hosts") or {}
    if upd:
        newest = max((str(d.get("collected_at") or "") for d in upd.values()), default="")[:10]

        def checked(d):
            c = stamp(d.get("collected_at"))
            try:
                old = (dt_date(newest) - dt_date(c)).days >= STALE_DAYS
            except ValueError:
                old = False
            return c + (" (stale)" if old else "")
        important = {h for h, v in managed.items()
                     if "proxmox_nodes" in groups_of(v) or v.get("patch_requires_approval")}
        pending = {h for h, d in upd.items() if d.get("pending") or d.get("reboot_required") or d.get("error")}
        out.append(f"Updates: {len(upd) - len(pending)} of {len(upd)} checked hosts up to date"
                   + (f" (newest check {newest})" if newest else "") + ".")
        show = sorted((pending | important) & set(upd))
        if show:
            out += [""] + table(["Host", "OS", "Kernel", "Pending", "Security", "Reboot needed", "Checked", "Status"],
                                [[h, upd[h].get("os"), upd[h].get("kernel"), upd[h].get("pending"), upd[h].get("security"),
                                  "yes" if upd[h].get("reboot_required") else "", checked(upd[h]),
                                  upd[h].get("error") or ("up to date" if h not in pending else "updates pending")]
                                 for h in show])
        missing = sorted(h for h in important if h not in upd)
        if managed:
            nocheck = sorted(h for h, v in managed.items() if h not in upd
                             and set(groups_of(v)) & set(CHECK_UPDATES_GROUPS) and not kind_of(groups_of(v), DEVICE_KINDS))
            other = sorted(h for h, v in managed.items() if h not in upd and h not in nocheck)
            if nocheck:
                out += ["", "Not checked yet (`check-updates.yml`): " + ", ".join(cell(h) for h in nocheck) + "."]
            if other:
                out += ["", "Not covered by `check-updates.yml` (see Network devices): " + ", ".join(cell(h) for h in other) + "."]
        elif missing:
            out += ["", "Not checked: " + ", ".join(cell(h) for h in missing) + "."]
        out.append("")
    bmc = docs["bmc.json"].get("hosts") or {}
    if bmc:
        out += ["BMC health: " + ", ".join(f"{cell(h)} {cell(d.get('health') or '?')}"
                                          + (f" (not OK: {cell(', '.join(map(str, d.get('not_ok'))))})" if d.get("not_ok") else "")
                                          for h, d in sorted(bmc.items())) + ".", ""]
    devs = docs["routeros.json"].get("devices") or {}
    ros = [(h, f) for h, d in sorted(devs.items()) for f in d.get("findings") or []]
    if ros:
        sev: dict = {}
        for _, f in ros:
            sev[str(f.get("severity"))] = sev.get(str(f.get("severity")), 0) + 1
        out += ["RouterOS audit findings: " + ", ".join(f"{n} {cell(s)}" for s, n in sorted(sev.items()))
                + " (`routeros_audit.py`).", ""]
    newer = [(h, (d.get("update") or {})) for h, d in sorted(devs.items())
             if (d.get("update") or {}).get("latest-version") and (d.get("update") or {}).get("latest-version")
             != (d.get("update") or {}).get("installed-version")]
    if newer:
        out += ["RouterOS updates available: " + ", ".join(
            f"{cell(known_name(devs, h))} {cell(u.get('installed-version'))} → {cell(u.get('latest-version'))}"
            for h, u in newer) + ".", ""]
    if warnings:
        out += ["Capacity and coverage:", ""] + [f"- {cell(w)}" for w in sorted(warnings)] + [""]
    drift = drift_summary(root)
    if drift:
        out += [drift, ""]
    links = []
    if (root / "discovery" / "drift.md").is_file():
        links.append("[drift report](discovery/drift.md)")
    audits = sorted((root / "docs").glob("security-audit-*.md")) if (root / "docs").is_dir() else []
    if audits:
        links.append(f"[latest security audit](docs/{audits[-1].name})")
    if (root / "discovery" / "guest-map.md").is_file():
        links.append("[guest network map](discovery/guest-map.md)")
    if links:
        out += ["Details: " + ", ".join(links) + ".", ""]
    return out if len(out) > 2 else []


def known_name(devs: dict, host: str) -> str:
    return ((devs.get(host) or {}).get("identity") or {}).get("name") or host


def dt_date(s: str):
    import datetime as dt
    return dt.date.fromisoformat(s[:10])


def render(cfg: dict, managed: dict, note: str) -> str:
    root = Path(cfg["_root"])
    docs = {name: load_json(root / "discovery" / name) for name, _ in SOURCES}
    name = hmlib.get(cfg, "site.name", "") or "homelab"
    out = [f"# {cell(name)} — overview", "",
           "Generated by the homelab-manager skill (`overview.py`) from the files in this repository: don't edit it by "
           "hand, it is regenerated after every change. Nothing here was checked live; see Sources for how old each "
           "part is.", ""]
    st_list = hmlib.sites(cfg)
    snaps = [hmlib.site_part(hmlib.proxmox_snapshot_file(root), st) or {} for st in st_list]
    known = build_known(cfg, docs, managed, snaps)
    body, rows, warnings = [], [], []
    totals = {"nodes": 0, "guests": 0}
    for st in st_list:
        sec, stats = site_section(cfg, st, docs, managed, known)
        body += sec
        rows.append((st, stats["nodes"], stats["guests"], stats["vlans"]))
        warnings += stats["warnings"]
        totals["nodes"] += stats["nodes"]
        totals["guests"] += stats["guests"]
    glance = [f"{len(st_list)} site{'s' if len(st_list) != 1 else ''}", f"{totals['nodes']} Proxmox nodes",
              f"{totals['guests']} guests"]
    if managed:
        glance.append(f"{len(managed)} Ansible hosts")
    out += ["## At a glance", "", ", ".join(glance) + "."]
    if warnings:
        out.append(f"{len(warnings)} warning{'s' if len(warnings) != 1 else ''} under Health.")
    out.append("")
    if len(st_list) > 1:
        out += ["## Sites", ""] + sites_map(rows) + [""]
    out += body + containers(cfg, docs, managed) + management(cfg, managed, note) + health(cfg, root, docs, managed, warnings)
    out += sources(root, docs) + [""]
    text = "\n".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return redact(text, cfg) if hmlib.get(cfg, "overview.redact", False) is True else text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="write here instead of OVERVIEW.md in the repository root (- prints it)")
    ap.add_argument("--check", action="store_true", help="exit 0 when OVERVIEW.md is current, 1 stale, 2 missing")
    ap.add_argument("--no-ansible", action="store_true", help="don't read the Ansible inventory")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        hmlib.sites(cfg)
    except hmlib.ConfigError as e:
        print(f"overview: {e}", file=sys.stderr)
        return 3
    root = Path(cfg["_root"])
    managed, note = ({}, "--no-ansible") if a.no_ansible else load_ansible(root)
    text = render(cfg, managed, note)
    target = Path(a.out) if a.out and a.out != "-" else root / "OVERVIEW.md"
    if a.check:
        if not target.is_file():
            print(f"{target.name} missing — run overview.py")
            return 2
        fresh = target.read_text() == text
        print("fresh: OVERVIEW.md matches the repository data" if fresh
              else "stale: OVERVIEW.md differs from the repository data — run overview.py and commit it")
        return 0 if fresh else 1
    if a.out == "-":
        sys.stdout.write(text)
        return 0
    target.write_text(text)
    print(f"Wrote {target.relative_to(root) if target.is_relative_to(root) else target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
