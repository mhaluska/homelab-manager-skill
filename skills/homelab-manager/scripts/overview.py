#!/usr/bin/env python3
"""OVERVIEW.md: one readable page about the whole homelab, every site, with Mermaid maps (read-only).

    overview.py [--out FILE|-] [--check] [--no-ansible]

Renders what the repository already holds and contacts nothing (GitHub issue #87): homelab.yaml (sites,
network.vlans, clusters), discovery/proxmox.json (nodes, storage, guests, backup jobs), network.json (scanned
addresses), unifi.json, routeros.json, bmc.json, containers.json, updates.json, the managed Ansible inventory
(`ansible-inventory --list`; --no-ansible skips it), discovery/drift.md and the newest docs/security-audit-*.md.
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
SOURCES = [  # (discovery file, what writes it)
    ("proxmox.json", "proxmox_inventory.py --details"), ("network.json", "nmap_scan.py"),
    ("unifi.json", "unifi-info.yml"), ("routeros.json", "routeros_audit.py"), ("bmc.json", "bmc-info.yml"),
    ("containers.json", "docker-containers.yml"), ("updates.json", "check-updates.yml"),
]


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
        m = re.match(r"^\w+://([^:/]+)", str((s.get("proxmox") or {}).get("endpoint") or ""))
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


def guest_net(g: dict, cfg: dict, site_name: str) -> tuple[str, int | None, str]:
    """(IP, VLAN tag, VLAN label) of a guest."""
    ip, tag = hmlib._guest_net(g)
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


def site_map(st: dict, px: dict, vl: list[dict], guests_by: dict, routers: list[dict], devices: list[dict]) -> list[str]:
    """Mermaid flowchart of one site: routers → VLANs ← Proxmox nodes (guest counts per VLAN), other devices."""
    p = (st["name"] or "default").replace("-", "_")
    lines = ["```mermaid", "flowchart LR"]
    for i, r in enumerate(routers):
        lines.append(f'  {p}_r{i}["router {label(r["name"])}"]')
    for v in vl:
        text = " ".join(label(x) for x in (v.get("name"), v.get("cidr")) if x)
        lines.append(f'  {p}_v{v["id"]}(["VLAN {v["id"]}{" " + text if text else ""}"])')
        for i, _ in enumerate(routers):
            lines.append(f"  {p}_r{i} --- {p}_v{v['id']}")
    known = {v["id"] for v in vl}
    for i, n in enumerate(sorted(px.get("nodes") or [], key=lambda n: n.get("node") or "")):
        gs = guests_by.get(n.get("node"), [])
        lines.append(f'  {p}_n{i}["Proxmox {label(n.get("node"))} ({len(gs)} guests)"]')
        per_vlan: dict = {}
        for g in gs:
            per_vlan[g["_tag"]] = per_vlan.get(g["_tag"], 0) + 1
        for tag, count in sorted(per_vlan.items(), key=lambda x: (x[0] is None, x[0] or 0)):
            if tag is None:
                lines.append(f'  {p}_n{i} -->|"{count} untagged"| {p}_untagged(["untagged / native"])')
            else:
                if tag not in known:
                    lines.append(f'  {p}_v{tag}(["VLAN {tag} (not in network.vlans)"])')
                    known.add(tag)
                lines.append(f'  {p}_n{i} -->|"{count}"| {p}_v{tag}')
    for i, d in enumerate(devices):
        lines.append(f'  {p}_d{i}["{label(d)}"]')
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


def site_section(cfg: dict, st: dict, docs: dict, managed: dict) -> tuple[list[str], dict]:
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
        g["_ip"], g["_tag"], g["_vlan"] = guest_net(g, cfg, st["name"])
        guests_by.setdefault(g.get("node"), []).append(g)
    routers = []
    for host, d in sorted((docs["routeros.json"].get("devices") or {}).items()):
        s = hmlib.site_of_address(cfg, host)
        if (s or {}).get("name", "") == st["name"] or (s is None and st["default"]):
            routers.append({"name": (d.get("identity") or {}).get("name") or host, "host": host,
                            "findings": d.get("findings") or []})
    udev = sorted(unifi.get("devices") or [], key=lambda d: (str(d.get("name")), str(d.get("ipAddress"))))
    devices = [f"UniFi {d.get('name') or d.get('model')}" for d in udev]
    stats = {"nodes": len(px.get("nodes") or []), "guests": len(guests), "vlans": len(vl), "warnings": []}

    out = [f"## Site: {cell(title)}", ""]
    facts = []
    if st["default"]:
        for k, name in (("site.domain", "domain"), ("network.gateway", "gateway"), ("network.dns_servers", "DNS")):
            v = hmlib.get(cfg, k)
            if v:
                facts.append(f"{name} {cell(', '.join(map(str, v)) if isinstance(v, list) else v)}")
    if st["ranges"]:
        facts.append("ranges " + cell(", ".join(str(n) for n in st["ranges"])))
    if px:
        cl = px.get("cluster")
        facts.append(f"Proxmox VE {cell(px.get('version'))}, " + (
            f"cluster {cell(cl.get('name'))} (quorate: {'yes' if cl.get('quorate') else 'NO'})" if cl else "standalone"))
    if facts:
        out += ["; ".join(facts) + ".", ""]
    out += ["### Map", ""] + site_map(st, px, vl, guests_by, routers, devices) + [""]

    # network
    scanned = sorted((net.get("hosts") or {}).items(), key=lambda x: tuple(int(o) for o in x[0].split("."))
                     if re.fullmatch(r"\d+(\.\d+){3}", x[0]) else (999,))
    guest_ips = {g["_ip"] for g in guests if g["_ip"]}
    if vl:
        rows = []
        for v in vl:
            used = {ip for ip, _ in scanned if in_net(ip, v.get("cidr"))} | {ip for ip in guest_ips if in_net(ip, v.get("cidr"))}
            try:
                size = max(ipaddress.ip_network(str(v.get("cidr")), strict=False).num_addresses - 2, 1)
            except ValueError:
                size = None
            rows.append([v["id"], v.get("name"), v.get("cidr"), v.get("gw"),
                         len([g for g in guests if g["_tag"] == v["id"] or (g["_tag"] is None and g["_ip"]
                                                                              and in_net(g["_ip"], v.get("cidr")))]),
                         f"{len(used)}/{size}" if size else len(used)])
        out += ["### Network", ""] + table(["VLAN", "Name", "CIDR", "Gateway", "Guests", "Addresses used"], rows) + [""]

    # Proxmox
    if px:
        rows = []
        for n in sorted(px.get("nodes") or [], key=lambda n: n.get("node") or ""):
            gs = guests_by.get(n.get("node"), [])
            p = pct(n.get("mem_used_gib"), n.get("mem_gib"))
            if p is not None and p >= MEM_WARN_PCT:
                stats["warnings"].append(f"{title}: node {n.get('node')} memory {p}%")
            rows.append([n.get("node"), n.get("status"), n.get("cpus"),
                         f"{n.get('mem_used_gib')}/{n.get('mem_gib')} GiB" + (f" ({p}%)" if p is not None else ""),
                         f"{sum(1 for g in gs if g.get('status') == 'running')}/{len(gs)}"])
        out += ["### Proxmox nodes", ""] + table(["Node", "Status", "CPUs", "Memory", "Guests running"], rows) + [""]
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
            rows = [[j.get("id"), "yes" if j.get("enabled") else "no", j.get("schedule"), j.get("storage"),
                     "all" + (f" except {j.get('exclude')}" if j.get("exclude") else "") if j.get("all")
                     else (f"pool {j.get('pool')}" if j.get("pool") else ", ".join(map(str, j.get("vmid") or []))),
                     j.get("node") or "all"] for j in sorted(jobs, key=lambda j: str(j.get("id")))]
            out += (table(["Job", "Enabled", "Schedule", "Storage", "Guests", "Node"], rows) if rows
                    else ["No scheduled backup jobs."])
            missing = backup_uncovered(guests, jobs)
            if missing:
                stats["warnings"].append(f"{title}: {len(missing)} guests in no enabled backup job")
                out += ["", "In no enabled backup job: " + ", ".join(f"{g['vmid']} {cell(g.get('name'))}"
                                                                      for g in sorted(missing, key=lambda g: g["vmid"])) + "."]
            out.append("")

    # devices
    rows = [["UniFi", d.get("name"), d.get("model"), d.get("ipAddress"), d.get("firmwareVersion"), d.get("state")]
            for d in udev]
    rows += [["RouterOS", r["name"], "", r["host"], "", f"{len(r['findings'])} audit findings" if r["findings"] else ""]
             for r in routers]
    other = [(ip, h) for ip, h in scanned if ip not in guest_ips]
    if rows:
        out += ["### Network devices", ""] + table(["Kind", "Name", "Model", "Address", "Firmware", "State"], rows) + [""]
    if other:
        out += ["### Other scanned addresses", "", "Addresses nmap found that are not Proxmox guests (nodes, physical "
                "devices, appliances).", ""]
        out += table(["Address", "Looks like", "OS", "Open ports", "Last seen"],
                     [[ip, h.get("device_type_guess"), h.get("os"), len(h.get("ports") or []), h.get("last_seen")]
                      for ip, h in other]) + [""]
    return out, stats


def containers(doc: dict) -> list[str]:
    rows = []
    for host, d in sorted((doc.get("hosts") or {}).items()):
        for c in sorted(d.get("containers") or [], key=lambda c: str(c.get("name"))):
            ports = c.get("ports")
            rows.append([host, d.get("site"), c.get("name"), c.get("image"),
                         ", ".join(map(str, ports)) if isinstance(ports, list) else ports])
        for k in d.get("kubernetes") or []:
            rows.append([host, d.get("site"), "Kubernetes", k if isinstance(k, str) else json.dumps(k, sort_keys=True), ""])
    if not rows:
        return []
    return ["## Containers", ""] + table(["Host", "Site", "Container", "Image", "Ports"], rows) + [""]


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


def health(root: Path, docs: dict, warnings: list[str]) -> list[str]:
    out = ["## Health", ""]
    upd = docs["updates.json"].get("hosts") or {}
    if upd:
        pending = {h: d for h, d in upd.items() if d.get("pending") or d.get("reboot_required") or d.get("error")}
        out.append(f"Updates: {len(upd) - len(pending)} of {len(upd)} hosts up to date.")
        if pending:
            out += [""] + table(["Host", "OS", "Pending", "Security", "Reboot needed", "Error"],
                                [[h, d.get("os"), d.get("pending"), d.get("security"),
                                  "yes" if d.get("reboot_required") else "", d.get("error")]
                                 for h, d in sorted(pending.items())])
        out.append("")
    ros = [(h, f) for h, d in sorted((docs["routeros.json"].get("devices") or {}).items()) for f in d.get("findings") or []]
    if ros:
        sev: dict = {}
        for _, f in ros:
            sev[str(f.get("severity"))] = sev.get(str(f.get("severity")), 0) + 1
        out += ["RouterOS audit findings: " + ", ".join(f"{n} {cell(s)}" for s, n in sorted(sev.items()))
                + " (`routeros_audit.py`).", ""]
    if warnings:
        out += ["Capacity and coverage:", ""] + [f"- {cell(w)}" for w in sorted(warnings)] + [""]
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


def render(cfg: dict, managed: dict, note: str) -> str:
    root = Path(cfg["_root"])
    docs = {name: load_json(root / "discovery" / name) for name, _ in SOURCES}
    name = hmlib.get(cfg, "site.name", "") or "homelab"
    out = [f"# {cell(name)} — overview", "",
           "Generated by the homelab-manager skill (`overview.py`) from the files in this repository: don't edit it by "
           "hand, it is regenerated after every change. Nothing here was checked live; see Sources for how old each "
           "part is.", ""]
    st_list = hmlib.sites(cfg)
    body, rows, warnings = [], [], []
    totals = {"nodes": 0, "guests": 0}
    for st in st_list:
        sec, stats = site_section(cfg, st, docs, managed)
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
    out += body + containers(docs["containers.json"]) + management(cfg, managed, note) + health(root, docs, warnings)
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
