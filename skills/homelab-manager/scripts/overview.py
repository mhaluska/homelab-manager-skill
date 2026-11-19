#!/usr/bin/env python3
"""OVERVIEW.md: one readable page about the whole homelab, every site, with Mermaid maps (read-only).

    overview.py [--out FILE|-] [--check] [--no-ansible]

Renders what the repository already holds and contacts nothing (GitHub issue #87): homelab.yaml (sites,
network.vlans, clusters), discovery/proxmox.json (nodes, storage, guests, backup jobs, last backups, subscriptions,
certificates), network.json (scanned addresses, services, TLS certificates), unifi.json, routeros.json (devices,
NAT rules, CHR licences), bmc.json, containers.json, qnap-containers.json, updates.json, the managed
Ansible inventory (`ansible-inventory --list`; --no-ansible skips it), discovery/drift.md and the newest
docs/security-audit-*.md. Network devices and appliances start from the inventory (routeros, unifi, qnap,
appliances groups) and are enriched from the discovery files; BMCs (bmc group) are server hardware, each next to
the server it belongs to (host var bmc_of, else the name bmc-<host>, <host>-bmc or <host>-ipmi; GitHub issue #117); "Other scanned addresses" holds only addresses nothing in the repo names.
Per site also: start order after an outage, what stops when a node, gateway, storage server or NAS goes down, port
forwards and how to reach each host; then expirations (GitHub issue #89).
Writes OVERVIEW.md in the repository root (--out - prints it).

The output is deterministic (sorted, no "generated now" time; each source shows when it was collected; backup ages
and expiries are judged against the newest data, not today), so a diff shows only real changes: regenerate it after
every verified change and commit it with that change.
--check renders without writing: exit 0 when OVERVIEW.md is current, 1 when stale, 2 when missing.
Strings from discovery (guest names, tags, banners) are untrusted: escaped for Markdown tables and Mermaid labels.
overview.redact: true in homelab.yaml (a repo that is shared or public) masks IPv4 addresses, MACs, the domain and
the Proxmox endpoint hosts.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
import pve_node_plan as plan  # noqa: E402
from drift_report import load_ansible  # noqa: E402

STORAGE_WARN_PCT = 80
MEM_WARN_PCT = 85
MAP_COLUMNS = 5     # VLANs per column in a site map
STALE_DAYS = 7      # update data this much older than the newest check is marked stale
FOLD_ROWS = 15      # a longer Guests, Containers or Other scanned addresses table is collapsed (GitHub issue #113)
EXPIRY_WARN_DAYS = 30   # an expiry this close to the newest data is a warning (GitHub issue #89)
BACKUP_MAX_AGE_DAYS = 7   # default overview.backup_max_age_days: an older last backup is a warning (GitHub issue #89)
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

def cell(value, limit: int = 120) -> str:
    """A Markdown table cell from untrusted text: one line, no HTML, no table or link syntax. A list is every item,
    each escaped and length-limited on its own, joined uncut (GitHub issue #115: never a name cut in half)."""
    if isinstance(value, (list, tuple, set)):
        items = [cell(v) for v in value if v not in (None, "")]
        return ", ".join(i for i in items if i != "–") or "–"
    s = hmlib.clean("" if value is None else value, limit) or ""
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


def fold(lines: list[str], rows: int, what: str) -> list[str]:
    """A long table collapsed in <details> with its row count (GitHub issue #113); a short one as it is."""
    if rows <= FOLD_ROWS:
        return lines
    return [f"<details><summary>{plural(rows, what)}</summary>", ""] + lines + ["", "</details>"]


def slug(text: str, seen: dict) -> str:
    """The anchor GitHub (and GitLab) gives a heading: lower case, punctuation dropped, each space a hyphen; a
    repeated one gets -1, -2. Headings here have single spaces between words, so both hosts agree."""
    t = html.unescape(re.sub(r"\\(.)", r"\1", text)).strip().lower()
    t = re.sub(r"[^\w\- ]", "", t).replace(" ", "-")
    base, n = t, seen.get(t, 0)
    while t in seen:
        n += 1
        t = f"{base}-{n}"
    seen[base] = n
    seen[t] = 0
    return t


def contents(text: str) -> str:
    """Replace the TOC marker with a table of contents built from the page's own headings (GitHub issue #113): one
    line per section, a site's sub-sections inline. The sub-sections of a site carry the site in parentheses
    (several sites), dropped from the link text."""
    seen: dict = {}
    toc: list[list] = []
    fence = False
    for line in text.splitlines():
        if line.startswith("```"):
            fence = not fence
        m = None if fence else re.match(r"(#{1,3}) (.+)$", line)
        if not m:
            continue
        level, title = len(m.group(1)), m.group(2)
        anchor = slug(title, seen)
        if level == 2 and title not in ("At a glance", "Contents"):
            toc.append([title, anchor, []])
        elif level == 3 and toc:
            toc[-1][2].append((re.sub(r" \([^()]*\)$", "", title), anchor))
    lines = ["## Contents", ""]
    for title, anchor, subs in toc:
        lines.append(f"- [{title}](#{anchor})" + (" — " + " · ".join(f"[{t}](#{a})" for t, a in subs) if subs else ""))
    return text.replace(TOC_MARK, "\n".join(lines), 1)


TOC_MARK = "<!-- contents -->"


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


GENERIC_OS = re.compile(r"(Linux|FreeBSD|OpenBSD|NetBSD|Microsoft Windows)( [\d.x]+( - [\d.x]+)?)?", re.I)


def os_guess(os) -> str:
    """The best nmap OS match, "name (accuracy%)"; network.json stores a list of {name, accuracy}. Matches tied at
    the top accuracy are common (GitHub issue #105): a vendor/product match ("MikroTik RouterOS 7.2 - 7.5") wins
    over a generic one ("Linux 5.0 - 5.14"); tied product matches are all shown, tied generic ones as "or similar"."""
    if not isinstance(os, list):
        return str(os or "")
    ms = [m for m in os if isinstance(m, dict) and m.get("name")]
    if not ms:
        return ""
    top = max(int(m.get("accuracy") or 0) for m in ms)
    tied = [str(m["name"]) for m in ms if int(m.get("accuracy") or 0) == top]
    specific = [n for n in tied if not GENERIC_OS.fullmatch(n)]
    text = " / ".join(specific) if specific else tied[0] + (" or similar" if len(tied) > 1 else "")
    return f"{text} ({top}%)"


def ssh_model(sp: dict) -> str:
    """What ssh_probe.py read about a device (GitHub issue #104): its product (OPNsense, TrueNAS, PVE) or OS name,
    else hostname, kernel and architecture (a JetKVM: "jetkvm-x · Linux 5.10.160 armv7l")."""
    sp = sp if isinstance(sp, dict) else {}
    arch = str(sp.get("arch") or "")
    name = sp.get("product") or sp.get("os_name") or (f"FreeBSD {sp['os_freebsd']}" if sp.get("os_freebsd") else "")
    if name:
        return str(name) + (f" {arch}" if arch and arch not in str(name) else "")
    kern = " ".join(x for x in (str(sp.get("kernel") or ""), arch) if x)
    return " · ".join(x for x in (str(sp.get("hostname") or ""), kern) if x)


class Guests:
    """Proxmox guests of every site, found by name, address or MAC (GitHub issue #104: a CHR or an appliance VM)."""

    def __init__(self, snaps: list[dict]):
        self.all = [g for px in snaps for g in px.get("guests") or []
                    if not g.get("template") and isinstance(g.get("vmid"), int)]

    def find(self, names=(), addrs=(), macs=()) -> dict | None:
        names = {str(n).split(".")[0].lower() for n in names if n}
        addrs, macs = {str(a) for a in addrs if a}, {str(m).lower() for m in macs if m}
        for g in sorted(self.all, key=lambda g: g["vmid"]):
            nics = hmlib.guest_nics(g)
            if str(g.get("name") or "").lower() in names or addrs & {i for n in nics for i in n["ips"]} \
                    or macs & {n["mac"] for n in nics if n["mac"]}:
                return g
        return None


def guest_text(g: dict | None) -> str:
    return f"{'LXC' if g.get('type') == 'lxc' else 'VM'} {g['vmid']} on {g.get('node')}" if g else ""


def ros_model(d: dict, guest: dict | None) -> str:
    """A RouterOS model: the RouterBOARD model or board name; a CHR (board name "CHR <SMBIOS string>") as "CHR",
    with the Proxmox guest it runs as (GitHub issue #104)."""
    res, rb = d.get("resource") or {}, d.get("routerboard") or {}
    board = str(res.get("board-name") or "")
    if board == "CHR" or board.startswith("CHR "):
        return "CHR" + (f" ({guest_text(guest)})" if guest else "")
    return rb.get("model") or board


def ros_guest(guests: "Guests", d: dict, *names) -> dict | None:
    macs = [i.get("mac-address") for i in d.get("interfaces") or [] if isinstance(i, dict)]
    addrs = [str(a.get("address") or "").split("/")[0] for a in d.get("addresses") or [] if isinstance(a, dict)]
    return guests.find(names=[*names, (d.get("identity") or {}).get("name")], addrs=addrs, macs=macs)


def bmc_health(d: dict, host_vars: dict) -> dict:
    """Health of one BMC with its causes (GitHub issue #103): bmc-info.yml records health_causes (chassis_intrusion,
    components not OK); the host var bmc_health_accept names causes the user accepted (equal to or part of a cause,
    case-insensitive). accepted: the health is not OK and every recorded cause is accepted."""
    health = str(d.get("health") or "?")
    acc = host_vars.get("bmc_health_accept") or []
    acc = [str(a).lower() for a in ([acc] if isinstance(acc, str) else acc if isinstance(acc, list) else []) if a]
    causes = [str(c) for c in d.get("health_causes") or []]
    open_ = [c for c in causes if not any(a == c.lower() or a in c.lower() for a in acc)]
    bad = health not in ("OK", "?")
    return {"health": health, "bad": bad, "causes": causes, "open": open_, "recorded": "health_causes" in d,
            "accepted": bad and bool(causes) and not open_,
            "not_ok": [str(x) for x in d.get("not_ok") or []]}


def bmc_text(b: dict) -> str:
    """"Critical (accepted: chassis_intrusion)", "Critical (cause: psu PS2 Critical)", "OK"."""
    if not b["bad"]:
        return b["health"]
    if b["accepted"]:
        return f"{b['health']} (accepted: {', '.join(b['causes'])})"
    if b["causes"]:
        return f"{b['health']} (cause: {', '.join(b['open'])}" + (f"; accepted: {', '.join(c for c in b['causes'] if c not in b['open'])}"
                                                                  if len(b["open"]) < len(b["causes"]) else "") + ")"
    if b["recorded"]:
        return f"{b['health']} (cause unknown)"
    return f"{b['health']} (not OK: {', '.join(b['not_ok']) or '?'}; bmc-info.yml records the cause)"


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


def guest_links(g: dict) -> list[tuple[int | None, str]]:
    """(VLAN tag, bridge) of every NIC of a guest, each once (GitHub issue #107): a router VM counts on every VLAN it
    has a NIC in. The bridge is kept only for untagged NICs; a guest without NIC config: its primary NIC's tag."""
    out = []
    for n in hmlib.guest_nics(g):
        key = (n["tag"], "" if n["tag"] is not None else n["bridge"])
        if key not in out:
            out.append(key)
    return out or [(g.get("_tag"), "")]


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


def job_name(j: dict) -> str:
    """A backup job's comment, else its id unless Proxmox generated it (a hash or backup-xxxxxxxx-xxxx), else its
    schedule and storage (GitHub issues #97, #109): one rule for every job without a comment."""
    jid = str(j.get("id") or "")
    if j.get("comment"):
        return str(j["comment"])
    if jid and not re.fullmatch(r"[0-9a-f]{20,}(:\d+)?|backup-[0-9a-f]{8}(-[0-9a-f]{4,})*", jid):
        return jid
    return f"{j.get('schedule') or '?'} → {j.get('storage') or '?'}"


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
    for e in hmlib.routeros_addresses(cfg, managed):   # every interface address the audit read (GitHub #106)
        k.add(e["ip"], e["name"], "RouterOS")
    for nas, cs in nas_containers(docs["qnap-containers.json"]).items():
        for c in cs:
            for ip in c.get("ips") or []:
                k.add(ip, c.get("name"), f"NAS container on {nas}")
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


def nas_containers(doc: dict) -> dict[str, list[dict]]:
    """{NAS: [container]} from qnap-containers.json. qnap-containers.yml writes the layout of containers.json
    ({hosts: {nas: {containers: [{name, runtime, image, ips, networks, state, …}]}}}); the older {nas: {lxd, docker}}
    is read too, as the same records."""
    hosts = doc.get("hosts") if isinstance(doc.get("hosts"), dict) else doc
    out = {}
    for nas, d in sorted((hosts or {}).items()):
        if not isinstance(d, dict):
            continue
        cs = [c for c in d.get("containers") or [] if isinstance(c, dict)]
        cs += [{**c, "runtime": "lxd", "image": "", "ips": [str(c.get("ipv4") or "").split(" ")[0]],
                "networks": [c["ipv4"]] if c.get("ipv4") else []} for c in d.get("lxd") or [] if isinstance(c, dict)]
        cs += [{**c, "runtime": "docker"} for c in d.get("docker") or [] if isinstance(c, dict)]
        out[nas] = sorted(cs, key=lambda c: (str(c.get("runtime")) != "docker", str(c.get("name"))))
    return out


def hmlib_parts(doc: dict) -> list[dict]:
    """Per-site parts of a discovery file ({sites: {key: part}}) or the file itself when it has no sites."""
    sites = doc.get("sites")
    return [p for p in sites.values() if isinstance(p, dict)] if isinstance(sites, dict) else [doc]


def bmc_server(name: str, host_vars: dict, hosts: set) -> str:
    """The server a BMC belongs to (GitHub issue #117): the host var bmc_of, else the naming convention bmc-<host>,
    <host>-bmc or <host>-ipmi when that host is in the inventory or a Proxmox node; "" when unknown."""
    if host_vars.get("bmc_of"):
        return str(host_vars["bmc_of"])
    for pattern in (r"bmc-(.+)", r"(.+)-bmc", r"(.+)-ipmi"):
        m = re.fullmatch(pattern, name, re.I)
        if m and m.group(1) in hosts:
            return m.group(1)
    return ""


def device_rows(cfg: dict, st: dict, docs: dict, managed: dict, net: dict, unifi: dict, guests: Guests,
                nodes: tuple = ()) -> list[dict]:
    """Network devices, appliances and BMCs of a site (GitHub issue #94): inventory hosts in the device groups first, enriched from
    routeros.json, unifi.json, bmc.json, updates.json (QNAP) and nmap; then discovered devices not in the
    inventory. Model (GitHub issue #104): the host var hm_model, else the audit/controller/BMC/QNAP data, else what
    ssh_probe.py read, else the Proxmox guest it runs as; an nmap OS guess is never a model, only a labelled guess
    in State."""
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
                res = d.get("resource") or {}
                ident = (d.get("identity") or {}).get("name")
                r.update(model=ros_model(d, ros_guest(guests, d, h)), firmware=res.get("version") or "",
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
            r["server"] = bmc_server(h, v, set(managed) | set(nodes))
            if d:
                r.update(model=d.get("model") or "", firmware=d.get("bmc_firmware") or "",
                         health=bmc_text(bmc_health(d, v)), power=d.get("power_state") or "?",
                         seen=max(stamp(d.get("collected_at")), r["seen"]))
            else:
                r["health"] = "no data (bmc-info.yml)"
        elif kind == "QNAP NAS":
            d = upd.get(h) or {}
            fw = d.get("firmware") or {}
            r.update(model=fw.get("model") or "", firmware=d.get("os") or fw.get("version") or "",
                     state=(f"{d.get('pending')} app updates" if d.get("pending") else "up to date")
                     + f" ({stamp(d.get('collected_at'))})" if d else "no data (check-updates.yml)")
        else:
            sh = scanned.get(addr) or {}
            facts, g = ssh_model(sh.get("ssh_probe")), guests.find(names=[h], addrs=[addr])
            r["model"] = str(v.get("hm_model") or "") or (f"{facts} ({guest_text(g)})" if facts and g
                                                          else facts or guest_text(g))
            guess = os_guess(sh.get("os"))
            if not (r["model"] and (facts or v.get("hm_model"))):
                r["state"] = f"nmap guess: {guess}" if guess else "no data: set hm_model or run ssh_probe.py --include-managed"
        if v.get("hm_model"):
            r["model"] = str(v["hm_model"])
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
                     "model": ros_model(d, ros_guest(guests, d)),
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


# --------------------------------------------------------------------------- GitHub issue #89 helpers

def day(s) -> "dt.date | None":
    try:
        return dt.date.fromisoformat(str(s or "")[:10])
    except ValueError:
        return None


def last_backup(g: dict) -> str:
    """"2026-11-18", "failed 2026-11-18, last OK 2026-11-10", "–" (no backup in the task logs read)."""
    lb, err = g.get("last_backup") or {}, g.get("backup_error") or {}
    text = stamp(lb.get("at")) if lb else ""
    if err and (not lb or str(err.get("at") or "") > str(lb.get("at") or "")):
        return f"failed {stamp(err.get('at'))}" + (f", last OK {text}" if text else "")
    return text


def backup_failed(g: dict) -> bool:
    lb, err = g.get("last_backup") or {}, g.get("backup_error") or {}
    return bool(err) and (not lb or str(err.get("at") or "") > str(lb.get("at") or ""))


def max_backup_age(cfg: dict) -> int:
    v = hmlib.get(cfg, "overview.backup_max_age_days", BACKUP_MAX_AGE_DAYS)
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else BACKUP_MAX_AGE_DAYS


def startup_up(g: dict) -> str:
    m = re.search(r"(?:^|,)up=(\d+)", str((g.get("config") or {}).get("startup") or ""))
    return f"{m.group(1)} s" if m else ""


def short(name) -> str:
    return str(name or "").split(".")[0].lower()


def roles(cfg: dict, st: dict, px: dict, guests: list[dict], vl: list[dict], known: Known, managed: dict) -> dict:
    """What a host does for others (GitHub issue #89), by short name: gateway of VLANs (network.vlans[].gw), server of
    Proxmox storages (the storage's server), cluster member (clusters[].ansible_group), critical host. Only what the
    repository records; nothing is guessed from names."""
    out: dict = {}
    for v in vl:
        gw = v.get("gw")
        name = short(known.name(gw) if is_ip(gw) and known.addr.get(gw, ("", ""))[1] != "gateway" else
                     ("" if is_ip(gw) else gw))
        if name:
            out.setdefault(name, {}).setdefault("gateway", []).append(v["id"])
    for srv, sts in storage_servers(px, known).items():
        out.setdefault(srv, {})["storage"] = sts
    groups: dict = {}
    for h, v in managed.items():
        for g in groups_of(v):
            groups.setdefault(g, set()).add(short(h))
    for c in hmlib.get(cfg, "clusters", []) or []:
        if isinstance(c, dict):
            members = sorted(groups.get(c.get("ansible_group"), set()))
            for m in members:
                out.setdefault(m, {})["cluster"] = (str(c.get("name")), len(members), c.get("vip"))
    for h, v in managed.items():
        if v.get("patch_requires_approval"):
            out.setdefault(short(h), {})["critical"] = True
    return out


def storage_servers(px: dict, known: Known) -> dict:
    """{server short name or address: [storage, …]} of a site's network storages (NFS, CIFS, PBS)."""
    out: dict = {}
    for s in px.get("storage") or []:
        srv = str(s.get("server") or "")
        if not srv:
            continue
        names = {short(n) for n, _ in known.addr.values()}
        name = short(known.name(srv)) if is_ip(srv) and known.name(srv) else (
            short(srv) if not is_ip(srv) and short(srv) in names else srv)
        if s.get("storage") not in out.setdefault(name, []):
            out[name].append(s.get("storage"))
    return out


def role_text(r: dict) -> list[str]:
    out = []
    if r.get("gateway"):
        out.append("gateway of VLAN " + ", ".join(map(str, sorted(r["gateway"]))))
    if r.get("storage"):
        out.append("serves storage " + ", ".join(r["storage"]))
    if r.get("cluster"):
        out.append(f"{r['cluster'][0]} cluster member")
    if r.get("critical"):
        out.append("critical")
    return out


def guests_on(guests: list[dict], vlan_ids) -> list[dict]:
    ids = set(vlan_ids)
    return [g for g in guests if ids & {t for t, _ in g.get("_links") or []}]


WEB_PORTS = (80, 443, 8006, 8007, 8080, 8443, 9443)   # web UIs even when nmap names the service otherwise


def tls_url(ip: str, p: dict) -> str | None:
    """A web UI link for an open port nmap identified as HTTP (TLS when nmap saw a tunnel or a certificate)."""
    svc = str(p.get("service") or "").lower()
    if p.get("proto") not in (None, "tcp") or not ("http" in svc or svc == "webdav" or p.get("tls")
                                                   or p.get("port") in WEB_PORTS):
        return None
    tls = p.get("tunnel") == "ssl" or bool(p.get("tls")) or svc in ("https", "ssl/http") or p.get("port") in (
        443, 8006, 8007, 8443, 9443)
    port = int(p.get("port") or 0)
    host = f"[{ip}]" if ":" in ip else ip
    default = 443 if tls else 80
    return f"{'https' if tls else 'http'}://{host}" + ("" if port == default else f":{port}")


# --------------------------------------------------------------------------- sections

SOURCE_COMPONENT = {"proxmox.json": "proxmox", "network.json": "discovery"}   # GitHub issue #123


def sources(root: Path, docs: dict, cfg: dict | None = None) -> list[str]:
    rows = []
    for name, cmd in SOURCES:
        f = root / "discovery" / name
        comp = SOURCE_COMPONENT.get(name)
        if comp and not f.is_file() and not hmlib.get(cfg or {}, f"components.{comp}", True):
            rows.append([f"discovery/{name}", f"not used (components.{comp}: false)", ""])
            continue
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
        per_vlan: dict = {}   # (tag, bridge of an untagged NIC) → guests with a NIC there (GitHub issue #107)
        for g in guests_by.get(n.get("node"), []):
            for key in g.get("_links") or [(g["_tag"], "")]:
                per_vlan[key] = per_vlan.get(key, 0) + 1
        per_node[n.get("node")] = per_vlan
        tags_used |= {tag for tag, _ in per_vlan if tag is not None}
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
        lines.append(f'  {p}_n{i}["Proxmox {label(n.get("node"))} ({len(guests_by.get(n.get("node"), []))} guests)"]')
        for (tag, bridge), count in sorted(per_vlan.items(), key=lambda x: (x[0][0] is None, x[0][0] or 0, x[0][1])):
            if tag is None:
                ref = f"{p}_untagged" + ("_" + re.sub(r"\W", "_", bridge) if bridge else "")
                lines.append(f'  {p}_n{i} -->|"{count} untagged"| {ref}(["untagged'
                             + (f' on {label(bridge)}"])' if bridge else ' / native"])'))
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


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 'es' if word.endswith('s') else 's'}"


def sites_map(rows: list[tuple[dict, int, int, int]]) -> list[str]:
    """One box per site; no edges: the repository has no data on links between sites (GitHub issue #109)."""
    lines = ["```mermaid", "flowchart LR"]
    for i, (st, nodes, guests, vlans) in enumerate(rows):
        lines.append(f'  s{i}["{label(hmlib.site_title(st) or "default", 60)}<br/>{plural(nodes, "node")}, '
                     f'{plural(guests, "guest")}, {plural(vlans, "VLAN") if vlans else "flat network (untagged)"}"]')
    return lines + ["```"]


def start_order(px: dict, guests_by: dict, role: dict) -> list[str]:
    """Recovery after a power outage (GitHub issue #89): the cluster's quorum, then per node the autostart guests in
    the order Proxmox starts them (startup order, guests without one after, each by VMID; HA-managed guests are
    started by the HA manager), and the running guests nothing starts again."""
    rows, manual = [], []
    for n in sorted(px.get("nodes") or [], key=lambda n: n.get("node") or ""):
        gs = guests_by.get(n.get("node"), [])
        auto = sorted((g for g in gs if plan.onboot(g) or g.get("hastate")),
                      key=lambda g: (plan.startup_order(g), g["vmid"]))
        for i, g in enumerate(auto, 1):
            o = plan.startup_order(g)
            rows.append([n.get("node"), i, g["vmid"], g.get("name"), o if o < 10**6 else "–", startup_up(g),
                         ["HA"] * bool(g.get("hastate")) + role_text(role.get(short(g.get("name")), {}))])
        manual += [g for g in gs if g.get("status") == "running" and not plan.onboot(g) and not g.get("hastate")]
    if not rows and not manual:
        return []
    cl = px.get("cluster")
    count = len(px.get("nodes") or [])
    out = [("After a power outage each node starts by itself and then its autostart guests in this order; nodes start "
            "in parallel." if count > 1 else "After a power outage the node starts by itself and then its autostart "
            "guests in this order.")
           + (f" The cluster starts guests only when it has quorum: {count // 2 + 1} of {count} nodes up."
              if cl and count > 1 else ""), ""]
    if rows:
        out += fold(table(["Node", "#", "VMID", "Guest", "Order", "Up delay", "Role"], rows), len(rows), "autostart guest")
    if manual:
        out += ["", "Running now without autostart (start by hand after an outage): "
                + ", ".join(f"{g['vmid']} {cell(g.get('name'))}" + (f" ({cell(', '.join(role_text(role[short(g.get('name'))])))})"
                                                                    if role_text(role.get(short(g.get("name")), {})) else "")
                            for g in sorted(manual, key=lambda g: g["vmid"])) + "."]
    return out + [""]


def impact(cfg: dict, st: dict, px: dict, guests: list[dict], guests_by: dict, vl: list[dict], role: dict,
           docs: dict, managed: dict) -> list[str]:
    """What stops when one thing goes down (GitHub issue #89), only from recorded data: a Proxmox node (its guests and
    what they do for others), a gateway that isn't a guest here (its VLANs), a storage server (its storages and the
    guests with disks or ISOs there), a NAS (its containers and what they do)."""
    by_name = {short(g.get("name")): g for g in guests}
    vlan_name = {v["id"]: v.get("name") for v in vl}
    disks: dict = {}
    for g in guests:
        for _, sto in plan.volumes(g.get("config") or {}):
            disks.setdefault(sto, set()).add(g["vmid"])

    def effects(r: dict) -> list[str]:
        out = []
        if r.get("gateway"):
            n = len(guests_on(guests, r["gateway"]))
            out.append("routing lost for VLAN " + ", ".join(f"{v} {vlan_name.get(v) or ''}".strip() for v in
                                                           sorted(r["gateway"])) + f" ({plural(n, 'guest')} there)")
        if r.get("storage"):
            hit = set().union(*(disks.get(x, set()) for x in r["storage"]))
            out.append("storage " + ", ".join(r["storage"]) + " unavailable"
                       + (f": {plural(len(hit), 'guest')} with disks or ISOs there can't start" if hit else ""))
        if r.get("cluster"):
            name, total, vip = r["cluster"]
            out.append(f"{name} cluster has one member less of {total}" + (" (its VIP moves)" if vip else ""))
        return out

    rows = []
    nodes = sorted(px.get("nodes") or [], key=lambda n: n.get("node") or "")
    for n in nodes:
        gs = guests_by.get(n.get("node"), [])
        running = [g for g in gs if g.get("status") == "running"]
        ha = [g for g in running if g.get("hastate")]
        eff = [f"{plural(len(running), 'running guest')} stop" + (f" ({len(ha)} restarted elsewhere by HA)" if ha else "")]
        if px.get("cluster") and len(nodes) > 1:
            eff.append("the cluster keeps quorum" if len(nodes) - 1 >= len(nodes) // 2 + 1 else
                       "the cluster loses quorum: guests on the other nodes keep running but can't be started or changed")
        for g in sorted(gs, key=lambda g: g["vmid"]):
            for e in effects(role.get(short(g.get("name")), {})):
                eff.append(f"{g.get('name')}: {e}")
        rows.append([f"Proxmox node {n.get('node')}", eff])
    qnap = docs["qnap-containers.json"]
    nas = {}
    for n, cs in nas_containers(qnap).items():
        d = (qnap.get("hosts") or {}).get(n) or {} if isinstance(qnap.get("hosts"), dict) else {}
        s = (hmlib.target_site(cfg, managed, n) or {}).get("name") if not d.get("site") else d["site"]
        if (s or "") == st["name"] or (not s and st["default"]):
            nas[short(n)] = cs
    for name in sorted(set(role) | set(nas)):
        r = role.get(name, {})
        if name in by_name or not (r.get("gateway") or r.get("storage") or name in nas):
            continue
        eff = effects(r)
        if name in nas:
            cs = nas[name]
            eff.append(f"{plural(len(cs), 'container')} on it stop")
            for c in cs:
                eff += [f"{c.get('name')}: {e}" for e in effects(role.get(short(c.get("name")), {}))]
        rows.append([name, eff])
    if not rows:
        return []
    return ["What stops when one of these goes down, from the guests, `network.vlans` gateways, storage servers, NAS "
            "containers and clusters this repository records.", ""] + [
        f"- **{cell(w)}**: " + "; ".join(cell(e, 600) for e in eff) + "." for w, eff in rows] + [""]


NOT_PUBLIC = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                 "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/3")]


def is_public(ip: str) -> bool:
    """An IPv4 address outside the private, CGNAT, loopback, link-local and multicast ranges."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and not any(a in n for n in NOT_PUBLIC)


NAT_NOT_MATCH = {"chain", "action", "to-addresses", "to-ports", "comment", "log", "log-prefix", "_flags", "disabled",
                 "protocol", "dst-port", "src-address", "src-address-list", "bytes", "packets"}


def nat_rules(d: dict) -> list[dict]:
    return [r for r in d.get("nat") or [] if r.get("chain") == "dstnat" and r.get("action") in ("dst-nat", "netmap")
            and "X" not in str(r.get("_flags") or "") and r.get("disabled") not in ("yes", "true")]


def port_forwards(cfg: dict, st: dict, docs: dict, known: Known) -> list[str]:
    """Port forwards (GitHub issue #89): enabled RouterOS dst-nat rules and the routers' public addresses."""
    rows, public, unread = [], [], []
    for host, d in sorted((docs["routeros.json"].get("devices") or {}).items()):
        s = hmlib.site_of_address(cfg, host)
        if not ((s or {}).get("name", "") == st["name"] or (s is None and st["default"])):
            continue
        name = (d.get("identity") or {}).get("name") or host
        if "nat" not in d:
            unread.append(name)
        for r in nat_rules(d):
            to = str(r.get("to-addresses") or "")
            match = [f"{k} {v}" for k, v in sorted(r.items()) if k not in NAT_NOT_MATCH and v not in (None, "")]
            src = [f"{k.replace('src-', '')} {r[k]}" for k in ("src-address", "src-address-list") if r.get(k)]
            what = " ".join(x for x in (r.get("protocol"), r.get("dst-port")) if x)
            rows.append([name, what or "all traffic", match or "any",
                         src or "any", to + (f":{r['to-ports']}" if r.get("to-ports") else "")
                         + (f" ({known.name(to)})" if known.name(to) else ""), r.get("comment")])
        for a in d.get("addresses") or []:
            ip = str(a.get("address") or "").split("/")[0]
            if is_public(ip) and "X" not in str(a.get("_flags") or ""):
                public.append(f"{name} {a.get('address')} on {a.get('interface') or '?'}")
    if not (rows or public or unread):
        return []
    out = ["Enabled RouterOS dst-nat rules (`routeros_audit.py`). Forwards on other gateways (OPNsense, pfSense) and "
           "tunnels (Cloudflare, WireGuard) are not listed.", ""]
    if public:
        out += ["Public addresses on RouterOS interfaces: " + ", ".join(cell(x) for x in public) + ".", ""]
    if rows:
        out += fold(table(["Router", "Protocol / port", "Matches", "Sources", "Forwards to", "Comment"], rows),
                    len(rows), "port forward") + [""]
    if unread:
        out += [f"NAT rules not read yet on {', '.join(cell(x) for x in unread)}: run `routeros_audit.py` again.", ""]
    return out


def access(cfg: dict, st: dict, net: dict, managed: dict, known: Known) -> list[str]:
    """How to reach each known host (GitHub issue #89): SSH (the inventory's user and port), web UIs nmap found as
    links, and its other services."""
    scanned = net.get("hosts") or {}
    rows: dict = {}
    for host, v in managed.items():
        addr = str(hmlib.literal(v.get("ansible_host")) or "")
        s = hmlib.target_site(cfg, managed, host)
        if addr and is_ip(addr) and ((s or {}).get("name", "") == st["name"] or (s is None and st["default"])):
            rows[(host, addr)] = v
    for ip in scanned:
        name = known.name(ip)
        if name and not any(k[1] == ip for k in rows):
            rows[(name, ip)] = managed.get(name) or {}
    out = []
    for (name, ip), v in sorted(rows.items(), key=lambda x: (x[0][0].lower(), x[0][1])):
        ports = (scanned.get(ip) or {}).get("ports") or []
        user = hmlib.literal(v.get("ansible_user"))
        port = hmlib.literal(v.get("ansible_port"))
        ssh_ports = [p.get("port") for p in ports if p.get("service") == "ssh"]
        ssh = ""
        if v or ssh_ports:
            sp = port or (ssh_ports[0] if ssh_ports and 22 not in ssh_ports else None)
            ssh = f"ssh {user + '@' if user else ''}{ip}" + (f" -p {sp}" if sp and str(sp) != "22" else "")
        web = [u for p in ports if (u := tls_url(ip, p))]
        if "proxmox_nodes" in groups_of(v) and not any(p.get("port") == 8006 for p in ports):
            web.append(tls_url(ip, {"port": 8006}))   # the node's web UI, whether or not a scan covered its port
        other = [f"{p.get('service') or '?'}/{p.get('port')}" for p in ports
                 if p.get("service") != "ssh" and not tls_url(ip, p)]
        if ssh or web or other:
            out.append([name, ip, ssh, web, other])
    if not out:
        return []
    return ["How to reach each host this repository names: SSH as Ansible connects, web UIs and other services nmap "
            "found open (`nmap_scan.py --profile services`).", ""] + fold(
        table(["Host", "Address", "SSH", "Web UI", "Other services"], out), len(out), "host") + [""]


def server_hardware(bmcs: list[dict], sub) -> list[str]:
    """The site's BMCs as server hardware (GitHub issue #117), each with the server it belongs to."""
    if not bmcs:
        return []
    return sub("Server hardware") + table(
        ["Server", "BMC", "Model", "Address", "Firmware", "Health", "Power", "Last seen"],
        [[d["server"], d["name"], d["model"], d["address"], d["firmware"], d.get("health"), d.get("power"), d["seen"]]
         for d in bmcs]) + [""]


def scan_coverage(cfg: dict, cidr, scanned: list[str]) -> str:
    """"" when a VLAN's CIDR lies inside network.authorized_ranges and the scan saw a host there, else "not scanned"
    or "partly scanned" (GitHub issue #134)."""
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
        auth = hmlib._networks(hmlib.get(cfg, "network.authorized_ranges", []) or [])
    except (ValueError, hmlib.ConfigError):
        return ""
    if not any(in_net(ip, net) for ip in scanned):
        return "not scanned"
    over = [a for a in auth if a.version == net.version and a.overlaps(net)]
    if any(net.subnet_of(a) for a in over):
        return ""
    inside = sum(a.num_addresses for a in collapse(over) if a.subnet_of(net))
    return "" if inside >= net.num_addresses else "partly scanned"


def collapse(nets: list) -> list:
    return list(ipaddress.collapse_addresses(nets)) if nets else []


def guest_addresses(g: dict) -> set[str]:
    """Every address of a guest: its NICs' (config, agent, LXC) and the one it is reached at (inventory)."""
    return {a["ip"] for a in hmlib.guest_nic_addresses(g) if is_ip(a["ip"])} | ({g["_ip"]} if is_ip(g.get("_ip")) else set())


def vlan_usage(cfg: dict, st: dict, cidr, scanned: list[str], guests: list[dict], known: Known) -> dict:
    """Every address the repository knows in a VLAN's CIDR, de-duplicated (GitHub issue #134): {guest, infra,
    other: set of IPs, all, named: {guest name: its IPs known by name}, scan}. guest = any NIC address of this site's guests; infra = what the repo manages
    or names otherwise (inventory hosts and hm_extra_ips, Proxmox nodes, gateways, VIPs, RouterOS/UniFi, NAS
    containers); other = scanned hosts nothing names and discovery.ignore_unmanaged devices."""
    inside = lambda ip: is_ip(ip) and in_net(ip, cidr)
    def here(ip):   # Known is repo-wide: an address another site's ranges claim is that site's
        other = hmlib.site_of_address(cfg, ip)
        return other is None or other["name"] == st["name"]
    guest = {ip for g in guests for ip in guest_addresses(g) if inside(ip)}
    # an address the repo knows by a guest's name (a CHR's RouterOS interface, hm_extra_ips) is that guest's
    names = {str(g.get("name")) for g in guests if g.get("name")}
    named: dict[str, set] = {}
    for ip, (name, _) in known.addr.items():
        if name in names and inside(ip) and here(ip):
            named.setdefault(name, set()).add(ip)
            guest.add(ip)
    infra = {ip for ip, (_, kind) in known.addr.items() if kind != "known device" and inside(ip) and here(ip)} - guest
    ignored = set()   # single addresses only: a range a.b.c.x-y or a CIDR is a reservation, not devices in use
    for item in hmlib.get(cfg, hmlib.IGNORE_KEY, []) or []:
        ip = str((item.get("ip") if isinstance(item, dict) else item) or "").strip().removesuffix("/32")
        if is_ip(ip) and (not isinstance(item, dict) or item.get("site") in (None, "", st["name"])):
            ignored.add(ip)
    other = ({ip for ip in scanned if inside(ip)}
             | {ip for ip, (_, kind) in known.addr.items() if kind == "known device" and inside(ip) and here(ip)}
             | {ip for ip in ignored if inside(ip)}) - guest - infra
    return {"guest": guest, "infra": infra, "other": other, "all": guest | infra | other, "named": named,
            "scan": scan_coverage(cfg, cidr, scanned)}


def site_section(cfg: dict, st: dict, docs: dict, managed: dict, known: Known, all_guests: Guests,
                 multi: bool = False) -> tuple[list[str], dict]:
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
        g["_links"] = guest_links(g)
        guests_by.setdefault(g.get("node"), []).append(g)
    devices = device_rows(cfg, st, docs, managed, net, unifi, all_guests,
                          tuple(n.get("node") for n in px.get("nodes") or [] if n.get("node")))
    hardware = sorted((d for d in devices if d["kind"] == "BMC"), key=lambda d: (not d["server"], d["server"], d["name"]))
    stats = {"nodes": len(px.get("nodes") or []), "guests": len(guests), "vlans": len(vl), "warnings": [],
             "memory": 0, "storage": 0, "backup": 0, "backup_old": 0}
    role = roles(cfg, st, px, guests, vl, known, managed)
    backups_read = str((px.get("guest_ip_sources") or {}).get("backups") or "")

    out = [f"## Site: {cell(title)}", ""]

    def sub(name: str) -> list[str]:   # unique headings per site: the same anchor on GitHub and GitLab (#113)
        return [f"### {name}" + (f" ({cell(st['name'] or 'default')})" if multi else ""), ""]
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
        u = vlan_usage(cfg, st, v.get("cidr"), [ip for ip, _ in scanned], guests, known)
        used[v["id"]] = len(u["all"])
        try:
            size = max(ipaddress.ip_network(str(v.get("cidr")), strict=False).num_addresses - 2, 1)
        except ValueError:
            size = None
        count = f"{len(u['all'])}/{size}" if size else str(len(u["all"]))
        on = [g for g in guests if v["id"] in {t for t, _ in g["_links"]}   # every NIC (GitHub issue #107)
              or (g["_tag"] is None and g["_ip"] and in_net(g["_ip"], v.get("cidr")))]
        blind = sum(1 for g in on if not (guest_addresses(g) | u["named"].get(str(g.get("name")), set())) & u["guest"])
        parts = [(len(u["guest"]), "guest IP", "guest IPs"), (len(u["infra"]), "infra", "infra"),
                 (len(u["other"]), "other", "other")]
        use = " · ".join(f"{n} {one if n == 1 else many}" for n, one, many in parts if n)
        if blind and v.get("cidr"):   # no agent, DHCP, … (GitHub issue #134)
            use += f" (+{blind} guest{'s' if blind > 1 else ''}, address unknown)"
        rows.append([v["id"], v.get("name"), v.get("cidr"), v.get("gw"), len(on),
                     count + (f" ({u['scan']})" if u["scan"] and v.get("cidr") else ""), use.strip() or "–"])
    gateways = {v["id"]: (known.addr.get(v["gw"], ("", ""))[0] if known.addr.get(v["gw"], ("", ""))[1] != "gateway"
                          else "") or v["gw"] if is_ip(v.get("gw")) else v.get("gw") for v in vl if v.get("gw")}
    out += sub("Map") + site_map(st, px, vl, guests_by, gateways, devices, used) + [""]
    if vl:
        out += sub("Network") + table(["VLAN", "Name", "CIDR", "Gateway", "Guests", "Addresses used", "In use by"],
                                      rows) + [""]
        out += ["Addresses used: every address the repository knows in the CIDR, scanned or not. Guest IPs are any "
                "NIC of a Proxmox guest; infra is what the inventory, Proxmox nodes, gateways, VIPs, network devices and "
                "NAS containers use; other is scanned hosts nothing names and `discovery.ignore_unmanaged` devices."
                + (" Not scanned / partly scanned: the CIDR is (partly) outside `network.authorized_ranges`, or the scan "
                   "found no host there, so only the addresses the repository knows are counted."
                   if any(r[5].endswith("scanned)") for r in rows) else ""), ""]

    # Proxmox
    if px:
        rows = []
        for n in sorted(px.get("nodes") or [], key=lambda n: n.get("node") or ""):
            gs = guests_by.get(n.get("node"), [])
            p = pct(n.get("mem_used_gib"), n.get("mem_gib"))
            if p is not None and p >= MEM_WARN_PCT:
                stats["warnings"].append(f"{title}: node {n.get('node')} memory {p}%")
                stats["memory"] += 1
            addrs = [x.get("cidr") for x in (px.get("networks") or {}).get(n.get("node"), []) if x.get("cidr")]
            rows.append([n.get("node"), n.get("status"), short_version(n.get("pveversion")), n.get("kernel"), n.get("cpus"),
                         f"{n.get('mem_used_gib')}/{n.get('mem_gib')} GiB" + (f" ({p}%)" if p is not None else ""),
                         f"{sum(1 for g in gs if g.get('status') == 'running')}/{len(gs)}", sorted(addrs)])
        head = ["Node", "Status", "PVE", "Kernel", "CPUs", "Memory", "Guests running", "Addresses"]
        if not any(n.get("pveversion") or n.get("kernel") for n in px.get("nodes") or []):   # snapshot before 0.34.0
            head, rows = head[:2] + head[4:], [r[:2] + r[4:] for r in rows]
        out += sub("Proxmox nodes") + table(head, rows) + [""]
        out += server_hardware(hardware, sub)
        rows, seen = [], set()
        for s in sorted(px.get("storage") or [], key=lambda s: (s.get("storage") or "", s.get("node") or "")):
            key = s.get("storage") if s.get("shared") else (s.get("storage"), s.get("node"))
            if key in seen:
                continue
            seen.add(key)
            p = pct(s.get("used_gib"), s.get("size_gib"))
            if p is not None and p >= STORAGE_WARN_PCT:
                stats["storage"] += 1
                stats["warnings"].append(f"{title}: storage {s.get('storage')}"
                                         + ("" if s.get("shared") else f" on {s.get('node')}") + f" {p}% full")
            rows.append([s.get("storage"), "shared" if s.get("shared") else s.get("node"), s.get("type"),
                         f"{s.get('used_gib')}/{s.get('size_gib')} GiB", "–" if p is None else
                         f"{p}%" + (" ⚠" if p >= STORAGE_WARN_PCT else ""), s.get("content")])
        out += sub("Storage") + table(["Storage", "Node", "Type", "Used", "Full", "Content"], rows) + [""]

        with_backups = backups_read.startswith("ok")   # GitHub issue #89: newest backup from the vzdump task logs
        rows = [[g["vmid"], g.get("name"), g.get("type"), g.get("node"), g.get("status"), g.get("cpus"),
                 g.get("mem_gib"), g.get("disk_gib"), g["_vlan"], g["_ip"], onboot(g), "yes" if g.get("hastate") else "",
                 *([last_backup(g)] if with_backups else []), g.get("tags")] for g in sorted(guests, key=lambda g: g["vmid"])]
        out += sub("Guests") + (fold(table(["VMID", "Name", "Type", "Node", "Status", "vCPU", "RAM GiB", "Disk GiB", "VLAN",
                                            "IP", "Autostart", "HA", *(["Last backup"] if with_backups else []), "Tags"],
                                           rows), len(rows), "guest")
                                if rows else ["No guests."])
        if templates:
            out += ["", f"Templates: {len(templates)} (" + ", ".join(cell(t.get("name")) for t in
                                                                    sorted(templates, key=lambda t: t["vmid"])) + ")."]
        if not any("config" in g for g in guests) and guests:
            out += ["", "VLAN, IP and autostart need `proxmox_inventory.py --details`."]
        out.append("")

        jobs = px.get("backup_jobs")
        out += sub("Backups")
        if jobs is None:
            out += ["The backup jobs could not be read (the read-only token needs Sys.Audit on /).", ""]
        else:
            rows = [[job_name(j), "yes" if j.get("enabled") else "no", j.get("schedule"), j.get("storage"),
                     job_guests(j), j.get("node") or "all"]
                    for j in sorted(jobs, key=lambda j: str(j.get("id")))]
            out += (table(["Job", "Enabled", "Schedule", "Storage", "Guests", "Node"], rows) if rows
                    else ["No scheduled backup jobs."])
            missing = backup_uncovered(guests, jobs)
            if missing:
                stats["warnings"].append(f"{title}: {plural(len(missing), 'guest')} in no enabled backup job")
                stats["backup"] += len(missing)
                out += ["", f"In no enabled backup job ({len(missing)} of {len(guests)}): "
                        + ", ".join(f"{g['vmid']} {cell(g.get('name'))}" for g in sorted(missing, key=lambda g: g["vmid"]))
                        + "."]
            out += backup_ages(cfg, px, guests, missing, backups_read, title, stats)
            out.append("")
        if any("config" in g for g in guests):   # startup settings come with --details
            out += sub("Start order") + (start_order(px, guests_by, role)
                                         or ["No guest starts by itself after an outage.", ""])
    imp = impact(cfg, st, px, guests, guests_by, vl, role, docs, managed)
    if imp:
        out += sub("If it goes down") + imp

    if not px:
        out += server_hardware(hardware, sub)
    network = [d for d in devices if d["kind"] != "BMC"]
    if network:
        out += sub("Network devices and appliances") + table(
            ["Kind", "Name", "Model", "Address", "Firmware", "State", "Last seen"],
            [[d["kind"], d["name"], d["model"], d["address"], d["firmware"], d["state"], d["seen"]] for d in network]) + [""]
    fwd = port_forwards(cfg, st, docs, known)
    if fwd:
        out += sub("Port forwards") + fwd
    reach = access(cfg, st, net, managed, known)
    if reach:
        out += sub("Access") + reach
    ignored = {ip for ip, _ in scanned if ip not in guest_ips and not known.name(ip)
               and hmlib.ignored_address(cfg, ip, st["name"])}   # discovery.ignore_unmanaged (GitHub issue #106)
    other = [(ip, h) for ip, h in scanned if ip not in guest_ips and not known.name(ip) and ip not in ignored]
    gone = [(ip, h) for ip, h in other if h.get("missing_since")]   # not answering a ping sweep (GitHub issue #127)
    other = [(ip, h) for ip, h in other if not h.get("missing_since")]
    named = [ip for ip, _ in scanned if ip not in guest_ips and (known.name(ip) or ip in ignored)]
    if not other and named:
        out += sub("Other scanned addresses") + ["Every address nmap found belongs to a known host.", ""]
    if other:
        out += sub("Other scanned addresses") + ["Addresses nmap found that nothing in this repository names"
                + (f" ({len(named)} more belong to known hosts: Proxmox nodes, inventory hosts, guests, VIPs, "
                   "or are in `discovery.ignore_unmanaged`)" if named else "")
                + ". A known host's address on another network goes into its `hm_extra_ips` host variable.", ""]
        out += fold(table(["Address", "Name", "Looks like", "OS guess (nmap, match %)", "Open ports", "Last seen"],
                     [[ip, (h.get("ssh_probe") or {}).get("hostname") or list(h.get("hostnames") or []),
                       " ".join(x for x in (str(h.get("device_type_guess") or ""),   # MAC vendor (GitHub issue #105)
                                            f"({h['vendor']})" if h.get("vendor") else "") if x),
                       os_guess(h.get("os")), len(h.get("ports") or []),
                       stamp(h.get("last_seen"))]
                      for ip, h in other]), len(other), "address") + [""]
    if gone:
        if not (other or named):
            out += sub("Other scanned addresses")
        out += [f"<details><summary>{plural(len(gone), 'address')} nothing names, not answering since the last ping "
                "sweep</summary>", ""]
        out += table(["Address", "Name", "Looks like", "Missing since", "Last seen"],
                     [[ip, list(h.get("hostnames") or []), str(h.get("device_type_guess") or ""),
                       stamp(h.get("missing_since")), stamp(h.get("last_seen"))] for ip, h in gone])
        out += ["", "</details>", ""]
    if named:   # which known host each of them was attributed to (GitHub issue #109)
        out += [f"<details><summary>{plural(len(named), 'scanned address')} of known hosts or ignored</summary>", ""]
        out += table(["Address", "Known as", "Source"],
                     [[ip, *(known.addr.get(ip) or ("–", "discovery.ignore_unmanaged"))] for ip in named])
        out += ["", "</details>", ""]
    out += ["[↑ Contents](#contents)", ""]
    return out, stats


def backup_ages(cfg: dict, px: dict, guests: list[dict], missing: list[dict], read: str, title: str,
                stats: dict) -> list[str]:
    """Last successful backup of the guests in a job (GitHub issue #89), judged against the snapshot's own time so
    the page stays the same until the data changes: none within overview.backup_max_age_days, or a newer failure."""
    if not read:
        return []
    if not read.startswith("ok"):
        return ["", f"Last backups {cell(read)}: the read-only token needs Sys.Audit (PVEAuditor) for the task logs."]
    ref, limit = day(px.get("collected_at")), max_backup_age(cfg)
    skip = {g["vmid"] for g in missing}
    injob = [g for g in guests if g["vmid"] not in skip]
    old = [g for g in injob if not (g.get("last_backup") and ref and day(g["last_backup"].get("at"))
                                    and (ref - day(g["last_backup"]["at"])).days <= limit)]
    failed = [g for g in guests if backup_failed(g)]
    out = ["", f"Last successful backup (vzdump task logs, as of {ref or '?'}): {len(injob) - len(old)} of "
               f"{plural(len(injob), 'guest')} in a job within {limit} days."]
    if old:
        out.append(f"No successful backup within {limit} days: " + ", ".join(
            f"{g['vmid']} {cell(g.get('name'))} ({stamp((g.get('last_backup') or {}).get('at')) or 'none in the task logs'})"
            for g in sorted(old, key=lambda g: g["vmid"])) + ".")
    if failed:
        out.append("Newest backup failed: " + ", ".join(
            f"{g['vmid']} {cell(g.get('name'))} ({cell((g.get('backup_error') or {}).get('error'))})"
            for g in sorted(failed, key=lambda g: g["vmid"])) + ".")
    bad = {g["vmid"] for g in old + failed}
    if bad:
        stats["backup_old"] += len(bad)
        stats["warnings"].append(f"{title}: {plural(len(bad), 'guest')} without a successful backup within {limit} days"
                                 " or whose newest backup failed")
    return out


def compose(c: dict) -> str:
    """Where a container's Compose project lives (GitHub issue #102): its working directory, else its project."""
    return str(c.get("compose_working_dir") or c.get("compose_project") or "")


def containers(cfg: dict, docs: dict, managed: dict) -> list[str]:
    rows = []
    for host, d in sorted((docs["containers.json"].get("hosts") or {}).items()):
        for c in sorted(d.get("containers") or [], key=lambda c: str(c.get("name"))):
            ports = c.get("ports")
            rows.append([host, d.get("site"), c.get("name"), c.get("image"),
                         ports, compose(c)])
        for k in d.get("kubernetes") or []:
            rows.append([host, d.get("site"), "Kubernetes", k if isinstance(k, str) else json.dumps(k, sort_keys=True), "", ""])
    qnap = docs["qnap-containers.json"]
    for nas, cs in nas_containers(qnap).items():   # GitHub issue #97; the containers.json layout
        d = (qnap.get("hosts") or {}).get(nas) or {} if isinstance(qnap.get("hosts"), dict) else {}
        site = d.get("site") or ((hmlib.target_site(cfg, managed, nas) or {}).get("name") if managed else "")
        for c in cs:
            if c.get("runtime") == "lxd":
                rows.append([nas, site, c.get("name"), "LXD" + (f": {c['image']}" if c.get("image") else "")
                             + f" ({c.get('state') or '?'})", c.get("ips") if c.get("image") else c.get("networks"), ""])
            else:
                rows.append([nas, site, c.get("name"), c.get("image"), c.get("ports") or c.get("networks"), compose(c)])
    if not rows:
        return []
    return ["## Containers", ""] + fold(table(["Host", "Site", "Container", "Image", "Ports / network", "Compose"], rows),
                                        len(rows), "container") + [""]


def management(cfg: dict, managed: dict, note: str) -> list[str]:
    out = ["## Management", ""]
    if managed:
        groups: dict = {}
        for h, v in managed.items():
            for g in v.get("_groups_all") or v.get("groups") or []:
                if g not in ("all", "ungrouped"):
                    groups.setdefault(g, set()).add(h)
        out += ["Ansible groups (managed inventory):", ""]
        out += table(["Group", "Hosts", "Members"], [[g, len(hs), sorted(hs)]   # every member (GitHub issue #115)
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


SUB_LEVELS = {"c": "Community", "b": "Basic", "s": "Standard", "p": "Premium"}


def expirations(cfg: dict, root: Path, docs: dict, managed: dict, known: Known, counts: dict) -> list[str]:
    """What expires (GitHub issue #89): CHR licences (routeros.json), Proxmox VE subscriptions and node web
    certificates (proxmox.json), TLS certificates nmap read (network.json). Judged against the newest of these
    sources, not today, so the page changes only with the data; domains are not looked up (whois)."""
    rows, refs = [], []
    for host, d in sorted((docs["routeros.json"].get("devices") or {}).items()):
        lic = d.get("license") or {}
        if lic.get("deadline-at"):
            refs.append(stamp(d.get("collected_at")))
            rows.append([stamp(lic["deadline-at"]), f"CHR licence {lic.get('level') or ''}".strip(),
                         known_name(docs["routeros.json"]["devices"], host),
                         f"renews automatically {stamp(lic.get('next-renewal-at'))} when it reaches MikroTik"
                         if lic.get("next-renewal-at") else ""])
    certs: dict = {}
    for st, px in hmlib.proxmox_snapshots(cfg):
        refs.append(stamp(px.get("collected_at")))
        for n in px.get("nodes") or []:
            sub = n.get("subscription") or {}
            if sub.get("next_due") or sub.get("status") not in (None, "active", "notfound", "new"):
                level = SUB_LEVELS.get(str(sub.get("level") or ""), sub.get("level") or "")
                rows.append([stamp(sub.get("next_due")) or "–", f"Proxmox VE subscription {level}".strip(),
                             n.get("node"), "" if sub.get("status") == "active" else f"status {sub.get('status')}"])
            c = n.get("certificate") or {}
            if c.get("not_after"):
                certs.setdefault((stamp(c["not_after"]), c.get("subject") or "", c.get("issuer") or ""), []).append(
                    f"{n.get('node')}:8006")
    for part in hmlib_parts(docs["network.json"]):
        for ip, h in sorted((part.get("hosts") or {}).items()):
            for p in h.get("ports") or []:
                t = p.get("tls") or {}
                if t.get("not_after"):
                    refs.append(stamp(h.get("last_seen")))
                    certs.setdefault((stamp(t["not_after"]), t.get("subject") or "", t.get("issuer") or ""), []).append(
                        f"{known.name(ip) or ip}:{p.get('port')}")
    for (when, subject, issuer), where in certs.items():
        rows.append([when, f"TLS certificate {subject}" + (f" (issuer {issuer})" if issuer and issuer != subject else
                                                           " (self-signed)" if issuer else ""),
                     sorted(set(where)), ""])
    if not rows:
        return []
    ref = day(max((r for r in refs if r), default=""))
    soon = 0
    for r in rows:
        d = day(r[0])
        if ref and d and (d - ref).days <= EXPIRY_WARN_DAYS:
            soon += 1
            r[3] = ("expired" if d < ref else f"⚠ within {EXPIRY_WARN_DAYS} days") + (f"; {r[3]}" if r[3] else "")
    counts["expiring"] = counts.get("expiring", 0) + soon
    rows.sort(key=lambda r: (r[0] == "–", r[0], str(r[1])))
    return ["## Expirations", "", f"Soonest first, judged against the newest data ({ref or '?'}). Domain registrations "
            "are not checked.", ""] + fold(table(["Expires", "What", "Where", "Note"], rows), len(rows), "expiration") + [""]


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
                kinds = {kind_of(groups_of(managed[h]), DEVICE_KINDS) for h in other}
                see = [n for n, hit in (("Server hardware", "BMC" in kinds),
                                        ("Network devices and appliances", bool(kinds - {"BMC", ""}))) if hit]
                out += ["", "Not covered by `check-updates.yml`" + (f" (see {' and '.join(see)})" if see else "") + ": "
                        + ", ".join(cell(h) for h in other) + "."]
        elif missing:
            out += ["", "Not checked: " + ", ".join(cell(h) for h in missing) + "."]
        out.append("")
    bmc = docs["bmc.json"].get("hosts") or {}
    if bmc:
        out += ["BMC health: " + ", ".join(f"{cell(h)} {cell(bmc_text(bmc_health(d, managed.get(h) or {})))}"
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


ROS_WARN = ("critical", "high", "medium")   # routeros_audit.py severities that count as warnings; low and info don't
HEALTH_RANK = {"Critical": 0, "Warning": 1}


def glance_warnings(docs: dict, managed: dict, counts: dict) -> list[str]:
    """Every warning Health shows, by category, most severe first (GitHub issue #108): BMCs not OK (an accepted
    cause, #103, doesn't count), RouterOS findings of medium severity and above, failed update checks, hosts with
    security updates, guests in no backup job, full storage, node memory."""
    out = []
    bad: dict = {}
    for h, d in (docs["bmc.json"].get("hosts") or {}).items():
        b = bmc_health(d, managed.get(h) or {})
        if b["bad"] and not b["accepted"]:
            bad[b["health"]] = bad.get(b["health"], 0) + 1
    if bad:
        out.append("BMC: " + ", ".join(f"{n} {cell(k)}" for k, n in sorted(bad.items(), key=lambda x: (HEALTH_RANK.get(x[0], 2), x[0]))))
    sev: dict = {}
    for d in (docs["routeros.json"].get("devices") or {}).values():
        for f in d.get("findings") or []:
            k = str(f.get("severity") or "").lower()
            if k in ROS_WARN:
                sev[k] = sev.get(k, 0) + 1
    if sev:
        out.append("RouterOS audit: " + ", ".join(f"{sev[k]} {k}" for k in ROS_WARN if k in sev))
    upd = docs["updates.json"].get("hosts") or {}
    failed = [h for h, d in upd.items() if d.get("error")]
    if failed:
        out.append(f"update check failed on {plural(len(failed), 'host')}")
    sec = [h for h, d in upd.items() if isinstance(d.get("security"), int) and d["security"] > 0]
    if sec:
        nodes = [h for h in sec if "proxmox_nodes" in groups_of(managed.get(h) or {})]
        out.append(f"security updates on {plural(len(sec), 'host')}"
                   + (f" ({plural(len(nodes), 'Proxmox node')})" if nodes else ""))
    if counts.get("expiring"):
        out.append(f"{counts['expiring']} expir{'y' if counts['expiring'] == 1 else 'ies'} within {EXPIRY_WARN_DAYS} days"
                   " (see [Expirations](#expirations))")
    if counts.get("backup"):
        out.append(f"{plural(counts['backup'], 'guest')} in no enabled backup job")
    if counts.get("backup_old"):
        out.append(f"{plural(counts['backup_old'], 'guest')} without a recent successful backup")
    if counts.get("storage"):
        out.append(f"{plural(counts['storage'], 'storage')} {STORAGE_WARN_PCT} % full or more")
    if counts.get("memory"):
        out.append(f"{plural(counts['memory'], 'node')} at {MEM_WARN_PCT} % memory or more")
    return out


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
    all_guests = Guests(snaps)
    body, rows, warnings = [], [], []
    totals = {"nodes": 0, "guests": 0, "memory": 0, "storage": 0, "backup": 0, "backup_old": 0}
    for st in st_list:
        sec, stats = site_section(cfg, st, docs, managed, known, all_guests, len(st_list) > 1)
        body += sec
        rows.append((st, stats["nodes"], stats["guests"], stats["vlans"]))
        warnings += stats["warnings"]
        for k in ("nodes", "guests", "memory", "storage", "backup", "backup_old"):
            totals[k] += stats[k]
    exp = expirations(cfg, root, docs, managed, known, totals)
    glance = [plural(len(st_list), "site")]
    if hmlib.get(cfg, "components.proxmox", True) or totals["nodes"]:   # GitHub issue #123
        glance += [plural(totals["nodes"], "Proxmox node"), plural(totals["guests"], "guest")]
    if managed:
        glance.append(plural(len(managed), "Ansible host"))
    out += ["## At a glance", "", ", ".join(glance) + "."]
    found = glance_warnings(docs, managed, totals)
    if found:
        out.append("Warnings (details under [Health](#health)): " + " · ".join(found) + ".")
    out += ["", TOC_MARK, ""]
    if len(st_list) > 1:
        out += ["## Sites", ""] + sites_map(rows) + [""]
    out += body + containers(cfg, docs, managed) + management(cfg, managed, note) + health(cfg, root, docs, managed, warnings)
    out += exp
    out += sources(root, docs, cfg) + [""]
    text = "\n".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return contents(redact(text, cfg) if hmlib.get(cfg, "overview.redact", False) is True else text)


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
