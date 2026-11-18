#!/usr/bin/env python3
"""Compare what is running against what Git declares.

    drift_report.py [--env homelab] [--tofu-json FILE] [--no-tofu] [--out discovery/drift.md]
    drift_report.py --stale        # is discovery/drift.md older than its inputs? exit 0 fresh, 1 stale, 2 missing

Sources (all read-only):
  live      discovery/proxmox.json   (proxmox_inventory.py)  and discovery/network.json (nmap_scan.py;
            every site inside, another site's devices listed per site);
            other sites (sites: in homelab.yaml): their part of discovery/proxmox.json, reported per site
  state     `tofu show -json` in tofu/environments/<env>  (run under with_secrets.py for the state backend)
            or a file passed with --tofu-json; another site: its own environment tofu/environments/<site>
  declared  ansible/inventory/managed via `ansible-inventory --list`

Reports: Proxmox guests not managed by OpenTofu, managed resources missing in Proxmox,
attribute drift (cores, memory, node, status), Ansible hosts that don't exist, which scanned
addresses are Proxmox guests (by config/agent IP, MAC, DNS name), and network devices nobody manages.
An inventory host's other addresses (router/switch secondary IPs, multi-homed NAS or firewall) go in the host
var `hm_extra_ips: [10.0.20.1, …]`: they count as that host's, listed as secondary, not as unmanaged devices.
Container addresses from discovery/*containers.json (docker-containers.yml, or a NAS recorded by hand) are
listed as containers, not as unmanaged devices. Attribute drift inside OpenTofu itself is best seen
with `tofu plan -refresh-only`; this report covers the gaps between the sources.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

VM_TYPES = {"proxmox_virtual_environment_vm": "vm", "proxmox_virtual_environment_container": "lxc"}


def walk_resources(module: dict):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from walk_resources(child)


def tofu_guests(state: dict) -> dict[int, dict]:
    out = {}
    root = (state.get("values") or {}).get("root_module") or {}
    for r in walk_resources(root):
        kind = VM_TYPES.get(r.get("type"))
        if not kind or r.get("mode") != "managed":
            continue
        v = r.get("values") or {}
        vmid = v.get("vm_id") or (int(v["id"]) if str(v.get("id", "")).isdigit() else None)
        cpu = (v.get("cpu") or [{}])[0] if isinstance(v.get("cpu"), list) else (v.get("cpu") or {})
        mem = (v.get("memory") or [{}])[0] if isinstance(v.get("memory"), list) else (v.get("memory") or {})
        init = (v.get("initialization") or [{}])[0] if isinstance(v.get("initialization"), list) else {}
        out[vmid] = {"address": r.get("address"), "type": kind, "name": v.get("name") or init.get("hostname"),
                     "node": v.get("node_name"), "cores": cpu.get("cores"),
                     "mem_mib": mem.get("dedicated"), "started": v.get("started"), "template": v.get("template")}
    return out


MAC_RE = r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"


def guest_addresses(g: dict) -> tuple[dict[str, str], set[str]]:
    """({ip: source}, {mac}) of a guest from its snapshot: static IPs in its config (LXC `ip=`, VM
    cloud-init `ipconfigN`), addresses it reports (guest agent / LXC interfaces), and NIC MACs."""
    ips, macs = {}, set()
    for k, v in (g.get("config") or {}).items():
        v = str(v)
        if k.startswith(("net", "ipconfig")):
            for ip in re.findall(r"(?<![\w])ip6?=([0-9A-Fa-f.:]+)(?:/\d+)?", v):
                ips.setdefault(ip.lower(), "config")
        if k.startswith("net"):
            macs.update(m.lower() for m in re.findall(MAC_RE, v))
    for a in g.get("ips") or []:
        if a.get("ip"):
            ips.setdefault(str(a["ip"]).lower(), a.get("source") or "agent")
        if a.get("mac"):
            macs.add(str(a["mac"]).lower())
    return ips, macs


def match_guests(guests, net_hosts: dict) -> dict[str, tuple[dict, str]]:
    """{scanned ip: (guest, how)} — by IP (config or reported), then MAC, then DNS name = guest name."""
    by_ip, by_mac, by_name = {}, {}, {}
    for g in guests:
        if g.get("template"):
            continue
        ips, macs = guest_addresses(g)
        for ip, src in ips.items():
            by_ip.setdefault(ip, (g, f"{src} IP"))
        for m in macs:
            by_mac.setdefault(m, g)
        if g.get("name"):
            by_name.setdefault(str(g["name"]).lower(), g)
    out = {}
    for ip, h in net_hosts.items():
        if ip.lower() in by_ip:
            out[ip] = by_ip[ip.lower()]
        elif (h.get("mac") or "").lower() in by_mac:
            out[ip] = (by_mac[h["mac"].lower()], "MAC")
        else:
            for name in h.get("hostnames") or []:
                g = by_name.get(str(name or "").lower().split(".")[0])
                if g:
                    out[ip] = (g, f"DNS name {name}")
                    break
    return out


def load_tofu(args, root: Path, env: str):
    if args.no_tofu:
        return None, "skipped (--no-tofu)"
    if args.tofu_json:
        return json.loads(Path(args.tofu_json).read_text()), args.tofu_json
    d = root / "tofu" / "environments" / env
    if not d.is_dir():
        return None, f"{d.relative_to(root)} does not exist"
    r = subprocess.run(["tofu", "show", "-json", "-no-color"], cwd=d, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        lines = [l.strip(" ╷│╵") for l in r.stderr.splitlines() if l.strip(" ╷│╵")]
        return None, ("`tofu show -json` failed — run via with_secrets.py so the state backend is reachable"
                      + (f" ({hmlib.clean(lines[0], 160)})" if lines else ""))
    return json.loads(r.stdout or "{}"), f"tofu show -json ({d.relative_to(root)})"


def compare_state(px: dict, state: dict, prefix: str = "") -> tuple[list[str], int]:
    """One site's live guests against its OpenTofu state: (report lines, findings)."""
    live = {g["vmid"]: g for g in px.get("guests", [])}
    managed = tofu_guests(state)
    L, issues = [], 0
    unmanaged = [g for vid, g in live.items() if vid not in managed]
    missing = [m for vid, m in managed.items() if vid not in live]
    if unmanaged:
        issues += len(unmanaged)
        L += [f"**Not managed by OpenTofu ({len(unmanaged)})** — candidates for `tofu import` (needs approval):", ""]
        L += [f"- {prefix}{g['vmid']} {g['type']} `{g['name']}` on {g['node']} ({g['status']}"
              f"{', template' if g['template'] else ''})" for g in unmanaged]
        L.append("")
    if missing:
        issues += len(missing)
        L += [f"**In state but missing from Proxmox ({len(missing)})** — deleted outside OpenTofu? A plan would recreate them:", ""]
        L += [f"- {prefix}{vid} `{m['address']}` ({m['type']} {m['name'] or ''})" for vid, m in managed.items() if vid not in live]
        L.append("")
    diffs = []
    for vid, m in managed.items():
        g = live.get(vid)
        if not g:
            continue
        ref = f"{prefix}{vid} `{m['address']}`"
        if m["node"] and g["node"] != m["node"]:
            diffs.append(f"- {ref}: node {m['node']} → live {g['node']} (migrated?)")
        if m["cores"] and g["cpus"] and int(g["cpus"]) != int(m["cores"]):
            diffs.append(f"- {ref}: cores {m['cores']} → live {g['cpus']}")
        if m["mem_mib"] and g["mem_gib"] and abs(g["mem_gib"] * 1024 - int(m["mem_mib"])) > 64:
            diffs.append(f"- {ref}: memory {m['mem_mib']} MiB → live {round(g['mem_gib']*1024)} MiB")
        if m["started"] is True and g["status"] != "running":
            diffs.append(f"- {ref}: declared started, live {g['status']}")
    if diffs:
        issues += len(diffs)
        L += [f"**Attribute drift ({len(diffs)})** — confirm with `tofu plan -refresh-only`:", "", *diffs, ""]
    if not (unmanaged or missing or diffs):
        L += ["No differences.", ""]
    return L, issues


STALE_INPUTS = ["homelab.yaml", "ansible/inventory", "discovery/proxmox.json", "discovery/network.json",
                "discovery/containers.json"]


def container_ips(root: Path) -> dict[str, str]:
    """Addresses of containers (docker-containers.yml → discovery/containers.json, and hand-written
    discovery/<name>-containers.json in the same layout, e.g. a NAS): ip → "name (runtime on host)"."""
    out = {}
    for f in sorted((root / "discovery").glob("*containers.json")):
        try:
            data = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        for host, entry in (data.get("hosts") or {}).items():
            for c in (entry or {}).get("containers") or []:
                for ip in c.get("ips") or []:
                    out.setdefault(str(ip), f"`{hmlib.clean(c.get('name'), 80)}` ({c.get('runtime') or 'container'} "
                                            f"on `{hmlib.clean(host, 80)}`)")
    return out


def newest_inputs(root: Path, than: float) -> list[str]:
    """Inputs of the report changed after `than` (an mtime): files, or the newest file under a directory."""
    out = []
    for rel in STALE_INPUTS:
        p = root / rel
        files = (list(root.glob(rel)) if "*" in rel else
                 [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else ([p] if p.is_file() else []))
        if any(f.stat().st_mtime > than for f in files):
            out.append(rel)
    return out


def site_suffix(cfg: dict, ip: str) -> str:
    """' [site offsite]' when a site's `ranges` hold ip."""
    st = hmlib.site_of_address(cfg, ip)
    return f" [site {hmlib.site_title(st)}]" if st else ""


def vlan_suffix(cfg: dict, ip: str) -> str:
    """' [VLAN 20 DMZ]' when network.vlans has a cidr holding ip."""
    label = hmlib.vlan_label(cfg, ip=ip)
    return f" [{label}]" if label else ""


def extra_ips(v: dict) -> list[str]:
    """hm_extra_ips host var: addresses besides ansible_host (CIDR suffixes allowed)."""
    raw = v.get("hm_extra_ips") or []
    out = []
    for x in raw if isinstance(raw, list) else str(raw).replace(",", " ").split():
        try:
            out.append(str(ipaddress.ip_interface(str(x).strip()).ip))
        except ValueError:
            continue
    return out


def storage_findings(px: dict, snap: dict) -> list[str] | None:
    """Configured storage (default/lxc/image, per node with proxmox.nodes) missing on a node or lacking the
    content it is used for (GitHub issue #54). None: nothing configured or nothing to compare with."""
    where = px.get("_where") or "proxmox"
    try:
        per_node = hmlib.node_storages(px)
    except hmlib.ConfigError as e:
        return [f"- {e}"]
    if not (px.get("default_storage") or per_node) or not snap.get("storage"):
        return None
    store = {(s.get("node"), s.get("storage")): s for s in snap["storage"]}
    names = ([n["node"] for n in snap.get("nodes") or [] if n.get("status") in (None, "online")]
             or sorted({s.get("node") for s in snap["storage"] if s.get("node")}))
    found = [f"- `{where}.nodes.{n}`: no such node in the snapshot." for n in per_node if n not in names
             and n not in {x.get("node") for x in snap.get("nodes") or []}]
    for node in names:
        use, missing = hmlib.node_storage(px, node), set()
        for key, need, label in hmlib.STORAGE_ROLES:
            name = use[key]
            s = store.get((node, name))
            if not name:
                continue
            if s is None:
                if name not in missing:
                    missing.add(name)
                    found.append(f"- {node}: {key} `{name}` ({label}) is not on this node"
                                 + ("." if node in per_node else f" — set `{where}.nodes.{node}` to its own storage."))
            elif need and s.get("content") is not None and need not in str(s["content"]).split(","):
                found.append(f"- {node}: {key} `{name}` ({label}) doesn't take `{need}` content "
                             f"({s['content'] or 'none'}).")
    return found


def load_ansible(root: Path):
    inv = root / "ansible" / "inventory" / "managed"
    if not inv.exists():
        return {}, "no ansible/inventory/managed"
    r = subprocess.run(["ansible-inventory", "-i", str(inv), "--list"], cwd=root / "ansible",
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return {}, "ansible-inventory failed: " + (r.stderr.strip().splitlines() or ["?"])[-1]
    data = json.loads(r.stdout)
    hv = (data.get("_meta") or {}).get("hostvars") or {}
    hosts = {}
    for group, g in data.items():
        if group == "_meta" or not isinstance(g, dict):
            continue
        for h in g.get("hosts", []):
            hosts.setdefault(h, {"groups": [], **(hv.get(h) or {})})["groups"].append(group)
    for h, gs in hmlib.inventory_groups(data).items():   # parent groups too (site_<name>: {children: …})
        if h in hosts:
            hosts[h]["_groups_all"] = sorted(gs)
    return hosts, f"ansible-inventory ({inv.relative_to(root)})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env")
    ap.add_argument("--tofu-json")
    ap.add_argument("--no-tofu", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--stale", action="store_true", help="only check whether drift.md is older than its inputs")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
    except hmlib.ConfigError as e:
        print(f"drift_report: {e}", file=sys.stderr)
        return 3
    root = Path(cfg["_root"])
    env = a.env or hmlib.get(cfg, "opentofu.environment", "homelab")
    if a.stale:
        report = Path(a.out) if a.out else root / "discovery" / "drift.md"
        if not report.is_file():
            print(f"{report.relative_to(root)} missing — run drift_report.py")
            return 2
        newer = newest_inputs(root, report.stat().st_mtime)
        print(f"stale: changed since the report: {', '.join(newer)} — regenerate it before using it" if newer
              else "fresh: no input changed since the report")
        return 1 if newer else 0

    try:
        all_sites = hmlib.sites(cfg)
        snaps = hmlib.proxmox_snapshots(cfg)
        nets = hmlib.network_snapshots(cfg)   # per site, from network.json (GitHub #72, #75)
        ignores = {st["name"]: hmlib.site_entries(cfg, "discovery.ignore_unmanaged", st["name"]) for st in all_sites}
    except hmlib.ConfigError as e:
        print(f"drift_report: {e}", file=sys.stderr)
        return 3
    multi = len(all_sites) > 1
    for st, p in snaps:
        for g in p.get("guests") or []:
            g["_site"] = st["name"]
    px = next((p for st, p in snaps if st["default"]), None)
    others = [(st, p) for st, p in snaps if not st["default"]]
    all_guests = [g for _, p in snaps for g in p.get("guests") or []]
    gref = (lambda g: f"{g['_site']}/{g['vmid']}") if multi else (lambda g: str(g["vmid"]))
    in_site = (lambda st: f" — site {hmlib.site_title(st)}") if multi else (lambda st: "")
    net = None
    for _, db in nets:   # every site's scan in one view for matching guests and inventory hosts
        net = net or {"hosts": {}, "updated_at": db.get("updated_at")}
        for ip, h in (db.get("hosts") or {}).items():
            net["hosts"].setdefault(ip, h)
    states = {}   # site name → (state or None, why / source); each site is compared with its own environment
    for st in all_sites:
        if st["default"]:
            states[st["name"]] = load_tofu(a, root, env)
        else:
            states[st["name"]] = load_tofu(argparse.Namespace(no_tofu=a.no_tofu, tofu_json=None), root,
                                           hmlib.tofu_env(cfg, st["name"]))
            if not (root / "tofu" / "environments" / hmlib.tofu_env(cfg, st["name"])).is_dir() and not a.no_tofu:
                states[st["name"]] = (None, f"no OpenTofu environment (init_repo.py --add-site {st['name']})")
    ans, ans_src = load_ansible(root)

    L = [f"# Drift report — {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}", "",
         "| Source | Status |", "|---|---|",
         f"| Proxmox snapshot{in_site(all_sites[0])} | {px['collected_at'] if px else 'missing — run proxmox_inventory.py'} |",
         *[f"| Proxmox snapshot{in_site(st)} | " + (next((p['collected_at'] for x, p in others if x["name"] == st["name"]), None)
           or f"missing — run proxmox_inventory.py --site {st['name']}") + " |"
           for st in all_sites[1:] if st["proxmox"] and st["proxmox"].get("endpoint")],
         *([f"| Network scan{in_site(st) if len(nets) > 1 else ''} | {db.get('updated_at')} |" for st, db in nets]
           or ["| Network scan | missing — run nmap_scan.py |"]),
         *[f"| OpenTofu state{in_site(st)} | {msg if state is not None else 'unavailable: ' + msg} |"
           for st in all_sites for state, msg in [states[st["name"]]]
           if st["default"] or (st["proxmox"] and st["proxmox"].get("endpoint"))],
         f"| Ansible inventory | {ans_src} ({len(ans)} hosts) |", ""]
    issues = 0

    for st, p in snaps:
        state, _ = states[st["name"]]
        if state is not None:
            lines, n = compare_state(p, state, f"{st['name']}/" if multi else "")
            L += [f"## Proxmox ↔ OpenTofu{in_site(st)}", "", *lines]
            issues += n
            continue
        # No state: fall back to the `tofu` tag every module sets. Weaker than state (a tag can be hand-edited),
        # but still shows guests nobody manages.
        untagged = [g for g in p.get("guests") or [] if "tofu" not in str(g.get("tags") or "").replace(",", ";").split(";")
                    and not g.get("template")]  # Packer-built templates are untagged by design
        L += [f"## Proxmox ↔ OpenTofu{in_site(st)} (by `tofu` tag — state unavailable)", ""]
        if untagged:
            issues += len(untagged)
            L += [f"**No `tofu` tag ({len(untagged)})** — probably not managed by OpenTofu; confirm with state when reachable:", ""]
            L += [f"- {gref(g)} {g['type']} `{g['name']}` on {g['node']} ({g['status']}{', template' if g['template'] else ''})"
                  for g in untagged]
        else:
            L.append("Every guest carries the `tofu` tag.")
        L.append("")

    for st, p in snaps:
        L += [f"## Backups{in_site(st)}", ""]
        found = []
        if not [x for x in p.get("storage", []) if "backup" in str(x.get("content") or "").split(",")]:
            found.append("- No storage accepts `backup` content — vzdump has nowhere to write.")
        jobs = p.get("backup_jobs")
        if jobs is None:
            L.append("Backup jobs not collected (older snapshot or token can't read /cluster/backup).")
        else:
            active = [j for j in jobs if j.get("enabled")]
            if not active:
                found.append("- No enabled scheduled backup job.")
            else:
                # vmid/exclude: lists since 0.17.0; older snapshots hold strings that may end in "…" (cut
                # at 200 characters, GitHub issue #41): unknown, so warn instead of reporting false gaps.
                unknown = [j.get("id") or "?" for j in active
                           if hmlib.id_list(j.get("vmid")) is None or hmlib.id_list(j.get("exclude")) is None]
                if unknown:
                    found.append(f"- Can't read the guest list of job(s) {', '.join(f'`{x}`' for x in unknown)} "
                                 "(cut off in an older snapshot): run proxmox_inventory.py again.")
                else:
                    ids = {i for j in active if not j.get("all") for i in hmlib.id_list(j.get("vmid"))}
                    pools = {j["pool"] for j in active if j.get("pool")}
                    for g in p.get("guests") or []:
                        if g.get("template"):
                            continue
                        by_all = any(j.get("all") and g["vmid"] not in hmlib.id_list(j.get("exclude")) for j in active)
                        if not (by_all or g["vmid"] in ids or (g.get("pool") and g["pool"] in pools)):
                            found.append(f"- {gref(g)} `{g['name']}` is in no backup job.")

        if found:
            issues += len(found)
            L += found
            if any(f.endswith("is in no backup job.") for f in found):
                L += ["", "To add them to a job: references/proxmox.md, \"Backup jobs\"."]
        elif jobs is not None:
            L.append("Every guest is in an enabled backup job.")
        L.append("")

    for st, p in snaps:
        found = storage_findings(st["proxmox"] or {}, p)
        if found is None:
            continue
        L += [f"## Storage{in_site(st)}", ""]
        if found:
            issues += len(found)
            L += [*found, "", "Storage per node: references/proxmox.md, \"Storage per node\"."]
        else:
            L.append("Each node has the configured storage, with the content it needs.")
        L.append("")

    if ans:
        L += ["## Ansible inventory", ""]
        live_names = {(g["name"] or "").lower() for g in all_guests}
        guest_ips = {ip for g in all_guests for ip in guest_addresses(g)[0]}
        net_ips = set((net or {}).get("hosts", {}).keys())
        ghosts = []
        for h, v in ans.items():
            ip = v.get("ansible_host")
            in_px = h.lower().split(".")[0] in live_names or (ip or "").lower() in guest_ips
            in_net = bool(({ip} | set(extra_ips(v))) & net_ips) if ip else bool(set(extra_ips(v)) & net_ips)
            if snaps and net and not in_px and not in_net:
                ghosts.append(f"- `{h}` ({ip or 'no ansible_host'}) — not a Proxmox guest and not seen on the network")
        known_sites = {st["name"] for st in all_sites if st["name"]}
        site_problems = []
        for h, v in sorted(ans.items()):
            hs = hmlib.host_sites(v.get("_groups_all") or v.get("groups"))
            if len(hs) > 1:
                site_problems.append(f"- `{h}` is in several site groups ({', '.join('site_' + x for x in hs)}): keep one")
            site_problems += [f"- `{h}` is in `site_{x}`, but homelab.yaml has no site {x!r}" for x in hs
                              if x not in known_sites]
        if site_problems:
            issues += len(site_problems)
            L += [f"**Site groups ({len(site_problems)})**:", "", *site_problems, ""]
        ambiguous = hmlib.site_ambiguities(cfg, {h: v.get("_groups_all") or v.get("groups") or []
                                                 for h, v in ans.items()})
        if ambiguous:   # two or more sites: what "no site" leaves open (GitHub issue #63)
            issues += len(ambiguous)
            L += [f"**Site ambiguity ({len(ambiguous)})**:", "", *[f"- {x}" for x in ambiguous], ""]
        if ghosts:
            issues += len(ghosts)
            L += [f"**Inventory hosts not found anywhere ({len(ghosts)})**:", "", *ghosts, ""]
        else:
            L += ["All inventory hosts accounted for." if (snaps and net) else "Needs both snapshots to check.", ""]

    matched = match_guests(all_guests, net["hosts"]) if (snaps and net) else {}
    if snaps and net:
        L += ["## Proxmox guests ↔ network", ""]
        if matched:
            L += [f"{len(matched)} scanned address(es) belong to Proxmox guests:", ""]
            L += [f"- {ip} → {gref(g)} {g['type']} `{g['name']}` ({how})" + vlan_suffix(cfg, ip)
                  for ip, (g, how) in sorted(matched.items(), key=lambda x: ipaddress.ip_address(x[0]))]
        else:
            L.append("No scanned address matched a guest.")
        if not any(g.get("config") for g in all_guests):
            L += ["", "Snapshot has no guest configs: run `proxmox_inventory.py --details` to match by IP and MAC."]
        for st, p in snaps:
            agent = (p.get("guest_ip_sources") or {}).get("agent", "")
            if agent.startswith("forbidden"):
                L += ["", f"VM IPs from the guest agent were not read{in_site(st)} — {agent}."]
        seen = {(g["_site"], g["vmid"]) for g, _ in matched.values()}
        silent = [g for g in all_guests if g["status"] == "running" and not g.get("template")
                  and (g["_site"], g["vmid"]) not in seen]
        if silent:
            L += ["", f"Running guests not matched to any scanned address ({len(silent)}) — outside the scanned "
                  "ranges, firewalled, or no IP known:", ""]
            L += [f"- {gref(g)} {g['type']} `{g['name']}`" for g in silent]
        L.append("")

    if net:
        default_name = all_sites[0]["name"]
        own_files = {st["name"] for st, _ in nets}
        # what a site's network file is checked against: that site's inventory hosts, guests and nodes, and on the
        # default site's file also those of sites without a file of their own (scanned without --site)
        belongs = lambda x, st: not multi or x == st["name"] or (st["default"] and x not in own_files)
        host_site = lambda v: (hmlib.host_sites(v.get("_groups_all") or v.get("groups")) or [default_name])[0]
        secondary = {ip: h for h, v in ans.items() for ip in extra_ips(v)}
        containers = container_ips(root)
        per_site = len(nets) > 1
        for st, db in nets:
            hosts_here = db.get("hosts") or {}
            here = [v for v in ans.values() if belongs(host_site(v), st)]
            known_ips = {v.get("ansible_host") for v in here if v.get("ansible_host")}
            known_ips |= {ip for v in here for ip in extra_ips(v)}
            known_ips |= {ip for ip, (g, _) in matched.items() if belongs(g.get("_site", default_name), st)}
            for sp, p in snaps:
                if belongs(sp["name"], st):
                    for node_nets in (p.get("networks") or {}).values():
                        for n in node_nets:
                            if n.get("cidr"):
                                known_ips.add(str(ipaddress.ip_interface(n["cidr"]).ip))
            known_ips |= set(containers)
            ignore = ignores[st["name"]]
            ignored = lambda ip: any(ipaddress.ip_address(ip) in n for n in ignore
                                     if n.version == ipaddress.ip_address(ip).version)
            unknown = [(ip, h) for ip, h in hosts_here.items() if ip not in known_ips and not ignored(ip)]
            L += [f"## Network devices not in managed inventory{in_site(st) if per_site else ''}", ""]
            if unknown:
                L += [f"{len(unknown)} device(s) — add to inventory, or list in `discovery.ignore_unmanaged`"
                      + (f" (`{{ip: …, site: {st['name']}}}` for this site only)" if multi else "")
                      + (" (Proxmox guests are listed above, not here)" if matched else "") + ":", ""]
                L += [f"- {ip} {(h.get('hostnames') or [''])[0]} — {h.get('device_type_guess')} {h.get('vendor') or ''}".rstrip()
                      + vlan_suffix(cfg, ip) + (site_suffix(cfg, ip) if multi and st["default"] else "")
                      + (" — **management controller (BMC)**: keep it off user networks" if
                         "bmc" in str(h.get("device_type_guess") or "").split("/") else "")
                      for ip, h in sorted(unknown)]
            else:
                L.append("None.")
            L.append("")
        seen_secondary = sorted((ip for ip in secondary if ip in net["hosts"]), key=ipaddress.ip_address)
        if seen_secondary:
            L += [f"Secondary addresses of inventory hosts (`hm_extra_ips`, {len(seen_secondary)}):", ""]
            L += [f"- {ip} → `{secondary[ip]}` (secondary)" for ip in seen_secondary]
            L.append("")
        inventory_ips = {v.get("ansible_host") for v in ans.values()} | set(matched) | set(secondary)
        seen_containers = sorted((ip for ip in containers if ip in net["hosts"] and ip not in inventory_ips),
                                 key=ipaddress.ip_address)
        if seen_containers:
            L += [f"Container addresses (`discovery/*containers.json`, {len(seen_containers)}):", ""]
            L += [f"- {ip} → {containers[ip]}" + vlan_suffix(cfg, ip) for ip in seen_containers]
            L.append("")

    if snaps:  # VLAN/IP per guest NIC is checked there (GitHub issue #62)
        L += ["Guest NICs (VLAN, addresses, subnet and ansible_host checks): `discovery/guest-map.md`"
              + ("" if (root / "discovery" / "guest-map.md").exists() else " — run guest_map.py"), ""]
    L.append(f"**Total findings: {issues}** (unmanaged network devices listed separately)")
    text = "\n".join(L) + "\n"
    out = Path(a.out) if a.out else root / "discovery" / "drift.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
