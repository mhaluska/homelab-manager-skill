#!/usr/bin/env python3
"""Compare what is running against what Git declares.

    drift_report.py [--env homelab] [--tofu-json FILE] [--no-tofu] [--out discovery/drift.md]

Sources (all read-only):
  live      discovery/proxmox.json   (proxmox_inventory.py)  and discovery/network.json (nmap_scan.py)
  state     `tofu show -json` in tofu/environments/<env>  (run under with_secrets.py for the state backend)
            or a file passed with --tofu-json
  declared  ansible/inventory/managed via `ansible-inventory --list`

Reports: Proxmox guests not managed by OpenTofu, managed resources missing in Proxmox,
attribute drift (cores, memory, node, status), Ansible hosts that don't exist, which scanned
addresses are Proxmox guests (by config/agent IP, MAC, DNS name), and network devices nobody manages. Attribute drift inside OpenTofu itself is best seen
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
    return hosts, f"ansible-inventory ({inv.relative_to(root)})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env")
    ap.add_argument("--tofu-json")
    ap.add_argument("--no-tofu", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
    except hmlib.ConfigError as e:
        print(f"drift_report: {e}", file=sys.stderr)
        return 3
    root = Path(cfg["_root"])
    env = a.env or hmlib.get(cfg, "opentofu.environment", "homelab")

    px_file, net_file = root / "discovery" / "proxmox.json", root / "discovery" / "network.json"
    px = json.loads(px_file.read_text()) if px_file.exists() else None
    net = json.loads(net_file.read_text()) if net_file.exists() else None
    state, state_src = load_tofu(a, root, env)
    ans, ans_src = load_ansible(root)

    L = [f"# Drift report — {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}", "",
         "| Source | Status |", "|---|---|",
         f"| Proxmox snapshot | {px['collected_at'] if px else 'missing — run proxmox_inventory.py'} |",
         f"| Network scan | {net.get('updated_at') if net else 'missing — run nmap_scan.py'} |",
         f"| OpenTofu state | {state_src if state else 'unavailable: ' + state_src} |",
         f"| Ansible inventory | {ans_src} ({len(ans)} hosts) |", ""]
    issues = 0

    live = {g["vmid"]: g for g in (px or {}).get("guests", [])}
    managed = tofu_guests(state) if state else {}
    if px and state is not None:
        unmanaged = [g for vid, g in live.items() if vid not in managed]
        missing = [m for vid, m in managed.items() if vid not in live]
        L += ["## Proxmox ↔ OpenTofu", ""]
        if unmanaged:
            issues += len(unmanaged)
            L += [f"**Not managed by OpenTofu ({len(unmanaged)})** — candidates for `tofu import` (needs approval):", ""]
            L += [f"- {g['vmid']} {g['type']} `{g['name']}` on {g['node']} ({g['status']}{', template' if g['template'] else ''})"
                  for g in unmanaged]
            L.append("")
        if missing:
            issues += len(missing)
            L += [f"**In state but missing from Proxmox ({len(missing)})** — deleted outside OpenTofu? A plan would recreate them:", ""]
            L += [f"- {vid} `{m['address']}` ({m['type']} {m['name'] or ''})" for vid, m in managed.items() if vid not in live]
            L.append("")
        diffs = []
        for vid, m in managed.items():
            g = live.get(vid)
            if not g:
                continue
            if m["node"] and g["node"] != m["node"]:
                diffs.append(f"- {vid} `{m['address']}`: node {m['node']} → live {g['node']} (migrated?)")
            if m["cores"] and g["cpus"] and int(g["cpus"]) != int(m["cores"]):
                diffs.append(f"- {vid} `{m['address']}`: cores {m['cores']} → live {g['cpus']}")
            if m["mem_mib"] and g["mem_gib"] and abs(g["mem_gib"] * 1024 - int(m["mem_mib"])) > 64:
                diffs.append(f"- {vid} `{m['address']}`: memory {m['mem_mib']} MiB → live {round(g['mem_gib']*1024)} MiB")
            if m["started"] is True and g["status"] != "running":
                diffs.append(f"- {vid} `{m['address']}`: declared started, live {g['status']}")
        if diffs:
            issues += len(diffs)
            L += [f"**Attribute drift ({len(diffs)})** — confirm with `tofu plan -refresh-only`:", "", *diffs, ""]
        if not (unmanaged or missing or diffs):
            L += ["No differences.", ""]

    if px and state is None:
        # No state: fall back to the `tofu` tag every module sets. Weaker than state (a tag can be
        # hand-edited), but still shows guests nobody manages.
        untagged = [g for g in live.values() if "tofu" not in str(g.get("tags") or "").replace(",", ";").split(";")
                    and not g.get("template")]  # Packer-built templates are untagged by design
        L += ["## Proxmox ↔ OpenTofu (by `tofu` tag — state unavailable)", ""]
        if untagged:
            issues += len(untagged)
            L += [f"**No `tofu` tag ({len(untagged)})** — probably not managed by OpenTofu; confirm with state when reachable:", ""]
            L += [f"- {g['vmid']} {g['type']} `{g['name']}` on {g['node']} ({g['status']}{', template' if g['template'] else ''})"
                  for g in untagged]
        else:
            L.append("Every guest carries the `tofu` tag.")
        L.append("")

    if px:
        L += ["## Backups", ""]
        found = []
        if not [st for st in px.get("storage", []) if "backup" in str(st.get("content") or "").split(",")]:
            found.append("- No storage accepts `backup` content — vzdump has nowhere to write.")
        jobs = px.get("backup_jobs")
        if jobs is None:
            L.append("Backup jobs not collected (older snapshot or token can't read /cluster/backup).")
        else:
            active = [j for j in jobs if j.get("enabled")]
            if not active:
                found.append("- No enabled scheduled backup job.")
            else:
                covered_all = [j for j in active if j.get("all")]
                ids = {int(x) for j in active for x in str(j.get("vmid") or "").split(",") if x.strip().isdigit()}
                excl = {int(x) for j in covered_all for x in str(j.get("exclude") or "").split(",") if x.strip().isdigit()}
                for g in live.values():
                    if g.get("template"):
                        continue
                    if not ((covered_all and g["vmid"] not in excl) or g["vmid"] in ids):
                        found.append(f"- {g['vmid']} `{g['name']}` is in no backup job.")
        if found:
            issues += len(found)
            L += found
        elif jobs is not None:
            L.append("Every guest is in an enabled backup job.")
        L.append("")

    if ans:
        L += ["## Ansible inventory", ""]
        live_names = {(g["name"] or "").lower() for g in live.values()}
        guest_ips = {ip for g in live.values() for ip in guest_addresses(g)[0]}
        net_ips = set((net or {}).get("hosts", {}).keys())
        ghosts = []
        for h, v in ans.items():
            ip = v.get("ansible_host")
            in_px = h.lower().split(".")[0] in live_names or (ip or "").lower() in guest_ips
            in_net = ip in net_ips if ip else False
            if px and net and not in_px and not in_net:
                ghosts.append(f"- `{h}` ({ip or 'no ansible_host'}) — not a Proxmox guest and not seen on the network")
        if ghosts:
            issues += len(ghosts)
            L += [f"**Inventory hosts not found anywhere ({len(ghosts)})**:", "", *ghosts, ""]
        else:
            L += ["All inventory hosts accounted for." if (px and net) else "Needs both snapshots to check.", ""]

    matched = match_guests(live.values(), net["hosts"]) if (px and net) else {}
    if px and net:
        L += ["## Proxmox guests ↔ network", ""]
        if matched:
            L += [f"{len(matched)} scanned address(es) belong to Proxmox guests:", ""]
            L += [f"- {ip} → {g['vmid']} {g['type']} `{g['name']}` ({how})"
                  for ip, (g, how) in sorted(matched.items(), key=lambda x: ipaddress.ip_address(x[0]))]
        else:
            L.append("No scanned address matched a guest.")
        if not any(g.get("config") for g in live.values()):
            L += ["", "Snapshot has no guest configs: run `proxmox_inventory.py --details` to match by IP and MAC."]
        agent = (px.get("guest_ip_sources") or {}).get("agent", "")
        if agent.startswith("forbidden"):
            L += ["", f"VM IPs from the guest agent were not read — {agent}."]
        seen = {g["vmid"] for g, _ in matched.values()}
        silent = [g for g in live.values() if g["status"] == "running" and not g.get("template") and g["vmid"] not in seen]
        if silent:
            L += ["", f"Running guests not matched to any scanned address ({len(silent)}) — outside the scanned "
                  "ranges, firewalled, or no IP known:", ""]
            L += [f"- {g['vmid']} {g['type']} `{g['name']}`" for g in silent]
        L.append("")

    if net:
        known_ips = {v.get("ansible_host") for v in ans.values() if v.get("ansible_host")}
        known_ips |= set(matched)
        for node_nets in (px or {}).get("networks", {}).values():
            for n in node_nets:
                if n.get("cidr"):
                    known_ips.add(str(ipaddress.ip_interface(n["cidr"]).ip))
        ignore = set(hmlib.get(cfg, "discovery.ignore_unmanaged", []) or [])
        unknown = [(ip, h) for ip, h in net["hosts"].items() if ip not in known_ips and ip not in ignore]
        L += ["## Network devices not in managed inventory", ""]
        if unknown:
            L += [f"{len(unknown)} device(s) — add to inventory, or list in `discovery.ignore_unmanaged`"
                  + (" (Proxmox guests are listed above, not here)" if matched else "") + ":", ""]
            L += [f"- {ip} {(h.get('hostnames') or [''])[0]} — {h.get('device_type_guess')} {h.get('vendor') or ''}".rstrip()
                  for ip, h in sorted(unknown)]
        else:
            L.append("None.")
        L.append("")

    L.append(f"**Total findings: {issues}** (unmanaged network devices listed separately)")
    text = "\n".join(L) + "\n"
    out = Path(a.out) if a.out else root / "discovery" / "drift.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
