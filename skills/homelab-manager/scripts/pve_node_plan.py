#!/usr/bin/env python3
"""Plan patching one Proxmox VE node: what happens to each of its guests (read-only).

    pve_node_plan.py <node> [--site NAME] [--max-mem-pct 85] [--no-migrate] [--json]

Reads discovery/proxmox.json (refresh it first: `proxmox_inventory.py --details`) and decides per guest:
  migrate      running, every disk on shared storage, no passthrough/local ISO, not HA-managed: live-migrated
               (VM) or restart-migrated (LXC) to another online node, placed largest memory first on the node
               with the lowest memory use relative to its size, never above --max-mem-pct; migrated back after
  ha           HA-managed: moved by HA node maintenance mode and brought back by it
  stop         running but pinned to the node (local disks, passthrough, no room elsewhere, --no-migrate):
               shut down cleanly before the reboot, started again after it
  stays-stopped  stopped now, stays stopped (not moved)
Writes the plan into discovery/pve-patch.json (under its site, then node: GitHub issue #75), which
patch-proxmox-node.yml executes after checking it against
the live cluster, and prints the plan with each guest's autostart and storage. Exit 4 if the node can't be
patched safely now (cluster not quorate, another node offline, unknown node, snapshot without --details).
Another site (sites: in homelab.yaml): --site NAME reads and writes that site's part of both files (node names
repeat across sites). A standalone node (no cluster) has no other node: every running guest is stopped for the
reboot. Local LVM-thin pools are listed with the guests that stop on them and the node's uptime (GitHub issue #91).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

DISK_KEY = re.compile(r"^(scsi|virtio|sata|ide|efidisk|tpmstate|unused|mp)\d+$|^rootfs$")
LOCAL_DEVICE_KEY = re.compile(r"^(hostpci|usb|dev|virtiofs)\d+$")


def volumes(conf: dict) -> list[tuple[str, str]]:
    """[(config key, storage or 'path:/…' / 'cdrom')] of every disk, mount point and CD drive."""
    out = []
    for k, v in conf.items():
        if not DISK_KEY.match(k):
            continue
        first = str(v).split(",")[0].strip()
        if first in ("none", ""):
            continue
        if first == "cdrom" or first.startswith("/"):
            out.append((k, f"path:{first}"))
        elif ":" in first:
            out.append((k, first.split(":", 1)[0]))
    return out


def pins(g: dict, shared: set[str]) -> list[str]:
    """Why the guest can't leave its node: local volumes and passthrough devices."""
    conf = g.get("config") or {}
    why = [f"{k} on {st}" if not st.startswith("path:") else f"{k} {st[5:]}"
           for k, st in volumes(conf) if st not in shared]
    why += [f"{k} passthrough" for k in conf if LOCAL_DEVICE_KEY.match(k)]
    return why


def startup_order(g: dict) -> int:
    m = re.search(r"(?:^|,)order=(\d+)", str((g.get("config") or {}).get("startup") or ""))
    return int(m.group(1)) if m else 10**6  # unordered guests start after ordered ones


def onboot(g: dict) -> bool:
    return str((g.get("config") or {}).get("onboot", "0")) in ("1", "true")


def place(guests: list[dict], nodes: list[dict], max_pct: float) -> dict[int, str | None]:
    """{vmid: target node or None}: largest memory first, onto the node whose memory use after the move,
    relative to its size, is lowest — and never above max_pct."""
    used = {n["node"]: float(n.get("mem_used_gib") or 0) for n in nodes}
    cap = {n["node"]: float(n.get("mem_gib") or 0) for n in nodes}
    out = {}
    for g in sorted(guests, key=lambda g: (-(g.get("mem_gib") or 0), g["vmid"])):
        need = float(g.get("mem_gib") or 0)
        fits = [(round((used[n] + need) / cap[n] * 100, 3), n) for n in cap
                if cap[n] and (used[n] + need) / cap[n] * 100 <= max_pct]
        if fits:
            target = min(fits)[1]
            used[target] += need
            out[g["vmid"]] = target
        else:
            out[g["vmid"]] = None
    return out


def make_plan(inv: dict, node: str, max_pct: float = 85, migrate: bool = True) -> tuple[dict, list[str]]:
    """(plan, blockers). Blockers mean: don't patch this node now."""
    blockers = []
    nodes = inv.get("nodes") or []
    names = {n["node"] for n in nodes}
    if node not in names:
        return {}, [f"node {node!r} not in the snapshot (nodes: {', '.join(sorted(names)) or 'none'})"]
    cluster = inv.get("cluster")
    if cluster and not cluster.get("quorate"):
        blockers.append("cluster is not quorate")
    offline = sorted(n["node"] for n in nodes if n["node"] != node and n.get("status") != "online")
    if offline:
        blockers.append(f"other node(s) offline: {', '.join(offline)} — patch one node at a time with the rest up")
    guests = [g for g in inv.get("guests") or [] if g.get("node") == node and not g.get("template")]
    if guests and not any("config" in g for g in guests):
        # without disk placement every guest would look movable: refuse before classifying anything
        return {}, blockers + ["snapshot has no guest config — refresh with proxmox_inventory.py --details"]
    shared = {s["storage"] for s in inv.get("storage") or [] if s.get("shared")}
    others = [n for n in nodes if n["node"] != node and n.get("status") == "online"]

    rows, movable = [], []
    for g in sorted(guests, key=lambda g: g["vmid"]):
        row = {"vmid": g["vmid"], "type": g.get("type"), "name": g.get("name"), "status": g.get("status"),
               "onboot": onboot(g), "startup_order": startup_order(g), "ha": bool(g.get("hastate")),
               "mem_gib": g.get("mem_gib"), "storage": sorted({st for _, st in volumes(g.get("config") or {})}),
               "action": None, "target": None, "reason": ""}
        pinned = pins(g, shared)
        if g.get("status") != "running":
            row.update(action="stays-stopped", reason="not running")
        elif row["ha"]:
            row.update(action="ha", reason="HA-managed: node maintenance mode moves it"
                       + (f" (pinned: {', '.join(pinned)} — needs HA replication)" if pinned else ""))
        elif pinned:
            row.update(action="stop", reason="pinned: " + ", ".join(pinned))
        elif not migrate:
            row.update(action="stop", reason="--no-migrate")
        elif not others:
            row.update(action="stop", reason="no other online node")
        else:
            movable.append(g)
        rows.append(row)
    targets = place(movable, others, max_pct)
    for row in rows:
        if row["vmid"] in targets:
            t = targets[row["vmid"]]
            if t:
                row.update(action="migrate", target=t, reason="shared storage only")
            else:
                row.update(action="stop", reason=f"no node has room below {max_pct:g}% memory")
    # local LVM-thin pools whose guests stop (GitHub issue #91): the pool is thin_check'ed only when activated,
    # so stopping all its guests or rebooting is the first check since boot; patch-proxmox-node.yml checks first
    up = next((n.get("uptime_s") for n in nodes if n["node"] == node), None)
    thin = []
    for s in sorted(inv.get("storage") or [], key=lambda s: s.get("storage") or ""):
        if s.get("node") != node or s.get("shared") or s.get("type") != "lvmthin":
            continue
        on = [r["vmid"] for r in rows if s["storage"] in r["storage"]]
        if not on:
            continue
        thin.append({"storage": s["storage"], "used_pct": round(100 * s["used_gib"] / s["size_gib"])
                     if s.get("size_gib") and isinstance(s.get("used_gib"), (int, float)) else None,
                     "guests": on, "stop": [r["vmid"] for r in rows if r["vmid"] in on and r["action"] == "stop"]})
    plan = {"node": node, "site": inv.get("site") or "", "standalone": not cluster and len(nodes) == 1,
            "uptime_days": round(up / 86400) if isinstance(up, (int, float)) else None, "lvm_thin": thin,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "snapshot_at": inv.get("collected_at"), **({"details_at": inv["details_at"]} if inv.get("details_at") else {}),
            "max_mem_pct": max_pct, "guests": rows,
            # shut down in reverse startup order, start in startup order (as Proxmox does)
            "stop_order": [r["vmid"] for r in sorted(rows, key=lambda r: (-r["startup_order"], -r["vmid"]))
                           if r["action"] == "stop"]}
    return plan, blockers


def render(plan: dict, blockers: list[str]) -> str:
    where = f" at site {plan['site']}" if plan.get("site") else ""
    lines = [f"Patch plan for node {plan['node']}{where} (snapshot {plan.get('snapshot_at') or '?'}"
             + (f", guest config from {plan['details_at']}" if plan.get("details_at") else "") + "):", ""]
    if plan.get("standalone"):
        lines += ["Standalone node (no cluster): nowhere to move guests — every running guest is down during the "
                  "reboot.", ""]
    lines.append(f"  {'VMID':>6} {'TYPE':<4} {'NAME':<20} {'STATUS':<8} {'ONBOOT':<6} {'HA':<3} "
                 f"{'STORAGE':<22} ACTION")
    for r in plan["guests"]:
        act = r["action"] + (f" → {r['target']}" if r["target"] else "")
        lines.append(f"  {r['vmid']:>6} {r['type'] or '?':<4} {str(r['name'] or '')[:20]:<20} {r['status'] or '?':<8} "
                     f"{'yes' if r['onboot'] else 'no':<6} {'yes' if r['ha'] else '-':<3} "
                     f"{','.join(r['storage'])[:22]:<22} {act}  ({r['reason']})")
    if not plan["guests"]:
        lines.append("  (no guests on this node)")
    counts = {}
    for r in plan["guests"]:
        counts[r["action"]] = counts.get(r["action"], 0) + 1
    lines += ["", "Summary: " + (", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "nothing to move")]
    if plan.get("lvm_thin"):
        days = plan.get("uptime_days")
        lines += ["", "LVM-thin pools on this node (checked only when activated: the reboot is their first thin_check"
                  + (f" in {days} days" if days is not None else "") + "):"]
        for t in plan["lvm_thin"]:
            lines.append(f"  {t['storage']}: " + (f"{t['used_pct']}% used, " if t["used_pct"] is not None else "")
                         + f"{len(t['guests'])} guests, {len(t['stop'])} stopped for the reboot")
        lines += ["  patch-proxmox-node.yml checks their health and metadata use before stopping anything; add",
                  "  -e thin_check=true to also run thin_check on a metadata snapshot (references/patching.md)."]
    if blockers:
        lines += ["", "Do NOT patch this node now:"] + [f"  - {b}" for b in blockers]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("node")
    ap.add_argument("--max-mem-pct", type=float, default=85, help="never fill a target node above this (default 85)")
    ap.add_argument("--no-migrate", action="store_true", help="stop and restore every running guest instead")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--site", help="a node of this site (sites: in homelab.yaml; default: the default site)")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        st = hmlib.site(cfg, a.site)
    except hmlib.ConfigError as e:
        print(f"pve_node_plan: {e}", file=sys.stderr)
        return 3
    root = Path(cfg["_root"])
    try:
        inv = hmlib.site_part(hmlib.proxmox_snapshot_file(root), st, "proxmox_inventory.py --details")
    except hmlib.ConfigError as e:
        print(f"pve_node_plan: {e}", file=sys.stderr)
        return 3
    if not inv:
        print(f"pve_node_plan: no snapshot of site {hmlib.site_key(st)} in discovery/proxmox.json — run "
              "proxmox_inventory.py --details" + (f" --site {st['name']}" if not st["default"] else "") + " first.",
              file=sys.stderr)
        return 4
    inv = {**inv, "site": st["name"]}
    plan, blockers = make_plan(inv, a.node, a.max_mem_pct, not a.no_migrate)
    if not plan:
        print("pve_node_plan: " + "; ".join(blockers), file=sys.stderr)
        return 4
    out = hmlib.discovery_file(root, "pve-patch")
    if not blockers:
        plan["default_site"] = st["default"]   # patch-proxmox-node.yml: a node in no site_<name> group
        plans = hmlib.site_part(out, st) or {}
        plans[a.node] = plan
        hmlib.write_site_part(out, st, plans)
    print(json.dumps({"plan": plan, "blockers": blockers}, indent=2) if a.json else render(plan, blockers))
    if not blockers and not a.json:
        print(f"\nWrote {out.relative_to(root)} (site {hmlib.site_key(st)}, node {a.node}). Show it to the user; patch-proxmox-node.yml checks it against "
              "the live cluster before acting.")
    return 4 if blockers else 0


if __name__ == "__main__":
    sys.exit(main())
