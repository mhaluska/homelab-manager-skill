#!/usr/bin/env python3
"""Proxmox guest snapshots around patching (VMs and LXC containers).

    pve_snapshot.py list <guest…>                                  # read-only token
    pve_snapshot.py check <guest…> [--json]                        # read-only: can each one be snapshotted?
    pve_snapshot.py create <guest…> [--name prepatch-YYYYMMDD] [--description TEXT]
    pve_snapshot.py delete <guest…> --name NAME                    # needs the user's yes (the guard asks)
    pve_snapshot.py rollback <guest> --name NAME                   # needs the user's yes (the guard asks)

<guest> is a VMID or a guest name from the cluster. create/delete/rollback use the provisioning token
(proxmox.tokens.provisioning, role HomelabProvisioner: VM.Snapshot; rollback also VM.Snapshot.Rollback
on Proxmox VE 8+), list the read-only one. Each write waits for its Proxmox task and fails when the task
does. Snapshots are disk-only (no RAM state): fast, and enough to roll back a failed update.
A VM snapshot needs snapshot-capable storage (ZFS, LVM-thin, Ceph, qcow2); raw on LVM or directory
storage can't be snapshotted — the task error says so.
check (before a patch run with snapshot=true) reports every guest, not only the first problem: ok, not a
guest of the cluster (e.g. an LXD container on a NAS: snapshot it there), or no snapshot (Proxmox's snapshot
feature check, with the reason when the config shows one: a bind or device mount point of a container).
Exit 0 when all can be snapshotted, 1 when not.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
from proxmox_inventory import PVE  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,39}$")  # Proxmox snapshot name rules
TASK_TIMEOUT = 1800


def default_name() -> str:
    return "prepatch-" + dt.date.today().strftime("%Y%m%d")


def resolve(pve: PVE, wanted: list[str]) -> tuple[dict[str, dict], dict[str, str]]:
    """VMIDs or names → ({wanted: cluster resource {vmid, name, node, type: qemu|lxc}}, {wanted: problem})."""
    res = [r for r in (pve.get("/cluster/resources", type="vm") or []) if r.get("type") in ("qemu", "lxc")]
    found, problems = {}, {}
    for w in wanted:
        hits = [r for r in res if str(r.get("vmid")) == w or (r.get("name") or "").lower() == w.lower()]
        if not hits:
            problems[w] = f"No VM or container {w!r} in the cluster."
        elif len(hits) > 1:
            problems[w] = f"{w!r} is ambiguous: VMIDs {', '.join(str(h['vmid']) for h in hits)}. Use the VMID."
        elif hits[0].get("template"):
            problems[w] = f"{w!r} is a template: templates can't be snapshotted."
        else:
            found[w] = hits[0]
    return found, problems


def find_guests(pve: PVE, wanted: list[str]) -> list[dict]:
    """Resolve VMIDs or names to cluster resources; exits on the first one that isn't a snapshottable guest."""
    found, problems = resolve(pve, wanted)
    for w in wanted:
        if w in problems:
            raise SystemExit(problems[w])
    return [found[w] for w in wanted]


def blocking_mounts(conf: dict) -> list[str]:
    """Container mount points Proxmox can't snapshot: bind mounts and device passthrough (a path, not a volume)."""
    return [f"{k}: {v.split(',')[0]}" for k, v in sorted(conf.items())
            if re.fullmatch(r"mp\d+", k) and isinstance(v, str) and v.split(",")[0].startswith("/")]


def check(pve: PVE, wanted: list[str]) -> dict:
    """{ok: [..], not_a_guest: {wanted: why}, no_snapshot: {wanted: why}} — read-only (VM.Audit)."""
    found, problems = resolve(pve, wanted)
    out = {"ok": [], "not_a_guest": problems, "no_snapshot": {}}
    for w, g in found.items():
        feat = pve.get(base(g) + "/feature", feature="snapshot") or {}
        if feat.get("hasFeature"):
            out["ok"].append(w)
            continue
        mounts = blocking_mounts(pve.get(base(g) + "/config") or {}) if g["type"] == "lxc" else []
        out["no_snapshot"][w] = f"{label(g)}: " + (
            "bind or device mount point " + "; ".join(mounts) if mounts
            else "a disk is on storage without snapshots (raw on directory, LVM or NFS storage)")
    return out


def base(g: dict) -> str:
    return f"/nodes/{g['node']}/{g['type']}/{g['vmid']}"


def wait(pve: PVE, node: str, upid: str, what: str) -> None:
    deadline = time.monotonic() + TASK_TIMEOUT
    while time.monotonic() < deadline:
        st = pve.get(f"/nodes/{node}/tasks/{upid}/status") or {}
        if st.get("status") == "stopped":
            if st.get("exitstatus") != "OK":
                raise SystemExit(f"{what} failed: {st.get('exitstatus')}")
            return
        time.sleep(2)
    raise SystemExit(f"{what}: task {upid} still running after {TASK_TIMEOUT // 60} min — check it in Proxmox.")


def snapshots(pve: PVE, g: dict) -> list[dict]:
    return [s for s in (pve.get(base(g) + "/snapshot") or []) if s.get("name") != "current"]


def label(g: dict) -> str:
    return f"{g['vmid']} {g.get('name') or ''}".strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["list", "check", "create", "delete", "rollback"])
    ap.add_argument("guests", nargs="+")
    ap.add_argument("--name")
    ap.add_argument("--description", default="")
    ap.add_argument("--json", action="store_true", help="check: print the result as JSON")
    a = ap.parse_args()
    name = a.name or (default_name() if a.action == "create" else None)
    if a.action in ("delete", "rollback") and not name:
        ap.error(f"{a.action} needs --name (see `pve_snapshot.py list`)")
    if name and not NAME_RE.match(name):
        ap.error("--name: 2–40 letters, digits, - or _, starting with a letter")
    if a.action == "rollback" and len(a.guests) != 1:
        ap.error("rollback one guest at a time")
    try:
        cfg = hmlib.load_config()
        endpoint = hmlib.get(cfg, "proxmox.endpoint")
        if not endpoint:
            raise hmlib.ConfigError("proxmox.endpoint is empty in homelab.yaml.")
        secret = hmlib.get(cfg, "proxmox.tokens.read_only", "proxmox-ro") if a.action in ("list", "check") \
            else hmlib.get(cfg, "proxmox.tokens.provisioning", "proxmox-rw")
        pve = PVE(endpoint, hmlib.read_secret(cfg, secret), hmlib.proxmox_ssl_context(cfg))
    except hmlib.ConfigError as e:
        print(f"pve_snapshot: {e}", file=sys.stderr)
        return 3
    if a.action == "check":
        res = check(pve, a.guests)
        if a.json:
            print(json.dumps(res, indent=2))
        else:
            for w in res["ok"]:
                print(f"{w}: ok")
            for w, why in res["not_a_guest"].items():
                print(f"{w}: not a Proxmox guest — {why}")
            for w, why in res["no_snapshot"].items():
                print(f"{w}: can't be snapshotted — {why}")
        return 0 if not (res["not_a_guest"] or res["no_snapshot"]) else 1
    guests = find_guests(pve, a.guests)

    if a.action == "list":
        for g in guests:
            snaps = snapshots(pve, g)
            print(f"{label(g)} ({g['type']} on {g['node']}): " + ("no snapshots" if not snaps else ""))
            for s in sorted(snaps, key=lambda s: s.get("snaptime", 0)):
                when = dt.datetime.fromtimestamp(s["snaptime"]).strftime("%Y-%m-%d %H:%M") if s.get("snaptime") else "?"
                print(f"  {s['name']:<40} {when}  {hmlib.clean(s.get('description') or '', 80)}")
        return 0

    apply(pve, a.action, guests, name, a.description)
    return 0


def apply(pve: PVE, action: str, guests: list[dict], name: str, description: str = "") -> None:
    """create / delete / rollback snapshot `name` on each guest, waiting for every Proxmox task."""
    for g in guests:
        what = f"{action} snapshot {name!r} of {label(g)}"
        existing = {s["name"] for s in snapshots(pve, g)}
        if action == "create":
            if name in existing:
                print(f"{label(g)}: snapshot {name!r} already exists — kept (pass another --name for a new one)")
                continue
            params = {"snapname": name, "description": description or f"homelab-manager {name}"}
            if g["type"] == "qemu":
                params["vmstate"] = 0
            upid = pve.write("POST", base(g) + "/snapshot", **params)
        elif name not in existing:
            raise SystemExit(f"{label(g)} has no snapshot {name!r} (existing: {', '.join(sorted(existing)) or 'none'}).")
        elif action == "delete":
            upid = pve.write("DELETE", base(g) + f"/snapshot/{name}")
        else:
            upid = pve.write("POST", base(g) + f"/snapshot/{name}/rollback")
        if upid:
            wait(pve, g["node"], upid, what)
        print(f"{label(g)}: {action} {name!r} done")


if __name__ == "__main__":
    sys.exit(main())
