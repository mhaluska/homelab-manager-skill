#!/usr/bin/env python3
"""Proxmox guest snapshots around patching (VMs and LXC containers).

    pve_snapshot.py list <guest…>                                  # read-only token
    pve_snapshot.py check <guest…> [--json]                        # read-only: can each one be snapshotted?
    pve_snapshot.py create <guest…> [--name prepatch-YYYYMMDD] [--description TEXT]
    pve_snapshot.py delete <guest…> --name NAME                    # needs the user's yes (the guard asks)
    pve_snapshot.py rollback <guest> --name NAME [--no-start]      # needs the user's yes (the guard asks)
    pve_snapshot.py prune <guest…> --older-than DAYS [--prefix prepatch-]   # the user's yes (the guard asks)
    … --dry-run                                                    # create/delete/rollback/prune: only show it

`restore` is accepted for `rollback` (lxd_snapshot.py's word). A multi-guest create, delete or prune goes on
after a guest fails and ends with a list of what was done and what failed (exit 1 when anything failed).
prune deletes the snapshots whose name starts with --prefix (default prepatch-) and that are older than DAYS;
--dry-run lists them (and what create/delete/rollback would do) with the read-only token, changing nothing.

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
rollback stops the guest; one that was running is started again (Proxmox's start option, then pve_guest.py's
start if it is still stopped) unless --no-start, and the final status is printed (GitHub issue #59).
--site NAME: a guest of another site's Proxmox (sites: in homelab.yaml), with that site's tokens; VMIDs and
names are only unique within one site. Without it, a guest that is an inventory host picks its site from its
site_<name> group (else from the site ranges holding its ansible_host); VMIDs use the default site.
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
from proxmox_inventory import PVE, PveError  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,39}$")  # Proxmox snapshot name rules
TASK_TIMEOUT = 1800
STATUS_RETRIES = 5   # consecutive failed task-status reads (a node busy with the snapshot) before giving up
ACTION_ALIASES = {"restore": "rollback"}


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


def wait(pve: PVE, node: str, upid: str, what: str, sleep=time.sleep) -> None:
    deadline = time.monotonic() + TASK_TIMEOUT
    failures = 0
    while time.monotonic() < deadline:
        try:
            st = pve.get(f"/nodes/{node}/tasks/{upid}/status") or {}
            failures = 0
        except PveError as e:   # a transient API error while the task runs: try again before giving up
            failures += 1
            if failures >= STATUS_RETRIES:
                raise SystemExit(f"{what}: cannot read the task status ({e}); check task {upid} in Proxmox.")
            sleep(2 * failures)
            continue
        if st.get("status") == "stopped":
            if st.get("exitstatus") != "OK":
                raise SystemExit(f"{what} failed: {st.get('exitstatus')}")
            return
        sleep(2)
    raise SystemExit(f"{what}: task {upid} still running after {TASK_TIMEOUT // 60} min — check it in Proxmox.")


def snapshots(pve: PVE, g: dict) -> list[dict]:
    return [s for s in (pve.get(base(g) + "/snapshot") or []) if s.get("name") != "current"]


def prunable(snaps: list[dict], prefix: str, days: float, now: float | None = None) -> list[str]:
    """Names of the snapshots starting with prefix that are older than days (oldest first)."""
    cutoff = (time.time() if now is None else now) - days * 86400
    old = [s for s in snaps if str(s.get("name") or "").startswith(prefix) and isinstance(s.get("snaptime"), int)
           and s["snaptime"] < cutoff]
    return [s["name"] for s in sorted(old, key=lambda s: s["snaptime"])]


def label(g: dict) -> str:
    return f"{g['vmid']} {g.get('name') or ''}".strip()


def infer_site(cfg: dict, guests: list[str], managed: dict | None = None) -> str | None:
    """The site of guests named without --site (GitHub issue #83): the inventory site_<name> group of a guest
    that is an inventory host, else the site whose ranges hold its ansible_host. VMIDs and unknown names say
    nothing. None: the default site. Guests of different sites are refused (VMIDs repeat across sites)."""
    names = [g for g in guests if not g.isdigit()]
    if len(hmlib.sites(cfg)) < 2 or not names:
        return None
    if managed is None:
        managed, _ = hmlib.load_ansible(Path(cfg["_root"]))
    found = {g: st for g in names if (st := hmlib.target_site(cfg, managed, g))}
    by_site = sorted({st["name"] for st in found.values()})
    if len(by_site) > 1:
        raise hmlib.ConfigError("guests of different sites (" + ", ".join(f"{g}: {st['name']}" for g, st
                                in sorted(found.items())) + "): run once per site with --site.")
    if not by_site or found[next(iter(found))]["default"]:
        return None
    print(f"pve_snapshot: site {by_site[0]} (from the inventory; --site to override)", file=sys.stderr)
    return by_site[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["list", "check", "create", "delete", "rollback", "restore", "prune"])
    ap.add_argument("guests", nargs="+")
    ap.add_argument("--older-than", type=float, metavar="DAYS", help="prune: snapshots older than DAYS")
    ap.add_argument("--prefix", default="prepatch-", help="prune: only snapshots whose name starts with this")
    ap.add_argument("--dry-run", action="store_true", help="create/delete/rollback/prune: show it, change nothing")
    ap.add_argument("--name")
    ap.add_argument("--description", default="")
    ap.add_argument("--json", action="store_true", help="check: print the result as JSON")
    ap.add_argument("--no-start", action="store_true", help="rollback: leave the guest stopped")
    ap.add_argument("--site", help="the site whose Proxmox holds the guests (default: the guests' inventory "
                                   "site, else the default site)")
    a = ap.parse_args()
    a.action = ACTION_ALIASES.get(a.action, a.action)
    if a.action == "prune" and a.older_than is None:
        ap.error("prune needs --older-than DAYS")
    name = a.name or (default_name() if a.action == "create" else None)
    if a.action in ("delete", "rollback") and not name:
        ap.error(f"{a.action} needs --name (see `pve_snapshot.py list`)")
    if name and not NAME_RE.match(name):
        ap.error("--name: 2–40 letters, digits, - or _, starting with a letter")
    if a.action == "rollback" and len(a.guests) != 1:
        ap.error("rollback one guest at a time")
    try:
        cfg = hmlib.load_config()
        site = a.site if a.site else infer_site(cfg, a.guests)
        px = hmlib.proxmox_site(cfg, site)
        secret = hmlib.proxmox_token_name(px, "read_only" if a.action in ("list", "check") or a.dry_run
                                          else "provisioning")
        pve = PVE(hmlib.pick_endpoint(px), hmlib.read_secret(cfg, secret), hmlib.proxmox_ssl_context(cfg, px))
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

    if a.action == "prune":
        return 1 if prune(pve, guests, a.prefix, a.older_than, a.dry_run) else 0
    if a.dry_run:
        return dry_run(pve, a.action, guests, name)
    return 1 if apply(pve, a.action, guests, name, a.description, start=not a.no_start) else 0


def dry_run(pve: PVE, action: str, guests: list[dict], name: str) -> int:
    """What create/delete/rollback would do, from the snapshot lists (read-only)."""
    bad = 0
    for g in guests:
        existing = {s["name"] for s in snapshots(pve, g)}
        if action == "create":
            print(f"{label(g)}: would " + (f"keep the existing snapshot {name!r}" if name in existing
                                           else f"create snapshot {name!r}"))
        elif name not in existing:
            bad += 1
            print(f"{label(g)}: has no snapshot {name!r} (existing: {', '.join(sorted(existing)) or 'none'})")
        else:
            print(f"{label(g)}: would {action} snapshot {name!r}")
    print("Dry run: nothing was changed.")
    return 1 if bad else 0


def prune(pve: PVE, guests: list[dict], prefix: str, days: float, dry_run: bool = False) -> list[str]:
    """Delete each guest's snapshots named prefix* older than days. Returns the failures."""
    failed = []
    for g in guests:
        try:
            names = prunable(snapshots(pve, g), prefix, days)
        except SystemExit as e:
            failed.append(f"{label(g)}: {e}")
            continue
        if not names:
            print(f"{label(g)}: no {prefix}* snapshot older than {days:g} days")
            continue
        if dry_run:
            print(f"{label(g)}: would delete {', '.join(names)}")
            continue
        failed += apply(pve, "delete", [g], names, summary=False)
    if dry_run:
        print("Dry run: nothing was changed.")
    elif failed:
        print("Failed:\n" + "\n".join(f"  - {f}" for f in failed))
    return failed


def apply(pve: PVE, action: str, guests: list[dict], name, description: str = "", start: bool = True,
          summary: bool = True) -> list[str]:
    """create / delete / rollback snapshot `name` (or each of a list of names, delete only) on each guest,
    waiting for every Proxmox task. A guest that fails does not stop the others (a rollback is one guest).
    Returns the problems: failed guests, and guests a rollback should have started but that are not running."""
    import pve_guest  # imports this module
    down, done, failed = [], [], []
    names = name if isinstance(name, list) else [name]
    for g in guests:
        try:
            for n in names:
                if apply_one(pve, pve_guest, action, g, n, description, start, down):
                    done.append(f"{label(g)} {n}")
        except SystemExit as e:
            if action == "rollback":
                raise
            failed.append(f"{label(g)}: {e}")
            print(f"{label(g)}: {action} failed — {e}", file=sys.stderr)
    if summary and len(guests) > 1 and failed:
        print(f"\n{action}: done for {len(done)}, failed for {len(failed)}:")
        print("\n".join(f"  - {f}" for f in failed))
    return failed + down


def apply_one(pve: PVE, pve_guest, action: str, g: dict, name: str, description: str, start: bool,
              down: list[str]) -> bool:
    """One guest, one snapshot. True when something was done (False: an existing snapshot kept)."""
    what = f"{action} snapshot {name!r} of {label(g)}"
    existing = {s["name"] for s in snapshots(pve, g)}
    if action == "create":
        if name in existing:
            print(f"{label(g)}: snapshot {name!r} already exists — kept (pass another --name for a new one)")
            return False
        params = {"snapname": name, "description": description or f"homelab-manager {name}"}
        if g["type"] == "qemu":
            params["vmstate"] = 0
        upid = pve.write("POST", base(g) + "/snapshot", **params)
    elif name not in existing:
        raise SystemExit(f"{label(g)} has no snapshot {name!r} (existing: {', '.join(sorted(existing)) or 'none'}).")
    elif action == "delete":
        upid = pve.write("DELETE", base(g) + f"/snapshot/{name}")
    else:
        was_running = pve_guest.status(pve, g) == "running"
        upid = pve.write("POST", base(g) + f"/snapshot/{name}/rollback",
                         **({"start": 1} if start and was_running else {}))
    if upid:
        wait(pve, g["node"], upid, what)
    if action != "rollback":
        print(f"{label(g)}: {action} {name!r} done")
        return True
    final = pve_guest.start(pve, g) if start and was_running else pve_guest.status(pve, g)
    print(f"{label(g)}: rollback {name!r} done, now {final}"
          + ("" if final == "running" or not (start and was_running) else " — it was running before: start it"))
    if start and was_running and final != "running":
        down.append(label(g))
    return True


if __name__ == "__main__":
    sys.exit(hmlib.exit_main(main))
