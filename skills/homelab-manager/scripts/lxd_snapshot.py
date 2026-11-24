#!/usr/bin/env python3
"""LXD/Incus instance snapshots around patching (containers on a NAS or a plain LXD/Incus host).

    lxd_snapshot.py list <host…>                                  # read-only
    lxd_snapshot.py check <host…> [--json]                        # read-only: can each one be snapshotted?
    lxd_snapshot.py create <host…> [--name prepatch-YYYYMMDD]
    lxd_snapshot.py delete <host…> --name NAME                    # needs the user's yes (the guard asks)
    lxd_snapshot.py restore <host> --name NAME                    # needs the user's yes (the guard asks)
    lxd_snapshot.py prune <host…> --older-than DAYS [--prefix prepatch-]   # the user's yes (the guard asks)
    … --dry-run                                                   # create/delete/restore/prune: only show it

`rollback` is accepted for `restore` (pve_snapshot.py's word). A multi-host create, delete or prune goes on after
a host fails and ends with what failed (exit 1). prune deletes the snapshots whose name starts with --prefix
(default prepatch-) and that are older than DAYS. --dry-run shows what would happen and changes nothing.

<host> is the container's name in the managed Ansible inventory. Its host vars say where it runs:
  lxd_host       inventory name of the LXD/Incus host (the NAS) — required
  lxd_instance   instance name on that host (default: the short host name)
  lxd_project    LXD/Incus project (default: the default project)
The LXD/Incus host's vars:
  lxd_snapshots: true   opt-in: snapshots are writes on that host (appliances are read-only by default)
  lxd_cli               the client command (default: found — incus, lxc, QNAP Container Station's lxc)
  lxd_sudo: true        run the client with `sudo -n`
Everything goes through `<cli> query` (the REST API), which LXD and Incus share whatever their CLI version,
over `ssh -T` with BatchMode (agent keys, no password prompt) to ansible_host/ansible_user/ansible_port.

check reports per host: the storage driver (`dir` copies the whole root filesystem: its size is checked
against the pool's free space), disk devices the snapshot does NOT contain (bind mounts, custom volumes),
and scheduled snapshots (on ZFS only the newest snapshot can be restored). Exit 0 when all can be
snapshotted, 1 when not. restore refuses on ZFS while newer snapshots exist (they would have to go first).
Snapshots are disk-only (stateful: false).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
from pve_snapshot import NAME_RE, default_name  # noqa: E402

ACTION_ALIASES = {"rollback": "restore"}

SSH_TIMEOUT = 15
OP_TIMEOUT = 1800  # a `dir` snapshot copies the whole root filesystem
# client candidates when lxd_cli isn't set; QNAP Container Station bundles its own lxc
FIND_CLI = ("for c in incus lxc /share/*/.qpkg/container-station/bin/lxc; do "
            "if command -v \"$c\" >/dev/null 2>&1; then command -v \"$c\"; exit 0; fi; done; exit 1")


class LxdError(Exception):
    pass


def ssh_run(t: dict, command: str, timeout: int) -> tuple[int, str, str]:
    try:
        cmd = hmlib.ssh_cmd(t["address"], [command], user=t.get("user"), port=t.get("port"), timeout=SSH_TIMEOUT)
    except ValueError as e:
        return 255, "", str(e)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return 124, "", f"no answer within {timeout}s"
    return p.returncode, p.stdout, p.stderr


def targets(hosts: dict, wanted: list[str]) -> tuple[dict[str, dict], dict[str, str]]:
    """Inventory names → ({name: target}, {name: problem}). A target says how to reach the instance."""
    lit = hmlib.literal  # ansible-inventory doesn't render templates
    found, problems = {}, {}
    for w in wanted:
        hits = [w] if w in hosts else [h for h in hosts if h.split(".")[0] == w]
        if len(hits) != 1:
            problems[w] = f"{w!r} is not in the managed inventory." if not hits else f"{w!r} is ambiguous: {', '.join(hits)}."
            continue
        name = hits[0]
        hv = hosts[name]
        nas = lit(hv.get("lxd_host"))
        if not nas:
            problems[w] = f"{name} has no lxd_host host var (the inventory name of its LXD/Incus host)."
            continue
        if nas not in hosts:
            problems[w] = f"{name}: lxd_host {nas!r} is not in the managed inventory."
            continue
        nv = hosts[nas]
        found[w] = {"name": name, "instance": str(lit(hv.get("lxd_instance")) or name.split(".")[0]),
                    "project": lit(hv.get("lxd_project")), "nas": nas,
                    "address": str(lit(nv.get("ansible_host")) or nas), "user": lit(nv.get("ansible_user")),
                    "port": lit(nv.get("ansible_port")), "cli": lit(nv.get("lxd_cli")),
                    "sudo": str(lit(nv.get("lxd_sudo"))).lower() in ("true", "yes", "1"),
                    "opted_in": str(lit(nv.get("lxd_snapshots"))).lower() in ("true", "yes", "1")}
    return found, problems


class Api:
    """`<cli> query` on one LXD/Incus host over SSH; run(target, command, timeout) is swappable for tests."""

    def __init__(self, t: dict, run=ssh_run):
        self.t, self.run, self.cli = t, run, t.get("cli")

    def client(self) -> str:
        if not self.cli:
            rc, out, err = self.run(self.t, FIND_CLI, SSH_TIMEOUT + 20)
            if rc != 0 or not out.strip():
                raise LxdError(f"no incus or lxc client on {self.t['nas']} ({hmlib.clean(err.strip() or 'not found', 120)});"
                               " set lxd_cli in its host vars")
            self.cli = shlex.quote(out.strip().splitlines()[-1])
        return ("sudo -n " if self.t.get("sudo") else "") + self.cli

    def path(self, p: str) -> str:
        if self.t.get("project"):
            p += ("&" if "?" in p else "?") + "project=" + str(self.t["project"])
        return p

    def query(self, p: str, method: str = "GET", body: dict | None = None):
        cmd = [self.client(), "query"]
        if method != "GET":
            cmd += ["-X", method, "--wait"]
        if body is not None:
            cmd += ["-d", shlex.quote(json.dumps(body))]
        cmd.append(shlex.quote(self.path(p)))
        rc, out, err = self.run(self.t, " ".join(cmd), OP_TIMEOUT if method != "GET" else SSH_TIMEOUT + 45)
        if rc != 0:
            msg = next((l for l in (err + "\n" + out).splitlines() if l.strip()), f"exit {rc}")
            raise LxdError(f"{self.t['nas']}: {method} {p}: {hmlib.clean(msg.strip(), 200)}")
        out = out.strip()
        try:
            return json.loads(out) if out else None
        except json.JSONDecodeError:
            raise LxdError(f"{self.t['nas']}: {method} {p}: not JSON: {hmlib.clean(out, 120)}") from None

    def inst(self) -> str:
        return "/1.0/instances/" + self.t["instance"]

    def snapshots(self) -> list[dict]:
        snaps = self.query(self.inst() + "/snapshots?recursion=1") or []
        out = [{**s, "name": str(s.get("name", "")).split("/")[-1]} for s in snaps if isinstance(s, dict)]
        return sorted(out, key=lambda s: s.get("created_at") or "")


def label(t: dict) -> str:
    return f"{t['name']} ({t['instance']} on {t['nas']})"


def inspect(api: Api) -> dict:
    """Read-only facts for check and restore: driver, sizes, disks not in the snapshot, schedule."""
    inst = api.query(api.inst())
    if not isinstance(inst, dict):
        raise LxdError(f"{api.t['nas']}: no instance {api.t['instance']!r}")
    devices = inst.get("expanded_devices") or {}
    root = next((d for d in devices.values() if d.get("type") == "disk" and d.get("path") == "/"), {})
    pool = root.get("pool")
    driver = (api.query("/1.0/storage-pools/" + pool) or {}).get("driver") if pool else None
    excluded = []
    for k, d in sorted(devices.items()):
        if d.get("type") != "disk" or d is root or not d.get("source"):
            continue
        excluded.append(f"{k}: {'volume ' + d['source'] if d.get('pool') else d['source']} → {d.get('path', '?')}")
    free = usage = None
    if driver == "dir":
        space = (api.query(f"/1.0/storage-pools/{pool}/resources") or {}).get("space") or {}
        if space.get("total"):
            free = int(space["total"]) - int(space.get("used") or 0)
        usage = (((api.query(api.inst() + "/state") or {}).get("disk") or {}).get("root") or {}).get("usage") or None
    return {"type": inst.get("type", "container"), "status": inst.get("status"), "pool": pool, "driver": driver,
            "excluded": excluded, "free": free, "usage": usage,
            "schedule": (inst.get("expanded_config") or {}).get("snapshots.schedule") or ""}


def gib(n) -> str:
    return f"{int(n) / 2**30:.1f} GiB"


def check(found: dict[str, dict], problems: dict[str, str], run=ssh_run) -> dict:
    """{ok: [..], not_a_guest: {host: why}, no_snapshot: {host: why}, warnings: {host: [..]}} — read-only."""
    out = {"ok": [], "not_a_guest": dict(problems), "no_snapshot": {}, "warnings": {}}
    for w, t in found.items():
        if not t["opted_in"]:
            out["no_snapshot"][w] = (f"{label(t)}: snapshots are not enabled on {t['nas']} (appliances are read-only"
                                     f" by default): set lxd_snapshots: true in its host vars with the user's yes")
            continue
        try:
            f = inspect(Api(t, run))
        except LxdError as e:
            (out["not_a_guest"] if "404" in str(e) or "not found" in str(e).lower() else out["no_snapshot"])[w] = \
                f"{label(t)}: {e}"
            continue
        warn = []
        if f["driver"] == "dir":
            warn.append("storage driver dir: the snapshot is a full copy of the root filesystem (slow, uses its size)")
            if f["usage"] and f["free"] is not None and int(f["usage"]) > f["free"]:
                out["no_snapshot"][w] = (f"{label(t)}: root filesystem {gib(f['usage'])} doesn't fit in the "
                                         f"{gib(f['free'])} free on pool {f['pool']} (dir storage copies it)")
                continue
            if not f["usage"]:
                warn.append(f"root filesystem size unknown: check it fits in the {gib(f['free']) if f['free'] else '?'}"
                            f" free on pool {f['pool']}")
        if f["excluded"]:
            warn.append("not in the snapshot: " + "; ".join(f["excluded"]))
        if f["schedule"] and f["driver"] == "zfs":
            warn.append(f"scheduled snapshots ({f['schedule']}): on ZFS a newer one blocks restoring this one")
        out["ok"].append(w)
        if warn:
            out["warnings"][w] = warn
    return out


def prunable(snaps: list[dict], prefix: str, days: float, now: dt.datetime | None = None) -> list[str]:
    """Names of the snapshots starting with prefix created more than days ago (oldest first)."""
    cutoff = (now or dt.datetime.now(dt.timezone.utc)) - dt.timedelta(days=days)
    out = []
    for s in snaps:
        try:
            stamp = re.sub(r"\.\d+", "", str(s.get("created_at") or "")).replace("Z", "+00:00")   # LXD: nanoseconds
            created = dt.datetime.fromisoformat(stamp)
        except ValueError:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=dt.timezone.utc)
        if str(s.get("name") or "").startswith(prefix) and created < cutoff:
            out.append((created, s["name"]))
    return [n for _, n in sorted(out)]


def dry_run(api: Api, action: str, name: str) -> bool:
    """What apply would do (read-only). False when it would fail (no such snapshot)."""
    t = api.t
    names = [s["name"] for s in api.snapshots()]
    if action == "create":
        print(f"{label(t)}: would " + (f"keep the existing snapshot {name!r}" if name in names
                                       else f"create snapshot {name!r}"))
        return True
    if name not in names:
        print(f"{label(t)}: has no snapshot {name!r} (existing: {', '.join(names) or 'none'})")
        return False
    print(f"{label(t)}: would {action} snapshot {name!r}")
    return True


def apply(api: Api, action: str, name: str) -> None:
    """create / delete / restore snapshot `name` of one instance, waiting for the LXD operation."""
    t = api.t
    snaps = api.snapshots()
    names = [s["name"] for s in snaps]
    if action == "create":
        if name in names:
            print(f"{label(t)}: snapshot {name!r} already exists — kept (pass another --name for a new one)")
            return
        api.query(api.inst() + "/snapshots", "POST", {"name": name, "stateful": False})
    elif name not in names:
        raise LxdError(f"{label(t)} has no snapshot {name!r} (existing: {', '.join(names) or 'none'}).")
    elif action == "delete":
        api.query(f"{api.inst()}/snapshots/{name}", "DELETE")
    else:
        newer = names[names.index(name) + 1:]
        if newer and inspect(api)["driver"] == "zfs":
            raise LxdError(f"{label(t)}: on ZFS only the newest snapshot can be restored; newer: {', '.join(newer)}. "
                           "Delete those first (the user's yes), then restore.")
        api.query(api.inst(), "PUT", {"restore": name})
    print(f"{label(t)}: {action} {name!r} done")


def main(argv=None, run=ssh_run) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["list", "check", "create", "delete", "restore", "rollback", "prune"])
    ap.add_argument("hosts", nargs="+")
    ap.add_argument("--name")
    ap.add_argument("--older-than", type=float, metavar="DAYS", help="prune: snapshots older than DAYS")
    ap.add_argument("--prefix", default="prepatch-", help="prune: only snapshots whose name starts with this")
    ap.add_argument("--dry-run", action="store_true", help="create/delete/restore/prune: show it, change nothing")
    ap.add_argument("--json", action="store_true", help="check: print the result as JSON")
    a = ap.parse_args(argv)
    a.action = ACTION_ALIASES.get(a.action, a.action)
    if a.action == "prune" and a.older_than is None:
        ap.error("prune needs --older-than DAYS")
    name = a.name or (default_name() if a.action == "create" else None)
    if a.action in ("delete", "restore") and not name:
        ap.error(f"{a.action} needs --name (see `lxd_snapshot.py list`)")
    if name and not NAME_RE.match(name):
        ap.error("--name: 2–40 letters, digits, - or _, starting with a letter")
    if a.action == "restore" and len(a.hosts) != 1:
        ap.error("restore one instance at a time")
    try:
        cfg = hmlib.load_config()
    except hmlib.ConfigError as e:
        print(f"lxd_snapshot: {e}", file=sys.stderr)
        return 3
    hosts, src = hmlib.load_ansible(Path(cfg["_root"]))
    if not hosts:
        print(f"lxd_snapshot: no inventory ({src})", file=sys.stderr)
        return 3
    found, problems = targets(hosts, a.hosts)

    if a.action == "check":
        res = check(found, problems, run)
        if a.json:
            print(json.dumps(res, indent=2))
        else:
            for w in res["ok"]:
                print(f"{w}: ok" + "".join(f"\n  - {x}" for x in res["warnings"].get(w, [])))
            for w, why in res["not_a_guest"].items():
                print(f"{w}: not an LXD/Incus instance — {why}")
            for w, why in res["no_snapshot"].items():
                print(f"{w}: can't be snapshotted — {why}")
        return 0 if not (res["not_a_guest"] or res["no_snapshot"]) else 1

    for w in a.hosts:
        if w in problems:
            raise SystemExit(problems[w])
    failed = []
    for w in a.hosts:
        t = found[w]
        api = Api(t, run)
        try:
            if a.action == "list":
                snaps = api.snapshots()
                print(f"{label(t)}: " + ("no snapshots" if not snaps else ""))
                for s in snaps:
                    print(f"  {s['name']:<40} {(s.get('created_at') or '?')[:16].replace('T', ' ')}")
                continue
            if not t["opted_in"] and not a.dry_run:
                raise LxdError(f"{label(t)}: snapshots are not enabled on {t['nas']}: set lxd_snapshots: true in its "
                               "host vars with the user's yes")
            names = prunable(api.snapshots(), a.prefix, a.older_than) if a.action == "prune" else [name]
            if a.action == "prune" and not names:
                print(f"{label(t)}: no {a.prefix}* snapshot older than {a.older_than:g} days")
            for n in names:
                act = "delete" if a.action == "prune" else a.action
                if a.dry_run:
                    if not dry_run(api, act, n):
                        failed.append(f"{label(t)}: no snapshot {n!r}")
                else:
                    apply(api, act, n)
        except LxdError as e:
            if a.action == "restore" or len(a.hosts) == 1 and a.action != "prune":
                raise SystemExit(str(e)) from None
            failed.append(str(e))
            print(f"{label(t)}: {a.action} failed — {e}", file=sys.stderr)
    if a.dry_run:
        print("Dry run: nothing was changed.")
    if failed and len(a.hosts) > 1:
        print(f"\n{a.action}: failed for {len(failed)} of {len(a.hosts)}:\n" + "\n".join(f"  - {f}" for f in failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
