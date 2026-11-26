"""Zabbix around changes: maintenance windows, health gates for patching, acknowledging problems (#169, #170).

    zabbix_api.py maintenance list
    zabbix_api.py maintenance start --hosts H… [--guests-of NODE] [--hours 2] [--name N]     (rw token)
    zabbix_api.py maintenance stop --name N                                                 (rw token)
    zabbix_api.py gate --phase pre|post --hosts H… [--min high] [--since EPOCH] [--settle 600]  (ro token)
    zabbix_api.py ack <host> --message M [--commit REF] [--close] [--min warning]           (rw token)

Hosts are inventory names; only managed Zabbix hosts (matched, in scope) are touched, the rest is listed and
skipped. Windows the skill opens are named `homelab-manager <name>` and always end by themselves (default
zabbix.maintenance_hours, at most 24 h): a failed run can't leave alerts muted. Others' windows are only listed.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import hmlib
import zbxlib

PREFIX = "homelab-manager "
MAX_HOURS = 24


def managed_hosts(c: zbxlib.Client, cfg: dict, names: list[str]) -> tuple[dict[str, dict], list[str]]:
    """({inventory name: Zabbix host}, [names that are not managed Zabbix hosts])."""
    import zabbix_api
    root = Path(cfg["_root"])
    z = zbxlib.settings(cfg)
    inv = zabbix_api.inventory(root, cfg)
    short: dict[str, list[str]] = {}
    for n in inv:
        short.setdefault(n.split(".")[0], []).append(n)
    want = {}                       # inventory name → the name asked for
    for n in names:
        # a Proxmox guest name that is the short name of exactly one inventory host stands for it
        hits = [n] if n in inv else short.get(n) or []
        want[hits[0] if len(hits) == 1 else n] = n
    # the whole inventory: a Zabbix host two inventory hosts claim is ambiguous and never touched
    m = zbxlib.match_hosts(z, inv, zbxlib.read_hosts(c), hmlib.get(cfg, "site.domain") or "")
    scope = zbxlib.Scope(z)
    found = {n: zh for n, zh in m.pairs.items() if n in want and scope.host_managed(zh, True)}
    return found, sorted(asked for n, asked in want.items() if n not in found)


def guests_of(root: Path, node: str) -> list[str]:
    """Names of the running guests that patching a Proxmox node stops or moves, from its pve_node_plan.py plan
    (discovery/pve-patch.json). A guest name that is also an inventory name gets a window too."""
    for plans in hmlib.site_parts(hmlib.discovery_file(root, "pve-patch"), "pve_node_plan.py").values():
        plan = (plans or {}).get(node) if isinstance(plans, dict) else None
        if isinstance(plan, dict):
            return [str(g["name"]) for g in plan.get("guests") or []
                    if g.get("name") and g.get("action") in ("stop", "migrate", "ha")]
    raise hmlib.ConfigError(f"no patch plan for node {node} in discovery/pve-patch.json: run pve_node_plan.py {node}")


def cmd_maintenance(a, cfg) -> int:
    z = zbxlib.settings(cfg)
    if a.action == "list":
        c = zbxlib.connect(cfg, "ro")
        rows = c.call("maintenance.get", {"output": ["maintenanceid", "name", "active_since", "active_till"],
                                          "selectHosts": ["host"], "selectHostGroups": ["name"]}) or []
        now = time.time()
        for r in rows:
            till = int(r.get("active_till") or 0)
            state = "active" if int(r.get("active_since") or 0) <= now < till else "ended" if till <= now else "planned"
            ours = str(r["name"]).startswith(PREFIX)
            print(f"  {'*' if ours else ' '} {hmlib.clean(r['name'], 80)}: {state} until "
                  f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(till))}, {len(r.get('hosts') or [])} host(s)"
                  + (f", groups {', '.join(g['name'] for g in r.get('hostgroups') or [])}" if r.get("hostgroups") else ""))
        print(f"{len(rows)} maintenance window(s); * = opened by homelab-manager")
        return 0
    c = zbxlib.connect(cfg, "rw")
    name = PREFIX + (a.name or time.strftime("patch %Y-%m-%d %H:%M"))
    existing = next((r for r in c.call("maintenance.get", {"output": ["maintenanceid", "name"],
                                                            "selectHosts": ["hostid"], "filter": {"name": name}}) or []),
                    None)
    if a.action == "stop":
        if not a.name:
            raise hmlib.ConfigError("maintenance stop needs --name (the name it was started with)")
        if existing is None:
            print(f"No maintenance window {name!r}: nothing to stop.")
            return 0
        c.call("maintenance.delete", [existing["maintenanceid"]])
        print(f"Closed maintenance window {name!r}.")
        return 0
    names = list(a.hosts or [])
    if a.guests_of:
        names += [n for n in guests_of(Path(cfg["_root"]), a.guests_of) if n not in names]
    if not names:
        raise hmlib.ConfigError("maintenance start needs --hosts (and/or --guests-of NODE)")
    hours = float(a.hours or z.get("maintenance_hours") or 2)
    if not 0 < hours <= MAX_HOURS:
        raise hmlib.ConfigError(f"--hours must be between 0 and {MAX_HOURS}")
    found, skipped = managed_hosts(c, cfg, names)
    if skipped:
        print(f"  not managed Zabbix hosts (no window for them): {', '.join(skipped)}")
    if not found:
        print("No managed Zabbix host among them: no maintenance window opened.")
        return 0
    now = int(time.time())
    till = now + int(hours * 3600)
    hostids = sorted({zh["hostid"] for zh in found.values()}
                     | {h["hostid"] for h in (existing or {}).get("hosts") or []})
    params = {"name": name, "active_since": now - 60, "active_till": till, "maintenance_type": 0,
              "description": "Opened by homelab-manager for a patch run; ends by itself.",
              "hosts": [{"hostid": h} for h in hostids],
              "timeperiods": [{"timeperiod_type": 0, "start_date": now - 60, "period": till - now + 60}]}
    if existing:
        c.call("maintenance.update", {"maintenanceid": existing["maintenanceid"], **params})
    else:
        c.call("maintenance.create", params)
    print(f"Maintenance window {name!r} open for {len(hostids)} host(s) until "
          f"{time.strftime('%H:%M', time.localtime(till))}: {', '.join(sorted(found))}")
    return 0


def cmd_gate(a, cfg) -> int:
    """pre: refuse when the hosts have open, unacknowledged problems at --min or above (patching would hide an
    outage; an acknowledged one is known and passes).
    post: wait up to --settle seconds until every host's agent is available and no problem at --min or above
    started since --since."""
    c = zbxlib.connect(cfg, "ro")
    z = zbxlib.settings(cfg)
    floor = zbxlib.severity_level(a.min or z.get("patch_gate_severity") or "high")
    deadline = time.time() + (a.settle if a.phase == "post" else 0)
    while True:
        found, skipped = managed_hosts(c, cfg, a.hosts)
        ids = {zh["hostid"]: n for n, zh in found.items()}
        probs = [p for p in zbxlib.read_problems(c, list(ids)) if zbxlib.severity_level(p["severity"]) >= floor
                 and (not p["acknowledged"] if a.phase == "pre" else p["since"] >= int(a.since or 0))]
        bad = [f"{', '.join(ids.get(i, i) for i in p['hostids'] if i in ids)}: {p['severity']} {p['name']}"
               for p in probs]
        down = []
        if a.phase == "post":
            fresh = {h["hostid"]: h for h in zbxlib.read_hosts(c) if h["hostid"] in ids}
            down = [ids[i] for i, h in fresh.items() if zbxlib.agent_availability(h) == "unavailable"]
        if not bad and not down:
            note = f" ({', '.join(skipped)} not in Zabbix)" if skipped else ""
            print(f"Zabbix gate {a.phase}: OK for {len(found)} host(s){note}")
            return 0
        if time.time() >= deadline:
            break
        time.sleep(min(15, max(1, deadline - time.time())))
    sev = zbxlib.severity_name(floor)
    if bad:
        print(("Open problems at " if a.phase == "pre" else "New problems at ") + f"{sev} or above:\n  "
              + "\n  ".join(bad), file=sys.stderr)
    if down:
        print("Agent not available again: " + ", ".join(down), file=sys.stderr)
    print("Stopped: " + ("fix or acknowledge them first, or run with -e zabbix_gate=ignore after the user's yes."
                         if a.phase == "pre" else "check the hosts before the next batch."), file=sys.stderr)
    return 1


def cmd_ack(a, cfg) -> int:
    c = zbxlib.connect(cfg, "rw")
    found, skipped = managed_hosts(c, cfg, [a.host])
    if skipped:
        raise hmlib.ConfigError(f"{a.host} is not a managed Zabbix host: its problems are not acknowledged here")
    zh = found[a.host]
    floor = zbxlib.severity_level(a.min)
    probs = [p for p in zbxlib.read_problems(c, [zh["hostid"]]) if zbxlib.severity_level(p["severity"]) >= floor
             and not (p["acknowledged"] and not a.close)]
    if not probs:
        print(f"No open problem to acknowledge on {a.host}.")
        return 0
    msg = ("homelab-manager: " + a.message + (f" ({a.commit})" if a.commit else ""))[:2048]
    closable = [p["eventid"] for p in probs if p["manual_close"]] if a.close else []
    rest = [p["eventid"] for p in probs if p["eventid"] not in closable]
    if closable:
        c.call("event.acknowledge", {"eventids": closable, "action": 1 | 2 | 4, "message": msg})
    if rest:
        c.call("event.acknowledge", {"eventids": rest, "action": 2 | 4, "message": msg})
    print(f"Acknowledged {len(probs)} problem(s) on {a.host}" + (f", closed {len(closable)}" if closable else "")
          + (f"; {len(rest)} can't be closed by hand (their trigger doesn't allow it)" if a.close and rest else "")
          + ":\n  " + "\n  ".join(f"{p['severity']} {p['name']}" for p in probs))
    return 0


def add_parsers(sub):
    p = sub.add_parser("maintenance")
    p.add_argument("action", choices=["list", "start", "stop"])
    p.add_argument("--hosts", nargs="*")
    p.add_argument("--guests-of")
    p.add_argument("--hours", type=float)
    p.add_argument("--name")
    p = sub.add_parser("gate")
    p.add_argument("--phase", choices=["pre", "post"], required=True)
    p.add_argument("--hosts", nargs="+", required=True)
    p.add_argument("--min")
    p.add_argument("--since", type=int)
    p.add_argument("--settle", type=int, default=600)
    p = sub.add_parser("ack")
    p.add_argument("host")
    p.add_argument("--message", required=True)
    p.add_argument("--commit")
    p.add_argument("--close", action="store_true")
    p.add_argument("--min", default="information")


HANDLERS = {"maintenance": cmd_maintenance, "gate": cmd_gate, "ack": cmd_ack}
