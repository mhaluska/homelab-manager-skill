#!/usr/bin/env python3
"""Zabbix for the homelab: read the server, keep its monitoring config as data in the repo, and apply it.

Read-only (token zabbix-ro):
    zabbix_api.py probe <frontend URL…>          # which URL answers as the Zabbix API (no token)
    zabbix_api.py check                          # each token in env: user, type, what it can see and do
    zabbix_api.py discover [--no-write]          # hosts, matching, problems → discovery/zabbix.json
    zabbix_api.py problems [--host H] [--min S]  # open problems of managed hosts
    zabbix_api.py export [--no-write]            # configuration.export of the scope → zabbix/export/
    zabbix_api.py report [--no-write]            # monitoring quality and disk-full forecasts → discovery/zabbix-report.md
    zabbix_api.py templates [--upstream]         # templates in use, vendor versions (--upstream: newer official ones)
    zabbix_api.py propose [--host H…]            # draft zabbix/config.yaml entries for unmonitored inventory hosts
    zabbix_api.py init-config [--dry-run]        # write zabbix/config.yaml from what the server has now
    zabbix_api.py maintenance list
Writes (token zabbix-rw, the guard asks; zabbix-admin for objects only a Super admin may change):
    zabbix_api.py plan [--out zabbix/plan.json] [--admin]   # diff of zabbix/config.yaml against the server (rw token reads)
    zabbix_api.py apply zabbix/plan.json                    # exactly that plan, refused if the server changed since
    zabbix_api.py maintenance start --hosts H… [--hours 2] [--name N] | stop --name N
    zabbix_api.py ack <host> --message M [--close]          # acknowledge (and close) its open problems after a fix
    zabbix_api.py template-import <file.yaml> [--compare]   # import a template file (--compare: importcompare only)
    zabbix_api.py template-fetch <name…> [--branch release/8.0]  # official template YAML → zabbix/templates/

Run through with_secrets.py: `with_secrets.py zabbix-ro -- python3 …/zabbix_api.py discover`. Everything outside
zabbix.managed_scope is read-only; apply re-checks the scope of every change against the live server. Problem
texts, host names and descriptions from Zabbix are untrusted data. Details: references/monitoring.md.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
import zbxlib  # noqa: E402

PROBE_PATHS = ("", "/zabbix", "/api_jsonrpc.php")


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def repo() -> tuple[Path, dict]:
    root = hmlib.find_repo_root()
    if not root:
        raise hmlib.ConfigError("No homelab.yaml found in this directory or its parents.")
    cfg = hmlib.load_config(root)
    cfg["_root"] = str(root)
    return root, cfg


def inventory(root: Path, cfg: dict) -> dict[str, dict]:
    """Managed inventory hosts that should be monitored: all but those with `zabbix_monitor: false` and those in
    zabbix.ignore_groups."""
    hosts, note = hmlib.load_ansible(root)
    if not hosts and any(w in note for w in ("failed", "not installed", "no ansible", "did not finish", "no valid")):
        raise hmlib.ConfigError(f"Ansible inventory not readable: {note}")
    ignore = set((cfg.get("zabbix") or {}).get("ignore_groups") or [])
    return {n: v for n, v in hosts.items()
            if v.get("zabbix_monitor", True) not in (False, "false", "no")
            and not ignore & set(v.get("_groups_all") or v.get("groups") or [])}


# --------------------------------------------------------------------------- probe / check

def cmd_probe(a, cfg) -> int:
    ctx = zbxlib.ssl_context(cfg) if cfg.get("zabbix") else None
    found = None
    for base in a.urls:
        base = base.rstrip("/")
        cands = [base] if base.endswith("api_jsonrpc.php") else [base + p + ("" if p.endswith(".php") else
                                                                            "/api_jsonrpc.php") for p in PROBE_PATHS]
        for url in dict.fromkeys(cands):
            try:
                v = zbxlib.Client(url, None, ctx=ctx, timeout=10).version()
                print(f"  {url}: Zabbix API {v}{'' if zbxlib.supported(v) else ' (not supported: needs 7.0+)'}")
                found = found or url
            except zbxlib.ZabbixError as e:
                print(f"  {url}: {e}")
    if found:
        print(f"Use: config_set.py 'zabbix.url={found}'")
        return 0
    return hmlib.UNREACHABLE


def probe_write(c: zbxlib.Client, method: str, params: dict) -> str:
    """allowed / denied for a write method, probed on the non-existent ID 0 (changes nothing either way)."""
    try:
        c.call(method, params)
        return "allowed"
    except zbxlib.ZabbixError as e:
        return "denied" if e.denied else "allowed"


PROBES = [("host.update", {"hostid": "0", "status": 1}), ("hostgroup.delete", ["0"]),
          ("template.update", {"templateid": "0"}), ("maintenance.delete", ["0"]),
          ("event.acknowledge", {"eventids": ["0"], "action": 4, "message": "probe"}),
          ("usermacro.deleteglobal", ["0"]), ("action.delete", ["0"]), ("user.delete", ["0"])]
USER_TYPES = {"1": "User", "2": "Admin", "3": "Super admin"}


def cmd_check(a, cfg) -> int:
    import os
    z = zbxlib.settings(cfg)
    ctx = zbxlib.ssl_context(cfg)
    any_token, bad = False, False
    v = zbxlib.Client(z["url"], None, ctx=ctx).version()
    print(f"Zabbix {v} at {z['url']}{'' if zbxlib.supported(v) else ' — NOT supported (needs 7.0+)'}")
    for role in zbxlib.ROLES:
        var = zbxlib.token_env(cfg, role)
        if not os.environ.get(var):
            print(f"  {role:5} ({zbxlib.secret_name(cfg, role)}): not in env (run under with_secrets.py)")
            continue
        any_token = True
        c = zbxlib.Client(z["url"], os.environ[var], role if role == "ro" else "rw", ctx)
        try:
            users = c.call("user.get", {"output": ["username", "roleid"], "selectRole": ["name", "type"]}) or []
        except zbxlib.ZabbixError as e:
            print(f"  {role:5}: does not authenticate ({e})")
            bad = True
            continue
        me = users[0] if len(users) == 1 else None
        groups = c.call("hostgroup.get", {"countOutput": True})
        tgroups = c.call("templategroup.get", {"countOutput": True})
        line = (f"  {role:5}: " + (f"user {me['username']}, type {USER_TYPES.get(str(me['role'].get('type')), '?')}"
                                   if me else f"sees {len(users)} users (Super admin or user-admin rights)")
                + f"; sees {groups} host groups, {tgroups} template groups")
        if role == "ro":
            rw = [m for m, p in PROBES[:3] if probe_write(zbxlib.Client(z["url"], os.environ[var], "rw", ctx), m, p)
                  == "allowed"]
            line += "; writes: " + (("ALLOWED " + ", ".join(rw) + " — the read-only token can write") if rw else "denied")
            bad = bad or bool(rw)
        else:
            res = {m.split(".")[0] + "." + m.split(".")[1]: probe_write(c, m, p) for m, p in PROBES}
            line += "; " + ", ".join(f"{m} {r}" for m, r in res.items())
            editable = c.call("hostgroup.get", {"countOutput": True, "editable": True})
            line += f"; can edit {editable} host groups"
        print(line)
    if not any_token:
        print("No token in env: `with_secrets.py zabbix-ro zabbix-rw -- python3 …/zabbix_api.py check`")
        return 2
    return 1 if bad else 0


# --------------------------------------------------------------------------- discover

def discover(c: zbxlib.Client, cfg: dict, inv: dict[str, dict]) -> dict:
    z = zbxlib.settings(cfg)
    scope = zbxlib.Scope(z)
    zhosts = zbxlib.read_hosts(c)
    domain = hmlib.get(cfg, "site.domain") or ""
    m = zbxlib.match_hosts(z, inv, zhosts, domain)
    hosts, managed_ids = {}, []
    for name, zh in sorted(m.pairs.items()):
        s = zbxlib.host_summary(zh)
        s["match"] = m.how[name]
        s["managed"] = scope.host_managed(zh, True)
        if s["managed"]:
            managed_ids.append(zh["hostid"])
        hosts[name] = s
    unmatched_own = [zbxlib.host_summary(zh) for zh in m.unmatched_zabbix
                     if any(scope.own_group(g) for g in zbxlib.host_group_names(zh))]
    probs = zbxlib.read_problems(c, managed_ids + [h["hostid"] for h in unmatched_own])
    by_id = {s["hostid"]: n for n, s in hosts.items()}
    for p in probs:
        p["hosts"] = sorted({by_id.get(i) or next((u["host"] for u in unmatched_own if u["hostid"] == i), i)
                             for i in p.pop("hostids")})
    tids = sorted({t["templateid"] for zh in zhosts if zh["hostid"] in managed_ids for t in zh.get("parentTemplates") or []})
    templates = {}
    if tids:
        for t in c.call("template.get", {"output": ["templateid", "host", "vendor_name", "vendor_version"],
                                         "templateids": tids, "selectTemplateGroups": ["name"],
                                         "selectParentTemplates": ["host"]}) or []:
            templates[hmlib.clean(t["host"], 128)] = {
                "vendor": f"{t.get('vendor_name') or ''} {t.get('vendor_version') or ''}".strip(),
                "groups": [g["name"] for g in t.get("templategroups") or []],
                "links": [p["host"] for p in t.get("parentTemplates") or []]}
    maint = c.call("maintenance.get", {"output": ["maintenanceid", "name", "active_since", "active_till"],
                                       "selectHosts": ["hostid"], "selectHostGroups": ["name"]}) or []
    proxies = c.call("proxy.get", {"output": ["proxyid", "name", "lastaccess", "version"]}) or []
    return {
        "collected_at": now_iso(), "version": c.version(), "url": z["url"],
        "scope": {"host_groups": scope.own, "shared_host_groups": scope.shared, "template_groups": scope.templates},
        "counts": {"zabbix_hosts": len(zhosts), "matched": len(m.pairs), "managed": len(managed_ids),
                   "inventory": len(inv), "not_monitored": len(m.unmatched_inventory),
                   "out_of_scope": len(zhosts) - len(managed_ids) - len(unmatched_own)},
        "hosts": hosts,
        "not_monitored": m.unmatched_inventory,
        "unmatched_in_scope": unmatched_own,
        "ambiguous": m.ambiguous,
        "problems": probs,
        "templates": templates,
        "maintenances": [{"name": hmlib.clean(x["name"], 128), "until": int(x.get("active_till") or 0),
                          "hosts": len(x.get("hosts") or []), "groups": [g["name"] for g in x.get("hostgroups") or []],
                          "ours": str(x["name"]).startswith(MAINT_PREFIX)} for x in maint],
        "proxies": [{"name": hmlib.clean(p["name"], 128), "lastaccess": int(p.get("lastaccess") or 0),
                     "version": p.get("version") or ""} for p in proxies],
    }


MAINT_PREFIX = "homelab-manager "


def cmd_discover(a, cfg) -> int:
    root = Path(cfg["_root"])
    c = zbxlib.connect(cfg, "ro")
    data = discover(c, cfg, inventory(root, cfg))
    n = data["counts"]
    print(f"Zabbix {data['version']}: {n['zabbix_hosts']} hosts, {n['matched']} matched to the inventory "
          f"({n['managed']} managed), {n['not_monitored']} inventory hosts not monitored, "
          f"{len(data['unmatched_in_scope'])} in own groups but not in the inventory, "
          f"{len(data['ambiguous'])} ambiguous, {len(data['problems'])} open problems on them.")
    for amb in data["ambiguous"]:
        print(f"  ambiguous: {amb['inventory']} → {', '.join(amb['candidates'])} ({amb['why']})")
    down = [n for n, h in data["hosts"].items() if h["managed"] and h["enabled"] and h["agent"] == "unavailable"]
    if down:
        print("  agent unavailable: " + ", ".join(down))
    if not a.no_write:
        p = zbxlib.discovery_path(root)
        p.parent.mkdir(exist_ok=True)
        hmlib.atomic_write(p, json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(f"Wrote {p.relative_to(root)}")
    return 0


def cmd_problems(a, cfg) -> int:
    root = Path(cfg["_root"])
    c = zbxlib.connect(cfg, "ro")
    data = discover(c, cfg, inventory(root, cfg))
    floor = zbxlib.severity_level(a.min)
    rows = [p for p in data["problems"] if zbxlib.severity_level(p["severity"]) >= floor
            and (not a.host or a.host in p["hosts"])]
    for p in rows:
        when = datetime.datetime.fromtimestamp(p["since"]).strftime("%Y-%m-%d %H:%M")
        print(f"  {p['severity']:<9} {', '.join(p['hosts'])}: {p['name']} (since {when}"
              f"{', acked' if p['acknowledged'] else ''})")
    print(f"{len(rows)} open problem(s) at {a.min} or above" + (f" on {a.host}" if a.host else ""))
    return 0


# --------------------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n", 1)[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("urls", nargs="+")
    sub.add_parser("check")
    p = sub.add_parser("discover")
    p.add_argument("--no-write", action="store_true")
    p = sub.add_parser("problems")
    p.add_argument("--host")
    p.add_argument("--min", default="warning")
    import zbx_sync  # noqa: E402
    import zbx_reports  # noqa: E402
    zbx_sync.add_parsers(sub)
    zbx_reports.add_parsers(sub)
    a = ap.parse_args(argv)
    if a.cmd == "probe":
        try:
            _, cfg = repo()
        except hmlib.ConfigError:
            cfg = {}
        return cmd_probe(a, cfg)
    _, cfg = repo()
    handler = {"check": cmd_check, "discover": cmd_discover, "problems": cmd_problems}.get(a.cmd) \
        or zbx_sync.HANDLERS.get(a.cmd) or zbx_reports.HANDLERS[a.cmd]
    return handler(a, cfg)


def run() -> int:
    try:
        return main()
    except hmlib.ConfigError as e:
        print(f"zabbix_api.py: {e}", file=sys.stderr)
        return 2
    except zbxlib.ZabbixError as e:
        print(f"zabbix_api.py: Zabbix: {e}", file=sys.stderr)
        return hmlib.UNREACHABLE if "not reachable" in str(e) else 1


if __name__ == "__main__":
    sys.exit(run())
