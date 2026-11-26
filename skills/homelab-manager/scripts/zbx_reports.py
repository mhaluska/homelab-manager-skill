"""Zabbix reports, all read-only (GitHub issues #170, #172): export, quality and capacity report, propose.

    zabbix_api.py export [--no-write]        # configuration.export of the scope → zabbix/export/*.yaml
    zabbix_api.py report [--no-write]        # quality findings and disk-full forecasts → discovery/zabbix-report.md
    zabbix_api.py propose [--host H…] [--write]   # zabbix/config.yaml entries for inventory hosts not in Zabbix

The export leaves out secret values (secret macros, SNMP and HTTP passwords, PSKs): Zabbix doesn't export most of
them, and the script removes what remains. Thresholds come from `zabbix.report` in homelab.yaml.
"""
from __future__ import annotations

import datetime
import json
import time
from collections import Counter
from pathlib import Path

import hmlib
import zbxlib

EXPORT_DIR = Path("zabbix") / "export"
REPORT = Path("discovery") / "zabbix-report.md"
SECRET_KEYS = {"password", "authpassphrase", "privpassphrase", "community", "tls_psk", "ssl_key_password",
               "privatekey", "passphrase"}
REDACTED = "<not exported>"
# template groups whose templates describe the OS or device (fnmatch; also your own, e.g. Templates/Home/OS)
OS_GROUPS = ["Templates/Operating systems", "Templates/Network devices", "Templates/Server hardware",
             "Templates/SAN", "Templates/Power", "Templates/Virtualization", "*/OS", "*/Network", "*/Network devices"]
REPORT_DEFAULTS = {"flapping_per_week": 20, "disk_full_pct": 95, "disk_forecast_days": 30, "trend_days": 30,
                   "os_template_groups": OS_GROUPS}
DAY = 86400


def report_settings(z: dict) -> dict:
    return {**REPORT_DEFAULTS, **(z.get("report") or {})}


def scope_ids(c: zbxlib.Client, cfg: dict) -> dict:
    """The managed part of the server: own host groups, scoped template groups and their templates, managed hosts
    (matched to the inventory, in a scoped group), plus the hosts in own groups that match nothing."""
    import zabbix_api
    z = zbxlib.settings(cfg)
    scope = zbxlib.Scope(z)
    root = Path(cfg["_root"])
    hosts = zbxlib.read_hosts(c)
    m = zbxlib.match_hosts(z, zabbix_api.inventory(root, cfg), hosts, hmlib.get(cfg, "site.domain") or "")
    managed = {n: zh for n, zh in m.pairs.items() if scope.host_managed(zh, True)}
    hgroups = {g["name"]: g["groupid"] for g in c.call("hostgroup.get", {"output": ["groupid", "name"]}) or []}
    tgroups = {g["name"]: g["groupid"] for g in c.call("templategroup.get", {"output": ["groupid", "name"]}) or []}
    templates = c.call("template.get", {"output": ["templateid", "host", "vendor_name", "vendor_version"],
                                        "selectTemplateGroups": ["name"],
                                        "selectParentTemplates": ["templateid", "host"],
                                        "selectTags": ["tag", "value"]}) or []
    return {"z": z, "scope": scope, "managed": managed,
            "stale": [zh for zh in m.unmatched_zabbix if any(scope.own_group(g) for g in zbxlib.host_group_names(zh))],
            "ambiguous": m.ambiguous,
            "host_groups": {n: i for n, i in hgroups.items() if scope.own_group(n)},
            "template_groups": {n: i for n, i in tgroups.items() if scope.template_group(n)},
            "templates": {t["host"]: t for t in templates}}


# --------------------------------------------------------------------------- export

def strip_secrets(node):
    """Secret values out of an export, in place: secret-text macros and password-like fields."""
    if isinstance(node, dict):
        if str(node.get("type")) in ("SECRET_TEXT", "1") and "macro" in node and "value" in node:
            node["value"] = REDACTED
        for k, v in node.items():
            if k.lower() in SECRET_KEYS and isinstance(v, str) and v:
                node[k] = REDACTED
            else:
                strip_secrets(v)
    elif isinstance(node, list):
        for v in node:
            strip_secrets(v)
    return node


def cmd_export(a, cfg) -> int:
    import zbx_sync
    c = zbxlib.connect(cfg, "ro")
    s = scope_ids(c, cfg)
    # the templates the managed hosts use (with what they link), as far as they are in scope: not every stock one
    used = set()
    for zh in s["managed"].values():
        for t in zh.get("parentTemplates") or []:
            closure(t["host"], s["templates"], used)
    own_templates = [t["templateid"] for name, t in s["templates"].items() if name in used
                     and any(s["scope"].template_group(g["name"]) for g in t.get("templategroups") or [])]
    parts = {"host_groups": ("host_groups", sorted(s["host_groups"].values())),
             "template_groups": ("template_groups", sorted(s["template_groups"].values())),
             "templates": ("templates", sorted(own_templates)),
             "hosts": ("hosts", sorted(zh["hostid"] for zh in s["managed"].values()))}
    root = Path(cfg["_root"])
    out = root / EXPORT_DIR
    for fname, (opt, ids) in parts.items():
        if not ids:
            print(f"  {fname}: nothing in scope")
            continue
        raw = c.call("configuration.export", {"format": "json", "options": {opt: ids}})
        data = strip_secrets(json.loads(raw))
        (data.get("zabbix_export") or {}).pop("date", None)
        if a.no_write:
            print(f"  {fname}: {len(ids)} object(s)")
            continue
        out.mkdir(parents=True, exist_ok=True)
        hmlib.atomic_write(out / f"{fname}.yaml", "# zabbix_api.py export: the managed scope as Zabbix has it "
                           "(secret values left out). Read-only copy, for diffs and rollback.\n"
                           + zbx_sync.json_to_yaml(data))
        print(f"  {fname}: {len(ids)} object(s) → {(out / (fname + '.yaml')).relative_to(root)}")
    return 0


# --------------------------------------------------------------------------- report

def closure(name: str, templates: dict, seen=None) -> set[str]:
    """A template and every template it links, recursively."""
    seen = set() if seen is None else seen
    if name in seen:
        return seen
    seen.add(name)
    for p in (templates.get(name) or {}).get("parentTemplates") or []:
        closure(p["host"], templates, seen)
    return seen


def linear_days_to(points: list[tuple[int, float]], limit: float) -> float | None:
    """Days until a least-squares line through (clock, value) reaches limit; None when flat or falling."""
    n = len(points)
    if n < 24:
        return None
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    var = sum((p[0] - mx) ** 2 for p in points)
    if var == 0:
        return None
    slope = sum((p[0] - mx) * (p[1] - my) for p in points) / var       # per second
    if slope <= 0:
        return None
    last_t = max(p[0] for p in points)
    now_v = my + slope * (last_t - mx)
    return max(0.0, (limit - now_v) / slope / DAY)


def chunks(seq, n):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def quality(c: zbxlib.Client, s: dict, r: dict, now: int) -> dict:
    names = {zh["hostid"]: n for n, zh in s["managed"].items()}
    ids = sorted(names)
    out = {"unsupported": {}, "silent": [], "disabled": [], "decommissioned_due": [], "duplicate_links": [],
           "no_os_template": [], "old_agents": [], "flapping": [], "stale": [], "ambiguous": s["ambiguous"]}
    if not ids:
        return out
    for row in c.call("item.get", {"hostids": ids, "output": ["hostid", "name", "key_", "error"],
                                   "filter": {"state": 1, "status": 0}, "monitored": True}) or []:
        out["unsupported"].setdefault(names[row["hostid"]], []).append(
            f"{hmlib.clean(row.get('key_'), 80)}: {hmlib.clean(row.get('error'), 120)}")
    days = int(s["z"].get("decommission_days") or 30)
    for n, zh in sorted(s["managed"].items()):
        tags = {t["tag"]: t["value"] for t in zh.get("tags") or []}
        if str(zh.get("status")) == "1":
            since = tags.get("decommissioned")
            if since:
                try:
                    age = (datetime.date.today() - datetime.date.fromisoformat(since)).days
                except ValueError:
                    age = 0
                if age >= days:
                    out["decommissioned_due"].append(f"{n} (decommissioned {since}, {age} days)")
            else:
                out["disabled"].append(n)
            continue
        if zbxlib.agent_availability(zh) == "unavailable":
            out["silent"].append(n)
        linked = [t["host"] for t in zh.get("parentTemplates") or []]
        for t in linked:
            for other in linked:
                if other != t and t in closure(other, s["templates"]) - {other}:
                    out["duplicate_links"].append(f"{n}: {t} (already in {other})")
        allt = set().union(*(closure(t, s["templates"]) for t in linked)) if linked else set()
        if not any(zbxlib.group_match(g["name"], r["os_template_groups"]) for t in allt
                   for g in (s["templates"].get(t) or {}).get("templategroups") or []):
            out["no_os_template"].append(n)
    server = zbxlib.version_tuple(c.version())
    older: dict[str, list[str]] = {}
    for row in c.call("item.get", {"hostids": ids, "output": ["hostid", "lastvalue"],
                                   "filter": {"key_": "agent.version"}}) or []:
        v = hmlib.clean(str(row.get("lastvalue") or ""), 20)
        if v and zbxlib.version_tuple(v) < server:
            older.setdefault(v, []).append(names[row["hostid"]])
    out["old_agents"] = [f"{v}: {len(h)} host(s) ({', '.join(sorted(h)[:5])}{' …' if len(h) > 5 else ''})"
                         for v, h in sorted(older.items(), key=lambda kv: zbxlib.version_tuple(kv[0]))]
    counts, label = Counter(), {}
    for ev in c.call("event.get", {"hostids": ids, "source": 0, "object": 0, "value": 1, "time_from": now - 7 * DAY,
                                   "output": ["objectid", "name"], "selectHosts": ["hostid"], "limit": 20000}) or []:
        counts[ev["objectid"]] += 1
        hosts = ", ".join(sorted(names.get(h["hostid"], "?") for h in ev.get("hosts") or []))
        label[ev["objectid"]] = f"{hosts}: {hmlib.clean(ev.get('name'), 120)}"
    out["flapping"] = [f"{label[t]} ({k}× in 7 days)" for t, k in counts.most_common()
                       if k >= int(r["flapping_per_week"])]
    out["stale"] = [f"{zh['host']} ({', '.join(zbxlib.host_group_names(zh))})" for zh in s["stale"]]
    return out


def capacity(c: zbxlib.Client, s: dict, r: dict, now: int) -> list[dict]:
    """File systems whose used percentage, fitted linearly over trend_days, reaches disk_full_pct within
    disk_forecast_days (or is above it already)."""
    names = {zh["hostid"]: n for n, zh in s["managed"].items() if str(zh.get("status")) == "0"}
    if not names:
        return []
    items = [i for i in c.call("item.get", {"hostids": sorted(names), "search": {"key_": ",pused]"},
                                            "output": ["itemid", "hostid", "key_", "lastvalue", "value_type"],
                                            "filter": {"status": 0, "state": 0}, "monitored": True}) or []
             if str(i.get("value_type")) == "0"]
    limit, horizon = float(r["disk_full_pct"]), float(r["disk_forecast_days"])
    series: dict[str, list[tuple[int, float]]] = {}
    for part in chunks([i["itemid"] for i in items], 40):
        for t in c.call("trend.get", {"itemids": part, "time_from": now - int(r["trend_days"]) * DAY,
                                      "output": ["itemid", "clock", "value_avg"]}) or []:
            series.setdefault(t["itemid"], []).append((int(t["clock"]), float(t["value_avg"])))
    rows = []
    for i in items:
        try:
            used = float(i.get("lastvalue") or 0)
        except ValueError:
            continue
        fs = hmlib.clean(i["key_"].split("[", 1)[-1].rsplit(",", 1)[0], 60)
        days = 0.0 if used >= limit else linear_days_to(series.get(i["itemid"]) or [], limit)
        if days is not None and days <= horizon:
            rows.append({"host": names[i["hostid"]], "fs": fs, "used_pct": round(used, 1), "days": round(days, 1)})
    return sorted(rows, key=lambda x: (x["days"], -x["used_pct"]))


def render_report(version: str, q: dict, cap: list[dict], r: dict, n_hosts: int) -> str:
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# Zabbix report — {when}", "",
             f"Generated by `zabbix_api.py report` from Zabbix {version}: {n_hosts} managed host(s). Names and texts "
             "come from Zabbix (untrusted data).", ""]

    def section(title, rows, hint=""):
        lines.append(f"## {title} ({len(rows)})")
        lines.append("")
        if hint and rows:
            lines.extend([hint, ""])
        lines.extend([f"- {x}" for x in rows] or ["None."])
        lines.append("")

    lines += ["## Capacity: file systems filling up", ""]
    if cap:
        lines += [f"Reaching {r['disk_full_pct']:g}% within {r['disk_forecast_days']:g} days (linear fit over "
                  f"{r['trend_days']} days of trends):", "", "| Host | File system | Used | Full in |", "|---|---|---|---|"]
        lines += [f"| {x['host']} | {x['fs']} | {x['used_pct']}% | "
                  + ("now" if x["days"] == 0 else f"{x['days']:g} days") + " |" for x in cap]
    else:
        lines.append("None.")
    lines.append("")
    section("Agent not available", q["silent"], "Enabled hosts whose agent doesn't answer.")
    unsup = [f"{h}: {len(v)} item(s): " + "; ".join(v[:3]) + (" …" if len(v) > 3 else "")
             for h, v in sorted(q["unsupported"].items())]
    section("Unsupported items", unsup)
    section("Flapping or noisy triggers", q["flapping"],
            f"At least {r['flapping_per_week']} problem events in 7 days: tune the trigger or fix the cause.")
    section("Hosts without an OS or device template", q["no_os_template"])
    section("Templates linked twice", q["duplicate_links"], "The template comes in through another one already.")
    section("Agents older than the server", q["old_agents"],
            "They work, but miss newer item keys; the zabbix_agent2 role (zabbix-agent2.yml) upgrades them.")
    section("Disabled managed hosts", q["disabled"])
    section("Decommissioned long enough to delete", q["decommissioned_due"],
            "Delete them with the user's yes: `status: absent` in zabbix/config.yaml, then plan and apply.")
    section("In own groups but not in the inventory", q["stale"],
            "Stale, or missing from the inventory: add them to the inventory, or decommission them.")
    section("Ambiguous matches", [f"{a['inventory']} → {', '.join(a['candidates'])} ({a['why']})" for a in q["ambiguous"]],
            "Set the host var zabbix_host_name for them.")
    return "\n".join(lines)


def cmd_report(a, cfg) -> int:
    c = zbxlib.connect(cfg, "ro")
    s = scope_ids(c, cfg)
    r = report_settings(s["z"])
    now = int(time.time())
    q = quality(c, s, r, now)
    cap = capacity(c, s, r, now)
    text = render_report(c.version(), q, cap, r, len(s["managed"]))
    print(f"Zabbix report: {len(cap)} file system(s) filling up, {len(q['silent'])} agent(s) not available, "
          f"{sum(len(v) for v in q['unsupported'].values())} unsupported item(s) on {len(q['unsupported'])} host(s), "
          f"{len(q['flapping'])} flapping trigger(s), {len(q['no_os_template'])} host(s) without an OS template, "
          f"{len(q['old_agents'])} old agent(s), {len(q['decommissioned_due'])} decommissioned host(s) due for deletion.")
    if a.no_write:
        print(text)
        return 0
    root = Path(cfg["_root"])
    (root / REPORT).parent.mkdir(exist_ok=True)
    hmlib.atomic_write(root / REPORT, text + "\n")
    print(f"Wrote {REPORT}")
    return 0


# --------------------------------------------------------------------------- propose

def propose(conf: dict, inv: dict, managed: dict, wanted: list[str] | None) -> dict[str, dict]:
    """Draft entries for inventory hosts that are neither in Zabbix nor in zabbix/config.yaml. A host that
    profiles or defaults already describe gets an empty entry; otherwise it takes the groups and templates most
    of its Ansible-group peers in Zabbix have."""
    import zbx_sync
    configured = set((conf.get("hosts") or {}))
    out = {}
    for name in sorted(wanted or inv):
        if name in managed or name in configured or name not in inv:
            continue
        base = zbx_sync.host_entry({k: v for k, v in conf.items() if k != "hosts"}, name, inv[name])
        if base.get("groups") and base.get("templates"):
            out[name] = {"entry": {}, "why": "profiles/defaults describe it"}
            continue
        # peers from the host's own Ansible groups (not their parents, not site_*), the smallest first
        size = Counter(g for h in inv.values() for g in h.get("groups") or [])
        peers = []
        own = {g for g in inv[name].get("groups") or [] if g not in ("all", "ungrouped") and not g.startswith("site_")}
        for g in sorted(own, key=lambda g: (size[g], g)):
            peers = [p for p in managed if g in (inv.get(p, {}).get("groups") or [])]
            if peers:
                break
        if not peers:
            out[name] = {"entry": {"groups": [], "templates": []}, "why": "no peer in Zabbix: fill in groups and templates"}
            continue
        votes_g = Counter(g for p in peers for g in managed[p]["groups"])
        votes_t = Counter(tuple(managed[p]["templates"]) for p in peers)
        entry = {"groups": sorted(g for g, k in votes_g.items() if k * 2 >= len(peers)),
                 "templates": list(votes_t.most_common(1)[0][0])}
        out[name] = {"entry": entry, "why": f"like {', '.join(sorted(peers)[:3])}" + (" …" if len(peers) > 3 else "")}
    return out


def cmd_propose(a, cfg) -> int:
    import subprocess
    import zabbix_api
    import zbx_sync
    root = Path(cfg["_root"])
    path = root / zbx_sync.CONFIG
    conf = zbxlib.load_yaml(path) or {}
    c = zbxlib.connect(cfg, "ro")
    z = zbxlib.settings(cfg)
    scope = zbxlib.Scope(z)
    inv = zabbix_api.inventory(root, cfg)
    m = zbxlib.match_hosts(z, inv, zbxlib.read_hosts(c), hmlib.get(cfg, "site.domain") or "")
    managed = {n: {"groups": [g for g in zbxlib.host_group_names(zh) if scope.host_group(g)],
                   "templates": [t["host"] for t in zh.get("parentTemplates") or []]}
               for n, zh in m.pairs.items() if scope.host_managed(zh, True)}
    unknown = [h for h in a.host or [] if h not in inv]
    if unknown:
        raise hmlib.ConfigError(f"not in the inventory (or zabbix_monitor: false): {', '.join(unknown)}")
    drafts = propose(conf, inv, managed, a.host)
    already = sorted(set(a.host or []) & (set(m.pairs) | set(conf.get("hosts") or {})))
    if already:
        print(f"  already in Zabbix or zabbix/config.yaml: {', '.join(already)}")
    if not drafts:
        print("No inventory host left to propose.")
        return 0
    print("hosts:")
    for name, d in drafts.items():
        body = zbx_sync.json_to_yaml({name: d["entry"]}).rstrip("\n").replace("\n", "\n  ")
        print(f"  # {d['why']}\n  {body}")
    if not a.write:
        print(f"\n{len(drafts)} draft(s). --write adds them to {zbx_sync.CONFIG} (comments kept); then "
              "`zabbix_api.py plan`.")
        return 0
    if not path.exists():
        raise hmlib.ConfigError(f"No {zbx_sync.CONFIG}: run `zabbix_api.py init-config` first")
    for name, d in drafts.items():
        expr = f'.hosts[{json.dumps(name)}] = {json.dumps(d["entry"])}'
        r = subprocess.run([hmlib.yq_bin(), "-i", expr, str(path)], capture_output=True, text=True,
                           timeout=hmlib.YQ_TIMEOUT)
        if r.returncode != 0:
            raise hmlib.ConfigError(f"yq could not update {zbx_sync.CONFIG}: {r.stderr.strip()}")
    print(f"Added {len(drafts)} host(s) to {zbx_sync.CONFIG}: check them, then `zabbix_api.py plan`.")
    return 0


def add_parsers(sub):
    p = sub.add_parser("export")
    p.add_argument("--no-write", action="store_true")
    p = sub.add_parser("report")
    p.add_argument("--no-write", action="store_true")
    p = sub.add_parser("propose")
    p.add_argument("--host", nargs="+")
    p.add_argument("--write", action="store_true")


HANDLERS = {"export": cmd_export, "report": cmd_report, "propose": cmd_propose}
