"""Monitoring config as data: zabbix/config.yaml → plan → apply (GitHub issues #168, #170, #171, #174).

    zabbix_api.py plan [--out zabbix/plan.json] [--admin]
    zabbix_api.py apply zabbix/plan.json
    zabbix_api.py init-config [--dry-run]

Rules:
- Only what zabbix/config.yaml lists is managed. A key that is present is managed exactly (`templates:` is the full
  list of linked templates); a key left out is left alone. Objects not listed are never touched.
- Every write is inside zabbix.managed_scope: own host groups, matched hosts in scoped groups, templates in scoped
  template groups. Out-of-scope groups of a managed host are kept as they are.
- `plan` only reads (read-only token). `apply` (read-write token; admin token for global objects) re-reads the
  server, rebuilds the plan and refuses unless it is exactly the saved one; writes then go only to the ids that plan
  resolved. Secret values (`{secret: <name>}`) come from the environment with_secrets.py fills, never from a file.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
import sys
from pathlib import Path

import hmlib
import zbxlib

CONFIG = Path("zabbix") / "config.yaml"
PLAN = Path("zabbix") / "plan.json"
PLAN_VERSION = 1
HOST_KEYS = {"name", "groups", "templates", "tags", "macros", "inventory", "interfaces", "proxy", "status",
             "description", "unlink"}
ADMIN_KINDS = ("global_macros", "action", "mediatype", "drule", "regexp")
OBJECT_API = {"action": ("action", "actionid", {"selectFilter": "extend", "selectOperations": "extend",
                                                  "selectRecoveryOperations": "extend",
                                                  "selectUpdateOperations": "extend"}),
              "mediatype": ("mediatype", "mediatypeid", {}),
              "drule": ("drule", "druleid", {"selectDChecks": "extend"}),
              "regexp": ("regexp", "regexpid", {"selectExpressions": "extend"})}
STATUS = {"enabled": "0", "disabled": "1", "decommissioned": "1"}
DECOM_TAG = "decommissioned"


def today() -> str:
    return datetime.date.today().isoformat()


# --------------------------------------------------------------------------- config

class PlanError(Exception):
    pass


def load_conf(root: Path) -> dict:
    data = zbxlib.load_yaml(Path(root) / CONFIG)
    if data is None:
        raise hmlib.ConfigError(f"No {CONFIG}: write it with `zabbix_api.py init-config` (from what the server has now) "
                                "or `zabbix_api.py propose` (drafts for unmonitored hosts).")
    if not isinstance(data, dict):
        raise hmlib.ConfigError(f"{CONFIG} must be a mapping")
    return data


def _merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for k, v in (extra or {}).items():
        if k in ("groups", "templates") and isinstance(v, list):
            out[k] = list(dict.fromkeys(list(out.get(k) or []) + v))
        elif isinstance(v, dict) and isinstance(out.get(k), dict) and k != "interfaces":
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


def host_entry(conf: dict, name: str, inv: dict) -> dict:
    """A host's desired state: defaults, then each profile whose Ansible group the host is in (in the order
    `profiles:` lists them), then the host's own entry. Lists (groups, templates) add up, maps merge."""
    out = dict(conf.get("defaults") or {})
    groups = set(inv.get("_groups_all") or inv.get("groups") or [])
    for g, prof in (conf.get("profiles") or {}).items():
        if g in groups:
            out = _merge(out, prof or {})
    out = _merge(out, (conf.get("hosts") or {}).get(name) or {})
    bad = set(out) - HOST_KEYS
    if bad:
        raise PlanError(f"hosts.{name}: unknown key(s) {', '.join(sorted(bad))} (allowed: {', '.join(sorted(HOST_KEYS))})")
    return out


def secret_env(cfg: dict, name: str) -> str:
    entry = hmlib.get(cfg, f"secrets.{name}")
    if not isinstance(entry, dict):
        raise PlanError(f"secret {name!r} is not defined under secrets: in homelab.yaml")
    if (entry.get("kind") or "env") != "env" or not entry.get("env"):
        raise PlanError(f"secret {name!r} must be kind env with an env name to be used in zabbix/config.yaml")
    return str(entry["env"])


def is_secret(v) -> bool:
    return isinstance(v, dict) and "secret" in v


# --------------------------------------------------------------------------- server state

def read_state(c: zbxlib.Client, admin: zbxlib.Client | None = None) -> dict:
    st = {"version": c.version()}
    st["hostgroups"] = {g["name"]: g["groupid"] for g in c.call("hostgroup.get", {"output": ["groupid", "name"]}) or []}
    st["templategroups"] = {g["name"]: g["groupid"]
                            for g in c.call("templategroup.get", {"output": ["groupid", "name"]}) or []}
    st["templates"] = {}
    for t in c.call("template.get", {"output": ["templateid", "host", "name", "description"],
                                     "selectTemplateGroups": ["name"], "selectParentTemplates": ["templateid", "host"],
                                     "selectMacros": ["hostmacroid", "macro", "value", "type", "description"],
                                     "selectTags": ["tag", "value"]}) or []:
        st["templates"][t["host"]] = t
    st["hosts"] = zbxlib.read_hosts(c)
    st["proxies"] = {p["name"]: p["proxyid"] for p in c.call("proxy.get", {"output": ["proxyid", "name"]}) or []}
    st["httptests"] = c.call("httptest.get", {"output": ["httptestid", "name", "hostid", "delay", "status"],
                                              "selectSteps": "extend", "selectTags": ["tag", "value"],
                                              "tags": [{"tag": zbxlib.MANAGED_TAG, "value": zbxlib.MANAGED_VALUE,
                                                        "operator": 1}]}) or []
    st["cert_items"] = c.call("item.get", {"output": ["itemid", "hostid", "key_", "name", "type", "master_itemid"],
                                           "tags": [{"tag": zbxlib.MANAGED_TAG, "value": zbxlib.MANAGED_VALUE,
                                                     "operator": 1}],
                                           "selectTriggers": ["triggerid", "description", "expression"]}) or []
    st["services"] = c.call("service.get", {"output": ["serviceid", "name", "algorithm", "sortorder", "description"],
                                            "selectChildren": ["serviceid", "name"], "selectTags": ["tag", "value"],
                                            "selectProblemTags": ["tag", "operator", "value"]}) or []
    st["slas"] = c.call("sla.get", {"output": ["slaid", "name", "slo", "period", "timezone", "status",
                                                "description"],
                                    "selectServiceTags": ["tag", "operator", "value"]}) or []
    if admin is not None:
        st["global_macros"] = {m["macro"]: m for m in admin.call("usermacro.get", {
            "globalmacro": True, "output": ["globalmacroid", "macro", "value", "type", "description"]}) or []}
        for kind, (api, idf, extra) in OBJECT_API.items():
            st[kind] = {o["name"]: o for o in admin.call(f"{api}.get", {"output": "extend", **extra}) or []}
        st["users"] = admin.call("user.get", {"output": ["username", "roleid"], "selectRole": ["name"],
                                              "selectUsrgrps": ["name"]}) or []
    return st


# --------------------------------------------------------------------------- planning helpers

def tags_list(d: dict) -> list[dict]:
    return sorted(({"tag": str(k), "value": "" if v is None else str(v)} for k, v in (d or {}).items()),
                  key=lambda t: (t["tag"], t["value"]))


def norm_tags(tags) -> list[tuple[str, str]]:
    return sorted((str(t.get("tag")), str(t.get("value") or "")) for t in tags or [])


class Plan:
    def __init__(self):
        self.ops: list[dict] = []
        self.errors: list[str] = []
        self.notes: list[str] = []
        self.allowed: dict[str, set] = {}     # id kind → ids apply may write (defence in depth)

    def add(self, kind: str, action: str, target: str, method: str, params, changes: list[str],
            destructive: bool = False, admin: bool = False):
        self.ops.append({"kind": kind, "action": action, "target": target, "method": method, "params": params,
                         "changes": changes, "destructive": destructive, "admin": admin})

    def allow(self, what: str, ident):
        if ident:
            self.allowed.setdefault(what, set()).add(str(ident))

    def counts(self) -> dict:
        out = {"create": 0, "update": 0, "delete": 0}
        for o in self.ops:
            out[o["action"]] = out.get(o["action"], 0) + 1
        return out


def macro_ops(plan: Plan, kind: str, target: str, owner_ref: dict, actual: list[dict], desired: dict):
    """Per-macro usermacro.create/update/delete for a host or template (owner_ref = {"$host": …}/{"$template": …})."""
    have = {m["macro"]: m for m in actual or []}
    for macro, want in sorted((desired or {}).items()):
        secret = is_secret(want)
        wtype = "1" if secret else str((want or {}).get("type", "0")) if isinstance(want, dict) else "0"
        wval = {"$secret": want["secret"]} if secret else (str(want.get("value", "")) if isinstance(want, dict)
                                                           else str(want))
        wdesc = str(want.get("description", "")) if isinstance(want, dict) else ""
        cur = have.get(macro)
        if cur is None:
            plan.add(kind, "create", target, "usermacro.create",
                     {"hostid": owner_ref, "macro": macro, "value": wval, "type": wtype, "description": wdesc},
                     [f"macro {macro} +" + (" (secret)" if secret else f" = {wval}")])
            continue
        diff = []
        if str(cur.get("type", "0")) != wtype:
            diff.append("type")
        if not secret and str(cur.get("value", "")) != wval:
            diff.append(f"value {cur.get('value', '')!r} → {wval!r}")
        if secret and isinstance(want, dict) and want.get("rotate"):
            diff.append("secret value (rotate)")
        if str(cur.get("description") or "") != wdesc:
            diff.append("description")
        if diff:
            plan.allow("hostmacro", cur.get("hostmacroid"))
            plan.add(kind, "update", target, "usermacro.update",
                     {"hostmacroid": cur.get("hostmacroid"), "value": wval, "type": wtype, "description": wdesc},
                     [f"macro {macro}: " + ", ".join(diff)])
    for macro in sorted(set(have) - set(desired or {})):
        plan.allow("hostmacro", have[macro].get("hostmacroid"))
        plan.add(kind, "delete", target, "usermacro.delete", [have[macro].get("hostmacroid")],
                 [f"macro {macro} -"], destructive=True)


# --------------------------------------------------------------------------- the plan

def build_plan(cfg: dict, conf: dict, st: dict, inv: dict[str, dict], admin: bool = False) -> Plan:
    z = zbxlib.settings(cfg)
    scope = zbxlib.Scope(z)
    plan = Plan()
    if scope.empty:
        plan.errors.append("zabbix.managed_scope has no host groups: set the groups the skill may manage first")
        return plan
    domain = hmlib.get(cfg, "site.domain") or ""

    # host groups and template groups
    for g in conf.get("host_groups") or []:
        if not scope.own_group(g):
            plan.errors.append(f"host_groups: {g!r} is outside managed_scope.host_groups")
        elif g not in st["hostgroups"]:
            plan.add("hostgroup", "create", g, "hostgroup.create", {"name": g}, ["+ host group"])
    for g in conf.get("template_groups") or []:
        if not scope.template_group(g):
            plan.errors.append(f"template_groups: {g!r} is outside managed_scope.template_groups")
        elif g not in st["templategroups"]:
            plan.add("templategroup", "create", g, "templategroup.create", {"name": g}, ["+ template group"])
    planned_hg = set(st["hostgroups"]) | {o["target"] for o in plan.ops if o["kind"] == "hostgroup"}
    planned_tg = set(st["templategroups"]) | {o["target"] for o in plan.ops if o["kind"] == "templategroup"}

    # wrapper templates
    wrappers = conf.get("wrappers") or {}
    for name, w in sorted(wrappers.items()):
        w = w or {}
        grp = w.get("group")
        if not grp or not scope.template_group(grp):
            plan.errors.append(f"wrappers.{name}: group {grp!r} must be in managed_scope.template_groups")
            continue
        if grp not in planned_tg:
            plan.errors.append(f"wrappers.{name}: template group {grp!r} doesn't exist (add it to template_groups)")
            continue
        links = list(w.get("links") or [])
        missing = [t for t in links if t not in st["templates"] and t not in wrappers]
        if missing:
            plan.errors.append(f"wrappers.{name}: linked template(s) not on the server: {', '.join(missing)} "
                               "(import them first: zabbix_api.py template-fetch / template-import)")
            continue
        cur = st["templates"].get(name)
        tags = tags_list({**(w.get("tags") or {}), zbxlib.MANAGED_TAG: zbxlib.MANAGED_VALUE})
        ref = {"$template": name}
        if cur is None:
            plan.add("template", "create", name, "template.create",
                     {"host": name, "groups": [{"$templategroup": grp}], "templates": [{"$template": t} for t in links],
                      "tags": tags, "description": str(w.get("description", ""))},
                     [f"+ wrapper in {grp}"] + ([f"links {', '.join(links)}"] if links else []))
            macro_ops(plan, "template", name, ref, [], w.get("macros"))
            continue
        cur_groups = [g["name"] for g in cur.get("templategroups") or []]
        if not any(scope.template_group(g) for g in cur_groups):
            plan.errors.append(f"wrappers.{name}: a template of that name exists outside managed_scope.template_groups "
                               f"({', '.join(cur_groups)}): not ours, pick another name")
            continue
        plan.allow("template", cur["templateid"])
        params, changes = {"templateid": cur["templateid"]}, []
        keep = [g for g in cur_groups if not scope.template_group(g)]
        if set(cur_groups) != set(keep + [grp]):
            params["groups"] = [{"$templategroup": g} for g in sorted(set(keep + [grp]))]
            changes.append(f"groups {', '.join(sorted(cur_groups))} → {', '.join(sorted(set(keep + [grp])))}")
        cur_links = [p["host"] for p in cur.get("parentTemplates") or []]
        if "links" in w and set(cur_links) != set(links):
            params["templates"] = [{"$template": t} for t in links]
            gone = sorted(set(cur_links) - set(links))
            if gone:
                params["templates_clear"] = [{"$template": t} for t in gone]
            changes.append("links " + " ".join([f"+{t}" for t in sorted(set(links) - set(cur_links))]
                                                + [f"-{t}" for t in gone]))
        if "tags" in w and norm_tags(cur.get("tags")) != norm_tags(tags):
            params["tags"] = tags
            changes.append("tags")
        if "description" in w and str(cur.get("description") or "") != str(w["description"]):
            params["description"] = str(w["description"])
            changes.append("description")
        if len(params) > 1:
            plan.add("template", "update", name, "template.update", params, changes,
                     destructive="templates_clear" in params)
        if "macros" in w:
            macro_ops(plan, "template", name, ref, cur.get("macros"), w.get("macros"))
    known_templates = set(st["templates"]) | set(wrappers)

    # hosts
    configured = conf.get("hosts") or {}
    match_inv = {n: inv.get(n, {}) for n in configured}
    m = zbxlib.match_hosts(z, match_inv, st["hosts"], domain)
    for a in m.ambiguous:
        plan.errors.append(f"hosts.{a['inventory']}: ambiguous ({a['why']}: {', '.join(a['candidates'])}) — set "
                           "zabbix_host_name for it")
    ambiguous = {a["inventory"] for a in m.ambiguous}
    proxies = st.get("proxies") or {}
    for name in sorted(configured):
        if name in ambiguous:
            continue
        try:
            want = host_entry(conf, name, inv.get(name, {}))
        except PlanError as e:
            plan.errors.append(str(e))
            continue
        if name not in inv and want.get("status") not in ("decommissioned", "disabled", "absent"):
            plan.notes.append(f"hosts.{name}: not in the Ansible inventory (decommission it: status: decommissioned)")
        bad_groups = [g for g in want.get("groups") or [] if not scope.host_group(g)]
        if bad_groups:
            plan.errors.append(f"hosts.{name}: group(s) outside managed_scope: {', '.join(bad_groups)}")
            continue
        missing_groups = [g for g in want.get("groups") or [] if g not in planned_hg]
        if missing_groups:
            plan.errors.append(f"hosts.{name}: host group(s) don't exist: {', '.join(missing_groups)} (add to host_groups)")
            continue
        missing_t = [t for t in want.get("templates") or [] if t not in known_templates]
        if missing_t:
            plan.errors.append(f"hosts.{name}: template(s) not on the server: {', '.join(missing_t)}")
            continue
        if want.get("proxy") and want["proxy"] not in proxies:
            plan.errors.append(f"hosts.{name}: proxy {want['proxy']!r} doesn't exist")
            continue
        zh = m.pairs.get(name)
        if zh is not None and not scope.host_managed(zh, True):
            plan.errors.append(f"hosts.{name}: the Zabbix host {zh['host']} is in no managed group "
                               f"({', '.join(zbxlib.host_group_names(zh)) or 'none'}): left alone")
            continue
        status = want.get("status", "enabled")
        if status not in (*STATUS, "absent"):
            plan.errors.append(f"hosts.{name}: status {status!r} (enabled, disabled, decommissioned or absent)")
            continue
        if zh is None:
            if status in ("absent", "decommissioned"):
                continue
            plan_new_host(plan, z, name, inv.get(name, {}), want, domain, cfg)
        else:
            plan_host_update(plan, scope, name, zh, want, status, st, cfg)
    if not admin and any(conf.get(k) for k in ("global_macros", "objects")):
        plan.notes.append("global_macros / objects: skipped — plan with --admin (zabbix-admin token) to include them")

    plan_web(plan, conf, st, m, scope)
    plan_services(plan, conf, st)
    if admin:
        plan_admin(plan, conf, st, cfg)
    return plan


def default_interfaces(inv: dict) -> list[dict]:
    ip = str(inv.get("ansible_host") or "")
    return [{"type": "agent", "ip": ip, "port": "10050"}] if ip else []


def iface_params(i: dict) -> dict:
    t = str(i.get("type", "agent"))
    code = zbxlib.INTERFACE_CODES.get(t, t)
    ip, dns = str(i.get("ip") or ""), str(i.get("dns") or "")
    out = {"type": code, "main": "1", "useip": "1" if ip else "0", "ip": ip, "dns": dns,
           "port": str(i.get("port") or {"1": "10050", "2": "161", "3": "623", "4": "12345"}.get(code, ""))}
    if code == "2":
        snmp = i.get("snmp") or {}
        det = {"version": str(snmp.get("version", "2")), "bulk": "1"}
        if det["version"] in ("1", "2"):
            det["community"] = ({"$secret": snmp["community"]["secret"]} if is_secret(snmp.get("community"))
                                else str(snmp.get("community", "{$SNMP_COMMUNITY}")))
        else:
            det.update({"securityname": str(snmp.get("securityname", "")),
                        "securitylevel": str(snmp.get("securitylevel", "2")),
                        "authprotocol": str(snmp.get("authprotocol", "1")),
                        "privprotocol": str(snmp.get("privprotocol", "1"))})
            for k in ("authpassphrase", "privpassphrase"):
                if is_secret(snmp.get(k)):
                    det[k] = {"$secret": snmp[k]["secret"]}
        out["details"] = det
    return out


def plan_new_host(plan: Plan, z: dict, name: str, inv: dict, want: dict, domain: str, cfg: dict):
    tech = zbxlib.new_host_name(z, name, inv, domain)
    if not tech:
        plan.errors.append(f"hosts.{name}: no Zabbix host and no host_match pattern rule (or zabbix_host_name) to "
                           "name a new one")
        return
    if not want.get("groups"):
        plan.errors.append(f"hosts.{name}: a new host needs groups:")
        return
    ifaces = want["interfaces"] if "interfaces" in want else default_interfaces(inv)
    tags = tags_list({**(want.get("tags") or {}), zbxlib.MANAGED_TAG: zbxlib.MANAGED_VALUE})
    params = {"host": tech, "groups": [{"$hostgroup": g} for g in want["groups"]],
              "templates": [{"$template": t} for t in want.get("templates") or []], "tags": tags,
              "interfaces": [iface_params(i) for i in ifaces],
              "status": STATUS.get(want.get("status", "enabled"), "0")}
    if want.get("name"):
        params["name"] = str(want["name"])
    if want.get("description"):
        params["description"] = str(want["description"])
    if want.get("inventory"):
        params["inventory_mode"] = "0"
        params["inventory"] = {k: str(v) for k, v in want["inventory"].items()}
    if want.get("proxy"):
        params.update({"monitored_by": "1", "proxyid": {"$proxy": want["proxy"]}})
    plan.add("host", "create", name, "host.create", params,
             [f"+ host {tech} in {', '.join(want['groups'])}"]
             + ([f"templates {', '.join(want.get('templates'))}"] if want.get("templates") else [])
             + [f"interfaces {', '.join(i.get('type', 'agent') for i in ifaces) or 'none (active agent only)'}"])
    for macro, val in sorted((want.get("macros") or {}).items()):
        macro_ops(plan, "host", name, {"$host": tech}, [], {macro: val})


def plan_host_update(plan: Plan, scope: zbxlib.Scope, name: str, zh: dict, want: dict, status: str, st: dict,
                     cfg: dict):
    hostid = zh["hostid"]
    plan.allow("host", hostid)
    if status == "absent":
        plan.add("host", "delete", name, "host.delete", [hostid], [f"- host {zh['host']} (its history goes too)"],
                 destructive=True)
        return
    params, changes, destructive = {"hostid": hostid}, [], False
    cur_groups = zbxlib.host_group_names(zh)
    if "groups" in want:
        keep = [g for g in cur_groups if not scope.host_group(g)]
        new = list(dict.fromkeys(keep + list(want["groups"])))
        if set(new) != set(cur_groups):
            params["groups"] = [{"$hostgroup": g} for g in new]
            changes.append("groups " + " ".join([f"+{g}" for g in new if g not in cur_groups]
                                                 + [f"-{g}" for g in cur_groups if g not in new]))
    cur_t = [t["host"] for t in zh.get("parentTemplates") or []]
    if "templates" in want and set(cur_t) != set(want["templates"]):
        params["templates"] = [{"$template": t} for t in want["templates"]]
        gone = sorted(set(cur_t) - set(want["templates"]))
        if gone and want.get("unlink") != "keep":
            params["templates_clear"] = [{"$template": t} for t in gone]
            destructive = True
        changes.append("templates " + " ".join([f"+{t}" for t in want["templates"] if t not in cur_t]
                                                + [f"-{t}" for t in gone])
                       + (" (unlinked and cleared: their items and history on this host go)" if
                          gone and want.get("unlink") != "keep" else ""))
    tags = dict(want.get("tags") or {})
    if status == "decommissioned":
        old = {t["tag"]: t["value"] for t in zh.get("tags") or []}
        tags[DECOM_TAG] = old.get(DECOM_TAG) or today()
    if "tags" in want or status == "decommissioned":
        wt = tags_list({**tags, zbxlib.MANAGED_TAG: zbxlib.MANAGED_VALUE})
        if norm_tags(zh.get("tags")) != norm_tags(wt):
            params["tags"] = wt
            changes.append("tags " + ", ".join(f"{t['tag']}={t['value']}" for t in wt))
    want_status = STATUS.get(status, "0")
    if str(zh.get("status")) != want_status:
        params["status"] = want_status
        changes.append("disable" + (" (decommissioned)" if status == "decommissioned" else "")
                       if want_status == "1" else "enable")
    for key in ("name", "description"):
        if key in want and str(zh.get(key) or "") != str(want[key]):
            params[key] = str(want[key])
            changes.append(key)
    if want.get("inventory"):
        cur_inv = zh.get("inventory") if isinstance(zh.get("inventory"), dict) else {}
        diff = {k: str(v) for k, v in want["inventory"].items() if str(cur_inv.get(k) or "") != str(v)}
        if str(zh.get("inventory_mode")) == "-1" or diff:
            if str(zh.get("inventory_mode")) == "-1":
                params["inventory_mode"] = "0"
            if diff:
                params["inventory"] = diff
            changes.append("inventory " + ", ".join(sorted(diff)) if diff else "inventory on")
    if "proxy" in want:
        proxies = st.get("proxies") or {}
        want_px = proxies.get(want["proxy"]) if want["proxy"] else "0"
        if str(zh.get("proxyid") or "0") != str(want_px):
            if want["proxy"]:
                params.update({"monitored_by": "1", "proxyid": {"$proxy": want["proxy"]}})
            else:
                params.update({"monitored_by": "0", "proxyid": "0"})
            changes.append(f"proxy → {want['proxy'] or 'server'}")
    if len(params) > 1:
        plan.add("host", "update", name, "host.update", params, changes, destructive=destructive)
    if "macros" in want:
        macro_ops(plan, "host", name, {"$hostid": hostid}, zh.get("macros"), want["macros"])
    if "interfaces" in want:
        plan_interfaces(plan, name, zh, want["interfaces"])


def plan_interfaces(plan: Plan, name: str, zh: dict, desired: list[dict]):
    """Interfaces matched by type and position (the first of a type is main)."""
    have: dict[str, list[dict]] = {}
    for i in zh.get("interfaces") or []:
        have.setdefault(str(i.get("type")), []).append(i)
    for lst in have.values():
        lst.sort(key=lambda i: (str(i.get("main")) != "1", int(i.get("interfaceid") or 0)))
    seen: dict[str, int] = {}
    for d in desired:
        p = iface_params(d)
        t = p["type"]
        idx = seen.get(t, 0)
        seen[t] = idx + 1
        p["main"] = "1" if idx == 0 else "0"
        cur = have.get(t, [])[idx] if idx < len(have.get(t, [])) else None
        label = f"{zbxlib.INTERFACE_TYPES.get(t, t)} interface {p['ip'] or p['dns']}:{p['port']}"
        if cur is None:
            plan.add("interface", "create", name, "hostinterface.create", {"hostid": zh["hostid"], **p}, [f"+ {label}"])
            continue
        diff = [k for k in ("useip", "ip", "dns", "port") if str(cur.get(k) or "") != p[k]]
        if t == "2" and "details" in p:
            cd = cur.get("details") or {}
            diff += [f"details.{k}" for k, v in p["details"].items()
                     if not isinstance(v, dict) and str(cd.get(k) or "") != v]
        if diff:
            plan.allow("interface", cur["interfaceid"])
            upd = {"interfaceid": cur["interfaceid"], **{k: p[k] for k in ("useip", "ip", "dns", "port")}}
            if "details" in p:
                upd["details"] = p["details"]
            plan.add("interface", "update", name, "hostinterface.update", upd, [f"~ {label} ({', '.join(diff)})"])
    for t, lst in have.items():
        for cur in lst[seen.get(t, 0):]:
            plan.allow("interface", cur["interfaceid"])
            plan.add("interface", "delete", name, "hostinterface.delete", [cur["interfaceid"]],
                     [f"- {zbxlib.INTERFACE_TYPES.get(t, t)} interface {cur.get('ip') or cur.get('dns')}:"
                      f"{cur.get('port')} (fails if items use it)"], destructive=True)


# --------------------------------------------------------------------------- web, certificates, services (#171)

CERT_KEY = 'web.certificate.get["{host}","{port}"]'


def plan_web(plan: Plan, conf: dict, st: dict, m: zbxlib.Match, scope: zbxlib.Scope):
    """`web:` entries: a web scenario on a managed host, and with tls_expiry_days an agent 2 certificate item, a
    dependent expiry item and a trigger. Matched by (host, name); scenarios tagged managed-by and no longer listed
    are removed."""
    entries = conf.get("web") or []
    want_keys = set()
    tag = [{"tag": zbxlib.MANAGED_TAG, "value": zbxlib.MANAGED_VALUE}]
    for e in entries:
        name, host = e.get("name"), e.get("host")
        zh = m.pairs.get(host)
        if not name or not e.get("url"):
            plan.errors.append(f"web: an entry needs name and url ({e})")
            continue
        if zh is None or not scope.host_managed(zh, True):
            plan.errors.append(f"web.{name}: host {host!r} isn't a managed Zabbix host (list it under hosts: first)")
            continue
        plan.allow("host", zh["hostid"])
        want_keys.add((zh["hostid"], name))
        step = {"name": name, "url": str(e["url"]), "status_codes": str(e.get("status_codes", "200")),
                "timeout": str(e.get("timeout", "15s")), "required": str(e.get("required", "")), "no": "1",
                "follow_redirects": "1"}
        params = {"name": name, "hostid": zh["hostid"], "delay": str(e.get("delay", "1m")), "steps": [step], "tags": tag}
        cur = next((t for t in st.get("httptests") or [] if t["hostid"] == zh["hostid"] and t["name"] == name), None)
        if cur is None:
            plan.add("web", "create", f"{host}/{name}", "httptest.create", params, [f"+ web scenario {e['url']}"])
        else:
            s0 = (cur.get("steps") or [{}])[0]
            diff = [k for k in ("url", "status_codes", "timeout", "required") if str(s0.get(k) or "") != step[k]]
            if str(cur.get("delay")) != params["delay"]:
                diff.append("delay")
            if diff:
                plan.allow("httptest", cur["httptestid"])
                plan.add("web", "update", f"{host}/{name}", "httptest.update",
                         {"httptestid": cur["httptestid"], "delay": params["delay"], "steps": [step]},
                         [f"~ web scenario ({', '.join(diff)})"])
        days = e.get("tls_expiry_days")
        if days and str(e["url"]).startswith("https://"):
            plan_cert(plan, e, zh, int(days), st)
    for t in st.get("httptests") or []:
        if (t["hostid"], t["name"]) not in want_keys and t["hostid"] in {z["hostid"] for z in m.pairs.values()}:
            plan.allow("httptest", t["httptestid"])
            plan.add("web", "delete", t["name"], "httptest.delete", [t["httptestid"]],
                     ["- web scenario (no longer in zabbix/config.yaml)"], destructive=True)


def plan_cert(plan: Plan, e: dict, zh: dict, days: int, st: dict):
    from urllib.parse import urlsplit
    u = urlsplit(str(e["url"]))
    key = CERT_KEY.format(host=u.hostname, port=u.port or 443)
    passive = [i for i in zh.get("interfaces") or [] if str(i.get("type")) == "1"]
    have = [i for i in st.get("cert_items") or [] if i["hostid"] == zh["hostid"] and i["key_"] == key]
    if have:
        return
    tag = [{"tag": zbxlib.MANAGED_TAG, "value": zbxlib.MANAGED_VALUE}]
    master = {"hostid": zh["hostid"], "name": f"Certificate {u.hostname}", "key_": key, "type": "0" if passive else "7",
              "value_type": "4", "delay": "1h", "history": "1d", "trends": "0", "tags": tag}
    if passive:
        master["interfaceid"] = passive[0]["interfaceid"]
    target = f"{e.get('host')}/{e['name']}"
    plan.add("cert", "create", target, "item.create", master, [f"+ certificate check {u.hostname}:{u.port or 443}"])
    dep = {"hostid": zh["hostid"], "name": f"Certificate {u.hostname}: expires", "key_": f"cert.expiry[{u.hostname}]",
           "type": "18", "master_itemid": {"$item": key, "hostid": zh["hostid"]}, "value_type": "3", "units": "unixtime",
           "preprocessing": [{"type": "12", "params": "$.x509.not_after.timestamp", "error_handler": "0",
                              "error_handler_params": ""}], "tags": tag}
    plan.add("cert", "create", target, "item.create", dep, ["+ expiry item"])
    expr = f"last(/{zh['host']}/cert.expiry[{u.hostname}])-now()<{days}d"
    plan.add("cert", "create", target, "trigger.create",
             {"description": f"Certificate of {u.hostname} expires in less than {days} days", "expression": expr,
              "priority": "3", "tags": tag}, [f"+ trigger < {days} days"])


def plan_services(plan: Plan, conf: dict, st: dict):
    """`services:` (a tree by children names, problem tags drive the status) and `slas:` (by service tags)."""
    by_name = {s["name"]: s for s in st.get("services") or []}
    listed = conf.get("services") or []
    names = {s.get("name") for s in listed}
    order, seen = [], set()
    entries = {s.get("name"): s for s in listed}

    def visit(n, path=()):
        if n in seen or n not in entries:
            return
        if n in path:
            plan.errors.append(f"services: {n} is its own descendant")
            return
        for ch in entries[n].get("children") or []:
            visit(ch, path + (n,))
        seen.add(n)
        order.append(entries[n])
    for n in list(entries):
        visit(n)
    listed = order + [s for s in listed if not s.get("name")]
    for s in listed:
        name = s.get("name")
        if not name:
            plan.errors.append("services: an entry needs a name")
            continue
        unknown = [ch for ch in s.get("children") or [] if ch not in names and ch not in by_name]
        if unknown:
            plan.errors.append(f"services.{name}: unknown child service(s): {', '.join(unknown)}")
            continue
        params = {"name": name, "algorithm": str(s.get("algorithm", 2)), "sortorder": str(s.get("sortorder", 0)),
                  "description": str(s.get("description", "")),
                  "problem_tags": [{"tag": str(t["tag"]), "operator": "0", "value": str(t.get("value", ""))}
                                   for t in s.get("problem_tags") or []],
                  "tags": tags_list({**(s.get("tags") or {}), zbxlib.MANAGED_TAG: zbxlib.MANAGED_VALUE}),
                  "children": [{"$service": ch} for ch in s.get("children") or []]}
        cur = by_name.get(name)
        if cur is None:
            plan.add("service", "create", name, "service.create", params, ["+ service"])
            continue
        if (zbxlib.MANAGED_TAG, zbxlib.MANAGED_VALUE) not in norm_tags(cur.get("tags")):
            plan.errors.append(f"services.{name}: a service of that name exists and isn't managed by homelab-manager")
            continue
        diff = []
        for k in ("algorithm", "sortorder", "description"):
            if str(cur.get(k) or "") != params[k]:
                diff.append(k)
        if sorted((t["tag"], t["value"]) for t in cur.get("problem_tags") or []) != \
                sorted((t["tag"], t["value"]) for t in params["problem_tags"]):
            diff.append("problem tags")
        if sorted(c["name"] for c in cur.get("children") or []) != sorted(s.get("children") or []):
            diff.append("children")
        if norm_tags(cur.get("tags")) != norm_tags(params["tags"]):
            diff.append("tags")
        if diff:
            plan.allow("service", cur["serviceid"])
            plan.add("service", "update", name, "service.update", {"serviceid": cur["serviceid"], **params},
                     [f"~ {', '.join(diff)}"])
    slas = {s["name"]: s for s in st.get("slas") or []}
    for s in conf.get("slas") or []:
        name = s.get("name")
        params = {"name": name, "slo": str(s.get("slo", "99.9")),
                  "period": str({"daily": 0, "weekly": 1, "monthly": 2, "quarterly": 3, "annually": 4}
                                .get(str(s.get("period", "monthly")), s.get("period", 2))),
                  "timezone": str(s.get("timezone") or "UTC"),
                  "description": "managed-by homelab-manager",
                  "service_tags": [{"tag": str(t["tag"]), "operator": "0", "value": str(t.get("value", ""))}
                                   for t in s.get("service_tags") or []]}
        cur = slas.get(name)
        if cur is None:
            plan.add("sla", "create", name, "sla.create", params, [f"+ SLA {params['slo']} %"])
        elif "homelab-manager" not in str(cur.get("description") or ""):
            plan.errors.append(f"slas.{name}: an SLA of that name exists and isn't managed by homelab-manager")
        else:
            diff = [k for k in ("slo", "period", "timezone") if str(cur.get(k)) != params[k] and
                    not (k == "slo" and float(cur.get(k) or 0) == float(params[k]))]
            if sorted((t["tag"], t["value"]) for t in cur.get("service_tags") or []) != \
                    sorted((t["tag"], t["value"]) for t in params["service_tags"]):
                diff.append("service tags")
            if diff:
                plan.allow("sla", cur["slaid"])
                plan.add("sla", "update", name, "sla.update", {"slaid": cur["slaid"], **params}, [f"~ {', '.join(diff)}"])


# --------------------------------------------------------------------------- global objects (#174, admin token)

def _norm(v):
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in sorted(v.items())}
    if isinstance(v, list):
        return [_norm(x) for x in v]
    return "" if v is None else str(v)


def _subset(want, have) -> bool:
    """Every key the config sets has the same value on the server (lists compare whole, after normalising)."""
    if isinstance(want, dict):
        return isinstance(have, dict) and all(_subset(v, have.get(k)) for k, v in want.items())
    if isinstance(want, list):
        if not isinstance(have, list) or len(want) != len(have):
            return False
        return all(_subset(w, h) for w, h in zip(want, have))
    return _norm(want) == _norm(have)


def drule_ranges_ok(params: dict, cfg: dict) -> str | None:
    ranges = [ipaddress.ip_network(r, strict=False) for r in hmlib.get(cfg, "network.authorized_ranges") or []]
    for part in str(params.get("iprange") or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                base = lo.rsplit(".", 1)[0]
                nets = [ipaddress.ip_network(lo, strict=False),
                        ipaddress.ip_network(hi if "." in hi else f"{base}.{hi}", strict=False)]
            else:
                nets = [ipaddress.ip_network(part, strict=False)]
        except ValueError:
            return f"iprange {part!r} is not an address range"
        for n in nets:
            if not any(n.subnet_of(r) for r in ranges if r.version == n.version):
                return f"iprange {part} is outside network.authorized_ranges"
    return None


def plan_admin(plan: Plan, conf: dict, st: dict, cfg: dict):
    have = st.get("global_macros") or {}
    for macro, want in sorted((conf.get("global_macros") or {}).items()):
        secret = is_secret(want)
        wval = {"$secret": want["secret"]} if secret else str(want.get("value") if isinstance(want, dict) else want)
        wtype = "1" if secret else "0"
        cur = have.get(macro)
        if cur is None:
            plan.add("global_macro", "create", macro, "usermacro.createglobal",
                     {"macro": macro, "value": wval, "type": wtype}, ["+ global macro"], admin=True)
        elif str(cur.get("type")) != wtype or (not secret and str(cur.get("value")) != wval) or \
                (secret and isinstance(want, dict) and want.get("rotate")):
            plan.allow("globalmacro", cur["globalmacroid"])
            plan.add("global_macro", "update", macro, "usermacro.updateglobal",
                     {"globalmacroid": cur["globalmacroid"], "value": wval, "type": wtype}, ["~ global macro"],
                     admin=True)
    objects = conf.get("objects") or {}
    for kind, entries in objects.items():
        if kind not in OBJECT_API:
            plan.errors.append(f"objects.{kind}: not supported (only {', '.join(OBJECT_API)})")
            continue
        api, idf, _ = OBJECT_API[kind]
        current = st.get(kind) or {}
        for e in entries or []:
            name, params = e.get("name"), dict(e.get("params") or {})
            if not name:
                plan.errors.append(f"objects.{kind}: an entry needs a name")
                continue
            if kind == "drule":
                why = drule_ranges_ok(params, cfg)
                if why:
                    plan.errors.append(f"objects.drule.{name}: {why}")
                    continue
            cur = current.get(name)
            if e.get("absent"):
                if cur:
                    plan.allow(kind, cur[idf])
                    plan.add(kind, "delete", name, f"{api}.delete", [cur[idf]], [f"- {kind}"], destructive=True,
                             admin=True)
                continue
            if cur is None:
                plan.add(kind, "create", name, f"{api}.create", {"name": name, **params}, [f"+ {kind}"], admin=True)
            elif not _subset(params, cur):
                plan.allow(kind, cur[idf])
                diff = [k for k, v in params.items() if not _subset(v, cur.get(k))]
                plan.add(kind, "update", name, f"{api}.update", {idf: cur[idf], **params},
                         [f"~ {kind}: {', '.join(diff)}"], admin=True)
    # users, user groups and roles stay read-only (GitHub #174 triage): differences are reported, never changed
    users = {u["username"]: u for u in st.get("users") or []}
    for user, want in ((conf.get("access") or {}).get("users") or {}).items():
        want = want or {}
        cur = users.get(user)
        if cur is None:
            plan.notes.append(f"access.users.{user}: not on the server (read-only here: create it in the Zabbix UI)")
            continue
        diff = []
        if want.get("role") and (cur.get("role") or {}).get("name") != want["role"]:
            diff.append(f"role {(cur.get('role') or {}).get('name')} (want {want['role']})")
        if "groups" in want and sorted(g["name"] for g in cur.get("usrgrps") or []) != sorted(want["groups"]):
            diff.append("groups " + ", ".join(sorted(g["name"] for g in cur.get("usrgrps") or [])))
        if diff:
            plan.notes.append(f"access.users.{user}: differs — {'; '.join(diff)} (read-only: change it in the UI)")


# --------------------------------------------------------------------------- output, plan file, apply

def plan_text(plan: Plan) -> str:
    lines = []
    for o in plan.ops:
        sign = {"create": "+", "update": "~", "delete": "-"}[o["action"]]
        lines.append(f"  {sign} {o['kind']} {o['target']}: " + "; ".join(o["changes"])
                     + ("  [DESTRUCTIVE]" if o["destructive"] else "") + ("  [admin]" if o["admin"] else ""))
    c = plan.counts()
    lines.append(f"Plan: +{c['create']} create, ~{c['update']} update, -{c['delete']} delete"
                 + (f", {sum(o['destructive'] for o in plan.ops)} destructive" if any(o["destructive"] for o in plan.ops)
                    else ""))
    for n in plan.notes:
        lines.append(f"  note: {n}")
    for e in plan.errors:
        lines.append(f"  ERROR: {e}")
    return "\n".join(lines)


def fingerprint(ops: list[dict]) -> str:
    return hashlib.sha256(json.dumps(ops, sort_keys=True).encode()).hexdigest()


def compute(cfg: dict, c: zbxlib.Client, admin_c, inv: dict, admin: bool) -> tuple[Plan, dict]:
    root = Path(cfg["_root"])
    conf = load_conf(root)
    st = read_state(c, admin_c if admin else None)
    return build_plan(cfg, conf, st, inv, admin=admin), st


def cmd_plan(a, cfg) -> int:
    import zabbix_api
    root = Path(cfg["_root"])
    c = zbxlib.connect(cfg, "ro")
    admin_c = None
    if a.admin:
        admin_c = zbxlib.connect(cfg, "admin")
        admin_c.role = "ro"          # planning only reads, whatever the token could do
    plan, _ = compute(cfg, c, admin_c, zabbix_api.inventory(root, cfg), a.admin)
    print(plan_text(plan))
    if plan.errors:
        print(f"{len(plan.errors)} error(s): fix zabbix/config.yaml (nothing saved)", file=sys.stderr)
        return 1
    if not plan.ops:
        print("No changes: the server matches zabbix/config.yaml.")
        return 0
    out = root / (a.out or PLAN)
    out.parent.mkdir(exist_ok=True)
    data = {"version": PLAN_VERSION, "created_at": zbxlib_now(), "server": c.version(), "admin": bool(a.admin),
            "ops": plan.ops, "fingerprint": fingerprint(plan.ops)}
    hmlib.atomic_write(out, json.dumps(data, indent=2) + "\n")
    print(f"Saved {out.relative_to(root)}. With the user's yes: with_secrets.py "
          f"{zbxlib.secret_name(cfg, 'rw')}{' ' + zbxlib.secret_name(cfg, 'admin') if a.admin else ''}"
          f"{''.join(' ' + s for s in plan_secrets(plan.ops))} -- python3 …/zabbix_api.py apply {out.relative_to(root)}")
    return 0


def zbxlib_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def plan_secrets(ops) -> list[str]:
    found = set()

    def walk(v):
        if isinstance(v, dict):
            if "$secret" in v:
                found.add(v["$secret"])
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    for o in ops:
        walk(o["params"])
    return sorted(found)


class Resolver:
    """Turns the plan's name references into ids at apply time ({"$hostgroup": name} → {"groupid": id} …)."""

    def __init__(self, c: zbxlib.Client, st: dict, cfg: dict, env=None):
        self.c, self.st, self.cfg = c, st, cfg
        self.env = os.environ if env is None else env
        self.hosts = {h["host"]: h["hostid"] for h in st["hosts"]}

    def secret(self, name: str) -> str:
        var = secret_env(self.cfg, name)
        v = self.env.get(var)
        if not v:
            raise PlanError(f"secret {name!r} ({var}) is not in the environment: add it to with_secrets.py")
        return v

    def __call__(self, v, key: str | None = None):
        if isinstance(v, dict):
            if "$hostgroup" in v:
                return {"groupid": self.st["hostgroups"][v["$hostgroup"]]}
            if "$templategroup" in v:
                return {"groupid": self.st["templategroups"][v["$templategroup"]]}
            if "$template" in v:
                tid = self.st["templates"][v["$template"]]["templateid"]
                return tid if key == "hostid" else {"templateid": tid}
            if "$host" in v:
                return self.hosts[v["$host"]]
            if "$hostid" in v:
                return v["$hostid"]
            if "$proxy" in v:
                return self.st["proxies"][v["$proxy"]]
            if "$secret" in v:
                return self.secret(v["$secret"])
            if "$service" in v:
                return {"serviceid": self.st["services_by_name"][v["$service"]]}
            if "$item" in v:
                return self.st["items_by_key"][(v["hostid"], v["$item"])]
            return {k: self(x, k) for k, x in v.items()}
        if isinstance(v, list):
            return [self(x, key) for x in v]
        return v

    def created(self, op: dict, result):
        """Remember ids of objects this apply created, for later ops that reference them."""
        ids = (result or {})
        def first(field):
            return (ids.get(field) or [None])[0]
        p = op["params"]
        if op["method"] == "hostgroup.create":
            self.st["hostgroups"][p["name"]] = first("groupids")
        elif op["method"] == "templategroup.create":
            self.st["templategroups"][p["name"]] = first("groupids")
        elif op["method"] == "template.create":
            self.st["templates"][p["host"]] = {"templateid": first("templateids")}
        elif op["method"] == "host.create":
            self.hosts[p["host"]] = first("hostids")
        elif op["method"] == "service.create":
            self.st.setdefault("services_by_name", {})[p["name"]] = first("serviceids")
        elif op["method"] == "item.create":
            self.st.setdefault("items_by_key", {})[(p["hostid"], p["key_"])] = first("itemids")


ID_FIELDS = {"hostid": "host", "templateid": "template", "hostmacroid": "hostmacro", "interfaceid": "interface",
             "httptestid": "httptest", "serviceid": "service", "slaid": "sla", "globalmacroid": "globalmacro",
             "actionid": "action", "mediatypeid": "mediatype", "druleid": "drule", "regexpid": "regexp"}
DELETE_KIND = {"host.delete": "host", "usermacro.delete": "hostmacro", "hostinterface.delete": "interface",
               "httptest.delete": "httptest", "action.delete": "action", "mediatype.delete": "mediatype",
               "drule.delete": "drule", "regexp.delete": "regexp"}


def check_ids(op: dict, plan: Plan):
    """Defence in depth: an update or delete may only name ids the rebuilt plan resolved."""
    if op["action"] == "create":
        hid = op["params"].get("hostid") if isinstance(op["params"], dict) else None
        if isinstance(hid, str) and hid not in plan.allowed.get("host", set()):
            raise PlanError(f"{op['kind']} {op['target']}: host id {hid} is not in the managed scope")
        return
    if op["method"] in DELETE_KIND:
        kind = DELETE_KIND[op["method"]]
        bad = [i for i in op["params"] if str(i) not in plan.allowed.get(kind, set())]
    else:
        bad = [f"{f}={op['params'][f]}" for f, kind in ID_FIELDS.items()
               if isinstance(op["params"].get(f), str) and op["params"][f] not in plan.allowed.get(kind, set())]
    if bad:
        raise PlanError(f"{op['kind']} {op['target']}: id(s) {', '.join(map(str, bad))} are not in the managed scope")


def cmd_apply(a, cfg) -> int:
    import zabbix_api
    root = Path(cfg["_root"])
    path = Path(a.plan_file)
    path = path if path.is_absolute() else Path.cwd() / path
    try:
        saved = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise hmlib.ConfigError(f"plan file {a.plan_file}: {e}")
    if saved.get("version") != PLAN_VERSION or fingerprint(saved.get("ops") or []) != saved.get("fingerprint"):
        raise hmlib.ConfigError("the plan file was edited or comes from another version: run plan again")
    c = zbxlib.connect(cfg, "rw")
    admin_c = zbxlib.connect(cfg, "admin") if saved.get("admin") else None
    plan, st = compute(cfg, c, admin_c, zabbix_api.inventory(root, cfg), bool(saved.get("admin")))
    if plan.errors or fingerprint(plan.ops) != saved["fingerprint"]:
        print(plan_text(plan))
        print("The server or zabbix/config.yaml changed since the plan: nothing applied. Run plan again and show "
              "the new plan.", file=sys.stderr)
        return 3
    st["services_by_name"] = {s["name"]: s["serviceid"] for s in st.get("services") or []}
    st["items_by_key"] = {(i["hostid"], i["key_"]): i["itemid"] for i in st.get("cert_items") or []}
    res = Resolver(c, st, cfg)
    for o in plan.ops:                     # every secret resolvable before the first write
        for s in plan_secrets([o]):
            res.secret(s)
    done = 0
    for o in plan.ops:
        check_ids(o, plan)
        client = admin_c if o["admin"] else c
        try:
            params = res(o["params"])
            result = client.call(o["method"], params)
        except (zbxlib.ZabbixError, KeyError, PlanError) as e:
            print(f"  FAILED {o['kind']} {o['target']} ({o['method']}): {e}", file=sys.stderr)
            print(f"Applied {done} of {len(plan.ops)} change(s); the rest was not tried. Run plan again.",
                  file=sys.stderr)
            return 1
        res.created(o, result)
        done += 1
        print(f"  done {o['kind']} {o['target']}: {'; '.join(o['changes'])}")
    path.unlink(missing_ok=True)
    print(f"Applied {done} change(s); removed {a.plan_file}. Refresh: zabbix_api.py discover")
    return 0


# --------------------------------------------------------------------------- init-config

def cmd_init_config(a, cfg) -> int:
    """zabbix/config.yaml from what the server has now for the managed, matched hosts, so the first plan shows no
    changes. Groups and templates as they are; tags and macros only when --with-tags/--with-macros (secret macros
    are left out: their values never leave Zabbix)."""
    import zabbix_api
    root = Path(cfg["_root"])
    target = root / CONFIG
    if target.exists() and not a.force:
        raise hmlib.ConfigError(f"{CONFIG} exists: edit it, or --force to rewrite it from the server")
    c = zbxlib.connect(cfg, "ro")
    z = zbxlib.settings(cfg)
    scope = zbxlib.Scope(z)
    inv = zabbix_api.inventory(root, cfg)
    hosts = zbxlib.read_hosts(c)
    m = zbxlib.match_hosts(z, inv, hosts, hmlib.get(cfg, "site.domain") or "")
    out_hosts, groups = {}, set()
    for name, zh in sorted(m.pairs.items()):
        if not scope.host_managed(zh, True):
            continue
        e = {"groups": [g for g in zbxlib.host_group_names(zh) if scope.host_group(g)],
             "templates": [t["host"] for t in zh.get("parentTemplates") or []]}
        groups |= {g for g in e["groups"] if scope.own_group(g)}
        if a.with_tags:
            e["tags"] = {t["tag"]: t["value"] for t in zh.get("tags") or [] if t["tag"] != zbxlib.MANAGED_TAG}
        if a.with_macros:
            e["macros"] = {mm["macro"]: mm.get("value", "") for mm in zh.get("macros") or [] if str(mm.get("type")) != "1"}
        out_hosts[name] = e
    data = {"host_groups": sorted(groups), "template_groups": [], "profiles": {}, "wrappers": {}, "hosts": out_hosts,
            "web": [], "services": [], "slas": []}
    text = HEADER + json_to_yaml(data)
    if a.dry_run:
        print(text)
        return 0
    target.parent.mkdir(exist_ok=True)
    hmlib.atomic_write(target, text)
    print(f"Wrote {CONFIG}: {len(out_hosts)} managed host(s), {len(groups)} own group(s). Check it with "
          "`zabbix_api.py plan` (expect few or no changes), then commit.")
    return 0


HEADER = """# Zabbix monitoring as data (references/monitoring.md). `zabbix_api.py plan` shows the difference to the server,
# `apply` makes it, after the user's yes. Only what is listed here is managed; a key that is present is managed
# exactly (templates: = all linked templates), a key left out is left alone. Secret values: {secret: <name>}
# (a kind env secret in homelab.yaml), never the value itself.
"""


def json_to_yaml(data) -> str:
    """YAML through yq (keeps the file readable and valid)."""
    import subprocess
    r = subprocess.run([hmlib.yq_bin(), "-P", "-o=yaml", "."], input=json.dumps(data), capture_output=True, text=True,
                       timeout=hmlib.YQ_TIMEOUT)
    if r.returncode != 0:
        raise hmlib.ConfigError(f"yq could not write YAML: {r.stderr.strip()}")
    return r.stdout


def add_parsers(sub):
    p = sub.add_parser("plan")
    p.add_argument("--out")
    p.add_argument("--admin", action="store_true")
    p = sub.add_parser("apply")
    p.add_argument("plan_file")
    p = sub.add_parser("init-config")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--with-tags", action="store_true")
    p.add_argument("--with-macros", action="store_true")


HANDLERS = {"plan": cmd_plan, "apply": cmd_apply, "init-config": cmd_init_config}
