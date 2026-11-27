"""Zabbix for homelab-manager: settings, the JSON-RPC client, host matching and the managed scope.

Used by zabbix_api.py (GitHub issue #168 and its follow-ups #169–#174). Python 3 stdlib only.

- Settings come from the `zabbix:` section of homelab.yaml (settings()).
- Tokens come from the environment that with_secrets.py fills (zabbix-ro / zabbix-rw / zabbix-admin): this
  module never reads the keychain itself, so a token never passes through a command line.
- A client opened with the read-only role refuses every method that isn't a read, before anything is sent.
- Host matching follows the user's ordered `host_match` rules; a short name alone never matches.
- The managed scope (`managed_scope`) decides what may ever be written: own groups, shared groups (a host there
  counts only when matched to an inventory host) and template groups. Everything else is read-only.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

import hmlib

ROLES = ("ro", "rw", "admin")
DEFAULT_SECRETS = {"ro": "zabbix-ro", "rw": "zabbix-rw", "admin": "zabbix-admin"}
DEFAULT_ENV = {"ro": "ZABBIX_RO_TOKEN", "rw": "ZABBIX_RW_TOKEN", "admin": "ZABBIX_ADMIN_TOKEN"}
SUPPORTED = ((7, 0), (8, 0))          # LTS lines; 7.2/7.4 work like 7.0, 6.x is refused
MANAGED_TAG = "managed-by"
MANAGED_VALUE = "homelab-manager"
SEVERITIES = ["not_classified", "information", "warning", "average", "high", "disaster"]
INTERFACE_TYPES = {"1": "agent", "2": "snmp", "3": "ipmi", "4": "jmx"}
INTERFACE_CODES = {v: k for k, v in INTERFACE_TYPES.items()}
AVAILABLE = {"0": "unknown", "1": "available", "2": "unavailable"}
# Methods a read-only client may call; everything else is a write. importcompare changes nothing but needs a
# write-capable role in Zabbix, so it is allowed here only for rw.
READ_SUFFIXES = (".get",)
READ_METHODS = {"apiinfo.version", "configuration.export", "user.checkAuthentication"}
NO_AUTH = {"apiinfo.version"}


class ZabbixError(Exception):
    def __init__(self, message: str, code: int | None = None, data: str = ""):
        super().__init__(message + (f": {data}" if data else ""))
        self.code, self.data = code, data

    @property
    def denied(self) -> bool:
        """The role does not allow the method ("No permissions to call …")."""
        return "No permissions to call" in (self.data or "")


def is_read(method: str) -> bool:
    return method.endswith(READ_SUFFIXES) or method in READ_METHODS


# --------------------------------------------------------------------------- settings

def settings(cfg: dict, need_url: bool = True) -> dict:
    """The `zabbix:` section with defaults filled in; ConfigError when it is missing or has no url."""
    z = dict(cfg.get("zabbix") or {})
    if need_url and not z.get("url"):
        raise hmlib.ConfigError("homelab.yaml has no zabbix.url: set the API URL (…/api_jsonrpc.php) with "
                                "config_set.py, or run `zabbix_api.py probe <frontend URL>` to find it.")
    z.setdefault("secrets", {})
    z["secrets"] = {**DEFAULT_SECRETS, **(z["secrets"] or {})}
    z.setdefault("host_match", [])
    z.setdefault("managed_scope", {})
    z["_where"] = "zabbix"
    return z


def api_url(url: str) -> str:
    """The JSON-RPC endpoint for a frontend or API URL."""
    url = url.strip().rstrip("/")
    return url if url.endswith("api_jsonrpc.php") else url + "/api_jsonrpc.php"


def token_env(cfg: dict, role: str) -> str:
    """The environment variable with_secrets.py fills with the role's token."""
    z = settings(cfg, need_url=False)
    name = z["secrets"][role]
    entry = hmlib.get(cfg, f"secrets.{name}") or {}
    return str(entry.get("env") or DEFAULT_ENV[role])


def secret_name(cfg: dict, role: str) -> str:
    return settings(cfg, need_url=False)["secrets"][role]


# --------------------------------------------------------------------------- client

class Client:
    def __init__(self, url: str, token: str | None, role: str = "ro", ctx=None, timeout: int = 60):
        self.url, self.token, self.role, self.ctx, self.timeout = api_url(url), token, role, ctx, timeout
        self._id = 0
        self._version = None
        self.calls: list[str] = []        # methods called, for tests and the --verbose summary

    def call(self, method: str, params=None):
        if self.role == "ro" and not is_read(method):
            raise ZabbixError(f"{method} is a write: the read-only token never calls it")
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": {} if params is None else params,
                           "id": self._id}).encode()
        headers = {"Content-Type": "application/json-rpc", "User-Agent": "homelab-manager"}
        if method not in NO_AUTH:
            if not self.token:
                raise ZabbixError("no API token in the environment")
            headers["Authorization"] = "Bearer " + self.token
        self.calls.append(method)
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise ZabbixError(f"HTTP {e.code} from {self.url}") from None
        except (urllib.error.URLError, OSError) as e:
            raise ZabbixError(f"{self.url} not reachable ({getattr(e, 'reason', e)})") from None
        try:
            data = json.loads(raw)
        except ValueError:
            raise ZabbixError(f"{self.url} did not answer with JSON (not a Zabbix API URL?)") from None
        if "error" in data:
            err = data["error"] or {}
            raise ZabbixError(str(err.get("message") or "API error"), err.get("code"),
                              hmlib.clean(err.get("data") or "", 300))
        return data.get("result")

    def version(self) -> str:
        if self._version is None:
            self._version = str(self.call("apiinfo.version"))
        return self._version

    def major(self) -> tuple[int, int]:
        return version_tuple(self.version())


def version_tuple(v: str) -> tuple[int, int]:
    m = re.match(r"(\d+)\.(\d+)", str(v))
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def supported(v: str) -> bool:
    return version_tuple(v) >= SUPPORTED[0]


def ssl_context(cfg: dict):
    return hmlib.proxmox_ssl_context(cfg, settings(cfg, need_url=False))


def connect(cfg: dict, role: str = "ro", env=None) -> Client:
    """A client for the role, with its token from the environment (with_secrets.py sets it)."""
    env = os.environ if env is None else env
    z = settings(cfg)
    var = token_env(cfg, role)
    token = env.get(var)
    if not token and role == "ro":
        # a patch run has only the rw token: reads use it through a client that still refuses every write
        token = env.get(token_env(cfg, "rw"))
    if not token:
        raise hmlib.ConfigError(f"{var} is not set: run under `with_secrets.py {secret_name(cfg, role)} -- …`")
    c = Client(z["url"], token, role, ssl_context(cfg), int(z.get("timeout") or 60))
    v = c.version()
    if not supported(v):
        raise hmlib.ConfigError(f"Zabbix {v} is not supported: homelab-manager needs 7.0 LTS or newer")
    return c


# --------------------------------------------------------------------------- scope

def group_match(name: str, patterns) -> bool:
    """`Home/*` matches `Home` and everything under it; other patterns are fnmatch globs, case-sensitive."""
    for p in patterns or []:
        p = str(p)
        if p.endswith("/*") and name == p[:-2]:
            return True
        if fnmatch.fnmatchcase(name, p):
            return True
    return False


class Scope:
    """What homelab-manager may write. own: host groups that are the user's (create/rename/delete when empty);
    shared: groups other owners use too (stock `Linux servers`): a host there is managed only when it matches an
    inventory host, and the group itself is never changed; templates: template groups wrappers and imported
    templates may live in."""

    def __init__(self, z: dict):
        s = z.get("managed_scope") or {}
        self.own = list(s.get("host_groups") or [])
        self.shared = list(s.get("shared_host_groups") or [])
        self.templates = list(s.get("template_groups") or [])
        self.tag = s.get("tag")        # optional {tag: value} a host must carry to be managed

    @property
    def empty(self) -> bool:
        return not (self.own or self.shared)

    def own_group(self, name: str) -> bool:
        return group_match(name, self.own)

    def host_group(self, name: str) -> bool:
        return group_match(name, self.own) or group_match(name, self.shared)

    def template_group(self, name: str) -> bool:
        return group_match(name, self.templates)

    def tagged(self, host: dict) -> bool:
        if not self.tag:
            return True
        want = self.tag if isinstance(self.tag, dict) else {str(self.tag): MANAGED_VALUE}
        tags = {t.get("tag"): t.get("value") for t in host.get("tags") or []}
        return all(tags.get(k) == v for k, v in want.items())

    def host_managed(self, host: dict, matched: bool) -> bool:
        """A Zabbix host the skill may write: matched to an inventory host, in at least one scoped group (own or
        shared), and carrying the scope tag if one is set. Hosts only in own groups but not matched are listed
        (stale or not in the inventory) but never written by host matching alone."""
        if not matched or not self.tagged(host):
            return False
        return any(self.host_group(g) for g in host_group_names(host))


def host_group_names(host: dict) -> list[str]:
    return [g.get("name") for g in (host.get("hostgroups") or host.get("groups") or []) if g.get("name")]


# --------------------------------------------------------------------------- matching

class Match:
    def __init__(self):
        self.pairs: dict[str, dict] = {}          # inventory name → Zabbix host
        self.how: dict[str, str] = {}             # inventory name → rule that matched
        self.ambiguous: list[dict] = []           # {inventory, candidates, why}
        self.unmatched_inventory: list[str] = []
        self.unmatched_zabbix: list[dict] = []    # Zabbix hosts no inventory host matched

    def zabbix_to_inventory(self) -> dict[str, str]:
        return {z["hostid"]: n for n, z in self.pairs.items()}


def _rule_applies(rule: dict, inv: dict) -> bool:
    sites = rule.get("sites")
    if sites:
        hs = hmlib.host_sites(inv.get("_groups_all") or inv.get("groups") or [])
        if not set(map(str, sites)) & set(hs or [hmlib.DEFAULT_SITE_KEY]):
            return False
    groups = rule.get("groups")
    if groups and not set(map(str, groups)) & set(inv.get("_groups_all") or inv.get("groups") or []):
        return False
    return True


def expand(pattern: str, name: str, inv: dict, domain: str = "") -> str:
    short = name.split(".")[0]
    return (str(pattern).replace("{inventory_hostname}", name).replace("{host}", name)
            .replace("{short}", short).replace("{domain}", domain or ""))


def new_host_name(z: dict, name: str, inv: dict, domain: str = "") -> str | None:
    """The technical name a new Zabbix host gets: the zabbix_host_name host var, else the first applicable
    pattern rule. None when no rule gives one (the user must add a rule or the var)."""
    if inv.get("zabbix_host_name"):
        return str(inv["zabbix_host_name"])
    for rule in z.get("host_match") or []:
        if rule.get("pattern") and _rule_applies(rule, inv):
            return expand(rule["pattern"], name, inv, domain)
    return None


def match_hosts(z: dict, inventory: dict[str, dict], zhosts: list[dict], domain: str = "") -> Match:
    """Match inventory hosts to Zabbix hosts by the user's ordered rules (zabbix_host_name var first; then each
    rule: `pattern` on the technical name then the visible name, `regex` with a named group `host`, and
    `interface_ip`, which needs the short name to agree too). A Zabbix host claimed twice, or an inventory host
    that a rule maps to two Zabbix hosts, is ambiguous: reported, never written."""
    m = Match()
    by_host = {}
    by_name = {}
    for zh in zhosts:
        by_host.setdefault(zh.get("host"), []).append(zh)
        by_name.setdefault(zh.get("name"), []).append(zh)
    claims: dict[str, list[str]] = {}
    found: dict[str, tuple[dict, str]] = {}
    rules = z.get("host_match") or []
    for name, inv in sorted(inventory.items()):
        hit, how, why = None, "", ""
        override = inv.get("zabbix_host_name")
        candidates = []
        if override:
            candidates = by_host.get(str(override)) or by_name.get(str(override)) or []
            how = "zabbix_host_name"
        for i, rule in enumerate(rules):
            if candidates or not _rule_applies(rule, inv):
                continue
            if rule.get("pattern"):
                want = expand(rule["pattern"], name, inv, domain)
                candidates = by_host.get(want) or by_name.get(want) or []
                how = f"rule {i + 1} ({rule['pattern']})"
            elif rule.get("regex"):
                rx = re.compile(str(rule["regex"]))
                candidates = []
                for zh in zhosts:
                    for field in ("host", "name"):
                        mm = rx.fullmatch(str(zh.get(field) or ""))
                        if mm and mm.groupdict().get("host") == name:
                            candidates.append(zh)
                            break
                how = f"rule {i + 1} (regex)"
            elif rule.get("interface_ip"):
                ip = str(inv.get("ansible_host") or "")
                short = name.split(".")[0]
                candidates = [zh for zh in zhosts if ip and any(str(f.get("ip")) == ip for f in zh.get("interfaces") or [])
                              and str(zh.get("host", "")).split(".")[0] == short]
                how = f"rule {i + 1} (interface IP and short name)"
        uniq = {c["hostid"]: c for c in candidates}
        if len(uniq) == 1:
            hit = next(iter(uniq.values()))
        elif len(uniq) > 1:
            why = f"{how} gives {len(uniq)} Zabbix hosts"
            m.ambiguous.append({"inventory": name, "candidates": sorted(c.get("host") for c in uniq.values()),
                                "why": why})
            continue
        if hit:
            found[name] = (hit, how)
            claims.setdefault(hit["hostid"], []).append(name)
        else:
            m.unmatched_inventory.append(name)
    for hostid, names in claims.items():
        if len(names) > 1:
            zh = found[names[0]][0]
            m.ambiguous.append({"inventory": ", ".join(sorted(names)), "candidates": [zh.get("host")],
                                "why": "one Zabbix host matched by several inventory hosts"})
            for n in names:
                found.pop(n, None)
    for name, (zh, how) in found.items():
        m.pairs[name] = zh
        m.how[name] = how
    taken = {z["hostid"] for z in m.pairs.values()}
    m.unmatched_zabbix = [zh for zh in zhosts if zh["hostid"] not in taken]
    m.unmatched_inventory = sorted(set(m.unmatched_inventory) | {a["inventory"] for a in m.ambiguous
                                                                  if "," not in a["inventory"]})
    return m


# --------------------------------------------------------------------------- reading the server

HOST_OUTPUT = ["hostid", "host", "name", "status", "maintenance_status", "maintenanceid", "active_available",
               "monitored_by", "proxyid", "proxy_groupid", "tls_connect", "tls_accept", "description",
               "inventory_mode"]


def read_hosts(c: Client) -> list[dict]:
    params = {"output": HOST_OUTPUT,
              "selectInterfaces": ["interfaceid", "type", "main", "useip", "ip", "dns", "port", "available",
                                   "error", "details"],
              "selectHostGroups": ["groupid", "name"],
              "selectParentTemplates": ["templateid", "host", "name"],
              "selectTags": ["tag", "value"],
              "selectMacros": ["macro", "value", "type", "description"],
              "selectInventory": "extend"}
    if c.major() < (7, 0):
        params["output"] = [f for f in HOST_OUTPUT if f not in ("monitored_by", "proxy_groupid")]
    hosts = c.call("host.get", params) or []
    for h in hosts:
        for m in h.get("macros") or []:
            if str(m.get("type")) == "1":   # secret: Zabbix never returns the value, keep it that way
                m.pop("value", None)
    return hosts


def host_summary(h: dict) -> dict:
    """A host as discovery/zabbix.json stores it: names cleaned (they are untrusted data), no macro values."""
    ifaces = [{"type": INTERFACE_TYPES.get(str(i.get("type")), str(i.get("type"))), "main": str(i.get("main")) == "1",
               "ip": i.get("ip") or "", "dns": hmlib.clean(i.get("dns") or "", 120), "port": str(i.get("port") or ""),
               "available": AVAILABLE.get(str(i.get("available")), "unknown"),
               **({"error": hmlib.clean(i["error"], 200)} if i.get("error") else {})}
              for i in h.get("interfaces") or []]
    inv = h.get("inventory") if isinstance(h.get("inventory"), dict) else {}
    return {"hostid": h["hostid"], "host": hmlib.clean(h.get("host"), 128), "name": hmlib.clean(h.get("name"), 128),
            "enabled": str(h.get("status")) == "0", "maintenance": str(h.get("maintenance_status")) == "1",
            "groups": [hmlib.clean(g, 255) for g in host_group_names(h)],
            "templates": [hmlib.clean(t.get("host") or t.get("name"), 128) for t in h.get("parentTemplates") or []],
            "tags": {hmlib.clean(t.get("tag"), 64): hmlib.clean(t.get("value"), 128) for t in h.get("tags") or []},
            "macros": sorted(m.get("macro") for m in h.get("macros") or []),
            "interfaces": ifaces,
            "agent": agent_availability(h),
            "checks": agent_checks(h),
            "encryption": {"connect": str(h.get("tls_connect") or "1"), "accept": str(h.get("tls_accept") or "1")},
            "proxyid": str(h.get("proxyid") or "0"),
            "inventory": {k: hmlib.clean(v, 200) for k, v in inv.items() if v and k in INVENTORY_FIELDS}}


INVENTORY_FIELDS = ("os", "os_short", "serialno_a", "location", "hardware", "vendor", "model", "tag", "notes",
                    "type", "macaddress_a")


def agent_availability(h: dict) -> str:
    """available / unavailable / unknown / none for the host's agent: passive agent interface, else the active
    checks status (Zabbix 6.4+: active_available)."""
    ag = [i for i in h.get("interfaces") or [] if str(i.get("type")) == "1"]
    states = [AVAILABLE.get(str(i.get("available")), "unknown") for i in ag]
    if "available" in states:
        return "available"
    act = AVAILABLE.get(str(h.get("active_available")), "unknown")
    if act == "available":
        return "available"
    if "unavailable" in states or act == "unavailable":
        return "unavailable"
    return "unknown" if ag or act != "unknown" else "none"


def agent_checks(h: dict) -> dict:
    """{"passive": state of the agent interface or none, "active": active checks status} (GitHub issue #178)."""
    ag = [AVAILABLE.get(str(i.get("available")), "unknown") for i in h.get("interfaces") or [] if str(i.get("type")) == "1"]
    passive = "available" if "available" in ag else (ag[0] if ag else "none")
    return {"passive": passive, "active": AVAILABLE.get(str(h.get("active_available")), "unknown")}


# action condition 24 = host metadata; operators: 2 contains, 3 does not contain, 8 matches, 9 does not match
METADATA_OPS = {"2": "contains", "3": "not contains", "8": "matches", "9": "not matches"}
# how an action combines its conditions: and/or = conditions of one type OR'ed, of different types AND'ed
EVAL_TYPES = {"0": "and/or", "1": "and", "2": "or", "3": "custom"}


def read_autoregistration(c: Client) -> list[dict] | None:
    """The host-metadata conditions of the autoregistration actions and how each action combines them (GitHub
    issue #179); None when the token may not read actions."""
    try:
        acts = c.call("action.get", {"output": ["actionid", "name", "status", "eventsource"],
                                     "filter": {"eventsource": "2"}, "selectFilter": "extend"}) or []
    except ZabbixError:
        return None
    out = []
    for a in acts:
        if str(a.get("eventsource", "2")) != "2":
            continue
        conds = (a.get("filter") or {}).get("conditions") or []
        flt = a.get("filter") or {}
        out.append({"name": hmlib.clean(a.get("name"), 128), "enabled": str(a.get("status")) == "0",
                    "eval": EVAL_TYPES.get(str(flt.get("evaltype", "0")), "and/or"),
                    **({"formula": hmlib.clean(flt.get("formula"), 255)} if str(flt.get("evaltype")) == "3" else {}),
                    "metadata": [{"op": METADATA_OPS.get(str(x.get("operator")), str(x.get("operator"))),
                                  "value": hmlib.clean(x.get("value"), 255)}
                                 for x in conds if str(x.get("conditiontype")) == "24"]})
    return out


def severity_name(v) -> str:
    try:
        return SEVERITIES[int(v)]
    except (ValueError, IndexError, TypeError):
        return str(v)


def severity_level(name) -> int:
    name = str(name).lower()
    if name.isdigit():
        return int(name)
    return SEVERITIES.index(name) if name in SEVERITIES else SEVERITIES.index("high")


def read_problems(c: Client, hostids: list[str] | None = None) -> list[dict]:
    """Open problems (cleaned names: problem texts are untrusted) with their host ids."""
    params = {"output": ["eventid", "objectid", "name", "severity", "clock", "acknowledged", "suppressed"],
              "recent": False, "sortfield": ["eventid"], "sortorder": "DESC"}
    if hostids is not None:
        if not hostids:
            return []
        params["hostids"] = hostids
    probs = c.call("problem.get", params) or []
    if not probs:
        return []
    trig = {t["triggerid"]: t for t in c.call("trigger.get", {
        "output": ["triggerid", "manual_close"], "triggerids": sorted({p["objectid"] for p in probs}),
        "selectHosts": ["hostid"]}) or []}
    out = []
    for p in probs:
        t = trig.get(p["objectid"]) or {}
        out.append({"eventid": p["eventid"], "name": hmlib.clean(p.get("name"), 200),
                    "severity": severity_name(p.get("severity")), "since": int(p.get("clock") or 0),
                    "acknowledged": str(p.get("acknowledged")) == "1", "suppressed": str(p.get("suppressed")) == "1",
                    "manual_close": str(t.get("manual_close")) == "1",
                    "hostids": [h["hostid"] for h in t.get("hosts") or []]})
    return out


# --------------------------------------------------------------------------- repo data

def load_yaml(path: Path):
    """A YAML file as data (yq), None when it doesn't exist."""
    import subprocess
    if not path.exists():
        return None
    r = subprocess.run([hmlib.yq_bin(), "-o=json", ".", str(path)], capture_output=True, text=True,
                       timeout=hmlib.YQ_TIMEOUT)
    if r.returncode != 0:
        raise hmlib.ConfigError(f"{path} is not valid YAML: {r.stderr.strip()}")
    return json.loads(r.stdout or "null")


def discovery_path(root) -> Path:
    return Path(root) / "discovery" / "zabbix.json"


def load_discovery(root) -> dict | None:
    p = discovery_path(root)
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def monitoring_gaps(doc: dict, configured: dict, inventory: set[str], decommission_days: int = 30,
                    today=None) -> list[tuple[str, list[str]]]:
    """Monitoring findings from discovery/zabbix.json and zabbix/config.yaml, without calling Zabbix (drift_report,
    overview): [(heading, rows)], only headings with rows."""
    import datetime
    today = today or datetime.date.today()
    hosts = doc.get("hosts") or {}
    out = [("Inventory hosts not monitored (`zabbix_api.py propose` drafts entries)", [f"`{n}`" for n in doc.get("not_monitored") or []
                                              if n not in configured]),
           ("Agent not available", [f"`{n}` ({h.get('host')})" for n, h in sorted(hosts.items())
                                    if h.get("managed") and h.get("enabled") and h.get("agent") == "unavailable"]),
           ("Ambiguous Zabbix matches (set zabbix_host_name)",
            [f"`{a['inventory']}` → {', '.join(a['candidates'])}" for a in doc.get("ambiguous") or []]),
           ("In own Zabbix groups but not in the inventory",
            [f"{h['host']} ({', '.join(h.get('groups') or [])})" for h in doc.get("unmatched_in_scope") or []
             if not (h.get("tags") or {}).get("decommissioned")]),
           ("zabbix/config.yaml hosts not in the inventory (decommission them)",
            [f"`{n}`" for n, e in sorted(configured.items()) if n not in inventory
             and (e or {}).get("status") not in ("decommissioned", "disabled", "absent")])]
    due = []
    for n, h in sorted(hosts.items()):
        since = (h.get("tags") or {}).get("decommissioned")
        try:
            age = (today - datetime.date.fromisoformat(since)).days if since else -1
        except ValueError:
            age = -1
        if age >= decommission_days:
            due.append(f"`{n}` (decommissioned {since}): delete with the user's yes (status: absent)")
    out.append((f"Decommissioned over {decommission_days} days", due))
    return [(t, rows) for t, rows in out if rows]
