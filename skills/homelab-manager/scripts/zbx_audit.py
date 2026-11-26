"""zabbix_api.py audit: what a security audit of the Zabbix setup needs, read-only (GitHub issue #173).

    with_secrets.py zabbix-ro [zabbix-admin] -- python3 …/zabbix_api.py audit [--no-write]

Reads, with *.get calls only:
- the server version (supported: 7.0 LTS and newer; LTS or a standard release), the frontend's TLS (http, or the
  certificate's expiry; verified as zabbix.verify_tls/ca_cert say);
- the managed hosts (zabbix.managed_scope, host_match): how the server talks to each agent (unencrypted or PSK /
  certificate) and the agent's version (item agent.version);
- the proxies: encryption, last seen, version compatibility;
- Zabbix's own health from the internal items of the Zabbix server host (queue, caches, busy processes), as far as
  the token can see them;
- with the admin token (optional, used for reads only): the default `Admin` account, guest access, MFA and the API
  tokens (unused, without expiry). The skill never tries a password: whether `Admin` still has the default one is
  the user's check.
Writes discovery/zabbix-audit.json; security_audit.py turns it into findings (security_audit.zabbix_findings), and
this command prints them too. Everything the tokens can't read is listed under not_checked.
"""
from __future__ import annotations

import datetime
import json
import os
import socket
import ssl
import tempfile
import time
import urllib.parse
from pathlib import Path

import hmlib
import zbxlib

HEALTH_KEYS = {   # internal item keys (Zabbix server health template) → name in zabbix-audit.json
    "zabbix[queue]": "queue",
    "zabbix[queue,10m]": "queue_10m",
    "zabbix[wcache,history,pused]": "history_cache_pused",
    "zabbix[wcache,index,pused]": "history_index_pused",
    "zabbix[wcache,trend,pused]": "trend_cache_pused",
    "zabbix[wcache,values]": "values_per_second",
    "zabbix[rcache,buffer,pused]": "config_cache_pused",
    "zabbix[vcache,buffer,pused]": "value_cache_pused",
    "zabbix[process,housekeeper,avg,busy]": "housekeeper_busy",
    "zabbix[process,poller,avg,busy]": "poller_busy",
    "zabbix[process,agent poller,avg,busy]": "agent_poller_busy",
    "zabbix[process,unreachable poller,avg,busy]": "unreachable_poller_busy",
    "zabbix[process,preprocessing worker,avg,busy]": "preprocessing_busy",
    "zabbix[process,history syncer,avg,busy]": "history_syncer_busy",
    "zabbix[process,trapper,avg,busy]": "trapper_busy",
}
TOKEN_UNUSED_DAYS = 90
ADMIN_NEEDED = "needs the admin token (with_secrets.py zabbix-admin)"


def add_parsers(sub):
    p = sub.add_parser("audit", help="read-only security and health audit of the Zabbix setup")
    p.add_argument("--no-write", action="store_true", help="don't write discovery/zabbix-audit.json")


def audit_path(root) -> Path:
    return Path(root) / "discovery" / "zabbix-audit.json"


def read_only_client(cfg: dict, role: str, env=None) -> zbxlib.Client | None:
    """A client for the role's token that refuses every write (role "ro" in zbxlib), or None without a token."""
    env = os.environ if env is None else env
    token = env.get(zbxlib.token_env(cfg, role))
    if not token:
        return None
    z = zbxlib.settings(cfg)
    return zbxlib.Client(z["url"], token, "ro", zbxlib.ssl_context(cfg), int(z.get("timeout") or 60))


# --------------------------------------------------------------------------- frontend TLS

def _decode_der(der: bytes) -> dict:
    """notAfter of a DER certificate without verifying it (verify_tls: false): CPython's test decoder on a PEM file."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        name = f.name
    try:
        return ssl._ssl._test_decode_cert(name)   # noqa: SLF001 - stdlib only; no other parser in the stdlib
    finally:
        os.unlink(name)


def frontend_tls(url: str, ctx, timeout: float = 10.0, now: float | None = None) -> dict:
    """{scheme, verified, cert_days | cert_error}: the frontend's certificate as this Mac sees it."""
    u = urllib.parse.urlparse(url)
    out = {"scheme": u.scheme or "?"}
    if u.scheme != "https":
        return out
    host, port = u.hostname or "", u.port or 443
    ctx = ctx or ssl.create_default_context()
    out["verified"] = ctx.verify_mode != ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert() if out["verified"] else _decode_der(s.getpeercert(binary_form=True))
    except ssl.SSLCertVerificationError as e:
        out["cert_error"] = hmlib.clean(e.verify_message or str(e), 200)
        return out
    except (OSError, ssl.SSLError, ValueError) as e:
        out["error"] = hmlib.clean(str(e), 200)
        return out
    try:
        end = ssl.cert_time_to_seconds(cert["notAfter"])
        out["cert_days"] = int((end - (time.time() if now is None else now)) // 86400)
    except (KeyError, ValueError):
        out["error"] = "no expiry date in the certificate"
    return out


# --------------------------------------------------------------------------- reads

def managed_hosts(c: zbxlib.Client, cfg: dict, inv: dict) -> list[tuple[str, dict]]:
    """[(inventory name, Zabbix host)] of the managed hosts (as zabbix_api.py discover decides)."""
    z = zbxlib.settings(cfg)
    scope = zbxlib.Scope(z)
    zhosts = zbxlib.read_hosts(c)
    m = zbxlib.match_hosts(z, inv, zhosts, hmlib.get(cfg, "site.domain") or "")
    return [(n, zh) for n, zh in sorted(m.pairs.items()) if scope.host_managed(zh, True)]


def agent_versions(c: zbxlib.Client, hostids: list[str]) -> dict[str, str]:
    if not hostids:
        return {}
    items = c.call("item.get", {"output": ["hostid", "lastvalue", "lastclock"], "hostids": hostids,
                                "filter": {"key_": "agent.version"}}) or []
    return {i["hostid"]: hmlib.clean(i.get("lastvalue"), 40) for i in items if i.get("lastvalue")}


def server_health(c: zbxlib.Client) -> dict:
    """The Zabbix server's internal items the token can see: {host, items: {name: value}, missing: [...]}."""
    found = c.call("item.get", {"output": ["hostid", "lastclock"], "templated": False, "monitored": True,
                                "filter": {"key_": ["zabbix[queue]", "zabbix[queue,10m]"], "type": "5"}}) or []
    found = [i for i in found if int(i.get("lastclock") or 0)]   # a host whose server items collect data
    if not found:
        return {"visible": False}
    hostid = max(found, key=lambda i: int(i["lastclock"]))["hostid"]
    host = (c.call("host.get", {"output": ["host"], "hostids": [hostid]}) or [{}])[0]
    items = c.call("item.get", {"output": ["key_", "lastvalue", "lastclock", "state"], "hostids": [hostid],
                                "filter": {"key_": list(HEALTH_KEYS)}}) or []
    vals = {}
    for i in items:
        name = HEALTH_KEYS.get(i.get("key_"))
        if name and str(i.get("state")) != "1" and i.get("lastclock") not in (None, "0"):
            try:
                vals[name] = round(float(i["lastvalue"]), 2)
            except (TypeError, ValueError):
                pass
    return {"visible": True, "host": hmlib.clean(host.get("host"), 128), "items": vals,
            "missing": sorted(n for n in HEALTH_KEYS.values() if n not in vals)}


def proxies(c: zbxlib.Client) -> list[dict]:
    out = []
    fields = ["proxyid", "name", "operating_mode", "tls_connect", "tls_accept", "lastaccess", "version",
              "compatibility", "state"]
    for p in c.call("proxy.get", {"output": fields}) or []:
        out.append({"name": hmlib.clean(p.get("name"), 128), "mode": "passive" if str(p.get("operating_mode")) == "1"
                    else "active", "tls_connect": str(p.get("tls_connect") or "1"),
                    "tls_accept": str(p.get("tls_accept") or "1"), "lastaccess": int(p.get("lastaccess") or 0),
                    "version": hmlib.clean(p.get("version"), 20) or "", "compatibility": str(p.get("compatibility") or "0")})
    return out


def _disabled(groups: list[dict]) -> bool:
    return any(str(g.get("users_status")) == "1" for g in groups or [])


def admin_reads(c: zbxlib.Client, now: float) -> dict:
    """With the admin token: Admin and guest accounts, MFA, API tokens. Read errors are kept, never retried."""
    out: dict = {}
    grp = ["name", "users_status", "gui_access", "mfa_status"]
    try:
        users = c.call("user.get", {"output": ["userid", "username"], "selectUsrgrps": grp,
                                    "selectRole": ["name", "type"]}) or []
    except zbxlib.ZabbixError as e:
        return {"error": f"user.get: {e}"}
    by_name = {u.get("username"): u for u in users}
    adm = by_name.get("Admin")
    out["admin_user"] = {"exists": bool(adm), "enabled": bool(adm) and not _disabled(adm.get("usrgrps"))}
    guest = by_name.get("guest")
    out["guest"] = {"exists": bool(guest),
                    "enabled": bool(guest) and not _disabled(guest.get("usrgrps"))
                    and not all(str(g.get("gui_access")) == "3" for g in guest.get("usrgrps") or [{}])}
    out["super_admins"] = sorted(u["username"] for u in users if str((u.get("role") or {}).get("type")) == "3")
    try:
        auth = c.call("authentication.get", {"output": ["mfa_status"]}) or {}
        mfa_on = str(auth.get("mfa_status")) == "1"
        groups = c.call("usergroup.get", {"output": ["name", "mfa_status", "gui_access", "users_status"],
                                          "selectUsers": ["username"]}) or []
        out["mfa"] = {"configured": mfa_on,
                      "groups_without": sorted(g["name"] for g in groups if g.get("users") and
                                               str(g.get("mfa_status")) != "1" and str(g.get("users_status")) != "1"
                                               and str(g.get("gui_access")) != "3")}
    except zbxlib.ZabbixError as e:
        out["mfa"] = {"error": hmlib.clean(str(e), 200)}
    try:
        names = {u["userid"]: u["username"] for u in users}
        toks = c.call("token.get", {"output": ["tokenid", "name", "userid", "lastaccess", "expires_at", "status",
                                               "created_at"]}) or []
        out["tokens"] = [{"name": hmlib.clean(t.get("name"), 64), "user": names.get(t.get("userid"), "?"),
                          "enabled": str(t.get("status")) == "0", "lastaccess": int(t.get("lastaccess") or 0),
                          "created": int(t.get("created_at") or 0), "expires": int(t.get("expires_at") or 0)}
                         for t in toks]
    except zbxlib.ZabbixError as e:
        out["tokens_error"] = hmlib.clean(str(e), 200)
    return out


def collect(c: zbxlib.Client, cfg: dict, inv: dict, admin: zbxlib.Client | None = None,
            now: float | None = None, tls=frontend_tls) -> dict:
    now = time.time() if now is None else now
    z = zbxlib.settings(cfg)
    v = c.version()
    major = zbxlib.version_tuple(v)
    data: dict = {"collected_at": datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat(timespec="seconds"),
                  "url": z["url"], "version": v, "line": f"{major[0]}.{major[1]}", "supported": zbxlib.supported(v),
                  "lts": major[1] == 0, "tokens": {"ro": True, "admin": admin is not None}, "not_checked": []}
    data["frontend"] = tls(z["url"], zbxlib.ssl_context(cfg))
    hosts = managed_hosts(c, cfg, inv)
    vers = agent_versions(c, [zh["hostid"] for _, zh in hosts])
    data["hosts"] = [{"name": n, "host": hmlib.clean(zh.get("host"), 128), "enabled": str(zh.get("status")) == "0",
                      "agent": zbxlib.agent_availability(zh), "tls_connect": str(zh.get("tls_connect") or "1"),
                      "tls_accept": str(zh.get("tls_accept") or "1"), "agent_version": vers.get(zh["hostid"], "")}
                     for n, zh in hosts]
    data["proxies"] = proxies(c)
    try:
        data["health"] = server_health(c)
    except zbxlib.ZabbixError as e:
        data["health"] = {"visible": False, "error": hmlib.clean(str(e), 200)}
    if not data["health"].get("visible"):
        data["not_checked"].append("Zabbix server health: its internal items aren't visible to this token")
    if admin is not None:
        data["admin"] = admin_reads(admin, now)
    else:
        data["not_checked"].append(f"the Admin account, guest access, MFA and API tokens: {ADMIN_NEEDED}")
    return data


# --------------------------------------------------------------------------- command

def cmd_audit(a, cfg) -> int:
    import security_audit
    import zabbix_api
    root = Path(cfg["_root"])
    c = zbxlib.connect(cfg, "ro")
    admin = read_only_client(cfg, "admin")
    data = collect(c, cfg, zabbix_api.inventory(root, cfg), admin)
    found = security_audit.zabbix_findings(data)
    n = {s: sum(1 for f in found if f[1] == s) for s in ("high", "medium", "low", "info")}
    print(f"Zabbix {data['version']} ({'LTS' if data['lts'] else 'standard release'}): {len(data['hosts'])} managed "
          f"hosts, {len(data['proxies'])} proxies; findings: {n['high']} high, {n['medium']} medium, {n['low']} low, "
          f"{n['info']} info")
    group: dict = {}
    for key, sev, text, where in found:
        group.setdefault((sev, key, text), []).append(where)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for (sev, key, text), ws in sorted(group.items(), key=lambda x: (order[x[0][0]], x[0][1])):
        hosts = [w for w in ws if w != "Zabbix"]
        print(f"  {sev}: {text}" + (f" — {', '.join(hosts[:8])}" + (f" and {len(hosts) - 8} more" if len(hosts) > 8
                                                                     else "") if hosts else "") + f" · `{key}`")
    for x in data["not_checked"]:
        print(f"  not checked: {x}")
    if not a.no_write:
        p = audit_path(root)
        p.parent.mkdir(exist_ok=True)
        hmlib.atomic_write(p, json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(f"Wrote {p.relative_to(root)}; security_audit.py adds the findings to the security audit")
    return 0


HANDLERS = {"audit": cmd_audit}
