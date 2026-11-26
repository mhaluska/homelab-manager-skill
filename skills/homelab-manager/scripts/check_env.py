#!/usr/bin/env python3
"""Check that this Mac is ready to manage the homelab.

    check_env.py              tools + SSH agent + config + configured keychain items + Proxmox TLS
                              + the skill's Proxmox tokens without an expiry or expiring soon (read-only token)
                              + whether the repo is ahead of or behind its upstream (git.auto_push)
                              + Ansible targets whose Python the installed ansible-core can't use
    check_env.py --keychain   also run a keychain self-test (write, read, delete a dummy item)
    check_env.py --json       machine-readable output

Never prints secret values — only whether each item exists and is readable without
a GUI prompt (which on a headless Mac would hang forever).
"""
from __future__ import annotations

import json
import os
import re
import secrets as pysecrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

TOOLS = {
    "tofu": (["tofu", "version"], "brew install opentofu"),
    "packer": (["packer", "version"], "brew tap hashicorp/tap && brew install hashicorp/tap/packer"),
    "ansible": (["ansible", "--version"], "brew install ansible"),
    "nmap": (["nmap", "--version"], "brew install nmap"),
    "yq": (["yq", "--version"], "brew install yq"),
    "jq": (["jq", "--version"], "brew install jq"),
    "git": (["git", "--version"], "xcode-select --install"),
    "gh": (["gh", "--version"], "brew install gh   (only needed to report GitHub issues)"),
}
# a tool only a component uses: skipped while homelab.yaml disables that component (GitHub issue #120)
TOOL_COMPONENT = {"tofu": "proxmox", "packer": "templates", "ansible": "ansible", "nmap": "discovery"}
SELFTEST_SERVICE = "homelab/_selftest"
TOKEN_EXPIRY_WARN_DAYS = 30   # a token (or its user) expiring this soon is a warning (GitHub issue #155)


def run(cmd, timeout=15, input_text=None, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


def check_tools(cfg=None):
    """Every tool; with a homelab.yaml, the tools of disabled components are reported as not needed."""
    out = []
    for name, (cmd, install) in TOOLS.items():
        comp = TOOL_COMPONENT.get(name)
        if cfg and comp and not hmlib.get(cfg, f"components.{comp}", True):
            out.append({"check": f"tool:{name}", "ok": None, "detail": f"not needed (components.{comp}: false)"})
            continue
        if not shutil.which(cmd[0]):
            out.append({"check": f"tool:{name}", "ok": False, "detail": f"missing — {install}"})
            continue
        _, so, se = run(cmd)
        first = (so or se).strip().splitlines()[0] if (so or se).strip() else "?"
        out.append({"check": f"tool:{name}", "ok": True, "detail": first})
    return out


def check_ssh_agent():
    if not os.environ.get("SSH_AUTH_SOCK"):
        return [{"check": "ssh-agent", "ok": False, "detail": "SSH_AUTH_SOCK not set — no agent in this session"}]
    rc, so, _ = run(["ssh-add", "-l"])
    if rc == 0:
        keys = [l.split()[-1] if l.strip() else "" for l in so.strip().splitlines()]
        return [{"check": "ssh-agent", "ok": True, "detail": f"{len(keys)} key(s) loaded: {', '.join(keys)}"}]
    return [{"check": "ssh-agent", "ok": False, "detail": "agent running but no keys loaded (ssh-add --apple-use-keychain ~/.ssh/<key>)"}]


def check_gh():
    if not shutil.which("gh"):
        return []
    rc, so, se = run(["gh", "auth", "status"], timeout=20)
    logged = [l for l in (so + se).splitlines() if "Logged in to" in l]
    if logged:
        return [{"check": "gh:auth", "ok": True,
                 "detail": "; ".join(l.strip().lstrip("✓ ").split(" (")[0] for l in logged)}]
    return [{"check": "gh:auth", "ok": False, "detail": "not logged in — run: gh auth login (stores the token in the keychain)"}]


def check_keychain_unlocked():
    rc, so, se = run(["/usr/bin/security", "show-keychain-info"], timeout=10)
    if rc == 0:
        return [{"check": "keychain:login", "ok": True, "detail": "default keychain unlocked (" + ((so + se).strip().split()[-1] if (so + se).strip() else "?") + ")"}]
    return [{"check": "keychain:login", "ok": False,
             "detail": f"default keychain not usable ({(se or so).strip() or rc}). With auto-login it should be unlocked; "
                       "if the Mac was rebooted to the login window, log in once on the console or via Screen Sharing."}]


def check_keychain_selftest():
    """Write, read back and delete a random dummy item. Proves non-interactive access works."""
    token = pysecrets.token_hex(16)
    user = os.environ.get("USER", "")
    rc, _, se = run(["/usr/bin/security", "add-generic-password", "-U", "-T", "/usr/bin/security",
                     "-a", user, "-s", SELFTEST_SERVICE, "-w", token], timeout=15)
    if rc != 0:
        return [{"check": "keychain:selftest", "ok": False, "detail": f"cannot write test item ({se.strip() or rc})"}]
    try:
        value = hmlib.keychain_read(SELFTEST_SERVICE, user, timeout=15)
        ok = value == token
        detail = "write → read → delete OK, no GUI prompt" if ok else "read back a different value"
    except hmlib.ConfigError as e:
        ok, detail = False, str(e)
    run(["/usr/bin/security", "delete-generic-password", "-a", user, "-s", SELFTEST_SERVICE], timeout=15)
    return [{"check": "keychain:selftest", "ok": ok, "detail": detail}]


def check_config_and_secrets():
    root = hmlib.find_repo_root()
    if not root:
        return [{"check": "config", "ok": None, "detail": "not inside a homelab-infrastructure repo (no homelab.yaml)"}], None
    try:
        cfg = hmlib.load_config(root)
    except hmlib.ConfigError as e:
        return [{"check": "config", "ok": False, "detail": str(e)}], None
    out = [{"check": "config", "ok": True, "detail": str(root / hmlib.CONFIG_NAME)}]
    for name, entry in (cfg.get("secrets") or {}).items():
        if not isinstance(entry, dict) or not entry.get("service"):
            continue
        if entry.get("kind") == "s3_credentials" and hmlib.get(cfg, "opentofu.state_backend", "local") != "s3":
            continue  # only needed for the S3 state backend
        service, account = entry["service"], entry.get("account") or os.environ.get("USER")
        rc, _, _ = run(["/usr/bin/security", "find-generic-password", "-a", account, "-s", service], timeout=10)
        if rc != 0:
            out.append({"check": f"secret:{name}", "ok": False,
                        "detail": f"missing — create with: security add-generic-password -U -T /usr/bin/security -a \"$USER\" -s {service} -w"})
            continue
        try:
            v = hmlib.keychain_read(service, account, timeout=15)
            fmt_ok = True
            want = {"proxmox_token": (r"^[^@\s]+@[^!\s]+![^=\s]+=\S+$", "user@realm!tokenid=secret"),
                    "pbs_token": (r"^[^@\s]+@[^!\s]+![^:=\s]+[:=]\S+$", "user@realm!tokenid:secret"),
                    "s3_credentials":(r"^[^:\s]+:\S+$", "ACCESS_KEY_ID:SECRET_ACCESS_KEY"),
                    "user_password": (r"^[^:\s]+:.+$", "user:password")}.get(entry.get("kind"))
            if want:
                fmt_ok = bool(re.match(want[0], v))
            out.append({"check": f"secret:{name}", "ok": bool(v) and fmt_ok,
                        "detail": ("readable" if fmt_ok else f"readable but not in {want[1]} format")
                        + f" ({len(v)} chars)"})
        except hmlib.ConfigError as e:
            out.append({"check": f"secret:{name}", "ok": False, "detail": str(e)})
    return out, cfg


def check_zabbix(cfg, client=None):
    """zabbix: in homelab.yaml (GitHub issue #168): the token secrets it names exist as kind env entries, a ca_cert
    file exists, and the API answers apiinfo.version (no token, read-only)."""
    z = (cfg or {}).get("zabbix") or {}
    if not z.get("url"):
        return []
    import zbxlib
    out = []
    zs = zbxlib.settings(cfg)
    for role in ("ro", "rw", "admin"):
        name = zs["secrets"].get(role)
        entry = hmlib.get(cfg, f"secrets.{name}") if name else None
        if entry is None:
            if role != "admin":
                out.append({"check": f"zabbix:{role}", "ok": False,
                            "detail": f"zabbix.secrets.{role} names {name!r}, which secrets: doesn't have (kind env)"})
            continue
        if entry.get("kind") != "env":
            out.append({"check": f"zabbix:{role}", "ok": False, "detail": f"secrets.{name} must be kind env"})
    ca = z.get("ca_cert")
    if ca and not Path(os.path.expanduser(str(ca))).is_file():
        out.append({"check": "zabbix:tls", "ok": False, "detail": f"zabbix.ca_cert {ca} doesn't exist"})
        return out
    try:
        c = client or zbxlib.Client(zs["url"], None, "ro", zbxlib.ssl_context(cfg), timeout=10)
        v = c.version()
        ok = zbxlib.supported(v)
        out.append({"check": "zabbix", "ok": ok, "detail": f"{zbxlib.api_url(zs['url'])}: Zabbix {v}"
                    + ("" if ok else " (needs 7.0 LTS or newer)")})
    except (zbxlib.ZabbixError, hmlib.ConfigError) as e:
        out.append({"check": "zabbix", "ok": False, "detail": str(e)})
    return out


KEYCHAINS = ["/Library/Keychains/System.keychain", str(Path.home() / "Library/Keychains/login.keychain-db")]


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float = 8):
    """None if the TLS handshake (with verification as ctx says) succeeds, else the exception."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return None
    except (OSError, ssl.SSLError) as e:
        return e


def _chain_names(host: str, port: int) -> list[str]:
    """Common names of the issuers (and intermediates) the server presents, without verifying them."""
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=8) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            chain = s.get_unverified_chain() if hasattr(s, "get_unverified_chain") else [s.getpeercert(True)]
    except (OSError, ssl.SSLError):
        return []
    names = []
    with tempfile.TemporaryDirectory() as d:
        for i, der in enumerate(chain or []):
            der = der if isinstance(der, bytes) else der.public_bytes(ssl._ssl.ENCODING_DER)
            f = Path(d) / f"{i}.pem"
            f.write_text(ssl.DER_cert_to_PEM_cert(der))
            try:
                info = ssl._ssl._test_decode_cert(str(f))
            except Exception:  # private helper; detection is best effort
                continue
            for field in ("issuer",) + (("subject",) if i else ()):
                for rdn in info.get(field, ()):
                    for k, v in rdn:
                        if k == "commonName" and v not in names:
                            names.append(v)
    return names


def _keychain_ca_fix(host: str, port: int, names: list[str]):
    """Find a keychain certificate that makes verification pass: (name, keychain) or None."""
    for name in names:
        for kc in KEYCHAINS:
            if not Path(kc).exists():
                continue
            rc, pem, _ = run(["/usr/bin/security", "find-certificate", "-a", "-c", name, "-p", kc], timeout=10)
            if rc != 0 or "BEGIN CERTIFICATE" not in pem:
                continue
            with tempfile.NamedTemporaryFile("w", suffix=".pem") as f:
                f.write(pem)
                f.flush()
                if _handshake(host, port, ssl.create_default_context(cafile=f.name)) is None:
                    return name, kc
    return None


def check_proxmox_tls(cfg):
    """The certificate of every site's Proxmox (sites: in homelab.yaml; one site without it)."""
    if not cfg:
        return []
    try:
        targets = hmlib.proxmox_sites(cfg)
    except hmlib.ConfigError as e:
        return [{"check": "sites", "ok": False, "detail": str(e)}]
    return [r for px in targets for r in _check_endpoints(cfg, px)]


def _check_endpoints(cfg, px):
    """Every address of a site's Proxmox (GitHub issue #98). One that cannot be reached is a warning while another
    answers: scripts use the first that answers (a node being patched, say)."""
    eps = px.get("endpoints") or [px["endpoint"]]
    if len(eps) == 1:
        return _check_tls(cfg, px)
    rows = []
    for i, ep in enumerate(eps, 1):
        r = _check_tls(cfg, {**px, "endpoint": ep})[0]
        rows.append({**r, "check": f"{r['check']}#{i}"})
    if any(r["ok"] for r in rows):
        for i, r in enumerate(rows):
            if r["ok"] is False and r["detail"].startswith("cannot connect"):
                r["ok"] = None
                r["detail"] += (" — the first endpoint is down: scripts use the next one that answers" if i == 0
                                else " — a fallback endpoint is down")
    return rows


def _check_tls(cfg, px):
    check = "proxmox:tls" + (f":{px['_site']}" if px["_site"] and px["_where"] != "proxmox" else "")
    where, endpoint = px["_where"], px["endpoint"]
    if px.get("verify_tls", True) is False:
        return [{"check": check, "ok": None,
                 "detail": f"verify_tls: false — certificate not checked (prefer {where}.ca_cert)"}]
    u = urllib.parse.urlsplit(endpoint)
    if u.scheme == "http":   # hmlib.proxmox_site allows it only with allow_http: true
        return [{"check": check, "ok": None,
                 "detail": f"{where}.allow_http: true — the API token crosses the network in clear text "
                           "(use https://<host>:8006)"}]
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 8006)
    if not host:
        return [{"check": check, "ok": False, "detail": f"{where}.endpoint {endpoint!r} is not a URL"}]
    try:
        ctx = hmlib.proxmox_ssl_context(cfg, px)
    except hmlib.ConfigError as e:
        return [{"check": check, "ok": False, "detail": str(e)}]
    ca = hmlib.proxmox_ca_file(cfg, px)
    err = _handshake(host, port, ctx)
    if err is None:
        return [{"check": check, "ok": True,
                 "detail": f"{host}:{port} certificate verified ({'ca_cert ' + ca if ca else 'default CA bundle'})"}]
    if not isinstance(err, ssl.SSLCertVerificationError):
        return [{"check": check, "ok": False, "detail": f"cannot connect to {host}:{port} ({err})"}]
    if getattr(err, "verify_code", None) == 62:
        return [{"check": check, "ok": False,
                 "detail": f"certificate does not match {host} ({err.verify_message}); use the name in the certificate"}]
    names = _chain_names(host, port)
    found = _keychain_ca_fix(host, port, names)
    if found:
        name, kc = found   # names come from the server's (not yet trusted) certificate: cleaned and shell-quoted
        slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()[:40] or "ca"
        return [{"check": check, "ok": False,
                 "detail": f"CA {hmlib.clean(name, 80)!r} is trusted in the macOS keychain ({kc}), but Python does not "
                           f"read the keychain. Export it and point ca_cert at it: mkdir -p ~/.config/homelab && "
                           f"security find-certificate -a -c {shlex.quote(name)} -p {kc} > ~/.config/homelab/{slug}.pem && "
                           f"python3 $HM/scripts/config_set.py '{where}.ca_cert=~/.config/homelab/{slug}.pem'"}]
    issuer = f" (issuer {hmlib.clean(names[0], 80)!r})" if names else ""
    return [{"check": check, "ok": False,
             "detail": f"certificate not trusted{issuer}: {err.verify_message}. Set {where}.ca_cert to the CA's PEM "
                       "(Proxmox's own CA: /etc/pve/pve-root-ca.pem on a node) rather than verify_tls: false: "
                       f"python3 $HM/scripts/config_set.py '{where}.ca_cert=~/.config/homelab/<ca>.pem'"}]


def token_expiry_row(check: str, tokens: dict[str, str], users: list, now: float,
                     days: int = TOKEN_EXPIRY_WARN_DAYS) -> dict:
    """One site's verdict on the skill's tokens ({kind: user@realm!tokenid}) from GET /access/users?full=1.
    Proxmox gives a token's `expire` (and its user's) but no creation time, so its age is unknown: a token without
    an expiry is a warning (rotation is up to the user), one expiring within `days` too, an expired one a failure."""
    listed = {}
    for u in users or []:
        if not isinstance(u, dict):
            continue
        for t in u.get("tokens") or []:
            if isinstance(t, dict) and t.get("tokenid"):
                ends = [int(x) for x in (t.get("expire"), u.get("expire")) if str(x or "").isdigit() and int(x) > 0]
                listed[f"{u.get('userid')}!{t['tokenid']}"] = min(ends) if ends else 0
    never, soon, gone, unknown, fine = [], [], [], [], []
    for tid in dict.fromkeys(tokens.values()):
        name = hmlib.clean(tid, 80)
        if tid not in listed:
            unknown.append(name)
        elif not listed[tid]:
            never.append(name)
        elif listed[tid] <= now:
            gone.append(name)
        elif listed[tid] - now <= days * 86400:
            soon.append(f"{name} in {max(1, int((listed[tid] - now) // 86400))} days")
        else:
            fine.append(f"{name} in {int((listed[tid] - now) // 86400)} days")
    parts = []
    if gone:
        parts.append(f"expired: {', '.join(gone)} — create a new token (docs/proxmox-tokens.md) and update its keychain item")
    if soon:
        parts.append(f"expiring: {', '.join(soon)} — rotate it before then (references/security.md \"Tokens\")")
    if never:
        parts.append(f"no expiry: {', '.join(never)} — give each one when you next rotate it "
                     "(pveum user token modify <user> <tokenid> --expire <epoch>, on a node)")
    if unknown:
        parts.append(f"not listed by Proxmox: {', '.join(unknown)} (removed, or the read-only token can't see its user)")
    if not parts:
        return {"check": check, "ok": True, "detail": "tokens expire: " + ", ".join(fine)}
    return {"check": check, "ok": False if gone else None, "detail": "; ".join(parts)}


def check_token_expiry(cfg, now: float | None = None, connect=None):
    """The skill's Proxmox tokens (read_only, provisioning) of every site: expired, expiring within
    TOKEN_EXPIRY_WARN_DAYS or without an expiry. One GET /access/users?full=1 per site with the read-only token
    (PVEAuditor: Sys.Audit); the token IDs come from the keychain values, never their secrets."""
    import time
    from proxmox_inventory import PVE, PveError
    if not cfg:
        return []
    try:
        targets = hmlib.proxmox_sites(cfg)
    except hmlib.ConfigError:
        return []   # reported by the TLS check
    now = time.time() if now is None else now
    connect = connect or (lambda px, token: PVE(hmlib.pick_endpoint(px), token, hmlib.proxmox_ssl_context(cfg, px)))
    out = []
    for px in targets:
        check = "proxmox:tokens" + (f":{px['_site']}" if px["_site"] and px["_where"] != "proxmox" else "")
        values = {}
        for kind in ("read_only", "provisioning"):
            try:
                values[kind] = hmlib.read_secret(cfg, hmlib.proxmox_token_name(px, kind))
            except hmlib.ConfigError:
                continue   # a missing or unreadable item is reported by its secret: row
        if "read_only" not in values:
            out.append({"check": check, "ok": None, "detail": "read-only token not readable: expiry not checked"})
            continue
        ids = {k: v.split("=", 1)[0] for k, v in values.items() if "!" in v.split("=", 1)[0]}
        try:
            users = connect(px, values["read_only"]).get("/access/users", full=1)
        except PveError as e:
            msg = hmlib.clean(str(e), 200)
            out.append({"check": check, "ok": False if "(401)" in msg else None, "detail": f"expiry not checked: {msg}"})
            continue
        except hmlib.ConfigError as e:
            out.append({"check": check, "ok": None, "detail": f"expiry not checked: {e}"})
            continue
        out.append(token_expiry_row(check, ids, users if isinstance(users, list) else [], now))
    return out


def check_tofu_sites(cfg):
    """Several sites: each site's OpenTofu environment refuses another site's token (site.tf), and the state
    settings keep the environments apart."""
    if not cfg or not hmlib.get(cfg, "components.proxmox", True):
        return []
    try:
        all_sites = hmlib.sites(cfg)
    except hmlib.ConfigError:
        return []    # check_proxmox_tls reports it
    if len(all_sites) < 2:
        return []
    root, out = Path(cfg["_root"]), []
    envs = root / "tofu" / "environments"
    for st in all_sites:
        env = hmlib.tofu_env(cfg, st["name"])
        check = f"tofu:{env}"
        d = envs / env
        if not d.is_dir():
            if not st["default"] and st["proxmox"]:
                out.append({"check": check, "ok": None, "detail": f"site {st['name']} has no OpenTofu environment yet "
                            f"(init_repo.py --add-site {st['name']} before provisioning there)"})
            continue
        f = d / "site.tf"
        want = f'var.proxmox_site == "{st["name"]}"'
        if not f.is_file() or want not in f.read_text(errors="replace"):
            out.append({"check": check, "ok": False,
                        "detail": f"tofu/environments/{env} doesn't check the token's site ({want} in site.tf): a "
                                  f"plan with another site's token would change that Proxmox — init_repo.py "
                                  f"--add-site {st['name'] if not st['default'] else all_sites[1]['name']} writes it"})
        else:
            out.append({"check": check, "ok": True, "detail": f"site {hmlib.site_title(st)}, token site checked"})
    kind = hmlib.get(cfg, "opentofu.state_backend", "local") or "local"
    key = {"local": "opentofu.local.path", "s3": "opentofu.s3.key"}.get(kind)
    fixed = str(hmlib.get(cfg, key) or "") if key else ""
    if fixed and "{env}" not in fixed and sum((envs / hmlib.tofu_env(cfg, s["name"])).is_dir() for s in all_sites) > 1:
        out.append({"check": "tofu:state", "ok": False,
                    "detail": f"{key} has no {{env}}: every site's environment would use one state. Put {{env}} in "
                              "it (moving the default environment's state is a -migrate-state, with a yes)"})
    return out


# Targets need a Python that the controller's ansible-core still supports. EL8 ships Python 3.6, which
# ansible-core 2.17 dropped: such hosts need e.g. python3.12 from AppStream and ansible_python_interpreter.
EL8_GROUP = re.compile(r"^(el|rhel|rocky|alma|almalinux|centos|centos_?stream|ol|oracle|oraclelinux)_?8$", re.I)


def ansible_core_version(text: str) -> tuple[int, ...]:
    m = re.search(r"core (\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else ()


def el8_without_interpreter(inventory: dict) -> list[str]:
    """Hosts in an EL8-named group (el8, rocky8, centos_stream8 …) with no ansible_python_interpreter."""
    hv = (inventory.get("_meta") or {}).get("hostvars") or {}
    out = set()

    def walk(group: str, el8: bool, seen: set):
        if group in seen:
            return
        seen.add(group)
        g = inventory.get(group) or {}
        el8 = el8 or bool(EL8_GROUP.match(group))
        if el8:
            out.update(h for h in g.get("hosts", []) if not (hv.get(h) or {}).get("ansible_python_interpreter"))
        for child in g.get("children", []):
            walk(child, el8, seen)

    walk("all", False, set())
    return sorted(out)


def site_group_problems(inventory: dict, cfg: dict) -> list[str]:
    """Hosts in several site_<name> groups, and site_<name> groups homelab.yaml has no site for."""
    def members(group: str, seen: set) -> set:
        g = inventory.get(group) or {}
        out = set(g.get("hosts") or [])
        for child in g.get("children") or []:
            if child not in seen:
                out |= members(child, seen | {child})
        return out
    try:
        known = {s["name"] for s in hmlib.sites(cfg) if s["name"]}
    except hmlib.ConfigError as e:
        return [str(e)]
    per_host: dict[str, list[str]] = {}
    problems = []
    for group in sorted(inventory):
        if not group.startswith(hmlib.SITE_GROUP_PREFIX):
            continue
        name = group[len(hmlib.SITE_GROUP_PREFIX):]
        if name not in known:
            problems.append(f"group {group}: homelab.yaml has no site {name!r} (sites:)")
        for h in members(group, {group}):
            per_host.setdefault(h, []).append(group)
    problems += [f"{h} is in several site groups ({', '.join(gs)})" for h, gs in sorted(per_host.items()) if len(gs) > 1]
    return problems



def managed_inventory(cfg) -> dict | None:
    """`ansible-inventory --list` of the managed inventory (once per run); None without Ansible or inventory."""
    root = Path(cfg["_root"]) if cfg else None
    if not root or not shutil.which("ansible") or not (root / "ansible" / "inventory" / "managed").exists():
        return None
    return hmlib.ansible_inventory(root)[0]


def check_site_ambiguity(cfg, inventory: dict | None = None):
    """Two or more sites: what "no site" makes ambiguous (untagged VLANs, hosts in no site group, overlapping
    ranges, clusters across sites — GitHub issue #63)."""
    if not cfg:
        return []
    try:
        inventory = managed_inventory(cfg) if inventory is None else inventory
        found = hmlib.site_ambiguities(cfg, hmlib.inventory_groups(inventory) if inventory else None)
    except hmlib.ConfigError:
        return []   # reported by check_config_and_secrets / proxmox TLS
    return [{"check": "sites:ambiguous", "ok": False, "detail": f} for f in found]


CERT_VARS = (("bmc_validate_certs", "BMC", "group_vars/bmc.yml"),
             ("unifi_validate_certs", "UniFi controller", "group_vars/unifi.yml"))


def unverified_cert_hosts(inventory: dict) -> dict[str, list[str]]:
    """{variable: hosts} for the Ansible variables that turn certificate checks off (BMCs, UniFi controllers)."""
    hv = (inventory.get("_meta") or {}).get("hostvars") or {}
    out = {}
    for var, _, _ in CERT_VARS:
        hosts = sorted(h for h, v in hv.items() if str((v or {}).get(var, "")).strip().lower() in ("false", "no", "0"))
        if hosts:
            out[var] = hosts
    return out


def check_ansible_targets(cfg):
    inventory = managed_inventory(cfg)
    if not inventory:
        return []
    out = []
    sites = site_group_problems(inventory, cfg)
    if sites:
        out.append({"check": "ansible:sites", "ok": False,
                    "detail": "; ".join(sites[:5]) + ("; …" if len(sites) > 5 else "")
                              + " — every host belongs to at most one site (references/proxmox.md, Several sites)"})
    _, so, _ = run(["ansible", "--version"])
    hosts = el8_without_interpreter(inventory) if ansible_core_version(so) >= (2, 17) else []
    if hosts:
        out.append({"check": "ansible:python", "ok": False,
                    "detail": f"{len(hosts)} EL8 host(s) without ansible_python_interpreter ({', '.join(hosts[:5])}"
                              f"{', …' if len(hosts) > 5 else ''}): ansible-core 2.17+ can't use EL8's Python 3.6. "
                              "Install python3.12 there and set ansible_python_interpreter: /usr/bin/python3.12 in the "
                              "group's group_vars (references/ansible.md, Onboarding existing hosts)"})
    off = unverified_cert_hosts(inventory)
    for var, what, where in CERT_VARS:
        if var in off:
            hosts = off[var]
            out.append({"check": f"ansible:{var}", "ok": None,
                        "detail": f"{var}: false for {len(hosts)} host(s) ({', '.join(hosts[:5])}"
                                  f"{', …' if len(hosts) > 5 else ''}) — the {what} certificate is not checked, so "
                                  "a device posing as it on the network would receive its credentials. Set it true "
                                  f"in {where} once the CA is trusted"})
    return out


def git_sync_status(ahead: int | None, behind: int | None, upstream: str | None, auto_push: bool):
    """Result for the repo's branch vs its upstream (counts as of the last fetch). None = nothing to say."""
    if not upstream:
        if not auto_push:
            return None
        return {"check": "git:upstream", "ok": False,
                "detail": "git.auto_push is true but the branch has no upstream: add a remote and push once with "
                          "`git push -u origin <branch>` (or set git.auto_push: false)"}
    if behind:
        return {"check": "git:upstream", "ok": False,
                "detail": f"{behind} commit(s) on {upstream} not in this clone: `git pull --ff-only` before changing "
                          "anything, or the next push is rejected"}
    if ahead:
        return {"check": "git:upstream", "ok": False if auto_push else None,
                "detail": f"{ahead} commit(s) not pushed to {upstream}: not backed up off this Mac — `git push`"
                          + ("" if auto_push else " (git.auto_push: true pushes after each verified commit)")}
    return {"check": "git:upstream", "ok": True, "detail": f"in sync with {upstream} (as of the last fetch)"}


def check_git_upstream(cfg):
    root = Path(cfg["_root"]) if cfg else None
    if not root or not shutil.which("git") or not (root / ".git").exists():
        return []
    auto_push = hmlib.get(cfg, "git.auto_push", False) is True
    rc, so, _ = run(["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], cwd=root)
    upstream = so.strip() if rc == 0 else None
    ahead = behind = None
    if upstream:
        rc, so, _ = run(["git", "rev-list", "--left-right", "--count", "HEAD...@{u}"], cwd=root)
        if rc == 0 and len(so.split()) == 2:
            ahead, behind = (int(x) for x in so.split())
    r = git_sync_status(ahead, behind, upstream, auto_push)
    return [r] if r else []


def main(argv):
    cfg_results, cfg = check_config_and_secrets()
    results = check_tools(cfg) + check_ssh_agent() + check_gh() + check_keychain_unlocked()
    if "--keychain" in argv:
        results += check_keychain_selftest()
    results += (cfg_results + check_proxmox_tls(cfg) + check_token_expiry(cfg) + check_tofu_sites(cfg)
                + check_ansible_targets(cfg)
                + check_site_ambiguity(cfg)
                + check_zabbix(cfg)
                + check_git_upstream(cfg))
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            mark = {True: "OK  ", False: "FAIL", None: "--  "}[r["ok"]]
            print(f"[{mark}] {r['check']:<22} {r['detail']}")
    return 1 if any(r["ok"] is False for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
