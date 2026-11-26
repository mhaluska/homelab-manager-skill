"""Shared helpers for homelab-manager scripts and the safety hook.

Standard library only (the Mac Mini's python3 has no third-party packages).
YAML is read through `yq`, which the skill installs as a prerequisite.
"""
from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse
from pathlib import Path

CONFIG_NAME = "homelab.yaml"
PLUGIN_ROOT = Path(__file__).resolve().parents[3]


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------- config

def find_repo_root(start: str | os.PathLike | None = None) -> Path | None:
    """Walk up from `start` to the first directory holding homelab.yaml."""
    p = Path(start or os.getcwd()).resolve()
    for d in [p, *p.parents]:
        if (d / CONFIG_NAME).is_file():
            return d
    return None


YQ_TIMEOUT = 20   # seconds for one yq call (the SessionStart hook has 20 s in all)


def yq_bin() -> str:
    """Path of yq: PATH first, then Homebrew's (a shell without /opt/homebrew/bin on PATH) (GitHub issue #119)."""
    yq = shutil.which("yq") or "/opt/homebrew/bin/yq"
    if not Path(yq).exists():
        raise ConfigError("yq is not installed (brew install yq).")
    return yq


def load_config(root: str | os.PathLike | None = None) -> dict:
    root = Path(root) if root else find_repo_root()
    if not root:
        raise ConfigError(f"No {CONFIG_NAME} found in this directory or its parents. "
                          "Initialise the repository first (init_repo.py).")
    res = subprocess.run([yq_bin(), "-o=json", ".", str(root / CONFIG_NAME)],
                         capture_output=True, text=True, timeout=YQ_TIMEOUT)
    if res.returncode != 0:
        raise ConfigError(f"{CONFIG_NAME} is not valid YAML: {res.stderr.strip()}")
    cfg = json.loads(res.stdout or "{}") or {}
    cfg["_root"] = str(root)
    # only for this plugin's scripts run as commands: hooks (guard.py) and imports in tests are not checked
    script = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else None
    level, msg = (plugin_version_check(cfg, script.name) if script and script.parent == Path(__file__).resolve().parent
                  else ("ok", ""))
    if level == "refuse":
        raise ConfigError(msg)
    if level == "warn":
        print(f"warning: {msg}", file=sys.stderr)
    return cfg


# Scripts that only read the repository (or act outside it): an older plugin version only warns (GitHub issue #111).
# issues.py stays usable so a problem with the old version can still be reported.
WARN_ONLY_SCRIPTS = {"check_env.py", "pve_node_plan.py", "pve_guest.py", "with_secrets.py", "tofu_init.py",
                     "issues.py", "upgrade_notes.py"}


def plugin_version() -> str:
    """The version of the plugin these scripts belong to (its .claude-plugin/plugin.json); '' when unreadable."""
    try:
        return str(json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text()).get("version") or "")
    except (OSError, ValueError):
        return ""


def _vtuple(v) -> tuple[int, ...] | None:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def plugin_version_check(cfg: dict, script: str, mine: str | None = None) -> tuple[str, str]:
    """('ok' | 'warn' | 'refuse', message): is this plugin version older than the one the repository was upgraded to
    (upgrades.reviewed)? Several installed versions sit side by side in the plugin cache, and a session that started
    on an old one keeps calling its scripts; one that writes repo files would undo the newer version's changes
    (GitHub issue #111). Scripts in WARN_ONLY_SCRIPTS only warn."""
    mine = plugin_version() if mine is None else mine
    reviewed = get(cfg, "upgrades.reviewed")
    a, b = _vtuple(mine), _vtuple(reviewed)
    if not a or not b or a >= b:
        return "ok", ""
    msg = (f"{script or 'this script'} is from homelab-manager {mine}, but this repository was upgraded to {reviewed} "
           f"(upgrades.reviewed in {CONFIG_NAME}). Run the {reviewed} (or newer) version's script: the plugin cache "
           f"keeps old versions, so call it by the current version's path. If the plugin was downgraded on purpose, "
           f"set upgrades.reviewed={mine} with config_set.py.")
    return ("warn" if script in WARN_ONLY_SCRIPTS else "refuse"), msg


def get(cfg: dict, dotted: str, default=None):
    cur = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur or cur[part] in (None, ""):
            return default
        cur = cur[part]
    return cur


# --------------------------------------------------------------------------- TLS

def proxmox_ca_file(cfg: dict, px: dict | None = None) -> str | None:
    """ca_cert of a Proxmox block (default: proxmox.*) as a usable path: ~ expanded, relative to the repo root."""
    px = default_proxmox(cfg) if px is None else px
    ca = px.get("ca_cert")
    if not ca:
        return None
    p = Path(os.path.expanduser(str(ca)))
    if not p.is_absolute() and cfg.get("_root"):
        p = Path(cfg["_root"]) / p
    return str(p)


def proxmox_ssl_context(cfg: dict, px: dict | None = None):
    """SSL context for a Proxmox API as homelab.yaml configures it (px: a site's block, default proxmox.*).

    Python (OpenSSL) does not read the macOS keychain: a CA trusted only there must be exported
    to a PEM file and set as proxmox.ca_cert (check_env.py detects this case).
    """
    import ssl
    px = default_proxmox(cfg) if px is None else px
    verify = px.get("verify_tls", True)
    if verify is False:
        return ssl._create_unverified_context()
    ca = proxmox_ca_file(cfg, px)
    if ca and not Path(ca).is_file():
        where = px.get("_where", "proxmox")
        raise ConfigError(f"{where}.ca_cert {ca!r} does not exist.")
    return ssl.create_default_context(cafile=ca)


# --------------------------------------------------------------------------- sites

# A site is a location (home, a rented server, family's house). `sites:` in homelab.yaml lists them, the default
# first: its Proxmox is the top-level `proxmox:` block or sites[0].proxmox (one of the two, GitHub issue #64); any
# other site may have its own (`sites[].proxmox`, same keys). Inventory hosts belong to a site through the
# Ansible group site_<name> (none: the default site).
# Without `sites:` there is one unnamed default site. A site other than the default may also have its own
# vmid_ranges, vmid_scheme and templates (build network); its OpenTofu environment is tofu/environments/<name>.
SITE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
SITE_GROUP_PREFIX = "site_"
SITE_SETTINGS = ("vmid_ranges", "vmid_scheme", "templates")
EVERY_SITE = "all"   # network.vlans site: all — a VLAN every site has, on purpose (GitHub issue #63)


def sites(cfg: dict) -> list[dict]:
    """[{name, label, default, proxmox (dict | None), ranges, _where}], the default site first; validates them."""
    raw = cfg.get("sites") or []
    if not isinstance(raw, list):
        raise ConfigError("sites must be a list of {name, label, proxmox, ranges}.")
    top = cfg.get("proxmox") if isinstance(cfg.get("proxmox"), dict) else {}
    if not raw:
        _check_vlan_sites(cfg, [])
        return [{"name": "", "label": "", "default": True, "proxmox": {**top, "_where": "proxmox"}, "ranges": [],
                 "settings": {}}]
    out, seen = [], set()
    for i, s in enumerate(raw):
        if not isinstance(s, dict) or not s.get("name"):
            raise ConfigError(f"sites[{i}] needs a name.")
        name = str(s["name"])
        if not SITE_NAME_RE.match(name):
            raise ConfigError(f"site name {name!r}: lowercase letters, digits and _, starting with a letter "
                              f"(it becomes the Ansible group {SITE_GROUP_PREFIX}{name}).")
        if name in seen:
            raise ConfigError(f"site {name!r} is listed twice.")
        if i > 0 and name == DEFAULT_SITE_KEY:
            raise ConfigError(f"site name {name!r} is reserved for the default site (discovery files keep a repo's "
                              "data under it before its default site has a name).")
        if name == EVERY_SITE:
            raise ConfigError(f"site name {name!r} is reserved (network.vlans site: {EVERY_SITE} = every site).")
        seen.add(name)
        own = i > 0 or s.get("proxmox") not in (None, {})
        if i == 0 and own and top.get("endpoint"):
            raise ConfigError(f"sites[0] ({name}) has a proxmox: block and so does the top level: describe the default "
                              "site's Proxmox in one of them (sites[0].proxmox, or the top-level proxmox: block). "
                              "Adding a second site? The existing one comes first: "
                              "init_repo.py --name-default-site <its name>, then sites+=….")
        px = s.get("proxmox") if own else top
        if px is not None and not isinstance(px, dict):
            raise ConfigError(f"sites.{name}.proxmox must be a mapping.")
        settings = {k: s[k] for k in SITE_SETTINGS if s.get(k) not in (None, "", {}, [])}
        if i == 0 and settings:
            raise ConfigError(f"sites[0] ({name}) is the default site: its {', '.join(settings)} are the top-level "
                              "keys, not sites[0].")
        if i > 0 and name == default_env(cfg):
            raise ConfigError(f"site name {name!r} is the default site's OpenTofu environment "
                              "(opentofu.environment): choose another name.")
        for k in ("vmid_ranges", "templates"):
            if k in settings and not isinstance(settings[k], dict):
                raise ConfigError(f"sites.{name}.{k} must be a mapping like the top-level {k}.")
        out.append({"name": name, "label": str(s.get("label") or ""), "default": i == 0,
                    "proxmox": {**px, "_where": f"sites[{name}].proxmox" if own else "proxmox"} if px else None,
                    "ranges": _networks(s.get("ranges")), "settings": settings})
    _check_vlan_sites(cfg, [s["name"] for s in out])
    return out


def _check_vlan_sites(cfg: dict, names: list[str]):
    for key in SITE_LISTS:   # {ip, site} entries (GitHub issue #66); ignore_unmanaged: {ip, name, mac, site?} (#100)
        for item in get(cfg, key, []) or []:
            if not isinstance(item, dict):
                continue
            site_needed = key != IGNORE_KEY
            st = str(item.get("site") or "")
            if not item.get("ip") or (site_needed and not st) or (st and st not in names):
                raise ConfigError(f"{key}: {item!r} needs ip and {'a' if site_needed else 'an optional'} site from "
                                  f"sites: ({', '.join(names) or 'none'}).")
            if item.get("name") and _RANGE_RE.match(str(item["ip"]).strip()):   # GitHub issue #124
                raise ConfigError(f"{key}: {item['name']!r} is one device: give it one address, not the range "
                                  f"{item['ip']} (list a range as a plain entry or {{ip, site}}).")
    for v in get(cfg, "network.vlans", []) or []:
        st = v.get("site") if isinstance(v, dict) else None
        if st not in (None, "", EVERY_SITE) and st not in names:
            raise ConfigError(f"network.vlans: VLAN {v.get('id')} has site {st!r}, which is not in sites: "
                              f"({', '.join(names) or 'none'}; {EVERY_SITE} = every site).")


def default_proxmox(cfg: dict) -> dict:
    """The default site's Proxmox block (top-level proxmox: or sites[0].proxmox), with `_where`; {} if none."""
    return sites(cfg)[0]["proxmox"] or {}


def config_value(cfg: dict, key: str, default=None):
    """get(), but proxmox.* is read from the default site's Proxmox block wherever homelab.yaml keeps it."""
    if key == "proxmox" or key.startswith("proxmox."):
        raw = cfg.get("sites")
        if isinstance(raw, list) and raw and isinstance(raw[0], dict) and isinstance(raw[0].get("proxmox"), dict) \
                and raw[0]["proxmox"]:
            return get({"proxmox": raw[0]["proxmox"]}, key, default)
    return get(cfg, key, default)


def site_config(cfg: dict, name: str | None = None) -> dict:
    """cfg as seen from one site: its own vmid_ranges / vmid_scheme / templates in place of the top-level ones."""
    s = site(cfg, name)
    out = dict(cfg)
    for k, v in s["settings"].items():
        out[k] = {**cfg[k], **v} if k == "templates" and isinstance(cfg.get(k), dict) else v
    return out


# Packer build settings under templates: (and sites[].templates), written into the site's pkrvars file (#158)
TEMPLATE_BUILD = {"sshd_hardening": (True, False), "unattended_updates": ("distro", "security", "off")}


def template_build_errors(cfg: dict) -> list[str]:
    """Values of templates.sshd_hardening / unattended_updates (top level or a site's) Packer would refuse."""
    where = [("templates", cfg.get("templates"))]
    raw = cfg.get("sites")
    for i, s in enumerate(raw if isinstance(raw, list) else []):
        if isinstance(s, dict):
            where.append((f"sites[{s.get('name') or i}].templates", s.get("templates")))
    out = []
    for prefix, tpl in where:
        for key, allowed in TEMPLATE_BUILD.items():
            v = tpl.get(key) if isinstance(tpl, dict) else None
            if v is None or v == "" or (type(v) is type(allowed[0]) and v in allowed):   # 1 is not true
                continue
            out.append(f"{prefix}.{key} must be {' or '.join(json.dumps(a) for a in allowed)}, not {json.dumps(v)}.")
    return out


def default_env(cfg: dict) -> str:
    return str(get(cfg, "opentofu.environment", "homelab") or "homelab")


def tofu_env(cfg: dict, name: str | None = None) -> str:
    """The OpenTofu environment of a site: opentofu.environment for the default site, the site name otherwise."""
    s = site(cfg, name)
    return default_env(cfg) if s["default"] else s["name"]


def site_of_env(cfg: dict, env: str | None) -> dict:
    """The site an OpenTofu environment belongs to: the site of that name, else the default site."""
    all_sites = sites(cfg)
    return next((s for s in all_sites[1:] if s["name"] == env), all_sites[0])


def site(cfg: dict, name: str | None = None) -> dict:
    """A site by name; None or '' is the default site."""
    all_sites = sites(cfg)
    if not name:
        return all_sites[0]
    for s in all_sites:
        if s["name"] == name:
            return s
    known = ", ".join(s["name"] for s in all_sites if s["name"]) or "none (no sites: in homelab.yaml)"
    raise ConfigError(f"no site {name!r} in homelab.yaml (sites: {known}).")


def site_title(s: dict) -> str:
    return (f"{s['name']} ({s['label']})" if s["label"] else s["name"]) or "default"


def endpoint_list(value) -> list[str]:
    """Proxmox API addresses in priority order (GitHub issue #98): `endpoint` is one URL, a comma-separated list of
    them, or a YAML list. Any node of a cluster serves the whole cluster's API."""
    items = value if isinstance(value, list) else str(value or "").split(",")
    return [str(x).strip() for x in items if str(x or "").strip()]


def proxmox_site(cfg: dict, name: str | None = None) -> dict:
    """The Proxmox block of a site, with `_site` (its name) and `_where` (its config path); endpoint required.
    `endpoints` lists every configured address; `endpoint` is the first (pick_endpoint chooses one that answers)."""
    s = site(cfg, name)
    px = s["proxmox"]
    eps = endpoint_list(px.get("endpoint")) if px else []
    if not eps:
        where = px["_where"] if px else f"sites[{s['name']}].proxmox"
        raise ConfigError(f"{where}.endpoint is empty in homelab.yaml"
                          + (f" (site {s['name']!r} has no Proxmox)." if not s["default"] else "."))
    for ep in eps:
        u = urllib.parse.urlsplit(ep)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ConfigError(f"{px['_where']}.endpoint: {ep!r} is not a URL like https://pve1.example:8006.")
        if u.scheme == "http" and px.get("allow_http") is not True:
            raise ConfigError(f"{px['_where']}.endpoint: {ep!r} is plain http, so the API token would cross the "
                              "network in clear text. Proxmox serves https on port 8006: use https://<host>:8006 "
                              f"(or set {px['_where']}.allow_http: true if a TLS proxy in front really needs it).")
    return {**px, "endpoint": eps[0], "endpoints": eps, "_site": s["name"]}


def endpoint_reachable(ep: str, timeout: float = 3.0) -> bool:
    u = urllib.parse.urlsplit(ep)
    try:
        with socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), timeout=timeout):
            return True
    except OSError:
        return False


def pick_endpoint(px: dict, reachable=None) -> str:
    """The first of a site's Proxmox addresses that accepts a connection (GitHub issue #98), checked only when
    there are several; when none answers, the first (its error is the one to report). Says on stderr when it is
    not the first. A refused token or certificate is not a reason to move on: every node would refuse it."""
    eps = px.get("endpoints") or endpoint_list(px.get("endpoint"))
    reachable = reachable or endpoint_reachable
    if len(eps) < 2:
        return eps[0] if eps else ""
    for i, ep in enumerate(eps):
        if reachable(ep):
            if i:
                site_name = px.get("_site")
                print(f"Proxmox{' ' + site_name if site_name else ''}: {', '.join(eps[:i])} not reachable, "
                      f"using {ep}", file=sys.stderr)
            return ep
    return eps[0]


UNREACHABLE = 4   # exit code: the check could not run (API or host unreachable, data missing), GitHub #156


def exit_main(main, *args) -> int:
    """Run a script's main(). An API error raised as a SystemExit with a message and an `hm_exit` code (PveError)
    prints the message and returns that code, not the 1 Python gives every message: 1 means "found something"."""
    try:
        return main(*args)
    except SystemExit as e:
        code = getattr(e, "hm_exit", None)
        if code is None or e.code is None or isinstance(e.code, int):
            raise
        print(e.code, file=sys.stderr)
        return code


def proxmox_sites(cfg: dict) -> list[dict]:
    """The Proxmox block of every site that has one with an endpoint."""
    return [proxmox_site(cfg, s["name"]) for s in sites(cfg) if s["proxmox"] and endpoint_list(s["proxmox"].get("endpoint"))]


# Storage a guest gets on a node (GitHub issue #54): proxmox.nodes.<node> replaces default_storage and
# lxc_storage on that node (lxc_storage falls back to the node's default_storage, never to a site-wide pool the
# node may not have); image_storage: the node's, else the site's. Mirrors defaults.node_datastores in OpenTofu.
STORAGE_ROLES = (("default_storage", "images", "VM disks"), ("lxc_storage", "rootdir", "LXC root filesystems"),
                 ("image_storage", None, "cloud images"))


def node_storages(px: dict) -> dict[str, dict]:
    """proxmox.nodes of one site's Proxmox block, validated: {node: {default_storage, lxc_storage, image_storage}}."""
    raw = px.get("nodes") or {}
    where = f"{px.get('_where') or 'proxmox'}.nodes"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping like {{pve3: {{default_storage: local-lvm}}}}.")
    for node, e in raw.items():
        if not isinstance(e, dict) or not e.get("default_storage"):
            raise ConfigError(f"{where}.{node} needs default_storage (it replaces the site's on that node).")
        extra = set(e) - {k for k, _, _ in STORAGE_ROLES}
        if extra:
            raise ConfigError(f"{where}.{node}: unknown key(s) {', '.join(sorted(extra))} "
                              f"(default_storage, lxc_storage, image_storage).")
    return raw


def node_storage(px: dict, node: str) -> dict[str, str]:
    """{default_storage, lxc_storage, image_storage} for guests on this node ('' = not configured)."""
    n = node_storages(px).get(node)
    base = n if n else px
    default = str(base.get("default_storage") or "")
    return {"default_storage": default,
            "lxc_storage": str(base.get("lxc_storage") or default),
            "image_storage": str((n or {}).get("image_storage") or px.get("image_storage") or default)}


def proxmox_token_name(px: dict, kind: str) -> str:
    """Secret name of a site's read_only / provisioning token (defaults as in the template)."""
    return ((px.get("tokens") or {}).get(kind)) or {"read_only": "proxmox-ro", "provisioning": "proxmox-rw"}[kind]


def site_of_secret(cfg: dict, secret: str) -> dict | None:
    """The Proxmox block of the site whose tokens name this secret (the default site first)."""
    for s in sites(cfg):
        px = s["proxmox"]
        if px and secret in [proxmox_token_name(px, k) for k in ("read_only", "provisioning")]:
            return {**px, "_site": s["name"]}
    return None


# Proxmox Backup Servers whose datastores proxmox_inventory.py reads (GitHub issue #151): `pbs:` in homelab.yaml,
# [{server, token, port, fingerprint, ca_cert, verify_tls}]. `server` is the address the Proxmox `pbs` storages give
# (a list when they name it several ways); `token` names a secret of kind pbs_token (DatastoreAudit, read-only).
PBS_KEYS = {"server", "token", "port", "fingerprint", "ca_cert", "verify_tls"}


def pbs_servers(cfg: dict) -> list[dict]:
    """pbs: entries, validated, each with `names` (its server names in lower case) and `_where`."""
    raw = get(cfg, "pbs", []) or []
    if not isinstance(raw, list):
        raise ConfigError("pbs must be a list of {server, token} (Proxmox Backup Servers, docs/proxmox-tokens.md).")
    out, seen = [], {}
    for i, e in enumerate(raw):
        where = f"pbs[{i}]"
        if not isinstance(e, dict) or not e.get("server") or not e.get("token"):
            raise ConfigError(f"{where} needs server (as the Proxmox pbs storage names it) and token (a secret name).")
        extra = set(e) - PBS_KEYS
        if extra:
            raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(extra))} ({', '.join(sorted(PBS_KEYS))}).")
        names = [str(x).strip().lower() for x in (e["server"] if isinstance(e["server"], list) else [e["server"]])]
        for n in names:
            if not n or "/" in n or " " in n:
                raise ConfigError(f"{where}.server: {n!r} is not a host name or address.")
            if n in seen:
                raise ConfigError(f"{where}.server: {n} is also in pbs[{seen[n]}].")
            seen[n] = i
        out.append({**e, "names": names, "_where": where})
    return out


def pbs_server(cfg: dict, server) -> dict | None:
    """The pbs: entry for a storage's server address (case-insensitive), or None."""
    name = str(server or "").strip().lower()
    return next((e for e in pbs_servers(cfg) if name in e["names"]), None)


# discovery/ (GitHub issue #75): one file per kind, never a site in its name. A file whose source is one site
# (proxmox, network, pve-patch, unifi) holds {"sites": {<site>: <that site's data>}}; files keyed by inventory host
# tag each host with its site. A repo without sites: keeps its data under "default".
DEFAULT_SITE_KEY = "default"
SITE_FILES = ("proxmox", "network", "pve-patch", "unifi")


def discovery_file(root: str | os.PathLike, kind: str) -> Path:
    """The discovery file of one kind (proxmox → discovery/proxmox.json)."""
    return Path(root, "discovery", kind + ".json")


def site_key(st: dict) -> str:
    """The key of site st in a per-site discovery file."""
    return st["name"] or DEFAULT_SITE_KEY


def site_parts(f: Path, rerun: str = "") -> dict:
    """{site key: data} of a per-site discovery file ({} when missing). A file from before 0.29.0 (no "sites"
    key) is the default site's data."""
    if not f.is_file():
        return {}
    try:
        doc = json.loads(f.read_text())
    except ValueError:
        raise ConfigError(f"{f.name} is not valid JSON" + (f": run {rerun} again." if rerun else "."))
    if not isinstance(doc, dict):
        raise ConfigError(f"{f.name} is not a JSON object.")
    if not isinstance(doc.get("sites"), dict):   # (unifi.json before 0.29.0 had a list of UniFi sites there)
        return {DEFAULT_SITE_KEY: doc} if doc else {}
    return doc["sites"]


def site_part(f: Path, st: dict, rerun: str = "") -> dict | None:
    """Site st's data in a per-site discovery file, or None. The default site also finds data kept under
    "default" from before it had a name."""
    parts = site_parts(f, rerun)
    if site_key(st) in parts:
        return parts[site_key(st)]
    return parts.get(DEFAULT_SITE_KEY) if st["default"] else None


def atomic_write(path, text: str) -> None:
    """Replace a file's content all at once: a temporary file in the same directory, then os.replace. An interrupted
    run leaves the old file whole instead of a truncated one. An existing file keeps its permissions."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


@contextlib.contextmanager
def file_lock(path):
    """Hold an exclusive lock for a read-modify-write of `path`, so two runs (one per site) don't lose each other's
    data. The lock file lives in the temporary directory, not in the repository."""
    import fcntl
    key = hashlib.sha1(str(Path(path).resolve()).encode()).hexdigest()[:16]
    with open(Path(tempfile.gettempdir()) / f"homelab-manager-{key}.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def write_site_part(f: Path, st: dict, data: dict, sort_keys: bool = False) -> None:
    """Store site st's data in a per-site discovery file; the other sites' data stays."""
    f.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(f):
        parts = site_parts(f)
        if st["default"]:
            parts.pop(DEFAULT_SITE_KEY, None)
        parts[site_key(st)] = data
        atomic_write(f, json.dumps({"sites": parts}, indent=2, sort_keys=sort_keys) + "\n")


def _snapshots(cfg: dict, kind: str, rerun: str) -> list[tuple[dict, dict]]:
    f = discovery_file(cfg["_root"], kind)
    out = []
    for s in sites(cfg):
        part = site_part(f, s, rerun)
        if part:
            out.append((s, part))
    return out


def proxmox_snapshot_file(root: str | os.PathLike) -> Path:
    """discovery/proxmox.json: every site's Proxmox snapshot."""
    return discovery_file(root, "proxmox")


def proxmox_snapshots(cfg: dict) -> list[tuple[dict, dict]]:
    """[(site, snapshot)] for every site with a snapshot in discovery/proxmox.json, the default site first."""
    return _snapshots(cfg, "proxmox", "proxmox_inventory.py")


def host_sites(groups) -> list[str]:
    """Site names of an inventory host from its site_<name> groups (normally zero or one)."""
    return sorted(g[len(SITE_GROUP_PREFIX):] for g in groups or [] if str(g).startswith(SITE_GROUP_PREFIX))


def inventory_groups(inventory: dict) -> dict[str, set[str]]:
    """{host: every group it is in, parents included} from `ansible-inventory --list` JSON."""
    parents: dict[str, set[str]] = {}
    out: dict[str, set[str]] = {}
    for group, g in inventory.items():
        if group == "_meta" or not isinstance(g, dict):
            continue
        for child in g.get("children") or []:
            parents.setdefault(child, set()).add(group)
        for h in g.get("hosts") or []:
            out.setdefault(h, set()).add(group)

    def up(group: str, seen: set) -> set:
        found = set()
        for p in parents.get(group, ()):
            if p not in seen:
                found |= {p} | up(p, seen | {p})
        return found
    for h, gs in out.items():
        for g in list(gs):
            gs |= up(g, {g})
        gs -= {"all", "ungrouped"}
    return out


def site_ambiguities(cfg: dict, host_groups: dict | None = None) -> list[str]:
    """With two or more sites, what "no site" makes ambiguous (GitHub issue #63): VLANs without a site, VLAN names
    used by several entries one of which is not tied to a site, overlapping site ranges, sites without ranges,
    inventory hosts in no site_<name> group and clusters across sites. host_groups: {host: all its groups}."""
    all_sites = sites(cfg)
    if len(all_sites) < 2:
        return []
    out = []
    default = all_sites[0]["name"]
    vl = [v for v in get(cfg, "network.vlans", []) or [] if isinstance(v, dict)]
    for v in vl:
        if v.get("site") in (None, ""):
            out.append(f"network.vlans: VLAN {v.get('id')}{' (' + str(v['name']) + ')' if v.get('name') else ''} has "
                       f"no site, so it applies to every site: tag it `site: <name>`, or `site: {EVERY_SITE}` if "
                       "every site has it")
    by_name: dict[str, list] = {}
    for v in vl:
        if v.get("name"):
            by_name.setdefault(str(v["name"]).lower(), []).append(v)
    for vs in by_name.values():
        if len(vs) > 1 and any(v.get("site") in (None, "", EVERY_SITE) for v in vs):
            out.append(f"network.vlans: the name {vs[0]['name']!r} is used by VLANs "
                       f"{', '.join(str(v.get('id')) for v in vs)} and not all of them name one site: "
                       f"`--vlan {vs[0]['name']}` is ambiguous at a site that has both")
    for i, a in enumerate(all_sites):
        for b in all_sites[i + 1:]:
            for na in a["ranges"]:
                for nb in b["ranges"]:
                    if na.version == nb.version and na.overlaps(nb):
                        out.append(f"sites: {a['name']} range {na} overlaps {b['name']} range {nb}: reports label an "
                                   f"address there as {a['name']}")
    for st in all_sites:
        if not st["ranges"]:
            out.append(f"sites: {st['name']} has no ranges, so reports don't label its addresses"
                       + (f" (init_repo.py --name-default-site {default} --steps ranges proposes them)"
                          if st["default"] else ""))
    shared = [(a["name"], b["name"], na, nb) for i, a in enumerate(all_sites) for b in all_sites[i + 1:]
              for na in a["ranges"] for nb in b["ranges"] if na.version == nb.version and na.overlaps(nb)]
    for key in SITE_LISTS:
        for item in get(cfg, key, []) or []:
            if isinstance(item, dict):
                if item.get("site") or not item.get("ip"):
                    continue
                item = item["ip"]
            for n in _networks([item], ranges=True):
                hit = next((x for x in shared if any(n.version == r.version and n.overlaps(r) for r in x[2:])), None)
                if hit:
                    out.append(f"{key}: {item} is in ranges sites {hit[0]} and {hit[1]} share, so it applies at both — "
                               f"name the site: {{ip: {item}, site: <name>}}")
    if host_groups is None:
        return out
    loose = sorted(h for h, gs in host_groups.items() if not host_sites(gs))
    if loose:
        out.append(f"{len(loose)} inventory host(s) in no site_<name> group, so counted as the default site "
                   f"{default}: {', '.join(loose[:8])}{', …' if len(loose) > 8 else ''} — put them in "
                   f"site_{default} (init_repo.py --name-default-site {default} --steps group) or their site's group")
    for c in get(cfg, "clusters", []) or []:
        g = c.get("ansible_group") if isinstance(c, dict) else None
        members = sorted(h for h, gs in host_groups.items() if g and g in gs)
        named = sorted({x for h in members for x in host_sites(host_groups[h])})
        nosite = [h for h in members if not host_sites(host_groups[h])]
        label = f"cluster {c.get('name') or g} (group {g})"
        if len(named) > 1:
            out.append(f"clusters: {label} spans sites {', '.join(named)}: a cluster should live at one site")
        if nosite and named:
            out.append(f"clusters: {label} has hosts in no site group ({', '.join(nosite[:5])}) next to hosts of "
                       f"site {', '.join(named)}")
    return out


def proposed_default_ranges(cfg: dict) -> list[str]:
    """Ranges for the default site (GitHub issue #65): network.authorized_ranges and the CIDRs of VLANs without a
    site or of the default site's own, without what another site's ranges cover, merged."""
    all_sites = sites(cfg)
    default = all_sites[0]["name"]
    others = [n for s in all_sites[1:] for n in s["ranges"]]
    cand = list(_networks(get(cfg, "network.authorized_ranges", [])))
    for v in get(cfg, "network.vlans", []) or []:
        if isinstance(v, dict) and v.get("cidr") and v.get("site") in (None, "", default):
            try:
                cand.append(ipaddress.ip_interface(str(v["cidr"]).strip()).network)
            except ValueError:
                continue
    cand = [n for n in cand if not any(n.version == o.version and n.overlaps(o) for o in others)]
    out = []
    for version in (4, 6):
        out += [str(n) for n in ipaddress.collapse_addresses(n for n in cand if n.version == version)]
    return out


def has_site_group(root: str | os.PathLike, name: str) -> bool:
    """Whether a file of the managed inventory defines the group site_<name>."""
    inv = Path(root) / "ansible" / "inventory" / "managed"
    rx = re.compile(rf"^\s+{re.escape(SITE_GROUP_PREFIX + name)}:", re.M)
    return any(rx.search(f.read_text(errors="replace")) for f in sorted(inv.glob("*.y*ml")) if f.is_file())


def default_site_gaps(cfg: dict, root: str | os.PathLike | None = None) -> list[str]:
    """What keeps the default site implicit (GitHub issue #65): 'name' (no sites:), 'ranges' (none), 'vlans'
    (VLANs without a site), 'group' (no site_<default> group in the managed inventory)."""
    raw = cfg.get("sites") or []
    gaps = [] if raw else ["name"]
    st = sites(cfg)[0]
    if not st["ranges"]:
        gaps.append("ranges")
    if any(isinstance(v, dict) and v.get("site") in (None, "") for v in get(cfg, "network.vlans", []) or []):
        gaps.append("vlans")
    inv = Path(root) / "ansible" / "inventory" / "managed" if root else None
    if inv and inv.is_dir() and not (st["name"] and has_site_group(root, st["name"])):
        gaps.append("group")
    return gaps


def site_of_address(cfg: dict, ip: str) -> dict | None:
    """The site whose `ranges` hold this address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((s for s in sites(cfg) if any(addr in n for n in s["ranges"])), None)


def literal(value):
    """An inventory value as given, or None when it is a Jinja template: ansible-inventory does not render them, so
    `{{ x | default(omit) }}` would otherwise be used verbatim (GitHub issue #101)."""
    return None if value is None or "{{" in str(value) or "{%" in str(value) else value


def accept_keys(raw) -> set[str]:
    """Finding keys from an accept list (routeros_audit_accept, security_audit_accept, …; GitHub issues #138, #139):
    a list of keys or one key, matched exactly and case-insensitive; Jinja templates and empty entries are dropped."""
    return {str(k).strip().lower() for k in ([raw] if isinstance(raw, str) else raw if isinstance(raw, list) else [])
            if literal(k) is not None and str(k).strip()}


_ANSIBLE: dict = {}


def _inventory_signature(inv: Path) -> tuple:
    return tuple(sorted((str(f), f.stat().st_mtime_ns, f.stat().st_size) for f in inv.rglob("*") if f.is_file()))


def ansible_inventory(root, timeout: int = 120) -> tuple[dict | None, str]:
    """(`ansible-inventory --list` JSON of ansible/inventory/managed, source note); (None, why) when it can't be read
    (no inventory, Ansible not installed, an error, a timeout, broken JSON). Read once per run while the inventory
    files stay the same."""
    root = Path(root)
    inv = root / "ansible" / "inventory" / "managed"
    if not inv.exists():
        return None, "no ansible/inventory/managed"
    key = (str(root.resolve()), _inventory_signature(inv))
    if key in _ANSIBLE:
        return _ANSIBLE[key]
    note = f"ansible-inventory ({inv.relative_to(root)})"
    try:
        r = subprocess.run(["ansible-inventory", "-i", str(inv), "--list"], cwd=root / "ansible",
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            out = (None, "ansible-inventory failed: " + clean((r.stderr.strip().splitlines() or ["?"])[-1], 200))
        else:
            out = (json.loads(r.stdout or "{}"), note)
    except FileNotFoundError:
        out = (None, "ansible-inventory is not installed")
    except subprocess.TimeoutExpired:
        out = (None, f"ansible-inventory did not finish in {timeout} s")
    except ValueError:
        out = (None, "ansible-inventory printed no valid JSON")
    _ANSIBLE[key] = out
    return out


def load_ansible(root) -> tuple[dict, str]:
    """({host: vars with "groups" and "_groups_all"}, source note) of the managed inventory; ({}, why) when it can't
    be read (see ansible_inventory)."""
    data, note = ansible_inventory(root)
    if data is None:
        return {}, note
    hv = (data.get("_meta") or {}).get("hostvars") or {}
    hosts: dict = {}
    for group, g in data.items():
        if group == "_meta" or not isinstance(g, dict):
            continue
        for h in g.get("hosts", []):
            hosts.setdefault(h, {"groups": [], **(hv.get(h) or {})})["groups"].append(group)
    for h, gs in inventory_groups(data).items():   # parent groups too (site_<name>: {children: …})
        if h in hosts:
            hosts[h]["_groups_all"] = sorted(gs)
    return hosts, note


def inventory_host(managed: dict, key: str) -> tuple[str, dict] | None:
    """(name, vars) of the managed-inventory host whose name or ansible_host is key (load_ansible)."""
    if key in managed:
        return key, managed[key]
    return next(((n, v) for n, v in managed.items() if str(v.get("ansible_host") or "") == key), None)


def target_site(cfg: dict, managed: dict, key: str) -> dict | None:
    """The site of a host given by inventory name or address (GitHub issues #82, #83): its inventory
    site_<name> group, else the site whose ranges hold its address; None when neither says."""
    found = inventory_host(managed, key)
    groups = (found[1].get("_groups_all") or found[1].get("groups")) if found else []
    named = [s for s in sites(cfg) if s["name"] and s["name"] in host_sites(groups)]
    if len(named) == 1:
        return named[0]
    return site_of_address(cfg, str((found[1].get("ansible_host") if found else None) or key))


# --------------------------------------------------------------------------- scan scope

def _networks(items, ranges: bool = False) -> list:
    """Networks of address entries: an IP or a CIDR; with ranges (excluded_hosts, ignore_unmanaged: GitHub issue
    #124) also a last-octet range a.b.c.x-y, as the CIDR blocks that cover exactly that range. Scan scope
    (authorized_ranges, site ranges) stays IPs and CIDRs."""
    nets = []
    for item in items or []:
        got = target_to_network(str(item)) if ranges else None
        if got is None:
            try:
                got = [ipaddress.ip_network(str(item).strip(), strict=False)]
            except ValueError:
                raise ConfigError(f"Invalid network in homelab.yaml: {item!r}"
                                  + (" (an IP, a CIDR or a range a.b.c.x-y)" if ranges else ""))
        nets += got
    return nets


IGNORE_KEY = "discovery.ignore_unmanaged"
SITE_LISTS = ("network.excluded_hosts", IGNORE_KEY)


def site_entries(cfg: dict, key: str, site_name: str | None = None) -> list:
    """Networks of an address list that may name sites (GitHub issue #66): a plain address applies at every site,
    {ip, site} only at that site. site_name None = the scan's site is unknown: every entry (never fewer)."""
    known = {s["name"] for s in sites(cfg) if s["name"]}
    out = []
    for item in get(cfg, key, []) or []:
        if isinstance(item, dict) and key == IGNORE_KEY and not item.get("site"):   # {ip, name, mac}: every site
            if not item.get("ip"):
                raise ConfigError(f"{key}: {item!r} needs ip ({{ip: 10.0.0.5, name: TV}}).")
            out += _networks([item["ip"]], ranges=True)
        elif isinstance(item, dict):
            st = str(item.get("site") or "")
            if not item.get("ip") or not st:
                raise ConfigError(f"{key}: {item!r} needs ip and site ({{ip: 10.0.0.5, site: <name>}}).")
            if st not in known:
                raise ConfigError(f"{key}: {item['ip']} has site {st!r}, which is not in sites: "
                                  f"({', '.join(sorted(known)) or 'none'}).")
            if site_name is not None and st != site_name:
                continue
            out += _networks([item["ip"]], ranges=True)
        else:
            out += _networks([item], ranges=True)
    return out


def known_devices(cfg: dict) -> list[dict]:
    """Named entries of discovery.ignore_unmanaged (GitHub issue #100): [{ip, name, mac, site}], site being the entry's
    site, else the site whose ranges hold the address, else the default site; mac lower-case or ''."""
    default = site(cfg)["name"]
    out = []
    for item in get(cfg, IGNORE_KEY, []) or []:
        if not isinstance(item, dict) or not item.get("name") or not item.get("ip"):
            continue
        ip = str(item["ip"])
        st = str(item.get("site") or "") or (site_of_address(cfg, ip.split("/")[0]) or {}).get("name") or default
        out.append({"ip": ip, "name": str(item["name"]), "mac": str(item.get("mac") or "").lower(), "site": st})
    return out


def ignored_address(cfg: dict, ip: str, site_name: str | None = None) -> bool:
    """ip is in discovery.ignore_unmanaged at site_name, in any form: a plain address or network, {ip, site} or
    {ip, name, mac} (GitHub issue #106: overview.py and drift_report.py agree)."""
    try:
        addr = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return False
    return any(addr in n for n in site_entries(cfg, IGNORE_KEY, site_name) if n.version == addr.version)


def routeros_addresses(cfg: dict, managed: dict | None = None) -> list[dict]:
    """Every address of an audited RouterOS device (discovery/routeros.json: the audited address and each interface
    address) as [{ip, name, site}] (GitHub issue #106): name is the inventory host, else the identity; site the one
    the audit recorded, else the inventory host's, else the site whose ranges hold the address, else the default."""
    try:
        devs = json.loads(discovery_file(cfg["_root"], "routeros").read_text()).get("devices") or {}
    except (OSError, ValueError, AttributeError):
        return []
    default, out = site(cfg)["name"], []
    for host, d in sorted(devs.items()):
        if not isinstance(d, dict):
            continue
        inv = inventory_host(managed or {}, host)
        name = inv[0] if inv else (d.get("identity") or {}).get("name") or host
        st = (d.get("site") or ((target_site(cfg, managed or {}, host) or {}).get("name") if inv else None)
              or (site_of_address(cfg, host) or {}).get("name") or default)
        seen = set()
        for a in [host] + [x.get("address") for x in d.get("addresses") or [] if isinstance(x, dict)]:
            ip = str(a or "").split("/")[0].strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                out.append({"ip": ip, "name": str(name), "site": st})
    return out


def dst_nat_rules(device: dict) -> list[dict]:
    """The enabled dst-nat (port forward) rules of a routeros.json device (overview.py, security_audit.py)."""
    return [r for r in device.get("nat") or [] if isinstance(r, dict) and r.get("chain") == "dstnat"
            and r.get("action") in ("dst-nat", "netmap") and "X" not in str(r.get("_flags") or "")
            and r.get("disabled") not in ("yes", "true")]


def nat_ports(value, limit: int = 1024) -> set[int] | None:
    """The ports of a RouterOS port list ("80,443,8000-8010"), None when it is empty (every port). A range is cut at
    limit ports; a negated list ("!22") is every port."""
    text = str(value or "").replace(" ", "")
    if not text or text.startswith("!"):
        return None
    out: set[int] = set()
    for part in text.split(","):
        a, _, b = part.partition("-")
        if a.isdigit() and (b.isdigit() or not b):
            lo, hi = int(a), int(b or a)
            out.update(range(lo, min(hi, lo + limit - 1) + 1))
    return out


def scan_scope(cfg: dict, site_name: str | None = None) -> tuple[list, list]:
    """(authorized ranges, excluded networks) for a scan at site_name; None: every site's exclusions."""
    allowed = _networks(get(cfg, "network.authorized_ranges", []))
    excluded = site_entries(cfg, "network.excluded_hosts", site_name)
    return allowed, excluded


def network_file(root: str | os.PathLike) -> Path:
    """discovery/network.json: every site's scan results (GitHub #72, #75)."""
    return discovery_file(root, "network")


def scan_site(cfg: dict, name: str | None) -> dict | None:
    """The site a scan runs at (--site), or None when not given."""
    return site(cfg, name) if name else None


def network_snapshots(cfg: dict) -> list[tuple[dict, dict]]:
    """[(site, network db)] for every site with scan results in discovery/network.json, the default site first."""
    return _snapshots(cfg, "network", "nmap_scan.py")


def outside_site(cfg: dict, st: dict, targets: list[str]) -> list[str]:
    """Targets not inside the ranges of site st (a warning: the scan may be at another site)."""
    if not st or not st["ranges"]:
        return []
    out = []
    for t in targets:
        nets = target_to_network(t) or []
        if nets and not all(any(n.version == r.version and n.subnet_of(r) for r in st["ranges"]) for n in nets):
            out.append(t)
    return out


def site_scan_ranges(cfg: dict, name: str) -> tuple[list[str], list[str]]:
    """(targets, skipped) for `nmap_scan.py --site name` without targets (GitHub issue #118): the site's ranges
    clipped to network.authorized_ranges — a range only partly authorized gives its authorized parts — and the
    site ranges (or parts) left out. The only site of a repo may have no ranges: it scans every authorized range
    (GitHub issue #125). Raises ConfigError for an unknown site, or one with no ranges next to other sites."""
    st = site(cfg, name)
    allowed, _ = scan_scope(cfg)
    outer = lambda nets: [n for n in nets if not any(o != n and o.version == n.version and n.subnet_of(o)
                                                     for o in nets)]
    if not st["ranges"]:
        if len(sites(cfg)) > 1:
            raise ConfigError(f"site {site_title(st)} has no ranges in homelab.yaml (with several sites, "
                              "network.authorized_ranges also holds the other sites' networks): give the scan "
                              "targets, or set the site's ranges.")
    keep, skipped = ([] if st["ranges"] else list(allowed)), []
    for r in st["ranges"]:
        if any(r.version == a.version and r.subnet_of(a) for a in allowed):
            keep.append(r)
            continue
        parts = outer(list(dict.fromkeys(a for a in allowed if r.version == a.version and a.subnet_of(r))))
        keep += parts
        if sum(n.num_addresses for n in parts) < r.num_addresses:
            skipped.append(f"{r} (scanning only {', '.join(map(str, parts))})" if parts else str(r))
    # no merging of neighbours: each target must stay inside one authorized range for check_targets and the guard
    return [str(n) for n in sorted(outer(list(dict.fromkeys(keep))), key=lambda n: (n.version, n))], skipped


_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


def target_to_network(target: str):
    """Turn an nmap target (IP, CIDR, or last-octet range a.b.c.x-y) into a network.

    Returns None for anything else (hostnames, wildcards, complex ranges): those
    are refused because they cannot be checked against the authorized ranges.
    """
    t = target.strip()
    m = _RANGE_RE.match(t)
    if m:
        lo, hi = int(m.group(2)), int(m.group(3))
        if lo > hi or hi > 255:
            return None
        first = ipaddress.ip_address(m.group(1) + str(lo))
        last = ipaddress.ip_address(m.group(1) + str(hi))
        return list(ipaddress.summarize_address_range(first, last))
    try:
        return [ipaddress.ip_network(t, strict=False)]
    except ValueError:
        return None


def check_targets(targets: list[str], cfg: dict) -> list[str]:
    """Return a list of problems; empty list means every target is in scope."""
    allowed, _ = scan_scope(cfg)
    if not allowed:
        return ["network.authorized_ranges in homelab.yaml is empty — nothing is authorized for scanning."]
    problems = []
    for t in targets:
        nets = target_to_network(t)
        if nets is None:
            problems.append(f"{t!r} is not an IP, CIDR or a.b.c.x-y range (hostnames are refused: they cannot be checked against the authorized ranges).")
            continue
        for n in nets:
            if not any(n.version == a.version and n.subnet_of(a) for a in allowed):
                problems.append(f"{t} is outside the authorized ranges ({', '.join(map(str, allowed))}).")
                break
    return problems


# --------------------------------------------------------------------------- secrets

def secret_entry(cfg: dict, name: str) -> dict:
    entry = get(cfg, f"secrets.{name}")
    if not isinstance(entry, dict) or not entry.get("service"):
        raise ConfigError(f"Secret {name!r} is not defined under `secrets:` in homelab.yaml.")
    return entry


def keychain_read(service: str, account: str | None = None, timeout: int = 15) -> str:
    """Read a generic password from the login keychain. Never log the value."""
    cmd = ["/usr/bin/security", "find-generic-password", *(["-a", account] if account else []), "-s", service, "-w"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ConfigError(f"Keychain read of {service!r} timed out — the keychain is probably locked or "
                          "showing an access prompt on the Mac's screen. Run check_env.py --keychain.")
    if res.returncode != 0:
        raise ConfigError(f"Keychain item {service!r} not readable (exit {res.returncode}). "
                          "Create it with: security add-generic-password -U -T /usr/bin/security "
                          f"-a \"$USER\" -s {service} -w")
    return res.stdout.rstrip("\n")


def read_secret(cfg: dict, name: str) -> str:
    e = secret_entry(cfg, name)
    return keychain_read(e["service"], e.get("account") or os.environ.get("USER"))


def secret_forms(secret: str) -> list[str]:
    """A secret as it may appear in output: itself, URL-encoded, JSON-escaped, hex and base64 (whole, and the
    prefix that stays the same whatever follows it, e.g. `echo "$T" | base64`). Longest first."""
    import base64
    raw = secret.encode()
    forms = {secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret), json.dumps(secret)[1:-1],
             raw.hex(), raw.hex().upper()}
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        whole = enc(raw).decode()
        forms |= {whole, whole.rstrip("=")}
        stable = enc(raw[:len(raw) // 3 * 3]).decode()
        if len(stable) >= 8:
            forms.add(stable)
    return sorted((f for f in forms if len(f) >= 4), key=len, reverse=True)


def redact(text: str, secrets: list[str]) -> str:
    """Best effort: replaces the forms in secret_forms(). A command can still transform a secret some other way;
    the guard hook limits which commands with_secrets.py may start without asking."""
    for s in secrets:
        if s and len(s) >= 4:
            for form in secret_forms(s):
                text = text.replace(form, "***REDACTED***")
    return text


# --------------------------------------------------------------------------- ssh

# Options for every ssh the scripts start: a host reached on an authorized network may still be hostile, so nothing
# of this Mac's is forwarded to it (an agent forwarded by a `Host *` ForwardAgent yes would let it use the keys)
# and no password is ever offered.
SSH_SAFE_OPTS = ["-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
                 "-o", "PermitLocalCommand=no", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]


def ssh_host(value) -> str:
    """A host name or address for ssh's command line; ValueError for one ssh would read as an option or split."""
    h = str(value or "").strip()
    if not h or h.startswith("-") or any(c.isspace() or ord(c) < 32 for c in h):
        raise ValueError(f"{str(value)[:80]!r} is not a host name or address for ssh")
    return h


def ssh_bin() -> str:
    return shutil.which("ssh") or "/usr/bin/ssh"


def ssh_cmd(host, command: list[str], user: str | None = None, port=None, timeout: int = 10,
            options: list[str] = ()) -> list[str]:
    """The argv of a non-interactive ssh the scripts run: no pty, agent keys only (BatchMode, never a password), no
    connection sharing, nothing forwarded (SSH_SAFE_OPTS), the host after `--`. ValueError for a host ssh would
    misread (ssh_host). `options` go before the safe ones (e.g. a known_hosts file)."""
    return [ssh_bin(), "-T", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", *options,
            "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "LogLevel=ERROR", *SSH_SAFE_OPTS,
            *(["-p", str(port)] if port else []), *(["-l", user] if user else []), "--", ssh_host(host), *command]


def ssh_config(host, port=None, user: str | None = None) -> dict[str, list[str]] | None:
    """What ssh would use for host (`ssh -G`, which reads the config and connects to nothing): {lower-case option:
    [values]}; None when it can't tell."""
    try:
        r = subprocess.run([ssh_bin(), "-G", *(["-p", str(port)] if port else []), *(["-l", user] if user else []),
                            "--", ssh_host(host)], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    opts: dict[str, list[str]] = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(" ")
        opts.setdefault(k.lower(), []).append(v.strip())
    return opts


# --------------------------------------------------------------------------- untrusted data

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# Unicode categories that render as nothing or reorder text: format (zero-width, bidirectional overrides), private
# use, surrogates, line and paragraph separators
_INVISIBLE = {"Cf", "Co", "Cs", "Zl", "Zp"}


def clean(value, limit: int | None = 200):
    """Sanitise strings that come from the network (banners, hostnames, VM notes).

    They are data, not instructions: strip control characters and characters that are invisible or reorder text,
    and cap the length so a hostile banner can't smuggle a wall of text (or hidden text) into the conversation.
    limit=None: no cap (text Claude wrote itself, such as a skill issue's body; GitHub issue #167).
    """
    if value is None:
        return None
    s = _CTRL.sub("", str(value))
    if not s.isascii():
        s = "".join(c for c in s if unicodedata.category(c) not in _INVISIBLE)
    return s if limit is None or len(s) <= limit else s[:limit] + "…"


def id_list(value):
    """A Proxmox ID list ("100,101, 102") as ints; never length-capped (GitHub issue #41).

    None or "" → []; anything that isn't digits and commas → None (unknown, don't trust it).
    """
    if value is None or value == "":
        return []
    if isinstance(value, list):
        value = ",".join(str(x) for x in value)
    s = re.sub(r"\s+", "", str(value))
    if not s:
        return []
    if not re.fullmatch(r"\d+(,\d+)*", s):
        return None
    return [int(x) for x in s.split(",")]


# ---- VMIDs -------------------------------------------------------------------------------------
# vmid_ranges hand out the next free ID; vmid_scheme (optional) derives a guest's ID from its
# network instead, for sites whose IDs encode meaning, e.g. "{vlan}{octet:03d}" → 1020015 for
# VLAN 1020, x.x.x.15. Placeholders: vlan, octet (last IP octet), o1–o4 (the IP's octets).
SCHEME_CANDIDATES = ["{vlan}{octet:03d}", "{vlan}{octet}", "{o3}{octet:03d}", "{vlan}{o3:03d}{octet:03d}"]
VMID_MIN, VMID_MAX = 100, 999_999_999


def vmid_from_scheme(scheme: str, ip: str | None, vlan: int | str | None) -> int:
    if not ip and re.search(r"\{(octet|o\d)", scheme):
        raise ConfigError(f"vmid_scheme {scheme!r} needs the guest's static IP (--ip).")
    if vlan in (None, "") and "{vlan" in scheme:
        raise ConfigError(f"vmid_scheme {scheme!r} needs the guest's VLAN tag (--vlan).")
    try:
        o = [int(x) for x in str(ip or "0.0.0.0").split("/")[0].split(".")]
        vmid = int(scheme.format(vlan=int(vlan or 0), octet=o[3], o1=o[0], o2=o[1], o3=o[2], o4=o[3]))
    except (ValueError, IndexError, KeyError) as e:
        raise ConfigError(f"vmid_scheme {scheme!r} can't be applied to ip={ip} vlan={vlan}: {e}")
    if not VMID_MIN <= vmid <= VMID_MAX:
        raise ConfigError(f"vmid_scheme gives {vmid}, outside Proxmox's VMID range {VMID_MIN}–{VMID_MAX}.")
    return vmid


def next_vmid(cfg: dict, kind: str, used: dict[int, str], ip: str | None = None, vlan=None) -> int:
    """The VMID for a new guest of `kind` (vms, lxc, templates, base_images). `used`: {vmid: name}."""
    scheme = get(cfg, "vmid_scheme")
    if scheme and kind in ("vms", "lxc"):
        vmid = vmid_from_scheme(scheme, ip, vlan)
        if vmid in used:
            raise ConfigError(f"VMID {vmid} (vmid_scheme {scheme!r}) is already used by {used[vmid]}.")
        return vmid
    rng = get(cfg, f"vmid_ranges.{kind}")
    if not (isinstance(rng, list) and len(rng) == 2):
        raise ConfigError(f"vmid_ranges.{kind} is not set in homelab.yaml.")
    free = next((i for i in range(int(rng[0]), int(rng[1]) + 1) if i not in used), None)
    if free is None:
        raise ConfigError(f"vmid_ranges.{kind} {rng} is full.")
    return free


# interfaces whose addresses are no way to reach the guest: tunnels, container and VM bridges, overlays
VIRTUAL_IFACE_RE = re.compile(r"^(lo|wg|tun|tap|docker|br-|veth|virbr|cni|flannel|cali|vxlan|kube|tailscale|zt"
                              r"|podman|lxc|lxd|incus|nebula|ppp)", re.I)
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def guest_nic_addresses(g: dict) -> list[dict]:
    """Every address of a guest's snapshot (--details), one {ip, source, iface, mac} each, in the order found:
    static addresses from its config (LXC `ip=`, VM cloud-init `ipconfigN`), then reported ones (guest agent,
    LXC interfaces). A config address carries its NIC's name and MAC where the config names them."""
    out, seen = [], set()
    conf = g.get("config") or {}
    for k in sorted(conf, key=lambda k: (re.sub(r"\d+$", "", k), int(re.search(r"(\d*)$", k).group(1) or 0))):
        v = str(conf[k])
        if not k.startswith(("net", "ipconfig")):
            continue
        nic = conf.get("net" + k[len("ipconfig"):]) if k.startswith("ipconfig") else v
        mac = _MAC_RE.search(str(nic or ""))
        name = re.search(r"(?<![\w])name=([^,]+)", str(nic or ""))
        for ip in re.findall(r"(?<![\w])ip6?=([^,/\s]+)", v):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue    # dhcp, auto, manual (an earlier pattern took ip=dhcp for the address "d")
            if ip.lower() not in seen:
                seen.add(ip.lower())
                out.append({"ip": ip.lower(), "source": "config", "iface": name.group(1) if name else "",
                            "mac": mac.group(0).lower() if mac else ""})
    for a in g.get("ips") or []:
        ip = str(a.get("ip") or "").lower()
        if ip and ip not in seen:
            seen.add(ip)
            out.append({"ip": ip, "source": a.get("source") or "agent", "iface": str(a.get("iface") or ""),
                        "mac": str(a.get("mac") or "").lower()})
    return out


def rank_guest_addresses(g: dict, ranges: list | None = None) -> list[dict]:
    """guest_nic_addresses, the best way to reach the guest first (GitHub issue #56): on a NIC of the guest's
    Proxmox config (a config address, or a reported one whose MAC is a netN MAC), inside `ranges` (e.g. the
    site's ranges and authorized_ranges), not on a tunnel/bridge/container interface or a zero MAC, IPv4,
    a config address, then the order found. Loopback, link-local, multicast and unparsable addresses are left out."""
    nic_macs = {m.lower() for k, v in (g.get("config") or {}).items() if k.startswith("net")
                for m in _MAC_RE.findall(str(v))}
    ranked = []
    for i, a in enumerate(guest_nic_addresses(g)):
        try:
            addr = ipaddress.ip_address(a["ip"])
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            continue
        on_nic = a["source"] == "config" or (a["mac"] and a["mac"] in nic_macs)
        in_ranges = not ranges or any(addr in n for n in ranges if n.version == addr.version)
        virtual = bool(VIRTUAL_IFACE_RE.match(a["iface"])) or (a["source"] != "config"
                                                                and a["mac"] in ("", "00:00:00:00:00:00"))
        ranked.append(((not on_nic, not in_ranges, virtual, addr.version != 4, a["source"] != "config", i), a))
    return [a for _, a in sorted(ranked, key=lambda x: x[0])]


def guest_nics(g: dict) -> list[dict]:
    """A guest's NICs from its snapshot config (--details) in netN order (net2 before net10), each
    {idx, tag, bridge, mac, ips}: ips are the NIC's static IPv4/IPv6 (LXC `ip=`, VM `ipconfigN`) and the addresses the
    guest agent / LXC interfaces report for its MAC (GitHub issue #97: VLAN and IP of the same NIC)."""
    conf = g.get("config") or {}
    nics = []
    for k in sorted((k for k in conf if re.fullmatch(r"net\d+", k)), key=lambda k: int(k[3:])):
        v, idx = str(conf[k]), int(k[3:])
        mac = _MAC_RE.search(v)
        tag = re.search(r"(?<![\w-])tag=(\d+)", v)
        bridge = re.search(r"(?<![\w-])bridge=([^,\s]+)", v)
        ips = re.findall(r"(?<![\w])ip6?=([0-9A-Fa-f.:]+)(?:/\d+)?", v)
        ips += re.findall(r"(?<![\w])ip6?=([0-9A-Fa-f.:]+)(?:/\d+)?", str(conf.get(f"ipconfig{idx}") or ""))
        nics.append({"idx": idx, "tag": int(tag.group(1)) if tag else None, "bridge": bridge.group(1) if bridge else "",
                     "mac": mac.group(0).lower() if mac else "", "ips": [i.lower() for i in ips]})
    for a in g.get("ips") or []:
        ip, mac = str(a.get("ip") or "").lower(), str(a.get("mac") or "").lower()
        for n in nics:
            if mac and n["mac"] == mac and ip and ip not in n["ips"]:
                n["ips"].append(ip)
    return nics


def _guest_net(g: dict, prefer_ip: str | None = None) -> tuple[str | None, int | None]:
    """(IPv4, VLAN tag) of one NIC of a guest, from its snapshot config (--details): the NIC holding prefer_ip
    (e.g. its ansible_host), else the first NIC (netN order) with an IPv4, else the first NIC's tag with the best
    reported address (rank_guest_addresses). Never a VLAN of one NIC with the IP of another (GitHub issue #97)."""
    nics = guest_nics(g)
    v4 = re.compile(r"\d+\.\d+\.\d+\.\d+")
    if prefer_ip:
        n = next((n for n in nics if prefer_ip in n["ips"]), None)
        if n:
            return prefer_ip, n["tag"]
    for n in nics:
        ip = next((i for i in n["ips"] if v4.fullmatch(i)), None)
        if ip:
            return ip, n["tag"]
    ip = next((a["ip"] for a in rank_guest_addresses(g) if v4.fullmatch(a["ip"])), None)
    return ip, (nics[0]["tag"] if nics else None)


def vmid_fit(cfg: dict, guests: list[dict]) -> str | None:
    """A warning when the site's existing VMIDs don't follow vmid_ranges / vmid_scheme, with a
    scheme suggestion when one explains most guests. None when they fit (or too few guests)."""
    guests = [g for g in guests if isinstance(g.get("vmid"), int)]
    if len(guests) < 3:
        return None
    scheme = get(cfg, "vmid_scheme")
    nets = {g["vmid"]: _guest_net(g) for g in guests if not g.get("template")}

    def explained(s):
        ok = n = 0
        for vmid, (ip, vlan) in nets.items():
            if ip and (vlan is not None or "{vlan" not in s):
                n += 1
                try:
                    ok += vmid_from_scheme(s, ip, vlan) == vmid
                except ConfigError:
                    pass
        return ok, n

    if scheme:
        ok, n = explained(scheme)
        if n and ok * 2 < n:
            return (f"Only {ok} of {n} guests with a known IP follow vmid_scheme {scheme!r}. "
                    "Check the scheme in homelab.yaml before creating guests.")
        return None
    ranges = [r for r in (get(cfg, "vmid_ranges") or {}).values() if isinstance(r, list) and len(r) == 2]
    outside = [g["vmid"] for g in guests if not any(int(a) <= g["vmid"] <= int(b) for a, b in ranges)]
    if not ranges or len(outside) * 2 <= len(guests):
        return None
    msg = (f"{len(outside)} of {len(guests)} existing guests have VMIDs outside vmid_ranges "
           f"(e.g. {', '.join(map(str, sorted(outside)[:3]))}): new IDs from the ranges would break your convention.")
    best = max(((explained(s), s) for s in SCHEME_CANDIDATES), key=lambda x: x[0][0])
    (ok, n), s = best
    if n and ok * 2 > n:
        return (msg + f" {ok} of {n} guests with a known IP and VLAN match vmid_scheme {s!r}: "
                f"set it with config_set.py 'vmid_scheme={s}'.")
    return msg + " Set vmid_scheme (e.g. \"{vlan}{octet:03d}\") or adjust vmid_ranges in homelab.yaml."


# --------------------------------------------------------------------------- language

LANGUAGE_CODE_RE = re.compile(r"[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8}){0,2}|[^\W\d_]{2,20}")


def language_code(value) -> str | None:
    """site.language when it is a language code (sk, pt-BR, zh-Hant-TW) or one word naming a language (Slovak),
    else None. The session-start hook puts it into Claude's context, so free text there is never used."""
    v = str(value).strip() if value is not None else ""
    return v if LANGUAGE_CODE_RE.fullmatch(v) else None


# Text that goes to the plugin's GitHub repository (skill issues, pull requests, code) must be English.
# The user's homelab repo may use another language (site.language); this check is only for the plugin side.
LANGUAGE_WORDS = PLUGIN_ROOT / "skills" / "homelab-manager" / "assets" / "language-words.json"
_CODE_RE = re.compile(r"```.*?(```|\Z)|~~~.*?(~~~|\Z)|`[^`\n]*`|<!--.*?-->|<[^<>\s]{1,60}>|https?://\S+", re.S)
_WORD_RE = re.compile(r"[a-z]+(?:'[a-z]+)?")
_words_cache: dict[str, frozenset] = {}


def _language_words() -> dict[str, frozenset]:
    if not _words_cache:
        data = json.loads(LANGUAGE_WORDS.read_text())
        _words_cache.update(english=frozenset(data["english"]), foreign=frozenset(data["foreign"]))
    return _words_cache


def prose_words(text: str) -> list[str]:
    """Lower-cased plain words of `text` outside code, URLs and <placeholders>. Tokens that look like code
    (snake_case, dotted names, paths, flags, numbers, CamelCase) are skipped."""
    out = []
    for tok in _CODE_RE.sub(" ", text).split():
        tok = tok.strip(".,;:!?()[]{}\"'*_#>|")
        if tok and tok.isascii() and not re.search(r"[^A-Za-z']", tok) and not re.search(r"[a-z][A-Z]", tok):
            if _WORD_RE.fullmatch(tok.lower()):
                out.append(tok.lower())
    return out


def non_english_letters(text: str) -> list[str]:
    """Words outside code that contain letters beyond ASCII (diacritics, Cyrillic, CJK, …).
    Typographic characters such as — → … are not letters and don't count."""
    found = []
    for tok in _CODE_RE.sub(" ", text).split():
        if any(ord(c) > 127 and c.isalpha() for c in tok):
            w = tok.strip(".,;:!?()[]{}\"'*_#>|—–…“”‘’«»„")
            if w not in found:
                found.append(w)
    return found


def english_problems(text: str, min_words: int = 12) -> list[str]:
    """Why `text` doesn't look English; [] when it does (or is too short to judge).
    Heuristic: no letters outside ASCII, and among plain words, more common English function words than
    function words of other languages; a longer text must have some English function words at all."""
    problems = []
    letters = non_english_letters(text)
    if letters:
        problems.append("letters outside English: " + ", ".join(letters[:8]) + (" …" if len(letters) > 8 else ""))
    words = prose_words(text)
    lw = _language_words()
    en = sum(w in lw["english"] for w in words)
    foreign = [w for w in words if w in lw["foreign"]]
    if len(foreign) >= 2 and len(foreign) >= en:
        problems.append(f"{len(foreign)} non-English function words ({', '.join(dict.fromkeys(foreign[:8]))}) "
                        f"against {en} English ones")
    elif len(words) >= min_words and en * 20 < len(words):
        problems.append(f"only {en} common English words among {len(words)}")
    return problems


# --------------------------------------------------------------------------- VLAN names

def vlans(cfg: dict, site_name: str | None = None) -> list[dict]:
    """network.vlans entries with an integer id: [{id, name, cidr, gw, site}, …]. With site_name ('' = the
    unnamed default site), only that site's VLANs and those without a site or with site: all (every site)."""
    out = []
    for v in get(cfg, "network.vlans", []) or []:
        if isinstance(v, dict) and str(v.get("id", "")).strip().isdigit():
            if site_name is None or v.get("site") in (None, "", EVERY_SITE, site_name):
                out.append({**v, "id": int(v["id"])})
    return out


def resolve_vlan(cfg: dict, value, site_name: str | None = None) -> int | None:
    """A VLAN ID from an ID or a name in network.vlans (case-insensitive); None for an empty value."""
    if value in (None, ""):
        return None
    s = str(value).strip()
    if s.isdigit():
        return int(s)
    table = vlans(cfg, site_name)
    hits = [v["id"] for v in table if str(v.get("name") or "").lower() == s.lower()]
    if len(hits) == 1:
        return hits[0]
    known = ", ".join(f"{v.get('name')} ({v['id']})" for v in table if v.get("name")) or "none"
    raise ConfigError(f"VLAN {s!r} is {'ambiguous' if hits else 'not'} in network.vlans of homelab.yaml "
                      f"(known: {known}). Add it there or pass the VLAN ID.")


def vlan_label(cfg: dict, vlan_id=None, ip: str | None = None, site_name: str | None = None) -> str:
    """'VLAN 20 DMZ' for an ID, or the VLAN whose cidr holds `ip`; '' when unknown."""
    table = vlans(cfg, site_name)
    hit = None
    if vlan_id not in (None, ""):
        hit = next((v for v in table if v["id"] == int(vlan_id)), None) or {"id": int(vlan_id)}
    elif ip:
        for v in table:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(str(v.get("cidr")), strict=False):
                    hit = v
                    break
            except ValueError:
                continue
    if not hit:
        return ""
    return f"VLAN {hit['id']}" + (f" {hit['name']}" if hit.get("name") else "")
