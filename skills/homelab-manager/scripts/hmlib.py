"""Shared helpers for homelab-manager scripts and the safety hook.

Standard library only (the Mac Mini's python3 has no third-party packages).
YAML is read through `yq`, which the skill installs as a prerequisite.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
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


def load_config(root: str | os.PathLike | None = None) -> dict:
    root = Path(root) if root else find_repo_root()
    if not root:
        raise ConfigError(f"No {CONFIG_NAME} found in this directory or its parents. "
                          "Initialise the repository first (init_repo.py).")
    yq = shutil.which("yq") or "/opt/homebrew/bin/yq"
    if not Path(yq).exists():
        raise ConfigError("yq is not installed (brew install yq).")
    res = subprocess.run([yq, "-o=json", ".", str(root / CONFIG_NAME)],
                         capture_output=True, text=True, timeout=20)
    if res.returncode != 0:
        raise ConfigError(f"{CONFIG_NAME} is not valid YAML: {res.stderr.strip()}")
    cfg = json.loads(res.stdout or "{}") or {}
    cfg["_root"] = str(root)
    return cfg


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
    ca = (px or {}).get("ca_cert") if px is not None else get(cfg, "proxmox.ca_cert")
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
    verify = (px or {}).get("verify_tls", True) if px is not None else get(cfg, "proxmox.verify_tls", True)
    if verify is False:
        return ssl._create_unverified_context()
    ca = proxmox_ca_file(cfg, px)
    if ca and not Path(ca).is_file():
        where = (px or {}).get("_where", "proxmox") if px is not None else "proxmox"
        raise ConfigError(f"{where}.ca_cert {ca!r} does not exist.")
    return ssl.create_default_context(cafile=ca)


# --------------------------------------------------------------------------- sites

# A site is a location (home, a rented server, family's house). `sites:` in homelab.yaml lists them, the default
# first: its Proxmox is the top-level `proxmox:` block; any other site may have its own (`sites[].proxmox`, same
# keys). Inventory hosts belong to a site through the Ansible group site_<name> (none: the default site).
# Without `sites:` there is one unnamed default site. A site other than the default may also have its own
# vmid_ranges, vmid_scheme and templates (build network); its OpenTofu environment is tofu/environments/<name>.
SITE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
SITE_GROUP_PREFIX = "site_"
SITE_SETTINGS = ("vmid_ranges", "vmid_scheme", "templates")


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
        seen.add(name)
        if i == 0 and s.get("proxmox"):
            raise ConfigError(f"sites[0] ({name}) is the default site: its Proxmox is the top-level proxmox: block, "
                              "not sites[0].proxmox.")
        px = top if i == 0 else s.get("proxmox")
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
                    "proxmox": {**px, "_where": "proxmox" if i == 0 else f"sites[{name}].proxmox"} if px else None,
                    "ranges": _networks(s.get("ranges")), "settings": settings})
    _check_vlan_sites(cfg, [s["name"] for s in out])
    return out


def _check_vlan_sites(cfg: dict, names: list[str]):
    for v in get(cfg, "network.vlans", []) or []:
        st = v.get("site") if isinstance(v, dict) else None
        if st not in (None, "") and st not in names:
            raise ConfigError(f"network.vlans: VLAN {v.get('id')} has site {st!r}, which is not in sites: "
                              f"({', '.join(names) or 'none'}).")


def site_config(cfg: dict, name: str | None = None) -> dict:
    """cfg as seen from one site: its own vmid_ranges / vmid_scheme / templates in place of the top-level ones."""
    s = site(cfg, name)
    out = dict(cfg)
    for k, v in s["settings"].items():
        out[k] = {**cfg[k], **v} if k == "templates" and isinstance(cfg.get(k), dict) else v
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


def proxmox_site(cfg: dict, name: str | None = None) -> dict:
    """The Proxmox block of a site, with `_site` (its name) and `_where` (its config path); endpoint required."""
    s = site(cfg, name)
    px = s["proxmox"]
    if not px or not px.get("endpoint"):
        where = px["_where"] if px else f"sites[{s['name']}].proxmox"
        raise ConfigError(f"{where}.endpoint is empty in homelab.yaml"
                          + (f" (site {s['name']!r} has no Proxmox)." if not s["default"] else "."))
    return {**px, "_site": s["name"]}


def proxmox_sites(cfg: dict) -> list[dict]:
    """The Proxmox block of every site that has one with an endpoint."""
    return [proxmox_site(cfg, s["name"]) for s in sites(cfg) if s["proxmox"] and s["proxmox"].get("endpoint")]


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


def proxmox_snapshot_file(root: str | os.PathLike, site_name: str | None = None, default: bool = True) -> Path:
    """discovery/proxmox.json for the default site, discovery/proxmox-<name>.json for the others."""
    d = Path(root) / "discovery"
    return d / "proxmox.json" if default or not site_name else d / f"proxmox-{site_name}.json"


def proxmox_snapshots(cfg: dict) -> list[tuple[dict, dict]]:
    """[(site, snapshot)] for every site whose snapshot file exists, the default site first."""
    out = []
    for s in sites(cfg):
        f = proxmox_snapshot_file(cfg["_root"], s["name"], s["default"])
        if f.is_file():
            try:
                out.append((s, json.loads(f.read_text())))
            except ValueError:
                raise ConfigError(f"{f.name} is not valid JSON: run proxmox_inventory.py again.")
    return out


def host_sites(groups) -> list[str]:
    """Site names of an inventory host from its site_<name> groups (normally zero or one)."""
    return sorted(g[len(SITE_GROUP_PREFIX):] for g in groups or [] if str(g).startswith(SITE_GROUP_PREFIX))


def site_of_address(cfg: dict, ip: str) -> dict | None:
    """The site whose `ranges` hold this address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((s for s in sites(cfg) if any(addr in n for n in s["ranges"])), None)


# --------------------------------------------------------------------------- scan scope

def _networks(items) -> list:
    nets = []
    for item in items or []:
        try:
            nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            raise ConfigError(f"Invalid network in homelab.yaml: {item!r}")
    return nets


def scan_scope(cfg: dict) -> tuple[list, list]:
    allowed = _networks(get(cfg, "network.authorized_ranges", []))
    excluded = _networks(get(cfg, "network.excluded_hosts", []))
    return allowed, excluded


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


def redact(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "***REDACTED***")
    return text


# --------------------------------------------------------------------------- untrusted data

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(value, limit: int = 200):
    """Sanitise strings that come from the network (banners, hostnames, VM notes).

    They are data, not instructions: strip control characters and cap the length
    so a hostile banner can't smuggle a wall of text into the conversation.
    """
    if value is None:
        return None
    s = _CTRL.sub("", str(value))
    return s if len(s) <= limit else s[:limit] + "…"


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


def _guest_net(g: dict) -> tuple[str | None, int | None]:
    """(static IPv4, VLAN tag) of a guest's first NIC, from its snapshot config (--details)."""
    conf = g.get("config") or {}
    ip = vlan = None
    for k in sorted(conf):
        v = str(conf[k])
        if k.startswith(("net", "ipconfig")):
            m = re.search(r"(?<![\w])ip=(\d+\.\d+\.\d+\.\d+)", v)
            ip = ip or (m.group(1) if m else None)
            m = re.search(r"(?<![\w-])tag=(\d+)", v)
            vlan = vlan if vlan is not None else (int(m.group(1)) if m else None)
    if not ip:
        ip = next((a["ip"] for a in g.get("ips") or [] if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", str(a.get("ip")))), None)
    return ip, vlan


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
    unnamed default site), only that site's VLANs and those without a site (the same at every site)."""
    out = []
    for v in get(cfg, "network.vlans", []) or []:
        if isinstance(v, dict) and str(v.get("id", "")).strip().isdigit():
            if site_name is None or v.get("site") in (None, "", site_name):
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
