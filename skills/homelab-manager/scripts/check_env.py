#!/usr/bin/env python3
"""Check that this Mac is ready to manage the homelab.

    check_env.py              tools + SSH agent + config + configured keychain items + Proxmox TLS
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
SELFTEST_SERVICE = "homelab/_selftest"


def run(cmd, timeout=15, input_text=None, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


def check_tools():
    out = []
    for name, (cmd, install) in TOOLS.items():
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
                    "s3_credentials": (r"^[^:\s]+:\S+$", "ACCESS_KEY_ID:SECRET_ACCESS_KEY"),
                    "user_password": (r"^[^:\s]+:.+$", "user:password")}.get(entry.get("kind"))
            if want:
                fmt_ok = bool(re.match(want[0], v))
            out.append({"check": f"secret:{name}", "ok": bool(v) and fmt_ok,
                        "detail": ("readable" if fmt_ok else f"readable but not in {want[1]} format")
                        + f" ({len(v)} chars)"})
        except hmlib.ConfigError as e:
            out.append({"check": f"secret:{name}", "ok": False, "detail": str(e)})
    return out, cfg


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
    return [r for px in targets for r in _check_tls(cfg, px)]


def _check_tls(cfg, px):
    check = "proxmox:tls" + (f":{px['_site']}" if px["_site"] and px["_where"] != "proxmox" else "")
    where, endpoint = px["_where"], px["endpoint"]
    if px.get("verify_tls", True) is False:
        return [{"check": check, "ok": None,
                 "detail": f"verify_tls: false — certificate not checked (prefer {where}.ca_cert)"}]
    u = urllib.parse.urlsplit(endpoint)
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
        name, kc = found
        slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower() or "ca"
        return [{"check": check, "ok": False,
                 "detail": f"CA {name!r} is trusted in the macOS keychain ({kc}), but Python does not read the "
                           f"keychain. Export it and point ca_cert at it: mkdir -p ~/.config/homelab && "
                           f"security find-certificate -a -c \"{name}\" -p {kc} > ~/.config/homelab/{slug}.pem && "
                           f"python3 $HM/scripts/config_set.py '{where}.ca_cert=~/.config/homelab/{slug}.pem'"}]
    issuer = f" (issuer {names[0]!r})" if names else ""
    return [{"check": check, "ok": False,
             "detail": f"certificate not trusted{issuer}: {err.verify_message}. Set {where}.ca_cert to the CA's PEM "
                       "(Proxmox's own CA: /etc/pve/pve-root-ca.pem on a node) rather than verify_tls: false: "
                       f"python3 $HM/scripts/config_set.py '{where}.ca_cert=~/.config/homelab/<ca>.pem'"}]


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


_INVENTORY: dict = {}


def managed_inventory(cfg) -> dict | None:
    """`ansible-inventory --list` of the managed inventory (once per run); None without Ansible or inventory."""
    root = Path(cfg["_root"]) if cfg else None
    if not root or not shutil.which("ansible") or not (root / "ansible" / "inventory" / "managed").exists():
        return None
    if root not in _INVENTORY:
        rc, so, _ = run(["ansible-inventory", "-i", "inventory/managed", "--list"], timeout=60, cwd=root / "ansible")
        _INVENTORY[root] = json.loads(so or "{}") if rc == 0 else None
    return _INVENTORY[root]


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
    results = check_tools() + check_ssh_agent() + check_gh() + check_keychain_unlocked()
    if "--keychain" in argv:
        results += check_keychain_selftest()
    cfg_results, cfg = check_config_and_secrets()
    results += (cfg_results + check_proxmox_tls(cfg) + check_tofu_sites(cfg) + check_ansible_targets(cfg)
                + check_site_ambiguity(cfg)
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
