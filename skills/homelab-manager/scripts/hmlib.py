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
