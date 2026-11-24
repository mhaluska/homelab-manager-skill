#!/usr/bin/env python3
"""PreToolUse guard for file edits (Edit, Write, MultiEdit, NotebookEdit): the files that guard the guard.

guard.py checks Bash commands; this hook asks before Claude changes, with its file tools,
  - homelab.yaml settings that widen what the plugin may do: the scan scope (network.authorized_ranges,
    network.excluded_hosts), TLS certificate checks (every verify_tls) and issues.auto_send;
  - the installed plugin (its hooks and scripts) or any other Claude Code plugin;
  - Claude Code permission settings (.claude/settings.json, .claude/settings.local.json).
Other edits get no decision (normal Claude Code permission handling). Fails closed: any error asks.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "skills" / "homelab-manager" / "scripts"))
FILE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
# the plugin, its other installed versions (…/homelab-manager/<version>), and every plugin
PLUGIN_HOMES = [PLUGIN_ROOT] + ([PLUGIN_ROOT.parent] if PLUGIN_ROOT.parent.name == "homelab-manager" else []) \
    + [Path.home() / ".claude" / "plugins"]
WATCHED = ("network.authorized_ranges", "network.excluded_hosts", "issues.auto_send")


def resolved(path: str, cwd: str) -> Path:
    p = Path(os.path.expanduser(path))
    p = p if p.is_absolute() else Path(cwd) / p
    try:
        return Path(os.path.abspath(p)).resolve()
    except OSError:
        return Path(os.path.abspath(p))


def new_text(tool: str, inp: dict, old: str) -> str:
    """The file's text after the edit."""
    if tool == "Write":
        return inp.get("content") or ""
    text = old
    for e in (inp.get("edits") or []) if tool == "MultiEdit" else [inp]:
        o, n = e.get("old_string") or "", e.get("new_string") or ""
        if not o:
            text = n
        elif e.get("replace_all"):
            text = text.replace(o, n)
        else:
            text = text.replace(o, n, 1)
    return text


def parse_yaml(text: str) -> dict:
    """homelab.yaml text as data (yq, like hmlib.load_config); ValueError when it is not valid YAML."""
    import hmlib
    if not text.strip():
        return {}
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
    try:
        r = subprocess.run([hmlib.yq_bin(), "-o=json", ".", f.name], capture_output=True, text=True, timeout=20)
    finally:
        os.unlink(f.name)
    if r.returncode != 0:
        raise ValueError(r.stderr.strip()[:200] or "not valid YAML")
    data = json.loads(r.stdout or "{}")
    return data if isinstance(data, dict) else {}


def tls_settings(node, path: str = "") -> dict[str, object]:
    """Every verify_tls in the document, by its path (proxmox.verify_tls, sites[offsite].proxmox.verify_tls, …)."""
    out = {}
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else str(k)
            if k == "verify_tls":
                out[p] = v
            out.update(tls_settings(v, p))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            name = v.get("name", i) if isinstance(v, dict) else i
            out.update(tls_settings(v, f"{path}[{name}]"))
    return out


def get(cfg: dict, dotted: str):
    for part in dotted.split("."):
        cfg = cfg.get(part) if isinstance(cfg, dict) else None
    return cfg


def homelab_changes(old: str, new: str) -> list[str]:
    """The watched settings an edit of homelab.yaml changes."""
    try:
        before = parse_yaml(old)
    except ValueError:
        before = {}
    after = parse_yaml(new)   # an edit that breaks the file raises: main() asks
    changed = [k for k in WATCHED if get(before, k) != get(after, k)]
    a, b = tls_settings(before), tls_settings(after)
    changed += sorted(k for k in set(a) | set(b) if a.get(k, True) != b.get(k, True))
    return changed


def reason_for(tool: str, inp: dict, cwd: str) -> str | None:
    path = inp.get("file_path") or inp.get("notebook_path") or ""
    if not path:
        return None
    p = resolved(path, cwd)
    if any(p.is_relative_to(h.resolve()) for h in PLUGIN_HOMES if h.exists()):
        return "changes an installed Claude Code plugin (its hooks and scripts): only with the user's yes."
    if p.name in ("settings.json", "settings.local.json") and p.parent.name == ".claude":
        return "changes Claude Code permission settings (.claude/settings*.json): only with the user's yes."
    if p.name == "homelab.yaml":
        old = p.read_text(errors="replace") if p.is_file() else ""
        try:
            changed = homelab_changes(old, new_text(tool, inp, old))
        except ValueError as e:
            return f"leaves homelab.yaml unreadable ({e}); review the edit."
        if changed:
            return (f"changes {', '.join(changed)} in homelab.yaml (scan scope, TLS checks or issue sending): only "
                    "with the user's yes; config_set.py is the usual way to change settings.")
    return None


def decision(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": "homelab-manager guard: this edit " + reason}}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("hook input is not a JSON object")
        tool = payload.get("tool_name")
        if tool not in FILE_TOOLS:
            return 0
        reason = reason_for(tool, payload.get("tool_input") or {}, payload.get("cwd") or os.getcwd())
        out = decision(reason) if reason else None
    except Exception as e:  # noqa: BLE001 — fail closed
        out = decision(f"could not be checked (guard error {type(e).__name__}: {str(e)[:120]}); review it manually.")
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
