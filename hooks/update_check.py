#!/usr/bin/env python3
"""Tell the user when a newer homelab-manager release exists. Checks the network at most once a day.

    update_check.py            # SessionStart hook: prints hook JSON only when an update is available
    update_check.py --force    # check now, plain-text answer (for "is there a new version?")

Latest version = highest `vX.Y.Z` tag on the plugin's Git remote (`git ls-remote`, read-only,
non-interactive, short timeout). The remote comes from HM_UPDATE_URL, the installed marketplace
entry in ~/.claude/plugins/known_marketplaces.json, or this checkout's `origin`.
The result is cached in ~/.cache/homelab-manager/update-check.json; a failed check is retried after 6 h.
Also (local, no network, every session): when the working directory is a homelab repo set up by an
older plugin version, tells Claude which one-time upgrades `init_repo.py --sync-managed` would apply.
Never fails the session: any error → silent.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE = "homelab-manager-skill"
CACHE = Path(os.environ.get("HM_UPDATE_CACHE", Path.home() / ".cache" / "homelab-manager" / "update-check.json"))
OK_TTL, FAIL_TTL = dt.timedelta(hours=24), dt.timedelta(hours=6)
TAG_RE = re.compile(r"refs/tags/v(\d+)\.(\d+)\.(\d+)$")


def vtuple(v: str) -> tuple[int, ...]:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", (v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def installed_version() -> str:
    return json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]


def remote_url() -> str | None:
    if os.environ.get("HM_UPDATE_URL"):
        return os.environ["HM_UPDATE_URL"]
    known = Path.home() / ".claude" / "plugins" / "known_marketplaces.json"
    try:
        src = json.loads(known.read_text()).get(MARKETPLACE, {}).get("source", {})
        if src.get("url"):
            return src["url"]
        if src.get("repo"):
            return f"https://github.com/{src['repo']}.git"
    except (OSError, ValueError, AttributeError):
        pass
    r = subprocess.run(["git", "-C", str(ROOT), "remote", "get-url", "origin"], capture_output=True, text=True)
    return r.stdout.strip() or None if r.returncode == 0 else None


def latest_tag(url: str) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0",
           "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o ConnectTimeout=5"}
    r = subprocess.run(["git", "ls-remote", "--tags", "--refs", url], capture_output=True, text=True,
                       timeout=15, env=env)
    if r.returncode != 0:
        raise RuntimeError((r.stderr.strip().splitlines() or ["git ls-remote failed"])[-1][:200])
    versions = [tuple(int(x) for x in m.groups()) for m in map(TAG_RE.search, r.stdout.split()) if m]
    if not versions:
        raise RuntimeError("no vX.Y.Z tags on the remote")
    return "%d.%d.%d" % max(versions)


def load_cache() -> dict:
    try:
        return json.loads(CACHE.read_text())
    except (OSError, ValueError):
        return {}


def check(force: bool) -> dict:
    cache = load_cache()
    now = dt.datetime.now(dt.timezone.utc)
    try:
        last = dt.datetime.fromisoformat(cache["checked_at"])
        fresh = now - last < (OK_TTL if cache.get("latest") else FAIL_TTL)
    except (KeyError, ValueError):
        fresh = False
    if fresh and not force:
        return cache
    url = remote_url()
    result = {"checked_at": now.isoformat(timespec="seconds"), "latest": None, "error": None}
    try:
        if not url:
            raise RuntimeError("plugin Git remote unknown")
        result["latest"] = latest_tag(url)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        result["error"] = str(e)
        result["latest"] = None
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(result) + "\n")
    except OSError:
        pass
    return result


def update_text(have: str, latest: str) -> str:
    return (f"homelab-manager {latest} is available (installed: {have}). Update with "
            f"`/plugin marketplace update {MARKETPLACE}`, then reinstall or update the plugin from `/plugin`; "
            f"see CHANGELOG.md for what changed.")


SCRIPTS = ROOT / "skills" / "homelab-manager" / "scripts"


def repo_upgrades() -> list[str]:
    """One-time upgrades pending for the homelab repo in the working directory (empty outside one)."""
    sys.path.insert(0, str(SCRIPTS))
    import hmlib
    import init_repo
    root = hmlib.find_repo_root()
    return [desc for desc, _ in init_repo.upgrades(root)] if root else []


def upgrade_text(steps: list[str]) -> str:
    return ("This homelab repository was set up by an older homelab-manager and needs a one-time update: "
            + "; ".join(steps) + f". Tell the user, run `python3 {SCRIPTS}/init_repo.py --sync-managed --dry-run`, "
            "and after their yes run it without --dry-run and commit (`Update repo for homelab-manager`).")


def main() -> int:
    force = "--force" in sys.argv[1:]
    try:
        have = installed_version()
        res = check(force)
    except Exception as e:  # never break a session
        if force:
            print(f"Update check failed: {e}")
        return 0
    latest = res.get("latest")
    newer = bool(latest) and vtuple(latest) > vtuple(have)
    if force:
        if res.get("error"):
            print(f"Update check failed: {res['error']} (installed: {have})")
        else:
            print(update_text(have, latest) if newer else f"homelab-manager {have} is up to date (latest: {latest}).")
        return 0
    try:
        steps = repo_upgrades()
    except Exception:  # never break a session
        steps = []
    notes, context = [], []
    if newer:
        notes.append(update_text(have, latest))
        context.append(notes[-1] + " Mention this to the user once.")
    if steps:
        notes.append("homelab-manager: this repository needs a one-time update for the installed plugin version.")
        context.append(upgrade_text(steps))
    if notes:
        print(json.dumps({"systemMessage": " ".join(notes),
                          "hookSpecificOutput": {"hookEventName": "SessionStart",
                                                 "additionalContext": " ".join(context)}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
