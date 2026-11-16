#!/usr/bin/env python3
"""Initialise (or complete) a homelab-infrastructure repository from the bundled template.

    init_repo.py [TARGET_DIR] [--dry-run]

- Copies assets/repo-template into TARGET_DIR (default: current directory).
  Existing files are NEVER overwritten — they are listed as "kept".
- `git init -b main` if needed; points core.hooksPath at scripts/git-hooks (secret guard).
- Registers this plugin's marketplace in .claude/settings.json when its Git remote is known,
  so opening the repo on another machine offers to install the plugin.
Does not commit: the skill reviews the result with the user and commits.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE.parent / "assets" / "repo-template"
PLUGIN_ROOT = HERE.parents[2]


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def marketplace_source() -> dict | None:
    r = git("remote", "get-url", "origin", cwd=PLUGIN_ROOT)
    url = r.stdout.strip() if r.returncode == 0 else ""
    if not url:
        return None
    if url.startswith(("git@github.com:", "https://github.com/")):
        repo = url.split("github.com", 1)[1].lstrip(":/").removesuffix(".git")
        return {"source": "github", "repo": repo}
    return {"source": "git", "url": url}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=".")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    target = Path(a.target).resolve()
    if not TEMPLATE.is_dir():
        print(f"template missing: {TEMPLATE}", file=sys.stderr)
        return 2

    created, kept = [], []
    for src in sorted(TEMPLATE.rglob("*")):
        if src.is_dir() or src.name == ".DS_Store":
            continue
        rel = src.relative_to(TEMPLATE)
        dst = target / rel
        if dst.exists():
            kept.append(str(rel))
            continue
        created.append(str(rel))
        if not a.dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    if not a.dry_run:
        if not (target / ".git").exists():
            r = git("init", "-b", "main", cwd=target)
            print(r.stdout.strip() or r.stderr.strip())
        git("config", "core.hooksPath", "scripts/git-hooks", cwd=target)
        settings = target / ".claude" / "settings.json"
        src = marketplace_source()
        if src and settings.exists():
            data = json.loads(settings.read_text())
            data.setdefault("extraKnownMarketplaces", {}).setdefault("homelab-manager-skill", {"source": src})
            data.setdefault("enabledPlugins", {}).setdefault("homelab-manager@homelab-manager-skill", True)
            settings.write_text(json.dumps(data, indent=2) + "\n")

    print(f"{'Would create' if a.dry_run else 'Created'} {len(created)} file(s) in {target}")
    for c in created:
        print(f"  + {c}")
    if kept:
        print(f"Kept {len(kept)} existing file(s) unchanged:")
        for k in kept:
            print(f"  = {k}")
    name = git("config", "user.name", cwd=target).stdout.strip()
    email = git("config", "user.email", cwd=target).stdout.strip()
    print(f"Git identity: {name or '(unset)'} <{email or 'unset'}>")
    print("\nNext: fill homelab.yaml (network.authorized_ranges, proxmox.endpoint, …), "
          "create keychain items, run check_env.py --keychain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
