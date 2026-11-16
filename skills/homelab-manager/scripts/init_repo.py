#!/usr/bin/env python3
"""Initialise (or extend) a homelab-infrastructure repository from the bundled template.

    init_repo.py --list-components
    init_repo.py [TARGET_DIR] --components proxmox,templates,ansible,discovery[,windows,appliances,kubernetes] [--dry-run]
    init_repo.py [TARGET_DIR] --add-components templates        # later: enable a part you skipped

- Copies only the files the chosen components need. Existing files are NEVER overwritten.
- Records the choice under `components:` in homelab.yaml — the skill ignores disabled parts.
- `git init -b main` if needed; core.hooksPath → scripts/git-hooks (blocks committing secrets).
- Registers this plugin's marketplace in .claude/settings.json when its Git remote is known.
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

# component → (description, requires, template path prefixes)
COMPONENTS = {
    "proxmox": ("Proxmox VE VMs and LXC containers, provisioned with OpenTofu", [],
                ["tofu/", "docs/proxmox-tokens.md"]),
    "templates": ("VM templates from official cloud images, built with Packer", ["proxmox"],
                  ["packer/", "docs/templates.md"]),
    "ansible": ("Configuration management and patching with Ansible (Linux)", [],
                ["ansible/ansible.cfg", "ansible/requirements.yml", "ansible/inventory/managed/hosts.yml",
                 "ansible/inventory/managed/group_vars/all.yml", "ansible/playbooks/ping.yml",
                 "ansible/playbooks/check-updates.yml", "ansible/playbooks/patch-linux.yml", "ansible/roles/"]),
    "discovery": ("Network discovery with nmap in authorized ranges", [], []),
    "windows": ("Windows hosts (Ansible over OpenSSH)", ["ansible"], ["ansible/inventory/managed/group_vars/windows.yml"]),
    "appliances": ("Appliances: NAS, firewall, switches, BMCs (inventory + read-only checks)", ["ansible"],
                   ["ansible/inventory/managed/group_vars/appliances.yml"]),
    "kubernetes": ("Kubernetes clusters (rolling patching with drain/uncordon)", ["ansible"], ["ansible/playbooks/hooks/"]),
}
CORE = ["homelab.yaml", "README.md", "CLAUDE.md", "ISSUES.md", ".gitignore", ".claude/", "docs/README.md",
        "docs/decisions.md", "scripts/", "discovery/"]


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def marketplace_source() -> dict | None:
    r = git("remote", "get-url", "origin", cwd=PLUGIN_ROOT)
    url = r.stdout.strip() if r.returncode == 0 else ""
    if not url:
        return None
    if url.startswith(("git@github.com:", "https://github.com/")):
        return {"source": "github", "repo": url.split("github.com", 1)[1].lstrip(":/").removesuffix(".git")}
    return {"source": "git", "url": url}


def resolve(names: list[str]) -> list[str]:
    out = []
    def visit(n):
        if n not in COMPONENTS:
            raise SystemExit(f"unknown component {n!r}; choose from {', '.join(COMPONENTS)}")
        for r in COMPONENTS[n][1]:
            visit(r)
        if n not in out:
            out.append(n)
    for n in names:
        visit(n)
    return out


def current_components(target: Path) -> list[str]:
    cfg = target / "homelab.yaml"
    if not cfg.exists():
        return []
    r = subprocess.run(["yq", "-o=json", ".components // {}", str(cfg)], capture_output=True, text=True)
    try:
        return [k for k, v in json.loads(r.stdout or "{}").items() if v is True]
    except json.JSONDecodeError:
        return []


def wanted(rel: str, comps: list[str]) -> bool:
    prefixes = CORE + [p for c in comps for p in COMPONENTS[c][2]]
    return any(rel == p or (p.endswith("/") and rel.startswith(p)) for p in prefixes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=".")
    ap.add_argument("--components", help="comma-separated; default: all")
    ap.add_argument("--add-components", help="comma-separated components to enable in an existing repo")
    ap.add_argument("--list-components", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.list_components:
        for n, (desc, req, _) in COMPONENTS.items():
            print(f"{n:<11} {desc}" + (f"  (needs {', '.join(req)})" if req else ""))
        return 0
    target = Path(a.target).resolve()
    existing = current_components(target)
    if a.add_components:
        comps = resolve(existing + a.add_components.split(","))
    elif a.components:
        comps = resolve(a.components.split(","))
    else:
        comps = existing or list(COMPONENTS)
    added = [c for c in comps if c not in existing]

    created, kept = [], []
    for src in sorted(TEMPLATE.rglob("*")):
        if src.is_dir() or src.name == ".DS_Store":
            continue
        rel = src.relative_to(TEMPLATE).as_posix()
        if not wanted(rel, comps):
            continue
        dst = target / rel
        if dst.exists():
            kept.append(rel)
            continue
        created.append(rel)
        if not a.dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    if not a.dry_run:
        expr = " | ".join(f".components.{n} = {str(n in comps).lower()}" for n in COMPONENTS)
        subprocess.run(["yq", "-i", expr, str(target / "homelab.yaml")], check=True)
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

    print(f"Components: {', '.join(comps)}" + (f"  (newly enabled: {', '.join(added)})" if existing and added else ""))
    print(f"{'Would create' if a.dry_run else 'Created'} {len(created)} file(s) in {target}")
    for c in created:
        print(f"  + {c}")
    if kept:
        print(f"Kept {len(kept)} existing file(s) unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
