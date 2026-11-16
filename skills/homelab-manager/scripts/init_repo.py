#!/usr/bin/env python3
"""Initialise (or extend) a homelab-infrastructure repository from the bundled template.

    init_repo.py --list-components
    init_repo.py [TARGET_DIR] --components proxmox,templates,ansible,discovery[,windows,appliances,kubernetes] [--dry-run]
    init_repo.py [TARGET_DIR] --add-components templates        # later: enable a part you skipped
    init_repo.py [TARGET_DIR] --sync-managed [--dry-run]        # bring a repo set up by an older plugin version up to date

- Copies only the files the chosen components need. Existing files are NEVER overwritten
  (an existing .claude/settings.json — e.g. from installing the plugin with project scope — gets the
  template's permission rules merged in, so the safety settings aren't lost),
  except plugin-managed ones (MANAGED) with --sync-managed.
- --sync-managed also applies one-time upgrades for repos set up by older plugin versions (see upgrades());
  the SessionStart hook (hooks/update_check.py) tells Claude when one is pending.
- Records the choice under `components:` in homelab.yaml — the skill ignores disabled parts.
- `git init -b main` if needed; core.hooksPath → scripts/git-hooks (blocks committing secrets).
- Registers this plugin's marketplace in .claude/settings.json when its Git remote is known.
Does not commit: the skill reviews the result with the user and commits.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import config_set  # noqa: E402
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
CORE = ["homelab.yaml", "README.md", "CLAUDE.md", "skill_issues.md", ".gitignore", ".claude/", "docs/README.md",
        "docs/decisions.md", "scripts/", "discovery/"]
# Owned by the plugin: kept identical to the template by --sync-managed (headers say so). None at the moment.
MANAGED: list[str] = []
# Were plugin-managed in older versions; removed by --sync-managed if still unedited-managed (header present).
OBSOLETE = [".github/ISSUE_TEMPLATE/homelab-problem.yml", ".github/ISSUE_TEMPLATE/config.yml"]  # until 0.5.2
MANAGED_MARK = "Managed by the homelab-manager plugin"
OLD_CLAUDE_RULE = re.compile(r"^- Record problems you find.*?(?=^\S|\Z)", re.M | re.S)       # until 0.5.2
NEW_CLAUDE_RULE = re.compile(r"^- Homelab problems .*?(?=^\S|\Z)", re.M | re.S)
OLD_README_ROW = re.compile(r"^\| `ISSUES\.md` \| Problems found while managing the homelab.*$", re.M)  # until 0.5.2
PREV_CLAUDE_RULE = re.compile(r"^- Homelab problems .*`skill_issues\.md` is only for problems with the\n.*?(?=^\S|\Z)",
                              re.M | re.S)                                                  # 0.6.0–0.8.0
PREV_README_ROW = re.compile(r"^\| `skill_issues\.md` \| Problems with the homelab-manager skill itself, "
                             r"to report to its GitHub repository \|$", re.M)               # 0.6.0–0.8.0
NEW_README_ROW = re.compile(r"^\| `skill_issues\.md` \|.*$", re.M)
LEGACY_ISSUES, NEW_ISSUES = "ISSUES.md", "skill_issues.md"                                   # until 0.7.0
OLD_ISSUES_KEYS = ("github", "repo", "labels")                                               # until 0.5.2


def merge_settings(src: Path, dst: Path) -> list[str]:
    """Add the template's permission rules and keys to an existing settings.json; never removes anything."""
    have, want = json.loads(dst.read_text() or "{}"), json.loads(src.read_text())
    added = []
    for kind, rules in (want.get("permissions") or {}).items():
        cur = have.setdefault("permissions", {}).setdefault(kind, [])
        for rule in rules:
            if rule not in cur:
                cur.append(rule)
                added.append(f"{kind}: {rule}")
    for k, v in want.items():
        if k != "permissions" and k not in have:
            have[k] = v
            added.append(k)
    if added:
        dst.write_text(json.dumps(have, indent=2) + "\n")
    return added


def _template_line(rel: str, rx: re.Pattern) -> str:
    return rx.search((TEMPLATE / rel).read_text()).group(0)


def _prune(d: Path, stop: Path):
    while d != stop and d.is_dir() and not any(d.iterdir()):
        d.rmdir()
        d = d.parent


def upgrades(target: Path) -> list[tuple[str, callable]]:
    """Changes that bring a repo set up by an older plugin version in line with this one: [(description, apply)]."""
    out = []
    for src in sorted(TEMPLATE.rglob("*")):
        rel = src.relative_to(TEMPLATE).as_posix()
        if src.is_dir() or not any(rel.startswith(m) for m in MANAGED):
            continue
        dst = target / rel
        if dst.exists() and dst.read_bytes() == src.read_bytes():
            continue
        def copy(src=src, dst=dst):
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        out.append((("update " if dst.exists() else "add ") + rel, copy))
    for rel in OBSOLETE:
        dst = target / rel
        if dst.is_file() and MANAGED_MARK in dst.read_text(errors="replace")[:400]:
            def remove(dst=dst):
                dst.unlink()
                _prune(dst.parent, target)
            out.append((f"remove {rel} (no longer used: homelab problems aren't tracked as issues)", remove))
    cfg = target / "homelab.yaml"
    if cfg.exists():
        r = subprocess.run(["yq", "-o=json", ".issues // {} | keys", str(cfg)], capture_output=True, text=True)
        try:
            stale = [k for k in json.loads(r.stdout or "[]") if k in OLD_ISSUES_KEYS]
        except ValueError:
            stale = []
        if stale:
            def fix_yaml(cfg=cfg):
                f = subprocess.run(["yq", '.issues.file // "skill_issues.md"', str(cfg)],
                                   capture_output=True, text=True).stdout.strip() or "skill_issues.md"
                config_set.edit_file(cfg, [("delete", f"issues.{k}") for k in OLD_ISSUES_KEYS] + [
                    ("set", "issues.file", f, "problems with / ideas for the homelab-manager skill itself (not the homelab)"),
                    ("set", "issues.report", True,
                     "offer to report them to the plugin's GitHub repository (sanitised, asks first)")])
            out.append((f"homelab.yaml: issues.{', issues.'.join(stale)} → issues.report", fix_yaml))
    for rel, what, rx, new, why in (
            ("CLAUDE.md", "rule", OLD_CLAUDE_RULE, lambda: _template_line("CLAUDE.md", NEW_CLAUDE_RULE),
             "the file is now for problems with the skill"),
            ("README.md", "table row", OLD_README_ROW, lambda: _template_line("README.md", NEW_README_ROW),
             "the file is now for problems with the skill"),
            ("CLAUDE.md", "rule", PREV_CLAUDE_RULE, lambda: _template_line("CLAUDE.md", NEW_CLAUDE_RULE),
             "the file now also collects ideas to improve the skill"),
            ("README.md", "table row", PREV_README_ROW, lambda: _template_line("README.md", NEW_README_ROW),
             "the file now also collects ideas to improve the skill")):
        f = target / rel
        if f.is_file() and rx.search(f.read_text()):
            def patch(f=f, rx=rx, new=new):
                f.write_text(rx.sub(lambda m: new(), f.read_text(), count=1))
            out.append((f"{rel}: replace the issues {what} ({why})", patch))
    sys.path.insert(0, str(HERE))
    import issues  # noqa: E402  (needs yq via hmlib only when homelab.yaml exists)
    msgs = issues.migrate(target, dry_run=True)
    if msgs:
        out.append(("; ".join(msgs), lambda: issues.migrate(target, dry_run=False)))
    rename = rename_issues_file(target)
    if rename:
        out.append(rename)
    tokens = token_user_acls(target)
    if tokens:
        out.append(tokens)
    return out


TOKEN_ACL = re.compile(r"^pveum acl modify (\S+) --tokens '([^'!]+)![^']+' --roles (\S+)[ \t]*$", re.M)
PRIVSEP_NOTE = "Both tokens use privilege separation"


def token_user_acls(target: Path):
    """Until 0.9.1 docs/proxmox-tokens.md granted roles only to the privsep tokens, which then had no rights."""
    f = target / "docs" / "proxmox-tokens.md"
    if not f.is_file():
        return None

    def user_line(m):
        return f"pveum acl modify {m.group(1)} --users {m.group(2)} --roles {m.group(3)}"

    text = f.read_text()
    missing = [m for m in TOKEN_ACL.finditer(text) if user_line(m) not in text]
    if not missing:
        return None

    def patch():
        t = f.read_text()
        t = TOKEN_ACL.sub(lambda m: m.group(0) if user_line(m) in t else user_line(m) + "\n" + m.group(0), t)
        if PRIVSEP_NOTE not in t:
            head, sep, rest = t.partition("\n\n## ")
            note = _template_paragraph("docs/proxmox-tokens.md", PRIVSEP_NOTE)
            t = head.rstrip("\n") + "\n\n" + note + "\n" + sep.lstrip("\n") + rest if sep else t + "\n" + note
        f.write_text(t)

    return (f"docs/proxmox-tokens.md: grant the token roles to the user too ({len(missing)} ACL line(s); "
            "privilege-separated tokens get no rights otherwise — run the new lines on Proxmox)", patch)


def _template_paragraph(rel: str, start: str) -> str:
    for para in (TEMPLATE / rel).read_text().split("\n\n"):
        if para.startswith(start):
            return para.rstrip("\n") + "\n"
    raise RuntimeError(f"{rel} template has no paragraph starting {start!r}")


def rename_issues_file(target: Path):
    """ISSUES.md → skill_issues.md (until 0.7.0): the old name read like the homelab's own issue list."""
    old, new = target / LEGACY_ISSUES, target / NEW_ISSUES
    cfg = target / "homelab.yaml"
    if not old.is_file() or new.exists() or not cfg.exists():
        return None
    configured = subprocess.run(["yq", ".issues.file // \"\"", str(cfg)], capture_output=True, text=True).stdout.strip()
    if configured not in ("", LEGACY_ISSUES):
        return None                       # the user chose their own file name: leave it
    def apply():
        tracked = git("ls-files", "--error-unmatch", LEGACY_ISSUES, cwd=target).returncode == 0
        if tracked:
            git("mv", LEGACY_ISSUES, NEW_ISSUES, cwd=target)
        else:
            old.rename(new)
        config_set.edit_file(cfg, [("set", "issues.file", NEW_ISSUES)])
        for rel in ("CLAUDE.md", "README.md"):
            f = target / rel
            if f.is_file() and f"`{LEGACY_ISSUES}`" in f.read_text():
                f.write_text(f.read_text().replace(f"`{LEGACY_ISSUES}`", f"`{NEW_ISSUES}`"))
    return (f"rename {LEGACY_ISSUES} → {NEW_ISSUES} (the old name looked like the homelab's own issue list); "
            f"update issues.file and the mentions in CLAUDE.md / README.md", apply)


def sync_managed(target: Path, dry_run: bool) -> int:
    steps = upgrades(target)
    for desc, apply in steps:
        if not dry_run:
            apply()
        print(("would " if dry_run else "") + desc)
    if not steps:
        print("Up to date with the plugin — nothing to change.")
    elif not dry_run:
        print("Review with `git diff` / `git status`, then commit.")
    return 0


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
    ap.add_argument("--sync-managed", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.list_components:
        for n, (desc, req, _) in COMPONENTS.items():
            print(f"{n:<11} {desc}" + (f"  (needs {', '.join(req)})" if req else ""))
        return 0
    target = Path(a.target).resolve()
    if a.sync_managed:
        return sync_managed(target, a.dry_run)
    existing = current_components(target)
    if a.add_components:
        comps = resolve(existing + a.add_components.split(","))
    elif a.components:
        comps = resolve(a.components.split(","))
    else:
        comps = existing or list(COMPONENTS)
    added = [c for c in comps if c not in existing]

    created, kept, merged = [], [], []
    for src in sorted(TEMPLATE.rglob("*")):
        if src.is_dir() or src.name == ".DS_Store":
            continue
        rel = src.relative_to(TEMPLATE).as_posix()
        if not wanted(rel, comps):
            continue
        dst = target / rel
        if dst.exists():
            if rel == ".claude/settings.json":
                try:
                    if a.dry_run:
                        merged.append(rel)
                    elif merge_settings(src, dst):
                        merged.append(rel)
                    continue
                except (ValueError, OSError) as e:
                    print(f"warning: could not merge {rel} ({e}); add the rules from the template by hand",
                          file=sys.stderr)
            kept.append(rel)
            continue
        created.append(rel)
        if not a.dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    if not a.dry_run:
        config_set.edit_file(target / "homelab.yaml", [("set", f"components.{n}", n in comps) for n in COMPONENTS])
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
    if merged:
        print(f"{'Would merge' if a.dry_run else 'Merged'} template permission rules into: {', '.join(merged)}")
    if kept:
        print(f"Kept {len(kept)} existing file(s) unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
