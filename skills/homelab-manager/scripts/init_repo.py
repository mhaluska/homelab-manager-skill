#!/usr/bin/env python3
"""Initialise (or extend) a homelab-infrastructure repository from the bundled template.

    init_repo.py --list-components
    init_repo.py [TARGET_DIR] --components proxmox,templates,ansible,discovery[,windows,appliances,kubernetes] [--dry-run]
    init_repo.py [TARGET_DIR] --add-components templates        # later: enable a part you skipped
    init_repo.py [TARGET_DIR] --sync-managed [--dry-run]        # bring a repo set up by an older plugin version up to date
    init_repo.py [TARGET_DIR] --add-site NAME [--dry-run]       # scaffold a site listed in homelab.yaml sites:
    init_repo.py [TARGET_DIR] --name-default-site NAME [--steps ranges,vlans,group] [--dry-run]

- Copies only the files the chosen components need. Existing files are NEVER overwritten
  (an existing .claude/settings.json — e.g. from installing the plugin with project scope — gets the
  template's permission rules merged in, so the safety settings aren't lost),
  except plugin-managed ones (MANAGED) with --sync-managed.
- --sync-managed also applies one-time upgrades for repos set up by older plugin versions (see upgrades());
  the SessionStart hook (hooks/update_check.py) tells Claude when one is pending. It also lists the opt-in
  changes newer releases suggest (upgrade_notes.py — never applied by it, they need the user's yes) and the
  user's reported skill issues the installed release fixed. Suggestions are offered until each is applied or
  declined (upgrade_notes.py --decline); a real run with none left records the installed version in
  upgrades.reviewed.
- --sync-managed replaces a template file the user never edited (it matches a released template byte for
  byte, assets/template-history.json) with the current one, adding new files it names; edited files get
  upgrade-note suggestions instead.
- Records the choice under `components:` in homelab.yaml — the skill ignores disabled parts.
- `git init -b main` if needed; core.hooksPath → scripts/git-hooks (blocks committing secrets).
- Registers this plugin's marketplace in .claude/settings.json when its Git remote is known.
- --add-site: the site's OpenTofu environment tofu/environments/<name> (proxmox component) and a site.tf in it
  and in the default environment that refuses another site's token; group_vars/site_<name>.yml (ansible). For the
  default site only group_vars/site_<name>.yml (it uses the top-level settings and environment). It points out
  a default site that isn't explicit yet.
- --name-default-site: makes the existing site explicit (setup, or before a second site): sites[0] gets the
  name and ranges proposed from authorized_ranges and VLAN CIDRs; VLANs without a site get it; hosts.yml gets
  site_<name> with every inventory host in no site group, plus group_vars/site_<name>.yml.
Does not commit: the skill reviews the result with the user and commits.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import config_set  # noqa: E402
import hmlib  # noqa: E402
import upgrade_notes  # noqa: E402
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
                 "ansible/playbooks/check-updates.yml", "ansible/playbooks/patch-linux.yml",
                 "ansible/playbooks/security-audit.yml",
                 "ansible/playbooks/docker-containers.yml",
                 "ansible/playbooks/patch-proxmox-node.yml", "ansible/playbooks/dist-upgrade-debian.yml",
                 "ansible/playbooks/dist-upgrade-ubuntu.yml",
                 "ansible/playbooks/tasks/", "ansible/playbooks/vars/",
                 "ansible/playbooks/hooks/vrrp-health.yml",
                 "ansible/inventory/managed/group_vars/proxmox_nodes.yml", "ansible/roles/"]),
    "discovery": ("Network discovery with nmap in authorized ranges", [], []),
    "windows": ("Windows hosts (Ansible over OpenSSH)", ["ansible"], ["ansible/inventory/managed/group_vars/windows.yml",
                                                                         "ansible/playbooks/patch-windows.yml"]),
    "appliances": ("Appliances: NAS, firewall, switches, BMCs (inventory + read-only checks)", ["ansible"],
                   ["ansible/inventory/managed/group_vars/appliances.yml", "ansible/inventory/managed/group_vars/bmc.yml",
                    "ansible/playbooks/bmc-info.yml", "ansible/inventory/managed/group_vars/unifi.yml",
                    "ansible/playbooks/unifi-info.yml", "ansible/playbooks/routeros-disable-services.yml",
                    "ansible/playbooks/routeros-restrict-management.yml",
                    "ansible/playbooks/routeros-routerboot-upgrade.yml",
                    "ansible/inventory/managed/group_vars/qnap.yml", "ansible/playbooks/qnap-containers.yml"]),
    "kubernetes": ("Kubernetes clusters (rolling patching with drain/uncordon)", ["ansible"],
                   ["ansible/playbooks/hooks/k8s-drain.yml", "ansible/playbooks/hooks/k8s-uncordon.yml",
                    "ansible/playbooks/hooks/k8s-health.yml"]),
}
CORE = ["homelab.yaml", "README.md", "CLAUDE.md", "skill_issues.md", ".gitignore", ".claude/", "docs/README.md",
        "docs/decisions.md", "docs/recovery.md", "scripts/", "discovery/"]
# Owned by the plugin: kept identical to the template by --sync-managed (headers say so). None at the moment.
MANAGED: list[str] = []
# Were plugin-managed in older versions; removed by --sync-managed if still unedited-managed (header present).
OBSOLETE = [".github/ISSUE_TEMPLATE/homelab-problem.yml", ".github/ISSUE_TEMPLATE/config.yml"]  # until 0.5.2
MANAGED_MARK = "Managed by the homelab-manager plugin"
# Template files --sync-managed never replaces even when unedited: config and data the scripts edit in place,
# and docs whose changes come with steps on Proxmox that a silent replacement would hide.
HISTORY = HERE.parent / "assets" / "template-history.json"
NEVER_REPLACE = {"homelab.yaml", ".claude/settings.json", "skill_issues.md", "docs/proxmox-tokens.md"}
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
        hmlib.atomic_write(dst, json.dumps(have, indent=2) + "\n")
    return added


def missing_settings(src: Path, dst: Path) -> list[str]:
    """Template permission rules an existing settings.json lacks (unreadable JSON: none, it is the user's file)."""
    try:
        have = (json.loads(dst.read_text() or "{}").get("permissions") or {})
        want = json.loads(src.read_text()).get("permissions") or {}
        return [f"{kind}: {r}" for kind, rules in want.items() for r in rules if r not in (have.get(kind) or [])]
    except (ValueError, OSError, AttributeError):
        return []


def _template_line(rel: str, rx: re.Pattern) -> str:
    return rx.search((TEMPLATE / rel).read_text()).group(0)


def _prune(d: Path, stop: Path):
    while d != stop and d.is_dir() and not any(d.iterdir()):
        d.rmdir()
        d = d.parent


def _blob(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()   # git's blob hash, as in the history


def unedited_templates(target: Path) -> list[tuple[str, str, list[str]]]:
    """Repo files that differ from the template but match a released one byte for byte (no local edits):
    [(path, last release with that content, new template files it names that the repo lacks)] (GitHub issue #68).
    New files an upgrade note offers (file_missing) stay opt-in."""
    if not (target / "homelab.yaml").exists() or not HISTORY.exists():
        return []
    hist = json.loads(HISTORY.read_text())["files"]
    comps = current_components(target) or list(COMPONENTS)   # no components: section = older repo: all
    opt_in = {n["when"]["file_missing"] for n in upgrade_notes.all_notes() if "file_missing" in (n.get("when") or {})}
    rels = [p.relative_to(TEMPLATE).as_posix() for p in sorted(TEMPLATE.rglob("*"))
            if p.is_file() and p.name != ".DS_Store"]
    vt = upgrade_notes.vtuple
    out = []
    for rel in rels:
        if rel in NEVER_REPLACE or any(rel.startswith(m) for m in MANAGED) or not wanted(rel, comps):
            continue
        dst, src = target / rel, TEMPLATE / rel
        if not dst.is_file():
            continue
        have = dst.read_bytes()
        if have == src.read_bytes() or _blob(have) not in hist.get(rel, {}):
            continue
        since = hist[rel][_blob(have)][1]
        text = src.read_text(errors="replace")
        new = [c for c in rels if c not in opt_in and c not in NEVER_REPLACE and wanted(c, comps) and not (target / c).exists()
               and not any(vt(a) <= vt(since) <= vt(b) for a, b in hist.get(c, {}).values())
               and "/".join(c.split("/")[-2:]) in text]
        out.append((rel, since, new))
    return out


def upgrades(target: Path) -> list[tuple[str, callable]]:
    """Changes that bring a repo set up by an older plugin version in line with this one: [(description, apply)]."""
    out = []
    replaced, added = set(), set()
    for rel, since, new in unedited_templates(target):
        new = [c for c in new if c not in added]
        added |= set(new)
        replaced.add(rel)
        def replace(rel=rel, new=new):
            for r in [rel, *new]:
                (target / r).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(TEMPLATE / r, target / r)
        out.append((f"replace {rel} with the current template (no local edits since {since})"
                    + (f"; add {', '.join(new)} (it uses them)" if new else ""), replace))
    first = len(out)
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
    settings = target / ".claude" / "settings.json"
    if settings.is_file() and (target / "homelab.yaml").exists():
        missing = missing_settings(TEMPLATE / ".claude" / "settings.json", settings)
        if missing:
            out.append((f"add the template's permission rules to .claude/settings.json ({', '.join(missing)}); "
                        "nothing is removed", lambda: merge_settings(TEMPLATE / ".claude" / "settings.json", settings)))
    cfg = target / "homelab.yaml"
    if cfg.exists():
        r = subprocess.run([hmlib.yq_bin(), "-o=json", ".issues // {} | keys", str(cfg)], capture_output=True,
                           text=True, timeout=hmlib.YQ_TIMEOUT)
        try:
            stale = [k for k in json.loads(r.stdout or "[]") if k in OLD_ISSUES_KEYS]
        except ValueError:
            stale = []
        if stale:
            def fix_yaml(cfg=cfg):
                f = subprocess.run([hmlib.yq_bin(), '.issues.file // "skill_issues.md"', str(cfg)],
                                   capture_output=True, text=True,
                                   timeout=hmlib.YQ_TIMEOUT).stdout.strip() or "skill_issues.md"
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
                hmlib.atomic_write(f, rx.sub(lambda m: new(), f.read_text(), count=1))
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
    site_files = discovery_site_files(target)
    if site_files:
        out.append(site_files)
    else:
        stale_key = network_site_key(target)
        if stale_key:
            out.append(stale_key)
    # a file replaced whole needs none of the older patches to it
    return out[:first] + [o for o in out[first:] if not any(o[0].startswith(r + ":") for r in replaced)]


def discovery_site_files(target: Path):
    """Until 0.28.x discovery/ had a file per site (proxmox-<site>.json, network-<site>.json,
    pve-patch-[<site>-]<node>.json with its -state.json); since 0.29.0 each kind is one file with every site
    inside it, and unifi.json too (GitHub issue #75). Moves them in; a site's data already in the new file wins."""
    d = target / "discovery"
    if not d.is_dir():
        return None
    import hmlib  # noqa: E402
    try:
        default_key = hmlib.site_key(hmlib.site(hmlib.load_config(target)))
    except (hmlib.ConfigError, OSError, ValueError):
        default_key = hmlib.DEFAULT_SITE_KEY

    def load(f: Path):
        try:
            doc = json.loads(f.read_text())
        except (OSError, ValueError):
            return None
        return doc if isinstance(doc, dict) else None

    found: dict[str, dict] = {}     # kind → {site key: data}
    legacy: list[Path] = []          # files moved in, removed afterwards
    rewrite: set[str] = set()        # kinds whose own file is still in the old layout
    for kind in ("proxmox", "network", "unifi"):
        main = load(d / f"{kind}.json")
        if main and not isinstance(main.get("sites"), dict):
            found.setdefault(kind, {})[default_key] = main
            rewrite.add(kind)
        for f in sorted(d.glob(f"{kind}-*.json")):
            name, doc = f.stem[len(kind) + 1:], load(f)
            if doc is not None and hmlib.SITE_NAME_RE.match(name):
                found.setdefault(kind, {}).setdefault(name, doc)
                legacy.append(f)
    for f in sorted(d.glob("pve-patch-*.json")):
        doc = load(f)
        if f.stem.endswith("-state") or not doc or not doc.get("node"):
            continue
        key = doc.get("site") or default_key
        state = f.with_name(f.stem + "-state.json")
        if state.is_file():
            doc["state_before"] = load(state)
            legacy.append(state)
        doc.setdefault("default_site", key == default_key)
        found.setdefault("pve-patch", {}).setdefault(key, {})[doc["node"]] = doc
        legacy.append(f)
    if not found:
        return None

    def move():
        for kind, sites_ in found.items():
            f = d / f"{kind}.json"
            parts = {} if kind in rewrite else hmlib.site_parts(f)
            for key, data in sites_.items():
                if kind == "pve-patch":
                    parts.setdefault(key, {})
                    for node, plan in data.items():
                        parts[key].setdefault(node, plan)
                else:
                    if kind == "network":
                        data.pop("site", None)   # the key in network.json says it (GitHub issue #82)
                    parts.setdefault(key, data)
            hmlib.atomic_write(f, json.dumps({"sites": parts}, indent=2, sort_keys=kind == "network") + "\n")
        for f in legacy:
            f.unlink(missing_ok=True)

    names = sorted({f.name for f in legacy} | {f"{k}.json" for k in rewrite})
    return (f"discovery/: move {', '.join(names)} into one file per kind with every site inside "
            f"({', '.join(sorted(f'{k}.json' for k in found))}; GitHub issue #75)", move)


def network_site_key(target: Path):
    """0.29.x moved network-<site>.json into network.json with its old "site" key, which the next ssh_probe.py or
    nmap_scan.py run of that site drops (GitHub issue #82): drop it now, so it doesn't show up in a later diff."""
    f = target / "discovery" / "network.json"
    try:
        doc = json.loads(f.read_text())
    except (OSError, ValueError):
        return None
    parts = doc.get("sites") if isinstance(doc, dict) else None
    if not isinstance(parts, dict):
        return None
    stale = sorted(k for k, v in parts.items() if isinstance(v, dict) and "site" in v)
    if not stale:
        return None

    def drop():
        for k in stale:
            parts[k].pop("site", None)
        hmlib.atomic_write(f, json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return (f"discovery/network.json: drop the redundant \"site\" key of {', '.join(stale)} (the key it is stored "
            "under says it; GitHub issue #82)", drop)


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
        hmlib.atomic_write(f, t)

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
    configured = subprocess.run([hmlib.yq_bin(), ".issues.file // \"\"", str(cfg)], capture_output=True, text=True,
                                timeout=hmlib.YQ_TIMEOUT).stdout.strip()
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
                hmlib.atomic_write(f, f.read_text().replace(f"`{LEGACY_ISSUES}`", f"`{NEW_ISSUES}`"))
    return (f"rename {LEGACY_ISSUES} → {NEW_ISSUES} (the old name looked like the homelab's own issue list); "
            f"update issues.file and the mentions in CLAUDE.md / README.md", apply)


def suggestions(target: Path) -> tuple[list[dict], list[tuple[dict, str]]]:
    """(opt-in upgrade notes newer than upgrades.reviewed and not settled — except those whose file
    --sync-managed replaces with the template —, reported skill issues fixed by this release)."""
    if not (target / "homelab.yaml").exists():
        return [], []
    import issues  # noqa: E402
    replaced = {r for r, _, _ in unedited_templates(target)}
    notes = upgrade_notes.pending(target, replaced=replaced)
    try:
        fixed = issues.fixed_by_release(issues.load(issues.issues_path(issues.hmlib.load_config(target))))
    except issues.hmlib.ConfigError:
        fixed = []
    return notes, fixed


def covered_notes(target: Path) -> list[dict]:
    """Pending notes that replacing unedited files with the template settles (call before applying). A note
    about several files that still has an edited one left stays a suggestion naming only those (GitHub #76)."""
    if not (target / "homelab.yaml").exists():
        return []
    replaced = {r for r, _, _ in unedited_templates(target)}
    left = {n["id"] for n in upgrade_notes.pending(target, replaced=replaced)}
    return [n for n in upgrade_notes.pending(target) if n["id"] not in left]


def record_reviewed(target: Path):
    config_set.edit_file(target / "homelab.yaml", [("set", upgrade_notes.REVIEWED_KEY, upgrade_notes.installed_version(),
                                                    "upgrade notes reviewed up to this plugin version (init_repo.py --sync-managed)")])


def _reviewed_lags(target: Path) -> bool:
    cfg = target / "homelab.yaml"
    if not cfg.exists():
        return False
    import hmlib  # noqa: E402
    have = upgrade_notes.reviewed_version(hmlib.load_config(target))
    return upgrade_notes.vtuple(have) < upgrade_notes.vtuple(upgrade_notes.installed_version())


def sync_managed(target: Path, dry_run: bool) -> int:
    steps = upgrades(target)
    covered = covered_notes(target)
    notes, fixed = suggestions(target)
    lags = _reviewed_lags(target)
    if not (steps or notes or fixed or lags):
        print("Up to date with the plugin — nothing to change.")
        return 0
    if steps:
        print("One-time updates" + (" (applied by this command):" if dry_run else ":"))
    for desc, apply in steps:
        if not dry_run:
            apply()
        print("  " + ("would " if dry_run else "") + desc)
    if covered:
        print("  Those replacements bring in these changes of newer releases:")
        for n in covered:
            print(f"    [{n['version']} · {n['id']}] {n['text']}")
            if n.get("after_replace"):
                print(f"      → still to do: {n['after_replace']}")
    if notes:
        print("Suggested by newer releases (opt-in — not applied; ask the user for each):")
        print("\n".join("  " + upgrade_notes.describe(n) for n in notes))
        print("    → settle each one: apply it (a note whose change is in the repo drops out by itself), or record the "
              "user's no with `upgrade_notes.py --decline ID` (a manual step done: `--done ID`). They are offered again "
              "until then.")
    if fixed:
        print("Reported skill issues fixed by the installed release (tell the user):")
        for i, v in fixed:
            print(f"  {i['id']} (#{i['github_number']}) fixed in {v}: {i['title']}")
        print("    → mark them resolved with their yes: `issues.py fixed --apply`")
    have = upgrade_notes.installed_version()
    if dry_run:
        if steps:
            print("A run without --dry-run applies the one-time updates.")
        if lags and not notes:
            print(f"A run without --dry-run records upgrades.reviewed = {have}.")
        return 0
    if lags and not notes:
        upgrade_notes.mark_reviewed(target)
        print(f"Recorded upgrades.reviewed = {have} (no suggestions left to settle).")
    elif notes:
        print(f"upgrades.reviewed stays at the old version until every suggestion is settled; run --sync-managed "
              "again afterwards.")
    if steps or lags:
        print("Review with `git diff` / `git status`, then commit.")
    return 0


SITE_TF = """# This environment belongs to site "{name}" (homelab.yaml sites:). with_secrets.py sets TF_VAR_proxmox_site to the
# site of the Proxmox token it injects, so a plan run with another site's token stops here instead of changing the
# wrong Proxmox. Written by init_repo.py --add-site.
variable "proxmox_site" {{
  type        = string
  default     = null
  description = "Site of the injected Proxmox token (set by with_secrets.py)."
  validation {{
    condition     = var.proxmox_site == "{name}"
    error_message = "This is the OpenTofu environment of site {name}: run it under with_secrets.py with that site's Proxmox token."
  }}
}}
"""
SITE_GROUP_VARS = """# Settings for the hosts of site {name} (inventory group site_{name}): DNS, NTP, mirrors, proxies.
# The priority makes them win over OS groups (linux, rocky, …) on purpose instead of by alphabetical order.
ansible_group_priority: 10
"""


def add_site(target: Path, name: str, dry_run: bool) -> int:
    """Scaffold a site that is already listed in homelab.yaml (sites:). Never overwrites a file."""
    import hmlib
    try:
        cfg = hmlib.load_config(target)
        st = hmlib.site(cfg, name)
    except hmlib.ConfigError as e:
        print(f"init_repo: {e}", file=sys.stderr)
        print(f"Add it first: config_set.py 'sites+={{name: {name}, label: …, proxmox: {{endpoint: …, tokens: …}}}}'",
              file=sys.stderr)
        return 3
    comps = current_components(target)
    files: dict[str, str] = {}
    if "proxmox" in comps and not st["default"]:   # the default site uses the top-level settings and environment
        env = f"tofu/environments/{hmlib.tofu_env(cfg, name)}"
        src = TEMPLATE / "tofu" / "environments" / "homelab"
        for f in sorted(src.iterdir()):
            if f.is_file() and f.name != ".DS_Store":
                files[f"{env}/{f.name}"] = f.read_text()
        files[f"{env}/site.tf"] = SITE_TF.format(name=name)
        default_env = target / "tofu" / "environments" / hmlib.default_env(cfg)
        if default_env.is_dir():
            files[f"{default_env.relative_to(target).as_posix()}/site.tf"] = SITE_TF.format(name=hmlib.site(cfg)["name"])
    if "ansible" in comps:
        files[f"ansible/inventory/managed/group_vars/site_{name}.yml"] = SITE_GROUP_VARS.format(name=name)
    created = [rel for rel in files if not (target / rel).exists()]
    for rel in created:
        if not dry_run:
            (target / rel).parent.mkdir(parents=True, exist_ok=True)
            (target / rel).write_text(files[rel])
    print(f"Site {hmlib.site_title(st)}: {'would create' if dry_run else 'created'} {len(created)} file(s)")
    for rel in created:
        print(f"  + {rel}")
    if "proxmox" in comps and st["proxmox"] and not st["default"]:
        env = hmlib.tofu_env(cfg, name)
        print(f"Next: fill `defaults` in tofu/environments/{env}/homelab.auto.tfvars from sites[{name}].proxmox, then "
              f"`tofu_init.py --site {name}`; run plans with the site's token "
              f"({hmlib.proxmox_token_name(st['proxmox'], 'provisioning')}).")
    gaps = hmlib.default_site_gaps(cfg, target)
    if gaps and not st["default"]:
        default = hmlib.site(cfg)["name"]
        print(f"The default site {default} isn't explicit yet ({', '.join(gaps)}): with two sites an untagged VLAN "
              f"or a host in no site group is ambiguous. `init_repo.py --name-default-site {default} --dry-run` "
              "shows the steps; run each with the user's yes.")
    return 0


NAME_STEPS = ("ranges", "vlans", "group")


def _sites_with_ranges(text: str, raw: list, name: str, ranges: list[str]) -> str | None:
    """homelab.yaml with `ranges:` inserted under a block-style `- name: <name>` item of sites:; None if the
    item is not written that way (the caller then rewrites the list)."""
    lines = text.splitlines(True)
    start = next((i for i, l in enumerate(lines) if re.match(r"^sites:", l)), None)
    if start is None:
        return None
    for i in range(start + 1, len(lines)):
        l = lines[i]
        if l.strip() and not l.startswith((" ", "-", "#")):
            return None   # past the sites: block
        m = re.match(rf"""^(\s*)- name:\s*["']?{re.escape(name)}["']?\s*(#.*)?$""", l.rstrip("\n"))
        if m:
            ind = m.group(1) + "  "
            lines.insert(i + 1, f"{ind}ranges: {config_set.render(ranges)}\n")
            return "".join(lines)
    return None


def _yaml_hosts(obj, out: set):
    """Host names under every `hosts:` mapping of an inventory file (yq JSON)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "hosts" and isinstance(v, dict):
                out.update(v)
            else:
                _yaml_hosts(v, out)


def _loose_hosts(target: Path) -> tuple[list[str], list[str], str | None]:
    """(hosts in no site_<name> group, of them the ones only in generated tofu_hosts*.yml, error)."""
    import hmlib
    ansible = target / "ansible"
    data, note = hmlib.ansible_inventory(target)
    if data is None:
        return [], [], "ansible-inventory is not available or failed: " + note
    groups = hmlib.inventory_groups(data)
    loose = sorted(h for h, gs in groups.items() if not hmlib.host_sites(gs))
    managed, generated = set(), set()
    for f in sorted((ansible / "inventory" / "managed").glob("*.y*ml")):
        found: set = set()
        _yaml_hosts(config_set.yq_json(f.read_text()), found)
        (generated if f.name.startswith("tofu_hosts") else managed).update(found)
    return loose, sorted(h for h in loose if h in generated and h not in managed), None


def _hosts_with_group(text: str, group: str, hosts: list[str]) -> str | None:
    """hosts.yml with `group` (listing hosts) added as the first child of all:; None if `all: children:` is not
    written as a block."""
    lines = text.splitlines(True)
    top = next((i for i, l in enumerate(lines) if re.match(r"^all:\s*(#.*)?$", l)), None)
    if top is None:
        return None
    ch = next((i for i in range(top + 1, len(lines)) if re.match(r"^\s+children:\s*(#.*)?$", lines[i])), None)
    if ch is None:
        return None
    nxt = next((l for l in lines[ch + 1:] if l.strip() and not l.lstrip().startswith("#")), "")
    base = len(lines[ch]) - len(lines[ch].lstrip())
    ind = " " * max(len(nxt) - len(nxt.lstrip()), base + 2)
    block = [f"{ind}{group}:{' ' * max(1, 22 - len(group) - len(ind))}# the default site (homelab.yaml sites[0]): "
             f"hosts of other sites go in their site_<name>\n"]
    block += [f"{ind}  hosts:\n"] + [f"{ind}    {h}:\n" for h in hosts] if hosts else [f"{ind}  hosts: {{}}\n"]
    lines[ch + 1:ch + 1] = block
    return "".join(lines)


def name_default_site(target: Path, name: str, steps: list[str], dry_run: bool) -> int:
    """Make the default site explicit (GitHub issue #65): name it in sites:, give it ranges, tag the VLANs without a
    site with it and put the inventory hosts of no site in site_<name>. Each step only with the user's yes."""
    import hmlib
    bad = [x for x in steps if x not in NAME_STEPS]
    if bad:
        print(f"init_repo: unknown step(s) {', '.join(bad)} (steps: {', '.join(NAME_STEPS)}).", file=sys.stderr)
        return 2
    cfg_file = target / "homelab.yaml"
    try:
        cfg = hmlib.load_config(target)
        raw = cfg.get("sites") or []
        if raw and raw[0].get("name") != name:
            raise hmlib.ConfigError(f"the default site (sites[0]) is already named {raw[0].get('name')!r}; site "
                                    "names can't be changed yet.")
        if not raw:   # validate the name the way sites: does
            hmlib.sites({**cfg, "sites": [{"name": name}]})
    except hmlib.ConfigError as e:
        print(f"init_repo: {e}", file=sys.stderr)
        return 3
    verb = "would" if dry_run else "will"
    print(f"Default site {name}: {'dry run' if dry_run else 'applying'} — {', '.join(steps) or 'name only'}")
    text = cfg_file.read_text()
    doc = config_set.yq_json(text)
    want_sites = [dict(x) for x in raw] or [{"name": name}]
    if not raw:
        print(f"  name: sites: [{{name: {name}}}] — the existing location becomes site {name}")
    if "ranges" in steps:
        if want_sites[0].get("ranges"):
            print(f"  ranges: already {', '.join(map(str, want_sites[0]['ranges']))}")
        else:
            prop = hmlib.proposed_default_ranges({**cfg, "sites": want_sites})
            if prop:
                want_sites[0]["ranges"] = prop
                print(f"  ranges: {', '.join(prop)} (network.authorized_ranges and the VLAN CIDRs of this site; "
                      "check that every one is at this location)")
            else:
                print(f"  ranges: nothing to propose — set them by hand: config_set.py can't edit list items, "
                      f"edit sites[0] in homelab.yaml")
    new_text = text
    if want_sites != raw:
        inserted = _sites_with_ranges(text, raw, name, want_sites[0]["ranges"]) if raw and "ranges" in want_sites[0] \
            else None
        if inserted is not None:
            new_text = inserted
        else:
            new_text, _ = config_set.apply_ops(text, doc, [("set", "sites", want_sites)])
    want_vlans = None
    if "vlans" in steps:
        vl = hmlib.get(cfg, "network.vlans", []) or []
        untagged = [v for v in vl if isinstance(v, dict) and v.get("site") in (None, "")]
        if untagged:
            want_vlans = [{**v, "site": name} if isinstance(v, dict) and v.get("site") in (None, "") else v for v in vl]
            new_text, _ = config_set.apply_ops(new_text, config_set.yq_json(new_text),
                                               [("set", "network.vlans", want_vlans)])
            print(f"  vlans: site: {name} on " + ", ".join(f"{v.get('id')}{' ' + str(v['name']) if v.get('name') else ''}"
                                                       for v in untagged)
                  + f" (a VLAN every site has: site: {hmlib.EVERY_SITE} instead)")
        else:
            print("  vlans: every VLAN already names a site")
    if new_text != text:
        expect = {**doc, **({"sites": want_sites} if want_sites != raw else {})}
        if want_vlans is not None:
            expect["network"] = {**(doc.get("network") or {}), "vlans": want_vlans}
        try:
            if config_set._norm(config_set.yq_json(new_text)) != config_set._norm(expect):
                raise config_set.EditError("the edited homelab.yaml doesn't match the intended change")
            hmlib.sites(config_set.yq_json(new_text))
        except (config_set.EditError, hmlib.ConfigError) as e:
            print(f"init_repo: {e}; nothing was written.", file=sys.stderr)
            return 1
        sys.stdout.writelines("    " + l for l in config_set.difflib.unified_diff(
            text.splitlines(True), new_text.splitlines(True), "a/homelab.yaml", "b/homelab.yaml"))
        if not dry_run:
            hmlib.atomic_write(cfg_file, new_text)
    files = {}
    if "group" in steps:
        hosts_file = target / "ansible" / "inventory" / "managed" / "hosts.yml"
        group = hmlib.SITE_GROUP_PREFIX + name
        if not hosts_file.is_file():
            print("  group: no ansible/inventory/managed/hosts.yml (ansible component not enabled)")
        elif hmlib.has_site_group(target, name):
            loose, _, err = _loose_hosts(target)
            print(f"  group: {group} exists" + (f"; in no site group: {', '.join(loose)} — add them to it (or to "
                                                 "their site's group) by hand" if loose else "")
                  + (f" ({err})" if err else ""))
        else:
            loose, generated, err = _loose_hosts(target)
            if err:
                print(f"  group: {err} — can't tell which hosts are in no site group; nothing changed",
                      file=sys.stderr)
                return 1
            listed = [h for h in loose if h not in generated]
            new_hosts = _hosts_with_group(hosts_file.read_text(), group, listed)
            if new_hosts is None:
                print(f"  group: hosts.yml has no block-style `all: children:`; add {group} by hand with: "
                      + ", ".join(listed), file=sys.stderr)
                return 1
            got = (((config_set.yq_json(new_hosts).get("all") or {}).get("children") or {}).get(group) or {})
            if sorted((got.get("hosts") or {})) != listed:
                print(f"init_repo: adding {group} to hosts.yml didn't give the intended result; nothing changed.",
                      file=sys.stderr)
                return 1
            print(f"  group: {group} in hosts.yml with {len(listed)} host(s): {', '.join(listed) or 'none yet'}")
            if generated:
                print(f"         generated by tofu_to_inventory.py ({', '.join(generated)}): run it again, it puts "
                      f"them in {group}")
            if not dry_run:
                hmlib.atomic_write(hosts_file, new_hosts)
            files[f"ansible/inventory/managed/group_vars/{group}.yml"] = SITE_GROUP_VARS.format(name=name)
    for rel, body in files.items():
        if not (target / rel).exists():
            print(f"  + {rel}")
            if not dry_run:
                (target / rel).write_text(body)
    print("Nothing written (dry run)." if dry_run else "Review with `git diff`, then commit.")
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
    r = subprocess.run([hmlib.yq_bin(), "-o=json", ".components // {}", str(cfg)], capture_output=True, text=True,
                       timeout=hmlib.YQ_TIMEOUT)
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
    ap.add_argument("--add-site", metavar="NAME", help="scaffold a site already listed in homelab.yaml sites:")
    ap.add_argument("--name-default-site", metavar="NAME",
                    help="make the existing (default) site explicit: name, ranges, VLAN tags, site_<name> group")
    ap.add_argument("--steps", help=f"with --name-default-site: comma-separated, default all ({','.join(NAME_STEPS)})")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.list_components:
        for n, (desc, req, _) in COMPONENTS.items():
            print(f"{n:<11} {desc}" + (f"  (needs {', '.join(req)})" if req else ""))
        return 0
    try:   # every other mode reads or edits homelab.yaml: refuse before writing anything (GitHub issue #119)
        hmlib.yq_bin()
    except hmlib.ConfigError as e:
        print(f"init_repo: {e} Nothing was written.", file=sys.stderr)
        return 2
    target = Path(a.target).resolve()
    if a.sync_managed:
        return sync_managed(target, a.dry_run)
    if a.add_site:
        return add_site(target, a.add_site, a.dry_run)
    if a.name_default_site:
        steps = [x.strip() for x in a.steps.split(",") if x.strip()] if a.steps is not None else list(NAME_STEPS)
        return name_default_site(target, a.name_default_site, steps, a.dry_run)
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
        if "homelab.yaml" in created:  # a new repo has every current feature: no upgrade notes for it
            record_reviewed(target)
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
            hmlib.atomic_write(settings, json.dumps(data, indent=2) + "\n")

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
    try:
        sys.exit(main())
    except subprocess.TimeoutExpired as e:   # yq or another tool hung: a clear line, not a traceback
        print(f"init_repo: {Path(str(e.cmd[0])).name} did not finish in {e.timeout:g} s; nothing after it was done.",
              file=sys.stderr)
        sys.exit(2)
