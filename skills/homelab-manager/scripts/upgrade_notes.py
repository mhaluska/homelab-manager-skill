#!/usr/bin/env python3
"""Upgrade advisor: opt-in changes newer plugin releases suggest for an existing homelab repo.

    upgrade_notes.py [--all] [--json]    # notes that apply here and are newer than upgrades.reviewed
                                         # (--all: ignore the reviewed version)
    upgrade_notes.py --decline ID [ID…]  # the user said no: never offer these notes again
    upgrade_notes.py --done ID [ID…]     # applied, for notes whose condition can't see it (manual steps)

Reads assets/upgrade-notes.json (machine-readable, one entry per opt-in change and release) and checks
each note against the repo: enabled components, homelab.yaml keys, user-owned files, snapshots.
Notes are never applied automatically: they are suggestions that need the user's yes.
init_repo.py --sync-managed shows them (with the one-time updates it applies itself). A note stays pending
until it is settled: applied (its `when` no longer holds), recorded with --done, or declined with --decline
(upgrades.done / upgrades.declined in homelab.yaml). Only when no note is pending does --sync-managed move
upgrades.reviewed to the installed version and drop the settled ids it no longer needs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hmlib  # noqa: E402

NOTES = HERE.parent / "assets" / "upgrade-notes.json"
TEMPLATE = HERE.parent / "assets" / "repo-template"
REVIEWED_KEY = "upgrades.reviewed"
DECLINED_KEY, DONE_KEY = "upgrades.declined", "upgrades.done"
KIND_LABEL = {"config": "config", "template": "template section", "regenerate": "regenerate", "manual": "manual step"}


def vtuple(v) -> tuple[int, ...]:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def installed_version() -> str:
    return json.loads((hmlib.PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]


def reviewed_version(cfg: dict) -> str:
    return str(hmlib.get(cfg, REVIEWED_KEY) or "")


def settled(cfg: dict) -> set[str]:
    """Note ids the user declined or marked done."""
    out = set()
    for key in (DECLINED_KEY, DONE_KEY):
        v = hmlib.get(cfg, key) or []
        out |= {str(x) for x in v} if isinstance(v, list) else set()
    return out


def all_notes() -> list[dict]:
    return json.loads(NOTES.read_text())["notes"]


def _enabled(cfg: dict, comp: str) -> bool:
    comps = cfg.get("components")
    return True if not isinstance(comps, dict) else comps.get(comp) is True  # no section = older repo: all


def _check(note: dict, cfg: dict, root: Path) -> tuple[bool, dict]:
    """(applies, placeholders) for one note."""
    w, ph = note.get("when") or {}, {"HM": str(HERE.parent)}
    if w.get("component") and not _enabled(cfg, w["component"]):
        return False, ph
    if w.get("config_empty") and hmlib.config_value(cfg, w["config_empty"]) not in (None, "", [], {}):
        return False, ph
    if w.get("config_set") and hmlib.config_value(cfg, w["config_set"]) in (None, "", [], {}):
        return False, ph
    if w.get("file_lacks"):
        rel, text = w["file_lacks"]
        f = root / rel
        if not f.is_file() or text in f.read_text(errors="replace"):
            return False, ph
        ph["template"] = str(TEMPLATE / rel)
    if w.get("file_has"):
        rel, text = w["file_has"]
        f = root / rel
        if not f.is_file() or text not in f.read_text(errors="replace"):
            return False, ph
        ph["template"] = str(TEMPLATE / rel)
    if w.get("file_missing"):
        rel = w["file_missing"]
        if (root / rel).exists():
            return False, ph
        ph["template"] = str(TEMPLATE / rel)
    if w.get("multi_site"):   # two or more sites in homelab.yaml
        try:
            if len(hmlib.sites(cfg)) < 2:
                return False, ph
        except hmlib.ConfigError:
            return False, ph
    if w.get("default_site_implicit"):   # two or more sites, the default one not explicit (GitHub issue #65)
        try:
            if len(hmlib.sites(cfg)) < 2 or not hmlib.default_site_gaps(cfg, root):
                return False, ph
            ph["site"] = hmlib.site(cfg)["name"]
        except hmlib.ConfigError:
            return False, ph
    if w.get("agent_ips_unread"):
        try:
            agent = (json.loads((root / "discovery" / "proxmox.json").read_text()).get("guest_ip_sources") or {}).get("agent")
        except (OSError, ValueError):
            return False, ph
        if not agent or agent == "ok" or agent == "not queried":
            return False, ph
    if w.get("vmids_outside_ranges"):
        try:
            guests = json.loads((root / "discovery" / "proxmox.json").read_text()).get("guests") or []
        except (OSError, ValueError):
            return False, ph
        fit = hmlib.vmid_fit(cfg, guests)
        if not fit:
            return False, ph
        ph["detail"] = fit
    return True, ph


def pending(root: Path, everything: bool = False) -> list[dict]:
    """Notes that apply to the repo at `root`, from releases after its reviewed version up to the installed one."""
    cfg = hmlib.load_config(root)
    since = (0, 0, 0) if everything else vtuple(reviewed_version(cfg))
    upto = vtuple(installed_version())
    done = settled(cfg)
    out = []
    for n in all_notes():
        if not since < vtuple(n["version"]) <= upto or n["id"] in done:
            continue
        ok, ph = _check(n, cfg, Path(root))
        if ok:
            n = dict(n)
            for field in ("action", "after_replace"):
                if field in n:
                    for k, v in ph.items():
                        n[field] = n[field].replace("{" + k + "}", v)
            out.append(n)
    return out


def describe(n: dict) -> str:
    return (f"[{n['version']} · {KIND_LABEL.get(n['kind'], n['kind'])} · {n['id']}] {n['text']}\n"
            f"    → {n['action']}")


def settle(root: Path, key: str, ids: list[str]) -> str:
    """Record note ids under upgrades.declined / upgrades.done; returns the diff."""
    import config_set  # noqa: E402
    known = {n["id"] for n in all_notes()}
    bad = [i for i in ids if i not in known]
    if bad:
        raise SystemExit(f"upgrade_notes: unknown note id(s): {', '.join(bad)}")
    return config_set.edit_file(Path(root) / "homelab.yaml", [("add", key, i) for i in ids])


def mark_reviewed(root: Path) -> str:
    """Move upgrades.reviewed to the installed version (call only when nothing is pending) and drop the
    declined/done ids of notes it now covers."""
    import config_set  # noqa: E402
    cfg = hmlib.load_config(root)
    have = installed_version()
    covered = {n["id"] for n in all_notes() if vtuple(n["version"]) <= vtuple(have)}
    ops = [("set", REVIEWED_KEY, have, "upgrade notes settled up to this plugin version (init_repo.py --sync-managed)")]
    for key in (DECLINED_KEY, DONE_KEY):
        cur = hmlib.get(cfg, key)
        if isinstance(cur, list):
            keep = [x for x in cur if str(x) not in covered]
            ops.append(("set", key, keep) if keep else ("delete", key))
    return config_set.edit_file(Path(root) / "homelab.yaml", ops)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="ignore upgrades.reviewed")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--decline", nargs="+", metavar="ID", help="the user declined these notes: don't offer them again")
    ap.add_argument("--done", nargs="+", metavar="ID", help="these notes were applied (for ones whose condition stays)")
    a = ap.parse_args()
    root = hmlib.find_repo_root()
    if not root:
        print("upgrade_notes: no homelab.yaml found", file=sys.stderr)
        return 3
    if a.decline or a.done:
        for key, ids in ((DECLINED_KEY, a.decline), (DONE_KEY, a.done)):
            if ids:
                settle(root, key, ids)
                print(f"Recorded in {key}: {', '.join(ids)}")
        left = pending(root)
        print(f"{len(left)} suggestion(s) still pending." if left else
              "No suggestions left: run init_repo.py --sync-managed to record the review.")
        return 0
    notes = pending(root, a.all)
    if a.json:
        print(json.dumps(notes, indent=2, ensure_ascii=False))
    elif notes:
        print("\n".join(describe(n) for n in notes))
    else:
        print("No suggested changes from newer releases.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
