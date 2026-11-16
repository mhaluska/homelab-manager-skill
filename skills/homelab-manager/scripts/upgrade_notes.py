#!/usr/bin/env python3
"""Upgrade advisor: opt-in changes newer plugin releases suggest for an existing homelab repo.

    upgrade_notes.py [--all] [--json]    # notes that apply here and are newer than upgrades.reviewed
                                         # (--all: ignore the reviewed version)

Reads assets/upgrade-notes.json (machine-readable, one entry per opt-in change and release) and checks
each note against the repo: enabled components, homelab.yaml keys, user-owned files, snapshots.
Notes are never applied automatically: they are suggestions that need the user's yes.
init_repo.py --sync-managed shows them (with the one-time updates it applies itself) and, when run
for real, records the installed version in upgrades.reviewed so the same notes aren't offered again.
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
KIND_LABEL = {"config": "config", "template": "template section", "regenerate": "regenerate", "manual": "manual step"}


def vtuple(v) -> tuple[int, ...]:
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def installed_version() -> str:
    return json.loads((hmlib.PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]


def reviewed_version(cfg: dict) -> str:
    return str(hmlib.get(cfg, REVIEWED_KEY) or "")


def _enabled(cfg: dict, comp: str) -> bool:
    comps = cfg.get("components")
    return True if not isinstance(comps, dict) else comps.get(comp) is True  # no section = older repo: all


def _check(note: dict, cfg: dict, root: Path) -> tuple[bool, dict]:
    """(applies, placeholders) for one note."""
    w, ph = note.get("when") or {}, {"HM": str(HERE.parent)}
    if w.get("component") and not _enabled(cfg, w["component"]):
        return False, ph
    if w.get("config_empty") and hmlib.get(cfg, w["config_empty"]) not in (None, "", [], {}):
        return False, ph
    if w.get("config_set") and hmlib.get(cfg, w["config_set"]) in (None, "", [], {}):
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
    out = []
    for n in json.loads(NOTES.read_text())["notes"]:
        if not since < vtuple(n["version"]) <= upto:
            continue
        ok, ph = _check(n, cfg, Path(root))
        if ok:
            action = n.get("action", "")
            for k, v in ph.items():
                action = action.replace("{" + k + "}", v)
            out.append({**n, "action": action})
    return out


def describe(n: dict) -> str:
    return f"[{n['version']} · {KIND_LABEL.get(n['kind'], n['kind'])}] {n['text']}\n    → {n['action']}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="ignore upgrades.reviewed")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    root = hmlib.find_repo_root()
    if not root:
        print("upgrade_notes: no homelab.yaml found", file=sys.stderr)
        return 3
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
