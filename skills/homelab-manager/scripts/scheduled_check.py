#!/usr/bin/env python3
"""A scheduled read-only check of the homelab, run by launchd on this Mac (GitHub issue #150).

  scheduled_check.py status                    is it installed, when, which plugin version, the last run
  scheduled_check.py install --time 07:40      a LaunchAgent that runs `run` every day at that time (user's yes)
  scheduled_check.py uninstall                 remove it (user's yes)
  scheduled_check.py run                       what launchd runs; also by hand

`run` does a fixed list of read-only steps, none of them configurable, so the job can't be turned into anything
else: refresh the Proxmox snapshot with the read-only token (`proxmox_inventory.py --all-sites`, writes only
discovery/proxmox*.json, commits nothing), render OVERVIEW.md in memory (nothing is written) and show a macOS
notification when there are warnings that weren't in the last notification, or when a step could not run.
No SSH, no Ansible (a LaunchAgent has no SSH agent or sudo to answer), no e-mail or webhook.

Exit codes (references/discovery.md "Exit codes"): 0 nothing to report, 1 warnings, 3 configuration, 4 a step
could not run. The guard asks for install and uninstall; status and run need no yes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

LABEL_PREFIX = "com.homelab-manager.scheduled-check"
AGENTS = Path.home() / "Library" / "LaunchAgents"
LOGS = Path.home() / "Library" / "Logs" / "homelab-manager"
STATE = Path.home() / ".local" / "state" / "homelab-manager"
SCRIPT = Path(__file__).resolve()
# launchd starts jobs with a bare PATH: yq, tofu and the rest are in Homebrew's
PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
STEP_TIMEOUT = 900
NOTIFY_MAX = 230   # macOS cuts a notification's text; keep the end readable


def repo_id(root: Path) -> str:
    return hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:10]


def label(root: Path) -> str:
    return f"{LABEL_PREFIX}.{repo_id(root)}"


def plist_path(root: Path) -> Path:
    return AGENTS / f"{label(root)}.plist"


def parse_time(text: str) -> tuple[int, int]:
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", text or "")
    if not m:
        raise ValueError(f"--time {text!r}: give HH:MM, e.g. 07:40")
    return int(m.group(1)), int(m.group(2))


def plist(root: Path, hour: int, minute: int, script: Path = SCRIPT) -> dict:
    log = LOGS / f"scheduled-check-{repo_id(root)}.log"
    return {"Label": label(root),
            "ProgramArguments": ["/usr/bin/python3", str(script), "run"],
            "WorkingDirectory": str(root.resolve()),
            "StartCalendarInterval": {"Hour": hour, "Minute": minute},
            "EnvironmentVariables": {"PATH": PATH},
            "StandardOutPath": str(log), "StandardErrorPath": str(log),
            "ProcessType": "Background", "LowPriorityIO": True}


def installed(root: Path) -> dict | None:
    p = plist_path(root)
    if not p.is_file():
        return None
    try:
        return plistlib.loads(p.read_bytes())
    except (plistlib.InvalidFileException, ValueError, OSError):
        return {}


def outdated(root: Path, script: Path = SCRIPT) -> dict | None:
    """The installed job's plist when it runs another copy of this script (an older plugin version):
    init_repo.py --sync-managed points it at this one."""
    pl = installed(root)
    if not pl:
        return None
    args = pl.get("ProgramArguments") or []
    return pl if len(args) > 1 and args[1] != str(script) else None


def write_plist(root: Path, data: dict) -> Path:
    p = plist_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    hmlib.atomic_write(p, plistlib.dumps(data).decode())
    return p


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True, timeout=30)


def load(p: Path) -> str | None:
    """(Re)load the job; an error text, or None."""
    domain = f"gui/{os.getuid()}"
    launchctl("bootout", domain, str(p))   # not loaded yet: fails, fine
    r = launchctl("bootstrap", domain, str(p))
    return None if r.returncode == 0 else (r.stderr or r.stdout).strip() or f"launchctl exit {r.returncode}"


def repoint(root: Path, script: Path = SCRIPT) -> str | None:
    """Point an installed job at this copy of the script, keeping its time; an error text, or None."""
    pl = installed(root)
    if not pl:
        return None
    when = pl.get("StartCalendarInterval") or {}
    return load(write_plist(root, plist(root, int(when.get("Hour", 7)), int(when.get("Minute", 40)), script)))


# --------------------------------------------------------------------------- run

def notify(text: str, title: str) -> None:
    """A macOS notification. The text (from host data: untrusted) goes in as an argument, never into the script."""
    if len(text) > NOTIFY_MAX:
        text = text[:NOTIFY_MAX - 1] + "…"
    subprocess.run(["/usr/bin/osascript", "-e", "on run argv", "-e",
                    "display notification (item 1 of argv) with title (item 2 of argv)", "-e", "end run",
                    text, title], capture_output=True, timeout=30)


def glance_warnings(text: str) -> list[str]:
    """The categories of the "Warnings (details under Health)" line at the top of a rendered OVERVIEW.md."""
    m = re.search(r"^Warnings \(details under \[Health\]\(#health\)\): (.*)\.$", text, re.M)
    return [w.strip() for w in m.group(1).split(" · ")] if m else []


def keychain_unlocked() -> bool:
    r = subprocess.run(["/usr/bin/security", "show-keychain-info"], capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def run_steps(cfg: dict, root: Path) -> tuple[list[str], list[str]]:
    """(warnings, problems): what OVERVIEW.md warns about, and the steps that could not run."""
    problems = []
    if hmlib.get(cfg, "components.proxmox", True) and hmlib.proxmox_sites(cfg):
        if not keychain_unlocked():
            problems.append("the keychain is locked: the Proxmox snapshot was not refreshed")
        else:
            try:
                r = subprocess.run([sys.executable, str(SCRIPT.parent / "proxmox_inventory.py"), "--all-sites"],
                                   cwd=root, capture_output=True, text=True, timeout=STEP_TIMEOUT)
                if r.returncode != 0:
                    last = (r.stderr or r.stdout).strip().splitlines()[-1:] or [f"exit {r.returncode}"]
                    problems.append(f"Proxmox snapshot: {hmlib.clean(last[0], 160)}")
            except subprocess.TimeoutExpired:
                problems.append(f"Proxmox snapshot: no answer within {STEP_TIMEOUT // 60} minutes")
    import overview
    managed, note = hmlib.load_ansible(root)
    return glance_warnings(overview.render(cfg, managed, note)), problems


def state_file(root: Path) -> Path:
    return STATE / f"scheduled-check-{repo_id(root)}.json"


def cmd_run(root: Path | None = None) -> int:
    try:
        cfg = hmlib.load_config(root)
    except hmlib.ConfigError as e:
        print(f"scheduled_check: {e}", file=sys.stderr)
        notify(f"Could not read homelab.yaml: {e}", "homelab: scheduled check")
        return 3
    root = Path(cfg["_root"])
    name = hmlib.get(cfg, "site.name", "") or root.name
    warnings, problems = run_steps(cfg, root)
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    print(f"{stamp} warnings: {len(warnings)}; could not run: {len(problems)}")
    for line in problems + warnings:
        print(f"  {line}")
    sf = state_file(root)
    try:
        before = set(json.loads(sf.read_text()).get("warnings") or [])
    except (OSError, ValueError):
        before = set()
    new = [w for w in warnings if w not in before]
    if problems:
        notify("; ".join(problems), f"homelab {name}: check could not run")
    elif new:
        notify("; ".join(new) + " (OVERVIEW.md → Health)", f"homelab {name}: new warnings")
    sf.parent.mkdir(parents=True, exist_ok=True)
    hmlib.atomic_write(sf, json.dumps({"at": stamp, "warnings": warnings, "problems": problems}, indent=1) + "\n")
    return hmlib.UNREACHABLE if problems else (1 if warnings else 0)


# --------------------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    i = sub.add_parser("install")
    i.add_argument("--time", required=True, help="HH:MM, every day")
    sub.add_parser("uninstall")
    sub.add_parser("run")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        return cmd_run()
    root = hmlib.find_repo_root()
    if not root:
        print("scheduled_check: run it in the homelab repository (no homelab.yaml here).", file=sys.stderr)
        return 3
    root = Path(root)
    if a.cmd == "install":
        try:
            hour, minute = parse_time(a.time)
        except ValueError as e:
            ap.error(str(e))
        err = load(write_plist(root, plist(root, hour, minute)))
        if err:
            print(f"scheduled_check: wrote {plist_path(root)}, but launchctl refused it: {err}", file=sys.stderr)
            return 4
        print(f"Installed: every day at {hour:02d}:{minute:02d}, read-only (Proxmox snapshot, OVERVIEW.md warnings "
              f"as a notification). Log: {LOGS}. Remove with `scheduled_check.py uninstall`.")
        return 0
    if a.cmd == "uninstall":
        p = plist_path(root)
        if not p.exists():
            print("Not installed.")
            return 0
        launchctl("bootout", f"gui/{os.getuid()}", str(p))
        p.unlink()
        print(f"Removed {p}.")
        return 0
    pl = installed(root)
    if pl is None:
        print("Not installed (scheduled_check.py install --time HH:MM, with the user's yes).")
        return 0
    when = pl.get("StartCalendarInterval") or {}
    args = pl.get("ProgramArguments") or []
    print(f"Installed: every day at {int(when.get('Hour', 0)):02d}:{int(when.get('Minute', 0)):02d} "
          f"({plist_path(root)}).")
    if outdated(root):
        print(f"It runs {args[1] if len(args) > 1 else '?'}, not this plugin version: "
              "init_repo.py --sync-managed points it here.")
    try:
        last = json.loads(state_file(root).read_text())
        print(f"Last run {last.get('at')}: {len(last.get('warnings') or [])} warning(s), "
              f"{len(last.get('problems') or [])} step(s) could not run.")
    except (OSError, ValueError):
        print("No run yet.")
    return 0


if __name__ == "__main__":
    sys.exit(hmlib.exit_main(main))
