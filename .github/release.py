#!/usr/bin/env python3
"""Prepare a release: bump the version, date the CHANGELOG section, refresh the template history, commit and tag.

    python3 .github/release.py X.Y.Z [--no-tests]

Refuses (and changes nothing) when X.Y.Z is not newer than plugin.json, the tracked tree has uncommitted changes,
or the CHANGELOG's top section is missing or empty. The top section is `## Unreleased` (renamed to
`## X.Y.Z — <today>`) or already `## X.Y.Z …`. When the repo template changed since the last release tag,
assets/template-history.json is regenerated (it needs the release tags locally). Then the unit tests run
(--no-tests skips them), and the release is committed as `Release X.Y.Z` with an annotated tag vX.Y.Z.
Nothing is pushed: the command to push is printed.
"""
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / ".claude-plugin" / "plugin.json"
CHANGELOG = ROOT / "CHANGELOG.md"
TEMPLATE = "skills/homelab-manager/assets/repo-template/"
HISTORY = "skills/homelab-manager/assets/template-history.json"


def vtuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def git(*args, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=check)


def fail(msg: str) -> int:
    print(f"release: {msg}", file=sys.stderr)
    return 1


def dated_changelog(text: str, version: str, today: str) -> str:
    """The CHANGELOG with its top section named `## version — today`; SystemExit when it can't be."""
    m = re.search(r"^## ([^\n]*)\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not m:
        raise SystemExit("CHANGELOG.md has no section")
    head, body = m.group(1).strip(), m.group(2).strip()
    if head.lower() != "unreleased" and not re.match(rf"{re.escape(version)}\b", head):
        raise SystemExit(f"CHANGELOG.md's top section is '## {head}': name it '## Unreleased' or '## {version}'")
    if not body:
        raise SystemExit(f"CHANGELOG.md's top section '## {head}' is empty")
    if head.lower() == "unreleased":
        head = f"{version} — {today}"
    return text[:m.start()] + f"## {head}\n" + text[m.start(2):]


def _release_notes():
    import importlib.util
    spec = importlib.util.spec_from_file_location("release_notes", Path(__file__).with_name("release_notes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or not re.fullmatch(r"\d+\.\d+\.\d+", args[0]):
        return fail("usage: release.py X.Y.Z [--no-tests] (a version X.Y.Z)")
    version = args[0]
    plugin = json.loads(PLUGIN.read_text())
    if vtuple(version) <= vtuple(plugin["version"]):
        return fail(f"{version} must be newer than plugin.json's {plugin['version']}")
    if git("rev-parse", "-q", "--verify", f"refs/tags/v{version}", check=False).returncode == 0:
        return fail(f"tag v{version} exists already")
    if git("status", "--porcelain", "--untracked-files=no").stdout.strip():
        return fail("the tracked tree has uncommitted changes: commit or stash them first")
    try:
        changelog = dated_changelog(CHANGELOG.read_text(), version, datetime.date.today().isoformat())
    except SystemExit as e:
        return fail(str(e))
    notes = _release_notes()
    if notes.styled(version):
        problems = notes.lint(notes.section(changelog, version))
        if problems:
            return fail("the CHANGELOG section doesn't follow the layout in CLAUDE.md:\n  " + "\n  ".join(problems))

    tags = sorted((t for t in git("tag", "--list", "v*").stdout.split() if re.fullmatch(r"v\d+\.\d+\.\d+", t)),
                  key=lambda t: vtuple(t[1:]))
    template_changed = not tags or git("diff", "--quiet", tags[-1], "HEAD", "--", TEMPLATE, check=False).returncode != 0
    touched = [str(PLUGIN), str(CHANGELOG), str(ROOT / HISTORY)]
    try:
        plugin["version"] = version
        PLUGIN.write_text(json.dumps(plugin, indent=2, ensure_ascii=False) + "\n")
        CHANGELOG.write_text(changelog)
        if template_changed:
            r = subprocess.run([sys.executable, str(ROOT / ".github" / "template_history.py")], cwd=ROOT)
            if r.returncode:
                raise RuntimeError("template_history.py failed")
        if "--no-tests" not in argv:
            print("Running the unit tests…", flush=True)
            r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=ROOT)
            if r.returncode:
                raise RuntimeError("unit tests failed")
        git("add", "--", *[p for p in touched if Path(p).exists()])
        git("commit", "-q", "-m", f"Release {version}")
        git("tag", "-a", f"v{version}", "-m", f"homelab-manager {version}")
    except (RuntimeError, subprocess.CalledProcessError) as e:
        git("checkout", "--", *[p for p in touched if git("ls-files", "--error-unmatch", p, check=False).returncode == 0],
            check=False)
        return fail(f"{e}; the version bump was undone")
    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    print(f"Released {version} locally (commit 'Release {version}', tag v{version}"
          f"{', template history regenerated' if template_changed else ''}). Push it with:\n"
          f"    git push origin {branch} v{version}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
