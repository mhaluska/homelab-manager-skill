#!/usr/bin/env python3
"""Print the CHANGELOG.md section for a version, as GitHub release notes.

    python3 .github/release_notes.py v0.5.0 [--check-version]

--check-version also fails when .claude-plugin/plugin.json has a different version,
so a tag can't be released with a manifest that says otherwise.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "mhaluska/homelab-manager-skill"


def section(changelog: str, version: str) -> str:
    m = re.search(rf"^## {re.escape(version)}\b[^\n]*\n(.*?)(?=^## |\Z)", changelog, re.S | re.M)
    if not m:
        raise SystemExit(f"CHANGELOG.md has no '## {version}' section")
    body = m.group(1).strip()
    if not body:
        raise SystemExit(f"CHANGELOG.md section {version} is empty")
    return body


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    tag = argv[0]
    version = tag.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"not a release tag: {tag}")
    if "--check-version" in argv:
        have = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
        if have != version:
            raise SystemExit(f"plugin.json version {have} != tag {tag}")
    body = section((ROOT / "CHANGELOG.md").read_text(), version)
    print(f"{body}\n\n---\n**Install**\n```\n/plugin marketplace add {REPO}\n"
          f"/plugin install homelab-manager@homelab-manager-skill\n```\n"
          f"**Update**: `/plugin marketplace update homelab-manager-skill`")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
