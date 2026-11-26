#!/usr/bin/env python3
"""Print the CHANGELOG.md section for a version, as GitHub release notes.

    python3 .github/release_notes.py v0.5.0 [--check-version]
    python3 .github/release_notes.py --lint [X.Y.Z]      # check a section's layout (default: the top one)

--check-version also fails when .claude-plugin/plugin.json has a different version,
so a tag can't be released with a manifest that says otherwise.

Sections from STYLED_FROM on follow the layout in CLAUDE.md ("CHANGELOG sections"): a short summary paragraph,
then `### New`, `### Improved`, `### Fixed` (each optional, in that order) with one `- **Headline.** text` bullet per
change, and an optional `### Upgrading`. Older sections are printed as they are.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "mhaluska/homelab-manager-skill"
STYLED_FROM = (0, 65, 0)
HEADINGS = ["New", "Improved", "Fixed", "Upgrading"]
MAX_BULLET_LINES = 6


def vtuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def section(changelog: str, version: str) -> str:
    m = re.search(rf"^## {re.escape(version)}(?![\w.])[^\n]*\n(.*?)(?=^## |\Z)", changelog, re.S | re.M)
    if not m:
        raise SystemExit(f"CHANGELOG.md has no '## {version}' section")
    body = m.group(1).strip()
    if not body:
        raise SystemExit(f"CHANGELOG.md section {version} is empty")
    return body


def versions(changelog: str) -> list[str]:
    return re.findall(r"^## (\d+\.\d+\.\d+)\b", changelog, re.M)


def previous(changelog: str, version: str) -> str | None:
    """The newest released version older than `version`, from the CHANGELOG."""
    older = [v for v in versions(changelog) if vtuple(v) < vtuple(version)]
    return max(older, key=vtuple) if older else None


def lint(body: str) -> list[str]:
    """Problems with a section's layout (see the module docstring); [] when it is fine."""
    problems = []
    parts = re.split(r"^### (.*)\n", body, flags=re.M)
    summary, rest = parts[0].strip(), parts[1:]
    if not summary:
        problems.append("no summary paragraph before the first ### heading")
    elif summary.startswith(("-", "*", "#")):
        problems.append("the summary must be plain sentences, not a list or heading")
    elif len(summary) > 400:
        problems.append(f"the summary is {len(summary)} characters: keep it to one or two sentences (≤ 400)")
    heads = [h.strip() for h in rest[0::2]]
    for h in heads:
        if h not in HEADINGS:
            problems.append(f"unknown heading '### {h}' (use {', '.join(HEADINGS)})")
    known = [h for h in heads if h in HEADINGS]
    if known != sorted(known, key=HEADINGS.index) or len(known) != len(set(known)):
        problems.append(f"headings out of order or repeated: {', '.join(heads)} (order: {', '.join(HEADINGS)})")
    if not any(h in ("New", "Improved", "Fixed") for h in heads):
        problems.append("no ### New, ### Improved or ### Fixed section")
    for head, text in zip(heads, rest[1::2]):
        bullets = re.split(r"^(?=- )", text.strip(), flags=re.M)
        bullets = [b for b in bullets if b.strip()]
        if not bullets:
            problems.append(f"'### {head}' is empty")
        for b in bullets:
            first = b.splitlines()[0]
            if not b.startswith("- "):
                problems.append(f"'### {head}': text outside a bullet: {first[:60]!r}")
                continue
            if head != "Upgrading" and not re.match(r"- \*\*[^*]+[.!?]\*\*( |$)", b):
                problems.append(f"'### {head}': start with a bold headline ending in a full stop: {first[:60]!r}")
            if len(b.strip().splitlines()) > MAX_BULLET_LINES:
                problems.append(f"'### {head}': bullet longer than {MAX_BULLET_LINES} lines: {first[:60]!r}")
    return problems


def styled(version: str) -> bool:
    return vtuple(version) >= STYLED_FROM


def render(changelog: str, version: str) -> str:
    body = section(changelog, version)
    prev = previous(changelog, version)
    footer = ["---", "**Install**", "```", f"/plugin marketplace add {REPO}",
              "/plugin install homelab-manager@homelab-manager-skill", "```",
              "**Update:** `/plugin marketplace update homelab-manager-skill`, then start a new session in your "
              "homelab repository: it offers the repo updates this release brings."]
    if prev:
        footer.append(f"\n**Full list of changes:** [v{prev}…v{version}](https://github.com/{REPO}/compare/"
                      f"v{prev}...v{version})")
    return body + "\n\n" + "\n".join(footer)


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    changelog = (ROOT / "CHANGELOG.md").read_text()
    if argv[0] == "--lint":
        top = re.search(r"^## ([^\n]*)\n(.*?)(?=^## |\Z)", changelog, re.M | re.S)
        if len(argv) > 1:
            label, body = argv[1], section(changelog, argv[1])
        elif top:
            label, body = top.group(1).split(" ")[0], top.group(2).strip()
        else:
            raise SystemExit("CHANGELOG.md has no section")
        problems = lint(body)
        for p in problems:
            print(f"CHANGELOG {label}: {p}", file=sys.stderr)
        return 1 if problems else 0
    tag = argv[0]
    version = tag.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"not a release tag: {tag}")
    if "--check-version" in argv:
        have = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
        if have != version:
            raise SystemExit(f"plugin.json version {have} != tag {tag}")
    print(render(changelog, version))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
