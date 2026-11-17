#!/usr/bin/env python3
"""English-only check for this repository: code, comments, docs, commit messages, pull requests and issues.

    check_english.py diff BASE HEAD     # lines added between BASE and HEAD, and the commit messages in it
    check_english.py text [FILE]        # a title + body (pull request or issue) from FILE or stdin

Exit 0 = English, 1 = findings (printed as GitHub annotations in `diff` mode, as a list in `text` mode).
Uses hmlib.english_problems (skills/homelab-manager/scripts/hmlib.py), the same check that keeps skill
issues and gh issue/pr writes English. It can't tell an ASCII identifier in another language from an
English one (pocet_hostov), so review still matters.

Skipped: paths matching a glob in .github/language-allowlist, and any line containing `lang: allow`
(for deliberate non-English samples, such as test fixtures for this check).
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "homelab-manager" / "scripts"))
import hmlib  # noqa: E402

MARKER = "lang: allow"
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def allowlist(root: Path) -> list[str]:
    f = root / ".github" / "language-allowlist"
    if not f.is_file():
        return []
    return [l.strip() for l in f.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]


def allowed(path: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in globs)


def line_problems(line: str) -> list[str]:
    """One added line: letters outside English, or more foreign than English function words. Code lines
    have few English words, so the 'too few English words' rule for longer prose is left out here."""
    if MARKER in line:
        return []
    return hmlib.english_problems(line, min_words=10**9)


def added_lines(base: str, head: str, root: Path):
    """(path, line number, text) of every line added between base and head (merge base, like a PR)."""
    out = subprocess.run(["git", "diff", "--no-color", "--no-ext-diff", "--unified=0", f"{base}...{head}"],
                         cwd=root, capture_output=True, text=True, check=True).stdout
    path, num = None, 0
    for line in out.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif (m := HUNK_RE.match(line)):
            num = int(m.group(1))
        elif line.startswith("+") and path:
            yield path, num, line[1:]
            num += 1


def commit_messages(base: str, head: str, root: Path) -> list[tuple[str, str]]:
    out = subprocess.run(["git", "log", "--no-merges", "--format=%h%x00%B%x1e", f"{base}..{head}"],
                         cwd=root, capture_output=True, text=True, check=True).stdout
    return [tuple(c.strip().split("\0", 1)) for c in out.split("\x1e") if "\0" in c]


def annotate(msg: str, path: str | None = None, line: int | None = None) -> str:
    where = f" file={path},line={line}" if path else ""
    return f"::error{where}::{msg.replace('%', '%25').replace(chr(10), '%0A')}"


def cmd_diff(base: str, head: str, root: Path = ROOT) -> int:
    globs, findings = allowlist(root), []
    for path, num, text in added_lines(base, head, root):
        if allowed(path, globs):
            continue
        for p in line_problems(text):
            findings.append(annotate(f"Not English: {p}", path, num))
    for sha, msg in commit_messages(base, head, root):
        msg = "\n".join(l for l in msg.splitlines() if MARKER not in l)
        for p in hmlib.english_problems(msg):
            findings.append(annotate(f"Commit {sha} message is not English: {p}"))
    print("\n".join(findings) if findings else "English check passed.")
    if findings:
        print(f"\n{len(findings)} finding(s). This repository is English-only: code, comments, docs, commit messages "
              "and pull requests. Deliberate exceptions: add `lang: allow` to the line or the path to "
              ".github/language-allowlist.")
    return 1 if findings else 0


def strip_generated(text: str) -> str:
    """Drop the Environment section issues.py adds (versions and tool names, not prose)."""
    return re.sub(r"(?ms)^#{2,3}\s+Environment\s*$.*?(?=^#{2,3}\s|\Z)", "", text)


def cmd_text(path: str | None) -> int:
    text = Path(path).read_text() if path and path != "-" else sys.stdin.read()
    problems = hmlib.english_problems(strip_generated(text))
    print("\n".join(f"- {p}" for p in problems) if problems else "English check passed.")
    return 1 if problems else 0


def main() -> int:
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "diff":
        return cmd_diff(a[1], a[2])
    if a and a[0] == "text" and len(a) <= 2:
        return cmd_text(a[1] if len(a) == 2 else None)
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
