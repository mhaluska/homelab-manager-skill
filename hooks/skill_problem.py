#!/usr/bin/env python3
"""PostToolUse / PostToolUseFailure hook: notice when a bundled script misbehaves.

When a Bash command that ran one of this skill's scripts ($HM/scripts/*.py) crashed with a
Python traceback, or exited non-zero, this adds a reminder to Claude's context to note it in
skill_issues.md (`issues.py add`) in the same turn — so skill problems are logged when they happen,
not only when the user asks. A plain non-zero exit is often the homelab or the input
(unreachable host, refused scan), so that reminder asks Claude to judge; a traceback is always
a skill bug. Never blocks anything; any error → silent.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "homelab-manager" / "scripts"
TRACEBACK = re.compile(r"Traceback \(most recent call last\):(?:.|\n)*?^(\w+(?:\.\w+)*(?:Error|Exception|Exit|Interrupt)?)\b",
                       re.M)
ADD = 'python3 $HM/scripts/issues.py add --kind script --key {key} --title "…" --body-file <details.md>'


def scripts_in(command: str) -> list[str]:
    names = {p.stem for p in SCRIPTS.glob("*.py")}
    found = re.findall(r"scripts/([A-Za-z0-9_]+)\.py\b", command)
    return list(dict.fromkeys(n for n in found if n in names))


def output_text(payload: dict) -> str:
    resp = payload.get("tool_response")
    parts = [str(payload.get("error") or "")]
    if isinstance(resp, dict):
        parts += [str(resp.get(k) or "") for k in ("stdout", "stderr", "output", "error")]
    elif resp:
        parts.append(str(resp))
    return "\n".join(parts)


def message(payload: dict) -> str | None:
    if payload.get("tool_name") != "Bash":
        return None
    names = scripts_in((payload.get("tool_input") or {}).get("command", ""))
    if not names:
        return None
    text = output_text(payload)
    tb = TRACEBACK.search(text)
    failed = payload.get("hook_event_name") == "PostToolUseFailure" or bool(tb)
    if not failed:
        return None
    name = names[-1]
    if name == "issues":
        return ("homelab-manager: issues.py itself failed. Tell the user in your report (it can't log "
                "its own failure), with the error.")
    if tb:
        exc = tb.group(1).split(".")[-1].lower()
        return (f"homelab-manager: {name}.py crashed ({tb.group(1)}). An unhandled exception in a bundled "
                f"script is a skill bug: note it now, before your final report — "
                f"{ADD.format(key=f'script:{name}:{exc}')} — and name the SKILL-ID in your report (SKILL.md §6).")
    return (f"homelab-manager: {name}.py exited with an error. If the cause is the skill (wrong result, "
            f"misleading message, an instruction that led here, a workaround you're about to apply) rather "
            f"than the homelab or the input, note it now with {ADD.format(key=f'script:{name}:<short-cause>')} "
            f"and name the SKILL-ID in your report (SKILL.md §6).")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        msg = message(payload)
    except Exception:
        return 0
    if msg:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": payload.get("hook_event_name", "PostToolUse"),
                                                 "additionalContext": msg}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
