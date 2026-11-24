"""Tests for The guard's gh language check and the skill-problem hook (hooks/skill_problem.py)."""
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import ROOT, SCRIPTS, run, yq  # noqa: E402,F401

sys.path.insert(0, str(ROOT / "hooks"))
import guard  # noqa: E402,F401


class GuardGhTests(unittest.TestCase):
    def d(self, cmd):
        out = guard.decide(guard.evaluate(cmd, "/tmp"))
        return out["hookSpecificOutput"]["permissionDecision"] if out else None

    def test_rules(self):
        self.assertEqual(self.d("gh issue create -t x -b y"), "ask")
        self.assertEqual(self.d("gh issue close 12"), "ask")
        self.assertEqual(self.d("gh issue comment 12 --body-file -"), "ask")
        self.assertEqual(self.d("gh label create severity:high"), "ask")
        self.assertEqual(self.d("gh release create v1.0.0"), "ask")
        self.assertEqual(self.d("gh repo delete o/r --yes"), "ask")
        self.assertEqual(self.d("gh api repos/o/r/issues -f title=x"), "ask")   # fields imply POST
        self.assertIsNone(self.d("gh api repos/o/r/issues -X GET -f state=all"))
        self.assertIsNone(self.d("gh api repos/o/r/releases/latest"))
        self.assertEqual(self.d("python3 /p/issues.py report"), "ask")
        self.assertEqual(self.d("python3 /p/issues.py report SKILL-002 --match SKILL-002=7"), "ask")
        self.assertIsNone(self.d("python3 /p/issues.py report --dry-run"))
        self.assertIsNone(self.d("python3 /p/issues.py add --title x --kind script"))
        self.assertIsNone(self.d("python3 /p/issues.py migrate"))
        self.assertIsNone(self.d("gh issue list --state all --json number,title"))
        self.assertIsNone(self.d("gh repo view --json nameWithOwner"))
        self.assertIsNone(self.d("gh auth status"))
        self.assertEqual(self.d("gh auth status --show-token"), "deny")
        self.assertEqual(self.d("gh auth status -t"), "deny")
        self.assertEqual(self.d("gh auth token"), "deny")
        self.assertEqual(self.d("gh api -X POST repos/o/r/issues"), "ask")


class SkillProblemHookTests(unittest.TestCase):
    """hooks/skill_problem.py reminds Claude to log skill problems when they happen (GitHub issue #2)."""

    def hook(self, payload):
        r = subprocess.run([sys.executable, str(ROOT / "hooks/skill_problem.py")], input=json.dumps(payload),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        return json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"] if r.stdout.strip() else None

    def payload(self, cmd, event="PostToolUse", stdout="", stderr="", error=None):
        p = {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": cmd},
             "tool_response": {"stdout": stdout, "stderr": stderr}}
        if error:
            p["error"] = error
        return p

    def test_traceback_in_bundled_script(self):
        tb = ('Traceback (most recent call last):\n'
              '  File "/p/skills/homelab-manager/scripts/drift_report.py", line 9, in <module>\n'
              '  File "/p/skills/homelab-manager/scripts/hmlib.py", line 3, in get\nKeyError: \'backup_jobs\'\n')
        msg = self.hook(self.payload("python3 $HM/scripts/drift_report.py", stderr=tb))
        self.assertIn("issues.py add --kind script --key script:drift_report:keyerror", msg)

    def test_unrelated_traceback_not_blamed_on_a_script(self):  # GitHub issue #8
        tb = 'Traceback (most recent call last):\n  File "<string>", line 1, in <module>\nKeyError: \'mac\'\n'
        cmd = "python3 $HM/scripts/drift_report.py --no-tofu >/dev/null; python3 -c 'import json; json.load(...)[\"mac\"]'"
        self.assertIsNone(self.hook(self.payload(cmd, stderr=tb)))
        self.assertIsNone(self.hook(self.payload(cmd, event="PostToolUseFailure", stderr=tb, error="Exit code 1")))
        theirs = tb.replace("<string>", "/Users/x/homelab/scripts/drift_report.py")
        self.assertIsNone(self.hook(self.payload("python3 $HM/scripts/drift_report.py; python3 scripts/drift_report.py",
                                                 stderr=theirs)))
        ours = tb.replace("<string>", "/p/skills/homelab-manager/scripts/nmap_scan.py")
        msg = self.hook(self.payload("python3 $HM/scripts/drift_report.py", stderr=tb + ours))
        self.assertIn("nmap_scan.py crashed", msg)

    def test_failure_asks_for_judgement(self):
        msg = self.hook(self.payload("python3 /x/skills/homelab-manager/scripts/check_env.py",
                                     event="PostToolUseFailure", error="Exit code 1"))
        self.assertIn("If the cause is the skill", msg)

    def test_quiet_when_fine_or_not_ours(self):
        self.assertIsNone(self.hook(self.payload("python3 $HM/scripts/check_env.py", stdout="all good")))
        self.assertIsNone(self.hook(self.payload("python3 my/scripts/thing.py", event="PostToolUseFailure")))
        self.assertIsNone(self.hook(self.payload("ls", event="PostToolUseFailure")))
        self.assertIsNone(self.hook({"tool_name": "Read"}))


if __name__ == "__main__":
    unittest.main()
