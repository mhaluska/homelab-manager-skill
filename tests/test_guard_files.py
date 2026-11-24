"""Unit tests for hooks/guard_files.py (Edit/Write/MultiEdit/NotebookEdit guard).

    python3 -m unittest discover -s tests -v
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "guard_files.py"

CONFIG = """site:
  domain: home.arpa
network:
  authorized_ranges: [10.0.10.0/24]
  excluded_hosts: [10.0.10.1]
proxmox:
  endpoint: https://10.0.10.2:8006
sites:
  - name: offsite
    proxmox: {endpoint: https://192.0.2.10:8006}
"""


def run(tool, tool_input, cwd):
    r = subprocess.run([sys.executable, str(HOOK)], capture_output=True, text=True, timeout=60,
                       input=json.dumps({"tool_name": tool, "tool_input": tool_input, "cwd": cwd}))
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() else None


class GuardFilesTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.cfg = self.d / "homelab.yaml"
        self.cfg.write_text(CONFIG)

    def tearDown(self):
        shutil.rmtree(self.d)

    def edit(self, old, new, **kw):
        return run("Edit", {"file_path": str(self.cfg), "old_string": old, "new_string": new, **kw}, str(self.d))

    def test_scan_scope_and_tls_edits_ask(self):
        self.assertEqual(self.edit("[10.0.10.0/24]", "[0.0.0.0/0]"), "ask")
        self.assertEqual(self.edit("  excluded_hosts: [10.0.10.1]\n", ""), "ask")
        self.assertEqual(self.edit("https://10.0.10.2:8006\n", "https://10.0.10.2:8006\n  verify_tls: false\n"), "ask")
        self.assertEqual(self.edit("{endpoint: https://192.0.2.10:8006}", "{endpoint: https://192.0.2.10:8006, verify_tls: false}"),
                         "ask")
        self.assertEqual(self.edit("site:\n", "issues: {auto_send: true}\nsite:\n"), "ask")
        self.assertEqual(run("Write", {"file_path": str(self.cfg), "content": CONFIG.replace("10.0.10.0/24", "10.0.0.0/8")},
                             str(self.d)), "ask")
        self.assertEqual(run("MultiEdit", {"file_path": str(self.cfg), "edits": [
            {"old_string": "home.arpa", "new_string": "lan"}, {"old_string": "10.0.10.1]", "new_string": "]"}]},
            str(self.d)), "ask")

    def test_other_homelab_yaml_edits_pass(self):
        self.assertIsNone(self.edit("home.arpa", "lan"))
        self.assertIsNone(self.edit("https://10.0.10.2:8006\n", "https://10.0.10.2:8006\n  verify_tls: true\n"))
        self.assertIsNone(run("Write", {"file_path": str(self.cfg), "content": CONFIG + "overview: {redact: true}\n"},
                              str(self.d)))
        self.assertIsNone(run("Edit", {"file_path": "notes.md", "old_string": "a", "new_string": "b"}, str(self.d)))

    def test_broken_yaml_asks(self):
        self.assertEqual(self.edit("site:\n", "site: [\n"), "ask")

    def test_plugin_and_settings_ask(self):
        self.assertEqual(run("Edit", {"file_path": str(ROOT / "hooks" / "guard.py"), "old_string": "DENY",
                                      "new_string": "ASK"}, str(self.d)), "ask")
        self.assertEqual(run("Write", {"file_path": str(self.d / ".claude" / "settings.json"), "content": "{}"},
                             str(self.d)), "ask")
        self.assertEqual(run("Write", {"file_path": ".claude/settings.local.json", "content": "{}"}, str(self.d)), "ask")
        self.assertEqual(run("NotebookEdit", {"notebook_path": str(ROOT / "hooks" / "x.ipynb"), "new_source": ""},
                             str(self.d)), "ask")

    def test_other_tools_and_bad_input(self):
        self.assertIsNone(run("Read", {"file_path": str(self.cfg)}, str(self.d)))
        r = subprocess.run([sys.executable, str(HOOK)], input="{oops", capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")


if __name__ == "__main__":
    unittest.main()
