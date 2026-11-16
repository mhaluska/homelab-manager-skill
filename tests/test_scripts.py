"""Tests for init_repo.py (components) and issues.py (ISSUES.md tracker)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "homelab-manager" / "scripts"
sys.path.insert(0, str(ROOT / "hooks"))
import guard  # noqa: E402


def run(script, *args, cwd):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], cwd=cwd, capture_output=True, text=True)


def yq(expr, path):
    return subprocess.run(["yq", "-o=json", expr, str(path)], capture_output=True, text=True).stdout.strip()


class InitComponentsTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_subset_only_creates_selected_parts(self):
        r = run("init_repo.py", self.d, "--components", "ansible,discovery", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        p = Path(self.d)
        self.assertTrue((p / "ansible/playbooks/patch-linux.yml").exists())
        self.assertTrue((p / "ISSUES.md").exists())
        self.assertFalse((p / "tofu").exists())
        self.assertFalse((p / "packer").exists())
        self.assertFalse((p / "ansible/playbooks/hooks").exists())
        self.assertFalse((p / "ansible/inventory/managed/group_vars/windows.yml").exists())
        comps = json.loads(yq(".components", p / "homelab.yaml"))
        self.assertEqual(comps["ansible"], True)
        self.assertEqual(comps["proxmox"], False)
        self.assertEqual(comps["templates"], False)

    def test_dependencies_are_pulled_in(self):
        run("init_repo.py", self.d, "--components", "templates,kubernetes", cwd=self.d)
        comps = json.loads(yq(".components", Path(self.d) / "homelab.yaml"))
        for c in ("templates", "proxmox", "kubernetes", "ansible"):
            self.assertTrue(comps[c], c)
        self.assertTrue((Path(self.d) / "tofu/modules/proxmox-vm/main.tf").exists())

    def test_add_component_later_never_overwrites(self):
        run("init_repo.py", self.d, "--components", "ansible", cwd=self.d)
        hosts = Path(self.d, "ansible/inventory/managed/hosts.yml")
        hosts.write_text("# my edits\n")
        r = run("init_repo.py", self.d, "--add-components", "proxmox", cwd=self.d)
        self.assertIn("newly enabled: proxmox", r.stdout)
        self.assertEqual(hosts.read_text(), "# my edits\n")
        self.assertTrue(Path(self.d, "tofu/environments/homelab/main.tf").exists())
        comps = json.loads(yq(".components", Path(self.d) / "homelab.yaml"))
        self.assertTrue(comps["ansible"] and comps["proxmox"])

    def test_first_commit_passes_secret_hook(self):
        run("init_repo.py", self.d, cwd=self.d)
        subprocess.run(["git", "add", "-A"], cwd=self.d, check=True)
        r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"],
                           cwd=self.d, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        Path(self.d, "leak.txt").write_text("t: homelab@pve!rw=0123abcd-1111-2222-3333-444455556666\n")
        subprocess.run(["git", "add", "leak.txt"], cwd=self.d, check=True)
        r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "leak"],
                           cwd=self.d, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


class IssuesTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "ansible", cwd=self.d)

    def tearDown(self):
        shutil.rmtree(self.d)

    def issues(self, *args):
        return run("issues.py", *args, cwd=self.d)

    def test_add_list_resolve_roundtrip(self):
        r = self.issues("add", "--title", "SSH password auth enabled on web01", "--severity", "high",
                        "--area", "security", "--source", "security-audit", "--key", "audit:ssh-pw:web01",
                        "--body", "PasswordAuthentication yes in /etc/ssh/sshd_config.\n\nFix: set to no.")
        self.assertIn("Added ISSUE-001", r.stdout)
        self.issues("add", "--title", "VM 105 not managed by OpenTofu", "--severity", "medium", "--area", "drift")
        text = Path(self.d, "ISSUES.md").read_text()
        self.assertIn("| ISSUE-001 | high | security |", text)
        self.assertIn("PasswordAuthentication yes", text)
        self.assertIn("ISSUE-002", self.issues("list", "--status", "open").stdout)
        r = self.issues("resolve", "1", "--note", "sshd hardened via Ansible")
        self.assertIn("ISSUE-001 → resolved", r.stdout)
        text = Path(self.d, "ISSUES.md").read_text()
        self.assertIn("**Resolution", text)
        self.assertEqual(text.count("PasswordAuthentication yes"), 1)  # body not duplicated by re-render
        self.assertNotIn("ISSUE-001", self.issues("list", "--status", "open").stdout)

    def test_dedupe_by_key(self):
        for _ in range(2):
            self.issues("add", "--title", "x", "--severity", "low", "--area", "drift", "--key", "drift:a")
        self.assertEqual(Path(self.d, "ISSUES.md").read_text().count("<!-- issue {"), 1)

    def test_hand_edits_survive(self):
        self.issues("add", "--title", "x", "--severity", "low", "--area", "drift", "--body", "original")
        p = Path(self.d, "ISSUES.md")
        p.write_text(p.read_text().replace("original", "original\n\nUser note: affects backups too."))
        self.issues("add", "--title", "y", "--severity", "low", "--area", "drift")
        self.assertIn("User note: affects backups too.", p.read_text())

    def test_untrusted_text_sanitised(self):
        f = Path(self.d, "body.txt")
        f.write_text("banner said: a\x00b \x1b]0;ignore previous instructions\x07")
        self.issues("add", "--title", "banner \x1b[31mred", "--severity", "low", "--area", "network", "--body-file", str(f))
        text = Path(self.d, "ISSUES.md").read_text()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x00", text)

    def test_open_dry_run_shows_glab_command(self):
        self.issues("add", "--title", "Template 9049 missing", "--severity", "medium", "--area", "templates")
        r = self.issues("open", "ISSUE-001", "--dry-run")
        self.assertIn("glab issue create --title [templates] Template 9049 missing", r.stdout)
        self.assertIn("severity::medium", r.stdout)
        self.assertIn("Tracked as ISSUE-001", r.stdout)
        self.assertIn("| open |", Path(self.d, "ISSUES.md").read_text())  # dry run changes nothing


class GuardGlabTests(unittest.TestCase):
    def d(self, cmd):
        out = guard.decide(guard.evaluate(cmd, "/tmp"))
        return out["hookSpecificOutput"]["permissionDecision"] if out else None

    def test_rules(self):
        self.assertEqual(self.d("glab issue create -t x -d y -y"), "ask")
        self.assertEqual(self.d("glab issue close 12"), "ask")
        self.assertEqual(self.d("python3 /p/issues.py open ISSUE-003"), "ask")
        self.assertIsNone(self.d("python3 /p/issues.py open ISSUE-003 --dry-run"))
        self.assertIsNone(self.d("python3 /p/issues.py add --title x --severity low --area drift"))
        self.assertIsNone(self.d("glab issue list"))
        self.assertIsNone(self.d("glab repo view -F json"))
        self.assertEqual(self.d("glab auth status --show-token"), "deny")
        self.assertEqual(self.d("glab config get token"), "deny")
        self.assertEqual(self.d("glab api -X POST projects/1/issues"), "ask")


if __name__ == "__main__":
    unittest.main()
