"""Tests for hooks/update_check.py (daily update check) and plugin agent definitions."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "hooks" / "update_check.py"


def git(*a, cwd):
    subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)


class UpdateCheckTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.remote = self.d / "remote"
        self.remote.mkdir()
        git("init", "-q", "-b", "main", cwd=self.remote)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x", cwd=self.remote)
        self.have = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
        self.env = {**os.environ, "HM_UPDATE_URL": str(self.remote), "HM_UPDATE_CACHE": str(self.d / "cache.json")}

    def tearDown(self):
        shutil.rmtree(self.d)

    def tag(self, v):
        git("tag", f"v{v}", cwd=self.remote)

    def run_hook(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=self.env)

    def test_silent_when_up_to_date(self):
        self.tag(self.have)
        r = self.run_hook()
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertIn("up to date", self.run_hook("--force").stdout)

    def test_reports_newer_version_and_caches_for_a_day(self):
        self.tag("99.0.0")
        self.tag("100.0.0-rc1")  # not a release tag
        out = json.loads(self.run_hook().stdout)
        self.assertIn("99.0.0 is available", out["systemMessage"])
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "SessionStart")
        shutil.rmtree(self.remote)  # cached: no network needed for the rest of the day
        self.assertIn("99.0.0 is available", json.loads(self.run_hook().stdout)["systemMessage"])

    def test_unreachable_remote_never_breaks_the_session(self):
        self.env["HM_UPDATE_URL"] = str(self.d / "missing")
        r = self.run_hook()
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertIn("failed", self.run_hook("--force").stdout)

    def test_old_repo_gets_suggestions_in_session_context(self):
        self.tag(self.have)
        repo = self.d / "repo"
        scripts = ROOT / "skills" / "homelab-manager" / "scripts"
        subprocess.run([sys.executable, str(scripts / "init_repo.py"), str(repo), "--components", "proxmox"],
                       check=True, capture_output=True)
        r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, env=self.env, cwd=repo)
        new = json.loads(r.stdout)                                        # new repo: only the language, for Claude
        self.assertNotIn("systemMessage", new)
        self.assertIn("no site.language", new["hookSpecificOutput"]["additionalContext"])
        subprocess.run(["yq", "-i", 'del(.upgrades) | .site.language = "en" | .network.vlans = [{"id": 10, "name": "mgmt"}]',
                        str(repo / "homelab.yaml")], check=True)
        doc = repo / "docs" / "proxmox-tokens.md"
        doc.write_text(doc.read_text().replace("HomelabAgentAudit", "Custom"))
        (repo / "discovery").mkdir(exist_ok=True)
        (repo / "discovery" / "proxmox.json").write_text(json.dumps(
            {"guests": [], "guest_ip_sources": {"agent": "forbidden: needs VM.GuestAgent.Audit", "lxc": "ok"}}))
        out = json.loads(subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True,
                                        env=self.env, cwd=repo).stdout)
        self.assertIn("1 suggested opt-in change(s)", out["systemMessage"])
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("guest-agent privilege", ctx)
        self.assertIn("--sync-managed --dry-run", ctx)
        self.assertIn("needs the user's yes", ctx)

    def test_repo_language_in_session_context(self):
        self.tag(self.have)
        repo = self.d / "repo"
        scripts = ROOT / "skills" / "homelab-manager" / "scripts"
        subprocess.run([sys.executable, str(scripts / "init_repo.py"), str(repo), "--components", "ansible"],
                       check=True, capture_output=True)
        subprocess.run([sys.executable, str(scripts / "config_set.py"), "site.language=sk"], cwd=repo,
                       check=True, capture_output=True)
        out = json.loads(subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True,
                                        env=self.env, cwd=repo).stdout)
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("language is 'sk'", ctx)
        self.assertIn("skill issues", ctx)
        r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, env=self.env, cwd=self.d)
        self.assertEqual(r.stdout, "")                                    # outside a homelab repo: silent

    def test_hook_registered(self):
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
        self.assertIn("update_check.py", hooks["SessionStart"][0]["hooks"][0]["command"])


class AgentModelTests(unittest.TestCase):
    def model(self, name):
        text = (ROOT / "agents" / f"{name}.md").read_text()
        return next(l.split(":", 1)[1].strip() for l in text.split("---")[1].splitlines() if l.startswith("model:"))

    def test_models(self):
        self.assertEqual(self.model("homelab-runner"), "haiku")    # alias = latest Haiku
        self.assertEqual(self.model("homelab-analyst"), "sonnet")  # alias = latest Sonnet


if __name__ == "__main__":
    unittest.main()
