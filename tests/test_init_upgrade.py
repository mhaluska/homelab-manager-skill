"""Tests for init_repo.py (components, --sync-managed upgrades, template history), upgrade notes and the pre-commit hook."""
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
        self.assertTrue((p / "skill_issues.md").exists())
        self.assertFalse((p / "tofu").exists())
        self.assertFalse((p / "packer").exists())
        self.assertFalse((p / "ansible/playbooks/hooks/k8s-drain.yml").exists())  # kubernetes only
        self.assertTrue((p / "ansible/playbooks/hooks/vrrp-health.yml").exists())  # any cluster (#39)
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

    def test_repo_modes_find_the_repo_from_a_subdirectory(self):
        # GitHub issue #164: run from ansible/, --sync-managed said "up to date" for a repo with pending notes
        run("init_repo.py", self.d, "--components", "ansible", cwd=self.d)
        subprocess.run(["yq", "-i", 'del(.upgrades)', str(Path(self.d) / "homelab.yaml")], check=True)
        sub = Path(self.d, "ansible")
        here = run("init_repo.py", "--sync-managed", "--dry-run", cwd=self.d)
        there = run("init_repo.py", "--sync-managed", "--dry-run", cwd=sub)
        self.assertEqual(there.returncode, 0, there.stderr)
        self.assertEqual(there.stdout, here.stdout)
        self.assertNotIn("Up to date", there.stdout)
        r = run("init_repo.py", "--add-components", "discovery", "--dry-run", cwd=sub)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"in {Path(self.d).resolve()}", r.stdout)
        self.assertFalse((sub / "homelab.yaml").exists())

    def test_repo_modes_refuse_outside_a_repo(self):
        for args in (["--sync-managed", "--dry-run"], ["--add-components", "discovery"], ["--add-site", "x"]):
            r = run("init_repo.py", *args, cwd=self.d)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("no homelab.yaml", r.stderr)
            self.assertNotIn("Up to date", r.stdout)
            r = run("init_repo.py", self.d, *args, cwd=self.d)            # explicit dir without homelab.yaml
            self.assertEqual(r.returncode, 2, args)
        self.assertEqual(list(Path(self.d).iterdir()), [])

    def test_new_repo_is_never_created_inside_an_existing_one(self):
        run("init_repo.py", self.d, "--components", "ansible", cwd=self.d)
        sub = Path(self.d, "ansible")
        r = run("init_repo.py", "--components", "ansible", cwd=sub)
        self.assertEqual(r.returncode, 2)
        self.assertIn("is inside the homelab repo", r.stderr)
        self.assertFalse((sub / "homelab.yaml").exists())
        self.assertEqual(run("init_repo.py", "--components", "ansible", "--dry-run", cwd=self.d).returncode, 0)

    def test_existing_settings_json_gets_permissions_merged(self):
        # e.g. the plugin was installed with project scope before setup ran
        s = Path(self.d, ".claude/settings.json")
        s.parent.mkdir()
        s.write_text(json.dumps({"enabledPlugins": {"homelab-manager@homelab-manager-skill": True},
                                 "permissions": {"allow": ["Bash(ls:*)"], "deny": ["Read(**/*.tfstate)"]}}))
        r = run("init_repo.py", self.d, "--components", "ansible", cwd=self.d)
        self.assertIn("Merged template permission rules", r.stdout)
        d = json.loads(s.read_text())
        self.assertIn("Read(~/.ssh/id_*)", d["permissions"]["deny"])
        self.assertEqual(d["permissions"]["deny"].count("Read(**/*.tfstate)"), 1)
        self.assertIn("Bash(tofu apply:*)", d["permissions"]["ask"])
        self.assertEqual(d["permissions"]["allow"][0], "Bash(ls:*)")        # user's rules kept, first
        self.assertIn("Bash(git add *)", d["permissions"]["allow"])
        self.assertTrue(d["enabledPlugins"]["homelab-manager@homelab-manager-skill"])
        r = run("init_repo.py", self.d, "--add-components", "discovery", cwd=self.d)
        self.assertNotIn("Merged", r.stdout)                                  # idempotent

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


class TemplateCoverageTests(unittest.TestCase):
    def test_every_template_file_belongs_to_a_component(self):
        sys.path.insert(0, str(SCRIPTS))
        import init_repo
        files = [p.relative_to(init_repo.TEMPLATE).as_posix() for p in init_repo.TEMPLATE.rglob("*")
                 if p.is_file() and p.name != ".DS_Store"]
        self.assertEqual([f for f in files if not init_repo.wanted(f, list(init_repo.COMPONENTS))], [],
                         "add these to CORE or a component in init_repo.py, or no repo gets them")

    def test_playbook_vars_files_exist_in_a_scaffold(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        self.assertEqual(run("init_repo.py", str(d), cwd=d).returncode, 0)
        refs = [(pb, ref.strip().strip("'\"")) for pb in (d / "ansible/playbooks").glob("*.yml")
                for m in re.finditer(r"^\s*vars_files:\s*\[([^\]]*)\]", pb.read_text(), re.M)
                for ref in m.group(1).split(",")]
        self.assertTrue(refs)
        self.assertEqual([f"{pb.name}: {ref}" for pb, ref in refs if not (pb.parent / ref).is_file()], [])


class StateBackendTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox", cwd=self.d)
        self.cfg = Path(self.d, "homelab.yaml")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}

    def tearDown(self):
        shutil.rmtree(self.d)

    def init(self, *args, env=None):
        return subprocess.run([sys.executable, str(SCRIPTS / "tofu_init.py"), *args], cwd=self.d,
                              capture_output=True, text=True, env=env or self.env)

    def test_local_is_default_and_outside_repo(self):
        self.assertIn('backend "local"', Path(self.d, "tofu/environments/homelab/backend.tf").read_text())
        subprocess.run(["yq", "-i", f'.opentofu.local.path = "{self.d}/../st/homelab.tfstate"', str(self.cfg)], check=True)
        r = self.init("--print")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[local]", r.stdout)
        self.assertIn("-backend-config=path=", r.stdout)
        self.assertNotIn(".gitlab", r.stdout)

    def test_s3_needs_config_and_keys(self):
        subprocess.run(["yq", "-i", '.opentofu.state_backend = "s3"', str(self.cfg)], check=True)
        self.assertIn("opentofu.s3.endpoint", self.init("--print").stderr)
        subprocess.run(["yq", "-i", '.opentofu.s3.endpoint = "https://s3.example:9000" | .opentofu.s3.bucket = "tf"',
                        str(self.cfg)], check=True)
        self.assertIn("with_secrets.py s3-state", self.init("--print").stderr)
        r = self.init("--print", env={**self.env, "AWS_ACCESS_KEY_ID": "k", "AWS_SECRET_ACCESS_KEY": "s"})
        self.assertIn('endpoints={s3="https://s3.example:9000"}', r.stdout)
        self.assertIn("use_lockfile=true", r.stdout)
        self.assertIn("skip_requesting_account_id=true", r.stdout)

    def test_s3_credentials_kind(self):
        sys.path.insert(0, str(SCRIPTS))
        import with_secrets, hmlib
        cfg = {"secrets": {"s3-state": {"service": "x", "kind": "s3_credentials"}}}
        orig = hmlib.read_secret
        hmlib.read_secret = lambda c, n: "AKIDEXAMPLE:secretvalue"
        try:
            env, _ = with_secrets.env_for(cfg, "s3-state")
        finally:
            hmlib.read_secret = orig
        self.assertEqual(env, {"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secretvalue"})

    def test_user_password_kind(self):  # issue 32: BMC credentials
        sys.path.insert(0, str(SCRIPTS))
        import with_secrets, hmlib
        cfg = {"secrets": {"bmc": {"service": "x", "kind": "user_password", "env": "BMC"},
                           "bad": {"service": "x", "kind": "user_password"}}}
        orig = hmlib.read_secret
        hmlib.read_secret = lambda c, n: "monitor:pa:ss"
        try:
            env, _ = with_secrets.env_for(cfg, "bmc")
            with self.assertRaises(hmlib.ConfigError):
                with_secrets.env_for(cfg, "bad")
        finally:
            hmlib.read_secret = orig
        self.assertEqual(env, {"BMC_USER": "monitor", "BMC_PASSWORD": "pa:ss"})


class SettingsUpgradeTests(unittest.TestCase):
    def test_sync_managed_adds_new_permission_rules_and_keeps_the_users(self):
        d = Path(tempfile.mkdtemp())
        try:
            run("init_repo.py", str(d), "--components", "ansible", cwd=d)
            p = d / ".claude" / "settings.json"
            p.write_text(json.dumps({"permissions": {"deny": ["Read(~/.ssh/id_*)", "Read(~/secret)"]},
                                     "model": "x"}))
            dry = run("init_repo.py", str(d), "--sync-managed", "--dry-run", cwd=d).stdout
            self.assertIn("deny: Read(~/.aws/credentials)", dry)
            run("init_repo.py", str(d), "--sync-managed", cwd=d)
            have = json.loads(p.read_text())
            self.assertIn("Read(~/secret)", have["permissions"]["deny"])
            self.assertIn("Read(~/.kube/config)", have["permissions"]["deny"])
            self.assertIn("Bash(packer build:*)", have["permissions"]["ask"])
            self.assertNotIn("allow", have["permissions"])              # never an allow rule (GitHub issue #157)
            self.assertNotIn("allow:", dry)
            self.assertEqual(have["model"], "x")
            p.write_text("{oops")                                       # the user's broken file: left alone
            self.assertNotIn("settings.json", run("init_repo.py", str(d), "--sync-managed", "--dry-run", cwd=d).stdout)
        finally:
            shutil.rmtree(d)

    def test_removed_allow_rules_stay_removed_and_old_repos_are_asked(self):   # GitHub issue #157
        d = Path(tempfile.mkdtemp())
        try:
            run("init_repo.py", str(d), "--components", "ansible", cwd=d)
            p = d / ".claude" / "settings.json"
            have = json.loads(p.read_text())
            self.assertIn("Bash(git commit *)", have["permissions"]["allow"])  # a new repo gets them at setup
            have["permissions"]["allow"] = ["Bash(ls:*)"]
            p.write_text(json.dumps(have))
            self.assertIn("Up to date", run("init_repo.py", str(d), "--sync-managed", "--dry-run", cwd=d).stdout)
            run("init_repo.py", str(d), "--sync-managed", cwd=d)
            r = run("init_repo.py", str(d), "--add-components", "discovery", cwd=d)
            self.assertNotIn("Merged", r.stdout)
            self.assertEqual(json.loads(p.read_text())["permissions"]["allow"], ["Bash(ls:*)"])
            ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", cwd=d).stdout)]
            self.assertNotIn("settings-allow-git", ids())     # reviewed at this version: a removal stays a removal
            run("config_set.py", "upgrades.reviewed=0.55.0", cwd=d)
            self.assertIn("settings-allow-git", ids())        # set up before 0.56.0: offered, needs a yes
            out = run("init_repo.py", str(d), "--sync-managed", "--dry-run", cwd=d).stdout
            self.assertIn("settings-allow-git", out)
            self.assertNotIn("allow: Bash(git", out)
            run("upgrade_notes.py", "--decline", "settings-allow-git", cwd=d)
            self.assertNotIn("settings-allow-git", ids())
            self.assertEqual(json.loads(p.read_text())["permissions"]["allow"], ["Bash(ls:*)"])
        finally:
            shutil.rmtree(d)


OLD_ISSUES_MD = """# Issues

Problems found while managing this homelab — by the homelab-manager skill (drift reports,
audits, failed runs, things noticed along the way) or added by you.

<!-- reported-through: 2026-11-16T10:00:00.000000+00:00 -->

| ID | Severity | Area | Title | Status | GitHub |
|---|---|---|---|---|---|
| ISSUE-001 | medium | drift | VM 104 unmanaged | github | [#3](https://github.com/me/homelab/issues/3) |

## ISSUE-001 — VM 104 unmanaged
<!-- issue {"id": "ISSUE-001", "title": "VM 104 unmanaged", "severity": "medium", "area": "drift", "status": "github", "found": "2026-11-16", "github_url": "https://github.com/me/homelab/issues/3", "github_number": 3} -->
- **Severity:** medium · **Area:** drift · **Found:** 2026-11-16 · **Status:** github

### Summary
test-old is not in OpenTofu.
<!-- /issue -->
"""


class UpgradeTests(unittest.TestCase):
    """Repos set up before 0.6.0 tracked homelab problems in ISSUES.md; --sync-managed migrates them."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        run("init_repo.py", str(self.d), "--components", "ansible", cwd=self.d)
        (self.d / "skill_issues.md").unlink()
        (self.d / "ISSUES.md").write_text(OLD_ISSUES_MD)
        subprocess.run(["yq", "-i", '.issues.file = "ISSUES.md" | .issues.github = true | .issues.repo = "" | .issues.labels = ["homelab"] | del(.issues.report)',
                        str(self.d / "homelab.yaml")], check=True)
        claude = self.d / "CLAUDE.md"
        claude.write_text(claude.read_text().split("- Homelab problems")[0]
                          + "- Record problems you find (drift, audit findings) in `ISSUES.md` via `issues.py`.\n"
                            "  Report with `issues.py report`.\n- Commit to `main` after verified changes.\n")
        readme = self.d / "README.md"
        row = next(l for l in readme.read_text().splitlines() if l.startswith("| `skill_issues.md`"))
        readme.write_text(readme.read_text().replace(
            row, "| `ISSUES.md` | Problems found while managing the homelab; can be reported as GitHub issues |"))
        readme.write_text(readme.read_text() + "\nOur notes.\n")   # edited: patched, not replaced (#68)
        form = self.d / ".github/ISSUE_TEMPLATE/homelab-problem.yml"
        form.parent.mkdir(parents=True)
        form.write_text("# Managed by the homelab-manager plugin — `init_repo.py --sync-managed` overwrites local edits.\nname: x\n")
        (form.parent / "config.yml").write_text("# Managed by the homelab-manager plugin.\nblank_issues_enabled: true\n")
        (self.d / ".github/workflows").mkdir()
        (self.d / ".github/workflows/mine.yml").write_text("on: push\n")   # the user's own file stays

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_dry_run_lists_and_changes_nothing(self):
        before = (self.d / "ISSUES.md").read_text()
        out = run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout
        for part in ("would remove .github/ISSUE_TEMPLATE/homelab-problem.yml", "homelab.yaml: issues.github",
                     "CLAUDE.md: replace", "README.md: replace", "move 1 homelab issue(s)",
                     "rename ISSUES.md → skill_issues.md"):
            self.assertIn(part, out)
        self.assertEqual((self.d / "ISSUES.md").read_text(), before)
        self.assertFalse((self.d / "skill_issues.md").exists())
        self.assertTrue((self.d / ".github/ISSUE_TEMPLATE/config.yml").exists())

    def test_apply_migrates_everything_once(self):
        r = run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        archive = (self.d / "docs/issues-archive.md").read_text()
        self.assertIn("ISSUE-001 — VM 104 unmanaged", archive)
        self.assertIn("test-old is not in OpenTofu.", archive)
        self.assertIn("issues/3", archive)
        self.assertFalse((self.d / "ISSUES.md").exists())
        text = (self.d / "skill_issues.md").read_text()
        self.assertIn("Issues with the homelab-manager skill", text)
        self.assertNotIn("ISSUE-001", text)
        self.assertNotIn("reported-through", text)                      # old marker was for the homelab repo
        self.assertFalse((self.d / ".github/ISSUE_TEMPLATE").exists())
        self.assertTrue((self.d / ".github/workflows/mine.yml").exists())
        issues_cfg = json.loads(yq(".issues", self.d / "homelab.yaml"))
        self.assertEqual(issues_cfg, {"file": "skill_issues.md", "report": True})
        claude = (self.d / "CLAUDE.md").read_text()
        self.assertNotIn("Record problems you find", claude)
        self.assertIn("- Homelab problems (drift", claude)
        self.assertIn("- Commit to `main`", claude)                     # following rule kept
        self.assertIn("Problems with the homelab-manager skill itself", (self.d / "README.md").read_text())
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout)
        r = run("issues.py", "add", "--title", "x", "--kind", "other", cwd=self.d)
        self.assertIn("Added SKILL-001", r.stdout)

    def test_edited_old_form_is_left_alone(self):
        form = self.d / ".github/ISSUE_TEMPLATE/homelab-problem.yml"
        form.write_text("name: my own form\n")
        out = run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout
        self.assertNotIn("homelab-problem.yml", out)
        self.assertTrue(form.exists())

    def test_session_start_hook_announces_pending_upgrade(self):
        env = {**os.environ, "HM_UPDATE_URL": str(self.d / "nowhere"), "HM_UPDATE_CACHE": str(self.d / "c.json")}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "update_check.py")], cwd=self.d,
                           capture_output=True, text=True, env=env)
        ctx = json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("one-time update", ctx)
        self.assertIn("--sync-managed --dry-run", ctx)
        run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "update_check.py")], cwd=self.d,
                           capture_output=True, text=True, env=env)
        out = json.loads(r.stdout)                         # upgraded: only the repo language is left to say
        self.assertNotIn("systemMessage", out)
        self.assertNotIn("one-time update", out["hookSpecificOutput"]["additionalContext"])


class RenameIssuesFileTests(unittest.TestCase):
    """0.6.0–0.7.0 repos kept skill problems in ISSUES.md; --sync-managed renames it to skill_issues.md."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        run("init_repo.py", str(self.d), "--components", "ansible", cwd=self.d)
        (self.d / "skill_issues.md").rename(self.d / "ISSUES.md")
        subprocess.run(["sed", "-i", "", "s/skill_issues\\.md/ISSUES.md/", "homelab.yaml", "CLAUDE.md", "README.md"],
                       cwd=self.d, check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.d, check=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "init"],
                       cwd=self.d, check=True)

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_old_file_still_used_until_renamed(self):
        run("issues.py", "add", "--title", "x", "--kind", "other", "--key", "k", cwd=self.d)
        self.assertIn("SKILL-001", (self.d / "ISSUES.md").read_text())
        self.assertFalse((self.d / "skill_issues.md").exists())

    def test_sync_renames_with_git_and_updates_mentions(self):
        run("issues.py", "add", "--title", "x", "--kind", "other", "--key", "k", cwd=self.d)
        subprocess.run(["git", "add", "ISSUES.md"], cwd=self.d, check=True)
        r = run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rename ISSUES.md → skill_issues.md", r.stdout)
        self.assertFalse((self.d / "ISSUES.md").exists())
        self.assertIn("SKILL-001", (self.d / "skill_issues.md").read_text())
        self.assertEqual(json.loads(yq(".issues.file", self.d / "homelab.yaml")), "skill_issues.md")
        for rel in ("CLAUDE.md", "README.md"):
            text = (self.d / rel).read_text()
            self.assertNotIn("ISSUES.md", text)
            self.assertIn("`skill_issues.md`", text)
        status = subprocess.run(["git", "status", "--porcelain"], cwd=self.d, capture_output=True, text=True).stdout
        self.assertRegex(status, r"(?m)^R. ISSUES.md -> skill_issues.md$")
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout)

    def test_custom_file_name_left_alone(self):
        subprocess.run(["yq", "-i", '.issues.file = "notes/skill.md"', "homelab.yaml"], cwd=self.d, check=True)
        out = run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout
        self.assertNotIn("rename", out)


PREV_CLAUDE_RULE = """- Homelab problems (drift, audit findings, failed runs) are reported in chat and in `discovery/drift.md` /
  `docs/security-audit-<date>.md`; they are not tracked in a file. `skill_issues.md` is only for problems with the
  homelab-manager skill itself (script bugs, wrong instructions, guard false alarms), added with `issues.py`;
  `issues.py report` sends them, sanitised and after the user's yes, to the plugin's GitHub repository.
"""
PREV_README_ROW = ("| `skill_issues.md` | Problems with the homelab-manager skill itself, "
                   "to report to its GitHub repository |")


MARKER = "2026-11-16T10:00:00.000000+00:00"
MARKER_LINES = (f"<!-- reported-through: {MARKER} -->\n_Last reported: 2026-11-16 10:00 UTC — only issues added "
                "or changed after this are sent next time._\n\n")


class IdeasUpgradeTests(unittest.TestCase):
    """0.6.0–0.8.0 repos say skill_issues.md is only for problems; --sync-managed adds the ideas wording."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        run("init_repo.py", str(self.d), "--components", "ansible", cwd=self.d)
        run("issues.py", "add", "--title", "x", "--kind", "script", "--body", "### Summary\nkept", cwd=self.d)
        claude, readme, issues_md = self.d / "CLAUDE.md", self.d / "README.md", self.d / "skill_issues.md"
        rule = claude.read_text().split("- Homelab problems")[1].split("\n- ")[0]
        claude.write_text(claude.read_text().replace("- Homelab problems" + rule + "\n", PREV_CLAUDE_RULE))
        readme.write_text(readme.read_text().replace(
            next(l for l in readme.read_text().splitlines() if l.startswith("| `skill_issues.md`")), PREV_README_ROW))
        readme.write_text(readme.read_text() + "\nOur notes.\n")   # edited: patched, not replaced (#68)
        text = issues_md.read_text()
        issues_md.write_text("# Issues with the homelab-manager skill\n\nOld header.\n\n" + MARKER_LINES
                             + text[text.index("| ID |"):])

    def tearDown(self):
        shutil.rmtree(self.d)

    def commit(self, msg):
        subprocess.run(["git", "add", "-A"], cwd=self.d, check=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", msg],
                       cwd=self.d, check=True)

    def test_header_refresh_keeps_reported_marker(self):
        run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        text = (self.d / "skill_issues.md").read_text()
        self.assertNotIn("Old header.", text)
        self.assertIn(f"<!-- reported-through: {MARKER} -->", text)
        self.assertEqual(text.count("reported-through"), 1)
        sys.path.insert(0, str(SCRIPTS))
        import issues
        self.assertEqual(issues.read_marker(self.d / "skill_issues.md"), MARKER)   # what report reads

    def test_marker_lost_by_090_is_restored_from_git(self):
        self.commit("0.8.0 repo, reported")
        issues_md = self.d / "skill_issues.md"
        run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        issues_md.write_text(issues_md.read_text().replace(MARKER_LINES, ""))   # what 0.9.0's sync left
        self.assertNotIn("reported-through", issues_md.read_text())
        self.commit("0.9.0 sync")
        out = run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout
        self.assertIn(f"restore the reported-through marker ({MARKER})", out)
        run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        self.assertIn(f"<!-- reported-through: {MARKER} -->", issues_md.read_text())
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout)

    def test_sync_adds_ideas_wording_once(self):
        out = run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout
        for part in ("CLAUDE.md: replace the issues rule (the file now also collects ideas",
                     "README.md: replace the issues table row (the file now also collects ideas",
                     "skill_issues.md: refresh the header"):
            self.assertIn(part, out)
        r = run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        claude = (self.d / "CLAUDE.md").read_text()
        self.assertIn("ideas to", claude)
        self.assertIn("- Commit to `main`", claude)                     # following rule kept
        self.assertIn("ideas to improve it", (self.d / "README.md").read_text())
        text = (self.d / "skill_issues.md").read_text()
        self.assertNotIn("Old header.", text)
        self.assertIn("### Summary\nkept", text)                         # entries survive
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout)


class UpgradeNotesTests(unittest.TestCase):
    """#11: opt-in changes of newer releases are suggested after an upgrade, never applied by themselves."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        run("init_repo.py", str(self.d), "--components", "proxmox", cwd=self.d)
        self.cfg = self.d / "homelab.yaml"

    def tearDown(self):
        shutil.rmtree(self.d)

    def sync(self, *args):
        return run("init_repo.py", str(self.d), "--sync-managed", *args, cwd=self.d)

    def make_old(self):
        """A repo set up by 0.10.x: no upgrades.reviewed, older tokens doc, snapshots without the new data."""
        subprocess.run(["yq", "-i", "del(.upgrades) | del(.vmid_scheme)", str(self.cfg)], check=True)
        run("config_set.py", "proxmox.endpoint=https://pve.example.test:8006", cwd=self.d)
        doc = self.d / "docs/proxmox-tokens.md"
        doc.write_text(re.sub(r"\nOptional — VM IPs.*?(?=\n## )", "\n", doc.read_text(), flags=re.S))
        lxc = lambda vmid, tag, ip: {"vmid": vmid, "name": f"g{vmid}", "type": "lxc", "template": False,
                                     "config": {"net0": f"name=eth0,bridge=vmbr0,ip={ip}/24,tag={tag}"}}
        (self.d / "discovery/proxmox.json").write_text(json.dumps({"guests": [
            lxc(1020015, 1020, "10.20.0.15"), lxc(1020016, 1020, "10.20.0.16"), lxc(30007, 30, "10.30.0.7")]}))
        (self.d / "discovery/drift.md").write_text("# Drift\n\n## Proxmox ↔ OpenTofu\n")
        return doc

    def test_new_repo_records_version_and_has_nothing_to_suggest(self):
        self.assertRegex(yq(".upgrades.reviewed", self.cfg), r'^"\d+\.\d+\.\d+"$')
        self.assertIn("Up to date", self.sync("--dry-run").stdout)

    def test_old_repo_suggestions_stay_until_settled_and_nothing_is_applied(self):  # GitHub issue #67
        doc = self.make_old()
        before = {f: f.read_text() for f in (doc, self.cfg, self.d / "discovery/proxmox.json")}
        out = self.sync("--dry-run").stdout
        self.assertNotIn("Up to date", out)
        self.assertIn("Suggested by newer releases (opt-in", out)
        self.assertIn("[0.10.0 · manual step · proxmox-tls-check]", out)          # check_env TLS
        self.assertIn("vmid_scheme={vlan}{octet:03d}", out)                         # inferred from the snapshot
        self.assertNotIn("[0.11.0 · template section", out)   # agent IPs not known to be unread (#14)
        self.assertIn("proxmox_inventory.py --details", out)
        self.assertIn("drift_report.py", out)
        self.assertEqual({f: f.read_text() for f in before}, before)               # dry run writes nothing
        out = self.sync().stdout
        self.assertNotIn("Recorded upgrades.reviewed", out)
        self.assertIn("stays at the old version", out)
        self.assertEqual(doc.read_text(), before[doc])                              # suggestions never applied
        self.assertEqual(yq(".vmid_scheme", self.cfg), "null")
        self.assertEqual(yq(".upgrades.reviewed", self.cfg), "null")
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", cwd=self.d).stdout)]
        pending = ids()
        self.assertIn("proxmox-tls-check", pending)                                # offered again
        self.assertIn("proxmox-tls-check", self.sync("--dry-run").stdout)
        r = run("upgrade_notes.py", "--done", "proxmox-tls-check", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run("upgrade_notes.py", "--decline", *[i for i in pending if i != "proxmox-tls-check"], cwd=self.d)
        self.assertIn("No suggestions left", r.stdout)
        self.assertEqual(json.loads(yq(".upgrades.done", self.cfg)), ["proxmox-tls-check"])
        self.assertEqual(ids(), [])
        out = self.sync().stdout
        self.assertIn("Recorded upgrades.reviewed", out)
        self.assertRegex(yq(".upgrades.reviewed", self.cfg), r'^"\d+\.\d+\.\d+"$')
        self.assertEqual(yq(".upgrades.declined", self.cfg), "null")              # covered by reviewed now
        self.assertEqual(yq(".upgrades.done", self.cfg), "null")
        self.assertIn("Up to date", self.sync("--dry-run").stdout)

    def test_applied_suggestion_drops_out_and_unknown_id_is_refused(self):
        self.make_old()
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", cwd=self.d).stdout)]
        self.assertIn("drift-guests-network", ids())
        (self.d / "discovery/drift.md").write_text("# Drift\n\n## Proxmox guests ↔ network\n")
        self.assertNotIn("drift-guests-network", ids())
        r = run("upgrade_notes.py", "--decline", "no-such-note", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown note id", r.stderr)

    def test_build_choice_in_docs_moves_to_homelab_yaml(self):   # GitHub issue #158
        sys.path.insert(0, str(SCRIPTS))
        import upgrade_notes
        run("init_repo.py", str(self.d), "--add-components", "templates", cwd=self.d)
        run("config_set.py", "upgrades.reviewed=0.60.0", "--delete", "templates.unattended_updates",
            "--delete", "templates.sshd_hardening", cwd=self.d)         # a repo set up before the keys
        ids = lambda: [n["id"] for n in upgrade_notes.pending(self.d)]
        with unittest.mock.patch.object(upgrade_notes, "installed_version", return_value="0.61.0"):
            self.assertNotIn("template-build-settings", ids())          # nothing recorded: the defaults apply
            doc = self.d / "docs/templates.md"
            doc.write_text(doc.read_text() + '\n- `unattended_updates = "off"`: patching through Ansible only.\n')
            note = next(n for n in upgrade_notes.pending(self.d) if n["id"] == "template-build-settings")
            self.assertIn(f"{SCRIPTS.parent}/scripts/config_set.py 'templates.unattended_updates=", note["action"])
            r = run("config_set.py", "templates.unattended_updates=off", cwd=self.d)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("template-build-settings", ids())
        hardening = next(n for n in upgrade_notes.all_notes() if n["id"] == "packer-ssh-hardening")
        self.assertIn("config_set.py", hardening["after_replace"])
        self.assertNotIn("site.pkrvars.hcl", hardening["after_replace"])   # gitignored and regenerated

    def test_reviewed_version_and_repo_state_filter_notes(self):
        self.make_old()
        run("config_set.py", "upgrades.reviewed=0.10.0", "vmid_scheme={vlan}{octet:03d}", cwd=self.d)
        Path(self.d, "discovery/drift.md").write_text("## Proxmox guests ↔ network\n")
        subprocess.run(["yq", "-i", '.site.language = "en" | .network.vlans = [{"id": 10, "name": "mgmt"}]',
                        str(self.cfg)], check=True)                     # config notes of 0.16.0 settled
        out = run("upgrade_notes.py", "--json", cwd=self.d).stdout
        ids = [n["id"] for n in json.loads(out)]
        sys.path.insert(0, str(SCRIPTS))
        import upgrade_notes
        self.assertEqual(ids, ["inventory-guest-ips", "recheck-hidden-suggestions",   # the latter: any reviewed repo
                               "inventory-node-versions", "overview-recovery-proxmox",
                               *(["storage-health", "scheduled-check"]
                                 if upgrade_notes.vtuple(upgrade_notes.installed_version()) >= (0, 61, 0) else [])])
        ids = [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=self.d).stdout)]
        self.assertIn("proxmox-tls-check", ids)
        subprocess.run(["yq", "-i", ".components.proxmox = false", str(self.cfg)], check=True)
        ids = [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", cwd=self.d).stdout)]
        self.assertEqual(ids, ["recheck-hidden-suggestions"])                        # no component condition

    def test_zabbix_note_only_where_zabbix_is_mentioned(self):  # GitHub issue #168
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import upgrade_notes
        note = next(n for n in upgrade_notes.all_notes() if n["id"] == "zabbix-monitoring")
        cfg = hmlib.load_config(self.d)
        self.assertFalse(upgrade_notes._check(note, cfg, self.d)[0])
        Path(self.d, "docs/monitoring.md").write_text("Alerts come from Zabbix.\n")
        self.assertTrue(upgrade_notes._check(note, cfg, self.d)[0])
        cfg["zabbix"] = {"url": "https://z.example/api_jsonrpc.php"}
        self.assertFalse(upgrade_notes._check(note, cfg, self.d)[0])   # already set up

    def test_storage_health_and_pbs_token_notes(self):  # GitHub issues #151, #152
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import upgrade_notes
        cfg = hmlib.load_config(self.d)
        notes = {n["id"]: n for n in upgrade_notes.all_notes()}
        applies = lambda i: upgrade_notes._check(notes[i], cfg, self.d)[0]
        snap, doc = self.d / "discovery/proxmox.json", self.d / "docs/proxmox-tokens.md"
        snap.write_text(json.dumps({"storage": [{"storage": "pbs1", "type": "pbs"}]}, indent=2))
        self.assertTrue(applies("storage-health"))
        self.assertFalse(applies("pbs-read-only-token"))                  # the template doc has the section
        doc.write_text(doc.read_text().split("## Proxmox Backup Server")[0])
        self.assertTrue(applies("pbs-read-only-token"))
        snap.write_text(json.dumps({"storage": [{"storage": "nfs1", "type": "nfs"}], "storage_health": {}}, indent=2))
        self.assertFalse(applies("storage-health"))
        self.assertFalse(applies("pbs-read-only-token"))                  # no PBS storage: nothing to read

    def test_guest_agent_section_only_when_agent_ips_unread_and_on_root(self):  # GitHub issue #14
        doc = self.make_old()
        snap = self.d / "discovery/proxmox.json"
        run("config_set.py", "upgrades.reviewed=0.10.0", cwd=self.d)
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", cwd=self.d).stdout)]
        snap.write_text(json.dumps({"guests": [], "guest_ip_sources": {"agent": "ok", "lxc": "ok"}}))
        self.assertNotIn("tokens-guest-agent", ids())
        snap.write_text(json.dumps({"guests": [], "guest_ip_sources": {"agent": "forbidden: x", "lxc": "ok"}}))
        self.assertIn("tokens-guest-agent", ids())
        tpl = (SCRIPTS.parent / "assets/repo-template/docs/proxmox-tokens.md").read_text()
        self.assertIn("pveum acl modify / --tokens 'homelab@pve!ro' --roles HomelabAgentAudit", tpl)
        self.assertNotIn("acl modify /vms", tpl)
        self.assertNotIn("tokens-guest-agent-acl-on-root", ids())
        doc.write_text(doc.read_text() + "\npveum acl modify /vms --users homelab@pve --roles HomelabAgentAudit\n"
                       "pveum acl modify /vms --tokens 'homelab@pve!ro' --roles HomelabAgentAudit\n")
        out = run("upgrade_notes.py", cwd=self.d).stdout
        self.assertIn("[0.12.2 · manual step · tokens-guest-agent-acl-on-root]", out)
        self.assertIn("pveum acl delete /vms --tokens 'homelab@pve!ro' --roles HomelabAgentAudit", out)

    def test_notes_file_is_well_formed(self):
        notes = json.loads((SCRIPTS.parent / "assets/upgrade-notes.json").read_text())["notes"]
        have = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["version"]
        changelog = (ROOT / "CHANGELOG.md").read_text()
        sys.path.insert(0, str(SCRIPTS))
        import upgrade_notes
        self.assertEqual(len({n["id"] for n in notes}), len(notes))
        for n in notes:
            self.assertIn(n["kind"], upgrade_notes.KIND_LABEL)
            self.assertLessEqual(upgrade_notes.vtuple(n["version"]), upgrade_notes.vtuple(have))
            self.assertIn(f"## {n['version']} ", changelog)
            self.assertTrue(set(n["when"]) <= {"component", "config_empty", "config_set", "file_lacks", "file_has", "file_missing",
                                               "vmids_outside_ranges", "agent_ips_unread", "default_site_implicit", "multi_site"}, n["id"])
            if "after_replace" in n:      # only a note a file replacement can settle has a leftover step
                self.assertTrue({"file_lacks", "file_has"} & set(n["when"]), n["id"])
            if "file_lacks" in n["when"] and n["kind"] == "template":
                for rel, text in upgrade_notes._pairs(n["when"]["file_lacks"]):   # the template settles it
                    self.assertIn(text, (SCRIPTS.parent / "assets/repo-template" / rel).read_text(), n["id"])
            # why the repo's copy wasn't replaced goes to `edited`, which a covered note doesn't show (GitHub #76)
            self.assertNotIn("local edits", n["text"], n["id"])


class TemplateHistoryTests(unittest.TestCase):  # GitHub issue #68
    def test_history_has_every_current_template_file(self):
        import hashlib
        tree = SCRIPTS.parent / "assets/repo-template"
        hist = json.loads((SCRIPTS.parent / "assets/template-history.json").read_text())["files"]
        for f in sorted(tree.rglob("*")):
            if not f.is_file() or f.name == ".DS_Store":
                continue
            rel, data = f.relative_to(tree).as_posix(), f.read_bytes()
            h = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
            self.assertIn(h, hist.get(rel, {}),
                          f"{rel} changed: run python3 .github/template_history.py and commit the result")


class UneditedTemplateTests(unittest.TestCase):  # GitHub issue #68
    TPL = "skills/homelab-manager/assets/repo-template/"

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "proxmox,ansible", cwd=self.d)
        self.cfg = self.d / "homelab.yaml"

    def old(self, tag, rel):
        r = subprocess.run(["git", "show", f"{tag}:{self.TPL}{rel}"], cwd=ROOT, capture_output=True)
        if r.returncode:
            self.skipTest(f"release tag {tag} not available")
        (self.d / rel).write_bytes(r.stdout)

    def sync(self, *args):
        return run("init_repo.py", str(self.d), "--sync-managed", *args, cwd=self.d)

    def test_unedited_file_is_replaced_and_its_note_settled(self):
        run("config_set.py", "upgrades.reviewed=0.22.0", cwd=self.d)
        run("upgrade_notes.py", "--done", "recheck-hidden-suggestions", cwd=self.d)
        for rel in ("ansible/playbooks/patch-linux.yml", "ansible/playbooks/check-updates.yml"):
            self.old("v0.22.0", rel)
        out = self.sync("--dry-run").stdout
        self.assertIn("would replace ansible/playbooks/patch-linux.yml with the current template "
                      "(no local edits since 0.22.0)", out)
        self.assertIn("[0.23.0 · patch-linux-autoremove-diskspace-lxc]", out)
        self.assertNotIn("Suggested by newer releases", out)                 # nothing left to merge by hand
        out = self.sync().stdout
        for rel in ("ansible/playbooks/patch-linux.yml", "ansible/playbooks/check-updates.yml"):
            self.assertEqual((self.d / rel).read_bytes(), (ROOT / self.TPL / rel).read_bytes())
        self.assertIn("Recorded upgrades.reviewed", out)
        self.assertIn("Up to date", self.sync("--dry-run").stdout)

    def test_edited_file_stays_a_suggestion(self):
        run("config_set.py", "upgrades.reviewed=0.22.0", cwd=self.d)
        rel = "ansible/playbooks/patch-linux.yml"
        self.old("v0.22.0", rel)
        (self.d / rel).write_text((self.d / rel).read_text() + "# local edit\n")
        before = (self.d / rel).read_text()
        out = self.sync().stdout
        self.assertNotIn(f"replace {rel}", out)
        self.assertIn("patch-linux-autoremove-diskspace-lxc", out)
        self.assertEqual((self.d / rel).read_text(), before)
        self.assertEqual(yq(".upgrades.reviewed", self.cfg), '"0.22.0"')

    def test_new_files_it_uses_are_added_opt_in_ones_are_not(self):
        self.old("v0.15.0", "ansible/playbooks/check-updates.yml")      # before tasks/restart-check.yml (0.16.0)
        (self.d / "ansible/playbooks/tasks/restart-check.yml").unlink()
        (self.d / "ansible/playbooks/patch-proxmox-node.yml").unlink()     # offered by a file_missing note
        out = self.sync().stdout
        self.assertIn("add ansible/playbooks/tasks/restart-check.yml (it uses them)", out)
        self.assertTrue((self.d / "ansible/playbooks/tasks/restart-check.yml").exists())
        self.assertFalse((self.d / "ansible/playbooks/patch-proxmox-node.yml").exists())

    def test_covered_note_drops_edited_text_and_multi_file_note_names_the_rest(self):  # GitHub issue #76
        run("config_set.py", "upgrades.reviewed=0.28.1", cwd=self.d)
        pb = "ansible/playbooks/"
        for f in ("check-updates.yml", "patch-proxmox-node.yml", "docker-containers.yml", "bmc-info.yml"):
            self.old("v0.28.1", pb + f)
        for f in ("docker-containers.yml", "bmc-info.yml"):
            (self.d / pb / f).write_text((self.d / pb / f).read_text() + "# local edit\n")
        out = self.sync("--dry-run").stdout
        self.assertIn(f"would replace {pb}check-updates.yml", out)
        self.assertIn(f"would replace {pb}patch-proxmox-node.yml", out)
        covered, _, suggested = out.partition("Suggested by newer releases")
        self.assertIn("[0.29.0 · pve-patch-one-file] pve_node_plan.py writes every plan", covered)
        self.assertNotIn("has local edits", covered)
        self.assertNotIn("pve-patch-one-file", suggested)
        self.assertIn("host-files-site-tag", suggested)
        self.assertIn(f"did not replace them: {pb}docker-containers.yml, {pb}bmc-info.yml.", suggested)
        self.assertIn(f"In {pb}docker-containers.yml, {pb}bmc-info.yml, add", suggested)
        self.assertNotIn("check-updates.yml", suggested)
        out = self.sync().stdout
        self.assertIn("host-files-site-tag", out.partition("Suggested by newer releases")[2])
        self.assertIn("host-files-site-tag", [n["id"] for n in json.loads(run("upgrade_notes.py", "--json",
                                                                                   cwd=self.d).stdout)])

    def test_after_replace_step_is_shown_and_docs_with_proxmox_steps_are_kept(self):
        run("config_set.py", "upgrades.reviewed=0.21.0", cwd=self.d)
        self.old("v0.21.0", "tofu/environments/homelab/variables.tf")
        self.old("v0.10.0", "docs/proxmox-tokens.md")
        out = self.sync("--dry-run").stdout
        self.assertIn("would replace tofu/environments/homelab/variables.tf", out)
        self.assertIn("still to do: Bring main.tf", out)
        self.assertNotIn("replace docs/proxmox-tokens.md", out)


class CheckUpdatesMergeTests(unittest.TestCase):  # issue 22
    def test_old_playbook_gets_upgrade_note(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "ansible", cwd=d)
        pb = d / "ansible/playbooks/check-updates.yml"
        self.assertIn("updates_merged", pb.read_text())
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertNotIn("check-updates-merge", ids())
        pb.write_text(pb.read_text().split("- name: Write discovery/updates.json")[0])
        self.assertIn("check-updates-merge", ids())


class OnboardingTests(unittest.TestCase):  # issue 20
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "proxmox,ansible", cwd=self.d)
        g = lambda vmid, name, kind, conf, status="running", ips=None: {
            "vmid": vmid, "name": name, "type": kind, "node": "pve1", "status": status, "template": False,
            "config": conf, **({"ips": ips} if ips else {})}
        guests = [
            g(101, "web01", "lxc", {"ostype": "debian", "net0": "name=eth0,bridge=vmbr0,ip=10.0.20.11/24,tag=20"}),
            g(102, "db01", "vm", {"ostype": "l26", "net0": "virtio=AA:BB:CC:00:00:02,bridge=vmbr0,tag=20"},
              ips=[{"ip": "fe80::1", "source": "agent"}, {"ip": "10.0.20.12", "source": "agent"}]),
            g(103, "win01", "vm", {"ostype": "win11", "net0": "virtio,bridge=vmbr0,tag=20"},
              ips=[{"ip": "10.0.20.13", "source": "agent"}]),
            g(104, "old01", "vm", {"ostype": "l26", "net0": "virtio,bridge=vmbr0,tag=20"}, status="stopped"),
            g(105, "noip", "vm", {"ostype": "l26", "net0": "virtio,bridge=vmbr0,tag=20"}),
            g(106, "Mgmt Box", "lxc", {"ostype": "rockylinux", "net0": "name=eth0,bridge=vmbr0,ip=10.0.30.5/24,tag=30"}),
            g(107, "known", "lxc", {"ostype": "debian", "net0": "name=eth0,bridge=vmbr0,ip=10.0.20.17/24,tag=20"}),
            {**g(9000, "tpl", "vm", {"ostype": "l26"}), "template": True},
        ]
        (self.d / "discovery/proxmox.json").write_text(json.dumps({"collected_at": "t", "guests": guests}))
        (self.d / "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n        known:\n          ansible_host: 10.0.20.17\n")

    def draft(self, *args):
        r = run("proxmox_to_inventory.py", *args, cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_draft_lists_linux_guests_and_skips_the_rest(self):
        out = self.draft()
        self.assertIn('        web01:  # debian\n          ansible_host: "10.0.20.11"\n          proxmox_vmid: 101', out)
        self.assertIn('db01:  # l26\n          ansible_host: "10.0.20.12"', out)       # agent IPv4, not link-local
        self.assertIn('mgmt-box:', out)
        self.assertIn("103 win01: not Linux (ostype win11)", out)
        self.assertIn("104 old01: stopped", out)
        self.assertIn("105 noip: no IP known", out)
        self.assertIn("107 known: already in the managed inventory", out)
        self.assertNotIn("tpl", out)
        data = json.loads(subprocess.run(["yq", "-o=json", "."], input=out, capture_output=True, text=True).stdout)
        self.assertEqual(sorted(data["all"]["children"]["onboarding"]["hosts"]), ["db01", "mgmt-box", "web01"])

    def test_filters(self):
        out = self.draft("--vlan", "30")
        self.assertIn("mgmt-box:", out)
        self.assertNotIn("web01", out)
        out = self.draft("--range", "10.0.20.0/28", "--type", "vm", "--group", "new")
        self.assertIn("    new:", out)
        self.assertIn("db01:", out)
        self.assertNotIn("web01", out)
        self.assertNotIn("noip", out)                                               # outside the range: silent

    def test_needs_details_snapshot(self):
        (self.d / "discovery/proxmox.json").write_text(json.dumps({"guests": [{"vmid": 1, "type": "vm"}]}))
        r = run("proxmox_to_inventory.py", cwd=self.d)
        self.assertEqual(r.returncode, 4)
        self.assertIn("--details", r.stderr)

    def test_el8_hosts_without_interpreter(self):
        sys.path.insert(0, str(SCRIPTS))
        import check_env
        self.assertEqual(check_env.ansible_core_version("ansible [core 2.21.6]\n  config file"), (2, 21))
        inv = {"_meta": {"hostvars": {"a": {}, "b": {"ansible_python_interpreter": "/usr/bin/python3.12"}, "c": {}}},
               "all": {"children": ["linux"]}, "linux": {"children": ["rocky8", "debian"]},
               "rocky8": {"hosts": ["a", "b"]}, "debian": {"hosts": ["c"]}}
        self.assertEqual(check_env.el8_without_interpreter(inv), ["a"])
        inv["linux"] = {"children": ["el9"]}
        self.assertEqual(check_env.el8_without_interpreter(inv), [])


class PreCommitHookTests(unittest.TestCase):
    HOOK = SCRIPTS.parent / "assets" / "repo-template" / "scripts" / "git-hooks" / "pre-commit"

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q"], cwd=self.d, check=True)

    def tearDown(self):
        shutil.rmtree(self.d)

    def staged(self, name, text="x\n"):
        p = self.d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        subprocess.run(["git", "add", "-f", "--", name], cwd=self.d, check=True)
        r = subprocess.run(["bash", str(self.HOOK)], cwd=self.d, capture_output=True, text=True)
        subprocess.run(["git", "rm", "-q", "--cached", "-f", "--", name], cwd=self.d, check=True)
        p.unlink()
        return r.returncode

    def test_refuses_secret_files_and_tokens(self):
        for name in ["state/x.tfstate", "a b/id_ed25519", "keys/id_rsa_backup", "cert.pfx", ".env.local",
                     "site.secret.pkrvars.hcl", "tofu/.terraform/x", "my key.pem", "ansible/.vault_pass"]:
            self.assertEqual(self.staged(name), 1, name)
        self.assertEqual(self.staged("notes.md", "aws ASIA" + "ABCDEFGHIJKLMNOP\n"), 1)
        self.assertEqual(self.staged("notes.md", "key AKIA" + "ABCDEFGHIJKLMNOP\n"), 1)
        for name in ["keys/id_ed25519.pub", "README.md", "tofu/.terraform.lock.hcl", "docs/id-card.md"]:
            self.assertEqual(self.staged(name), 0, name)


    def hook(self, *args):
        return subprocess.run(["bash", str(self.HOOK), *args], cwd=self.d, capture_output=True, text=True)

    def test_literal_passwords(self):
        for text in ['password: "hunter2hunter"\n', '  api_key = "abcdef123456"\n',
                     'services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=supersecret1\n',
                     "export GITHUB_TOKEN=abcdefabcdef\n", "mysql_root_password: s3cr3tvalue\n"]:
            self.assertEqual(self.staged("conf.yml", text), 1, text)
        for text in ['password: "{{ vault_db_password }}"\n', "secret = var.secret\n", "state_secret: s3-state\n",
                     "token = secrets.token_hex(16)\n", "password: short\n", "the secret:proxmox-ro line\n",
                     'password: "hunter2hunter"  # pre-commit: allow\n', "admin_password: changeme-later\n"]:
            self.assertEqual(self.staged("conf.yml", text), 0, text)
        (self.d / "c.yml").write_text('token: "abcdefabcdefabcdef"\n')
        subprocess.run(["git", "add", "c.yml"], cwd=self.d, check=True)
        r = self.hook()
        self.assertEqual(r.returncode, 1)
        self.assertIn('token: "ab…', r.stdout)
        self.assertNotIn("abcdefabcdefabcdef", r.stdout)   # the value is not printed

    def test_unencrypted_vault_file(self):
        self.assertEqual(self.staged("ansible/group_vars/all/vault.yml", "db_password: x\n"), 1)
        self.assertEqual(self.staged("ansible/group_vars/all/vault.yml", "$ANSIBLE_VAULT;1.1;AES256\n6162\n"), 0)

    def test_spaces_renames_and_history(self):
        git = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *a],
                                        cwd=self.d, check=True, capture_output=True)
        (self.d / "my notes.md").write_text("fine\n")
        (self.d / "cert.txt").write_text("not a key\n")
        git("add", "-A")
        self.assertEqual(self.hook().returncode, 0)       # a name with a space is one name
        git("commit", "-qm", "init")
        git("mv", "cert.txt", "cert.pfx")
        r = self.hook()
        self.assertEqual(r.returncode, 1)                 # a rename into a secret file name
        self.assertIn("cert.pfx", r.stdout)
        git("reset", "-q")
        self.assertEqual(self.hook("--history").returncode, 0)
        (self.d / "old.yml").write_text("password: hunter2hunter\n")
        git("add", "old.yml")
        git("commit", "-qm", "oops", "--no-verify")
        git("rm", "-q", "old.yml")
        git("commit", "-qm", "gone")
        self.assertEqual(self.hook().returncode, 0)
        self.assertEqual(self.hook("--history").returncode, 1)   # still in an old commit


class PluginVersionGuardTests(unittest.TestCase):  # GitHub issue #111
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", self.d, "--components", "proxmox,ansible,discovery", cwd=self.d)

    def test_older_plugin_than_repo(self):
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        cfg = {"upgrades": {"reviewed": "0.36.0"}}
        self.assertEqual(hmlib.plugin_version_check(cfg, "overview.py", "0.36.0")[0], "ok")
        self.assertEqual(hmlib.plugin_version_check(cfg, "overview.py", "0.37.1")[0], "ok")
        self.assertEqual(hmlib.plugin_version_check({}, "overview.py", "0.1.0")[0], "ok")
        level, msg = hmlib.plugin_version_check(cfg, "overview.py", "0.35.0")
        self.assertEqual(level, "refuse")
        self.assertIn("from homelab-manager 0.35.0, but this repository was upgraded to 0.36.0", msg)
        self.assertEqual(hmlib.plugin_version_check(cfg, "check_env.py", "0.35.0")[0], "warn")
        self.assertEqual(hmlib.plugin_version_check(cfg, "issues.py", "0.35.0")[0], "warn")

    def test_scripts_refuse_or_warn(self):
        self.assertEqual(run("config_set.py", "upgrades.reviewed=99.0.0", cwd=self.d).returncode, 0)
        r = run("overview.py", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 3)
        self.assertIn("was upgraded to 99.0.0", r.stderr)
        self.assertFalse(Path(self.d, "OVERVIEW.md").exists())
        r = run("issues.py", "list", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("warning: issues.py is from homelab-manager", r.stderr)


class MissingYqTests(unittest.TestCase):  # GitHub issue #119: no yq → a clean error before anything is written
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import config_set
        import hmlib
        import init_repo
        self.hmlib, self.init_repo, self.config_set = hmlib, init_repo, config_set
        self.d = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_yq_bin_falls_back_to_homebrew_then_errors(self):
        from unittest import mock
        with mock.patch.object(self.hmlib.shutil, "which", return_value=None), \
                mock.patch.object(self.hmlib.Path, "exists", lambda p: str(p) == "/opt/homebrew/bin/yq"):
            self.assertEqual(self.hmlib.yq_bin(), "/opt/homebrew/bin/yq")
        with mock.patch.object(self.hmlib.shutil, "which", return_value=None), \
                mock.patch.object(self.hmlib.Path, "exists", return_value=False):
            with self.assertRaisesRegex(self.hmlib.ConfigError, "brew install yq"):
                self.hmlib.yq_bin()

    def main(self, module, *argv):
        from unittest import mock
        err = io.StringIO()
        with mock.patch.object(self.hmlib, "yq_bin", side_effect=self.hmlib.ConfigError("yq is not installed (brew install yq).")), \
                mock.patch.object(sys, "argv", [module.__name__ + ".py", *argv]), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            return module.main(), err.getvalue()

    def test_init_repo_writes_nothing(self):
        for dry in ([], ["--dry-run"]):
            rc, err = self.main(self.init_repo, str(self.d), "--components", "ansible,discovery", *dry)
            self.assertEqual(rc, 2)
            self.assertIn("brew install yq", err)
            self.assertIn("Nothing was written", err)
            self.assertEqual(list(self.d.iterdir()), [])
        rc, _ = self.main(self.init_repo, "--list-components")   # needs no yq
        self.assertEqual(rc, 0)

    def test_config_set_clean_error(self):
        cfg = self.d / "homelab.yaml"
        cfg.write_text("site:\n  domain: a\n")
        rc, err = self.main(self.config_set, "--file", str(cfg), "site.domain=b")
        self.assertEqual(rc, 2)
        self.assertIn("config_set: yq is not installed (brew install yq).", err)
        self.assertEqual(cfg.read_text(), "site:\n  domain: a\n")


if __name__ == "__main__":
    unittest.main()
