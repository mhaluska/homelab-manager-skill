"""Tests for init_repo.py (components, upgrades) and issues.py (skill-problem tracker)."""
import json
import os
import re
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
        self.assertTrue((p / "skill_issues.md").exists())
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
        self.assertEqual(d["permissions"]["allow"], ["Bash(ls:*)"])          # user's rules kept
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


class IssuesTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "ansible", cwd=self.d)

    def tearDown(self):
        shutil.rmtree(self.d)

    def issues(self, *args):
        return run("issues.py", *args, cwd=self.d)

    def test_add_list_resolve_roundtrip(self):
        r = self.issues("add", "--title", "drift_report.py crashes without backup_jobs", "--kind", "script",
                        "--key", "script:drift_report:backup_jobs",
                        "--body", "### Summary\nKeyError 'backup_jobs'.\n\n### Actual\nTraceback …")
        self.assertIn("Added SKILL-001", r.stdout)
        self.issues("add", "--title", "Guard blocks gh issue list", "--kind", "guard")
        text = Path(self.d, "skill_issues.md").read_text()
        self.assertIn("| SKILL-001 | script | drift_report.py crashes without backup_jobs | open |", text)
        self.assertIn("### Environment\n- homelab-manager ", text)          # filled in automatically
        self.assertIn("- components: ansible", text)
        self.assertIn("SKILL-002", self.issues("list", "--status", "open").stdout)
        r = self.issues("resolve", "1", "--note", "fixed in 0.6.1")
        self.assertIn("SKILL-001 → resolved", r.stdout)
        text = Path(self.d, "skill_issues.md").read_text()
        self.assertIn("**Resolution", text)
        self.assertEqual(text.count("KeyError 'backup_jobs'"), 1)  # body not duplicated by re-render
        self.assertNotIn("SKILL-001", self.issues("list", "--status", "open").stdout)

    def test_idea_kinds_use_their_own_sections(self):
        r = self.issues("add", "--title", "Keep a dated history of drift reports", "--kind", "improvement",
                        "--key", "idea:drift:history",
                        "--body", "### Summary\nOnly the latest drift.md is kept.\n\n### Context\nWeekly checks.\n\n"
                                  "### Proposal\nWrite discovery/drift-<date>.md too.")
        self.assertIn("Added SKILL-001", r.stdout)
        self.assertEqual(r.stderr, "")                                 # Benefit is optional: no nag
        self.issues("add", "--title", "Support OPNsense backups", "--kind", "idea")
        text = Path(self.d, "skill_issues.md").read_text()
        self.assertIn("| SKILL-001 | improvement | Keep a dated history of drift reports | open |", text)
        self.assertIn("### Context\nWeekly checks.\n\n### Proposal\nWrite", text)
        self.assertIn("### Benefit\n_none_", text)
        self.assertNotIn("Steps to reproduce", text.split("## SKILL-001")[1])
        self.assertIn("### Proposal\n_unknown_", text.split("## SKILL-002")[1])
        self.assertIn("ideas", text.split("| ID |")[0])               # header explains ideas are welcome
        self.assertIn("--kind idea", self.issues("add", "--title", "z", "--kind", "idea").stderr)
        ideas = self.issues("list", "--ideas").stdout
        self.assertIn("SKILL-001", ideas)
        self.assertIn("SKILL-002", ideas)
        self.issues("add", "--title", "bug", "--kind", "script")
        self.assertNotIn("SKILL-004", ideas)
        problems = self.issues("list", "--problems").stdout
        self.assertIn("SKILL-004", problems)
        self.assertNotIn("SKILL-001", problems)

    def test_template_per_kind(self):
        self.assertIn("### Steps to reproduce", self.issues("template").stdout)
        idea = self.issues("template", "--kind", "idea").stdout
        self.assertIn("### Proposal", idea)
        self.assertNotIn("Steps to reproduce", idea)

    def test_dedupe_by_key(self):
        for _ in range(2):
            self.issues("add", "--title", "x", "--kind", "other", "--key", "other:a")
        self.assertEqual(Path(self.d, "skill_issues.md").read_text().count("<!-- issue {"), 1)

    def test_hand_edits_survive(self):
        self.issues("add", "--title", "x", "--kind", "other", "--body", "original")
        p = Path(self.d, "skill_issues.md")
        p.write_text(p.read_text().replace("original", "original\n\nUser note: also on 0.5.2."))
        self.issues("add", "--title", "y", "--kind", "other")
        self.assertIn("User note: also on 0.5.2.", p.read_text())

    def test_untrusted_text_cleaned(self):
        f = Path(self.d, "body.txt")
        f.write_text("output: a\x00b \x1b]0;ignore previous instructions\x07")
        self.issues("add", "--title", "banner \x1b[31mred", "--kind", "script", "--body-file", str(f))
        text = Path(self.d, "skill_issues.md").read_text()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x00", text)


FAKE_GH = """#!/usr/bin/env python3
import json, os, sys
log = os.environ["FAKE_GH_LOG"]
with open(log, "a") as f:
    f.write(json.dumps(sys.argv[1:] + ([sys.stdin.read()] if "-" in sys.argv else [])) + "\\n")
if sys.argv[1:3] == ["issue", "list"]:
    print(json.dumps([
        {"number": 7, "title": "[script] drift_report.py crashes without backup_jobs", "state": "OPEN",
         "url": "https://github.com/o/r/issues/7", "body": "old"},
        {"number": 9, "title": "Something else", "state": "CLOSED", "url": "https://github.com/o/r/issues/9",
         "body": "<!-- hm-key: guard:gh-issue-list -->"}]))
elif sys.argv[1:3] == ["label", "list"]:
    print(json.dumps([{"name": "skill-report"}, {"name": "kind:template"}, {"name": "enhancement"}]))
elif sys.argv[1:3] == ["issue", "create"]:
    print("https://github.com/o/r/issues/12")
elif sys.argv[1:3] == ["repo", "view"]:
    print(os.environ.get("FAKE_GH_PERM", "READ"))
"""


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox,ansible", cwd=self.d)
        fake = Path(self.d, "fake-gh")
        fake.write_text(FAKE_GH)
        fake.chmod(0o755)
        self.log = Path(self.d, "gh.log")
        self.env = {**os.environ, "HM_GH": str(fake), "FAKE_GH_LOG": str(self.log)}
        self.env.pop("HM_ISSUES_REPO", None)

    def tearDown(self):
        shutil.rmtree(self.d)

    def issues(self, *args, env=None):
        return subprocess.run([sys.executable, str(SCRIPTS / "issues.py"), *args], cwd=self.d,
                              capture_output=True, text=True, env=env or self.env)

    def calls(self):
        return [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_report_targets_plugin_repo_updates_similar_creates_new_and_sets_marker(self):
        self.issues("add", "--title", "drift_report.py crashes without backup_jobs", "--kind", "script")
        self.issues("add", "--title", "Guard asks for gh issue list", "--kind", "guard", "--key", "guard:gh-issue-list")
        self.issues("add", "--title", "packer validate fails on debian13", "--kind", "template")
        dry = self.issues("report", "--dry-run")
        self.assertIn("Target: mhaluska/homelab-manager-skill", dry.stdout)
        self.assertIn("SKILL-001  UPDATE #7", dry.stdout)
        self.assertIn("SKILL-002  UPDATE #9", dry.stdout)          # same key, even though closed
        self.assertIn("not reopened", dry.stdout)
        self.assertIn("SKILL-003  CREATE", dry.stdout)
        self.assertIn("### Environment", dry.stdout)                # dry run shows exactly what is sent
        self.assertEqual([c[:2] for c in self.calls()], [["issue", "list"]])  # dry run only lists
        self.assertIn("mhaluska/homelab-manager-skill", self.calls()[0])
        self.assertNotIn("reported-through", Path(self.d, "skill_issues.md").read_text())

        r = self.issues("report")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()[1:]
        verbs = [c[:2] for c in calls]
        self.assertEqual(verbs.count(["issue", "comment"]), 2)
        self.assertEqual(verbs.count(["issue", "create"]), 1)
        self.assertNotIn(["label", "create"], verbs)                 # never creates labels
        create = next(c for c in calls if c[:2] == ["issue", "create"])
        self.assertNotIn("--label", create)                          # READ permission: no labels
        comment = next(c for c in calls if c[:2] == ["issue", "comment"])
        self.assertIn("Seen again", comment[-1])                     # body sent on stdin, not argv
        text = Path(self.d, "skill_issues.md").read_text()
        self.assertIn("<!-- reported-through: ", text)
        self.assertIn("issues/12", text)

        again = self.issues("report", "--dry-run")                   # nothing new since the marker
        self.assertIn("0 issue(s) to report", again.stdout)
        self.issues("add", "--title", "New problem", "--kind", "other")
        self.assertIn("SKILL-004  CREATE", self.issues("report", "--dry-run").stdout)
        self.assertNotIn("SKILL-001", self.issues("report", "--dry-run").stdout)

    def test_report_ids_keeps_marker_for_other_unsent(self):  # GitHub issue #16
        self.issues("add", "--title", "packer validate fails on debian13", "--kind", "template")
        self.issues("add", "--title", "Another unrelated problem", "--kind", "other")
        r = self.issues("report", "SKILL-001")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Marker unchanged", r.stdout)
        dry = self.issues("report", "--dry-run").stdout
        self.assertIn("1 issue(s) to report", dry)
        self.assertIn("SKILL-002  CREATE", dry)
        self.assertNotIn("SKILL-001", dry)                           # sent: its own reported_at covers it

    def test_unsent_entry_behind_marker_is_offered(self):  # GitHub issue #16: repos the old bug left stuck
        self.issues("add", "--title", "Stuck problem", "--kind", "other")
        p = Path(self.d, "skill_issues.md")
        import importlib
        sys.path.insert(0, str(SCRIPTS))
        issues = importlib.import_module("issues")
        issues.save(p, issues.load(p), "2999-01-01T00:00:00+00:00")
        self.assertIn("SKILL-001  CREATE", self.issues("report", "--dry-run").stdout)

    def test_token_colon_prose_kept_secrets_counted(self):  # GitHub issue #15
        self.issues("add", "--title", "ACL for the 'token: root' path", "--kind", "template", "--body",
                    "Permissions for the token: `/` → VM.Audit, and the token: root path.\n"
                    "Real ones: token: 0b0c1d2e-3f40-4152-6374-8596a7b8c9d0 and api_key: sk3cr3tvalue99")
        out = self.issues("report", "--dry-run").stdout
        for kept in ("token: `/` → VM.Audit", "token: root path", "'token: root' path"):
            self.assertIn(kept, out, kept)
        for leak in ("0b0c1d2e", "sk3cr3tvalue99"):
            self.assertNotIn(leak, out, leak)
        self.assertIn("token: <redacted> and api_key: <redacted>", out)
        self.assertRegex(out, r"Redacted: .*2 secrets")

    def test_labels_only_with_triage_rights_and_only_existing(self):
        self.issues("add", "--title", "packer validate fails on debian13", "--kind", "template")
        self.issues("report", env={**self.env, "FAKE_GH_PERM": "WRITE"})
        create = next(c for c in self.calls() if c[:2] == ["issue", "create"])
        self.assertEqual(create[create.index("--label") + 1], "skill-report,kind:template")

    def test_idea_labels(self):
        self.issues("add", "--title", "Dated drift history", "--kind", "improvement")
        self.issues("report", env={**self.env, "FAKE_GH_PERM": "WRITE"})
        create = next(c for c in self.calls() if c[:2] == ["issue", "create"])
        self.assertEqual(create[create.index("--title") + 1], "[improvement] Dated drift history")
        self.assertEqual(create[create.index("--label") + 1], "enhancement")  # kind:improvement doesn't exist

    def test_sanitised_before_sending(self):
        subprocess.run(["yq", "-i", '.site.domain = "lab.example.net" | .proxmox.endpoint = "https://pve7.lab.example.net:8006"',
                        str(Path(self.d, "homelab.yaml"))], check=True)
        Path(self.d, "ansible/inventory/managed/hosts.yml").write_text("all:\n  children:\n    linux:\n      hosts:\n        nas-kitchen: {}\n")
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps({"guests": [{"vmid": 101, "name": "vault-prod"}]}))
        home = str(Path.home())
        body = ("### Summary\nScan of 192.168.77.0/24 failed on nas-kitchen.lab.example.net (vault-prod too).\n"
                f"### Evidence\nFile \"{home}/Git/homelab/x.py\" · MAC aa:bb:cc:dd:ee:ff · fd00:1::5 · ok 127.0.0.1\n"
                "PVEAPIToken=root@pam!tf=0b0c… password=hunter2 token ghp_abcdefghijklmnopqrstuvwxyz0123456789 "
                "mail me@example.org at 12:34:56\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
        self.issues("add", "--title", "nmap_scan fails on nas-kitchen", "--kind", "script", "--body", body)
        out = self.issues("report", "--dry-run").stdout
        for leak in ("192.168.77", "nas-kitchen", "example.net", "pve7", "vault-prod", home, "aa:bb:cc", "fd00:1::5",
                     "hunter2", "ghp_", "root@pam!tf", "me@example.org", "AAAA"):
            self.assertNotIn(leak, out, leak)
        for kept in ("<ip>/24", "<host>.<domain>", "127.0.0.1", "12:34:56", "<mac>", "nmap_scan fails on <host>"):
            self.assertIn(kept, out, kept)
        self.assertIn("nas-kitchen", Path(self.d, "skill_issues.md").read_text())  # local copy keeps the detail

    def test_proxmox_identifiers_redacted_with_stable_placeholders(self):  # GitHub issue #10
        px = {"nodes": [{"node": "atlas"}],
              "guests": [{"vmid": 1020015, "name": "gw", "node": "atlas", "pool": "family",
                          "config": {"net0": "virtio=AA:BB:CC:00:11:22,bridge=iotbr,tag=1020",
                                     "net1": "virtio=AA:BB:CC:00:11:23,bridge=vmbr0,tag=7,trunks=30;40"}},
                         {"vmid": 245, "name": "dns", "node": "atlas"}],
              "storage": [{"storage": "tank-ssd", "node": "atlas"}, {"storage": "local-zfs", "node": "atlas"}],
              "networks": {"atlas": [{"iface": "vmbr0.55", "type": "vlan"}, {"iface": "iotbr", "type": "bridge"}]}}
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(px))
        body = ("### Summary\nGuest 1020015 = VLAN 1020 on atlas; 245 too (tag=7, vlan55, trunks=30;40).\n"
                "Disk tank-ssd:vm-245-disk-0 in pool family on bridge iotbr, vmbr0.55; local-zfs is fine.\n"
                "Traceback line 245 of proxmox 9.1.245, port 1020 and VLAN 1020 again; 50% of 1024 MiB.")
        self.issues("add", "--title", "VMID 245 on atlas", "--kind", "script", "--body", body)
        out = self.issues("report", "--dry-run").stdout
        for leak in ("1020015", "1020", "atlas", "tank-ssd", "family", "iotbr", "vm-245", "tag=7", "vlan55",
                     "vmbr0.55", "30;40"):
            self.assertNotIn(leak, out, leak)
        for kept in ("[script] VMID <vmid-1> on <node-1>", "Guest <vmid-2> = VLAN <vlan-", "on <node-1>; <vmid-1> too",
                     "<storage-1>:vm-<vmid-1>-disk-0", "pool <pool-1>", "bridge <bridge-1>", "local-zfs is fine",
                     "line 245", "9.1.245", "1024 MiB", "50%"):
            self.assertIn(kept, out, kept)
        tag = re.search(r"VLAN (<vlan-\d+>) on", out).group(1)
        self.assertIn(f"VLAN {tag} again", out)  # same value, same placeholder
        self.assertRegex(out, r"Redacted: 2 VMIDs, \d VLANs, 1 node, 1 storage, 1 pool, 1 bridge")

    def test_dry_run_without_gh_still_shows_text(self):
        self.issues("add", "--title", "x crashes", "--kind", "script")
        r = self.issues("report", "--dry-run", env={**self.env, "HM_GH": "/usr/bin/false"})
        self.assertEqual(r.returncode, 0)
        self.assertIn("existing issues not checked", r.stderr)
        self.assertIn("SKILL-001  CREATE", r.stdout)
        self.assertNotEqual(self.issues("report", env={**self.env, "HM_GH": "/usr/bin/false"}).returncode, 0)

    def test_reporting_can_be_turned_off(self):
        subprocess.run(["yq", "-i", ".issues.report = false", str(Path(self.d, "homelab.yaml"))], check=True)
        self.assertEqual(self.issues("report", "--dry-run").returncode, 4)
        self.assertEqual(self.calls(), [])

    def test_overrides(self):
        self.issues("add", "--title", "drift_report.py crashes without backup_jobs", "--kind", "script")
        self.assertIn("CREATE", self.issues("report", "--dry-run", "--new", "SKILL-001").stdout)
        self.assertIn("UPDATE #9", self.issues("report", "--dry-run", "--match", "SKILL-001=9").stdout)


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


class IssueTemplateTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "ansible", cwd=self.d)

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_plain_body_gets_template_sections(self):
        r = run("issues.py", "add", "--title", "x", "--kind", "other", "--body", "just text", cwd=self.d)
        self.assertIn("no Steps to reproduce, Expected, Actual, Evidence yet", r.stderr)
        text = Path(self.d, "skill_issues.md").read_text()
        self.assertIn("### Summary\njust text", text)
        self.assertIn("### Proposed fix\n_none_", text)              # optional
        self.assertLess(text.index("### Evidence"), text.index("### Environment"))

    def test_template_command_and_plugin_issue_form_share_sections(self):
        sys.path.insert(0, str(SCRIPTS))
        import issues
        tpl = run("issues.py", "template", cwd="/").stdout             # works outside a homelab repo
        self.assertEqual([l[4:] for l in tpl.splitlines() if l.startswith("### ")], issues.SECTIONS)
        form = ROOT / ".github" / "ISSUE_TEMPLATE" / "skill-problem.yml"
        labels = json.loads(yq('[.body[] | select(.type == "textarea") | .attributes.label]', form))
        self.assertEqual(labels, issues.SECTIONS)

    def test_new_repo_has_no_issue_form_and_needs_no_upgrade(self):
        self.assertFalse(Path(self.d, ".github").exists())
        self.assertIn("Up to date", run("init_repo.py", self.d, "--sync-managed", "--dry-run", cwd=self.d).stdout)


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
        self.assertEqual(r.stdout.strip(), "")


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


class DriftTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox,ansible", cwd=self.d)
        snap = {"collected_at": "2026-01-01T00:00:00+00:00", "version": "9", "cluster": None, "nodes": [],
                "networks": {}, "storage": [{"storage": "local-zfs", "node": "pve1", "content": "images,rootdir"}],
                "guests": [{"vmid": 100, "name": "dns01", "type": "vm", "node": "pve1", "status": "running",
                            "template": False, "tags": "debian;tofu"},
                           {"vmid": 104, "name": "test-old", "type": "vm", "node": "pve1", "status": "stopped",
                            "template": False, "tags": ""},
                           {"vmid": 9051, "name": "tpl", "type": "vm", "node": "pve1", "status": "stopped",
                            "template": True, "tags": ""}],
                "backup_jobs": [{"id": "daily", "enabled": True, "all": False, "vmid": "100"}]}
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(snap))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_tag_fallback_and_backups_without_state(self):
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("104 vm `test-old`", r.stdout)
        self.assertNotIn("9051", r.stdout.split("## Backups")[0])  # Packer templates aren't "unmanaged"
        self.assertIn("No storage accepts `backup` content", r.stdout)
        self.assertIn("104 `test-old` is in no backup job", r.stdout)
        self.assertNotIn("100 `dns01` is in no backup job", r.stdout)


class GuestNetworkMappingTests(unittest.TestCase):
    """#7: scanned addresses are matched to Proxmox guests (config/agent IP, MAC, DNS name)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox,discovery", cwd=self.d)
        guest = lambda vmid, name, typ, **kw: {"vmid": vmid, "name": name, "type": typ, "node": "pve1",
                                               "status": "running", "template": False, "tags": "tofu", **kw}
        snap = {"collected_at": "2026-01-01T00:00:00+00:00", "version": "9", "cluster": None, "nodes": [],
                "networks": {}, "storage": [], "backup_jobs": None,
                "guest_ip_sources": {"agent": "forbidden: the read-only token (and its user) need VM.GuestAgent.Audit"},
                "guests": [guest(901, "dns", "lxc", config={"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,"
                                                                     "ip=10.0.10.53/24,gw=10.0.10.1,tag=10"}),
                           guest(101, "web", "vm", config={"net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0",
                                                           "ipconfig0": "ip=dhcp"},
                                 ips=[{"iface": "eth0", "mac": "bc:24:11:00:00:02", "ip": "10.0.10.80", "source": "agent"}]),
                           guest(102, "mail", "vm", config={"net0": "virtio=BC:24:11:00:00:03,bridge=vmbr0"}),
                           guest(103, "vault", "vm", config={"net0": "virtio=BC:24:11:00:00:04,bridge=vmbr0"}),
                           guest(104, "offline", "vm", config={})]}
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(snap))
        host = lambda mac=None, names=(): {"mac": mac, "hostnames": list(names), "device_type_guess": "linux", "vendor": None}
        net = {"updated_at": "2026-01-01", "hosts": {"10.0.10.53": host(), "10.0.10.80": host(),
                                                     "10.0.10.25": host(mac="BC:24:11:00:00:03"),
                                                     "10.0.10.40": host(names=["vault.lab.example"]),
                                                     "10.0.10.9": host(names=["printer.lab.example"]),
                                                     "10.0.10.7": {**host(names=["ilo-srv1"]), "device_type_guess": "bmc"}}}
        Path(self.d, "discovery/network.json").write_text(json.dumps(net))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_matching(self):
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        section = r.stdout.split("## Proxmox guests ↔ network")[1].split("\n## ")[0]
        for line in ("10.0.10.25 → 102 vm `mail` (MAC)", "10.0.10.40 → 103 vm `vault` (DNS name vault.lab.example)",
                     "10.0.10.53 → 901 lxc `dns` (config IP)", "10.0.10.80 → 101 vm `web` (agent IP)",
                     "- 104 vm `offline`", "VM.GuestAgent.Audit"):
            self.assertIn(line, section, line)
        unmanaged = r.stdout.split("## Network devices not in managed inventory")[1]
        self.assertIn("2 device(s)", unmanaged)
        self.assertIn("10.0.10.9 printer", unmanaged)
        self.assertIn("10.0.10.7 ilo-srv1 — bmc — **management controller (BMC)**", unmanaged)  # #17
        self.assertNotIn("printer.lab.example — linux — **", unmanaged)

    def test_inventory_reads_agent_and_lxc_ips_and_degrades_on_403(self):
        import urllib.error
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        calls = []

        def fake(path, **_):
            calls.append(path)
            if path.endswith("/agent/network-get-interfaces"):
                if "/101/" in path:
                    return {"result": [{"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1"}]},
                                       {"name": "eth0", "hardware-address": "bc:24:11:00:00:02",
                                        "ip-addresses": [{"ip-address": "10.0.10.80"}, {"ip-address": "fe80::1"}]}]}
                raise urllib.error.HTTPError(path, 403, "Forbidden", {}, None)
            if path.endswith("/interfaces"):
                return [{"name": "eth0", "hwaddr": "bc:24:11:00:00:01", "inet": "10.0.10.53/24"}]
            raise AssertionError(path)
        pve._get = fake
        src = {"agent": "not queried", "lxc": "not queried"}
        vm = lambda vmid: {"node": "pve1", "vmid": vmid}
        self.assertEqual([a["ip"] for a in inv.guest_ips(pve, vm(101), "qemu", {"agent": "1"}, src)], ["10.0.10.80"])
        self.assertEqual(inv.guest_ips(pve, vm(102), "qemu", {"agent": "enabled=1,fstrim_cloned_disks=1"}, src), [])
        self.assertIn("VM.GuestAgent.Audit", src["agent"])
        n = len(calls)
        self.assertEqual(inv.guest_ips(pve, vm(103), "qemu", {"agent": "1"}, src), [])  # no retry after 403
        self.assertEqual(inv.guest_ips(pve, vm(104), "qemu", {"agent": "0"}, src), [])
        self.assertEqual(len(calls), n)
        self.assertEqual(inv.guest_ips(pve, vm(901), "lxc", {}, src)[0]["ip"], "10.0.10.53")


    def test_no_guests_hint_names_narrow_acl(self):  # GitHub issue #14
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        perms = {"/": {"VM.Audit": 1, "VM.GuestAgent.Audit": 1}, "/vms": {"VM.GuestAgent.Audit": 1}}
        pve._get = lambda path, **_: perms
        hint = inv.no_guests_hint(pve)
        self.assertIn("/vms lacks VM.Audit", hint)
        self.assertIn("next to PVEAuditor", hint)
        del perms["/vms"]
        self.assertIsNone(inv.no_guests_hint(pve))
        self.assertIn("no VM.Audit on /", inv.no_guests_hint(type("P", (), {"_get": lambda self, p: {"/": {}}})()))
        s = inv.summary({"version": "9.1", "cluster": None, "nodes": [], "guests": [], "storage": [],
                         "warnings": ["no guests visible: x"]})
        self.assertIn("Warning: no guests visible: x.", s)


class VmidSchemeTests(unittest.TestCase):
    """#6: VMIDs that encode the network (vmid_scheme), and a warning when the ranges don't fit."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox", cwd=self.d)
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib
        lxc = lambda vmid, tag, ip: {"vmid": vmid, "name": f"g{vmid}", "type": "lxc", "template": False,
                                     "config": {"net0": f"name=eth0,bridge=vmbr0,ip={ip}/24,tag={tag}"}}
        self.guests = [lxc(1020015, 1020, "10.20.0.15"), lxc(1020016, 1020, "10.20.0.16"),
                       lxc(30007, 30, "10.30.0.7"), {"vmid": 9050, "name": "tpl", "template": True}]
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps({"guests": self.guests}))
        Path(self.d, "tofu/environments/homelab/homelab.auto.tfvars").write_text(
            Path(self.d, "tofu/environments/homelab/homelab.auto.tfvars").read_text() + "\n# vm_id = 101\nx = {\n  vm_id = 100\n}\n")

    def tearDown(self):
        shutil.rmtree(self.d)

    def cfg(self):
        return self.h.load_config(self.d)

    def test_ranges_by_default_and_warning_suggests_scheme(self):
        r = run("proxmox_inventory.py", "--next-vmid", "vms", cwd=self.d)
        self.assertEqual(r.stdout.strip(), "101", r.stderr)  # 100 is in tfvars
        self.assertEqual(run("proxmox_inventory.py", "--next-vmid", "templates", cwd=self.d).stdout.strip(), "9051")
        warn = self.h.vmid_fit(self.cfg(), self.guests)
        self.assertIn("3 of 4 existing guests have VMIDs outside vmid_ranges", warn)
        self.assertIn("vmid_scheme={vlan}{octet:03d}", warn)

    def test_scheme(self):
        self.assertEqual(run("config_set.py", "vmid_scheme={vlan}{octet:03d}", cwd=self.d).returncode, 0)
        self.assertIsNone(self.h.vmid_fit(self.cfg(), self.guests))
        r = run("proxmox_inventory.py", "--next-vmid", "lxc", "--ip", "10.20.0.17/24", "--vlan", "1020", cwd=self.d)
        self.assertEqual(r.stdout.strip(), "1020017", r.stderr)
        r = run("proxmox_inventory.py", "--next-vmid", "vms", "--ip", "10.20.0.15", "--vlan", "1020", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already used by lxc g1020015", r.stderr)
        r = run("proxmox_inventory.py", "--next-vmid", "vms", "--ip", "10.20.0.18", cwd=self.d)
        self.assertIn("needs the guest's VLAN tag", r.stderr)
        self.assertEqual(run("proxmox_inventory.py", "--next-vmid", "templates", cwd=self.d).stdout.strip(), "9051")
        with self.assertRaises(self.h.ConfigError):
            self.h.vmid_from_scheme("{vlan}{octet:03d}", "10.0.0.5", 0)  # 5 < 100
        self.assertIn("Only 0 of 3", self.h.vmid_fit({"vmid_scheme": "{o3}{octet:03d}"}, self.guests))


class TokenAclTests(unittest.TestCase):
    """#5: privilege-separated tokens only get what their user also has."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        run("init_repo.py", str(self.d), "--components", "proxmox", cwd=self.d)
        self.doc = self.d / "docs/proxmox-tokens.md"

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_template_grants_user_and_token(self):
        text = self.doc.read_text()
        for role, tid in (("PVEAuditor", "ro"), ("HomelabProvisioner", "rw")):
            self.assertIn(f"pveum acl modify / --users homelab@pve --roles {role}", text)
            self.assertIn(f"pveum acl modify / --tokens 'homelab@pve!{tid}' --roles {role}", text)
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout)

    def test_old_doc_gets_user_acls_once(self):
        text = self.doc.read_text()
        text = re.sub(r"\nOptional — VM IPs.*?\n```\n", "", text, flags=re.S)  # added in 0.11.0
        old = "\n".join(l for l in text.splitlines() if "--users" not in l) + "\n"
        old = old.split("Both tokens use privilege separation")[0].rstrip("\n") + "\n\n## " + old.split("\n## ", 1)[1]
        old = old.replace("/ --tokens 'homelab@pve!rw'", "/pool/lab --tokens 'homelab@pve!rw'")  # user-edited path
        self.doc.write_text(old)
        out = run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout
        self.assertIn("docs/proxmox-tokens.md: grant the token roles to the user too (2 ACL line(s)", out)
        self.assertEqual(self.doc.read_text(), old)
        run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        new = self.doc.read_text()
        self.assertIn("pveum acl modify / --users homelab@pve --roles PVEAuditor\n"
                      "pveum acl modify / --tokens 'homelab@pve!ro'", new)
        self.assertIn("pveum acl modify /pool/lab --users homelab@pve --roles HomelabProvisioner\n"
                      "pveum acl modify /pool/lab --tokens", new)
        self.assertEqual(new.count("Both tokens use privilege separation"), 1)
        self.assertLess(new.index("Both tokens"), new.index("## Read-only"))
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

    def test_old_repo_gets_suggestions_once_and_nothing_is_applied(self):
        doc = self.make_old()
        before = {f: f.read_text() for f in (doc, self.cfg, self.d / "discovery/proxmox.json")}
        out = self.sync("--dry-run").stdout
        self.assertNotIn("Up to date", out)
        self.assertIn("Suggested by newer releases (opt-in", out)
        self.assertIn("[0.10.0 · manual step]", out)                              # check_env TLS
        self.assertIn("vmid_scheme={vlan}{octet:03d}", out)                         # inferred from the snapshot
        self.assertNotIn("[0.11.0 · template section]", out)  # agent IPs not known to be unread (#14)
        self.assertIn("proxmox_inventory.py --details", out)
        self.assertIn("drift_report.py", out)
        self.assertEqual({f: f.read_text() for f in before}, before)               # dry run writes nothing
        out = self.sync().stdout
        self.assertIn("Recorded upgrades.reviewed", out)
        self.assertEqual(doc.read_text(), before[doc])                              # suggestions never applied
        self.assertEqual(yq(".vmid_scheme", self.cfg), "null")
        self.assertIn("Up to date", self.sync("--dry-run").stdout)                 # not offered again

    def test_reviewed_version_and_repo_state_filter_notes(self):
        self.make_old()
        run("config_set.py", "upgrades.reviewed=0.10.0", "vmid_scheme={vlan}{octet:03d}", cwd=self.d)
        Path(self.d, "discovery/drift.md").write_text("## Proxmox guests ↔ network\n")
        out = run("upgrade_notes.py", "--json", cwd=self.d).stdout
        ids = [n["id"] for n in json.loads(out)]
        self.assertEqual(ids, ["inventory-guest-ips"])
        ids = [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=self.d).stdout)]
        self.assertIn("proxmox-tls-check", ids)
        subprocess.run(["yq", "-i", ".components.proxmox = false", str(self.cfg)], check=True)
        self.assertEqual(json.loads(run("upgrade_notes.py", "--json", cwd=self.d).stdout), [])

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
        self.assertIn("[0.12.2 · manual step]", out)
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
            self.assertTrue(set(n["when"]) <= {"component", "config_empty", "config_set", "file_lacks", "file_has",
                                               "vmids_outside_ranges", "agent_ips_unread"}, n["id"])
            if "file_lacks" in n["when"] and n["kind"] == "template":
                self.assertIn(n["when"]["file_lacks"][1],
                              (SCRIPTS.parent / "assets/repo-template" / n["when"]["file_lacks"][0]).read_text())


FAKE_GH_CLOSED = """#!/usr/bin/env python3
import json, sys
if sys.argv[1:3] == ["issue", "list"]:
    print(json.dumps([{"number": 9, "stateReason": "COMPLETED"}, {"number": 4242, "stateReason": "COMPLETED"},
                      {"number": 77, "stateReason": "NOT_PLANNED"}]))
"""


class FixedIssuesTests(unittest.TestCase):
    """#12: reported entries fixed by the installed release are pointed out and can be resolved."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        run("init_repo.py", str(self.d), "--components", "ansible", cwd=self.d)
        sys.path.insert(0, str(SCRIPTS))
        import issues
        self.m = issues
        for t in ("guard splits commands inside quotes", "drift crash", "something not yet fixed", "seen again later"):
            run("issues.py", "add", "--title", t, "--kind", "guard", cwd=self.d)
        path = self.d / "skill_issues.md"
        items = issues.load(path)
        for i, (num, ver) in zip(items, ((9, "0.10.0"), (8, "0.11.0"), (4242, "0.10.0"), (10, "0.10.0"))):
            i.update(status="reported", github_number=num, github_url=f"https://github.com/o/r/issues/{num}",
                     plugin_version=ver)
        items[3]["last_seen_version"] = "0.11.0"   # still seen with the release that claims the fix
        issues.save(path, items)
        self.path = path

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_changelog_refs(self):
        refs = self.m.changelog_refs()
        self.assertEqual((refs[9][0], refs[5][0], refs[1][0]), ("0.11.0", "0.10.0", "0.7.0"))
        self.assertNotIn("0.5.0", refs.get(12, []))   # 0.5.0 says "fix GitHub issue #12" in prose

    def test_prose_mention_in_older_release_ignored(self):
        """#13: a bare #N in an older section must not hide the release that links N."""
        cl = self.d / "CHANGELOG.md"
        cl.write_text("# Changelog\n\n## 0.12.0 — x\n- Fix ([#12](https://github.com/o/r/issues/12)): y\n\n"
                      "## 0.11.0 — x\n- Fix ([#12](https://github.com/o/r/issues/12)) partly\n\n"
                      "## 0.5.0 — x\n- so \"fix GitHub issue #12\" works; see #9 too\n")
        orig_info = self.m.plugin_info
        self.m.plugin_info = lambda: {"version": "0.12.0"}
        try:
            refs = self.m.changelog_refs(cl)
            self.assertEqual(refs, {12: ["0.11.0", "0.12.0"]})
            orig_refs = self.m.changelog_refs
            self.m.changelog_refs = lambda: refs
            try:
                entry = {"id": "SKILL-013", "status": "reported", "github_number": 12, "plugin_version": "0.11.0"}
                self.assertEqual(self.m.fixed_by_release([entry]), [(entry, "0.12.0")])
                entry["last_seen_version"] = "0.12.0"
                self.assertEqual(self.m.fixed_by_release([entry]), [])
            finally:
                self.m.changelog_refs = orig_refs
        finally:
            self.m.plugin_info = orig_info

    def test_fixed_lists_hints_and_resolves(self):
        out = run("issues.py", "fixed", cwd=self.d).stdout
        self.assertIn("SKILL-001  #9 fixed in 0.11.0", out)
        for other in ("SKILL-002", "SKILL-003", "SKILL-004"):  # found with 0.11.0 / not in changelog / seen again
            self.assertNotIn(other, out)
        self.assertIn("Fixed by the installed release: SKILL-001 (#9, 0.11.0)", run("issues.py", "list", cwd=self.d).stdout)
        out = run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout
        self.assertIn("SKILL-001 (#9) fixed in 0.11.0", out)
        self.assertIn("issues.py fixed --apply", out)
        self.assertEqual(self.m.find(self.m.load(self.path), "SKILL-001")["status"], "reported")  # dry run
        self.assertIn("Resolved 1 entry", run("issues.py", "fixed", "--apply", cwd=self.d).stdout)
        i = self.m.find(self.m.load(self.path), "SKILL-001")
        self.assertEqual(i["status"], "resolved")
        self.assertIn("fixed in homelab-manager 0.11.0 (#9)", i["body"])
        self.assertIn("None of the reported entries", run("issues.py", "fixed", cwd=self.d).stdout)
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout)

    def test_github_closed_as_completed(self):
        fake = self.d / "fake-gh"
        fake.write_text(FAKE_GH_CLOSED)
        fake.chmod(0o755)
        env = {**os.environ, "HM_GH": str(fake), "HM_ISSUES_REPO": "o/r"}
        r = subprocess.run([sys.executable, str(SCRIPTS / "issues.py"), "fixed", "--github"], cwd=self.d,
                           capture_output=True, text=True, env=env)
        self.assertIn("SKILL-001  #9 fixed in 0.11.0", r.stdout)
        self.assertIn("SKILL-003  #4242 closed as completed on GitHub", r.stdout)
        self.assertEqual(r.stdout.count("SKILL-001"), 1)

    def test_seen_again_records_version(self):
        run("issues.py", "add", "--title", "x", "--kind", "script", "--key", "k:1", cwd=self.d)
        run("issues.py", "add", "--title", "x", "--kind", "script", "--key", "k:1", cwd=self.d)
        have = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["version"]
        self.assertEqual(self.m.find(self.m.load(self.path), "SKILL-005")["last_seen_version"], have)


class ProxmoxTlsAndPermissionTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import check_env
        import hmlib
        import proxmox_inventory
        self.check_env, self.hmlib, self.inv = check_env, hmlib, proxmox_inventory

    def pve(self, perms):
        import urllib.error
        pve = self.inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)

        def fake(path, **_):
            if path == "/access/permissions":
                return perms
            raise urllib.error.HTTPError(path, 403, "Forbidden", {}, None)
        pve._get = fake
        return pve

    def test_403_with_no_permissions_points_at_user_acl(self):
        with self.assertRaises(SystemExit) as e:
            self.pve({}).get("/cluster/status")
        msg = str(e.exception)
        self.assertIn("no effective permissions", msg)
        self.assertIn("pveum acl modify / --users homelab@pve --roles PVEAuditor", msg)
        self.assertNotIn("s3cret", msg)

    def test_403_with_other_paths_lists_them(self):
        with self.assertRaises(SystemExit) as e:
            self.pve({"/pool/lab": {"VM.Audit": 1}}).get("/cluster/status")
        self.assertIn("/pool/lab", str(e.exception))
        self.assertIn("pveum user token permissions homelab@pve ro", str(e.exception))

    def test_ca_cert_path_expanded_and_relative_to_repo(self):
        cfg = {"_root": "/repo", "proxmox": {"ca_cert": "certs/ca.pem"}}
        self.assertEqual(self.hmlib.proxmox_ca_file(cfg), "/repo/certs/ca.pem")
        cfg["proxmox"]["ca_cert"] = "~/x.pem"
        self.assertEqual(self.hmlib.proxmox_ca_file(cfg), str(Path.home() / "x.pem"))
        with self.assertRaises(self.hmlib.ConfigError):
            self.hmlib.proxmox_ssl_context(cfg)

    def test_tls_check_finds_ca_trusted_only_in_keychain(self):
        import ssl
        from unittest import mock
        err = ssl.SSLCertVerificationError("verify failed")
        err.verify_code, err.verify_message = 19, "self-signed certificate in certificate chain"
        ce = self.check_env
        cfg = {"proxmox": {"endpoint": "https://pve.example:8006"}}
        with mock.patch.object(ce, "_handshake", return_value=err), \
                mock.patch.object(ce, "_chain_names", return_value=["Home Root CA"]), \
                mock.patch.object(ce, "_keychain_ca_fix", return_value=("Home Root CA", "/Library/Keychains/System.keychain")):
            r = ce.check_proxmox_tls(cfg)[0]
        self.assertFalse(r["ok"])
        self.assertIn("trusted in the macOS keychain", r["detail"])
        self.assertIn('security find-certificate -a -c "Home Root CA" -p /Library/Keychains/System.keychain '
                      "> ~/.config/homelab/home-root-ca.pem", r["detail"])
        self.assertIn("proxmox.ca_cert=~/.config/homelab/home-root-ca.pem", r["detail"])
        with mock.patch.object(ce, "_handshake", return_value=err), \
                mock.patch.object(ce, "_chain_names", return_value=["Proxmox Virtual Environment"]), \
                mock.patch.object(ce, "_keychain_ca_fix", return_value=None):
            r = ce.check_proxmox_tls(cfg)[0]
        self.assertIn("pve-root-ca.pem", r["detail"])
        self.assertEqual(ce.check_proxmox_tls({"proxmox": {"endpoint": "https://x", "verify_tls": False}})[0]["ok"], None)
        self.assertEqual(ce.check_proxmox_tls({}), [])


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


class ConfigSetTests(unittest.TestCase):
    """config_set.py edits only the changed lines (yq -i re-serialises the file; GitHub issue #1)."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.f = self.d / "homelab.yaml"
        shutil.copy(SCRIPTS.parent / "assets/repo-template/homelab.yaml", self.f)
        self.orig = self.f.read_text()

    def tearDown(self):
        shutil.rmtree(self.d)

    def changed(self):
        new = self.f.read_text().splitlines()
        return [l for l in new if l not in self.orig.splitlines()]

    def test_list_append_keeps_comment_on_its_key(self):
        r = run("config_set.py", "network.authorized_ranges+=10.0.10.0/24", "network.authorized_ranges+=10.0.10.0/24",
                cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.changed(), ["  authorized_ranges: [10.0.10.0/24] # e.g. [10.0.10.0/24]"])
        self.assertEqual(json.loads(yq(".network.authorized_ranges", self.f)), ["10.0.10.0/24"])
        self.assertIn('  gateway: ""\n\nproxmox:', self.f.read_text())     # blank lines survive

    def test_scalars_inline_maps_new_keys_and_delete(self):
        r = run("config_set.py", "site.domain=home.arpa", "proxmox.verify_tls=false", "defaults.vm.cores=4",
                'defaults.ssh_public_keys=["ssh-ed25519 AAAA me@mac"]', "templates.build_network.dns+=10.0.10.1",
                "--delete", "discovery.ignore_unmanaged", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('  domain: "home.arpa"        # e.g. home.arpa\n', self.f.read_text())
        self.assertIn("  verify_tls: false          # false only", self.f.read_text())
        cfg = json.loads(yq(".", self.f))
        self.assertEqual(cfg["defaults"]["vm"], {"cores": 4, "memory_mib": 2048, "disk_gib": 20})
        self.assertEqual(cfg["defaults"]["ssh_public_keys"], ["ssh-ed25519 AAAA me@mac"])
        self.assertEqual(cfg["templates"]["build_network"]["dns"], ["10.0.10.1"])
        self.assertEqual(cfg["discovery"], None)
        self.assertEqual(len(self.f.read_text().splitlines()), len(self.orig.splitlines()))

    def test_dry_run_and_bad_input_write_nothing(self):
        r = run("config_set.py", "--dry-run", "site.domain=x", cwd=self.d)
        self.assertIn('+  domain: "x"', r.stdout)
        r = run("config_set.py", "site.name.deeper=1", cwd=self.d)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.f.read_text(), self.orig)

    def test_scaffold_keeps_template_formatting(self):
        d = self.d / "repo"
        run("init_repo.py", str(d), "--components", "ansible", cwd=self.d)
        new, old = (d / "homelab.yaml").read_text().splitlines(), self.orig.splitlines()
        self.assertEqual(len(new), len(old))
        self.assertRegex(next(l for l in new if l.startswith("  reviewed:")), r'^  reviewed: "\d+\.\d+\.\d+" +# ')
        self.assertEqual([l for l in new if l not in old and not l.startswith("  reviewed:")],
                         ["  proxmox: false      # Proxmox VE VMs/LXC via OpenTofu",
                          "  templates: false    # Packer VM templates (needs proxmox)",
                          "  discovery: false    # nmap discovery in authorized ranges"])


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
