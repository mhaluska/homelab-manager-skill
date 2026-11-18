"""Tests for init_repo.py (components, upgrades) and issues.py (skill-problem tracker)."""
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
import time
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

    def test_add_refuses_non_english(self):
        r = self.issues("add", "--title", "Skript padá bez backup_jobs", "--kind", "script")  # lang: allow
        self.assertEqual(r.returncode, 2)
        self.assertIn("English", r.stderr)
        r = self.issues("add", "--title", "drift_report.py crashes", "--kind", "script",
                        "--body", "### Summary\nSkript pada ked chyba backup jobs v konfiguracii a treba to opravit")  # lang: allow
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("SKILL-", Path(self.d, "skill_issues.md").read_text())
        r = self.issues("add", "--title", "drift_report.py crashes", "--kind", "script",
                        "--body", "### Evidence\n```\nChyba: súbor neexistuje\n```")  # lang: allow (log in a code block)
        self.assertEqual(r.returncode, 0, r.stderr)

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

    def test_same_key_replaces_title_and_body(self):  # issue 24
        self.issues("add", "--title", "A", "--kind", "improvement", "--key", "k", "--body", "### Summary\nAAA")
        r = self.issues("add", "--title", "B", "--kind", "improvement", "--key", "k", "--body", "### Summary\nBBB")
        self.assertIn("SKILL-001 already tracked (key k); updated title, body", r.stdout)
        shown = self.issues("show", "1").stdout
        self.assertIn('"title": "B"', shown)
        self.assertIn("BBB", shown)
        self.assertNotIn("AAA", shown)
        text = Path(self.d, "skill_issues.md").read_text()
        self.assertIn("| SKILL-001 | improvement | B | open |", text)
        self.assertEqual(text.count("<!-- issue {"), 1)
        r = self.issues("add", "--title", "B", "--kind", "improvement", "--key", "k")  # no body: details kept
        self.assertIn("BBB", self.issues("show", "1").stdout)
        self.assertNotIn("updated", r.stdout.split(";")[1].replace("last seen updated", ""))

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

    def test_report_refuses_entries_edited_into_another_language(self):
        self.issues("add", "--title", "Guard asks for gh issue list", "--kind", "guard")
        p = Path(self.d, "skill_issues.md")
        p.write_text(p.read_text().replace("Guard asks for gh issue list", "Guard sa pýta na gh issue list"))  # lang: allow
        dry = self.issues("report", "--dry-run")
        self.assertEqual(dry.returncode, 5)
        self.assertIn("SKILL-001: title", dry.stderr)
        r = self.issues("report")
        self.assertEqual(r.returncode, 5)
        self.assertFalse(any(c[:2] == ["issue", "create"] for c in self.calls()))
        self.assertNotIn("reported-through", p.read_text())

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


    def test_os_guesses_not_redacted_hostnames_are(self):  # GitHub issue #30
        net = {"hosts": {"10.0.10.7": {
            "ip": "10.0.10.7", "hostnames": ["pikachu.lab.example"],
            "os": [{"name": "MikroTik RouterOS 7.10 (Linux 5.6.3)", "accuracy": 95},
                   {"name": "Linux 4.15 - 5.19", "accuracy": 90}],
            "ports": [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "10.0p2 Debian 7"}],
            "ssh_probe": {"hostname": "bulbasaur", "os_name": "Debian GNU/Linux 13", "product": "Proxmox VE"}}}}
        Path(self.d, "discovery").mkdir(exist_ok=True)
        Path(self.d, "discovery/network.json").write_text(json.dumps(net))
        self.issues("add", "--title", "OS guess wrong", "--kind", "script", "--body",
                    "Guesses MikroTik RouterOS 7.10 (Linux 5.6.3) and Linux 4.15 - 5.19 on Debian GNU/Linux 13 "
                    "with OpenSSH; Proxmox VE; host pikachu.lab.example aka bulbasaur.")
        out = self.issues("report", "--dry-run").stdout
        for kept in ("MikroTik RouterOS 7.10 (Linux 5.6.3)", "Linux 4.15 - 5.19", "Debian GNU/Linux 13",
                     "OpenSSH", "Proxmox VE"):
            self.assertIn(kept, out, kept)
        for leak in ("pikachu", "bulbasaur", "lab.example"):
            self.assertNotIn(leak, out, leak)


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
        self.assertIn("references/proxmox.md", r.stdout)

    def _jobs(self, jobs):
        p = Path(self.d, "discovery/proxmox.json")
        snap = json.loads(p.read_text())
        snap["backup_jobs"] = jobs
        p.write_text(json.dumps(snap))
        return run("drift_report.py", "--no-tofu", cwd=self.d).stdout

    def test_backup_job_id_lists(self):  # issue 41
        out = self._jobs([{"id": "daily", "enabled": True, "all": False, "vmid": [100, 104]}])
        self.assertNotIn("is in no backup job", out)
        out = self._jobs([{"id": "all", "enabled": True, "all": True, "vmid": [], "exclude": [104]}])
        self.assertIn("104 `test-old` is in no backup job", out)
        self.assertNotIn("100 `dns01` is in no backup job", out)

    def test_truncated_backup_list_is_unknown(self):  # issue 41: old snapshots cut at 200 characters
        out = self._jobs([{"id": "daily", "enabled": True, "all": False, "vmid": "100,10…"}])
        self.assertIn("Can't read the guest list of job(s) `daily`", out)
        self.assertNotIn("is in no backup job", out)

    def _storage(self, yq_expr):  # issue 54: a cluster without shared storage, one node on LVM
        p = Path(self.d, "discovery/proxmox.json")
        snap = json.loads(p.read_text())
        snap["nodes"] = [{"node": n, "status": "online"} for n in ("pve1", "pve2", "pve3")]
        snap["storage"] = [{"storage": "local", "node": n, "content": "iso,vztmpl,import,backup"} for n in ("pve1", "pve2", "pve3")] \
            + [{"storage": "local-zfs", "node": n, "content": "images,rootdir"} for n in ("pve1", "pve2")] \
            + [{"storage": "tank-vm", "node": "pve1", "content": "images"},
               {"storage": "local-lvm", "node": "pve3", "content": "images,rootdir"}]
        p.write_text(json.dumps(snap))
        subprocess.run(["yq", "-i", yq_expr, str(Path(self.d, "homelab.yaml"))], check=True)
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        return r.stdout.split("## Storage")[1].split("\n## ")[0] if "## Storage" in r.stdout else r.stdout + r.stderr

    def test_storage_missing_on_a_node(self):
        out = self._storage('.proxmox.default_storage = "local-zfs" | .proxmox.image_storage = "local"')
        self.assertIn("pve3: default_storage `local-zfs` (VM disks) is not on this node — set `proxmox.nodes.pve3`", out)
        self.assertEqual(out.count("local-zfs"), 1)          # lxc_storage = the same storage: reported once
        self.assertNotIn("pve1", out)

    def test_storage_per_node_and_content(self):
        out = self._storage('.proxmox.default_storage = "local-zfs" | .proxmox.lxc_storage = "tank-vm"'
                            ' | .proxmox.nodes = {"pve3": {"default_storage": "local-lvm"}}')
        self.assertNotIn("pve3", out)                        # its own storage, LXC falls back to it
        self.assertIn("pve1: lxc_storage `tank-vm` (LXC root filesystems) doesn't take `rootdir` content (images)", out)
        self.assertIn("pve2: lxc_storage `tank-vm` (LXC root filesystems) is not on this node", out)
        out = self._storage('.proxmox.lxc_storage = "" | .proxmox.nodes.pve9 = {"default_storage": "x"}')
        self.assertIn("`proxmox.nodes.pve9`: no such node", out)
        self.assertIn("Each node has", self._storage('del(.proxmox.nodes.pve9)'))

    def test_storage_per_node_needs_default_storage(self):
        out = self._storage('.proxmox.default_storage = "local-zfs" | .proxmox.nodes = {"pve3": {"lxc_storage": "local-lvm"}}')
        self.assertIn("proxmox.nodes.pve3 needs default_storage", out)


class DriftExtraIpsTests(unittest.TestCase):
    """#31: hm_extra_ips makes a host's other addresses known; --stale says when drift.md is out of date."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "ansible,discovery", cwd=self.d)
        Path(self.d, "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    appliances:\n      hosts:\n        router1:\n          ansible_host: 10.0.10.1\n"
            "          hm_extra_ips: [10.0.20.1, 10.0.30.1/24]\n")
        host = {"mac": None, "hostnames": [], "device_type_guess": "router", "vendor": None}
        net = {"updated_at": "2026-01-01", "hosts": {ip: host for ip in ("10.0.10.1", "10.0.20.1", "10.0.30.1", "10.0.10.9")}}
        Path(self.d, "discovery/network.json").write_text(json.dumps(net))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_vlan_names_in_report(self):  # issue 34
        run("config_set.py", "network.vlans+={id: 20, name: DMZ, cidr: 10.0.10.0/24}", cwd=self.d)
        out = run("drift_report.py", "--no-tofu", cwd=self.d).stdout
        self.assertIn("10.0.10.9  — router [VLAN 20 DMZ]", out)

    def test_container_ips_are_not_unmanaged(self):  # issue 40
        nas = {"hosts": {"nas1": {"containers": [{"name": "pihole", "runtime": "lxd", "ips": ["10.0.10.9"]}]}}}
        Path(self.d, "discovery/nas1-containers.json").write_text(json.dumps(nas))
        out = run("drift_report.py", "--no-tofu", cwd=self.d).stdout
        unmanaged = out.split("## Network devices not in managed inventory")[1]
        self.assertIn("None.", unmanaged.split("Container addresses")[0])
        self.assertIn("10.0.10.9 → `pihole` (lxd on `nas1`)", out)

    def test_secondary_ips_are_not_unmanaged(self):
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        unmanaged = r.stdout.split("## Network devices not in managed inventory")[1]
        self.assertIn("1 device(s)", unmanaged)
        self.assertIn("10.0.10.9", unmanaged)
        self.assertIn("- 10.0.20.1 → `router1` (secondary)", unmanaged)
        self.assertIn("- 10.0.30.1 → `router1` (secondary)", unmanaged)

    def test_stale(self):
        self.assertEqual(run("drift_report.py", "--stale", cwd=self.d).returncode, 2)
        run("drift_report.py", "--no-tofu", cwd=self.d)
        drift = Path(self.d, "discovery/drift.md")
        os.utime(drift, (time.time() + 60, time.time() + 60))
        r = run("drift_report.py", "--stale", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stdout)
        os.utime(drift, (time.time() - 3600, time.time() - 3600))
        r = run("drift_report.py", "--stale", cwd=self.d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ansible/inventory", r.stdout)


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


    def test_lxc_lists_configured_ip_and_marks_extra(self):  # GitHub issue #61
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        pve._get = lambda path, **_: [{"name": "eth0", "hwaddr": "bc:24:11:00:00:01", "inet": "10.0.10.250/24"},
                                      {"name": "eth1", "hwaddr": "bc:24:11:00:00:02", "inet": "10.0.20.251/24"}]
        conf = {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=10.0.10.251/24,tag=10",
                "net1": "name=eth1,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=10.0.20.251/24",
                "net2": "name=eth2,bridge=vmbr0,ip=dhcp"}
        out = inv.guest_ips(pve, {"node": "pve1", "vmid": 901}, "lxc", conf, {"lxc": ""})
        self.assertEqual([(a["iface"], a["ip"], a["source"], a.get("extra", False)) for a in out],
                         [("eth0", "10.0.10.251", "config", False), ("eth1", "10.0.20.251", "config", False),
                          ("eth0", "10.0.10.250", "lxc", True)])
        self.assertEqual(out[0]["mac"], "bc:24:11:00:00:01")

    def test_reachable_address_ranked_first(self):  # GitHub issue #56
        sys.path.insert(0, str(SCRIPTS))
        import ipaddress
        import hmlib
        import proxmox_to_inventory as p2i
        g = {"type": "vm", "config": {"net0": "virtio=BC:24:11:AA:BB:01,bridge=vmbr0,tag=20"},
             "ips": [{"iface": "wg0", "mac": "00:00:00:00:00:00", "ip": "10.99.0.2", "source": "agent"},
                     {"iface": "docker0", "mac": "02:42:ac:11:00:01", "ip": "172.17.0.1", "source": "agent"},
                     {"iface": "ens18", "mac": "bc:24:11:aa:bb:01", "ip": "fe80::1", "source": "agent"},
                     {"iface": "ens18", "mac": "bc:24:11:aa:bb:01", "ip": "192.168.20.15", "source": "agent"}]}
        site = [ipaddress.ip_network("192.168.20.0/24")]
        self.assertEqual(p2i.pick_ip(g, [], site), "192.168.20.15")
        self.assertEqual(p2i.pick_ip(g, [], None), "192.168.20.15")      # NIC MAC wins without ranges too
        self.assertEqual(p2i.pick_ip(g, [ipaddress.ip_network("10.99.0.0/24")], site), "10.99.0.2")  # --range
        g["config"] = {"net0": "virtio,bridge=vmbr0"}                     # no MAC to match: the range decides
        self.assertEqual(p2i.pick_ip(g, [], site), "192.168.20.15")
        g["ips"] = g["ips"][:2]                                           # only virtual interfaces left
        self.assertEqual([a["ip"] for a in hmlib.rank_guest_addresses(g, site)], ["10.99.0.2", "172.17.0.1"])  # order found
        lxc = {"type": "lxc", "config": {"net0": "name=eth0,hwaddr=BC:24:11:00:00:01,ip=10.0.10.251/24"},
               "ips": [{"iface": "eth0", "mac": "bc:24:11:00:00:01", "ip": "10.0.10.250", "source": "lxc",
                        "extra": True}]}
        self.assertEqual(p2i.pick_ip(lxc, [], None), "10.0.10.251")       # configured, not the VIP

    def test_details_keep_what_pins_a_guest_to_its_node(self):  # issue 23
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        conf = {"scsi0": "ceph:vm-1-disk-0,size=32G", "efidisk0": "local-zfs:vm-1-disk-1", "hostpci0": "0000:01:00",
                "usb0": "host=1-2", "startup": "order=2,up=30", "onboot": 1, "description": "hi", "lock": "backup",
                "unused0": "local-zfs:vm-1-disk-2", "tpmstate0": "local-zfs:vm-1-disk-3", "args": "-cpu host"}
        out = inv.guest_config(conf)
        for k in ("scsi0", "efidisk0", "hostpci0", "usb0", "startup", "onboot", "unused0", "tpmstate0"):
            self.assertIn(k, out)
        self.assertNotIn("lock", out)
        self.assertNotIn("args", out)
        self.assertEqual(out["description"], "[untrusted] hi")

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

    def test_vlan_by_name(self):  # issue 34
        run("config_set.py", "vmid_scheme={vlan}{octet:03d}",
            "network.vlans+={id: 1020, name: DMZ, cidr: 10.20.0.0/24, gw: 10.20.0.1}", cwd=self.d)
        r = run("proxmox_inventory.py", "--next-vmid", "lxc", "--ip", "10.20.0.17", "--vlan", "dmz", cwd=self.d)
        self.assertEqual(r.stdout.strip(), "1020017", r.stderr)
        r = run("proxmox_inventory.py", "--next-vmid", "lxc", "--ip", "10.20.0.17", "--vlan", "IoT", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("known: DMZ (1020)", r.stderr)
        cfg = self.cfg()
        self.assertEqual(self.h.vlan_label(cfg, ip="10.20.0.9"), "VLAN 1020 DMZ")
        self.assertEqual(self.h.vlan_label(cfg, 30), "VLAN 30")
        self.assertEqual(self.h.vlan_label(cfg, ip="10.30.0.9"), "")


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
        text = re.sub(r"\n### Backup jobs \(optional\).*?\n```\n", "", text, flags=re.S)  # added in 0.17.0
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

    def test_reviewed_version_and_repo_state_filter_notes(self):
        self.make_old()
        run("config_set.py", "upgrades.reviewed=0.10.0", "vmid_scheme={vlan}{octet:03d}", cwd=self.d)
        Path(self.d, "discovery/drift.md").write_text("## Proxmox guests ↔ network\n")
        subprocess.run(["yq", "-i", '.site.language = "en" | .network.vlans = [{"id": 10, "name": "mgmt"}]',
                        str(self.cfg)], check=True)                     # config notes of 0.16.0 settled
        out = run("upgrade_notes.py", "--json", cwd=self.d).stdout
        ids = [n["id"] for n in json.loads(out)]
        self.assertEqual(ids, ["inventory-guest-ips", "recheck-hidden-suggestions"])   # the latter: any reviewed repo
        ids = [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=self.d).stdout)]
        self.assertIn("proxmox-tls-check", ids)
        subprocess.run(["yq", "-i", ".components.proxmox = false", str(self.cfg)], check=True)
        ids = [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", cwd=self.d).stdout)]
        self.assertEqual(ids, ["recheck-hidden-suggestions"])                        # no component condition

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
                                               "vmids_outside_ranges", "agent_ips_unread"}, n["id"])
            if "after_replace" in n:      # only a note a file replacement can settle has a leftover step
                self.assertTrue({"file_lacks", "file_has"} & set(n["when"]), n["id"])
            if "file_lacks" in n["when"] and n["kind"] == "template":
                self.assertIn(n["when"]["file_lacks"][1],
                              (SCRIPTS.parent / "assets/repo-template" / n["when"]["file_lacks"][0]).read_text())


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

    def test_after_replace_step_is_shown_and_docs_with_proxmox_steps_are_kept(self):
        run("config_set.py", "upgrades.reviewed=0.21.0", cwd=self.d)
        self.old("v0.21.0", "tofu/environments/homelab/variables.tf")
        self.old("v0.10.0", "docs/proxmox-tokens.md")
        out = self.sync("--dry-run").stdout
        self.assertIn("would replace tofu/environments/homelab/variables.tf", out)
        self.assertIn("still to do: Bring main.tf", out)
        self.assertNotIn("replace docs/proxmox-tokens.md", out)


FAKE_GH_CLOSED = """#!/usr/bin/env python3
import json, sys
if sys.argv[1:3] == ["issue", "list"]:
    print(json.dumps([{"number": 9, "stateReason": "COMPLETED"}, {"number": 4242, "stateReason": "COMPLETED"},
                      {"number": 77, "stateReason": "NOT_PLANNED"}]))
"""


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


class GuestMapTests(unittest.TestCase):  # GitHub issue #62
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "proxmox,ansible", cwd=self.d)
        subprocess.run(["yq", "-i", '.network.vlans = [{"id": 10, "name": "INFRA", "cidr": "10.0.10.0/24"}, '
                        '{"id": 20, "name": "DMZ", "cidr": "10.0.20.0/24"}] | .vmid_scheme = "{vlan}{octet:03d}"',
                        str(self.d / "homelab.yaml")], check=True)
        guests = [
            {"vmid": 10011, "name": "proxy1", "type": "lxc", "node": "pve1", "status": "running",
             "config": {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=10.0.10.11/24,tag=10"},
             "ips": [{"iface": "eth0", "mac": "bc:24:11:00:00:01", "ip": "10.0.10.11", "source": "config"},
                     {"iface": "eth0", "mac": "bc:24:11:00:00:01", "ip": "10.0.10.250", "source": "lxc", "extra": True}]},
            {"vmid": 20015, "name": "web01", "type": "vm", "node": "pve1", "status": "running",
             "config": {"net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0,tag=20",
                        "net1": "virtio=BC:24:11:00:00:03,bridge=vmbr0,tag=30"},
             "ips": [{"iface": "ens18", "mac": "bc:24:11:00:00:02", "ip": "10.0.10.15", "source": "agent"},
                     {"iface": "wg0", "mac": "00:00:00:00:00:00", "ip": "10.99.0.2", "source": "agent"}]},
            {"vmid": 10002, "name": "chr", "type": "vm", "node": "pve1", "status": "running",
             "config": {"net0": "virtio=BC:24:11:00:00:04,bridge=vmbr0,tag=10"}},
            {"vmid": 9000, "name": "tpl", "type": "vm", "template": True, "config": {}},
        ]
        (self.d / "discovery/proxmox.json").write_text(json.dumps({"collected_at": "t", "guests": guests}))
        (self.d / "discovery/network.json").write_text(json.dumps({"hosts": {
            "10.0.10.11": {"hostnames": ["proxy1"]}, "10.0.10.5": {"hostnames": ["switch"]}}}))
        (self.d / "discovery/routeros.json").write_text(json.dumps({"devices": {"10.0.10.1": {
            "interfaces": [{"name": "ether1", "mac-address": "BC:24:11:00:00:04"}],
            "addresses": [{"address": "10.0.10.1/24", "interface": "ether1"}]}}}))
        (self.d / "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n        proxy1:\n          ansible_host: 10.0.10.250\n"
            "        web01:\n          ansible_host: 10.0.20.15\n          proxmox_vmid: 20015\n")

    def test_map_and_findings(self):
        r = run("guest_map.py", "--out", "-", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn("10.0.10.11 (config), +10.0.10.250 (lxc)", out)
        self.assertIn("proxy1 uses 10.0.10.250, an extra address", out)
        self.assertIn("20015 web01 net0: 10.0.10.15 is outside VLAN 20's 10.0.20.0/24", out)
        self.assertIn("net1: VLAN tag 30 is not in network.vlans", out)
        self.assertIn("net1: running, no address known", out)
        self.assertIn("Ansible host web01 has ansible_host 10.0.20.15, not one of the guest's addresses", out)
        self.assertIn("10002 chr: vmid_scheme {vlan}{octet:03d} gives 10001 for 10.0.10.1 on VLAN 10", out)
        self.assertNotIn("gives 20015", out)                                # VMID fits its scheme
        self.assertIn("10.0.10.1 (routeros)", out)                         # CHR address by MAC
        self.assertNotIn("10.99.0.2", out)                                 # tunnel interface left out
        self.assertNotIn("tpl", out)
        self.assertIn("- 10.0.10.5 switch (VLAN 10 INFRA)", out)
        self.assertNotIn("- 10.0.10.11", out)
        r = run("guest_map.py", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.d / "discovery/guest-map.md").exists())


class VlanNameRedactionTests(unittest.TestCase):  # issue 34: VLAN names are site data
    def test_vlan_names_are_site_terms(self):
        sys.path.insert(0, str(SCRIPTS))
        import issues
        d = tempfile.mkdtemp()
        try:
            cfg = {"_root": d, "network": {"vlans": [{"id": 20, "name": "Kitchen-IoT"}, {"id": 30}]}}
            self.assertIn("Kitchen-IoT", issues.site_terms(cfg)[1])
            self.assertNotIn("Kitchen-IoT", issues.sanitize("The VM in Kitchen-IoT got no IP.", cfg))
        finally:
            shutil.rmtree(d)


class CommonWordRedactionTests(unittest.TestCase):  # issue 47: plain words used as site names
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import issues
        self.issues = issues
        self.d = tempfile.mkdtemp()
        self.cfg = {"_root": self.d, "network": {"vlans": [{"id": 20, "name": "storage"}, {"id": 30, "name": "host"},
                                                           {"id": 40, "name": "Kitchen-IoT"}]}}

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_plain_words_kept_in_running_text(self):
        out = self.issues.sanitize("Checking the storage driver; one with host networking on a Linux host.", self.cfg)
        self.assertEqual(out, "Checking the storage driver; one with host networking on a Linux host.")

    def test_plain_words_redacted_as_identifiers(self):
        out = self.issues.sanitize("VLAN `storage` has no DHCP; vlan: host and name=storage.", self.cfg)
        self.assertNotIn("storage", out)
        self.assertNotIn(": host", out)

    def test_placeholders_not_redacted_again(self):
        cfg = {"_root": self.d, "network": {"vlans": [{"id": 30, "name": "host"}, {"id": 40, "name": "node7"}]}}
        out = self.issues.sanitize("on node7 and `host`", cfg)
        self.assertNotIn("<<", out)
        self.assertIn("<host>", out)

    def test_keep(self):
        cfg = {**self.cfg, "_keep": ["Kitchen-IoT"]}
        self.assertIn("Kitchen-IoT", self.issues.sanitize("The VM in Kitchen-IoT got no IP.", cfg))


class PveSnapshotTests(unittest.TestCase):  # issue 37
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import pve_snapshot
        import proxmox_inventory
        self.s = pve_snapshot
        self.pve = proxmox_inventory.PVE("https://pve.example:8006", "homelab@pve!rw=s3cret", None)
        self.snaps = {101: [{"name": "current"}, {"name": "old", "snaptime": 1}]}
        self.calls = []

        def get(path, _method="GET", **params):
            self.calls.append((_method, path, params))
            if path == "/cluster/resources":
                return [{"type": "qemu", "vmid": 101, "name": "web01", "node": "pve1"},
                        {"type": "lxc", "vmid": 901, "name": "dns", "node": "pve2"},
                        {"type": "qemu", "vmid": 9050, "name": "tpl", "node": "pve1", "template": 1},
                        {"type": "storage", "id": "x"}]
            if path.endswith("/status"):
                return {"status": "stopped", "exitstatus": "OK"}
            if path.endswith("/snapshot") and _method == "GET":
                return self.snaps.get(int(path.split("/")[4]), [{"name": "current"}])
            return "UPID:pve1:1"
        self.pve.get = get

    def test_resolves_guests_by_vmid_or_name(self):
        gs = self.s.find_guests(self.pve, ["web01", "901"])
        self.assertEqual([(g["vmid"], g["type"], g["node"]) for g in gs], [(101, "qemu", "pve1"), (901, "lxc", "pve2")])
        with self.assertRaises(SystemExit):
            self.s.find_guests(self.pve, ["tpl"])
        with self.assertRaises(SystemExit):
            self.s.find_guests(self.pve, ["nope"])

    def test_create_waits_for_task_and_skips_existing(self):
        g = self.s.find_guests(self.pve, ["web01"])[0]
        self.assertEqual([s["name"] for s in self.s.snapshots(self.pve, g)], ["old"])
        self.s.wait(self.pve, "pve1", "UPID:pve1:1", "x")
        self.assertIn(("GET", "/nodes/pve1/tasks/UPID:pve1:1/status", {}), self.calls)

    def test_apply(self):
        gs = self.s.find_guests(self.pve, ["web01", "dns"])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.s.apply(self.pve, "create", gs, "prepatch-20261117")
            self.s.apply(self.pve, "create", gs[:1], "old")        # exists: kept, nothing sent
            self.s.apply(self.pve, "delete", gs[:1], "old")
        writes = [(m, p, prm) for m, p, prm in self.calls if m != "GET"]
        self.assertEqual(writes[0], ("POST", "/nodes/pve1/qemu/101/snapshot",
                                     {"snapname": "prepatch-20261117", "description": "homelab-manager prepatch-20261117",
                                      "vmstate": 0}))
        self.assertEqual(writes[1][1], "/nodes/pve2/lxc/901/snapshot")
        self.assertNotIn("vmstate", writes[1][2])
        self.assertEqual(writes[2], ("DELETE", "/nodes/pve1/qemu/101/snapshot/old", {}))
        self.assertEqual(len(writes), 3)
        self.assertIn("already exists", out.getvalue())
        with self.assertRaises(SystemExit):
            self.s.apply(self.pve, "rollback", gs[1:], "missing")

    def test_rollback_starts_a_guest_that_was_running(self):  # GitHub issue #59
        import pve_guest
        state = {"st": "running", "starts": 0}
        orig = self.pve.get

        def get(path, _method="GET", **params):
            if path.endswith("/status/current"):
                return {"status": state["st"]}
            if path.endswith("/rollback"):
                state["st"] = "stopped"                 # Proxmox's start was not enough: still stopped
            if path.endswith("/status/start"):
                state["st"] = "running"
                state["starts"] += 1
            return orig(path, _method, **params)
        self.pve.get = get
        g = self.s.find_guests(self.pve, ["web01"])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            down = self.s.apply(self.pve, "rollback", g, "old")
        self.assertEqual(down, [])
        self.assertIn(("POST", "/nodes/pve1/qemu/101/snapshot/old/rollback", {"start": 1}), self.calls)
        self.assertEqual(state["starts"], 1)
        self.assertIn("now running", out.getvalue())
        state["st"] = "stopped"                         # stopped before: left stopped, no start option
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.s.apply(self.pve, "rollback", g, "old")
        self.assertIn(("POST", "/nodes/pve1/qemu/101/snapshot/old/rollback", {}), self.calls)
        self.assertEqual(state["starts"], 1)
        self.assertIn("now stopped", out.getvalue())
        state["st"] = "running"
        with contextlib.redirect_stdout(io.StringIO()):
            self.s.apply(self.pve, "rollback", g, "old", start=False)
        self.assertEqual(state["starts"], 1)
        state["st"] = "paused"                          # only a stopped guest is started
        self.assertEqual(pve_guest.start(self.pve, g[0], timeout=0, sleep=lambda _: None), "paused")
        self.assertEqual(state["starts"], 1)

    def test_failed_task_raises(self):
        self.pve.get = lambda path, **_: {"status": "stopped", "exitstatus": "snapshot feature is not available"}
        with self.assertRaises(SystemExit) as e:
            self.s.wait(self.pve, "pve1", "UPID", "create snapshot")
        self.assertIn("not available", str(e.exception))

    def test_default_name_is_valid(self):
        self.assertRegex(self.s.default_name(), self.s.NAME_RE)

    def test_check_reports_every_guest(self):  # issue 49
        get = self.pve.get
        configs = {"/nodes/pve2/lxc/901/config": {"rootfs": "local-zfs:subvol-901-disk-0",
                                                   "mp0": "local-zfs:subvol-901-disk-1,mp=/data",
                                                   "mp1": "/dev/zvol/tank/vol,mp=/srv/raw"}}

        def with_feature(path, _method="GET", **params):
            if path.endswith("/feature"):
                self.assertEqual(params, {"feature": "snapshot"})
                return {"hasFeature": 1 if "/qemu/101/" in path else 0}
            if path in configs:
                return configs[path]
            return get(path, _method, **params)
        self.pve.get = with_feature
        res = self.s.check(self.pve, ["web01", "dns", "nas-lxd1", "tpl"])
        self.assertEqual(res["ok"], ["web01"])
        self.assertEqual(sorted(res["not_a_guest"]), ["nas-lxd1", "tpl"])
        self.assertIn("mp1: /dev/zvol/tank/vol", res["no_snapshot"]["dns"])
        self.assertNotIn("mp0", res["no_snapshot"]["dns"])
        self.assertFalse([c for c in self.calls if c[0] != "GET"])  # read-only
        with self.assertRaises(SystemExit):                       # the other actions still stop at the first
            self.s.find_guests(self.pve, ["web01", "nas-lxd1"])


class LxdSnapshotTests(unittest.TestCase):  # issue 44
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import lxd_snapshot
        self.l = lxd_snapshot
        self.hosts = {
            "nas1": {"groups": ["appliances"], "ansible_host": "192.0.2.10", "ansible_user": "admin",
                     "lxd_snapshots": True},
            "nas2": {"groups": ["appliances"], "ansible_host": "192.0.2.11", "lxd_cli": "/opt/incus", "lxd_sudo": True},
            "app1.lab.example": {"groups": ["debian"], "lxd_host": "nas1"},
            "app2": {"groups": ["debian"], "lxd_host": "nas1", "lxd_instance": "legacy-app", "lxd_project": "lab"},
            "app3": {"groups": ["debian"], "lxd_host": "nas2"},
            "web01": {"groups": ["rocky"]},
        }
        self.driver = "zfs"
        self.snaps = {"app1": [{"name": "app1/old", "created_at": "2026-01-01T00:00:00Z"}]}
        self.calls = []
        test = self

        def run(t, command, timeout):
            test.calls.append((t["nas"], command))
            if command == self.l.FIND_CLI:
                return 0, "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/lxc\n", ""
            args = shlex.split(command)
            q = args.index("query")
            method = args[args.index("-X") + 1] if "-X" in args else "GET"
            body = json.loads(args[args.index("-d") + 1]) if "-d" in args else None
            path = args[-1].split("?")[0]
            parts = path.split("/")
            if method != "GET":
                test.writes.append((args[:q], method, args[-1], body))
                return 0, "{}", ""
            if path == "/1.0/storage-pools/default":
                return 0, json.dumps({"driver": test.driver}), ""
            if path == "/1.0/storage-pools/default/resources":
                return 0, json.dumps({"space": {"used": 90 * 2**30, "total": 100 * 2**30}}), ""
            if len(parts) == 4 and parts[3] in ("app1", "legacy-app", "app3"):
                return 0, json.dumps({"type": "container", "status": "Running",
                                      "expanded_config": {"snapshots.schedule": "@daily"},
                                      "expanded_devices": {"root": {"type": "disk", "path": "/", "pool": "default"},
                                                           "data": {"type": "disk", "source": "/share/Data", "path": "/data"},
                                                           "vol": {"type": "disk", "pool": "default", "source": "db",
                                                                   "path": "/db"},
                                                           "eth0": {"type": "nic"}}}), ""
            if path.endswith("/state"):
                return 0, json.dumps({"disk": {"root": {"usage": test.usage}}}), ""
            if path.endswith("/snapshots"):
                return 0, json.dumps(test.snaps.get(parts[3], [])), ""
            return 1, "", "Error: Instance not found"
        self.run, self.writes, self.usage = run, [], 0

    def test_targets(self):
        found, problems = self.l.targets(self.hosts, ["app1", "app2", "web01", "nope"])
        self.assertEqual(found["app1"]["instance"], "app1")
        self.assertEqual(found["app1"]["address"], "192.0.2.10")
        self.assertEqual((found["app2"]["instance"], found["app2"]["project"]), ("legacy-app", "lab"))
        self.assertIn("lxd_host", problems["web01"])
        self.assertIn("not in the managed inventory", problems["nope"])

    def test_check(self):
        found, problems = self.l.targets(self.hosts, ["app1", "app2", "app3", "web01"])
        res = self.l.check(found, problems, self.run)
        self.assertEqual(res["ok"], ["app1", "app2"])
        self.assertIn("lxd_snapshots: true", res["no_snapshot"]["app3"])   # nas2 not opted in: never contacted
        self.assertFalse([c for c in self.calls if c[0] == "nas2"])
        self.assertIn("web01", res["not_a_guest"])
        w = " ".join(res["warnings"]["app1"])
        self.assertIn("data: /share/Data", w)
        self.assertIn("volume db", w)
        self.assertIn("scheduled snapshots", w)
        self.assertIn("project=lab", " ".join(c for _, c in self.calls))
        self.assertEqual(self.writes, [])                                  # read-only

    def test_check_dir_space(self):
        self.driver, self.usage = "dir", 20 * 2**30                          # 20 GiB rootfs, 10 GiB free
        found, problems = self.l.targets(self.hosts, ["app1"])
        res = self.l.check(found, problems, self.run)
        self.assertIn("doesn't fit", res["no_snapshot"]["app1"])
        self.usage = 0
        res = self.l.check(found, problems, self.run)
        self.assertIn("size unknown", " ".join(res["warnings"]["app1"]))

    def test_create_delete_restore(self):
        found, _ = self.l.targets(self.hosts, ["app1"])
        api = self.l.Api(found["app1"], self.run)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.l.apply(api, "create", "prepatch-20261117")
            self.l.apply(api, "create", "old")                             # exists: kept
            self.l.apply(api, "delete", "old")
        self.assertEqual(self.writes[0][1:], ("POST", "/1.0/instances/app1/snapshots",
                                              {"name": "prepatch-20261117", "stateful": False}))
        self.assertEqual(self.writes[1][1:3], ("DELETE", "/1.0/instances/app1/snapshots/old"))
        self.assertEqual(len(self.writes), 2)
        self.assertIn("already exists", out.getvalue())
        self.assertEqual(self.writes[0][0][-1], "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/lxc")
        with self.assertRaises(self.l.LxdError):
            self.l.apply(api, "restore", "missing")

    def test_restore_zfs_refuses_with_newer(self):
        self.snaps["app1"].append({"name": "auto-1", "created_at": "2026-02-01T00:00:00Z"})
        found, _ = self.l.targets(self.hosts, ["app1"])
        api = self.l.Api(found["app1"], self.run)
        with self.assertRaises(self.l.LxdError) as e:
            self.l.apply(api, "restore", "old")
        self.assertIn("auto-1", str(e.exception))
        self.driver = "btrfs"
        with contextlib.redirect_stdout(io.StringIO()):
            self.l.apply(api, "restore", "old")
        self.assertEqual(self.writes[-1][1:], ("PUT", "/1.0/instances/app1", {"restore": "old"}))

    def test_sudo_and_cli(self):
        t = {**self.l.targets(self.hosts, ["app3"])[0]["app3"], "opted_in": True}
        api = self.l.Api(t, self.run)
        api.query("/1.0/instances/app3")
        self.assertTrue(self.calls[-1][1].startswith("sudo -n /opt/incus query "))


class SitesTests(unittest.TestCase):  # issue 52
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib
        self.cfg = {"_root": "/nonexistent",
                    "proxmox": {"endpoint": "https://pve1.example:8006", "tokens": {"read_only": "proxmox-ro"}},
                    "sites": [{"name": "home"},
                              {"name": "offsite", "label": "Rented server", "ranges": ["192.0.2.0/24"],
                               "proxmox": {"endpoint": "https://pve-off.example:8006", "verify_tls": False,
                                           "tokens": {"read_only": "off-ro", "provisioning": "off-rw"}}},
                              {"name": "parents"}]}

    def test_sites(self):
        h = self.h
        self.assertEqual([s["name"] for s in h.sites(self.cfg)], ["home", "offsite", "parents"])
        self.assertEqual(h.site(self.cfg)["name"], "home")
        self.assertEqual(h.proxmox_site(self.cfg)["endpoint"], "https://pve1.example:8006")
        self.assertEqual(h.proxmox_site(self.cfg, "home")["_where"], "proxmox")
        off = h.proxmox_site(self.cfg, "offsite")
        self.assertEqual((off["endpoint"], off["_site"]), ("https://pve-off.example:8006", "offsite"))
        self.assertEqual(h.proxmox_token_name(off, "provisioning"), "off-rw")
        with self.assertRaises(h.ConfigError):
            h.proxmox_site(self.cfg, "parents")                    # no Proxmox there
        with self.assertRaises(h.ConfigError):
            h.site(self.cfg, "nope")
        self.assertEqual([p["_site"] for p in h.proxmox_sites(self.cfg)], ["home", "offsite"])
        self.assertEqual(h.site_of_secret(self.cfg, "off-ro")["_site"], "offsite")
        self.assertEqual(h.site_of_secret(self.cfg, "proxmox-rw")["_site"], "home")   # template default name
        self.assertEqual(h.site_of_address(self.cfg, "192.0.2.7")["name"], "offsite")
        self.assertIsNone(h.site_of_address(self.cfg, "10.0.0.1"))
        self.assertEqual(h.host_sites(["linux", "site_offsite"]), ["offsite"])
        self.assertEqual(h.proxmox_snapshot_file("/r", "offsite", False).name, "proxmox-offsite.json")
        self.assertEqual(h.proxmox_snapshot_file("/r", "home", True).name, "proxmox.json")
        single = h.sites({"proxmox": {"endpoint": "x"}})                  # no sites: one unnamed default
        self.assertEqual((len(single), single[0]["name"], single[0]["default"]), (1, "", True))

    def test_invalid_sites(self):
        h = self.h
        for bad in ([{"name": "Off-Site"}], [{"name": "a"}, {"name": "a"}], [{"label": "x"}],
                    [{"name": "home", "proxmox": {"endpoint": "x"}}], "home", [{"name": "x", "ranges": ["nope"]}]):
            with self.assertRaises(h.ConfigError, msg=bad):
                h.sites({"sites": bad})

    def test_site_settings_env_and_vlans(self):
        h = self.h
        cfg = {**self.cfg, "vmid_ranges": {"vms": [100, 899], "templates": [9050, 9999]}, "vmid_scheme": "",
               "templates": {"keep_versions": 3, "build_network": {"ip": "10.0.10.250/24"}},
               "network": {"vlans": [{"id": 20, "name": "DMZ"}, {"id": 30, "name": "Backup", "site": "offsite"},
                                     {"id": 31, "name": "Backup", "site": "home"}]}}
        cfg["sites"] = [cfg["sites"][0], {**cfg["sites"][1], "vmid_ranges": {"vms": [2000, 2099]},
                                          "templates": {"build_network": {"ip": "192.0.2.250/24"}}}, cfg["sites"][2]]
        off = h.site_config(cfg, "offsite")
        self.assertEqual(off["vmid_ranges"], {"vms": [2000, 2099]})
        self.assertEqual(off["templates"], {"keep_versions": 3, "build_network": {"ip": "192.0.2.250/24"}})
        self.assertEqual(h.site_config(cfg, "parents")["vmid_ranges"], cfg["vmid_ranges"])   # no own: top-level
        self.assertEqual(h.next_vmid(off, "vms", {2000: "x"}), 2001)
        self.assertEqual((h.tofu_env(cfg), h.tofu_env(cfg, "home"), h.tofu_env(cfg, "offsite")),
                         ("homelab", "homelab", "offsite"))
        self.assertEqual(h.site_of_env(cfg, "offsite")["name"], "offsite")
        self.assertEqual(h.site_of_env(cfg, "homelab")["name"], "home")
        self.assertEqual(h.resolve_vlan(cfg, "backup", "offsite"), 30)
        self.assertEqual(h.resolve_vlan(cfg, "backup", "home"), 31)
        self.assertEqual(h.resolve_vlan(cfg, "dmz", "offsite"), 20)                   # no site: every site
        with self.assertRaises(h.ConfigError):
            h.resolve_vlan(cfg, "backup")                                              # ambiguous without a site
        self.assertEqual(h.vlan_label(cfg, 30, site_name="offsite"), "VLAN 30 Backup")
        for bad in ({"sites": [{"name": "home"}, {"name": "homelab"}]},                # = the default environment
                    {"sites": [{"name": "home", "vmid_ranges": {"vms": [1, 2]}}]},      # default: top-level keys
                    {"sites": [{"name": "home"}, {"name": "off", "vmid_ranges": [1, 2]}]},
                    {"sites": [{"name": "home"}], "network": {"vlans": [{"id": 5, "site": "moon"}]}},
                    {"network": {"vlans": [{"id": 5, "site": "home"}]}}):
            with self.assertRaises(h.ConfigError, msg=bad):
                h.sites(bad)

    def test_next_vmid_per_site(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", d, "--components", "proxmox", cwd=d)
        r = run("config_set.py", "sites+={name: home}",
                "sites+={name: offsite, proxmox: {endpoint: 'https://pve-off.example:8006'}}", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        snap = lambda ids: json.dumps({"guests": [{"vmid": i, "type": "vm", "name": f"g{i}"} for i in ids]})
        Path(d, "discovery/proxmox.json").write_text(snap([100, 101]))
        Path(d, "discovery/proxmox-offsite.json").write_text(snap([100]))
        Path(d, "tofu/environments/homelab/homelab.auto.tfvars").write_text("vms = {\n  a = {\n    vm_id = 102\n  }\n}\n")
        Path(d, "tofu/environments/offsite").mkdir()
        Path(d, "tofu/environments/offsite/homelab.auto.tfvars").write_text("vms = {\n  b = {\n    vm_id = 101\n  }\n}\n")
        r = run("proxmox_inventory.py", "--next-vmid", "vms", cwd=d)
        self.assertEqual(r.stdout.strip(), "103", r.stderr)                 # not held back by the other site
        r = run("proxmox_inventory.py", "--next-vmid", "vms", "--site", "offsite", cwd=d)
        self.assertEqual(r.stdout.strip(), "102", r.stderr)
        r = run("config_set.py", "network.vlans+={id: 5, site: moon}", cwd=d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Nothing was written", r.stderr)

    def test_with_secrets_uses_the_site_of_the_token(self):
        import with_secrets
        cfg = {**self.cfg, "secrets": {n: {"service": "x", "kind": "proxmox_token"} for n in ("proxmox-ro", "off-ro")}}
        orig = self.h.read_secret
        self.h.read_secret = lambda c, n: "homelab@pve!ro=s3cret"
        try:
            home, _ = with_secrets.env_for(cfg, "proxmox-ro")
            off, _ = with_secrets.env_for(cfg, "off-ro")
        finally:
            self.h.read_secret = orig
        self.assertEqual(home["PROXMOX_VE_ENDPOINT"], "https://pve1.example:8006/")
        self.assertNotIn("PROXMOX_VE_INSECURE", home)
        self.assertEqual(off["PROXMOX_URL"], "https://pve-off.example:8006/api2/json")
        self.assertEqual(off["PROXMOX_VE_INSECURE"], "true")
        self.assertEqual((home["TF_VAR_proxmox_site"], off["TF_VAR_proxmox_site"], off["PKR_VAR_proxmox_site"]),
                         ("home", "offsite", "offsite"))

    def test_site_group_problems(self):
        import check_env
        inv = {"all": {"children": ["site_home", "site_offsite", "site_moon", "linux"]},
               "site_home": {"hosts": ["web01", "dup"]}, "site_offsite": {"children": ["offsite_dc"]},
               "offsite_dc": {"hosts": ["backup01", "dup"]}, "site_moon": {"hosts": ["rover"]},
               "linux": {"hosts": ["web01", "backup01"]}}
        problems = check_env.site_group_problems(inv, self.cfg)
        self.assertIn("group site_moon: homelab.yaml has no site 'moon' (sites:)", problems)
        self.assertIn("dup is in several site groups (site_home, site_offsite)", problems)
        self.assertEqual(len(problems), 2)

    def test_draft_goes_into_the_site_group(self):
        import proxmox_to_inventory
        text = proxmox_to_inventory.to_yaml({"backup01": {"ansible_host": "192.0.2.2", "_os": "debian"}}, [],
                                            "onboarding", "discovery/proxmox-offsite.json", "site_offsite")
        self.assertIn("    site_offsite:\n      hosts:\n        backup01:", text)

    def test_drift_and_redaction_cover_every_site(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", d, "--components", "proxmox,ansible,discovery", cwd=d)
        r = run("config_set.py", "proxmox.endpoint=https://pve1.example:8006", "sites+={name: home}",
                "sites+={name: offsite, label: Rented server, ranges: [192.0.2.0/24], "
                "proxmox: {endpoint: 'https://pve-off.example:8006'}}", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        guest = lambda vmid, name, tags: {"vmid": vmid, "name": name, "type": "vm", "node": "n1", "status": "running",
                                          "template": False, "tags": tags}
        snap = lambda guests: {"collected_at": "2026-01-01T00:00:00+00:00", "version": "9", "cluster": None,
                               "nodes": [], "networks": {}, "storage": [], "guests": guests, "backup_jobs": []}
        Path(d, "discovery/proxmox.json").write_text(json.dumps(snap([guest(100, "dns01", "tofu")])))
        Path(d, "discovery/proxmox-offsite.json").write_text(json.dumps(
            {"site": "offsite", **snap([guest(100, "offbackup", "")])}))
        Path(d, "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    site_home:\n      hosts:\n        dns01: {ansible_host: 10.0.10.5}\n"
            "    site_offsite:\n      hosts:\n        dns01:\n    site_moon:\n      hosts:\n        rover: {ansible_host: 10.9.9.9}\n")
        host = {"mac": None, "hostnames": [], "device_type_guess": "server", "vendor": None}
        Path(d, "discovery/network.json").write_text(json.dumps({"updated_at": "x", "hosts": {"192.0.2.9": host}}))
        r = run("drift_report.py", "--no-tofu", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn("| Proxmox snapshot — site offsite (Rented server) | 2026-01-01", out)
        self.assertIn("## Proxmox ↔ OpenTofu — site offsite (Rented server) (by `tofu` tag", out)
        self.assertIn("offsite/100 vm `offbackup`", out)                     # same VMID, kept apart
        self.assertNotIn("home/100 vm `dns01` on", out)                       # tagged: managed
        self.assertIn("## Backups — site offsite (Rented server)", out)
        self.assertIn("`dns01` is in several site groups", out)
        self.assertIn("`rover` is in `site_moon`, but homelab.yaml has no site 'moon'", out)
        self.assertIn("192.0.2.9  — server [site offsite (Rented server)]", out)
        import issues
        cfg = self.h.load_config(d)
        domains, hosts = issues.site_terms(cfg)
        self.assertIn("pve-off.example", hosts)
        self.assertIn("Rented server", hosts)
        self.assertIn("offbackup", hosts)


class SiteTofuTests(unittest.TestCase):  # issue 52, part 2
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", self.d, "--components", "proxmox,ansible", cwd=self.d)
        r = run("config_set.py", "proxmox.endpoint=https://pve1.example:8006", "sites+={name: home}",
                "sites+={name: offsite, proxmox: {endpoint: 'https://pve-off.example:8006'}}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib

    def test_add_site_and_check(self):
        import check_env
        cfg = self.h.load_config(self.d)
        self.assertEqual([r["ok"] for r in check_env.check_tofu_sites(cfg)], [False, None])  # homelab: no site.tf
        r = run("init_repo.py", self.d, "--add-site", "offsite", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('var.proxmox_site == "offsite"', Path(self.d, "tofu/environments/offsite/site.tf").read_text())
        self.assertIn('var.proxmox_site == "home"', Path(self.d, "tofu/environments/homelab/site.tf").read_text())
        self.assertTrue(Path(self.d, "tofu/environments/offsite/main.tf").is_file())
        self.assertIn("ansible_group_priority: 10",
                      Path(self.d, "ansible/inventory/managed/group_vars/site_offsite.yml").read_text())
        self.assertEqual([r["ok"] for r in check_env.check_tofu_sites(cfg)], [True, True])
        subprocess.run(["yq", "-i", '.opentofu.local.path = "~/st/state.tfstate"', str(Path(self.d, "homelab.yaml"))],
                       check=True)
        res = check_env.check_tofu_sites(self.h.load_config(self.d))
        self.assertEqual(res[-1]["check"], "tofu:state")
        self.assertFalse(res[-1]["ok"])
        self.assertNotEqual(run("init_repo.py", self.d, "--add-site", "home", cwd=self.d).returncode, 0)
        self.assertNotEqual(run("init_repo.py", self.d, "--add-site", "moon", cwd=self.d).returncode, 0)

    def test_state_per_environment(self):
        run("init_repo.py", self.d, "--add-site", "offsite", cwd=self.d)
        init = lambda *a: run("tofu_init.py", "--print", *a, cwd=self.d)
        r = init("--site", "offsite")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("tofu/environments/offsite", r.stdout)
        self.assertIn("/offsite.tfstate", r.stdout)
        cfg = Path(self.d, "homelab.yaml")
        subprocess.run(["yq", "-i", f'.opentofu.local.path = "{self.d}/st/state.tfstate"', str(cfg)], check=True)
        self.assertEqual(init().returncode, 0)                                   # default env: as before
        r = init("--site", "offsite")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("has no {env}", r.stderr)
        subprocess.run(["yq", "-i", f'.opentofu.local.path = "{self.d}/st/{{env}}.tfstate"', str(cfg)], check=True)
        self.assertIn(f"{self.d}/st/offsite.tfstate", init("--site", "offsite").stdout)

    def test_tofu_hosts_per_site(self):
        import tofu_to_inventory
        text = tofu_to_inventory.to_yaml({"linux": {"web09": {"ansible_host": "192.0.2.9"}}}, "offsite", "site_offsite")
        self.assertIn("(offsite)", text.splitlines()[0])
        self.assertIn("    site_offsite:\n      hosts:\n        web09:", text)
        self.assertIn("children: {}", tofu_to_inventory.to_yaml({}, "offsite", "site_offsite"))

    def test_drift_compares_each_site_with_its_state(self):
        import drift_report
        state = {"values": {"root_module": {"child_modules": [{"resources": [
            {"type": "proxmox_virtual_environment_vm", "mode": "managed", "address": "module.vm[\"web09\"].x",
             "values": {"vm_id": 100, "name": "web09", "node_name": "n1", "started": True}}]}]}}}
        px = {"guests": [{"vmid": 100, "name": "web09", "type": "vm", "node": "n2", "status": "running",
                          "template": False, "cpus": None, "mem_gib": None},
                         {"vmid": 101, "name": "hand", "type": "vm", "node": "n1", "status": "running",
                          "template": False, "cpus": None, "mem_gib": None}]}
        lines, n = drift_report.compare_state(px, state, "offsite/")
        text = "\n".join(lines)
        self.assertIn("- offsite/101 vm `hand`", text)
        self.assertIn("offsite/100 `module.vm[\"web09\"].x`: node n1 → live n2", text)
        self.assertEqual(n, 2)
        Path(self.d, "discovery/proxmox-offsite.json").write_text(json.dumps({"collected_at": "x", **px}))
        Path(self.d, "state.json").write_text(json.dumps(state))
        r = run("drift_report.py", "--tofu-json", "state.json", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("| OpenTofu state — site offsite | unavailable: no OpenTofu environment "
                      "(init_repo.py --add-site offsite) |", r.stdout)


class PveNodePlanTests(unittest.TestCase):  # issue 23
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import pve_node_plan
        self.p = pve_node_plan
        node = lambda n, mem, used, status="online": {"node": n, "status": status, "mem_gib": mem, "mem_used_gib": used}
        g = lambda vmid, kind, conf, mem=4, status="running", **kw: {
            "vmid": vmid, "type": kind, "name": f"g{vmid}", "node": "pve1", "status": status, "template": False,
            "mem_gib": mem, "config": conf, **kw}
        self.inv = {
            "collected_at": "t", "cluster": {"name": "c", "quorate": 1},
            "nodes": [node("pve1", 64, 40), node("pve2", 64, 20), node("pve3", 32, 8)],
            "storage": [{"storage": "ceph", "node": n, "shared": True} for n in ("pve1", "pve2", "pve3")]
                       + [{"storage": "local-zfs", "node": "pve1", "shared": False},
                          {"storage": "local", "node": "pve1", "shared": False}],
            "guests": [
                g(101, "vm", {"scsi0": "ceph:vm-101-disk-0,size=32G", "ide2": "none,media=cdrom", "onboot": 1,
                              "startup": "order=1"}, mem=16),
                g(102, "vm", {"scsi0": "ceph:vm-102-disk-0", "ide2": "local:iso/x.iso,media=cdrom"}),
                g(103, "vm", {"scsi0": "local-zfs:vm-103-disk-0", "startup": "order=2"}),
                g(104, "vm", {"scsi0": "ceph:vm-104-disk-0", "hostpci0": "0000:01:00"}),
                g(105, "lxc", {"rootfs": "ceph:subvol-105-disk-0", "mp0": "/srv/data,mp=/data"}),
                g(106, "lxc", {"rootfs": "ceph:subvol-106-disk-0"}, mem=2),
                g(107, "vm", {"scsi0": "ceph:vm-107-disk-0"}, hastate="started"),
                g(108, "vm", {"scsi0": "ceph:vm-108-disk-0"}, status="stopped"),
                {**g(9000, "vm", {"scsi0": "ceph:base"}), "template": True},
                {**g(201, "vm", {"scsi0": "ceph:vm-201"}), "node": "pve2"},
            ]}

    def actions(self, plan):
        return {r["vmid"]: (r["action"], r["target"]) for r in plan["guests"]}

    def test_shared_storage_guests_migrate_and_spread(self):
        plan, blockers = self.p.make_plan(self.inv, "pve1")
        self.assertEqual(blockers, [])
        acts = self.actions(plan)
        self.assertEqual(acts[101], ("migrate", "pve2"))        # 16 GiB: pve2 36/64=56% beats pve3 24/32=75%
        self.assertEqual(acts[106], ("migrate", "pve3"))        # pve3 10/32=31% beats pve2 (36+2)/64=59%
        self.assertEqual(acts[102][0], "stop")                  # local ISO pins it
        self.assertEqual(acts[103][0], "stop")
        self.assertEqual(acts[104][0], "stop")                  # passthrough
        self.assertEqual(acts[105][0], "stop")                  # bind mount
        self.assertEqual(acts[107][0], "ha")
        self.assertEqual(acts[108][0], "stays-stopped")
        self.assertNotIn(9000, acts)
        self.assertNotIn(201, acts)
        self.assertEqual(plan["stop_order"], [105, 104, 102, 103])  # unordered first (reverse startup order)
        self.assertIn("ide2 on local", next(r for r in plan["guests"] if r["vmid"] == 102)["reason"])
        self.assertTrue(next(r for r in plan["guests"] if r["vmid"] == 101)["onboot"])

    def test_capacity_and_no_migrate(self):
        plan, _ = self.p.make_plan(self.inv, "pve1", max_pct=40)
        self.assertEqual(self.actions(plan)[101][0], "stop")     # 16 GiB fits nowhere below 40 %
        self.assertIn("no node has room", next(r for r in plan["guests"] if r["vmid"] == 101)["reason"])
        plan, _ = self.p.make_plan(self.inv, "pve1", migrate=False)
        self.assertNotIn("migrate", {a for a, _ in self.actions(plan).values()})

    def test_blockers(self):
        self.inv["nodes"][2]["status"] = "offline"
        self.inv["cluster"]["quorate"] = 0
        _, blockers = self.p.make_plan(self.inv, "pve1")
        self.assertTrue(any("not quorate" in b for b in blockers))
        self.assertTrue(any("pve3" in b for b in blockers))
        plan, blockers = self.p.make_plan(self.inv, "nope")
        self.assertEqual(plan, {})

    def test_cli_writes_plan_only_without_blockers(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible", cwd=d)
        (d / "discovery/proxmox.json").write_text(json.dumps(self.inv))
        r = run("pve_node_plan.py", "pve1", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("migrate → pve2", r.stdout)
        plan = json.loads((d / "discovery/pve-patch-pve1.json").read_text())
        self.assertEqual(plan["node"], "pve1")
        (d / "discovery/pve-patch-pve1.json").unlink()
        self.inv["cluster"]["quorate"] = 0
        (d / "discovery/proxmox.json").write_text(json.dumps(self.inv))
        r = run("pve_node_plan.py", "pve1", cwd=d)
        self.assertEqual(r.returncode, 4)
        self.assertIn("Do NOT patch", r.stdout)
        self.assertFalse((d / "discovery/pve-patch-pve1.json").exists())


    def test_other_site_and_standalone_node(self):  # issue 52
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible", cwd=d)
        run("config_set.py", "sites+={name: home}", "sites+={name: offsite, proxmox: {endpoint: 'https://x:8006'}}", cwd=d)
        (d / "discovery/proxmox.json").write_text(json.dumps(self.inv))
        alone = {**self.inv, "site": "offsite", "cluster": None, "nodes": self.inv["nodes"][:1]}
        (d / "discovery/proxmox-offsite.json").write_text(json.dumps(alone))
        r = run("pve_node_plan.py", "pve1", "--site", "offsite", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("at site offsite", r.stdout)
        self.assertIn("Standalone node", r.stdout)
        plan = json.loads((d / "discovery/pve-patch-offsite-pve1.json").read_text())
        self.assertEqual((plan["site"], plan["standalone"]), ("offsite", True))
        self.assertEqual({r["action"] for r in plan["guests"]}, {"stop", "ha", "stays-stopped"})
        self.assertFalse((d / "discovery/pve-patch-pve1.json").exists())   # the home node's plan is separate
        self.assertEqual(run("pve_node_plan.py", "pve1", cwd=d).returncode, 0)
        plan = json.loads((d / "discovery/pve-patch-pve1.json").read_text())
        self.assertEqual((plan["site"], plan["standalone"]), ("home", False))


class PveNodePlaybookUpgradeTests(unittest.TestCase):  # issue 23
    def test_new_playbook_offered_to_existing_repos(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible", cwd=d)
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertTrue((d / "ansible/playbooks/tasks/pve-migrate.yml").is_file())
        self.assertNotIn("patch-proxmox-node", ids())
        (d / "ansible/playbooks/patch-proxmox-node.yml").unlink()
        notes = json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)
        note = next(n for n in notes if n["id"] == "patch-proxmox-node")
        self.assertIn("repo-template/ansible/playbooks/patch-proxmox-node.yml", note["action"])

    def test_patch_linux_guard_offered_to_existing_repos(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "ansible", cwd=d)
        self.assertIn("patch_requires_approval: true",
                      (d / "ansible/inventory/managed/group_vars/proxmox_nodes.yml").read_text())
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertNotIn("patch-requires-approval", ids())
        pb = d / "ansible/playbooks/patch-linux.yml"
        pb.write_text(re.sub(r"\n    - name: Refuse hosts that need.*?run_once: true\n", "\n", pb.read_text(), flags=re.S))
        self.assertNotIn("Refuse hosts that need", pb.read_text())
        self.assertIn("patch-requires-approval", ids())


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

    def test_yaml_flow_maps(self):  # issue 34: network.vlans entries
        r = run("config_set.py", "network.vlans+={id: 20, name: DMZ, cidr: 10.0.20.0/24}",
                'network.vlans+={"id": 30, "name": "MGMT"}', cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(yq(".network.vlans", self.f)),
                         [{"id": 20, "name": "DMZ", "cidr": "10.0.20.0/24"}, {"id": 30, "name": "MGMT"}])
        run("config_set.py", "vmid_scheme={vlan}{octet:03d}", cwd=self.d)          # not a flow map: a string
        self.assertEqual(json.loads(yq(".vmid_scheme", self.f)), "{vlan}{octet:03d}")

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


class NmapInterfaceTests(unittest.TestCase):  # issue 18
    def setUp(self):
        sys.path.insert(0, str(ROOT / "skills/homelab-manager/scripts"))
        import nmap_scan
        self.n = nmap_scan

    def test_parse_route(self):
        direct = "   route to: 10.0.10.5\ndestination: 10.0.10.0\n  interface: en0\n      flags: <UP,DONE,CLONING>\n"
        routed = "   route to: 10.0.20.5\n    gateway: 10.0.10.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC>\n"
        self.assertEqual(self.n.parse_route(direct), ("en0", False))
        self.assertEqual(self.n.parse_route(routed), ("en0", True))
        self.assertEqual(self.n.parse_route(""), (None, False))

    def test_probe_ip(self):
        self.assertEqual(self.n.probe_ip("10.0.10.0/24"), "10.0.10.1")
        self.assertEqual(self.n.probe_ip("10.0.10.5"), "10.0.10.5")
        self.assertEqual(self.n.probe_ip("10.0.10.20-30"), "10.0.10.21")

    def _xml(self, hosts):
        rows = "".join(f'<host><status state="up" reason="{r}"/><address addr="{ip}" addrtype="ipv4"/>'
                       + (f'<address addr="{m}" addrtype="mac"/>' if m else "") + "</host>" for ip, r, m in hosts)
        p = Path(tempfile.mkdtemp()) / "s.xml"
        p.write_text(f"<nmaprun>{rows}</nmaprun>")
        return p

    def test_proxy_arp_detected(self):
        same = [(f"10.0.10.{i}", "arp-response", "AA:BB:CC:00:00:01") for i in range(1, 40)]
        self.assertEqual(self.n.proxy_arp_mac(self._xml(same)), "aa:bb:cc:00:00:01")
        real = [(f"10.0.10.{i}", "arp-response", f"AA:BB:CC:00:00:{i:02x}") for i in range(1, 40)]
        self.assertIsNone(self.n.proxy_arp_mac(self._xml(real)))
        few = same[:5]
        self.assertIsNone(self.n.proxy_arp_mac(self._xml(few)))
        nomac = [(f"10.0.10.{i}", "syn-ack", None) for i in range(1, 40)]
        self.assertIsNone(self.n.proxy_arp_mac(self._xml(nomac)))

    def test_live_hosts(self):
        db = {"hosts": {"10.0.10.5": {}, "10.0.10.40": {}, "10.0.11.2": {}, "fe80::1": {}}}
        self.assertEqual(self.n.live_hosts(db, ["10.0.10.0/24"]), ["10.0.10.5", "10.0.10.40"])
        self.assertEqual(self.n.live_hosts(db, ["10.0.10.1-10"]), ["10.0.10.5"])

    def test_merge_guesses_from_all_scans(self):  # issue 21
        ports = [{"port": 22, "service": "ssh", "product": "OpenSSH Debian"},
                 {"port": 3128, "service": "http", "product": "Proxmox VE spiceproxy"}]
        svc = self.n.merge_host({}, {"ip": "10.0.10.2", "os": [], "ports": ports}, "services", "t1")
        self.assertEqual(svc["device_type_guess"], "hypervisor")
        os_scan = self.n.merge_host(svc, {"ip": "10.0.10.2", "os": [{"name": "Linux 6.x"}], "ports": ports}, "os", "t2")
        self.assertEqual(os_scan["device_type_guess"], "hypervisor")
        again = self.n.merge_host(os_scan, {"ip": "10.0.10.2", "os": [], "ports": ports[:1]}, "services", "t3")
        self.assertEqual(again["os"], [{"name": "Linux 6.x"}])   # earlier OS evidence kept and used
        ping = self.n.merge_host(os_scan, {"ip": "10.0.10.2", "os": [], "ports": []}, "ping", "t4")
        self.assertEqual(ping["device_type_guess"], "hypervisor")
        self.assertEqual(ping["first_seen"], "t1")

    # GitHub issue #28: the gateway's OS fingerprint mustn't turn a Debian VM behind it into `network`
    GW_OS = [{"name": "Linux 4.15 - 5.19", "accuracy": 92}, {"name": "MikroTik RouterOS 7.2 - 7.14 (Linux 5.6.3)",
             "accuracy": 91}, {"name": "OpenWrt 21.02 (Linux 5.4)", "accuracy": 90}]

    def _vm(self, **kw):
        return {"ip": "10.0.20.11", "os": [dict(o) for o in self.GW_OS], **kw,
                "ports": [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "10.0p2 Debian 7+deb13u4"},
                          {"port": 8080, "service": "http", "product": "Apache Tomcat", "version": None}]}

    def test_debian_banner_beats_borrowed_routeros_guess(self):
        self.assertEqual(self.n.guess_type(self._vm()), "linux")
        self.assertEqual(self.n.guess_type(self._vm(os_suspect=["10.0.20.1"])), "linux")

    def test_ostype_and_windows_banner(self):
        h = {"os": [{"name": "MikroTik RouterOS 7"}], "os_suspect": ["10.0.20.1"],
             "ports": [{"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC", "ostype": "Windows"}]}
        self.assertEqual(self.n.guess_type(h), "windows")
        self.assertEqual(self.n.banner_os({"product": "Apache httpd", "version": "2.4.62", "ostype": "Linux"}), "linux")
        self.assertIsNone(self.n.banner_os({"product": "OpenSSH", "version": "9.6"}))

    def test_real_router_keeps_network(self):
        gw = {"os": [dict(o) for o in self.GW_OS], "os_suspect": ["10.0.20.11"],
              "ports": [{"port": 22, "service": "ssh", "product": "MikroTik RouterOS sshd"},
                        {"port": 8291, "service": "unknown", "product": None}]}
        self.assertEqual(self.n.guess_type(gw), "network")
        alone = {"os": [{"name": "MikroTik RouterOS 7.2 - 7.14 (Linux 5.6.3)"}],   # no banner says otherwise
                 "ports": [{"port": 22, "service": "ssh", "product": "OpenSSH"}]}
        self.assertEqual(self.n.guess_type(alone), "network")

    def test_flag_shared_os(self):
        hosts = [{"ip": "10.0.20.1", "os": list(self.GW_OS)}, {"ip": "10.0.20.11", "os": list(self.GW_OS)},
                 {"ip": "10.0.20.12", "os": [{"name": "Linux 6.x"}]}, {"ip": "10.0.20.13", "os": []}]
        self.n.flag_shared_os(hosts)
        self.assertEqual(hosts[0]["os_suspect"], ["10.0.20.11"])
        self.assertEqual(hosts[1]["os_suspect"], ["10.0.20.1"])
        self.assertIs(hosts[2]["os_suspect"], False)
        self.assertNotIn("os_suspect", hosts[3])
        # a later services scan (no OS) keeps the flag; a clean os scan clears it
        merged = self.n.merge_host(hosts[1], {"ip": "10.0.20.11", "os": [], "ports": []}, "services", "t")
        self.assertEqual(merged["os_suspect"], ["10.0.20.1"])
        clean = self.n.merge_host(merged, {"ip": "10.0.20.11", "os": [{"name": "Linux 6.x"}], "os_suspect": False,
                                           "ports": []}, "os", "t2")
        self.assertIs(clean["os_suspect"], False)

    def test_parse_xml_reads_ostype(self):
        p = Path(tempfile.mkdtemp()) / "o.xml"
        p.write_text('<nmaprun><host><status state="up"/><address addr="10.0.20.11" addrtype="ipv4"/><ports>'
                     '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" '
                     'version="10.0p2 Debian 7+deb13u4" ostype="Linux"/></port></ports></host></nmaprun>')
        (h,) = self.n.parse_xml(p)
        self.assertEqual(h["ports"][0]["ostype"], "Linux")
        self.assertEqual(h["device_type_guess"], "linux")


class GitUpstreamTests(unittest.TestCase):  # issue 27
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import check_env
        self.ce = check_env
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        g = lambda *a, cwd: subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, check=True)
        self.git = g
        g("init", "-q", "--bare", "-b", "main", str(self.d / "remote.git"), cwd=self.d)
        self.repo = self.d / "repo"
        g("clone", "-q", str(self.d / "remote.git"), str(self.repo), cwd=self.d)
        for k, v in (("user.name", "t"), ("user.email", "t@example.test"), ("commit.gpgsign", "false")):
            g("config", k, v, cwd=self.repo)
        g("commit", "-q", "--allow-empty", "-m", "one", cwd=self.repo)
        g("push", "-q", "-u", "origin", "main", cwd=self.repo)

    def check(self, auto_push):
        return self.ce.check_git_upstream({"_root": str(self.repo), "git": {"auto_push": auto_push}})

    def test_in_sync_ahead_and_behind(self):
        self.assertEqual(self.check(True)[0]["ok"], True)
        self.git("commit", "-q", "--allow-empty", "-m", "two", cwd=self.repo)
        r = self.check(False)[0]
        self.assertIsNone(r["ok"])                                       # a hint, not a failure
        self.assertIn("1 commit(s) not pushed to origin/main", r["detail"])
        self.assertIn("git.auto_push: true", r["detail"])
        self.assertIs(self.check(True)[0]["ok"], False)                  # auto_push should have pushed it
        self.git("reset", "-q", "--hard", "HEAD~1", cwd=self.repo)
        self.git("update-ref", "refs/remotes/origin/main", "HEAD@{1}", cwd=self.repo)
        r = self.check(False)[0]
        self.assertIs(r["ok"], False)
        self.assertIn("git pull --ff-only", r["detail"])

    def test_existing_repo_is_offered_auto_push(self):
        run("init_repo.py", str(self.repo), "--components", "ansible", cwd=self.repo)
        cfg = self.repo / "homelab.yaml"
        self.assertEqual(yq(".git.auto_push", cfg), "false")                    # new repos: off, asked in setup
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=self.repo).stdout)]
        self.assertNotIn("git-auto-push", ids())
        subprocess.run(["yq", "-i", "del(.git.auto_push)", str(cfg)], check=True)
        self.assertIn("git-auto-push", ids())
        r = run("config_set.py", "git.auto_push=true", cwd=self.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(yq(".git.auto_push", cfg), "true")
        self.assertNotIn("git-auto-push", ids())

    def test_no_upstream(self):
        self.git("branch", "-q", "--unset-upstream", cwd=self.repo)
        self.assertEqual(self.check(False), [])
        r = self.check(True)[0]
        self.assertIs(r["ok"], False)
        self.assertIn("no upstream", r["detail"])


FAKE_SSH = r'''#!/usr/bin/env python3
import json, os, sys
host = sys.argv[-3]
with open(os.environ["FAKE_SSH_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
script = sys.stdin.read()
assert "hm_probe=1" in script and sys.argv[-2:] == ["sh", "-s"]
replies = {
    "10.0.20.11": "hm_probe=1\nhostname=db01.example.test\nkernel=Linux 4.18.0\nos_id=rocky\nos_version=8.10\n"
                  "os_like=rhel centos fedora\nos_name=Rocky Linux 8.10 (Green Obsidian)\nvirt=kvm\n"
                  "python_default=/usr/bin/python3 Python 3.6.8\npython=/usr/bin/python3 Python 3.6.8\n"
                  "python=/usr/bin/python3.12 Python 3.12.5\npython=/usr/libexec/platform-python Python 3.6.8\n",
    "10.0.20.20": "hm_probe=1\nhostname=pve2\nkernel=Linux 6.8.12-4-pve\nos_id=debian\nos_version=12\n"
                  "os_name=Debian GNU/Linux 12 (bookworm)\nproduct=pve-manager/8.3.1/fb48e850ef9dde27 (running kernel: 6.8)\n"
                  "virt=none\npython_default=/usr/bin/python3 Python 3.11.2\n",
}
if host == "10.0.20.12":
    sys.stderr.write("admin@10.0.20.12: Permission denied (publickey).\n")
    sys.exit(255)
if host == "10.0.20.15":
    sys.stdout.write("bad command name sh (line 1 column 1)\n")
    sys.exit(1)
sys.stdout.write(replies[host])
'''


class SshProbeTests(unittest.TestCase):  # issue 25
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "ansible,discovery", cwd=self.d)
        run("config_set.py", "network.authorized_ranges+=10.0.20.0/24", "network.excluded_hosts+=10.0.20.99",
            "defaults.admin_user=admin", cwd=self.d)
        ssh = lambda: [{"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": None}]
        hosts = {
            "10.0.20.11": {"ip": "10.0.20.11", "ports": ssh(), "os": [], "hostnames": [], "last_profile": "services"},
            "10.0.20.12": {"ip": "10.0.20.12", "ports": ssh(), "os": [], "hostnames": [], "last_profile": "services"},
            "10.0.20.13": {"ip": "10.0.20.13", "ports": [{"port": 80, "proto": "tcp"}], "last_profile": "services"},
            "10.0.20.14": {"ip": "10.0.20.14", "ports": [], "last_profile": "ping"},
            "10.0.20.15": {"ip": "10.0.20.15", "ports": ssh(), "os": [], "hostnames": [], "last_profile": "services"},
            "10.0.20.17": {"ip": "10.0.20.17", "ports": ssh(), "last_profile": "services"},
            "10.0.20.99": {"ip": "10.0.20.99", "ports": ssh(), "last_profile": "services"},
            "10.0.30.5": {"ip": "10.0.30.5", "ports": ssh(), "last_profile": "services"},
        }
        (self.d / "discovery/network.json").write_text(json.dumps({"hosts": hosts}))
        (self.d / "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n        known:\n          ansible_host: 10.0.20.17\n")
        bin_ = self.d / "bin"
        bin_.mkdir()
        (bin_ / "ssh").write_text(FAKE_SSH)
        (bin_ / "ssh").chmod(0o755)
        self.log = self.d / "ssh.log"
        self.env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "FAKE_SSH_LOG": str(self.log)}

    def probe(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "ssh_probe.py"), *args], cwd=self.d, env=self.env,
                              capture_output=True, text=True)

    def test_probes_ssh_hosts_in_range_and_merges(self):
        r = self.probe("10.0.20.0/24", "10.0.20.20")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("skip 10.0.20.13: no SSH seen on 22/tcp", r.stderr)
        self.assertIn("skip 10.0.20.14: only ping-scanned", r.stderr)
        self.assertIn("skip 10.0.20.17: already in the managed inventory", r.stderr)
        self.assertIn("skip 10.0.20.99: in network.excluded_hosts", r.stderr)
        self.assertNotIn("10.0.30.5", r.stderr + r.stdout)                          # not in the targets
        self.assertRegex(r.stdout, r"10\.0\.20\.11 +db01\.example\.test +Rocky Linux 8\.10.*3\.12\.5 \(python3 is 3\.6\.8\) +el8")
        self.assertIn("10.0.20.11 → /usr/bin/python3.12", r.stdout)
        self.assertIn("10.0.20.12       —                        auth failed", r.stdout)
        self.assertIn("10.0.20.15       —                        logged in, but `sh` did not run", r.stdout)
        self.assertRegex(r.stdout, r"10\.0\.20\.20 +pve2 +pve-manager.*proxmox_nodes")
        calls = [json.loads(l) for l in self.log.read_text().splitlines()]
        self.assertEqual(sorted(c[-3] for c in calls), ["10.0.20.11", "10.0.20.12", "10.0.20.15", "10.0.20.20"])
        for c in calls:
            self.assertIn("-T", c)
            self.assertIn("BatchMode=yes", c)
            self.assertIn("StrictHostKeyChecking=accept-new", c)
            kh = next(o for o in c if o.startswith("UserKnownHostsFile="))
            self.assertNotIn(".ssh", kh)                                            # throwaway known_hosts
            self.assertEqual(c[c.index("-l") + 1], "admin")                          # defaults.admin_user
        net = json.loads((self.d / "discovery/network.json").read_text())["hosts"]
        self.assertEqual(net["10.0.20.20"]["device_type_guess"], "hypervisor")      # new host, from the probe
        self.assertEqual(net["10.0.20.11"]["ssh_probe"]["os_id"], "rocky")
        self.assertFalse(net["10.0.20.12"]["ssh_probe"]["ok"])
        self.assertNotIn("ssh_probe", net["10.0.20.13"])

    def test_draft_and_no_write(self):
        before = (self.d / "discovery/network.json").read_text()
        r = self.probe("10.0.20.11", "10.0.20.20", "--draft", "--no-write", "--user", "ops")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.d / "discovery/network.json").read_text(), before)
        self.assertIn('    el8:\n      hosts:\n        db01:  # Rocky Linux 8.10 (Green Obsidian)\n'
                      '          ansible_host: "10.0.20.11"\n          ansible_user: "ops"\n'
                      '          ansible_python_interpreter: "/usr/bin/python3.12"', r.stdout)
        self.assertIn("    proxmox_nodes:", r.stdout)
        data = json.loads(subprocess.run(["yq", "-o=json", "."], input=r.stdout, capture_output=True, text=True).stdout)
        self.assertEqual(sorted(data["all"]["children"]), ["el8", "proxmox_nodes"])

    def test_scope(self):
        r = self.probe("10.0.30.0/24")
        self.assertEqual(r.returncode, 4)
        self.assertIn("outside the authorized ranges", r.stderr)
        self.assertFalse(self.log.exists())

    def test_python_rules(self):
        sys.path.insert(0, str(SCRIPTS))
        import ssh_probe as p
        self.assertEqual(p.min_target_python((2, 16)), (3, 6))
        self.assertEqual(p.min_target_python((2, 17)), (3, 7))
        self.assertEqual(p.min_target_python((2, 21)), (3, 8))
        old = {"python_default": {"path": "/usr/bin/python3", "version": "3.6.8"},
               "pythons": [{"path": "/usr/bin/python3", "version": "3.6.8"}]}
        self.assertEqual(p.python_advice(old, (3, 8)), ("3.6.8 — too old, needs 3.8+", None))
        self.assertEqual(p.python_advice(old, (3, 6)), ("3.6.8 ok", None))
        self.assertEqual(p.suggest_group({"os_id": "almalinux", "os_version": "9.4"}), "el9")
        self.assertEqual(p.suggest_group({"kernel": "FreeBSD 14.1-RELEASE", "os_freebsd": "14.1",
                                          "product": "pfSense 2.7.2"}), "appliances")
        self.assertEqual(p.suggest_group({"kernel": "FreeBSD 14.1-RELEASE", "os_freebsd": "14.1"}), "freebsd")


FAKE_ROS_SSH = r'''#!/usr/bin/env python3
import json, os, sys
host, cmd = sys.argv[-2], sys.argv[-1]
with open(os.environ["FAKE_SSH_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
if host == "10.0.0.9":
    sys.stderr.write("auditor@10.0.0.9: Permission denied (publickey).\n"); sys.exit(255)
chr_ = host == "10.0.0.2"
out = {
 "/system identity print without-paging": "  name: " + ("core-chr" if chr_ else "sw-rack") + "\n",
 "/system resource print without-paging": (
   "                   uptime: 3w2d4h\n                  version: " + ("7.15.3" if chr_ else "7.16.1") + " (stable)\n"
   "              free-memory: 400.0MiB\n             total-memory: 512.0MiB\n"
   "           free-hdd-space: " + ("80.0MiB" if chr_ else "3.1MiB") + "\n          total-hdd-space: 128.0MiB\n"
   "        architecture-name: " + ("x86_64" if chr_ else "arm") + "\n"
   "               board-name: " + ("CHR QEMU Standard PC (i440FX + PIIX, 1996)" if chr_ else "CRS326-24G-2S+") + "\n"),
 "/system routerboard print without-paging": "       routerboard: yes\n             model: CRS326-24G-2S+\n"
   "  current-firmware: 7.12\n  upgrade-firmware: 7.16.1\n",
 "/system package update print without-paging": "          channel: stable\n  installed-version: "
   + ("7.15.3" if chr_ else "7.16.1") + "\n     latest-version: 7.16.1\n",
 "/system license print without-paging": ("  system-id: abc\n      level: free\n  next-renewal-at: 2026-12-01 10:00:00\n"
   if chr_ else "  software-id: XYZ\n  level: 5\n"),
 "/interface print terse without-paging": " 0  R name=ether1 default-name=ether1 type=ether mtu=1500\n"
   " 1 X  name=ether2 default-name=ether2 type=ether mtu=1500\n",
 "/ip address print terse without-paging": " 0   address=10.0.0.1/24 network=10.0.0.0 interface=bridge\n",
 "/interface bridge print terse without-paging": " 0  R name=bridge vlan-filtering=yes comment=\"syntax error here\"\n",
 "/interface bridge vlan print terse without-paging": " 0   bridge=bridge vlan-ids=20 tagged=bridge,sfp1\n",
 "/interface vlan print terse without-paging": "",
 "/ip service print terse without-paging": (
   " 0   name=telnet port=23 address=\"\" vrf=main\n 1 X name=ftp port=21 address=\"\"\n"
   " 2   name=www port=80 address=10.0.0.0/24\n 3   name=ssh port=22 address=\"\"\n"),
 "/user print terse without-paging": " 0   name=admin group=full\n 1   name=auditor group=read\n",
}
if cmd not in out or (chr_ and "routerboard" in cmd):
    print("bad command name routerboard (line 1 column 9)"); sys.exit(1)
sys.stdout.write(out[cmd])
'''


class RouterosAuditTests(unittest.TestCase):  # issue 26
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import routeros_audit
        self.ra = routeros_audit
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "ansible,appliances", cwd=self.d)
        inv = self.d / "ansible/inventory/managed"
        (inv / "hosts.yml").write_text("all:\n  children:\n    appliances:\n      children:\n        routeros:\n"
                                       "          hosts:\n            sw-rack:\n              ansible_host: 10.0.0.1\n"
                                       "            chr1:\n              ansible_host: 10.0.0.2\n")
        (inv / "group_vars/routeros.yml").write_text("ansible_user: auditor\n")
        (inv / "hosts.yml").write_text((inv / "hosts.yml").read_text() + "    linux:\n      hosts:\n"
                                       "        web1:\n          ansible_host: 10.0.0.5\n")
        bin_ = self.d / "bin"
        bin_.mkdir()
        (bin_ / "ssh").write_text(FAKE_ROS_SSH)
        (bin_ / "ssh").chmod(0o755)
        self.log = self.d / "ssh.log"
        self.env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "FAKE_SSH_LOG": str(self.log)}

    def audit(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "routeros_audit.py"), *args], cwd=self.d,
                              env=self.env, capture_output=True, text=True)

    def test_parsers(self):
        rows = self.ra.parse_terse(' 0 X name=ftp port=21 address=""\n 1   name=ssh comment="a b=c"\nFlags: X\n')
        self.assertEqual(rows, [{"name": "ftp", "port": "21", "address": "", "_flags": "X"},
                                {"name": "ssh", "comment": "a b=c", "_flags": ""}])
        self.assertEqual(self.ra.parse_detail("   board-name: CRS326\n  version: 7.16 (stable)\n"),
                         {"board-name": "CRS326", "version": "7.16 (stable)"})
        self.assertEqual(self.ra.size_bytes("3.1MiB"), 3.1 * 2**20)
        self.assertEqual(self.ra.size_bytes("1024KiB"), 2**20)
        self.assertEqual(self.ra.parse_date("dec/01/2026 10:00:00"), self.ra.dt.date(2026, 12, 1))
        self.assertEqual(self.ra.parse_date("2026-12-01 10:00:00"), self.ra.dt.date(2026, 12, 1))

    def test_group_audit(self):
        r = self.audit("--group", "routeros", "10.0.0.9")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(l) for l in self.log.read_text().splitlines()]
        for c in calls:
            self.assertIn("-T", c)                                                   # no pty: raw-style hang
            self.assertIn("BatchMode=yes", c)
            if c[-2] != "10.0.0.9":
                self.assertEqual(c[c.index("-l") + 1], "auditor")                     # from group_vars/routeros.yml
            else:
                self.assertNotIn("-l", c)                                             # given directly: ssh config
            self.assertRegex(c[-1], r"^/[a-z /-]+ print( terse)? without-paging$")    # read-only
        self.assertFalse(any(c[-2] == "10.0.0.2" and "routerboard" in c[-1] for c in calls))  # skipped on CHR
        out = r.stdout
        self.assertIn("| 10.0.0.1 | sw-rack | CRS326-24G-2S+ | 7.16.1 (stable) | 7.12 | 3.1MiB |", out)
        self.assertIn("| 10.0.0.2 | core-chr | CHR QEMU", out)
        self.assertIn("**Version drift:** 7.15.3: 10.0.0.2; 7.16.1: 10.0.0.1", out)
        sw = out[out.index("## 10.0.0.1"):out.index("## 10.0.0.2")]
        self.assertIn("**high** — plain-text service `telnet` enabled (port 23, from any address): disable it and use ssh", sw)
        self.assertIn("**low** — plain-text service `www` enabled (port 80, limited to 10.0.0.0/24): disable it and use www-ssl\n", sw)
        self.assertNotIn("`ftp`", sw)                                                 # disabled (X flag)
        self.assertIn("RouterBOOT firmware 7.12 is behind 7.16.1", sw)
        self.assertIn("low free flash: 3.1MiB of 128.0MiB", sw)
        self.assertIn("default user `admin` is enabled", sw)
        chr_ = out[out.index("## 10.0.0.2"):]
        self.assertIn("RouterOS 7.16.1 available on channel stable (installed 7.15.3", chr_)
        self.assertIn("CHR licence level `free`", chr_)
        self.assertNotIn("routerboard", chr_)
        self.assertIn("## 10.0.0.9\n- **high** — not inspected: auth failed", out)
        db = json.loads((self.d / "discovery/routeros.json").read_text())["devices"]
        self.assertEqual(sorted(db), ["10.0.0.1", "10.0.0.2", "10.0.0.9"])
        self.assertEqual(db["10.0.0.1"]["bridges"][0]["vlan-filtering"], "yes")      # comment didn't look like an error
        self.assertEqual(db["10.0.0.1"]["bridge_vlans"][0]["tagged"], "bridge,sfp1")

    def test_licence_renewal_soon(self):
        dev = {"reachable": True, "errors": {}, "resource": {"board-name": "CHR"},
               "license": {"level": "p1", "next-renewal-at": "2026-12-01 10:00:00"}}
        f = self.ra.findings(dev, self.ra.dt.date(2026, 11, 17))
        self.assertIn("medium", [s for s, _ in f])
        self.assertEqual(self.ra.findings(dev, self.ra.dt.date(2026, 6, 1)), [])

    def test_templated_user_is_not_passed(self):
        sys.path.insert(0, str(SCRIPTS))
        self.assertEqual(self.ra.group_hosts(self.d, "linux"), [("10.0.0.5", None, None)])  # all.yml's {{ … }}

    def test_all_unreachable(self):
        r = self.audit("10.0.0.9", "--no-write")
        self.assertEqual(r.returncode, 2)
        self.assertFalse((self.d / "discovery/routeros.json").exists())
