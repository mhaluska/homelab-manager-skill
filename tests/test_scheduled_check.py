"""Tests for scheduled_check.py: the scheduled read-only check run by launchd (GitHub issue #150)."""
import contextlib
import io
import json
import os
import plistlib
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import SCRIPTS, run  # noqa: E402

sys.path.insert(0, str(SCRIPTS))
import init_repo  # noqa: E402
import scheduled_check as sc  # noqa: E402


class ScheduledCheckTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.repo = self.d / "repo"
        self.repo.mkdir()
        run("init_repo.py", str(self.repo), "--components", "proxmox,ansible,discovery", cwd=self.repo)
        for name, sub in (("AGENTS", "agents"), ("LOGS", "logs"), ("STATE", "state")):
            p = unittest.mock.patch.object(sc, name, self.d / sub)
            p.start()
            self.addCleanup(p.stop)
        self.calls, self.notes = [], []
        for name, fake in (("launchctl", self.fake_launchctl), ("notify", lambda t, title: self.notes.append((title, t)))):
            p = unittest.mock.patch.object(sc, name, fake)
            p.start()
            self.addCleanup(p.stop)

    def fake_launchctl(self, *args):
        self.calls.append(args)
        return unittest.mock.Mock(returncode=0, stdout="", stderr="")

    def test_plist(self):
        pl = sc.plist(self.repo, 7, 5)
        self.assertEqual(pl["ProgramArguments"], ["/usr/bin/python3", str(sc.SCRIPT), "run"])
        self.assertEqual(pl["StartCalendarInterval"], {"Hour": 7, "Minute": 5})
        self.assertEqual(pl["WorkingDirectory"], str(self.repo.resolve()))
        self.assertIn("/opt/homebrew/bin", pl["EnvironmentVariables"]["PATH"])
        self.assertEqual(sc.parse_time("7:40"), (7, 40))
        for bad in ("24:00", "7", "07:60", "x"):
            with self.assertRaises(ValueError):
                sc.parse_time(bad)

    def test_install_status_uninstall(self):
        cwd = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, cwd)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(sc.main(["status"]), 0)
        self.assertIn("Not installed", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sc.main(["install", "--time", "06:15"]), 0)
        p = sc.plist_path(self.repo)
        self.assertEqual(plistlib.loads(p.read_bytes())["StartCalendarInterval"], {"Hour": 6, "Minute": 15})
        self.assertIn("bootstrap", [c[0] for c in self.calls])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            sc.main(["status"])
        self.assertIn("every day at 06:15", out.getvalue())
        self.assertNotIn("not this plugin version", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sc.main(["uninstall"]), 0)
        self.assertFalse(p.exists())

    def test_sync_managed_repoints_an_older_plugin_version(self):
        old = Path("/old/plugin/0.60.0/skills/homelab-manager/scripts/scheduled_check.py")
        sc.write_plist(self.repo, sc.plist(self.repo, 5, 30, old))
        self.assertTrue(sc.outdated(self.repo))
        found = [(text, fn) for text, fn in init_repo.upgrades(self.repo) if "scheduled check" in text]
        self.assertEqual(len(found), 1)
        found[0][1]()
        pl = plistlib.loads(sc.plist_path(self.repo).read_bytes())
        self.assertEqual(pl["ProgramArguments"][1], str(sc.SCRIPT))
        self.assertEqual(pl["StartCalendarInterval"], {"Hour": 5, "Minute": 30})   # the user's time stays
        self.assertFalse(sc.outdated(self.repo))
        self.assertFalse([t for t, _ in init_repo.upgrades(self.repo) if "scheduled check" in t])

    def test_glance_warnings(self):
        text = "# x\n\n## At a glance\n\n1 site.\nWarnings (details under [Health](#health)): 2 ZFS pools · 1 disk · 5 expiries (see [Expirations](#expirations)).\n"
        self.assertEqual(sc.glance_warnings(text), ["2 ZFS pools", "1 disk", "5 expiries (see Expirations)"])
        self.assertEqual(sc.glance_warnings("# x\n"), [])

    def test_run_notifies_new_warnings_once_and_steps_that_could_not_run(self):
        with unittest.mock.patch.object(sc, "run_steps", return_value=(["2 ZFS pools"], [])), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sc.cmd_run(self.repo), 1)
            self.assertEqual(sc.cmd_run(self.repo), 1)   # the same warnings: no second notification
        self.assertEqual(len(self.notes), 1)
        self.assertIn("2 ZFS pools", self.notes[0][1])
        state = json.loads(sc.state_file(self.repo).read_text())
        self.assertEqual(state["warnings"], ["2 ZFS pools"])
        with unittest.mock.patch.object(sc, "keychain_unlocked", return_value=False), \
                unittest.mock.patch.object(sc.hmlib, "proxmox_sites", return_value=[{"_site": ""}]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sc.cmd_run(self.repo), 4)
        self.assertIn("keychain is locked", self.notes[-1][1])
        self.assertIn("could not run", self.notes[-1][0])

    def test_run_without_proxmox_renders_in_memory_only(self):
        before = sorted(p.relative_to(self.repo) for p in self.repo.rglob("*"))
        with contextlib.redirect_stdout(io.StringIO()):
            rc = sc.cmd_run(self.repo)
        self.assertIn(rc, (0, 1))
        self.assertEqual(sorted(p.relative_to(self.repo) for p in self.repo.rglob("*")), before)   # nothing written


if __name__ == "__main__":
    unittest.main()
