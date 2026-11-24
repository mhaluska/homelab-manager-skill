"""Release consistency and the release tooling in .github/ (release_notes.py, template_history.py, release.py).

    python3 -m unittest discover -s tests -v
"""
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"


def load(name):
    spec = importlib.util.spec_from_file_location(f"hm_{name}", GITHUB / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def vtuple(v):
    return tuple(int(x) for x in v.split("."))


class ConsistencyTests(unittest.TestCase):
    def test_changelog_top_section_is_the_plugin_version(self):
        have = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["version"]
        top = re.search(r"^## (\S+)", (ROOT / "CHANGELOG.md").read_text(), re.M).group(1)
        self.assertEqual(top, have, "bump plugin.json and the CHANGELOG together")

    def test_changelog_versions_descend(self):
        versions = re.findall(r"^## (\d+\.\d+\.\d+)\b", (ROOT / "CHANGELOG.md").read_text(), re.M)
        self.assertEqual(versions, sorted(versions, key=vtuple, reverse=True))
        self.assertEqual(len(versions), len(set(versions)))

    def test_marketplace_names_the_plugin(self):
        market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
        plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
        self.assertIn(plugin["name"], [p["name"] for p in market["plugins"]])


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.m = load("release_notes")

    def test_section(self):
        cl = "# Changelog\n\n## 0.2.0 — x\n- new\n\n## 0.1.0 — y\n- old\n"
        self.assertEqual(self.m.section(cl, "0.2.0"), "- new")
        self.assertEqual(self.m.section(cl, "0.1.0"), "- old")
        with self.assertRaises(SystemExit):
            self.m.section(cl, "0.3.0")
        with self.assertRaises(SystemExit):
            self.m.section("## 0.2.0 — x\n\n## 0.1.0\n- old\n", "0.2.0")   # empty section
        with self.assertRaises(SystemExit):
            self.m.section(cl, "0.1")   # 0.1 is not 0.1.0

    def test_cli(self):
        have = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["version"]
        r = subprocess.run([sys.executable, str(GITHUB / "release_notes.py"), f"v{have}", "--check-version"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("/plugin install homelab-manager@homelab-manager-skill", r.stdout)
        r = subprocess.run([sys.executable, str(GITHUB / "release_notes.py"), "v0.1.0", "--check-version"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("!= tag", r.stderr)
        r = subprocess.run([sys.executable, str(GITHUB / "release_notes.py"), "latest"], capture_output=True, text=True)
        self.assertIn("not a release tag", r.stderr)


class FakeRepo:
    """A temporary Git repository with the layout the release tools expect."""

    def __init__(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / ".github").mkdir()
        for f in ("template_history.py", "release.py", "release_notes.py"):
            shutil.copy(GITHUB / f, self.d / ".github" / f)
        (self.d / ".claude-plugin").mkdir()
        self.tpl = self.d / "skills/homelab-manager/assets/repo-template"
        self.tpl.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "CI")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.d, capture_output=True, text=True, check=True).stdout

    def version(self, v):
        (self.d / ".claude-plugin/plugin.json").write_text(json.dumps({"name": "x", "version": v}, indent=2) + "\n")

    def release(self, v, files):
        self.version(v)
        for rel, text in files.items():
            (self.tpl / rel).write_text(text)
        self.git("add", "-A")
        self.git("commit", "-qm", f"Release {v}")
        self.git("tag", "-a", f"v{v}", "-m", v)

    def run(self, script, *args):
        return subprocess.run([sys.executable, str(self.d / ".github" / script), *args], cwd=self.d,
                              capture_output=True, text=True)

    def cleanup(self):
        shutil.rmtree(self.d)


class TemplateHistoryToolTests(unittest.TestCase):
    def setUp(self):
        self.r = FakeRepo()
        self.addCleanup(self.r.cleanup)

    def test_build_spans_and_check(self):
        r = self.r
        r.release("0.1.0", {"a.txt": "one\n", "b.txt": "b\n"})
        r.release("0.2.0", {"a.txt": "one\n"})
        r.release("0.3.0", {"a.txt": "two\n"})
        self.assertEqual(r.run("template_history.py", "--check").returncode, 1)   # no file yet
        self.assertEqual(r.run("template_history.py").returncode, 0)
        hist = json.loads((r.d / "skills/homelab-manager/assets/template-history.json").read_text())["files"]
        spans = {h: span for h, span in hist["a.txt"].items()}
        self.assertEqual(sorted(spans.values()), [["0.1.0", "0.2.0"], ["0.3.0", "0.3.0"]])
        self.assertEqual(list(hist["b.txt"].values()), [["0.1.0", "0.3.0"]])
        self.assertEqual(r.run("template_history.py", "--check").returncode, 0)
        (r.tpl / "a.txt").write_text("three\n")   # a template edit after the last release
        self.assertEqual(r.run("template_history.py", "--check").returncode, 1)


class ReleaseScriptTests(unittest.TestCase):
    CL = "# Changelog\n\n## Unreleased\n- a change\n\n## 0.1.0 — 2026-01-01\n- first\n"

    def setUp(self):
        self.r = FakeRepo()
        self.addCleanup(self.r.cleanup)
        (self.r.d / "CHANGELOG.md").write_text(self.CL)
        self.r.release("0.1.0", {"a.txt": "one\n"})
        self.r.run("template_history.py")
        self.r.git("add", "-A")
        self.r.git("commit", "-qm", "history")

    def test_release_bumps_commits_and_tags(self):
        r = self.r
        (r.tpl / "a.txt").write_text("two\n")
        r.git("commit", "-qam", "Template change")
        out = r.run("release.py", "0.2.0", "--no-tests")
        self.assertEqual(out.returncode, 0, out.stderr + out.stdout)
        self.assertIn("git push origin main v0.2.0", out.stdout)
        self.assertEqual(json.loads((r.d / ".claude-plugin/plugin.json").read_text())["version"], "0.2.0")
        self.assertRegex((r.d / "CHANGELOG.md").read_text(), r"\n## 0\.2\.0 — \d{4}-\d{2}-\d{2}\n- a change\n")
        self.assertEqual(r.git("log", "-1", "--format=%s").strip(), "Release 0.2.0")
        self.assertEqual(r.git("cat-file", "-t", "v0.2.0").strip(), "tag")   # annotated
        self.assertEqual(r.git("status", "--porcelain").strip(), "")
        self.assertEqual(r.run("template_history.py", "--check").returncode, 0)   # regenerated for the change
        self.assertIn("0.2.0", (r.d / "skills/homelab-manager/assets/template-history.json").read_text())

    def test_refusals(self):
        r = self.r
        for args, why in [(["0.1.0"], "newer"), (["0.2"], "X.Y.Z"), (["0.0.9"], "newer")]:
            out = r.run("release.py", *args, "--no-tests")
            self.assertNotEqual(out.returncode, 0, args)
            self.assertIn(why, out.stderr, args)
        (r.d / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n## 0.1.0 — x\n- first\n")
        out = r.run("release.py", "0.2.0", "--no-tests")
        self.assertIn("uncommitted", out.stderr)            # tracked file changed
        r.git("commit", "-qam", "empty section")
        out = r.run("release.py", "0.2.0", "--no-tests")
        self.assertIn("empty", out.stderr)
        self.assertEqual(json.loads((r.d / ".claude-plugin/plugin.json").read_text())["version"], "0.1.0")
        self.assertEqual(r.git("tag", "--list", "v0.2.0").strip(), "")


if __name__ == "__main__":
    unittest.main()
