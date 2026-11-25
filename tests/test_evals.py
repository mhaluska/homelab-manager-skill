"""The eval cases' fixtures: each place-files.sh builds a repository on the current template."""
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import ROOT, SCRIPTS  # noqa: E402

EVALS = ROOT / "skills" / "homelab-manager" / "evals"
TEMPLATE = ROOT / "skills" / "homelab-manager" / "assets" / "repo-template"


class EvalFixtureTests(unittest.TestCase):
    def cases(self):
        return sorted(p for p in EVALS.iterdir() if (p / "case.yaml").is_file())

    def test_cases_have_their_parts(self):
        for case in self.cases():
            self.assertTrue((case / "prompt.md").is_file(), case.name)
            self.assertTrue(list((case / "graders").glob("*.md")), case.name)
            m = re.search(r"scaffold_script:\s*(\S+)", (case / "case.yaml").read_text())
            if m:
                self.assertTrue((case / m.group(1)).is_file(), case.name)

    def test_no_template_copies_in_fixtures(self):
        """files/ holds only what the case needs; the template comes from init_repo.py in place-files.sh."""
        for case in self.cases():
            if "init_repo.py" not in (case / "place-files.sh").read_text():
                continue   # an old repository on purpose (upgrade-old-repo) or an empty one (the init cases)
            for p in (case / "files").rglob("*") if (case / "files").is_dir() else []:
                rel = p.relative_to(case / "files")
                if p.is_file() and (TEMPLATE / rel).is_file():
                    self.assertNotEqual(p.read_bytes(), (TEMPLATE / rel).read_bytes(), f"{case.name}: {rel}")

    def test_place_files_gives_an_up_to_date_repo(self):
        for case in self.cases():
            if "init_repo.py" not in (case / "place-files.sh").read_text():
                continue   # the init cases start from an empty directory
            with self.subTest(case=case.name):
                d = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, d)
                r = subprocess.run(["bash", str(case / "place-files.sh")], cwd=d, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                r = subprocess.run([sys.executable, str(SCRIPTS / "init_repo.py"), "--sync-managed", "--dry-run"],
                                   cwd=d, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("Up to date with the plugin", r.stdout)


if __name__ == "__main__":
    unittest.main()
