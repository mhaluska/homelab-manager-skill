"""Tests for the English check (hmlib.english_problems) used for skill issues, gh issue writes and pull requests.

Non-English samples below carry a `lang: allow` marker so the pull-request language check skips them.
"""
import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "homelab-manager" / "scripts"))
sys.path.insert(0, str(ROOT / ".github"))
import check_english  # noqa: E402
import hmlib  # noqa: E402

ENGLISH = [
    "drift_report.py crashes without backup_jobs",
    "Support OPNsense backups",
    "The guard blocks `gh issue list` — it should only ask for writes → fix the regex.",
    "When the Proxmox API returns 500 for a stopped LXC, proxmox_inventory.py crashes with KeyError "
    "instead of skipping the guest.",
    "### Summary\nnmap_scan.py prints the wrong OS for routed hosts when a banner is present.\n\n"
    "### Evidence\n```\nChyba: súbor neexistuje\n```",  # lang: allow (localized tool output in a code block)
    "Redacted <host-1> and <ip-2> in the body; see https://example.com/é for details.",
]
FOREIGN = [
    "Skript padá, keď chýba backup_jobs",  # lang: allow
    "Skript drift report pada ked chyba backup jobs v konfiguracii, treba to opravit",  # lang: allow
    "Der Scan bricht ab wenn das Netz nicht erreichbar ist und ich weiss nicht warum",  # lang: allow
    "Сканирование не работает",  # lang: allow
    "Le script ne marche pas pour les hôtes dans le réseau",  # lang: allow
]


class EnglishCheckTests(unittest.TestCase):
    def test_english_passes(self):
        for text in ENGLISH:
            with self.subTest(text=text[:40]):
                self.assertEqual(hmlib.english_problems(text), [])

    def test_other_languages_fail(self):
        for text in FOREIGN:
            with self.subTest(text=text[:40]):
                self.assertTrue(hmlib.english_problems(text))

    def test_names_the_offending_words(self):
        problems = hmlib.english_problems("Skript padá, keď chýba backup_jobs")  # lang: allow
        self.assertIn("padá", problems[0])  # lang: allow

    def test_typography_is_not_a_letter(self):
        self.assertEqual(hmlib.non_english_letters("a → b — c … “d”"), [])

    def test_short_identifier_only_text_is_not_judged(self):
        self.assertEqual(hmlib.english_problems("x"), [])
        self.assertEqual(hmlib.english_problems("SKILL-002 nmap_scan.py --profile os"), [])

    def test_long_text_without_english_words_fails(self):
        text = " ".join(["Proxmox"] * 6 + ["cluster"] * 6 + ["kaput"] * 3)
        self.assertTrue(hmlib.english_problems(text))


class PullRequestCheckTests(unittest.TestCase):
    """.github/check_english.py diff: added lines and commit messages of a pull request."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.git("init", "-q", "-b", "main")
        (self.d / "a.py").write_text("x = 1\n")
        self.commit("Initial commit")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self):
        shutil.rmtree(self.d)

    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.d, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, msg):
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", msg)

    def check(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = check_english.cmd_diff(self.base, "HEAD", self.d)
        return code, out.getvalue()

    def test_english_change_passes(self):
        (self.d / "a.py").write_text("x = 1\n# Count the hosts that answered.\nfor k, v in d.items():\n    pass\n")
        self.commit("Count answering hosts")
        self.assertEqual(self.check()[0], 0)

    def test_non_english_comment_is_annotated(self):
        (self.d / "a.py").write_text("x = 1\n# Spočítaj hosty, ktoré odpovedali.\n")  # lang: allow
        self.commit("Count answering hosts")
        code, out = self.check()
        self.assertEqual(code, 1)
        self.assertIn("::error file=a.py,line=2::", out)

    def test_non_english_commit_message_fails(self):
        (self.d / "a.py").write_text("x = 2\n")
        self.commit("Oprava: skript pada ked chyba konfiguracia a nie je jasne preco")  # lang: allow
        code, out = self.check()
        self.assertEqual(code, 1)
        self.assertIn("message is not English", out)

    def test_marker_and_allowlist_skip(self):
        (self.d / ".github").mkdir()
        (self.d / ".github" / "language-allowlist").write_text("# names\nNOTICE\n")
        (self.d / "NOTICE").write_text("Copyright Ján Novák\n")  # lang: allow
        (self.d / "a.py").write_text('x = 1\nSAMPLE = "Skript padá"  # lang: allow\n')  # lang: allow
        self.commit("Add a notice and a sample")
        self.assertEqual(self.check()[0], 0)

    def test_text_mode_ignores_generated_environment(self):
        body = "Guard blocks gh issue list\n\n### Summary\nIt asks.\n\n### Environment\n- Python 3.15\n- jazyk: slovenčina\n"  # lang: allow
        self.assertEqual(hmlib.english_problems(check_english.strip_generated(body)), [])


if __name__ == "__main__":
    unittest.main()
