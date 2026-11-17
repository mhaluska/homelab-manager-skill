"""Tests for the English check (hmlib.english_problems) used for skill issues, gh issue writes and pull requests.

Non-English samples below carry a `lang: allow` marker so the pull-request language check skips them.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "homelab-manager" / "scripts"))
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


if __name__ == "__main__":
    unittest.main()
