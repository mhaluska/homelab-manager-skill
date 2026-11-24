"""Tests for shared helpers in hmlib.py: atomic writes and locks."""
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import SCRIPTS  # noqa: E402

sys.path.insert(0, str(SCRIPTS))
import hmlib  # noqa: E402


class AtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)

    def test_replaces_content_and_keeps_mode(self):
        f = self.d / "homelab.yaml"
        f.write_text("old\n")
        f.chmod(0o600)
        hmlib.atomic_write(f, "new\n")
        self.assertEqual(f.read_text(), "new\n")
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), ["homelab.yaml"])   # no temporary file left

    def test_failed_write_leaves_the_old_file(self):
        f = self.d / "network.json"
        f.write_text('{"sites": {}}\n')
        with unittest.mock.patch.object(hmlib.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                hmlib.atomic_write(f, '{"sites": {"a": 1}}\n')
        self.assertEqual(f.read_text(), '{"sites": {}}\n')
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), ["network.json"])
        with self.assertRaises(TypeError):   # an error while writing: same
            hmlib.atomic_write(f, None)
        self.assertEqual(f.read_text(), '{"sites": {}}\n')

    def test_concurrent_site_writes_keep_both(self):
        f = self.d / "discovery" / "network.json"
        sites = [{"name": f"s{i}", "default": False} for i in range(8)]
        orig = hmlib.site_parts

        def slow_parts(*a, **kw):   # widen the read-modify-write window
            parts = orig(*a, **kw)
            threading.Event().wait(0.02)
            return parts
        with unittest.mock.patch.object(hmlib, "site_parts", slow_parts):
            threads = [threading.Thread(target=hmlib.write_site_part, args=(f, st, {"n": i}))
                       for i, st in enumerate(sites)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(sorted(json.loads(f.read_text())["sites"]), sorted(hmlib.site_key(s) for s in sites))

    def test_scripts_write_repository_files_atomically(self):
        allowed = {("check_env.py", "f.write_text(ssl.DER_cert_to_PEM_cert(der))"),   # a new CA file in a temp dir
                   ("init_repo.py", "(target / rel).write_text(files[rel])"),        # new files of the scaffold
                   ("init_repo.py", "(target / rel).write_text(body)")}
        found = {(p.name, m.group(0).strip()) for p in SCRIPTS.glob("*.py")
                 for m in re.finditer(r"^.*\.write_text\(.*$", p.read_text(), re.M)}
        self.assertEqual(found - allowed, set(), "use hmlib.atomic_write for files in the user's repository")


if __name__ == "__main__":
    unittest.main()
