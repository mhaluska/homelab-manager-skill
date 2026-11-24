"""Shared helpers for the script tests."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "homelab-manager" / "scripts"


def run(script, *args, cwd):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], cwd=cwd, capture_output=True, text=True)


def yq(expr, path):
    return subprocess.run(["yq", "-o=json", expr, str(path)], capture_output=True, text=True).stdout.strip()


def closed_http_error(url, code, msg, hdrs, fp):
    """An HTTPError as PVE._get raises it: closed already (an open one warns when it is garbage-collected)."""
    import urllib.error
    e = urllib.error.HTTPError(url, code, msg, hdrs, fp)
    e.close()
    return e
