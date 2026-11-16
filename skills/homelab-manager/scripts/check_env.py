#!/usr/bin/env python3
"""Check that this Mac is ready to manage the homelab.

    check_env.py              tools + SSH agent + config + configured keychain items
    check_env.py --keychain   also run a keychain self-test (write, read, delete a dummy item)
    check_env.py --json       machine-readable output

Never prints secret values — only whether each item exists and is readable without
a GUI prompt (which on a headless Mac would hang forever).
"""
from __future__ import annotations

import json
import os
import re
import secrets as pysecrets
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

TOOLS = {
    "tofu": (["tofu", "version"], "brew install opentofu"),
    "packer": (["packer", "version"], "brew tap hashicorp/tap && brew install hashicorp/tap/packer"),
    "ansible": (["ansible", "--version"], "brew install ansible"),
    "nmap": (["nmap", "--version"], "brew install nmap"),
    "yq": (["yq", "--version"], "brew install yq"),
    "jq": (["jq", "--version"], "brew install jq"),
    "git": (["git", "--version"], "xcode-select --install"),
    "gh": (["gh", "--version"], "brew install gh   (only needed to report GitHub issues)"),
}
SELFTEST_SERVICE = "homelab/_selftest"


def run(cmd, timeout=15, input_text=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


def check_tools():
    out = []
    for name, (cmd, install) in TOOLS.items():
        if not shutil.which(cmd[0]):
            out.append({"check": f"tool:{name}", "ok": False, "detail": f"missing — {install}"})
            continue
        _, so, se = run(cmd)
        first = (so or se).strip().splitlines()[0] if (so or se).strip() else "?"
        out.append({"check": f"tool:{name}", "ok": True, "detail": first})
    return out


def check_ssh_agent():
    if not os.environ.get("SSH_AUTH_SOCK"):
        return [{"check": "ssh-agent", "ok": False, "detail": "SSH_AUTH_SOCK not set — no agent in this session"}]
    rc, so, _ = run(["ssh-add", "-l"])
    if rc == 0:
        keys = [l.split()[-1] if l.strip() else "" for l in so.strip().splitlines()]
        return [{"check": "ssh-agent", "ok": True, "detail": f"{len(keys)} key(s) loaded: {', '.join(keys)}"}]
    return [{"check": "ssh-agent", "ok": False, "detail": "agent running but no keys loaded (ssh-add --apple-use-keychain ~/.ssh/<key>)"}]


def check_gh():
    if not shutil.which("gh"):
        return []
    rc, so, se = run(["gh", "auth", "status"], timeout=20)
    logged = [l for l in (so + se).splitlines() if "Logged in to" in l]
    if logged:
        return [{"check": "gh:auth", "ok": True,
                 "detail": "; ".join(l.strip().lstrip("✓ ").split(" (")[0] for l in logged)}]
    return [{"check": "gh:auth", "ok": False, "detail": "not logged in — run: gh auth login (stores the token in the keychain)"}]


def check_keychain_unlocked():
    rc, so, se = run(["/usr/bin/security", "show-keychain-info"], timeout=10)
    if rc == 0:
        return [{"check": "keychain:login", "ok": True, "detail": "default keychain unlocked (" + ((so + se).strip().split()[-1] if (so + se).strip() else "?") + ")"}]
    return [{"check": "keychain:login", "ok": False,
             "detail": f"default keychain not usable ({(se or so).strip() or rc}). With auto-login it should be unlocked; "
                       "if the Mac was rebooted to the login window, log in once on the console or via Screen Sharing."}]


def check_keychain_selftest():
    """Write, read back and delete a random dummy item. Proves non-interactive access works."""
    token = pysecrets.token_hex(16)
    user = os.environ.get("USER", "")
    rc, _, se = run(["/usr/bin/security", "add-generic-password", "-U", "-T", "/usr/bin/security",
                     "-a", user, "-s", SELFTEST_SERVICE, "-w", token], timeout=15)
    if rc != 0:
        return [{"check": "keychain:selftest", "ok": False, "detail": f"cannot write test item ({se.strip() or rc})"}]
    try:
        value = hmlib.keychain_read(SELFTEST_SERVICE, user, timeout=15)
        ok = value == token
        detail = "write → read → delete OK, no GUI prompt" if ok else "read back a different value"
    except hmlib.ConfigError as e:
        ok, detail = False, str(e)
    run(["/usr/bin/security", "delete-generic-password", "-a", user, "-s", SELFTEST_SERVICE], timeout=15)
    return [{"check": "keychain:selftest", "ok": ok, "detail": detail}]


def check_config_and_secrets():
    root = hmlib.find_repo_root()
    if not root:
        return [{"check": "config", "ok": None, "detail": "not inside a homelab-infrastructure repo (no homelab.yaml)"}], None
    try:
        cfg = hmlib.load_config(root)
    except hmlib.ConfigError as e:
        return [{"check": "config", "ok": False, "detail": str(e)}], None
    out = [{"check": "config", "ok": True, "detail": str(root / hmlib.CONFIG_NAME)}]
    for name, entry in (cfg.get("secrets") or {}).items():
        if not isinstance(entry, dict) or not entry.get("service"):
            continue
        if entry.get("kind") == "s3_credentials" and hmlib.get(cfg, "opentofu.state_backend", "local") != "s3":
            continue  # only needed for the S3 state backend
        service, account = entry["service"], entry.get("account") or os.environ.get("USER")
        rc, _, _ = run(["/usr/bin/security", "find-generic-password", "-a", account, "-s", service], timeout=10)
        if rc != 0:
            out.append({"check": f"secret:{name}", "ok": False,
                        "detail": f"missing — create with: security add-generic-password -U -T /usr/bin/security -a \"$USER\" -s {service} -w"})
            continue
        try:
            v = hmlib.keychain_read(service, account, timeout=15)
            fmt_ok = True
            want = {"proxmox_token": (r"^[^@\s]+@[^!\s]+![^=\s]+=\S+$", "user@realm!tokenid=secret"),
                    "s3_credentials": (r"^[^:\s]+:\S+$", "ACCESS_KEY_ID:SECRET_ACCESS_KEY")}.get(entry.get("kind"))
            if want:
                fmt_ok = bool(re.match(want[0], v))
            out.append({"check": f"secret:{name}", "ok": bool(v) and fmt_ok,
                        "detail": ("readable" if fmt_ok else f"readable but not in {want[1]} format")
                        + f" ({len(v)} chars)"})
        except hmlib.ConfigError as e:
            out.append({"check": f"secret:{name}", "ok": False, "detail": str(e)})
    return out, cfg


def main(argv):
    results = check_tools() + check_ssh_agent() + check_gh() + check_keychain_unlocked()
    if "--keychain" in argv:
        results += check_keychain_selftest()
    cfg_results, _ = check_config_and_secrets()
    results += cfg_results
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            mark = {True: "OK  ", False: "FAIL", None: "--  "}[r["ok"]]
            print(f"[{mark}] {r['check']:<22} {r['detail']}")
    return 1 if any(r["ok"] is False for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
