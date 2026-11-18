#!/usr/bin/env python3
"""Status of a Proxmox guest, and starting one that is stopped (VMs and LXC containers).

    pve_guest.py status <guest…> [--json]        # read-only token
    pve_guest.py start <guest…> [--timeout 120]   # provisioning token (HomelabProvisioner: VM.PowerMgmt)

<guest> is a VMID or a guest name from the cluster. `start` only starts guests that are stopped (a running one
is left alone), waits for the Proxmox task and until the guest reports running, and prints the final status.
patch-linux.yml uses it when an LXC guest it rebooted comes back stopped instead of running (GitHub issue #59).
--site NAME: a guest of another site's Proxmox (sites: in homelab.yaml), with that site's tokens.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
from proxmox_inventory import PVE  # noqa: E402
from pve_snapshot import base, find_guests, label, wait  # noqa: E402


def status(pve: PVE, g: dict) -> str:
    """running / stopped / paused …, as Proxmox reports it now."""
    return str((pve.get(base(g) + "/status/current") or {}).get("status") or "unknown")


def start(pve: PVE, g: dict, timeout: int = 120, sleep=time.sleep) -> str:
    """Start a stopped guest and wait until it reports running; returns the final status."""
    st = status(pve, g)
    if st != "stopped":
        return st
    upid = pve.write("POST", base(g) + "/status/start")
    if upid:
        wait(pve, g["node"], upid, f"start {label(g)}")
    deadline = time.monotonic() + timeout
    while True:
        st = status(pve, g)
        if st == "running" or time.monotonic() >= deadline:
            return st
        sleep(2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["status", "start"])
    ap.add_argument("guests", nargs="+")
    ap.add_argument("--json", action="store_true", help="status: print {guest: status} as JSON")
    ap.add_argument("--timeout", type=int, default=120, help="start: seconds to wait for running (default 120)")
    ap.add_argument("--site", help="the site whose Proxmox holds the guests (default: the default site)")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        px = hmlib.proxmox_site(cfg, a.site)
        secret = hmlib.proxmox_token_name(px, "read_only" if a.action == "status" else "provisioning")
        pve = PVE(px["endpoint"], hmlib.read_secret(cfg, secret), hmlib.proxmox_ssl_context(cfg, px))
    except hmlib.ConfigError as e:
        print(f"pve_guest: {e}", file=sys.stderr)
        return 3
    guests = find_guests(pve, a.guests)
    if a.action == "status":
        res = {w: status(pve, g) for w, g in zip(a.guests, guests)}
        print(json.dumps(res, indent=2) if a.json else "\n".join(f"{w}: {s}" for w, s in res.items()))
        return 0
    rc = 0
    for g in guests:
        before = status(pve, g)
        st = start(pve, g, a.timeout)
        print(f"{label(g)}: {'started, ' if before == 'stopped' else ''}{st}")
        rc |= st != "running"
    return rc


if __name__ == "__main__":
    sys.exit(main())
