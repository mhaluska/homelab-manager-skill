#!/usr/bin/env python3
"""Status of a Proxmox guest, starting one that is stopped and shutting one down (VMs and LXC containers).

    pve_guest.py status <guest…> [--json]           # read-only token
    pve_guest.py start <guest…> [--timeout 120]      # provisioning token (HomelabProvisioner: VM.PowerMgmt)
    pve_guest.py shutdown <guest…> [--timeout 180]   # provisioning token; the guard asks
    pve_guest.py stop <guest…>                       # provisioning token; the guard asks

<guest> is a VMID or a guest name from the cluster. `start` only starts guests that are stopped (a running one
is left alone), waits for the Proxmox task and until the guest reports running, and prints the final status.
patch-linux.yml uses it when an LXC guest it rebooted comes back stopped instead of running (GitHub issue #59).
`shutdown` asks a running guest to shut down cleanly (ACPI or the QEMU guest agent for a VM, the container's init
for LXC) and waits up to --timeout seconds; a guest still running then is left running and reported (exit 1),
never forced. `stop` is the hard way, like pulling the power: only when a shutdown did not work, with the user's
yes. A guest that is already stopped is left alone (GitHub issue #155).
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


def _wait_stopped(pve: PVE, g: dict, upid, what: str, sleep=time.sleep) -> str | None:
    """Wait for a shutdown/stop task; the Proxmox error when it failed (e.g. the shutdown timed out), else None."""
    if not upid:
        return None
    try:
        wait(pve, g["node"], upid, what, sleep=sleep)
    except SystemExit as e:
        return str(e)
    return None


def shutdown(pve: PVE, g: dict, timeout: int = 180, sleep=time.sleep) -> tuple[str, str | None]:
    """Shut a running guest down cleanly within timeout seconds, never forced: (final status, error or None)."""
    st = status(pve, g)
    if st == "stopped":
        return st, None
    upid = pve.write("POST", base(g) + "/status/shutdown", timeout=timeout)
    err = _wait_stopped(pve, g, upid, f"shutdown {label(g)}", sleep)
    return status(pve, g), err


def stop(pve: PVE, g: dict, sleep=time.sleep) -> tuple[str, str | None]:
    """Stop a guest at once (no clean shutdown): (final status, error or None)."""
    st = status(pve, g)
    if st == "stopped":
        return st, None
    upid = pve.write("POST", base(g) + "/status/stop")
    err = _wait_stopped(pve, g, upid, f"stop {label(g)}", sleep)
    return status(pve, g), err


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["status", "start", "shutdown", "stop"])
    ap.add_argument("guests", nargs="+")
    ap.add_argument("--json", action="store_true", help="status: print {guest: status} as JSON")
    ap.add_argument("--timeout", type=int, help="start: seconds to wait for running (default 120); "
                                                "shutdown: seconds the guest gets to shut down (default 180)")
    ap.add_argument("--site", help="the site whose Proxmox holds the guests (default: the default site)")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        px = hmlib.proxmox_site(cfg, a.site)
        secret = hmlib.proxmox_token_name(px, "read_only" if a.action == "status" else "provisioning")
        pve = PVE(hmlib.pick_endpoint(px), hmlib.read_secret(cfg, secret), hmlib.proxmox_ssl_context(cfg, px))
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
        if a.action == "start":
            st = start(pve, g, a.timeout or 120)
            print(f"{label(g)}: {'started, ' if before == 'stopped' else ''}{st}")
            rc |= st != "running"
            continue
        st, err = shutdown(pve, g, a.timeout or 180) if a.action == "shutdown" else stop(pve, g)
        if before == "stopped":
            print(f"{label(g)}: already stopped")
        elif st == "stopped":
            print(f"{label(g)}: {'shut down' if a.action == 'shutdown' else 'stopped (hard)'}, stopped")
        else:
            print(f"{label(g)}: {a.action} failed, still {st}" + (f" ({err})" if err else "")
                  + (": `pve_guest.py stop` is the hard way, only with the user's yes" if a.action == "shutdown" else ""))
        rc |= st != "stopped"
    return rc


if __name__ == "__main__":
    sys.exit(main())
