"""Tests for overview.py and the data it collects for OVERVIEW.md."""
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import ROOT, SCRIPTS, closed_http_error, run, yq  # noqa: E402,F401

sys.path.insert(0, str(ROOT / "hooks"))
import guard  # noqa: E402,F401


class OverviewTests(unittest.TestCase):  # GitHub issue #87
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", self.d, "--components", "proxmox,ansible,discovery", cwd=self.d)
        run("config_set.py", "network.vlans+={id: 20, name: DMZ, cidr: 10.9.20.0/24, gw: 10.9.20.1}",
            "site.domain=lab.example", cwd=self.d)
        snap = {"collected_at": "2026-01-02T03:04:05+00:00", "version": "9.1", "cluster": {"name": "c1", "quorate": 1},
                "nodes": [{"node": "pve1", "status": "online", "cpus": 8, "mem_gib": 64, "mem_used_gib": 60}],
                "storage": [{"storage": "local-zfs", "node": "pve1", "type": "zfspool", "shared": False,
                             "size_gib": 100, "used_gib": 90, "content": "images"}],
                "guests": [{"vmid": 101, "name": "web|<b>x</b>\"[a](http://e)", "type": "vm", "node": "pve1",
                            "status": "running", "template": False, "cpus": 2, "mem_gib": 4, "disk_gib": 20,
                            "tags": "dmz", "config": {"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20",
                                                      "ipconfig0": "ip=10.9.20.5/24,gw=10.9.20.1", "onboot": 1}},
                           {"vmid": 102, "name": "db", "type": "lxc", "node": "pve1", "status": "stopped",
                            "template": False, "config": {"net0": "name=eth0,bridge=vmbr0,tag=20,ip=10.9.20.6/24"}},
                           {"vmid": 9050, "name": "tpl", "type": "vm", "node": "pve1", "template": True}],
                "backup_jobs": [{"id": "daily", "enabled": True, "all": False, "vmid": [101]}]}
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(snap))

    def test_hosts_missing_from_ping_sweep_listed_apart(self):  # GitHub issue #127
        r = run("config_set.py", "network.authorized_ranges+=10.9.20.0/24", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        Path(self.d, "discovery/network.json").write_text(json.dumps({"hosts": {
            "10.9.20.42": {"ip": "10.9.20.42", "device_type_guess": "linux", "last_seen": "2026-11-18T10:00:00+00:00"},
            "10.9.20.44": {"ip": "10.9.20.44", "device_type_guess": "phone", "hostnames": ["old-lease"],
                           "last_seen": "2026-11-01T10:00:00+00:00",
                           "missing_since": "2026-11-18T10:00:00+00:00"}}}))
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        sec = r.stdout[r.stdout.index("## Network devices not in managed inventory"):]
        current, gone = sec.split("Not answering since the last ping sweep (1)")
        self.assertIn("1 device(s)", current)
        self.assertIn("- 10.9.20.42", current)
        self.assertNotIn("10.9.20.44", current)
        self.assertIn("- 10.9.20.44 old-lease — missing since 2026-11-18, last seen 2026-11-01", gone)
        r = run("overview.py", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        md = Path(self.d, "OVERVIEW.md").read_text()
        other = md[md.index("### Other scanned addresses"):]
        current, gone = other.split("<details><summary>1 address nothing names, not answering since the last ping "
                                    "sweep</summary>")
        self.assertIn("| 10.9.20.42 |", current)
        self.assertNotIn("10.9.20.44", current)
        self.assertIn("| 10.9.20.44 | old-lease | phone | 2026-11-18 | 2026-11-01 |", gone)

    def test_named_unmanaged_devices(self):  # issue 100
        r = run("config_set.py", "network.authorized_ranges+=10.9.20.0/24",
                "discovery.ignore_unmanaged+={ip: 10.9.20.40, name: Living room TV}",
                "discovery.ignore_unmanaged+={ip: 10.9.20.50, name: EV charger, mac: AA:BB:CC:00:00:01}",
                "discovery.ignore_unmanaged+=10.9.20.60", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        Path(self.d, "discovery/network.json").write_text(json.dumps({"hosts": {
            "10.9.20.40": {"ip": "10.9.20.40", "device_type_guess": "camera"},
            "10.9.20.41": {"ip": "10.9.20.41", "mac": "aa:bb:cc:00:00:01", "device_type_guess": "water heater"},
            "10.9.20.42": {"ip": "10.9.20.42", "device_type_guess": "linux"},
            "10.9.20.43": {"ip": "10.9.20.43", "device_type_guess": "network"},
            "10.9.20.60": {"ip": "10.9.20.60"}}}))
        Path(self.d, "discovery/routeros.json").write_text(json.dumps({"devices": {"10.9.30.1": {   # GitHub #106
            "identity": {"name": "rtr9"}, "addresses": [{"address": "10.9.20.43/24"}]}}}))
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        sec = r.stdout[r.stdout.index("## Network devices not in managed inventory"):]
        self.assertIn("1 device(s)", sec)
        self.assertIn("- 10.9.20.42", sec)
        self.assertNotIn("- 10.9.20.43 ", sec.split("RouterOS interface addresses")[0])          # #106: a router's
        self.assertIn("RouterOS interface addresses (`discovery/routeros.json`, 1):\n\n- 10.9.20.43 → `rtr9`", sec)
        self.assertIn("routeros_audit.py --leases", sec)
        self.assertIn("Known unmanaged devices (`discovery.ignore_unmanaged`, 2 seen):\n\n"
                      "- 10.9.20.40 Living room TV\n- 10.9.20.50 EV charger (aa:bb:cc:00:00:01) — seen at 10.9.20.41\n",
                      sec)
        r = run("overview.py", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        md = Path(self.d, "OVERVIEW.md").read_text()
        self.assertIn("| Known device | Living room TV | – | 10.9.20.40 | – | not managed | – |", md)
        self.assertIn("| Known device | EV charger | – | 10.9.20.50 | – | not managed, MAC aa:bb:cc:00:00:01, seen at "
                      "10.9.20.41 | – |", md)
        other = md[md.index("### Other scanned addresses"):md.index("<details>")]
        self.assertIn("| 10.9.20.40 | Living room TV | known device |", md.split("<details>")[1])   # #109
        self.assertIn("| 10.9.20.42 |", other)
        self.assertNotIn("10.9.20.40", other)
        self.assertNotIn("10.9.20.41", other)
        self.assertNotIn("10.9.20.43", other)                                                      # #106
        self.assertNotIn("10.9.20.60", other)
        listed = md.split("<details>")[1]
        self.assertIn("| 10.9.20.43 | rtr9 | RouterOS |", listed)
        self.assertIn("| 10.9.20.60 | – | discovery.ignore\\_unmanaged |", listed)
        for bad in ("{name: x}", "{ip: 10.9.20.7, site: moon}"):
            self.assertNotEqual(run("config_set.py", f"discovery.ignore_unmanaged+={bad}", cwd=self.d).returncode, 0)

    def test_network_counts_every_known_address(self):  # GitHub issue #134
        snap = json.loads(Path(self.d, "discovery/proxmox.json").read_text())
        snap["guests"][1]["config"]["net1"] = "name=eth1,bridge=vmbr0,tag=30,ip=10.9.30.6/24"   # a second NIC
        snap["guests"].append({"vmid": 103, "name": "dhcp1", "type": "vm", "node": "pve1", "status": "running",
                               "template": False, "config": {"net0": "virtio=BC:24:11:00:00:03,bridge=vmbr0,tag=30"}})
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(snap))
        Path(self.d, "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    appliances:\n      hosts:\n        router1:\n          ansible_host: 10.9.20.2\n"
            "          hm_extra_ips: [10.9.30.1]\n")
        r = run("config_set.py", "network.vlans+={id: 30, name: LAB, cidr: 10.9.30.0/24}",
                "network.authorized_ranges+=10.9.20.0/24", "discovery.ignore_unmanaged+={ip: 10.9.20.60, name: TV}",
                "discovery.ignore_unmanaged+=10.9.20.61", "discovery.ignore_unmanaged+=10.9.20.200-210", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        Path(self.d, "discovery/network.json").write_text(json.dumps({"hosts": {
            ip: {"ip": ip, "device_type_guess": "linux"} for ip in ("10.9.20.2", "10.9.20.5", "10.9.20.50", "10.9.20.60")}}))
        r = run("overview.py", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        md = Path(self.d, "OVERVIEW.md").read_text()
        # .5 .6 guests; .1 gateway, .2 router1; .50 scanned, .60 named, .61 ignored (the .200-210 range doesn't count)
        self.assertIn("| 20 | DMZ | 10.9.20.0/24 | 10.9.20.1 | 2 | 7/254 | 2 guest IPs · 2 infra · 3 other |", md)
        # .6 (db's second NIC), .1 router1's hm_extra_ips; dhcp1 has no address; outside authorized_ranges
        self.assertIn("| 30 | LAB | 10.9.30.0/24 | – | 2 | 2/254 (not scanned) | 1 guest IP · 1 infra "
                      "(+1 guest, address unknown) |", md)
        self.assertIn("Not scanned / partly scanned:", md)

    def test_render_check_and_escaping(self):
        r = run("overview.py", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        md = Path(self.d, "OVERVIEW.md").read_text()
        self.assertIn("```mermaid", md)
        self.assertIn('pve1 (2 guests)"]', md)
        self.assertIn('-->|"2"| ', md)                                       # both guests on VLAN 20
        self.assertIn("| 20 | DMZ | 10.9.20.0/24 | 10.9.20.1 | 2 | 3/254 (not scanned) | 2 guest IPs · 1 infra |", md)
        self.assertIn("local-zfs on pve1 90% full", md)
        self.assertIn("In no enabled backup job (1 of 2): 102 db.", md)
        self.assertIn('subgraph default_g0["gateway 10.9.20.1"]', md)          # issue #93: VLANs under their gateway
        self.assertIn("| 101 | web\\|&lt;b&gt;x&lt;/b&gt;\"\\[a\\](http://e) | vm |", md)  # untrusted name
        self.assertNotIn("<b>", md)
        self.assertIn("discovery/proxmox.json | 2026-01-02 03:04 |", md)
        self.assertIn("Templates: 1 (tpl).", md)
        self.assertEqual(run("overview.py", "--no-ansible", "--check", cwd=self.d).returncode, 0)   # deterministic
        Path(self.d, "OVERVIEW.md").write_text(md.replace("DMZ", "LAN"))
        self.assertEqual(run("overview.py", "--no-ansible", "--check", cwd=self.d).returncode, 1)
        Path(self.d, "OVERVIEW.md").unlink()
        self.assertEqual(run("overview.py", "--no-ansible", "--check", cwd=self.d).returncode, 1)

    def test_storage_health_and_pbs(self):  # GitHub issues #151, #152
        f = Path(self.d, "discovery/proxmox.json")
        snap = json.loads(f.read_text())   # collected 2026-01-02T03:04:05Z
        snap["nodes"][0]["zfs"] = [
            {"pool": "tank", "state": "DEGRADED", "errors": "No known data errors", "scan": "scrub repaired …",
             "scrub_at": "2025-12-20", "scrub_errors": 0, "size_gib": 100, "alloc_gib": 40,
             "bad_devices": ["ata-DISK-B FAULTED (read/write/cksum 3/0/12)"]},
            {"pool": "old", "state": "ONLINE", "errors": "No known data errors", "scan": "scrub repaired …",
             "scrub_at": "2025-11-01", "scrub_errors": 0, "size_gib": 50, "alloc_gib": 5},
            {"pool": "fine", "state": "ONLINE", "errors": "No known data errors", "scan": "scrub in progress …",
             "scrub_running": True, "size_gib": 50, "alloc_gib": 5}]
        snap["nodes"][0]["disks"] = [
            {"dev": "/dev/sda", "type": "ssd", "model": "SSD X", "health": "PASSED", "used": "ZFS", "wear_pct": 60},
            {"dev": "/dev/sdb", "type": "hdd", "model": "HDD Y", "health": "FAILED", "used": "ZFS"},
            {"dev": "/dev/sdc", "type": "usb", "model": "Stick", "health": "UNKNOWN", "used": "exfat"}]
        snap["replication"] = [
            {"id": "101-0", "guest": 101, "source": "pve1", "target": "pve2", "enabled": True,
             "last_sync": "2026-01-01T10:00:00Z", "next_sync": "2026-01-02T03:20:00Z", "fail_count": 3,
             "error": "no space left"},
            {"id": "102-0", "guest": 102, "source": "pve1", "target": "pve2", "enabled": True,
             "last_sync": "2026-01-01T00:00:00Z", "next_sync": "2026-01-01T00:15:00Z", "fail_count": 0},
            {"id": "103-0", "guest": 103, "source": "pve1", "target": "pve2", "enabled": True,
             "last_sync": "2026-01-02T03:00:00Z", "next_sync": "2026-01-02T03:15:00Z", "fail_count": 0},
            {"id": "104-0", "guest": 104, "source": "pve1", "target": "pve2", "enabled": False,
             "next_sync": "2025-01-01T00:00:00Z", "fail_count": 9}]
        snap["ceph"] = {"health": "HEALTH_WARN", "checks": [{"check": "OSD_DOWN", "severity": "HEALTH_WARN",
                                                             "message": "1 osds down"}]}
        snap["storage_health"] = {"zfs": "ok", "disks": "not read: pve2: 500 smartctl hung", "replication": "ok",
                                  "ceph": "ok", "pbs": "no token for pbs2.example (pbs: in homelab.yaml, "
                                                       "docs/proxmox-tokens.md) (2 of 3 datastores read)"}
        job = {"schedule": "daily", "state": "OK", "at": "2026-01-01T05:00:00Z"}
        snap["pbs_datastores"] = [
            {"server": "pbs.example", "datastore": "store1", "storages": ["pbs-a"], "gc": job,
             "prune": [{"id": "p1", **job, "state": "ERROR: datastore is locked"}], "verify": [{"id": "v1", **job}],
             "snapshots": {"count": 10, "verified": 7, "failed": 1, "newest": "2026-01-02T01:00:00Z",
                           "newest_verified": "2026-01-01T01:00:00Z", "oldest_unverified": "2025-12-01T01:00:00Z"}},
            {"server": "pbs.example", "datastore": "store2", "storages": ["pbs-b"],
             "gc": {"schedule": "daily", "state": "running"}, "prune": [], "verify": [{"id": "v2", "state": "running"}],
             "snapshots": {"count": 4, "verified": 4, "failed": 0, "newest": "2025-06-01T00:00:00Z",
                           "newest_verified": "2025-06-01T00:00:00Z", "oldest_unverified": None}},   # an archive
            {"server": "pbs2.example", "datastore": "far", "storages": ["pbs-far"]}]
        f.write_text(json.dumps(snap))
        r = run("config_set.py", "overview.disk_wearout_max_pct=50", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run("overview.py", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        md = Path(self.d, "OVERVIEW.md").read_text()
        sec = md[md.index("### Storage health"):md.index("### Guests")]
        self.assertIn("| pve1 | tank | DEGRADED | 40/100 GiB | 2025-12-20, 0 errors | ⚠ state DEGRADED; devices: "
                      "ata-DISK-B FAULTED (read/write/cksum 3/0/12) |", sec)
        self.assertIn("| pve1 | old | ONLINE | 5/50 GiB | 2025-11-01, 0 errors | ⚠ last scrub 2025-11-01, over 35 days "
                      "before the snapshot |", sec)
        self.assertIn("| pve1 | fine | ONLINE | 5/50 GiB | running | OK |", sec)
        self.assertIn("Disks: 3 disks on 1 node, SMART passed on 1, unknown on 1; most worn: pve1 /dev/sda (ssd) 60 % "
                      "(a warning from 50 %).", sec)
        self.assertIn("| pve1 | /dev/sda | ssd | SSD X | ZFS | PASSED | 60 % | worn 60 % |", sec)
        self.assertIn("| pve1 | /dev/sdb | hdd | HDD Y | ZFS | FAILED | – | SMART FAILED |", sec)
        self.assertNotIn("/dev/sdc |", sec)
        self.assertIn("| 101-0 | 101 | pve1 → pve2 | 2026-01-01 10:00 | ⚠ 3 failed sync(s): no space left |", sec)
        self.assertIn("| 102-0 | 102 | pve1 → pve2 | 2026-01-01 00:00 | ⚠ late: next sync was due 2026-01-01 |", sec)
        self.assertIn("| 103-0 | 103 | pve1 → pve2 | 2026-01-02 03:00 | OK |", sec)
        self.assertIn("| 104-0 | 104 | pve1 → pve2 | never | disabled |", sec)
        self.assertIn("Ceph: HEALTH\\_WARN — OSD\\_DOWN: 1 osds down.", sec)
        self.assertIn("Not read: disks pve2: 500 smartctl hung.", sec)
        backups = md[md.index("### Backups"):]
        self.assertIn("| pbs-a | pbs.example | store1 | OK 2026-01-01 | failed 2026-01-01 | OK 2026-01-01 | 7/10, 1 failed "
                      "| 2026-01-01 | ⚠ prune job p1 failed: ERROR: datastore is locked; 1 snapshot(s) failed "
                      "verification; 2 snapshot(s) not verified, the oldest from 2025-12-01 |", backups)
        self.assertIn("| pbs-b | pbs.example | store2 | running | – | running | 4/4 | 2025-06-01 | OK |", backups)
        self.assertNotIn("| pbs-far |", backups)
        self.assertIn("PBS datastores (GC, prune, verify) not read for pbs2.example: add a read-only PBS token", backups)
        glance = md[md.index("Warnings (details"):].split("\n")[0]
        for text in ("2 ZFS pools degraded, with errors or not scrubbed recently", "2 disks failing SMART or worn out",
                     "Ceph not healthy on 1 site", "1 PBS datastore with a failed or old GC, prune or verify",
                     "2 replication jobs failing or late"):
            self.assertIn(text, glance)
        self.assertLess(glance.index("ZFS pools"), glance.index("guest in no"))
        health = md[md.index("## Health"):]
        self.assertIn("- default: ZFS pool tank on pve1: state DEGRADED", health)
        self.assertIn("- default: replication 102-0 (guest 102): late", health)
        self.assertIn("- default: PBS datastore store1 on pbs.example: prune job p1 failed", health)
        # healthy: no warnings, thresholds from homelab.yaml
        for p in snap["nodes"][0]["zfs"]:
            p.update(state="ONLINE", scrub_at="2025-12-20")
            p.pop("bad_devices", None)
        snap["nodes"][0]["disks"] = snap["nodes"][0]["disks"][:1]
        snap["replication"], snap["ceph"] = snap["replication"][2:], {"health": "HEALTH_OK", "checks": []}
        snap["pbs_datastores"] = snap["pbs_datastores"][1:2]
        f.write_text(json.dumps(snap))
        r = run("config_set.py", "overview.disk_wearout_max_pct=80", cwd=self.d)
        md = run("overview.py", "--no-ansible", "--out", "-", cwd=self.d).stdout
        glance = md[md.index("Warnings (details"):].split("\n")[0]
        for word in ("ZFS", "disk", "Ceph", "PBS", "replication"):
            self.assertNotIn(word, glance)
        self.assertIn("Ceph: HEALTH\\_OK.", md)

    def test_recovery_impact_exposure_expirations_access(self):  # GitHub issue #89
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import overview
        d = Path(self.d)
        r = run("config_set.py", "network.vlans+={id: 30, name: APPS, cidr: 10.9.30.0/24, gw: rtr1}",
                "network.vlans+={id: 40, name: LAN, cidr: 10.9.40.0/24, gw: core1}",
                "overview.backup_max_age_days=3", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        snap = json.loads((d / "discovery/proxmox.json").read_text())
        snap["guest_ip_sources"] = {"backups": "ok (2 vzdump task logs)"}
        snap["nodes"][0].update(subscription={"status": "active", "level": "c", "next_due": "2026-01-20"},
                                certificate={"not_after": "2030-01-01T00:00:00Z", "subject": "pve1", "issuer": "Lab CA"})
        snap["storage"].append({"storage": "pbs1", "node": "pve1", "type": "pbs", "shared": True, "server": "10.9.20.99",
                                "content": "backup"})
        g101, g102 = snap["guests"][0], snap["guests"][1]
        g101["config"]["startup"] = "order=2,up=30"
        g101["last_backup"] = {"at": "2026-01-02T01:00:00Z", "storage": "pbs1"}
        g102["last_backup"] = {"at": "2025-12-20T01:00:00Z", "storage": "pbs1"}
        g102["backup_error"] = {"at": "2026-01-02T01:00:00Z", "storage": "pbs1", "error": "disk|full"}
        g102["status"] = "running"
        snap["guests"].append({"vmid": 103, "name": "rtr1", "type": "vm", "node": "pve1", "status": "running",
                               "template": False, "config": {"net0": "virtio=x,bridge=vmbr0,tag=30", "onboot": 1,
                                                             "startup": "order=1", "scsi0": "pbs1:vm-103-disk-0"}})
        snap["backup_jobs"] = [{"id": "daily", "enabled": True, "all": True}]
        (d / "discovery/proxmox.json").write_text(json.dumps(snap))
        (d / "discovery/routeros.json").write_text(json.dumps({"devices": {"10.9.40.1": {
            "identity": {"name": "core1"}, "collected_at": "2026-01-02T00:00:00",
            "license": {"level": "p1", "deadline-at": "2026-01-25 10:00:00", "next-renewal-at": "2025-12-26 10:00:00"},
            "addresses": [{"address": "203.0.113.7/24", "interface": "ether1"}, {"address": "10.9.40.1/24"}],
            "nat": [{"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "443", "in-interface-list": "WAN",
                     "to-addresses": "10.9.20.5", "comment": "web|x", "_flags": ""},
                    {"chain": "dstnat", "action": "dst-nat", "to-addresses": "10.9.20.53", "connection-mark": "dns",
                     "src-address-list": "IOT", "_flags": ""},
                    {"chain": "dstnat", "action": "dst-nat", "to-addresses": "10.9.20.6", "_flags": "X"},
                    {"chain": "srcnat", "action": "masquerade", "_flags": ""}]}}}))
        (d / "discovery/network.json").write_text(json.dumps({"hosts": {"10.9.20.5": {"ip": "10.9.20.5", "ports": [
            {"port": 22, "proto": "tcp", "service": "ssh"}, {"port": 8443, "proto": "tcp", "service": "http", "tunnel": "ssl",
             "tls": {"subject": "web", "issuer": "Lab CA", "not_after": "2026-01-10T00:00:00"}},
            {"port": 80, "proto": "tcp", "service": "http"}, {"port": 3306, "proto": "tcp", "service": "mysql"}],
            "last_seen": "2026-01-03T00:00:00"}}}))
        (d / "discovery/qnap-containers.json").write_text(json.dumps({"collected_at": "x", "hosts": {"nas1": {
            "site": "", "containers": [{"name": "ct-pbs1", "runtime": "lxd", "image": "Debian 12", "ips": ["10.9.20.99"],
                                        "state": "running"},
                                       {"name": "app", "runtime": "docker", "image": "nginx", "ports": ["8080->80/tcp"]}]}}}))
        managed = {"pve1": {"ansible_host": "10.9.20.2", "ansible_user": "root", "_groups_all": ["proxmox_nodes"]},
                   "web|x": {"ansible_host": "10.9.20.5", "ansible_user": "{{ x }}", "ansible_port": 2222,
                             "_groups_all": ["linux", "web_cluster"]},
                   "rtr1": {"ansible_host": "10.9.30.1", "_groups_all": ["linux"], "patch_requires_approval": True},
                   "nas1": {"ansible_host": "10.9.20.100", "_groups_all": ["qnap"]}}
        self.assertEqual(run("config_set.py", "clusters+={name: web, ansible_group: web_cluster, vip: 10.9.20.80}",
                             cwd=self.d).returncode, 0)
        md = overview.render(hmlib.load_config(self.d), managed, "test")
        sec = lambda name: re.search(rf"### {name}\n.*?(?=\n##)", md, re.S).group(0)
        # last backup: column, a newer failure, the age limit from homelab.yaml, judged against the snapshot time
        self.assertIn("| yes | – | 2026-01-02 | dmz |", md)
        self.assertIn("| failed 2026-01-02, last OK 2025-12-20 |", md)
        back = sec("Backups")
        self.assertIn("as of 2026-01-02): 1 of 3 guests in a job within 3 days.", back)
        self.assertIn("No successful backup within 3 days: 102 db (2025-12-20), 103 rtr1 (none in the task logs).", back)
        self.assertIn("Newest backup failed: 102 db (disk\\|full).", back)
        self.assertIn("2 guests without a recent successful backup", md.split("## Contents")[0])
        # start order: Proxmox order then VMID; what each guest does; running guests without autostart
        start = sec("Start order")
        self.assertIn("| pve1 | 1 | 103 | rtr1 | 1 | – | gateway of VLAN 30, critical |", start)
        self.assertIn("| pve1 | 2 | 101 |", start)
        self.assertIn("| 2 | 30 s | – |", start)
        self.assertIn("Running now without autostart (start by hand after an outage): 102 db.", start)
        # impact: node, a gateway that is no guest here, a NAS whose container serves a storage
        imp = sec("If it goes down")
        self.assertIn("- **Proxmox node pve1**: 3 running guests stop; rtr1: routing lost for VLAN 30 APPS (1 guest there)."
                      , imp)
        self.assertIn("- **core1**: routing lost for VLAN 40 LAN (0 guests there).", imp)
        self.assertIn("- **ct-pbs1**: storage pbs1 unavailable: 1 guest with disks or ISOs there can't start.", imp)
        self.assertIn("- **nas1**: 2 containers on it stop; ct-pbs1: storage pbs1 unavailable", imp)
        # port forwards: enabled dst-nat only, every matcher, known targets, public addresses
        fwd = sec("Port forwards")
        self.assertIn("Public addresses on RouterOS interfaces: core1 203.0.113.7/24 on ether1.", fwd)
        self.assertIn("| core1 | tcp 443 | in-interface-list WAN | any | 10.9.20.5 (web\\|x) | web\\|x |", fwd)
        self.assertIn("| core1 | all traffic | connection-mark dns | address-list IOT | 10.9.20.53 | – |", fwd)
        self.assertNotIn("10.9.20.6 ", fwd)
        # access: inventory user (not a template) and port, web links, other services, the Proxmox UI
        acc = sec("Access")
        self.assertIn("| web\\|x | 10.9.20.5 | ssh 10.9.20.5 -p 2222 | https://10.9.20.5:8443, http://10.9.20.5 | "
                      "mysql/3306 |", acc)
        self.assertIn("| pve1 | 10.9.20.2 | ssh root@10.9.20.2 | https://10.9.20.2:8006 | – |", acc)
        # expirations: soonest first, against the newest data, not today
        exp = md[md.index("## Expirations"):md.index("## Sources")]
        self.assertIn("judged against the newest data (2026-01-03)", exp)
        rows = [l for l in exp.splitlines() if l.startswith("| 20")]
        self.assertEqual([l.split(" | ")[0] for l in rows], ["| 2026-01-10", "| 2026-01-20", "| 2026-01-25", "| 2030-01-01"])
        self.assertIn("| 2026-01-10 | TLS certificate web (issuer Lab CA) | web\\|x:8443 | ⚠ within 30 days |", exp)
        self.assertIn("| Proxmox VE subscription Community | pve1 | ⚠ within 30 days |", exp)
        self.assertIn("| CHR licence p1 | core1 | ⚠ within 30 days; renews automatically 2025-12-26", exp)
        self.assertIn("3 expiries within 30 days", md.split("## Contents")[0])
        # NAS containers in the containers.json layout qnap-containers.yml writes
        self.assertIn("| nas1 | – | ct-pbs1 | LXD: Debian 12 (running) | 10.9.20.99 | – |", md)
        self.assertIn("| nas1 | – | app | nginx | 8080-&gt;80/tcp | – |", md)

    def test_inventory_devices_known_addresses_and_health(self):  # GitHub issues #93-#97
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import overview
        d = Path(self.d)
        snap = json.loads((d / "discovery/proxmox.json").read_text())
        snap["nodes"][0].update(pveversion="pve-manager/9.1.11/abc", kernel="7.0.2-4-pve")
        snap["networks"] = {"pve1": [{"iface": "vmbr0", "cidr": "10.9.20.2/24"}, {"iface": "vmbr1", "cidr": "10.9.30.2/24"}]}
        snap["guests"].append({"vmid": 103, "name": "rtr1", "type": "vm", "node": "pve1", "status": "running",
                               "template": False, "config": {"net0": "virtio=x,bridge=vmbr0,tag=99",
                                                             "net2": "virtio=y,bridge=vmbr0,tag=20",
                                                             "net10": "virtio=z,bridge=vmbr0,tag=99"}})
        snap["backup_jobs"] = [{"id": "94303c4493efac4f203cefc5732a1514c671842c:1", "enabled": True, "vmid": [101, 103]}]
        (d / "discovery/proxmox.json").write_text(json.dumps(snap))
        (d / "discovery/network.json").write_text(json.dumps({"hosts": {
            "10.9.20.1": {"os": [{"name": "MikroTik RouterOS 7", "accuracy": 98}, {"name": "Linux", "accuracy": 90}]},
            "10.9.20.2": {"os": []}, "10.9.30.2": {"os": []}, "10.9.20.7": {"os": [], "ssh_probe": {"hostname": "rtr1.lan"}},
            "10.9.20.66": {"os": [{"name": "Linux 5.0 - 5.14", "accuracy": 95}], "device_type_guess": "linux"}}}))
        (d / "discovery/routeros.json").write_text(json.dumps({"devices": {"10.9.20.1": {
            "identity": {"name": "sw1"}, "resource": {"board-name": "CRS317", "version": "7.21.4"},
            "addresses": [{"address": "10.9.20.1/24"}], "findings": [{"severity": "low", "text": "x"}],
            "update": {"installed-version": "7.21.4", "latest-version": "7.21.5"}, "collected_at": "2026-01-02T00:00:00"}}}))
        (d / "discovery/bmc.json").write_text(json.dumps({"hosts": {"bmc1": {"model": "ML350", "health": "Critical",
                                                                              "not_ok": ["psu"], "power_state": "On"}}}))
        (d / "discovery/qnap-containers.json").write_text(json.dumps({"nas1": {"lxd": [
            {"name": "ct-pbs1", "state": "RUNNING", "ipv4": "10.9.20.99 (eth0)"}], "docker": [
            {"name": "app", "image": "nginx", "networks": ["bridge"], "compose_project": "web",
             "compose_working_dir": "/share/web", "compose_config_files": ["/share/web/compose.yml"]}]}}))
        (d / "discovery/updates.json").write_text(json.dumps({"hosts": {
            "pve1": {"os": "Debian 13", "pending": 0, "collected_at": "2026-01-10T00:00:00"},
            "web": {"os": "Rocky 9", "pending": 3, "collected_at": "2026-01-01T00:00:00"}}}))
        (d / "discovery/drift.md").write_text("# Drift report — 2026-01-02 03:04\n**Not managed by OpenTofu (2)** — x\n"
                                              "3 device(s) — add\n**Total findings: 2**\n")
        managed = {"pve1": {"ansible_host": "10.9.20.2", "_groups_all": ["linux", "proxmox_nodes"],
                            "patch_requires_approval": True},
                   "sw1": {"ansible_host": "10.9.20.1", "_groups_all": ["appliances", "routeros"]},
                   "sw2": {"ansible_host": "10.9.20.3", "_groups_all": ["appliances", "routeros"]},
                   "bmc1": {"ansible_host": "10.9.20.9", "_groups_all": ["appliances", "bmc"]},
                   "web": {"ansible_host": "10.9.20.5", "_groups_all": ["linux"]},
                   "rtr1": {"ansible_host": "10.9.20.8", "_groups_all": ["linux"]},
                   "db": {"ansible_host": "10.9.20.6", "_groups_all": ["linux"]}}
        md = overview.render(hmlib.load_config(self.d), managed, "test")
        self.assertIn("| 103 | rtr1 | vm | pve1 | running | – | – | – | VLAN 20 DMZ | 10.9.20.8 |", md)   # #97 NIC
        self.assertIn("| pve1 | online | 9.1.11 | 7.0.2-4-pve |", md)                                     # #97 node
        self.assertIn("| ? → ? | yes |", md)                                                            # #97, #109 job id
        self.assertIn("| 2 listed |", md)
        self.assertIn("| nas1 | – | ct-pbs1 | LXD (RUNNING) | 10.9.20.99 (eth0) | – |", md)              # #97 NAS
        self.assertIn("| app | nginx | bridge | /share/web |", md)                                      # #102
        self.assertIn("Drift (2026-01-02 03:04): 2 findings — 2 not managed by OpenTofu; 3 network devices", md)
        self.assertIn("| RouterOS | sw1 | CRS317 | 10.9.20.1 | 7.21.4 | 1 audit findings (2026-01-02) |", md)  # #94
        self.assertIn("| RouterOS | sw2 | – | 10.9.20.3 | – | not audited", md)
        self.assertIn("### Server hardware\n\n| Server | BMC | Model | Address | Firmware | Health | Power | Last seen |\n"
                      "|---|---|---|---|---|---|---|---|\n| – | bmc1 | ML350 | 10.9.20.9 | – | Critical (not OK: psu; "
                      "bmc-info.yml records the cause) | On | – |", md)                              # #117
        self.assertLess(md.index("### Proxmox nodes"), md.index("### Server hardware"))
        self.assertLess(md.index("### Server hardware"), md.index("### Storage"))
        devices = md.split("### Network devices and appliances")[1].split("###")[0]
        self.assertNotIn("bmc1", devices)
        self.assertNotIn("### Network devices\n", md)
        other = md.split("### Other scanned addresses")[1].split("<details>")[0]                   # #96
        self.assertIn("| 10.9.20.66 | – | linux | Linux 5.0 - 5.14 (95%) |", other)
        for ip in ("10.9.20.1 ", "10.9.20.2 ", "10.9.30.2 ", "10.9.20.7 "):
            self.assertNotIn(ip, other)
        self.assertNotIn("accuracy", md)
        health = md.split("## Health")[1]                                                          # #95
        self.assertIn("| pve1 | Debian 13 | – | 0 | – | – | 2026-01-10 | up to date |", health)
        self.assertIn("| web | Rocky 9 | – | 3 | – | – | 2026-01-01 (stale) | updates pending |", health)
        self.assertIn("Not checked yet (`check-updates.yml`): db, rtr1.", health)
        self.assertIn("Not covered by `check-updates.yml` (see Server hardware and Network devices and appliances): "
                      "bmc1, sw1, sw2.", health)
        self.assertIn("BMC health: bmc1 Critical (not OK: psu; bmc-info.yml records the cause).", health)
        self.assertIn("Warnings (details under [Health](#health)): BMC: 1 Critical · 1 guest in no enabled backup job · "   # #108
                      "1 storage 80 % full or more · 1 node at 85 % memory or more.", md)
        self.assertIn("RouterOS updates available: sw1 7.21.4 → 7.21.5.", health)
        site_map = md.split("```mermaid")[1]                                                      # #93
        self.assertIn('subgraph default_g0["gateway sw1"]', site_map)
        self.assertIn("devices: bmc1, sw1, sw2", site_map)

    def test_map_wraps_and_folds_vlans(self):  # GitHub issue #93
        sys.path.insert(0, str(SCRIPTS))
        import overview
        vl = [{"id": i, "name": f"V{i}", "cidr": f"10.9.{i}.0/24"} for i in range(1, 9)]
        st = {"name": "", "default": True}
        guests = {"pve1": [{"_tag": i} for i in range(1, 8)]}
        out = "\n".join(overview.site_map(st, {"nodes": [{"node": "pve1"}]}, vl, guests, {}, [], {}))
        self.assertIn("default_v1 ~~~ default_v6", out)                    # MAP_COLUMNS (5) per column
        self.assertIn('default_idle(["1 VLANs without guests or addresses: 8"])', out)
        self.assertNotIn("default_v8(", out)
        self.assertEqual(overview.os_guess("x"), "x")

    def test_every_nic_counts(self):  # GitHub issue #107: a router VM is on every VLAN it has a NIC in
        d = Path(self.d)
        run("config_set.py", "network.vlans+={id: 30, name: WAN, cidr: 10.9.30.0/24}", cwd=self.d)
        snap = json.loads((d / "discovery/proxmox.json").read_text())
        snap["guests"].append({"vmid": 103, "name": "rtr1", "type": "vm", "node": "pve1", "status": "running",
                               "template": False, "config": {"net0": "virtio=x,bridge=vmbr0,tag=30",
                                                             "net1": "virtio=y,bridge=vmbr0,tag=20",
                                                             "net2": "virtio=z,bridge=vmbr0,tag=77",
                                                             "net3": "virtio=w,bridge=vmbr9",
                                                             "net4": "virtio=v,bridge=vmbr9",
                                                             "ipconfig1": "ip=10.9.20.1/24"}})
        (d / "discovery/proxmox.json").write_text(json.dumps(snap))
        md = run("overview.py", "--no-ansible", "--out", "-", cwd=self.d).stdout
        self.assertIn("| 20 | DMZ | 10.9.20.0/24 | 10.9.20.1 | 3 |", md)
        self.assertIn("| 30 | WAN | 10.9.30.0/24 | – | 1 |", md)
        self.assertIn('pve1 (3 guests)"]', md)
        self.assertIn('default_n0 -->|"1"| default_v30', md)
        self.assertIn('default_v77(["VLAN 77 (not in network.vlans)"])', md)
        self.assertIn('default_n0 -->|"1 untagged"| default_untagged_vmbr9(["untagged on vmbr9"])', md)
        self.assertIn("| 103 | rtr1 | vm | pve1 | running | – | – | – | VLAN 20 DMZ | 10.9.20.1 |", md)   # one NIC here

    def test_wording(self):  # GitHub issue #109
        sys.path.insert(0, str(SCRIPTS))
        import overview
        job = {"schedule": "02:00", "storage": "pbs"}
        self.assertEqual(overview.job_name({"id": "backup-2f7154fd-a3d8", **job}), "02:00 → pbs")
        self.assertEqual(overview.job_name({"id": "94303c4493efac4f203cefc5732a1514c671842c:1", **job}), "02:00 → pbs")
        self.assertEqual(overview.job_name({"id": "daily", **job}), "daily")
        self.assertEqual(overview.job_name({"id": "backup-2f7154fd-a3d8", "comment": "Nightly", **job}), "Nightly")
        out = "\n".join(overview.sites_map([({"name": "", "label": "", "default": True}, 1, 1, 0),
                                            ({"name": "b", "label": "", "default": False}, 3, 2, 4)]))
        self.assertIn("1 node, 1 guest, flat network (untagged)", out)
        self.assertIn("3 nodes, 2 guests, 4 VLANs", out)
        self.assertNotIn("---", out)
        md = run("overview.py", "--no-ansible", "--out", "-", cwd=self.d).stdout
        self.assertIn("1 site, 1 Proxmox node, 2 guests.", md)

    def test_device_identification(self):  # GitHub issues #104, #105
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import overview
        tie = [{"name": "Linux 5.0 - 5.14", "accuracy": 98}, {"name": "MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)",
                                                               "accuracy": 98}, {"name": "Linux 4.15", "accuracy": 99 - 4}]
        self.assertEqual(overview.os_guess(tie), "MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (98%)")
        self.assertEqual(overview.os_guess([{"name": "Linux 2.6.32 - 3.13", "accuracy": 94},
                                            {"name": "Linux 5.0 - 5.14", "accuracy": 94}]), "Linux 2.6.32 - 3.13 or similar (94%)")
        self.assertEqual(overview.os_guess([{"name": "Linux 5.0 - 5.14", "accuracy": 90}]), "Linux 5.0 - 5.14 (90%)")
        self.assertEqual(overview.ssh_model({"hostname": "jetkvm-1", "kernel": "Linux 5.10.160", "arch": "armv7l"}),
                         "jetkvm-1 · Linux 5.10.160 armv7l")
        self.assertEqual(overview.ssh_model({"product": "OPNsense 26.7 (amd64)", "arch": "amd64"}), "OPNsense 26.7 (amd64)")
        d = Path(self.d)
        snap = json.loads((d / "discovery/proxmox.json").read_text())
        snap["guests"] += [{"vmid": 120, "name": "chr-a", "type": "vm", "node": "pve1", "template": False,
                            "config": {"net0": "virtio=BC:24:11:00:00:20,bridge=vmbr0,tag=20"}},
                           {"vmid": 121, "name": "opn1", "type": "vm", "node": "pve1", "template": False,
                            "config": {"net0": "virtio=BC:24:11:00:00:21,bridge=vmbr0,tag=20"}}]
        (d / "discovery/proxmox.json").write_text(json.dumps(snap))
        (d / "discovery/routeros.json").write_text(json.dumps({"devices": {"10.9.20.30": {
            "identity": {"name": "rtr-x"}, "resource": {"board-name": "CHR QEMU Standard PC (i440FX + PIIX, 1996)"},
            "interfaces": [{"name": "ether1", "mac-address": "BC:24:11:00:00:20"}]}}}))
        (d / "discovery/network.json").write_text(json.dumps({"hosts": {
            "10.9.20.31": {"os": tie, "ssh_probe": {"ok": True, "hostname": "jetkvm-1", "kernel": "Linux 5.10.160",
                                                     "arch": "armv7l"}},
            "10.9.20.32": {"os": tie},
            "10.9.20.40": {"os": tie, "device_type_guess": "linux", "vendor": "Raspberry Pi Trading"}}}))
        managed = {"rtr-x": {"ansible_host": "10.9.20.30", "_groups_all": ["appliances", "routeros"]},
                   "kvm1": {"ansible_host": "10.9.20.31", "_groups_all": ["appliances"]},
                   "kvm2": {"ansible_host": "10.9.20.32", "_groups_all": ["appliances"]},
                   "kvm3": {"ansible_host": "10.9.20.33", "_groups_all": ["appliances"], "hm_model": "JetKVM"},
                   "opn1": {"ansible_host": "10.9.20.34", "_groups_all": ["appliances"]}}
        md = overview.render(hmlib.load_config(self.d), managed, "test")
        self.assertIn("| RouterOS | rtr-x | CHR (VM 120 on pve1) | 10.9.20.30 |", md)
        self.assertIn("| Appliance | kvm1 | jetkvm-1 · Linux 5.10.160 armv7l | 10.9.20.31 | – | – |", md)
        self.assertIn("| Appliance | kvm2 | – | 10.9.20.32 | – | nmap guess: MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (98%) |", md)
        self.assertIn("| Appliance | kvm3 | JetKVM | 10.9.20.33 | – | – |", md)                      # hm_model wins
        self.assertIn("| Appliance | opn1 | VM 121 on pve1 | 10.9.20.34 | – | no data: set hm\\_model or run "
                      "ssh\\_probe.py --include-managed |", md)
        self.assertIn("| Address | Name | Looks like | OS guess (nmap, match %) |", md)
        self.assertIn("| 10.9.20.40 | – | linux (Raspberry Pi Trading) | MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (98%) |", md)

    def test_bmc_accepted_health(self):  # GitHub issue #103
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import overview
        d = {"health": "Critical", "not_ok": ["system Critical"], "health_causes": ["chassis_intrusion"]}
        self.assertTrue(overview.bmc_health(d, {"bmc_health_accept": ["chassis_intrusion"]})["accepted"])
        self.assertTrue(overview.bmc_health(d, {"bmc_health_accept": "Intrusion"})["accepted"])     # part, any case
        self.assertFalse(overview.bmc_health(d, {})["accepted"])
        two = dict(d, health_causes=["chassis_intrusion", "PSU 2 Critical"])
        b = overview.bmc_health(two, {"bmc_health_accept": ["chassis_intrusion"]})
        self.assertFalse(b["accepted"])                                                            # a new cause
        self.assertEqual(overview.bmc_text(b), "Critical (cause: PSU 2 Critical; accepted: chassis_intrusion)")
        self.assertFalse(overview.bmc_health(dict(d, health_causes=[]), {"bmc_health_accept": ["x"]})["accepted"])
        self.assertEqual(overview.bmc_text(overview.bmc_health(dict(d, health_causes=[]), {})), "Critical (cause unknown)")
        self.assertFalse(overview.bmc_health({"health": "OK", "health_causes": []}, {"bmc_health_accept": ["x"]})["accepted"])
        Path(self.d, "discovery/bmc.json").write_text(json.dumps({"hosts": {"bmc1": dict(d, model="X10", power_state="On")}}))
        managed = {"bmc1": {"ansible_host": "10.9.20.9", "_groups_all": ["appliances", "bmc"],
                            "bmc_health_accept": ["chassis_intrusion"]}}
        md = overview.render(hmlib.load_config(self.d), managed, "test")
        self.assertIn("| – | bmc1 | X10 | 10.9.20.9 | – | Critical (accepted: chassis\\_intrusion) | On |", md)
        self.assertIn("BMC health: bmc1 Critical (accepted: chassis\\_intrusion).", md)
        docs = {"bmc.json": {"hosts": {"bmc1": d, "bmc2": dict(d, health="Warning"), "bmc3": dict(d, health_causes=["psu"])}},
                "routeros.json": {"devices": {"r1": {"findings": [{"severity": "medium"}, {"severity": "low"},
                                                                    {"severity": "high"}, {"severity": "info"}]}}},
                "updates.json": {"hosts": {"pve1": {"security": 82}, "web": {"security": 3}, "db": {"security": 0},
                                           "x": {"error": "unreachable"}}}}
        managed["pve1"] = {"_groups_all": ["proxmox_nodes"]}
        self.assertEqual(overview.glance_warnings(docs, managed, {"backup": 18}),                 # GitHub #108
                         ["BMC: 1 Critical, 1 Warning", "RouterOS audit: 1 high, 1 medium", "update check failed on 1 host",
                          "security updates on 2 hosts (1 Proxmox node)", "18 guests in no enabled backup job"])

    def test_bmc_belongs_to_its_server(self):  # GitHub issue #117
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import overview
        hosts = {"pve1", "nas1"}
        self.assertEqual(overview.bmc_server("bmc-pve1", {}, hosts), "pve1")
        self.assertEqual(overview.bmc_server("pve1-bmc", {}, hosts), "pve1")
        self.assertEqual(overview.bmc_server("nas1-ipmi", {}, hosts), "nas1")
        self.assertEqual(overview.bmc_server("bmc-pve9", {}, hosts), "")             # no such host
        self.assertEqual(overview.bmc_server("ilo1", {"bmc_of": "srv7"}, hosts), "srv7")
        Path(self.d, "discovery/bmc.json").write_text(json.dumps({"hosts": {
            "pve1-ilo": {"model": "DL380", "health": "OK", "power_state": "On", "bmc_firmware": "3.10",
                         "collected_at": "2026-01-05T00:00:00"},
            "bmc-pve1": {"model": "X10", "health": "OK", "power_state": "Off"}}}))
        managed = {"pve1-ilo": {"ansible_host": "10.9.20.11", "_groups_all": ["appliances", "bmc"], "bmc_of": "pve1"},
                   "bmc-pve1": {"ansible_host": "10.9.20.12", "_groups_all": ["appliances", "bmc"]},
                   "spare-bmc": {"ansible_host": "10.9.20.13", "_groups_all": ["appliances", "bmc"]}}
        md = overview.render(hmlib.load_config(self.d), managed, "test")   # pve1 is a Proxmox node, not in the inventory
        hw = md.split("### Server hardware")[1].split("###")[0]
        self.assertIn("| pve1 | bmc-pve1 | X10 | 10.9.20.12 | – | OK | Off | – |", hw)
        self.assertIn("| pve1 | pve1-ilo | DL380 | 10.9.20.11 | 3.10 | OK | On | 2026-01-05 |", hw)
        self.assertIn("| – | spare-bmc | – | 10.9.20.13 | – | no data (bmc-info.yml) | – | – |", hw)
        self.assertLess(hw.index("bmc-pve1"), hw.index("spare-bmc"))                 # linked servers first
        self.assertNotIn("### Network devices", md)                                   # BMCs only: no device table
        self.assertIn("devices: bmc-pve1, pve1-ilo, spare-bmc", md)                   # still on the site map

    def test_lists_never_cut(self):  # GitHub issue #115
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        import overview
        self.assertEqual(overview.cell(["b|1", None, "", "a_2"]), "b\\|1, a\\_2")
        self.assertEqual(overview.cell([]), "–")
        self.assertTrue(overview.cell(["x" * 300]).endswith("…"))           # one item still has its own limit
        hosts = [f"host-{i:02d}.lab" for i in range(74)]
        managed = {h: {"ansible_host": f"10.9.20.{100 + i}", "_groups_all": ["linux"]} for i, h in enumerate(hosts)}
        ports = [f"{31900 + i}->{31900 + i}/tcp" for i in range(20)]
        Path(self.d, "discovery/containers.json").write_text(json.dumps({"hosts": {"docker1": {"containers": [
            {"name": "app", "image": "nginx", "ports": ports}]}}}))
        md = overview.render(hmlib.load_config(self.d), managed, "test")
        row = next(line for line in md.splitlines() if line.startswith("| linux | 74 |"))
        self.assertTrue(row.endswith(", ".join(h for h in hosts) + " |"))
        self.assertNotIn("…", row)
        self.assertIn(", ".join(p.replace(">", "&gt;") for p in ports) + " |", md)

    def test_containers_at_their_memory_limit(self):  # GitHub issue #143
        mem = lambda hits, refaults, oom=0, since="2026-01-01T00:00:00.123456789Z": {   # noqa: E731
            "limit": 32 * 2**20, "current": 33 * 10**6, "max_events": hits, "oom_kills": oom,
            "refault_file": refaults, "since": since}
        Path(self.d, "discovery/containers.json").write_text(json.dumps({"hosts": {"docker1": {
            "collected_at": "2026-01-04T00:00:00.000001", "containers": [               # 72 h after `since`
                {"name": "watchtower", "compose_working_dir": "/srv/watchtower", "memory": mem(970000, 53000000)},
                {"name": "cache", "memory": mem(5000, 100)},                  # at its limit, cache not re-read
                {"name": "db", "memory": mem(0, 0, oom=2)},
                {"name": "fresh", "memory": mem(2000, 20000, since="2026-01-03T23:30:00Z")},   # half an hour old
                {"name": "plain"}]}}}))
        md = run("overview.py", "--no-ansible", "--out", "-", cwd=self.d).stdout
        self.assertIn("3 containers at their memory limit", md.split("\n## ")[1])          # At a glance
        health = md.split("\n## Health")[1]
        self.assertIn("- docker1: container watchtower at its 32 MiB memory limit (hit 13472/h, 736111 pages re-read/h "
                      "since 2026-01-01): raise mem\\_limit in /srv/watchtower", health)
        self.assertIn("- docker1: container db at its 32 MiB memory limit (2 OOM kills since 2026-01-01)", health)
        self.assertIn("container fresh at its 32 MiB memory limit (hit 2000/h, 20000 pages", health)   # per first hour
        self.assertNotIn("container cache", md)
        self.assertNotIn("container plain", md)
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/docker-containers.yml").read_text()
        task = pb.split("- name: Memory counters of running containers with a memory limit")[1].split("\n        - name:")[0]
        self.assertIn("/proc/$p/cgroup", task)                       # any cgroup driver, Docker and Podman
        self.assertIn("failed_when: false", task)
        self.assertNotRegex(task, r"\b(echo [^\"]*>|tee|rm|kill|docker (stop|update|restart))\b")   # read-only
        self.assertIn("(c.HostConfig.Memory | default(0, true) | int) > 0", task)
        self.assertIn("'since': c.State.StartedAt", pb)
        self.assertIn("`memory`", (SCRIPTS.parent / "references/discovery.md").read_text())

    def test_contents_and_folding(self):  # GitHub issue #113
        sys.path.insert(0, str(SCRIPTS))
        import overview
        seen = {}
        self.assertEqual([overview.slug(t, seen) for t in ("Guests", "Guests", "Site: home (Home)", "a\\_b &lt;x&gt;",
                                                           "Guests")],
                         ["guests", "guests-1", "site-home-home", "a_b-x", "guests-2"])
        md = run("overview.py", "--no-ansible", "--out", "-", cwd=self.d).stdout
        self.assertIn("## Contents\n\n- [Site: default](#site-default) — [Map](#map) · [Network](#network) · ", md)
        self.assertIn("- [Health](#health)\n- [Sources](#sources)\n", md)
        self.assertIn("[↑ Contents](#contents)", md)
        self.assertLess(md.index("## At a glance"), md.index("## Contents"))
        r = run("config_set.py", "sites+={name: home}", "sites+={name: lab2, label: Lab 2, ranges: [10.8.0.0/16]}",
                cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        snap = json.loads(Path(self.d, "discovery/proxmox.json").read_text())
        snap["guests"] += [{"vmid": 200 + i, "name": f"g{i}", "type": "lxc", "node": "pve1", "template": False}
                           for i in range(overview.FOLD_ROWS)]
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(snap))
        md = run("overview.py", "--no-ansible", "--out", "-", cwd=self.d).stdout
        self.assertIn("### Guests (home)\n\n<details><summary>17 guests</summary>\n\n| VMID |", md)
        self.assertIn("- [Site: home](#site-home) — [Map](#map-home) · [Network](#network-home) · ", md)
        self.assertIn("- [Site: lab2 (Lab 2)](#site-lab2-lab-2) — [Map](#map-lab2)", md)
        for anchor in re.findall(r"\]\(#([^)]+)\)", md):                                     # every link resolves
            seen, slugs = {}, set()
            for line in md.splitlines():
                m = re.match(r"#{1,3} (.+)$", line)
                if m:
                    slugs.add(overview.slug(m.group(1), seen))
            self.assertIn(anchor, slugs)

    def test_mermaid_label_and_redaction(self):
        sys.path.insert(0, str(SCRIPTS))
        import overview
        self.assertEqual(overview.label('a"b<c>[d]|e;f'), "a'b'c''d''e'f")
        run("config_set.py", "overview.redact=true", cwd=self.d)
        md = run("overview.py", "--no-ansible", "--out", "-", cwd=self.d).stdout
        self.assertNotIn("10.9.20.", md)
        self.assertNotIn("lab.example", md)
        self.assertNotIn("BC:24:11", md)
        self.assertIn("x.x.x.x", md)


class OverviewCollectorTests(unittest.TestCase):  # GitHub issue #89: data for the remaining OVERVIEW.md sections
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory
        self.inv = proxmox_inventory

    LOG_NEW = ["INFO: starting new backup job: vzdump 101 102 --mode snapshot --storage pbs1 --mailnotification always",
               "INFO: Starting Backup of VM 101 (qemu)",
               "INFO: creating Proxmox Backup Server archive 'vm/101/2026-03-02T01:00:11Z'",
               "ERROR: unable to freeze guest fs - failed to open /data: Permission denied",
               "INFO: Finished Backup of VM 101 (00:00:19)",
               "INFO: Starting Backup of VM 102 (lxc)",
               "ERROR: Backup of VM 102 failed - unable to open file '/etc/pve/nodes/pve1/lxc/102.conf.tmp'",
               "INFO: Backup job finished with errors"]
    LOG_OLD = ["INFO: starting new backup job: vzdump 101 102 --storage nfs1",
               "INFO: Starting Backup of VM 102 (lxc)",
               "INFO: creating vzdump archive '/mnt/pve/nfs1/dump/vzdump-lxc-102-2026_03_01-01_00_00.tar.zst'",
               "INFO: Finished Backup of VM 102 (00:00:30)"]

    def test_parse_backup_log(self):
        r = self.inv.parse_backup_log(self.LOG_NEW, 1772413200)
        self.assertEqual(r[101], {"ok": True, "at": "2026-03-02T01:00:11Z", "storage": "pbs1"})  # a freeze error is no failure
        self.assertFalse(r[102]["ok"])
        self.assertIn("unable to open file", r[102]["error"])
        self.assertEqual(r[102]["at"], "2026-03-02T01:00:00Z")                                   # task start time
        self.assertEqual(self.inv.parse_backup_log(["INFO: Starting Backup of VM 7 (qemu)"], None)[7]["ok"], False)

    def fake(self, routes):
        import urllib.error
        pve = self.inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        calls = []

        def get(path, **_):
            calls.append(path)
            for key, val in routes.items():
                if path.endswith(key):
                    if val == 403:
                        raise closed_http_error(path, 403, "Forbidden", {}, None)
                    return val
            raise AssertionError(path)
        pve._get = get
        return pve, calls

    def test_last_backups_from_task_logs(self):
        nodes = [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "offline"}]
        guests = [{"vmid": 101, "node": "pve1"}, {"vmid": 102, "node": "pve1"}, {"vmid": 103, "node": "pve1"}]
        pve, calls = self.fake({
            "/nodes/pve1/tasks": [{"upid": "UPID:pve1:new", "status": "job errors", "starttime": 1772413200},
                                  {"upid": "UPID:pve1:run", "status": None, "starttime": 1772413300},
                                  {"upid": "UPID:pve1:old", "status": "OK", "starttime": 1772326800}],
            "UPID%3Apve1%3Anew/log": [{"t": t} for t in self.LOG_NEW],
            "UPID%3Apve1%3Aold/log": [{"t": t} for t in self.LOG_OLD]})
        found, how = self.inv.last_backups(pve, nodes, guests)
        self.assertEqual(how, "ok (2 vzdump task logs)")
        self.assertEqual(found[101], {"last_backup": {"at": "2026-03-02T01:00:11Z", "storage": "pbs1"}})
        self.assertEqual(found[102]["last_backup"], {"at": "2026-03-01T01:00:00Z", "storage": "nfs1"})  # older success
        self.assertEqual(found[102]["backup_error"]["storage"], "pbs1")                                 # newer failure
        self.assertNotIn(103, found)
        self.assertFalse(any("pve2" in c for c in calls))
        pve, _ = self.fake({"/nodes/pve1/tasks": 403})
        self.assertTrue(self.inv.last_backups(pve, nodes, guests)[1].startswith("not read"))

    def test_subscription_certificate_and_kept_backups(self):
        pve, _ = self.fake({"/subscription": {"status": "active", "level": "c", "nextduedate": "2027-01-31",
                                              "key": "pve2c-secret", "serverid": "ABC"},
                            "/certificates/info": [
                                {"filename": "pve-ssl.pem", "notafter": 1830919537, "subject": "/CN=pve1"},
                                {"filename": "pveproxy-ssl.pem", "notafter": 1800000000,
                                 "subject": "/C=CZ/O=Home/CN=Proxmox VE", "issuer": "/CN=Home CA"}]})
        self.assertEqual(self.inv.subscription(pve, "pve1"), {"status": "active", "level": "c", "next_due": "2027-01-31"})
        self.assertEqual(self.inv.web_certificate(pve, "pve1"), {"file": "pveproxy-ssl.pem", "subject": "Proxmox VE",
                                                                 "issuer": "Home CA", "not_after": "2027-01-15T08:00:00Z"})
        pve, _ = self.fake({"/subscription": 403, "/certificates/info": 403})
        self.assertIsNone(self.inv.subscription(pve, "pve1"))
        self.assertIsNone(self.inv.web_certificate(pve, "pve1"))
        old = {"guests": [{"vmid": 101, "type": "vm", "config": {}, "last_backup": {"at": "x"}}]}
        new = self.inv.keep_details(old, {"guests": [{"vmid": 101, "type": "vm"}]})
        self.assertEqual(new["guests"][0]["last_backup"], {"at": "x"})

    def test_nmap_reads_tls_certificate(self):
        import nmap_scan
        self.assertIn("ssl-cert", nmap_scan.PROFILES["services"])
        self.assertNotIn("--script", nmap_scan.PROFILES["ping"])
        f = Path(tempfile.mkdtemp()) / "s.xml"
        self.addCleanup(shutil.rmtree, f.parent)
        f.write_text('<nmaprun><host><status state="up"/><address addr="10.0.20.11" addrtype="ipv4"/><ports>'
                     '<port protocol="tcp" portid="443"><state state="open"/><service name="https"/>'
                     '<script id="ssl-cert" output="..."><table key="subject"><elem key="commonName">web|x</elem>'
                     '</table><table key="issuer"><elem key="organizationName">Home CA</elem></table>'
                     '<table key="extensions"><table><elem key="name">X509v3 Subject Alternative Name</elem>'
                     '<elem key="value">DNS:web.lab.example, IP Address:10.0.20.11, DNS:www.lab.example</elem></table>'
                     '</table><table key="validity"><elem key="notBefore">2026-01-01T00:00:00</elem>'
                     '<elem key="notAfter">2026-04-01T00:00:00</elem></table></script></port>'
                     '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
                     '</ports></host></nmaprun>')
        (h,) = nmap_scan.parse_xml(f)
        self.assertEqual(h["ports"][0]["tls"], {"subject": "web|x", "issuer": "Home CA", "not_after": "2026-04-01T00:00:00",
                                                "names": ["web.lab.example", "www.lab.example"]})
        self.assertNotIn("tls", h["ports"][1])

    def test_routeros_reads_nat_rules(self):
        import routeros_audit as ra
        self.assertIn("/ip firewall nat print", ra.COMMANDS["nat"][0])
        out = (' 0    comment=web chain=dstnat action=dst-nat to-addresses=10.0.20.5 to-ports=443 protocol=tcp '
               'in-interface-list=WAN dst-port=443\n 1 X  chain=srcnat action=masquerade out-interface-list=WAN\n')
        dev = ra.collect("r1", "u", 22, 5, runner=lambda h, u, p, t, cmd: (True, out if "nat" in cmd else
                                                                              "board-name: hEX\nversion: 7.20\n"))
        self.assertEqual([(r.get("chain"), r.get("to-addresses"), r["_flags"]) for r in dev["nat"]],
                         [("dstnat", "10.0.20.5", ""), ("srcnat", None, "X")])

    def test_dst_nat_rules_and_ports(self):
        import hmlib
        dev = {"nat": [{"chain": "dstnat", "action": "dst-nat", "_flags": ""},
                       {"chain": "dstnat", "action": "dst-nat", "_flags": "X"},
                       {"chain": "dstnat", "action": "netmap", "disabled": "yes"},
                       {"chain": "srcnat", "action": "masquerade"}, "junk"]}
        self.assertEqual(len(hmlib.dst_nat_rules(dev)), 1)
        self.assertEqual(hmlib.nat_ports("80,443,8000-8002"), {80, 443, 8000, 8001, 8002})
        self.assertIsNone(hmlib.nat_ports(""))
        self.assertIsNone(hmlib.nat_ports("!22"))
        self.assertEqual(len(hmlib.nat_ports("1-65535", limit=10)), 10)

    def test_guest_nic_addresses_skip_dhcp(self):
        import hmlib
        g = {"config": {"net0": "name=eth0,ip=dhcp,ip6=auto", "net1": "name=eth1,ip=192.0.2.9/24,ip6=2001:db8::9/64",
                        "ipconfig0": "ip=dhcp", "net2": "name=eth2,ip=manual"}}
        self.assertEqual([a["ip"] for a in hmlib.guest_nic_addresses(g)], ["192.0.2.9", "2001:db8::9"])


if __name__ == "__main__":
    unittest.main()
