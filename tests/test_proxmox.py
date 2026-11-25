"""Tests for Proxmox: VMID scheme, token ACLs, snapshots (pve_snapshot.py, lxd_snapshot.py), node patch plan, TLS."""
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


class VmidSchemeTests(unittest.TestCase):
    """#6: VMIDs that encode the network (vmid_scheme), and a warning when the ranges don't fit."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox", cwd=self.d)
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib
        lxc = lambda vmid, tag, ip: {"vmid": vmid, "name": f"g{vmid}", "type": "lxc", "template": False,
                                     "config": {"net0": f"name=eth0,bridge=vmbr0,ip={ip}/24,tag={tag}"}}
        self.guests = [lxc(1020015, 1020, "10.20.0.15"), lxc(1020016, 1020, "10.20.0.16"),
                       lxc(30007, 30, "10.30.0.7"), {"vmid": 9050, "name": "tpl", "template": True}]
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps({"guests": self.guests}))
        Path(self.d, "tofu/environments/homelab/homelab.auto.tfvars").write_text(
            Path(self.d, "tofu/environments/homelab/homelab.auto.tfvars").read_text() + "\n# vm_id = 101\nx = {\n  vm_id = 100\n}\n")

    def tearDown(self):
        shutil.rmtree(self.d)

    def cfg(self):
        return self.h.load_config(self.d)

    def test_ranges_by_default_and_warning_suggests_scheme(self):
        r = run("proxmox_inventory.py", "--next-vmid", "vms", cwd=self.d)
        self.assertEqual(r.stdout.strip(), "101", r.stderr)  # 100 is in tfvars
        self.assertEqual(run("proxmox_inventory.py", "--next-vmid", "templates", cwd=self.d).stdout.strip(), "9051")
        warn = self.h.vmid_fit(self.cfg(), self.guests)
        self.assertIn("3 of 4 existing guests have VMIDs outside vmid_ranges", warn)
        self.assertIn("vmid_scheme={vlan}{octet:03d}", warn)

    def test_scheme(self):
        self.assertEqual(run("config_set.py", "vmid_scheme={vlan}{octet:03d}", cwd=self.d).returncode, 0)
        self.assertIsNone(self.h.vmid_fit(self.cfg(), self.guests))
        r = run("proxmox_inventory.py", "--next-vmid", "lxc", "--ip", "10.20.0.17/24", "--vlan", "1020", cwd=self.d)
        self.assertEqual(r.stdout.strip(), "1020017", r.stderr)
        r = run("proxmox_inventory.py", "--next-vmid", "vms", "--ip", "10.20.0.15", "--vlan", "1020", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already used by lxc g1020015", r.stderr)
        r = run("proxmox_inventory.py", "--next-vmid", "vms", "--ip", "10.20.0.18", cwd=self.d)
        self.assertIn("needs the guest's VLAN tag", r.stderr)
        self.assertEqual(run("proxmox_inventory.py", "--next-vmid", "templates", cwd=self.d).stdout.strip(), "9051")
        with self.assertRaises(self.h.ConfigError):
            self.h.vmid_from_scheme("{vlan}{octet:03d}", "10.0.0.5", 0)  # 5 < 100
        self.assertIn("Only 0 of 3", self.h.vmid_fit({"vmid_scheme": "{o3}{octet:03d}"}, self.guests))

    def test_vlan_by_name(self):  # issue 34
        run("config_set.py", "vmid_scheme={vlan}{octet:03d}",
            "network.vlans+={id: 1020, name: DMZ, cidr: 10.20.0.0/24, gw: 10.20.0.1}", cwd=self.d)
        r = run("proxmox_inventory.py", "--next-vmid", "lxc", "--ip", "10.20.0.17", "--vlan", "dmz", cwd=self.d)
        self.assertEqual(r.stdout.strip(), "1020017", r.stderr)
        r = run("proxmox_inventory.py", "--next-vmid", "lxc", "--ip", "10.20.0.17", "--vlan", "IoT", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("known: DMZ (1020)", r.stderr)
        cfg = self.cfg()
        self.assertEqual(self.h.vlan_label(cfg, ip="10.20.0.9"), "VLAN 1020 DMZ")
        self.assertEqual(self.h.vlan_label(cfg, 30), "VLAN 30")
        self.assertEqual(self.h.vlan_label(cfg, ip="10.30.0.9"), "")


class TokenAclTests(unittest.TestCase):
    """#5: privilege-separated tokens only get what their user also has."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        run("init_repo.py", str(self.d), "--components", "proxmox", cwd=self.d)
        self.doc = self.d / "docs/proxmox-tokens.md"

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_template_grants_user_and_token(self):
        text = self.doc.read_text()
        for role, tid in (("PVEAuditor", "ro"), ("HomelabProvisioner", "rw")):
            self.assertIn(f"pveum acl modify / --users homelab@pve --roles {role}", text)
            self.assertIn(f"pveum acl modify / --tokens 'homelab@pve!{tid}' --roles {role}", text)
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout)

    def test_old_doc_gets_user_acls_once(self):
        text = self.doc.read_text()
        text = re.sub(r"\nOptional — VM IPs.*?\n```\n", "", text, flags=re.S)  # added in 0.11.0
        text = re.sub(r"\n### Backup jobs \(optional\).*?\n```\n", "", text, flags=re.S)  # added in 0.17.0
        text = re.sub(r"\n### PCI passthrough \(optional\).*?\n```\n", "", text, flags=re.S)  # added in 0.61.0
        old = "\n".join(l for l in text.splitlines() if "--users" not in l) + "\n"
        old = old.split("Both tokens use privilege separation")[0].rstrip("\n") + "\n\n## " + old.split("\n## ", 1)[1]
        old = old.replace("/ --tokens 'homelab@pve!rw'", "/pool/lab --tokens 'homelab@pve!rw'")  # user-edited path
        self.doc.write_text(old)
        out = run("init_repo.py", str(self.d), "--sync-managed", "--dry-run", cwd=self.d).stdout
        self.assertIn("docs/proxmox-tokens.md: grant the token roles to the user too (2 ACL line(s)", out)
        self.assertEqual(self.doc.read_text(), old)
        run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d)
        new = self.doc.read_text()
        self.assertIn("pveum acl modify / --users homelab@pve --roles PVEAuditor\n"
                      "pveum acl modify / --tokens 'homelab@pve!ro'", new)
        self.assertIn("pveum acl modify /pool/lab --users homelab@pve --roles HomelabProvisioner\n"
                      "pveum acl modify /pool/lab --tokens", new)
        self.assertEqual(new.count("Both tokens use privilege separation"), 1)
        self.assertLess(new.index("Both tokens"), new.index("## Read-only"))
        self.assertIn("Up to date", run("init_repo.py", str(self.d), "--sync-managed", cwd=self.d).stdout)


class InventoryErrorTests(unittest.TestCase):
    """One node or guest failing (HTTP 500/595, a timeout, broken JSON) must not lose the rest of the snapshot."""

    def test_failing_node_and_guest_are_recorded(self):
        import socket
        import urllib.error
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        resources = [{"type": "node", "node": n, "status": "online", "maxcpu": 4, "cpu": 0.1, "maxmem": 2 ** 33,
                      "mem": 2 ** 32} for n in ("pve1", "pve2")]
        resources += [{"type": t, "vmid": v, "name": f"g{v}", "node": n, "status": "running", "maxcpu": 1,
                       "maxmem": 2 ** 30, "maxdisk": 2 ** 33}
                      for t, v, n in (("qemu", 101, "pve1"), ("qemu", 102, "pve2"), ("lxc", 201, "pve1"))]

        def fake(path, **_):
            if path == "/version":
                return {"version": "9.0.3"}
            if path == "/cluster/resources":
                return resources
            if path.startswith("/nodes/pve2/network"):
                raise closed_http_error(path, 500, "Internal Server Error", {}, None)
            if path.startswith("/nodes/pve2/status"):
                raise socket.timeout("timed out")
            if path.endswith("/qemu/102/config"):
                raise ValueError("Expecting value")
            if path.endswith("/config"):
                return {"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0"}
            if path.startswith("/nodes/pve1/status"):
                return {"pveversion": "pve-manager/9.0.3"}
            return [] if not path.endswith(("/subscription", "/current")) else {}
        pve._get = fake
        snap = inv.collect(pve, details=True)
        self.assertEqual([n["node"] for n in snap["nodes"]], ["pve1", "pve2"])
        self.assertEqual([g["vmid"] for g in snap["guests"]], [101, 102, 201])
        self.assertIn("config", snap["guests"][0])
        self.assertNotIn("config", snap["guests"][1])
        self.assertEqual(snap["nodes"][0]["pveversion"], "pve-manager/9.0.3")
        errs = "\n".join(snap["errors"])
        self.assertIn("node pve2 network: Proxmox API refused /nodes/pve2/network (500)", errs)
        self.assertIn("node pve2 status: Proxmox API /nodes/pve2/status: timed out", errs)
        self.assertIn("guest 102 config: Proxmox API /nodes/pve2/qemu/102/config: the answer is not valid JSON", errs)
        self.assertEqual(len(snap["errors"]), 3)
        text = inv.summary(snap)
        self.assertIn("Not read (3 API call(s) failed", text)

    def test_unreachable_is_a_pve_error(self):
        import urllib.error
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)

        def down(path, **_):
            raise urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
        pve._get = down
        with self.assertRaises(inv.PveError) as e:
            pve.get("/version")
        self.assertIn("Cannot reach Proxmox", str(e.exception))
        self.assertIsInstance(e.exception, SystemExit)   # scripts that don't catch it still end with the message


class StorageHealthCollectTests(unittest.TestCase):
    """GitHub issues #151, #152: ZFS, disks, replication, Ceph and PBS datastores, from recorded (invented) answers."""

    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory
        self.inv = proxmox_inventory
        self.calls = []

    def fake(self, answers: dict):
        """A PVE whose _get answers from `answers` (an Exception is raised, a missing path is [])."""
        pve = self.inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)

        def get(path, **params):
            self.calls.append(path)
            a = answers.get(path, [])
            if isinstance(a, Exception):
                raise a
            return a
        pve._get = get
        return pve

    def base(self, storage_conf: list | None = None) -> dict:
        nodes = [{"type": "node", "node": n, "status": "online", "maxcpu": 4, "maxmem": 2 ** 34} for n in ("pve1", "pve2")]
        return {"/version": {"version": "9.1.1"}, "/cluster/resources": nodes, "/storage": storage_conf or [],
                "/nodes/pve1/status": {}, "/nodes/pve2/status": {}}

    def test_zfs_disks_replication_ceph(self):
        a = self.base([{"storage": "ceph-vm", "type": "rbd", "pool": "vm"}])
        a.update({
            "/nodes/pve1/disks/zfs": [{"name": "tank", "health": "DEGRADED", "size": 2 ** 41, "alloc": 2 ** 40}],
            "/nodes/pve1/disks/zfs/tank": {
                "name": "tank", "state": "DEGRADED", "errors": "No known data errors",
                "scan": "scrub repaired 0B in 01:02:03 with 2 errors on Sun Oct  4 01:26:03 2026",
                "children": [{"name": "tank", "state": "DEGRADED", "read": 0, "write": 0, "cksum": 0, "children": [
                    {"name": "mirror-0", "state": "DEGRADED", "read": 0, "write": 0, "cksum": 0, "children": [
                        {"name": "ata-DISK-A", "state": "ONLINE", "read": 0, "write": 0, "cksum": 0, "leaf": 1},
                        {"name": "ata-DISK-B", "state": "FAULTED", "read": 3, "write": 0, "cksum": "1.2K",
                         "leaf": 1, "msg": "too many errors"}]}]}]},
            "/nodes/pve1/disks/list": [
                {"devpath": "/dev/sda", "type": "ssd", "model": "SSD X", "health": "PASSED", "wearout": 12, "used": "ZFS"},
                {"devpath": "/dev/sdb", "type": "hdd", "model": "HDD Y", "health": "FAILED", "wearout": "N/A",
                 "used": "ZFS"},
                {"devpath": "/dev/nvme0n1", "type": "nvme", "model": "NVMe Z", "health": "PASSED", "wearout": 100}],
            "/nodes/pve2/disks/zfs": closed_http_error("u", 403, "Permission check failed", {}, None),
            "/nodes/pve2/disks/list": closed_http_error("u", 500, "smartctl hung", {}, None),
            "/cluster/replication": [{"id": "101-0", "guest": 101, "target": "pve2", "source": "pve1"},
                                     {"id": "102-0", "guest": 102, "target": "pve1", "source": "pve2", "disable": 1}],
            "/nodes/pve1/replication": [{"id": "101-0", "guest": 101, "source": "pve1", "target": "pve2",
                                         "last_sync": 1790000000, "next_sync": 1790000900, "fail_count": 2,
                                         "error": "no space left on device"}],
            "/nodes/pve2/replication": [],
            "/cluster/ceph/status": {"health": {"status": "HEALTH_WARN", "checks": {
                "OSD_DOWN": {"severity": "HEALTH_WARN", "summary": {"message": "1 osds down"}},
                "MUTED_ONE": {"severity": "HEALTH_WARN", "muted": True, "summary": {"message": "ignored"}}}}}})
        snap = self.inv.collect(self.fake(a), details=False)
        pve1, pve2 = snap["nodes"]
        pool = pve1["zfs"][0]
        self.assertEqual((pool["pool"], pool["state"], pool["scrub_at"], pool["scrub_errors"]),
                         ("tank", "DEGRADED", "2026-10-04", 2))
        self.assertEqual(pool["bad_devices"], ["ata-DISK-B FAULTED (read/write/cksum 3/0/1.2K)"])
        self.assertEqual([(d["dev"], d["health"], d.get("wear_pct")) for d in pve1["disks"]],
                         [("/dev/nvme0n1", "PASSED", 0), ("/dev/sda", "PASSED", 88), ("/dev/sdb", "FAILED", None)])
        self.assertNotIn("zfs", pve2)
        self.assertNotIn("disks", pve2)
        health = snap["storage_health"]
        self.assertIn("pve2: forbidden: the read-only token needs Sys.Audit", health["zfs"])
        self.assertIn("pve2: 500 smartctl hung", health["disks"])
        self.assertEqual((health["replication"], health["ceph"]), ("ok", "ok"))
        self.assertNotIn("errors", snap)   # a failed health read is a note, not a failed API call
        self.assertEqual(snap["replication"][0], {"id": "101-0", "guest": 101, "source": "pve1", "target": "pve2",
                                                  "enabled": True, "last_sync": "2026-09-21T14:13:20Z",
                                                  "next_sync": "2026-09-21T14:28:20Z", "fail_count": 2,
                                                  "error": "no space left on device"})
        self.assertEqual(snap["replication"][1]["enabled"], False)
        self.assertEqual(snap["ceph"], {"health": "HEALTH_WARN", "checks": [
            {"check": "OSD_DOWN", "severity": "HEALTH_WARN", "message": "1 osds down"}]})
        text = self.inv.summary(snap)
        self.assertIn("ZFS: pve1/tank DEGRADED (scrub 2026-10-04, 2 errors)", text)
        self.assertIn("Disks: 3, SMART not passed: 1, most worn 88%", text)
        self.assertIn("zfs not read — not read: pve2: forbidden", text)

    def test_nodes_without_ceph_or_replication_are_quiet(self):
        a = self.base([{"storage": "ext-ceph", "type": "rbd", "monhost": "10.0.0.1"}])   # someone else's Ceph
        a["/cluster/ceph/status"] = closed_http_error("u", 500, "binary not installed: /usr/bin/ceph-mon", {}, None)
        snap = self.inv.collect(self.fake(a), details=False)
        self.assertNotIn("/cluster/ceph/status", self.calls)
        self.assertNotIn("ceph", snap)
        self.assertEqual(snap["replication"], [])
        self.assertEqual(snap["storage_health"], {"zfs": "ok", "disks": "ok", "replication": "ok"})
        self.assertEqual([n["zfs"] for n in snap["nodes"]], [[], []])
        self.assertNotIn("Storage health", self.inv.summary(snap))
        # a hyper-converged Ceph that can't be read says so once; a replication list refused leaves it None
        a = self.base([{"storage": "ceph-vm", "type": "rbd"}])
        a["/cluster/ceph/status"] = closed_http_error("u", 500, "rados_connect failed", {}, None)
        a["/cluster/replication"] = closed_http_error("u", 403, "Permission check failed", {}, None)
        snap = self.inv.collect(self.fake(a), details=False)
        self.assertEqual(snap["storage_health"]["ceph"], "not read: 500 rados_connect failed")
        self.assertIsNone(snap["replication"])
        self.assertIn("forbidden", snap["storage_health"]["replication"])

    def test_zfs_scan_lines(self):
        scan = self.inv.zfs_scan
        self.assertEqual(scan("scrub repaired 0B in 00:05:41 with 0 errors on Sun Nov  8 00:29:43 2026"),
                         {"scrub_at": "2026-11-08", "scrub_errors": 0})
        self.assertEqual(scan("scrub in progress since Sun Nov  8 00:24:01 2026\n1.2T scanned"), {"scrub_running": True})
        for other in ("none requested", "resilvered 1.5G in 00:01:00 with 0 errors on Sun Nov  8 00:24:01 2026",
                      "scrub canceled on Sun Nov  8 00:24:01 2026", "", None):
            self.assertEqual(scan(other), {})

    def pbs_snapshot(self, opener):
        a = self.base([{"storage": "pbs-a", "type": "pbs", "server": "pbs.example", "datastore": "store1",
                        "fingerprint": "AA:BB"},
                       {"storage": "pbs-a2", "type": "pbs", "server": "pbs.example", "datastore": "store1",
                        "fingerprint": "AA:BB"},
                       {"storage": "pbs-ns", "type": "pbs", "server": "pbs.example", "datastore": "store2",
                        "namespace": "site/a"},
                       {"storage": "pbs-off", "type": "pbs", "server": "pbs.example", "datastore": "x", "disable": 1}])
        return self.inv.collect(self.fake(a), details=False, pbs=opener)

    def test_pbs_datastores(self):
        seen = []

        class FakePbs:
            def get(self, path, **params):
                seen.append((path, params))
                if path == "/admin/gc":
                    return [{"store": "store1", "schedule": "daily", "last-run-state": "OK",
                             "last-run-endtime": 1790000000, "next-run": 1790086400, "upid": "UPID:x"},
                            {"store": "store2", "schedule": "daily", "upid": "UPID:y"}]   # running
                if path == "/admin/prune":
                    return [{"id": "p1", "store": "store1", "schedule": "daily",
                             "last-run-state": "ERROR: datastore is locked", "last-run-endtime": 1790000000}]
                if path == "/admin/verify":
                    return [{"id": "v1", "store": "store1", "schedule": "daily", "last-run-state": "OK",
                             "last-run-endtime": 1790000000},
                            {"id": "v2", "store": "store2", "last-run-upid": "UPID:z"}]
                if path == "/admin/datastore/store1/snapshots":
                    return [{"backup-type": "vm", "backup-id": "101", "backup-time": 1789000000,
                             "verification": {"state": "ok"}},
                            {"backup-type": "vm", "backup-id": "101", "backup-time": 1789900000,
                             "verification": {"state": "failed"}},
                            {"backup-type": "ct", "backup-id": "102", "backup-time": 1789950000}]
                if path == "/admin/datastore/store2/snapshots":
                    raise self_inv.PbsError("403: the PBS token (and its user) need the DatastoreAudit role", 403)
                raise AssertionError(path)
        self_inv = self.inv
        opened = []

        def opener(server, port, fingerprint):
            opened.append((server, port, fingerprint))
            return FakePbs(), ""
        snap = self.pbs_snapshot(opener)
        self.assertEqual(opened, [("pbs.example", 8007, "AA:BB")])   # one client per server
        self.assertIn(("/admin/datastore/store2/snapshots", {"ns": "site/a"}), seen)
        ds1, ds2 = snap["pbs_datastores"]
        self.assertEqual(ds1["storages"], ["pbs-a", "pbs-a2"])
        self.assertEqual(ds1["gc"], {"schedule": "daily", "state": "OK", "at": "2026-09-21T14:13:20Z",
                                     "next": "2026-09-22T14:13:20Z"})
        self.assertEqual(ds1["prune"][0]["state"], "ERROR: datastore is locked")
        self.assertEqual(ds1["snapshots"], {"count": 3, "verified": 1, "failed": 1, "newest": "2026-09-21T00:20:00Z",
                                            "newest_verified": "2026-09-10T00:26:40Z",
                                            "oldest_unverified": "2026-09-21T00:20:00Z"})
        self.assertEqual((ds2["namespace"], ds2["gc"]["state"], ds2["verify"][0]["state"]), ("site/a", "running", "running"))
        self.assertIn("snapshots: 403", ds2["errors"][0])
        self.assertEqual(snap["storage_health"]["pbs"], "ok (2 of 2 datastores read)")
        self.assertNotIn("x", [d["datastore"] for d in snap["pbs_datastores"]])   # a disabled storage

    def test_pbs_without_token_or_refused(self):
        snap = self.pbs_snapshot(lambda *a: (None, ""))
        self.assertEqual(snap["storage_health"]["pbs"], "no token for pbs.example (pbs: in homelab.yaml, "
                                                        "docs/proxmox-tokens.md) (0 of 2 datastores read)")
        self.assertNotIn("snapshots", snap["pbs_datastores"][0])

        class Refused:
            def get(self, path, **params):
                raise inv.PbsError("401: the PBS token or its secret is wrong, or the token was removed", 401)
        inv = self.inv
        snap = self.pbs_snapshot(lambda *a: (Refused(), ""))
        self.assertEqual({d.get("error") for d in snap["pbs_datastores"]},
                         {"401: the PBS token or its secret is wrong, or the token was removed"})
        self.assertIn("pbs.example: 401", snap["storage_health"]["pbs"])
        snap = self.pbs_snapshot(lambda *a: (None, "Keychain item 'homelab/pbs-ro' not readable (exit 44)."))
        self.assertIn("not readable", snap["pbs_datastores"][0]["error"])

    def test_pbs_token_header_and_config(self):
        self.assertEqual(self.inv.pbs_token("homelab@pbs!ro:abc=1"), "homelab@pbs!ro:abc=1")
        self.assertEqual(self.inv.pbs_token("homelab@pbs!ro=abc"), "homelab@pbs!ro:abc")
        p = self.inv.PBS("fd00::5", 8007, "homelab@pbs!ro=abc", None, "AA:bb:01")
        self.assertEqual((p.fingerprint, p.headers["Authorization"]), ("aabb01", "PBSAPIToken=homelab@pbs!ro:abc"))
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        cfg = {"pbs": [{"server": ["PBS1.example", "10.0.0.9"], "token": "pbs-ro"}, {"server": "pbs2", "token": "t2"}]}
        self.assertEqual(hmlib.pbs_server(cfg, "pbs1.EXAMPLE")["token"], "pbs-ro")
        self.assertEqual(hmlib.pbs_server(cfg, "10.0.0.9")["token"], "pbs-ro")
        self.assertIsNone(hmlib.pbs_server(cfg, "other"))
        for bad in ([{"server": "a"}], [{"server": "a", "token": "t", "user": "x"}], {"server": "a"},
                    [{"server": "a", "token": "t"}, {"server": "A", "token": "u"}]):
            with self.assertRaises(hmlib.ConfigError):
                hmlib.pbs_servers({"pbs": bad})
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", d, "--components", "proxmox", cwd=d)
        r = run("config_set.py", "pbs+={server: pbs.example}", cwd=d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("needs server", r.stdout + r.stderr)
        r = run("config_set.py", "pbs+={server: pbs.example, token: pbs-ro}", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)


class PveSnapshotTests(unittest.TestCase):  # issue 37
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import pve_snapshot
        import proxmox_inventory
        self.s = pve_snapshot
        self.pve = proxmox_inventory.PVE("https://pve.example:8006", "homelab@pve!rw=s3cret", None)
        self.snaps = {101: [{"name": "current"}, {"name": "old", "snaptime": 1}]}
        self.calls = []

        def get(path, _method="GET", **params):
            self.calls.append((_method, path, params))
            if path == "/cluster/resources":
                return [{"type": "qemu", "vmid": 101, "name": "web01", "node": "pve1"},
                        {"type": "lxc", "vmid": 901, "name": "dns", "node": "pve2"},
                        {"type": "qemu", "vmid": 9050, "name": "tpl", "node": "pve1", "template": 1},
                        {"type": "storage", "id": "x"}]
            if path.endswith("/status"):
                return {"status": "stopped", "exitstatus": "OK"}
            if path.endswith("/snapshot") and _method == "GET":
                return self.snaps.get(int(path.split("/")[4]), [{"name": "current"}])
            return "UPID:pve1:1"
        self.pve.get = get

    def test_multi_guest_create_goes_on_after_a_failure(self):
        orig = self.pve.get

        def get(path, _method="GET", **params):
            if _method == "POST" and "/101/" in path:
                raise self.s.PveError("Proxmox API refused POST /nodes/pve1/qemu/101/snapshot (500): storage full")
            return orig(path, _method, **params)
        self.pve.get = get
        gs = self.s.find_guests(self.pve, ["web01", "dns"])
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            problems = self.s.apply(self.pve, "create", gs, "prepatch-1")
        self.assertEqual(len(problems), 1)
        self.assertIn("101 web01: Proxmox API refused", problems[0])
        self.assertIn("901 dns: create 'prepatch-1' done", out.getvalue())
        self.assertIn("create: done for 1, failed for 1", out.getvalue())

    def test_wait_retries_a_transient_status_error(self):
        answers = [self.s.PveError("timed out"), self.s.PveError("595"), {"status": "running"},
                   {"status": "stopped", "exitstatus": "OK"}]

        def status(path, **_):
            a = answers.pop(0)
            if isinstance(a, BaseException):
                raise a
            return a
        self.pve.get = status
        self.s.wait(self.pve, "pve1", "UPID", "create", sleep=lambda _: None)
        self.assertEqual(answers, [])
        self.pve.get = lambda path, **_: (_ for _ in ()).throw(self.s.PveError("down"))
        with self.assertRaises(SystemExit) as e:
            self.s.wait(self.pve, "pve1", "UPID", "create", sleep=lambda _: None)
        self.assertIn("cannot read the task status", str(e.exception))

    def test_prune_and_dry_run(self):
        day = 86400
        now = 100 * day
        snaps = [{"name": "prepatch-a", "snaptime": now - 40 * day}, {"name": "prepatch-b", "snaptime": now - 2 * day},
                 {"name": "manual", "snaptime": now - 90 * day}, {"name": "prepatch-c", "snaptime": now - 31 * day}]
        self.assertEqual(self.s.prunable(snaps, "prepatch-", 30, now), ["prepatch-a", "prepatch-c"])
        self.assertEqual(self.s.prunable(snaps, "prepatch-", 50, now), [])
        self.snaps[101] = [{"name": "current"}, {"name": "prepatch-old", "snaptime": 1}, {"name": "keep", "snaptime": 1}]
        g = self.s.find_guests(self.pve, ["web01"])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.s.prune(self.pve, g, "prepatch-", 30, dry_run=True), [])
        self.assertIn("would delete prepatch-old", out.getvalue())
        self.assertFalse([c for c in self.calls if c[0] != "GET"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.s.dry_run(self.pve, "rollback", g, "missing"), 1)
            self.assertEqual(self.s.dry_run(self.pve, "create", g, "prepatch-new"), 0)
        self.assertFalse([c for c in self.calls if c[0] != "GET"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.s.prune(self.pve, g, "prepatch-", 30), [])
        self.assertEqual([c[:2] for c in self.calls if c[0] != "GET"],
                         [("DELETE", "/nodes/pve1/qemu/101/snapshot/prepatch-old")])

    def test_infer_site(self):  # issue 83
        cfg = {"_root": "/nonexistent", "proxmox": {"endpoint": "https://pve1.example:8006"},
               "sites": [{"name": "home"}, {"name": "offsite", "ranges": ["192.0.2.0/24"],
                                            "proxmox": {"endpoint": "https://pve-off.example:8006"}}]}
        managed = {"jump": {"ansible_host": "10.0.0.9", "_groups_all": ["linux", "site_offsite"]},
                   "vpn": {"ansible_host": "192.0.2.4"}, "web01": {"ansible_host": "10.0.0.5"}}
        infer = lambda gs: self.s.infer_site(cfg, gs, managed)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(infer(["jump"]), "offsite")                  # site_<name> group
            self.assertEqual(infer(["vpn", "123"]), "offsite")            # ranges; a VMID says nothing
        self.assertIn("site offsite (from the inventory", err.getvalue())
        self.assertIsNone(infer(["web01"]))                               # default site
        self.assertIsNone(infer(["101", "nope"]))
        three = {**cfg, "sites": cfg["sites"] + [{"name": "lab", "ranges": ["10.0.0.0/24"]}]}
        import hmlib
        with self.assertRaises(hmlib.ConfigError) as e:
            self.s.infer_site(three, ["jump", "web01"], managed)
        self.assertIn("guests of different sites (jump: offsite, web01: lab)", str(e.exception))
        self.assertIsNone(self.s.infer_site({"_root": "/x", "proxmox": {"endpoint": "x"}}, ["jump"], managed))

    def test_resolves_guests_by_vmid_or_name(self):
        gs = self.s.find_guests(self.pve, ["web01", "901"])
        self.assertEqual([(g["vmid"], g["type"], g["node"]) for g in gs], [(101, "qemu", "pve1"), (901, "lxc", "pve2")])
        with self.assertRaises(SystemExit):
            self.s.find_guests(self.pve, ["tpl"])
        with self.assertRaises(SystemExit):
            self.s.find_guests(self.pve, ["nope"])

    def test_create_waits_for_task_and_skips_existing(self):
        g = self.s.find_guests(self.pve, ["web01"])[0]
        self.assertEqual([s["name"] for s in self.s.snapshots(self.pve, g)], ["old"])
        self.s.wait(self.pve, "pve1", "UPID:pve1:1", "x")
        self.assertIn(("GET", "/nodes/pve1/tasks/UPID:pve1:1/status", {}), self.calls)

    def test_apply(self):
        gs = self.s.find_guests(self.pve, ["web01", "dns"])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.s.apply(self.pve, "create", gs, "prepatch-20261117")
            self.s.apply(self.pve, "create", gs[:1], "old")        # exists: kept, nothing sent
            self.s.apply(self.pve, "delete", gs[:1], "old")
        writes = [(m, p, prm) for m, p, prm in self.calls if m != "GET"]
        self.assertEqual(writes[0], ("POST", "/nodes/pve1/qemu/101/snapshot",
                                     {"snapname": "prepatch-20261117", "description": "homelab-manager prepatch-20261117",
                                      "vmstate": 0}))
        self.assertEqual(writes[1][1], "/nodes/pve2/lxc/901/snapshot")
        self.assertNotIn("vmstate", writes[1][2])
        self.assertEqual(writes[2], ("DELETE", "/nodes/pve1/qemu/101/snapshot/old", {}))
        self.assertEqual(len(writes), 3)
        self.assertIn("already exists", out.getvalue())
        with self.assertRaises(SystemExit):
            self.s.apply(self.pve, "rollback", gs[1:], "missing")

    def test_rollback_starts_a_guest_that_was_running(self):  # GitHub issue #59
        import pve_guest
        state = {"st": "running", "starts": 0}
        orig = self.pve.get

        def get(path, _method="GET", **params):
            if path.endswith("/status/current"):
                return {"status": state["st"]}
            if path.endswith("/rollback"):
                state["st"] = "stopped"                 # Proxmox's start was not enough: still stopped
            if path.endswith("/status/start"):
                state["st"] = "running"
                state["starts"] += 1
            return orig(path, _method, **params)
        self.pve.get = get
        g = self.s.find_guests(self.pve, ["web01"])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            down = self.s.apply(self.pve, "rollback", g, "old")
        self.assertEqual(down, [])
        self.assertIn(("POST", "/nodes/pve1/qemu/101/snapshot/old/rollback", {"start": 1}), self.calls)
        self.assertEqual(state["starts"], 1)
        self.assertIn("now running", out.getvalue())
        state["st"] = "stopped"                         # stopped before: left stopped, no start option
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.s.apply(self.pve, "rollback", g, "old")
        self.assertIn(("POST", "/nodes/pve1/qemu/101/snapshot/old/rollback", {}), self.calls)
        self.assertEqual(state["starts"], 1)
        self.assertIn("now stopped", out.getvalue())
        state["st"] = "running"
        with contextlib.redirect_stdout(io.StringIO()):
            self.s.apply(self.pve, "rollback", g, "old", start=False)
        self.assertEqual(state["starts"], 1)
        state["st"] = "paused"                          # only a stopped guest is started
        self.assertEqual(pve_guest.start(self.pve, g[0], timeout=0, sleep=lambda _: None), "paused")
        self.assertEqual(state["starts"], 1)

    def test_guest_shutdown_and_stop(self):  # GitHub issue #155
        import pve_guest
        state = {"st": "running", "task": "OK"}
        orig = self.pve.get

        def get(path, _method="GET", **params):
            if path.endswith("/status/current"):
                return {"status": state["st"]}
            if path.endswith("/tasks/UPID:pve1:1/status"):
                return {"status": "stopped", "exitstatus": state["task"]}
            if path.endswith("/status/shutdown") and state["task"] == "OK":
                state["st"] = "stopped"
            if path.endswith("/status/stop"):
                state["st"] = "stopped"
            return orig(path, _method, **params)
        self.pve.get = get
        g = self.s.find_guests(self.pve, ["web01"])[0]
        self.assertEqual(pve_guest.shutdown(self.pve, g, timeout=60, sleep=lambda _: None), ("stopped", None))
        self.assertIn(("POST", "/nodes/pve1/qemu/101/status/shutdown", {"timeout": 60}), self.calls)
        self.assertNotIn("forceStop", str(self.calls))                 # never forced
        n = len(self.calls)                                            # stopped already: nothing is sent
        self.assertEqual(pve_guest.shutdown(self.pve, g, sleep=lambda _: None), ("stopped", None))
        self.assertEqual(pve_guest.stop(self.pve, g, sleep=lambda _: None), ("stopped", None))
        self.assertFalse([c for c in self.calls[n:] if c[0] != "GET"])
        state.update(st="running", task="VM quit/powerdown failed - got timeout")   # the guest ignored it
        st, err = pve_guest.shutdown(self.pve, g, timeout=1, sleep=lambda _: None)
        self.assertEqual(st, "running")
        self.assertIn("got timeout", err)
        state["task"] = "OK"
        self.assertEqual(pve_guest.stop(self.pve, g, sleep=lambda _: None), ("stopped", None))
        self.assertIn(("POST", "/nodes/pve1/qemu/101/status/stop", {}), self.calls)

    def test_failed_task_raises(self):
        self.pve.get = lambda path, **_: {"status": "stopped", "exitstatus": "snapshot feature is not available"}
        with self.assertRaises(SystemExit) as e:
            self.s.wait(self.pve, "pve1", "UPID", "create snapshot")
        self.assertIn("not available", str(e.exception))

    def test_default_name_is_valid(self):
        self.assertRegex(self.s.default_name(), self.s.NAME_RE)

    def test_check_reports_every_guest(self):  # issue 49
        get = self.pve.get
        configs = {"/nodes/pve2/lxc/901/config": {"rootfs": "local-zfs:subvol-901-disk-0",
                                                   "mp0": "local-zfs:subvol-901-disk-1,mp=/data",
                                                   "mp1": "/dev/zvol/tank/vol,mp=/srv/raw"}}

        def with_feature(path, _method="GET", **params):
            if path.endswith("/feature"):
                self.assertEqual(params, {"feature": "snapshot"})
                return {"hasFeature": 1 if "/qemu/101/" in path else 0}
            if path in configs:
                return configs[path]
            return get(path, _method, **params)
        self.pve.get = with_feature
        res = self.s.check(self.pve, ["web01", "dns", "nas-lxd1", "tpl"])
        self.assertEqual(res["ok"], ["web01"])
        self.assertEqual(sorted(res["not_a_guest"]), ["nas-lxd1", "tpl"])
        self.assertIn("mp1: /dev/zvol/tank/vol", res["no_snapshot"]["dns"])
        self.assertNotIn("mp0", res["no_snapshot"]["dns"])
        self.assertFalse([c for c in self.calls if c[0] != "GET"])  # read-only
        with self.assertRaises(SystemExit):                       # the other actions still stop at the first
            self.s.find_guests(self.pve, ["web01", "nas-lxd1"])


class LxdSnapshotTests(unittest.TestCase):  # issue 44
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import lxd_snapshot
        self.l = lxd_snapshot
        self.hosts = {
            "nas1": {"groups": ["appliances"], "ansible_host": "192.0.2.10", "ansible_user": "admin",
                     "lxd_snapshots": True},
            "nas2": {"groups": ["appliances"], "ansible_host": "192.0.2.11", "lxd_cli": "/opt/incus", "lxd_sudo": True},
            "app1.lab.example": {"groups": ["debian"], "lxd_host": "nas1"},
            "app2": {"groups": ["debian"], "lxd_host": "nas1", "lxd_instance": "legacy-app", "lxd_project": "lab"},
            "app3": {"groups": ["debian"], "lxd_host": "nas2"},
            "web01": {"groups": ["rocky"]},
        }
        self.driver = "zfs"
        self.snaps = {"app1": [{"name": "app1/old", "created_at": "2026-01-01T00:00:00Z"}]}
        self.calls = []
        test = self

        def run(t, command, timeout):
            test.calls.append((t["nas"], command))
            if command == self.l.FIND_CLI:
                return 0, "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/lxc\n", ""
            args = shlex.split(command)
            q = args.index("query")
            method = args[args.index("-X") + 1] if "-X" in args else "GET"
            body = json.loads(args[args.index("-d") + 1]) if "-d" in args else None
            path = args[-1].split("?")[0]
            parts = path.split("/")
            if method != "GET":
                test.writes.append((args[:q], method, args[-1], body))
                return 0, "{}", ""
            if path == "/1.0/storage-pools/default":
                return 0, json.dumps({"driver": test.driver}), ""
            if path == "/1.0/storage-pools/default/resources":
                return 0, json.dumps({"space": {"used": 90 * 2**30, "total": 100 * 2**30}}), ""
            if len(parts) == 4 and parts[3] in ("app1", "legacy-app", "app3"):
                return 0, json.dumps({"type": "container", "status": "Running",
                                      "expanded_config": {"snapshots.schedule": "@daily"},
                                      "expanded_devices": {"root": {"type": "disk", "path": "/", "pool": "default"},
                                                           "data": {"type": "disk", "source": "/share/Data", "path": "/data"},
                                                           "vol": {"type": "disk", "pool": "default", "source": "db",
                                                                   "path": "/db"},
                                                           "eth0": {"type": "nic"}}}), ""
            if path.endswith("/state"):
                return 0, json.dumps({"disk": {"root": {"usage": test.usage}}}), ""
            if path.endswith("/snapshots"):
                return 0, json.dumps(test.snaps.get(parts[3], [])), ""
            return 1, "", "Error: Instance not found"
        self.run, self.writes, self.usage = run, [], 0

    def test_targets(self):
        found, problems = self.l.targets(self.hosts, ["app1", "app2", "web01", "nope"])
        self.assertEqual(found["app1"]["instance"], "app1")
        self.assertEqual(found["app1"]["address"], "192.0.2.10")
        self.assertEqual((found["app2"]["instance"], found["app2"]["project"]), ("legacy-app", "lab"))
        self.assertIn("lxd_host", problems["web01"])
        self.assertIn("not in the managed inventory", problems["nope"])

    def test_check(self):
        found, problems = self.l.targets(self.hosts, ["app1", "app2", "app3", "web01"])
        res = self.l.check(found, problems, self.run)
        self.assertEqual(res["ok"], ["app1", "app2"])
        self.assertIn("lxd_snapshots: true", res["no_snapshot"]["app3"])   # nas2 not opted in: never contacted
        self.assertFalse([c for c in self.calls if c[0] == "nas2"])
        self.assertIn("web01", res["not_a_guest"])
        w = " ".join(res["warnings"]["app1"])
        self.assertIn("data: /share/Data", w)
        self.assertIn("volume db", w)
        self.assertIn("scheduled snapshots", w)
        self.assertIn("project=lab", " ".join(c for _, c in self.calls))
        self.assertEqual(self.writes, [])                                  # read-only

    def test_check_dir_space(self):
        self.driver, self.usage = "dir", 20 * 2**30                          # 20 GiB rootfs, 10 GiB free
        found, problems = self.l.targets(self.hosts, ["app1"])
        res = self.l.check(found, problems, self.run)
        self.assertIn("doesn't fit", res["no_snapshot"]["app1"])
        self.usage = 0
        res = self.l.check(found, problems, self.run)
        self.assertIn("size unknown", " ".join(res["warnings"]["app1"]))

    def test_create_delete_restore(self):
        found, _ = self.l.targets(self.hosts, ["app1"])
        api = self.l.Api(found["app1"], self.run)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.l.apply(api, "create", "prepatch-20261117")
            self.l.apply(api, "create", "old")                             # exists: kept
            self.l.apply(api, "delete", "old")
        self.assertEqual(self.writes[0][1:], ("POST", "/1.0/instances/app1/snapshots",
                                              {"name": "prepatch-20261117", "stateful": False}))
        self.assertEqual(self.writes[1][1:3], ("DELETE", "/1.0/instances/app1/snapshots/old"))
        self.assertEqual(len(self.writes), 2)
        self.assertIn("already exists", out.getvalue())
        self.assertEqual(self.writes[0][0][-1], "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/lxc")
        with self.assertRaises(self.l.LxdError):
            self.l.apply(api, "restore", "missing")

    def test_prune_and_dry_run(self):
        import datetime as dt
        now = dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc)
        snaps = [{"name": "prepatch-a", "created_at": "2026-01-01T00:00:00Z"},
                 {"name": "prepatch-b", "created_at": "2026-02-28T00:00:00.123456789Z"},
                 {"name": "manual", "created_at": "2025-01-01T00:00:00Z"}, {"name": "prepatch-x", "created_at": "?"}]
        self.assertEqual(self.l.prunable(snaps, "prepatch-", 30, now), ["prepatch-a"])
        found, _ = self.l.targets(self.hosts, ["app1"])
        api = self.l.Api(found["app1"], self.run)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(self.l.dry_run(api, "delete", "old"))
            self.assertFalse(self.l.dry_run(api, "restore", "missing"))
            self.assertTrue(self.l.dry_run(api, "create", "prepatch-new"))
        self.assertIn("would delete snapshot 'old'", out.getvalue())
        self.assertEqual(self.writes, [])

    def test_restore_zfs_refuses_with_newer(self):
        self.snaps["app1"].append({"name": "auto-1", "created_at": "2026-02-01T00:00:00Z"})
        found, _ = self.l.targets(self.hosts, ["app1"])
        api = self.l.Api(found["app1"], self.run)
        with self.assertRaises(self.l.LxdError) as e:
            self.l.apply(api, "restore", "old")
        self.assertIn("auto-1", str(e.exception))
        self.driver = "btrfs"
        with contextlib.redirect_stdout(io.StringIO()):
            self.l.apply(api, "restore", "old")
        self.assertEqual(self.writes[-1][1:], ("PUT", "/1.0/instances/app1", {"restore": "old"}))

    def test_sudo_and_cli(self):
        t = {**self.l.targets(self.hosts, ["app3"])[0]["app3"], "opted_in": True}
        api = self.l.Api(t, self.run)
        api.query("/1.0/instances/app3")
        self.assertTrue(self.calls[-1][1].startswith("sudo -n /opt/incus query "))


class PveNodePlanTests(unittest.TestCase):  # issue 23
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import pve_node_plan
        self.p = pve_node_plan
        node = lambda n, mem, used, status="online": {"node": n, "status": status, "mem_gib": mem, "mem_used_gib": used}
        g = lambda vmid, kind, conf, mem=4, status="running", **kw: {
            "vmid": vmid, "type": kind, "name": f"g{vmid}", "node": "pve1", "status": status, "template": False,
            "mem_gib": mem, "config": conf, **kw}
        self.inv = {
            "collected_at": "t", "cluster": {"name": "c", "quorate": 1},
            "nodes": [node("pve1", 64, 40), node("pve2", 64, 20), node("pve3", 32, 8)],
            "storage": [{"storage": "ceph", "node": n, "shared": True} for n in ("pve1", "pve2", "pve3")]
                       + [{"storage": "local-zfs", "node": "pve1", "shared": False},
                          {"storage": "local", "node": "pve1", "shared": False}],
            "guests": [
                g(101, "vm", {"scsi0": "ceph:vm-101-disk-0,size=32G", "ide2": "none,media=cdrom", "onboot": 1,
                              "startup": "order=1"}, mem=16),
                g(102, "vm", {"scsi0": "ceph:vm-102-disk-0", "ide2": "local:iso/x.iso,media=cdrom"}),
                g(103, "vm", {"scsi0": "local-zfs:vm-103-disk-0", "startup": "order=2"}),
                g(104, "vm", {"scsi0": "ceph:vm-104-disk-0", "hostpci0": "0000:01:00"}),
                g(105, "lxc", {"rootfs": "ceph:subvol-105-disk-0", "mp0": "/srv/data,mp=/data"}),
                g(106, "lxc", {"rootfs": "ceph:subvol-106-disk-0"}, mem=2),
                g(107, "vm", {"scsi0": "ceph:vm-107-disk-0"}, hastate="started"),
                g(108, "vm", {"scsi0": "ceph:vm-108-disk-0"}, status="stopped"),
                {**g(9000, "vm", {"scsi0": "ceph:base"}), "template": True},
                {**g(201, "vm", {"scsi0": "ceph:vm-201"}), "node": "pve2"},
            ]}

    def actions(self, plan):
        return {r["vmid"]: (r["action"], r["target"]) for r in plan["guests"]}

    def test_lvm_thin_pools_listed(self):  # GitHub issue #91
        inv = json.loads(json.dumps(self.inv))
        inv["nodes"][0]["uptime_s"] = 200 * 86400
        inv["storage"] += [{"storage": "lvm-data", "node": "pve1", "shared": False, "type": "lvmthin",
                            "size_gib": 200, "used_gib": 50},
                           {"storage": "lvm-empty", "node": "pve1", "shared": False, "type": "lvmthin"},
                           {"storage": "lvm-data", "node": "pve2", "shared": False, "type": "lvmthin"}]
        inv["guests"][2]["config"]["scsi1"] = "lvm-data:vm-103-disk-1"
        plan, _ = self.p.make_plan(inv, "pve1")
        self.assertEqual(plan["lvm_thin"], [{"storage": "lvm-data", "used_pct": 25, "guests": [103], "stop": [103]}])
        out = self.p.render(plan, [])
        self.assertIn("first thin_check in 200 days", out)
        self.assertIn("lvm-data: 25% used, 1 guests, 1 stopped for the reboot", out)
        self.assertEqual(self.p.make_plan(self.inv, "pve1")[0]["lvm_thin"], [])
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/patch-proxmox-node.yml").read_text()
        pre = pb.split("- name: LVM-thin pools before the reboot")[1].split("- name: Move guests off")[0]
        self.assertIn("item.lv_attr[8] | default('-') == '-'", pre)
        self.assertIn("< 90", pre)
        self.assertIn("thin_check -m", pre)
        self.assertIn("release_metadata_snap", pre.split("thin_check -m")[1])   # released after the check, always
        self.assertIn("thin_check | default(false) | bool and not ansible_check_mode", pre)
        self.assertLess(pb.index("LVM-thin pools before the reboot"), pb.index("Shutdown (reverse startup order"))

    def test_shared_storage_guests_migrate_and_spread(self):
        plan, blockers = self.p.make_plan(self.inv, "pve1")
        self.assertEqual(blockers, [])
        acts = self.actions(plan)
        self.assertEqual(acts[101], ("migrate", "pve2"))        # 16 GiB: pve2 36/64=56% beats pve3 24/32=75%
        self.assertEqual(acts[106], ("migrate", "pve3"))        # pve3 10/32=31% beats pve2 (36+2)/64=59%
        self.assertEqual(acts[102][0], "stop")                  # local ISO pins it
        self.assertEqual(acts[103][0], "stop")
        self.assertEqual(acts[104][0], "stop")                  # passthrough
        self.assertEqual(acts[105][0], "stop")                  # bind mount
        self.assertEqual(acts[107][0], "ha")
        self.assertEqual(acts[108][0], "stays-stopped")
        self.assertNotIn(9000, acts)
        self.assertNotIn(201, acts)
        self.assertEqual(plan["stop_order"], [105, 104, 102, 103])  # unordered first (reverse startup order)
        self.assertIn("ide2 on local", next(r for r in plan["guests"] if r["vmid"] == 102)["reason"])
        self.assertTrue(next(r for r in plan["guests"] if r["vmid"] == 101)["onboot"])

    def test_capacity_and_no_migrate(self):
        plan, _ = self.p.make_plan(self.inv, "pve1", max_pct=40)
        self.assertEqual(self.actions(plan)[101][0], "stop")     # 16 GiB fits nowhere below 40 %
        self.assertIn("no node has room", next(r for r in plan["guests"] if r["vmid"] == 101)["reason"])
        plan, _ = self.p.make_plan(self.inv, "pve1", migrate=False)
        self.assertNotIn("migrate", {a for a, _ in self.actions(plan).values()})

    def test_blockers(self):
        self.inv["nodes"][2]["status"] = "offline"
        self.inv["cluster"]["quorate"] = 0
        _, blockers = self.p.make_plan(self.inv, "pve1")
        self.assertTrue(any("not quorate" in b for b in blockers))
        self.assertTrue(any("pve3" in b for b in blockers))
        plan, blockers = self.p.make_plan(self.inv, "nope")
        self.assertEqual(plan, {})

    def test_snapshot_without_config_refuses_before_classifying(self):  # GitHub issue #85
        for g in self.inv["guests"]:
            g.pop("config")
        plan, blockers = self.p.make_plan(self.inv, "pve1")
        self.assertEqual(plan, {})
        self.assertTrue(any("--details" in b for b in blockers))
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible", cwd=d)
        (d / "discovery/proxmox.json").write_text(json.dumps(self.inv))
        r = run("pve_node_plan.py", "pve1", cwd=d)
        self.assertEqual(r.returncode, 4)
        self.assertIn("--details", r.stderr)
        self.assertNotIn("migrate", r.stdout + r.stderr)
        self.assertFalse((d / "discovery/pve-patch.json").exists())

    def test_plain_inventory_keeps_details_of_previous_snapshot(self):  # GitHub issue #85
        import proxmox_inventory as pinv
        old = {"collected_at": "t1", "guests": [{"vmid": 101, "type": "vm", "config": {"scsi0": "local-zfs:x"},
                                                 "ips": [{"ip": "10.9.0.5", "source": "agent"}]},
                                                {"vmid": 102, "type": "lxc", "config": {"rootfs": "ceph:y"}}]}
        new = {"collected_at": "t2", "guests": [{"vmid": 101, "type": "vm"}, {"vmid": 102, "type": "vm"},
                                                {"vmid": 103, "type": "vm"}]}
        out = pinv.keep_details(old, new)
        self.assertEqual(out["guests"][0]["config"], {"scsi0": "local-zfs:x"})
        self.assertEqual(out["guests"][0]["ips"], [{"ip": "10.9.0.5", "source": "agent"}])   # issue #97
        self.assertNotIn("config", out["guests"][1])            # VMID reused by another guest type
        self.assertNotIn("config", out["guests"][2])
        self.assertEqual(out["details_at"], "t1")
        self.assertEqual(pinv.keep_details({**old, "details_at": "t0"}, {"guests": [{"vmid": 101, "type": "vm"}]})
                         ["details_at"], "t0")                  # still the original --details run
        self.assertNotIn("details_at", pinv.keep_details(None, {"guests": []}))
        self.assertEqual(pinv.keep_details({**old, "config_version": 2}, {"guests": [{"vmid": 101, "type": "vm"}]})
                         ["config_version"], 2)                 # what tofu_import_plan.py checks (issue #149)
        self.assertNotIn("config_version", out)
        self.assertEqual(pinv.guest_config({"cpu": "host", "protection": "1", "swap": "512", "serial0": "socket",
                                            "lock": "backup"}),
                         {"cpu": "host", "protection": "1", "swap": "512", "serial0": "socket"})
        plan, _ = self.p.make_plan({**self.inv, "details_at": "t1"}, "pve1")
        self.assertIn("guest config from t1", self.p.render(plan, []))

    def test_upgrade_only_run_reports_plan_not_actions(self):  # GitHub issue #86
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/patch-proxmox-node.yml").read_text()
        result = pb[pb.index("- name: Result"):]
        for k in ("migrated", "ha", "stopped_and_restored"):
            self.assertRegex(result, rf"\b{k}={{{{ \S+ if did_reboot \| bool else \[\] }}}}")
        self.assertIn("planned_stop={{ plan.stop_order }}", result)

    def test_reboot_waits_for_every_unit_and_start_tolerates_a_race(self):  # GitHub issue #141
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/patch-proxmox-node.yml").read_text()
        wait = pb.split("- name: Wait for Proxmox services and onboot guests")[1].split("- name:")[0]
        self.assertNotIn("pve_services.rc", wait)                      # rc 0 when ANY unit is active
        self.assertIn("pve_services.stdout_lines[:4] | reject('equalto', 'active')", wait)
        self.assertIn("pve_services.stdout_lines[4] in ['active', 'failed']", wait)
        self.assertIn("pve_guests_timeout | default(1800)", wait)
        self.assertEqual(pb.count('ansible.builtin.shell: "{{ hm_start_guest }}"'), 2)   # rescue and after the reboot
        self.assertNotIn("grep -q running ||", pb)
        snippet = re.search(r"\n    hm_start_guest: \|\n((?:      .*\n)+)", pb).group(1)
        script = re.sub(r"^      ", "", snippet, flags=re.M).replace("{{ hm_guest_cmd }}", "pct").replace(
            "{{ hm_guest_id }}", "101")
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "sleep").write_text("#!/bin/sh\nexit 0\n")
        (d / "pct").write_text(textwrap.dedent("""\
            #!/bin/sh
            s="$(dirname "$0")/state"
            case "$1" in
              status) if [ -f "$s.up" ]; then echo "status: running"; else echo "status: stopped"; fi ;;
              start) echo start >> "$s.log"
                     if [ -f "$s.race" ]; then touch "$s.up"; echo "CT $2 already running" >&2; exit 255; fi
                     [ -f "$s.broken" ] && exit 1
                     touch "$s.up" ;;
            esac
            """))
        for f in ("sleep", "pct"):
            (d / f).chmod(0o755)
        sh = lambda: subprocess.run(["sh", "-c", script], env={**os.environ, "PATH": f"{d}:{os.environ['PATH']}"},
                                    capture_output=True, text=True)
        (d / "state.race").touch()                 # onboot start brings it up between status and start
        self.assertEqual(sh().returncode, 0)
        self.assertEqual(sh().returncode, 0)       # running already: no second start
        self.assertEqual((d / "state.log").read_text().count("start"), 1)
        for f in ("state.race", "state.up"):
            (d / f).unlink()
        (d / "state.broken").touch()               # a real failure still fails
        self.assertEqual(sh().returncode, 1)

    def test_cli_writes_plan_only_without_blockers(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible", cwd=d)
        (d / "discovery/proxmox.json").write_text(json.dumps(self.inv))
        r = run("pve_node_plan.py", "pve1", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("migrate → pve2", r.stdout)
        plan = json.loads((d / "discovery/pve-patch.json").read_text())["sites"]["default"]["pve1"]   # no sites:
        self.assertEqual((plan["node"], plan["default_site"]), ("pve1", True))
        (d / "discovery/pve-patch.json").unlink()
        self.inv["cluster"]["quorate"] = 0
        (d / "discovery/proxmox.json").write_text(json.dumps(self.inv))
        r = run("pve_node_plan.py", "pve1", cwd=d)
        self.assertEqual(r.returncode, 4)
        self.assertIn("Do NOT patch", r.stdout)
        self.assertFalse((d / "discovery/pve-patch.json").exists())


    def test_other_site_and_standalone_node(self):  # issue 52
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible", cwd=d)
        run("config_set.py", "sites+={name: home}", "sites+={name: offsite, proxmox: {endpoint: 'https://x:8006'}}", cwd=d)
        alone = {**self.inv, "site": "offsite", "cluster": None, "nodes": self.inv["nodes"][:1]}
        (d / "discovery/proxmox.json").write_text(json.dumps({"sites": {"home": self.inv, "offsite": alone}}))
        r = run("pve_node_plan.py", "pve1", "--site", "offsite", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("at site offsite", r.stdout)
        self.assertIn("Standalone node", r.stdout)
        plans = lambda: json.loads((d / "discovery/pve-patch.json").read_text())["sites"]
        plan = plans()["offsite"]["pve1"]
        self.assertEqual((plan["site"], plan["standalone"], plan["default_site"]), ("offsite", True, False))
        self.assertEqual({r["action"] for r in plan["guests"]}, {"stop", "ha", "stays-stopped"})
        self.assertNotIn("home", plans())                                   # the home node's plan is separate
        self.assertEqual(run("pve_node_plan.py", "pve1", cwd=d).returncode, 0)
        plan = plans()["home"]["pve1"]
        self.assertEqual((plan["site"], plan["standalone"], plan["default_site"]), ("home", False, True))
        self.assertEqual(plans()["offsite"]["pve1"]["site"], "offsite")      # kept


class PveNodePlaybookUpgradeTests(unittest.TestCase):  # issue 23
    def test_new_playbook_offered_to_existing_repos(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible", cwd=d)
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertTrue((d / "ansible/playbooks/tasks/pve-migrate.yml").is_file())
        self.assertNotIn("patch-proxmox-node", ids())
        (d / "ansible/playbooks/patch-proxmox-node.yml").unlink()
        notes = json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)
        note = next(n for n in notes if n["id"] == "patch-proxmox-node")
        self.assertIn("repo-template/ansible/playbooks/patch-proxmox-node.yml", note["action"])

    def test_patch_linux_guard_offered_to_existing_repos(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "ansible", cwd=d)
        self.assertIn("patch_requires_approval: true",
                      (d / "ansible/inventory/managed/group_vars/proxmox_nodes.yml").read_text())
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertNotIn("patch-requires-approval", ids())
        pb = d / "ansible/playbooks/patch-linux.yml"
        pb.write_text(re.sub(r"\n    - name: Refuse hosts that need.*?run_once: true\n", "\n", pb.read_text(), flags=re.S))
        self.assertNotIn("Refuse hosts that need", pb.read_text())
        self.assertIn("patch-requires-approval", ids())


class ProxmoxTlsAndPermissionTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import check_env
        import hmlib
        import proxmox_inventory
        self.check_env, self.hmlib, self.inv = check_env, hmlib, proxmox_inventory

    def pve(self, perms):
        import urllib.error
        pve = self.inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)

        def fake(path, **_):
            if path == "/access/permissions":
                return perms
            raise closed_http_error(path, 403, "Forbidden", {}, None)
        pve._get = fake
        return pve

    def test_403_with_no_permissions_points_at_user_acl(self):
        with self.assertRaises(SystemExit) as e:
            self.pve({}).get("/cluster/status")
        msg = str(e.exception)
        self.assertIn("no effective permissions", msg)
        self.assertIn("pveum acl modify / --users homelab@pve --roles PVEAuditor", msg)
        self.assertNotIn("s3cret", msg)

    def test_403_with_other_paths_lists_them(self):
        with self.assertRaises(SystemExit) as e:
            self.pve({"/pool/lab": {"VM.Audit": 1}}).get("/cluster/status")
        self.assertIn("/pool/lab", str(e.exception))
        self.assertIn("pveum user token permissions homelab@pve ro", str(e.exception))

    def test_token_expiry(self):  # GitHub issue #155: Proxmox has no token creation time, only `expire`
        ce, now, day = self.check_env, 1_800_000_000, 86400
        ids = {"read_only": "homelab@pve!ro", "provisioning": "homelab@pve!rw"}
        users = [{"userid": "homelab@pve", "expire": 0,
                  "tokens": [{"tokenid": "ro", "expire": now + 400 * day}, {"tokenid": "rw", "expire": now + 400 * day}]},
                 {"userid": "root@pam", "tokens": [{"tokenid": "other", "expire": 0}]}]   # not the skill's: ignored
        row = ce.token_expiry_row("proxmox:tokens", ids, users, now)
        self.assertTrue(row["ok"], row)
        self.assertIn("homelab@pve!ro in 400 days", row["detail"])
        users[0]["tokens"][1]["expire"] = 0                                               # rw never expires
        users[0]["tokens"][0]["expire"] = now + 10 * day                                  # ro soon
        row = ce.token_expiry_row("proxmox:tokens", ids, users, now)
        self.assertIsNone(row["ok"])
        self.assertIn("expiring: homelab@pve!ro in 10 days", row["detail"])
        self.assertIn("no expiry: homelab@pve!rw", row["detail"])
        users[0]["expire"] = now + 5 * day                                                # the user's expiry counts too
        self.assertIn("homelab@pve!rw in 5 days", ce.token_expiry_row("t", ids, users, now)["detail"])
        users[0]["expire"] = now - day
        row = ce.token_expiry_row("t", ids, users, now)
        self.assertIs(row["ok"], False)
        self.assertIn("expired: homelab@pve!ro, homelab@pve!rw", row["detail"])
        row = ce.token_expiry_row("t", {"read_only": "homelab@pve!gone"}, users, now)
        self.assertIn("not listed by Proxmox: homelab@pve!gone", row["detail"])

        cfg = {"proxmox": {"endpoint": "https://pve1.example:8006"},
               "secrets": {"proxmox-ro": {"service": "homelab/proxmox-ro"}, "proxmox-rw": {"service": "homelab/proxmox-rw"}}}
        values = {"proxmox-ro": "homelab@pve!ro=s3cret-ro", "proxmox-rw": "homelab@pve!rw=s3cret-rw"}
        calls = []

        class Fake:
            def get(self, path, **params):
                calls.append((path, params))
                return [{"userid": "homelab@pve", "tokens": [{"tokenid": "ro"}, {"tokenid": "rw", "expire": now + 99 * day}]}]

        def connect(px, token):
            self.assertEqual(token, "homelab@pve!ro=s3cret-ro")                         # the read-only token
            return Fake()
        with unittest.mock.patch.object(self.hmlib, "read_secret", side_effect=lambda c, n: values[n]):
            rows = ce.check_token_expiry(cfg, now=now, connect=connect)
        self.assertEqual(calls, [("/access/users", {"full": 1})])
        self.assertEqual(rows[0]["check"], "proxmox:tokens")
        self.assertIsNone(rows[0]["ok"])
        self.assertIn("no expiry: homelab@pve!ro", rows[0]["detail"])
        self.assertNotIn("s3cret", json.dumps(rows))

        error = self.inv.PveError("Proxmox API refused /access/users (401): the token 'homelab@pve!ro' is wrong")

        def refused(px, token):
            class R:
                def get(self, path, **_):
                    raise error
            return R()
        with unittest.mock.patch.object(self.hmlib, "read_secret", side_effect=lambda c, n: values[n]):
            self.assertIs(ce.check_token_expiry(cfg, now=now, connect=refused)[0]["ok"], False)
        with unittest.mock.patch.object(self.hmlib, "read_secret", side_effect=self.hmlib.ConfigError("locked")):
            self.assertIn("not readable", ce.check_token_expiry(cfg, now=now, connect=connect)[0]["detail"])

    def test_fallback_endpoints(self):  # GitHub issue 98
        from unittest import mock
        h, ce = self.hmlib, self.check_env
        one, two, three = "https://pve1.example:8006", "https://pve2.example:8006", "https://pve3.example:8006"
        self.assertEqual(h.endpoint_list(one), [one])
        self.assertEqual(h.endpoint_list(f"{one}, {two},{three}"), [one, two, three])
        self.assertEqual(h.endpoint_list([one, two]), [one, two])
        self.assertEqual(h.endpoint_list(None), [])
        cfg = {"proxmox": {"endpoint": [one, two, three]}}
        px = h.proxmox_site(cfg)
        self.assertEqual((px["endpoint"], px["endpoints"]), (one, [one, two, three]))
        self.assertEqual(len(h.proxmox_sites(cfg)), 1)
        with self.assertRaises(h.ConfigError):
            h.proxmox_site({"proxmox": {"endpoint": f"{one},pve2:8006"}})
        calls = []
        def up(*alive):
            return lambda ep: calls.append(ep) or ep in alive
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(h.pick_endpoint({**px, "_site": "home"}, up(two, three)), two)
        self.assertIn(f"Proxmox home: {one} not reachable, using {two}", err.getvalue())
        self.assertEqual(h.pick_endpoint(px, up(one)), one)
        self.assertEqual(h.pick_endpoint(px, up()), one)                      # none answers: the first's error
        calls.clear()
        self.assertEqual(h.pick_endpoint(h.proxmox_site({"proxmox": {"endpoint": one}}), up()), one)
        self.assertEqual(calls, [])                                           # one address: no probe
        down = OSError("Connection refused")
        with mock.patch.object(ce, "_handshake", side_effect=lambda host, port, ctx: down if host == "pve1.example" else None):
            rows = ce.check_proxmox_tls(cfg)
        self.assertEqual([r["check"] for r in rows], ["proxmox:tls#1", "proxmox:tls#2", "proxmox:tls#3"])
        self.assertEqual([r["ok"] for r in rows], [None, True, True])
        self.assertIn("the first endpoint is down", rows[0]["detail"])
        with mock.patch.object(ce, "_handshake", return_value=down):
            self.assertEqual([r["ok"] for r in ce.check_proxmox_tls(cfg)], [False, False, False])

    def test_plain_http_endpoint_needs_allow_http(self):
        h, ce = self.hmlib, self.check_env
        cfg = {"proxmox": {"endpoint": "http://pve.example:8006"}}
        with self.assertRaises(h.ConfigError) as e:
            h.proxmox_site(cfg)
        self.assertIn("clear text", str(e.exception))
        self.assertFalse(ce.check_proxmox_tls(cfg)[0]["ok"])
        cfg["proxmox"]["allow_http"] = "true"                           # only a real boolean
        with self.assertRaises(h.ConfigError):
            h.proxmox_site(cfg)
        cfg["proxmox"]["allow_http"] = True
        self.assertEqual(h.proxmox_site(cfg)["endpoint"], "http://pve.example:8006")
        r = ce.check_proxmox_tls(cfg)[0]
        self.assertIsNone(r["ok"])
        self.assertIn("clear text", r["detail"])
        sites = {"sites": [{"name": "home", "proxmox": {"endpoint": "https://pve.example:8006"}},
                           {"name": "far", "proxmox": {"endpoint": "http://pve2.example:8006"}}]}
        with self.assertRaises(h.ConfigError) as e:
            h.proxmox_site(sites, "far")
        self.assertIn("sites[far].proxmox", str(e.exception))
        self.assertEqual(h.proxmox_site(sites, "home")["endpoint"], "https://pve.example:8006")

    def test_unverified_bmc_and_unifi_certificates_warn(self):
        inv = {"_meta": {"hostvars": {"bmc-pve1": {"bmc_validate_certs": False}, "bmc-pve2": {"bmc_validate_certs": True},
                                      "udm": {"unifi_validate_certs": "false"}, "web1": {}}}}
        self.assertEqual(self.check_env.unverified_cert_hosts(inv),
                         {"bmc_validate_certs": ["bmc-pve1"], "unifi_validate_certs": ["udm"]})
        self.assertEqual(self.check_env.unverified_cert_hosts({}), {})

    def test_ca_cert_path_expanded_and_relative_to_repo(self):
        cfg = {"_root": "/repo", "proxmox": {"ca_cert": "certs/ca.pem"}}
        self.assertEqual(self.hmlib.proxmox_ca_file(cfg), "/repo/certs/ca.pem")
        cfg["proxmox"]["ca_cert"] = "~/x.pem"
        self.assertEqual(self.hmlib.proxmox_ca_file(cfg), str(Path.home() / "x.pem"))
        with self.assertRaises(self.hmlib.ConfigError):
            self.hmlib.proxmox_ssl_context(cfg)

    def test_tls_check_finds_ca_trusted_only_in_keychain(self):
        import ssl
        from unittest import mock
        err = ssl.SSLCertVerificationError("verify failed")
        err.verify_code, err.verify_message = 19, "self-signed certificate in certificate chain"
        ce = self.check_env
        cfg = {"proxmox": {"endpoint": "https://pve.example:8006"}}
        with mock.patch.object(ce, "_handshake", return_value=err), \
                mock.patch.object(ce, "_chain_names", return_value=["Home Root CA"]), \
                mock.patch.object(ce, "_keychain_ca_fix", return_value=("Home Root CA", "/Library/Keychains/System.keychain")):
            r = ce.check_proxmox_tls(cfg)[0]
        self.assertFalse(r["ok"])
        self.assertIn("trusted in the macOS keychain", r["detail"])
        self.assertIn("security find-certificate -a -c 'Home Root CA' -p /Library/Keychains/System.keychain "
                      "> ~/.config/homelab/home-root-ca.pem", r["detail"])
        self.assertIn("proxmox.ca_cert=~/.config/homelab/home-root-ca.pem", r["detail"])
        evil = 'Evil" $(touch /tmp/hm-x) "\u202e'   # a name from the server's certificate: quoted, cleaned for display
        with mock.patch.object(ce, "_handshake", return_value=err), \
                mock.patch.object(ce, "_chain_names", return_value=[evil]), \
                mock.patch.object(ce, "_keychain_ca_fix", return_value=(evil, "/Library/Keychains/System.keychain")):
            r = ce.check_proxmox_tls(cfg)[0]
        cmd = r["detail"].split("security find-certificate", 1)[1].split(" -p ", 1)[0]
        self.assertEqual(shlex.split(cmd), ["-a", "-c", evil])
        with mock.patch.object(ce, "_handshake", return_value=err), \
                mock.patch.object(ce, "_chain_names", return_value=["x" * 500]), \
                mock.patch.object(ce, "_keychain_ca_fix", return_value=None):
            self.assertLess(len(ce.check_proxmox_tls(cfg)[0]["detail"]), 400)
        with mock.patch.object(ce, "_handshake", return_value=err), \
                mock.patch.object(ce, "_chain_names", return_value=["Proxmox Virtual Environment"]), \
                mock.patch.object(ce, "_keychain_ca_fix", return_value=None):
            r = ce.check_proxmox_tls(cfg)[0]
        self.assertIn("pve-root-ca.pem", r["detail"])
        site_cfg = {"sites": [{"name": "home", "proxmox": cfg["proxmox"]},
                              {"name": "far", "proxmox": {"endpoint": "https://pve2.example:8006"}}]}
        with mock.patch.object(ce, "_handshake", return_value=err), \
                mock.patch.object(ce, "_chain_names", return_value=["Home Root CA"]), \
                mock.patch.object(ce, "_keychain_ca_fix", return_value=("Home Root CA", "/Library/Keychains/System.keychain")):
            r = ce.check_proxmox_tls(site_cfg)[1]
        self.assertIn("config_set.py 'sites[far].proxmox.ca_cert=~/.config/homelab/home-root-ca.pem'", r["detail"])
        self.assertEqual(ce.check_proxmox_tls({"proxmox": {"endpoint": "https://x", "verify_tls": False}})[0]["ok"], None)
        self.assertEqual(ce.check_proxmox_tls({}), [])


if __name__ == "__main__":
    unittest.main()
