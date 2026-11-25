"""Tests for Discovery: drift_report.py, guest_map.py, nmap_scan.py, ssh_probe.py and the discovery file layout."""
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


class DriftTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox,ansible", cwd=self.d)
        snap = {"collected_at": "2026-01-01T00:00:00+00:00", "version": "9", "cluster": None, "nodes": [],
                "networks": {}, "storage": [{"storage": "local-zfs", "node": "pve1", "content": "images,rootdir"}],
                "guests": [{"vmid": 100, "name": "dns01", "type": "vm", "node": "pve1", "status": "running",
                            "template": False, "tags": "debian;tofu"},
                           {"vmid": 104, "name": "test-old", "type": "vm", "node": "pve1", "status": "stopped",
                            "template": False, "tags": ""},
                           {"vmid": 9051, "name": "tpl", "type": "vm", "node": "pve1", "status": "stopped",
                            "template": True, "tags": ""}],
                "backup_jobs": [{"id": "daily", "enabled": True, "all": False, "vmid": "100"}]}
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(snap))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_tag_fallback_and_backups_without_state(self):
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("104 vm `test-old`", r.stdout)
        self.assertNotIn("9051", r.stdout.split("## Backups")[0])  # Packer templates aren't "unmanaged"
        self.assertIn("No storage accepts `backup` content", r.stdout)
        self.assertIn("104 `test-old` is in no backup job", r.stdout)
        self.assertNotIn("100 `dns01` is in no backup job", r.stdout)
        self.assertIn("references/proxmox.md", r.stdout)

    def _jobs(self, jobs):
        p = Path(self.d, "discovery/proxmox.json")
        snap = json.loads(p.read_text())
        snap["backup_jobs"] = jobs
        p.write_text(json.dumps(snap))
        return run("drift_report.py", "--no-tofu", cwd=self.d).stdout

    def test_backup_job_id_lists(self):  # issue 41
        out = self._jobs([{"id": "daily", "enabled": True, "all": False, "vmid": [100, 104]}])
        self.assertNotIn("is in no backup job", out)
        out = self._jobs([{"id": "all", "enabled": True, "all": True, "vmid": [], "exclude": [104]}])
        self.assertIn("104 `test-old` is in no backup job", out)
        self.assertNotIn("100 `dns01` is in no backup job", out)

    def test_truncated_backup_list_is_unknown(self):  # issue 41: old snapshots cut at 200 characters
        out = self._jobs([{"id": "daily", "enabled": True, "all": False, "vmid": "100,10…"}])
        self.assertIn("Can't read the guest list of job(s) `daily`", out)
        self.assertNotIn("is in no backup job", out)

    def _storage(self, yq_expr):  # issue 54: a cluster without shared storage, one node on LVM
        p = Path(self.d, "discovery/proxmox.json")
        snap = json.loads(p.read_text())
        snap["nodes"] = [{"node": n, "status": "online"} for n in ("pve1", "pve2", "pve3")]
        snap["storage"] = [{"storage": "local", "node": n, "content": "iso,vztmpl,import,backup"} for n in ("pve1", "pve2", "pve3")] \
            + [{"storage": "local-zfs", "node": n, "content": "images,rootdir"} for n in ("pve1", "pve2")] \
            + [{"storage": "tank-vm", "node": "pve1", "content": "images"},
               {"storage": "local-lvm", "node": "pve3", "content": "images,rootdir"}]
        p.write_text(json.dumps(snap))
        subprocess.run(["yq", "-i", yq_expr, str(Path(self.d, "homelab.yaml"))], check=True)
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        return r.stdout.split("## Storage")[1].split("\n## ")[0] if "## Storage" in r.stdout else r.stdout + r.stderr

    def test_storage_missing_on_a_node(self):
        out = self._storage('.proxmox.default_storage = "local-zfs" | .proxmox.image_storage = "local"')
        self.assertIn("pve3: default_storage `local-zfs` (VM disks) is not on this node — set `proxmox.nodes.pve3`", out)
        self.assertEqual(out.count("local-zfs"), 1)          # lxc_storage = the same storage: reported once
        self.assertNotIn("pve1", out)

    def test_storage_per_node_and_content(self):
        out = self._storage('.proxmox.default_storage = "local-zfs" | .proxmox.lxc_storage = "tank-vm"'
                            ' | .proxmox.nodes = {"pve3": {"default_storage": "local-lvm"}}')
        self.assertNotIn("pve3", out)                        # its own storage, LXC falls back to it
        self.assertIn("pve1: lxc_storage `tank-vm` (LXC root filesystems) doesn't take `rootdir` content (images)", out)
        self.assertIn("pve2: lxc_storage `tank-vm` (LXC root filesystems) is not on this node", out)
        out = self._storage('.proxmox.lxc_storage = "" | .proxmox.nodes.pve9 = {"default_storage": "x"}')
        self.assertIn("`proxmox.nodes.pve9`: no such node", out)
        self.assertIn("Each node has", self._storage('del(.proxmox.nodes.pve9)'))

    def test_storage_per_node_needs_default_storage(self):
        out = self._storage('.proxmox.default_storage = "local-zfs" | .proxmox.nodes = {"pve3": {"lxc_storage": "local-lvm"}}')
        self.assertIn("proxmox.nodes.pve3 needs default_storage", out)


class DriftWithoutProxmoxTests(unittest.TestCase):  # GitHub issue #123
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", self.d, "--components", "ansible,discovery,appliances", cwd=self.d)
        Path(self.d, "discovery/network.json").write_text(json.dumps(
            {"updated_at": "2026-11-19T10:00:00+00:00",
             "hosts": {"10.0.20.11": {"ip": "10.0.20.11", "ports": [], "hostnames": []}}}))
        Path(self.d, "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n        seen:\n          ansible_host: 10.0.20.11\n"
            "        gone:\n          ansible_host: 10.0.20.12\n")

    def test_no_proxmox_or_tofu_sources(self):
        r = run("drift_report.py", cwd=self.d)   # no --no-tofu needed
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("| Proxmox / OpenTofu | not used (components.proxmox: false) |", r.stdout)
        self.assertNotIn("Proxmox snapshot", r.stdout)
        self.assertNotIn("proxmox_inventory.py", r.stdout)
        self.assertNotIn("OpenTofu state", r.stdout)
        self.assertIn("- `gone` (10.0.20.12) — not seen on the network", r.stdout)   # the scan alone decides
        self.assertNotIn("`seen`", r.stdout)
        self.assertNotIn("Needs both snapshots", r.stdout)

    def test_overview_sources(self):
        r = run("overview.py", "--out", "-", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("| discovery/proxmox.json | not used (components.proxmox: false) |", r.stdout)
        self.assertNotIn("proxmox_inventory.py", r.stdout)
        self.assertNotIn("Proxmox node", r.stdout.split("## At a glance")[1].split("\n\n")[1])


class DriftExtraIpsTests(unittest.TestCase):
    """#31: hm_extra_ips makes a host's other addresses known; --stale says when drift.md is out of date."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "ansible,discovery", cwd=self.d)
        Path(self.d, "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    appliances:\n      hosts:\n        router1:\n          ansible_host: 10.0.10.1\n"
            "          hm_extra_ips: [10.0.20.1, 10.0.30.1/24]\n")
        host = {"mac": None, "hostnames": [], "device_type_guess": "router", "vendor": None}
        net = {"updated_at": "2026-01-01", "hosts": {ip: host for ip in ("10.0.10.1", "10.0.20.1", "10.0.30.1", "10.0.10.9")}}
        Path(self.d, "discovery/network.json").write_text(json.dumps(net))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_vlan_names_in_report(self):  # issue 34
        run("config_set.py", "network.vlans+={id: 20, name: DMZ, cidr: 10.0.10.0/24}", cwd=self.d)
        out = run("drift_report.py", "--no-tofu", cwd=self.d).stdout
        self.assertIn("10.0.10.9  — router [VLAN 20 DMZ]", out)

    def test_container_ips_are_not_unmanaged(self):  # issue 40
        nas = {"hosts": {"nas1": {"containers": [{"name": "pihole", "runtime": "lxd", "ips": ["10.0.10.9"]}]}}}
        Path(self.d, "discovery/nas1-containers.json").write_text(json.dumps(nas))
        out = run("drift_report.py", "--no-tofu", cwd=self.d).stdout
        unmanaged = out.split("## Network devices not in managed inventory")[1]
        self.assertIn("None.", unmanaged.split("Container addresses")[0])
        self.assertIn("10.0.10.9 → `pihole` (lxd on `nas1`)", out)

    def test_secondary_ips_are_not_unmanaged(self):
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        unmanaged = r.stdout.split("## Network devices not in managed inventory")[1]
        self.assertIn("1 device(s)", unmanaged)
        self.assertIn("10.0.10.9", unmanaged)
        self.assertIn("- 10.0.20.1 → `router1` (secondary)", unmanaged)
        self.assertIn("- 10.0.30.1 → `router1` (secondary)", unmanaged)

    def test_stale(self):
        self.assertEqual(run("drift_report.py", "--stale", cwd=self.d).returncode, 2)
        run("drift_report.py", "--no-tofu", cwd=self.d)
        drift = Path(self.d, "discovery/drift.md")
        os.utime(drift, (time.time() + 60, time.time() + 60))
        r = run("drift_report.py", "--stale", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stdout)
        os.utime(drift, (time.time() - 3600, time.time() - 3600))
        r = run("drift_report.py", "--stale", cwd=self.d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ansible/inventory", r.stdout)
        os.utime(drift, (time.time() + 60, time.time() + 60))           # GitHub issue #89: OVERVIEW.md too
        run("overview.py", cwd=self.d)
        self.assertEqual(run("drift_report.py", "--stale", cwd=self.d).returncode, 0)
        Path(self.d, "OVERVIEW.md").write_text("old")
        r = run("drift_report.py", "--stale", cwd=self.d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("OVERVIEW.md differs", r.stdout)


class GuestNetworkMappingTests(unittest.TestCase):
    """#7: scanned addresses are matched to Proxmox guests (config/agent IP, MAC, DNS name)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        run("init_repo.py", self.d, "--components", "proxmox,discovery", cwd=self.d)
        guest = lambda vmid, name, typ, **kw: {"vmid": vmid, "name": name, "type": typ, "node": "pve1",
                                               "status": "running", "template": False, "tags": "tofu", **kw}
        snap = {"collected_at": "2026-01-01T00:00:00+00:00", "version": "9", "cluster": None, "nodes": [],
                "networks": {}, "storage": [], "backup_jobs": None,
                "guest_ip_sources": {"agent": "forbidden: the read-only token (and its user) need VM.GuestAgent.Audit"},
                "guests": [guest(901, "dns", "lxc", config={"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,"
                                                                     "ip=10.0.10.53/24,gw=10.0.10.1,tag=10"}),
                           guest(101, "web", "vm", config={"net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0",
                                                           "ipconfig0": "ip=dhcp"},
                                 ips=[{"iface": "eth0", "mac": "bc:24:11:00:00:02", "ip": "10.0.10.80", "source": "agent"}]),
                           guest(102, "mail", "vm", config={"net0": "virtio=BC:24:11:00:00:03,bridge=vmbr0"}),
                           guest(103, "vault", "vm", config={"net0": "virtio=BC:24:11:00:00:04,bridge=vmbr0"}),
                           guest(104, "offline", "vm", config={})]}
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps(snap))
        host = lambda mac=None, names=(): {"mac": mac, "hostnames": list(names), "device_type_guess": "linux", "vendor": None}
        net = {"updated_at": "2026-01-01", "hosts": {"10.0.10.53": host(), "10.0.10.80": host(),
                                                     "10.0.10.25": host(mac="BC:24:11:00:00:03"),
                                                     "10.0.10.40": host(names=["vault.lab.example"]),
                                                     "10.0.10.9": host(names=["printer.lab.example"]),
                                                     "10.0.10.7": {**host(names=["ilo-srv1"]), "device_type_guess": "bmc"}}}
        Path(self.d, "discovery/network.json").write_text(json.dumps(net))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_matching(self):
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        section = r.stdout.split("## Proxmox guests ↔ network")[1].split("\n## ")[0]
        for line in ("10.0.10.25 → 102 vm `mail` (MAC)", "10.0.10.40 → 103 vm `vault` (DNS name vault.lab.example)",
                     "10.0.10.53 → 901 lxc `dns` (config IP)", "10.0.10.80 → 101 vm `web` (agent IP)",
                     "- 104 vm `offline`", "VM.GuestAgent.Audit"):
            self.assertIn(line, section, line)
        unmanaged = r.stdout.split("## Network devices not in managed inventory")[1]
        self.assertIn("2 device(s)", unmanaged)
        self.assertIn("10.0.10.9 printer", unmanaged)
        self.assertIn("10.0.10.7 ilo-srv1 — bmc — **management controller (BMC)**", unmanaged)  # #17
        self.assertNotIn("printer.lab.example — linux — **", unmanaged)

    def test_inventory_reads_agent_and_lxc_ips_and_degrades_on_403(self):
        import urllib.error
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        calls = []

        def fake(path, **_):
            calls.append(path)
            if path.endswith("/agent/network-get-interfaces"):
                if "/101/" in path:
                    return {"result": [{"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1"}]},
                                       {"name": "eth0", "hardware-address": "bc:24:11:00:00:02",
                                        "ip-addresses": [{"ip-address": "10.0.10.80"}, {"ip-address": "fe80::1"}]}]}
                raise closed_http_error(path, 403, "Forbidden", {}, None)
            if path.endswith("/interfaces"):
                return [{"name": "eth0", "hwaddr": "bc:24:11:00:00:01", "inet": "10.0.10.53/24"}]
            raise AssertionError(path)
        pve._get = fake
        src = {"agent": "not queried", "lxc": "not queried"}
        vm = lambda vmid: {"node": "pve1", "vmid": vmid}
        self.assertEqual([a["ip"] for a in inv.guest_ips(pve, vm(101), "qemu", {"agent": "1"}, src)], ["10.0.10.80"])
        self.assertEqual(inv.guest_ips(pve, vm(102), "qemu", {"agent": "enabled=1,fstrim_cloned_disks=1"}, src), [])
        self.assertIn("VM.GuestAgent.Audit", src["agent"])
        n = len(calls)
        self.assertEqual(inv.guest_ips(pve, vm(103), "qemu", {"agent": "1"}, src), [])  # no retry after 403
        self.assertEqual(inv.guest_ips(pve, vm(104), "qemu", {"agent": "0"}, src), [])
        self.assertEqual(len(calls), n)
        self.assertEqual(inv.guest_ips(pve, vm(901), "lxc", {}, src)[0]["ip"], "10.0.10.53")


    def test_lxc_lists_configured_ip_and_marks_extra(self):  # GitHub issue #61
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        pve._get = lambda path, **_: [{"name": "eth0", "hwaddr": "bc:24:11:00:00:01", "inet": "10.0.10.250/24"},
                                      {"name": "eth1", "hwaddr": "bc:24:11:00:00:02", "inet": "10.0.20.251/24"}]
        conf = {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=10.0.10.251/24,tag=10",
                "net1": "name=eth1,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=10.0.20.251/24",
                "net2": "name=eth2,bridge=vmbr0,ip=dhcp"}
        out = inv.guest_ips(pve, {"node": "pve1", "vmid": 901}, "lxc", conf, {"lxc": ""})
        self.assertEqual([(a["iface"], a["ip"], a["source"], a.get("extra", False)) for a in out],
                         [("eth0", "10.0.10.251", "config", False), ("eth1", "10.0.20.251", "config", False),
                          ("eth0", "10.0.10.250", "lxc", True)])
        self.assertEqual(out[0]["mac"], "bc:24:11:00:00:01")

    def test_reachable_address_ranked_first(self):  # GitHub issue #56
        sys.path.insert(0, str(SCRIPTS))
        import ipaddress
        import hmlib
        import proxmox_to_inventory as p2i
        g = {"type": "vm", "config": {"net0": "virtio=BC:24:11:AA:BB:01,bridge=vmbr0,tag=20"},
             "ips": [{"iface": "wg0", "mac": "00:00:00:00:00:00", "ip": "10.99.0.2", "source": "agent"},
                     {"iface": "docker0", "mac": "02:42:ac:11:00:01", "ip": "172.17.0.1", "source": "agent"},
                     {"iface": "ens18", "mac": "bc:24:11:aa:bb:01", "ip": "fe80::1", "source": "agent"},
                     {"iface": "ens18", "mac": "bc:24:11:aa:bb:01", "ip": "192.168.20.15", "source": "agent"}]}
        site = [ipaddress.ip_network("192.168.20.0/24")]
        self.assertEqual(p2i.pick_ip(g, [], site), "192.168.20.15")
        self.assertEqual(p2i.pick_ip(g, [], None), "192.168.20.15")      # NIC MAC wins without ranges too
        self.assertEqual(p2i.pick_ip(g, [ipaddress.ip_network("10.99.0.0/24")], site), "10.99.0.2")  # --range
        g["config"] = {"net0": "virtio,bridge=vmbr0"}                     # no MAC to match: the range decides
        self.assertEqual(p2i.pick_ip(g, [], site), "192.168.20.15")
        g["ips"] = g["ips"][:2]                                           # only virtual interfaces left
        self.assertEqual([a["ip"] for a in hmlib.rank_guest_addresses(g, site)], ["10.99.0.2", "172.17.0.1"])  # order found
        lxc = {"type": "lxc", "config": {"net0": "name=eth0,hwaddr=BC:24:11:00:00:01,ip=10.0.10.251/24"},
               "ips": [{"iface": "eth0", "mac": "bc:24:11:00:00:01", "ip": "10.0.10.250", "source": "lxc",
                        "extra": True}]}
        self.assertEqual(p2i.pick_ip(lxc, [], None), "10.0.10.251")       # configured, not the VIP

    def test_details_keep_what_pins_a_guest_to_its_node(self):  # issue 23
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        conf = {"scsi0": "ceph:vm-1-disk-0,size=32G", "efidisk0": "local-zfs:vm-1-disk-1", "hostpci0": "0000:01:00",
                "usb0": "host=1-2", "startup": "order=2,up=30", "onboot": 1, "description": "hi", "lock": "backup",
                "unused0": "local-zfs:vm-1-disk-2", "tpmstate0": "local-zfs:vm-1-disk-3", "args": "-cpu host"}
        out = inv.guest_config(conf)
        for k in ("scsi0", "efidisk0", "hostpci0", "usb0", "startup", "onboot", "unused0", "tpmstate0"):
            self.assertIn(k, out)
        self.assertNotIn("lock", out)
        self.assertNotIn("args", out)
        self.assertEqual(out["description"], "[untrusted] hi")
        lxc = inv.guest_config({"unprivileged": 1, "features": "nesting=1,keyctl=1", "hostname": "ct", "lock": "x"})
        self.assertEqual(lxc, {"unprivileged": "1", "features": "nesting=1,keyctl=1",   # GitHub issue #139
                               "hostname": "ct"})                                     # #149: an LXC entry's key

    def test_no_guests_hint_names_narrow_acl(self):  # GitHub issue #14
        sys.path.insert(0, str(SCRIPTS))
        import proxmox_inventory as inv
        pve = inv.PVE("https://pve.example:8006", "homelab@pve!ro=s3cret", None)
        perms = {"/": {"VM.Audit": 1, "VM.GuestAgent.Audit": 1}, "/vms": {"VM.GuestAgent.Audit": 1}}
        pve._get = lambda path, **_: perms
        hint = inv.no_guests_hint(pve)
        self.assertIn("/vms lacks VM.Audit", hint)
        self.assertIn("next to PVEAuditor", hint)
        del perms["/vms"]
        self.assertIsNone(inv.no_guests_hint(pve))
        self.assertIn("no VM.Audit on /", inv.no_guests_hint(type("P", (), {"_get": lambda self, p: {"/": {}}})()))
        s = inv.summary({"version": "9.1", "cluster": None, "nodes": [], "guests": [], "storage": [],
                         "warnings": ["no guests visible: x"]})
        self.assertIn("Warning: no guests visible: x.", s)


class GuestNicTests(unittest.TestCase):  # GitHub issue #97: VLAN and IP of the same NIC
    def test_nic_order_and_pairing(self):
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        g = {"config": {"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr1",
                        "net10": "virtio=BC:24:11:00:00:0A,bridge=vmbr0,tag=4051",
                        "net2": "virtio=BC:24:11:00:00:02,bridge=vmbr0,tag=4040",
                        "ipconfig2": "ip=10.9.40.1/24"},
             "ips": [{"ip": "10.9.51.1", "mac": "bc:24:11:00:00:0a", "source": "agent"}]}
        self.assertEqual([n["idx"] for n in hmlib.guest_nics(g)], [0, 2, 10])
        self.assertEqual(hmlib.guest_nics(g)[2]["ips"], ["10.9.51.1"])          # agent address by MAC
        self.assertEqual(hmlib._guest_net(g), ("10.9.40.1", 4040))               # first NIC with an IP, its tag
        self.assertEqual(hmlib._guest_net(g, prefer_ip="10.9.51.1"), ("10.9.51.1", 4051))
        self.assertEqual(hmlib._guest_net({"config": {"net0": "virtio=x,bridge=vmbr0,tag=7",
                                                      "net1": "virtio=y,bridge=vmbr0,tag=8"}}), (None, 7))


class GuestMapTests(unittest.TestCase):  # GitHub issue #62
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "proxmox,ansible", cwd=self.d)
        subprocess.run(["yq", "-i", '.network.vlans = [{"id": 10, "name": "INFRA", "cidr": "10.0.10.0/24"}, '
                        '{"id": 20, "name": "DMZ", "cidr": "10.0.20.0/24"}] | .vmid_scheme = "{vlan}{octet:03d}"',
                        str(self.d / "homelab.yaml")], check=True)
        guests = [
            {"vmid": 10011, "name": "proxy1", "type": "lxc", "node": "pve1", "status": "running",
             "config": {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=10.0.10.11/24,tag=10"},
             "ips": [{"iface": "eth0", "mac": "bc:24:11:00:00:01", "ip": "10.0.10.11", "source": "config"},
                     {"iface": "eth0", "mac": "bc:24:11:00:00:01", "ip": "10.0.10.250", "source": "lxc", "extra": True}]},
            {"vmid": 20015, "name": "web01", "type": "vm", "node": "pve1", "status": "running",
             "config": {"net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0,tag=20",
                        "net1": "virtio=BC:24:11:00:00:03,bridge=vmbr0,tag=30"},
             "ips": [{"iface": "ens18", "mac": "bc:24:11:00:00:02", "ip": "10.0.10.15", "source": "agent"},
                     {"iface": "wg0", "mac": "00:00:00:00:00:00", "ip": "10.99.0.2", "source": "agent"}]},
            {"vmid": 10002, "name": "chr", "type": "vm", "node": "pve1", "status": "running",
             "config": {"net0": "virtio=BC:24:11:00:00:04,bridge=vmbr0,tag=10"}},
            {"vmid": 9000, "name": "tpl", "type": "vm", "template": True, "config": {}},
        ]
        (self.d / "discovery/proxmox.json").write_text(json.dumps({"collected_at": "t", "guests": guests}))
        (self.d / "discovery/network.json").write_text(json.dumps({"hosts": {
            "10.0.10.11": {"hostnames": ["proxy1"]}, "10.0.10.5": {"hostnames": ["switch"]}}}))
        (self.d / "discovery/routeros.json").write_text(json.dumps({"devices": {"10.0.10.1": {
            "interfaces": [{"name": "ether1", "mac-address": "BC:24:11:00:00:04"}],
            "addresses": [{"address": "10.0.10.1/24", "interface": "ether1"}]}}}))
        (self.d / "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n        proxy1:\n          ansible_host: 10.0.10.250\n"
            "        web01:\n          ansible_host: 10.0.20.15\n          proxmox_vmid: 20015\n")

    def test_map_and_findings(self):
        r = run("guest_map.py", "--out", "-", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn("10.0.10.11 (config), +10.0.10.250 (lxc)", out)
        self.assertIn("proxy1 uses 10.0.10.250, an extra address", out)
        self.assertIn("20015 web01 net0: 10.0.10.15 is outside VLAN 20's 10.0.20.0/24", out)
        self.assertIn("net1: VLAN tag 30 is not in network.vlans", out)
        self.assertIn("net1: running, no address known", out)
        self.assertIn("Ansible host web01 has ansible_host 10.0.20.15, not one of the guest's addresses", out)
        self.assertIn("10002 chr: vmid_scheme {vlan}{octet:03d} gives 10001 for 10.0.10.1 on VLAN 10", out)
        self.assertNotIn("gives 20015", out)                                # VMID fits its scheme
        self.assertIn("10.0.10.1 (routeros)", out)                         # CHR address by MAC
        self.assertNotIn("10.99.0.2", out)                                 # tunnel interface left out
        self.assertNotIn("tpl", out)
        self.assertIn("- 10.0.10.5 switch (VLAN 10 INFRA)", out)
        self.assertNotIn("- 10.0.10.11", out)
        r = run("guest_map.py", "--no-ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.d / "discovery/guest-map.md").exists())


class DiscoveryLayoutTests(unittest.TestCase):  # GitHub issue #73
    def test_old_per_bmc_playbook_offered_the_merged_layout(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "ansible,appliances", cwd=d)
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertNotIn("bmc-one-file", ids())
        pb = d / "ansible/playbooks/bmc-info.yml"
        pb.write_text(pb.read_text().replace("discovery/bmc.json", "discovery/bmc-{{ inventory_hostname }}.json"))
        self.assertIn("bmc-one-file", ids())
        pb.unlink()      # no playbook at all: bmc-redfish offers it instead
        self.assertNotIn("bmc-one-file", ids())
        self.assertIn("bmc-redfish", ids())

    def test_bmc_playbook_without_vendor_workarounds_offered_the_template(self):  # GitHub issue #74
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "ansible,appliances", cwd=d)
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertNotIn("bmc-vendor-quirks", ids())
        pb = d / "ansible/playbooks/bmc-info.yml"
        pb.write_text(pb.read_text().replace("bmc_categories", "bmc_cats"))   # a 0.28.0 copy: one combined call
        self.assertIn("bmc-vendor-quirks", ids())
        pb.write_text(pb.read_text().replace("discovery/bmc.json", "discovery/bmc-{{ inventory_hostname }}.json"))
        self.assertEqual([i for i in ids() if i.startswith("bmc-")], ["bmc-one-file"])   # one note, not two

    def test_sync_managed_moves_per_site_files_into_one_file_per_kind(self):  # GitHub issue #75
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "proxmox,ansible,discovery,appliances", cwd=d)
        r = run("config_set.py", "sites+={name: home}", "sites+={name: offsite, proxmox: {endpoint: 'https://x:8006'}}",
                cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        disc = d / "discovery"
        old = {"proxmox.json": {"guests": [{"vmid": 100}]}, "proxmox-offsite.json": {"site": "offsite", "guests": []},
               "network.json": {"hosts": {"10.0.0.1": {}}}, "network-offsite.json": {"site": "offsite", "hosts": {}},
               "unifi.json": {"sites": ["Default"], "devices": []},
               "pve-patch-pve1.json": {"node": "pve1", "site": "home", "guests": []},
               "pve-patch-pve1-state.json": {"node": "pve1", "guests": [{"vmid": 100}]},
               "pve-patch-offsite-pve1.json": {"node": "pve1", "site": "offsite", "guests": []}}
        for name, doc in old.items():
            (disc / name).write_text(json.dumps(doc))
        out = run("init_repo.py", str(d), "--sync-managed", "--dry-run", cwd=d).stdout
        self.assertIn("discovery/: move", out)
        self.assertTrue((disc / "proxmox-offsite.json").exists())                   # dry run: nothing moved
        r = run("init_repo.py", str(d), "--sync-managed", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(f.name for f in disc.glob("*.json")),
                         ["network.json", "proxmox.json", "pve-patch.json", "unifi.json"])
        sites = lambda kind: json.loads((disc / f"{kind}.json").read_text())["sites"]
        self.assertEqual(sites("proxmox"), {"home": old["proxmox.json"], "offsite": old["proxmox-offsite.json"]})
        self.assertEqual(sorted(sites("network")), ["home", "offsite"])
        self.assertNotIn("site", sites("network")["offsite"])                     # its key says it (#82)
        self.assertEqual(sites("unifi"), {"home": old["unifi.json"]})
        plans = sites("pve-patch")
        self.assertEqual(plans["home"]["pve1"]["state_before"], old["pve-patch-pve1-state.json"])
        self.assertEqual((plans["home"]["pve1"]["default_site"], plans["offsite"]["pve1"]["default_site"]),
                         (True, False))
        self.assertNotIn("discovery/: move", run("init_repo.py", str(d), "--sync-managed", "--dry-run", cwd=d).stdout)
        net = json.loads((disc / "network.json").read_text())                      # moved by 0.29.x, key kept
        net["sites"]["offsite"]["site"] = "offsite"
        (disc / "network.json").write_text(json.dumps(net))
        self.assertIn('drop the redundant "site" key of offsite',
                      run("init_repo.py", str(d), "--sync-managed", "--dry-run", cwd=d).stdout)
        run("init_repo.py", str(d), "--sync-managed", cwd=d)
        self.assertNotIn("site", sites("network")["offsite"])
        self.assertEqual(sorted(sites("proxmox")["offsite"]), ["guests", "site"])   # proxmox.json keeps its key
        import hmlib                                                                 # readers see every site
        cfg = hmlib.load_config(d)
        self.assertEqual([s["name"] for s, _ in hmlib.proxmox_snapshots(cfg)], ["home", "offsite"])

    def test_site_files_keep_other_sites_and_read_old_layout(self):  # GitHub issue #75
        import hmlib
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        f = d / "discovery/network.json"
        f.parent.mkdir()
        f.write_text(json.dumps({"hosts": {"10.0.0.1": {}}}))                         # before 0.29.0
        home = {"name": "home", "default": True}
        off = {"name": "offsite", "default": False}
        self.assertEqual(hmlib.site_part(f, home), {"hosts": {"10.0.0.1": {}}})   # the default site's
        self.assertIsNone(hmlib.site_part(f, off))
        hmlib.write_site_part(f, off, {"hosts": {}})
        hmlib.write_site_part(f, home, {"hosts": {"10.0.0.2": {}}})
        self.assertEqual(json.loads(f.read_text()), {"sites": {"offsite": {"hosts": {}},
                                                               "home": {"hosts": {"10.0.0.2": {}}}}})
        unnamed = {"name": "", "default": True}                                     # no sites: in homelab.yaml
        hmlib.write_site_part(f, unnamed, {"hosts": {}})
        self.assertIn("default", hmlib.site_parts(f))
        self.assertEqual(hmlib.site_part(f, home), {"hosts": {"10.0.0.2": {}}})     # its own key wins

    def test_debian_sources(self):  # GitHub issue #84
        script = SCRIPTS.parent / "assets/repo-template/ansible/playbooks/tasks/debian-sources.sh"
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "sources.list.d").mkdir()
        (d / "preferences.d").mkdir()
        (d / "sources.list").write_text(
            "# comment\n"
            "deb http://deb.debian.org/debian bullseye main contrib non-free\n"
            "deb [arch=amd64] http://security.debian.org/debian-security bullseye-security main\n"
            "deb http://deb.debian.org/debian sid main\n"
            "deb http://cache.lan:3142/debian bullseye-backports main\n")
        (d / "sources.list.d/docker.list").write_text(
            "deb [signed-by=/k.asc] https://download.docker.com/linux/debian bullseye stable\n")
        (d / "sources.list.d/x.sources").write_text(
            "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bullseye bullseye-updates\n"
            "Components: main non-free\n\nTypes: deb\nURIs: https://repo.example/apt\nSuites: bullseye\n"
            "Components: main\n")
        (d / "preferences.d/unstable").write_text("Package: *\nPin: release a=unstable\nPin-Priority: 100\n")
        sh = lambda *a: subprocess.run(["sh", str(script), *a], env={**os.environ, "HM_APT_ROOT": str(d)},
                                       capture_output=True, text=True, check=True).stdout
        kinds = lambda out: sorted((l.split("\t")[1], l.split("\t")[2]) for l in out.splitlines())
        self.assertEqual(kinds(sh("list", "bullseye")), [
            ("debian", "bullseye"), ("debian", "bullseye bullseye-updates"), ("debian", "bullseye-security"),
            ("foreign", "bullseye"), ("foreign", "bullseye"), ("foreign", "bullseye-backports"), ("foreign", "sid")])
        self.assertIn(("debian", "bullseye-backports"), kinds(sh("list", "bullseye", "http://cache.lan:3142/")))
        self.assertEqual(sh("pins").strip(), str(d / "preferences.d/unstable"))
        sh("disable", "bullseye")
        sh("rewrite", "bullseye", "bookworm")
        text = (d / "sources.list").read_text()
        self.assertIn("deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware\n", text)
        self.assertIn("http://security.debian.org/debian-security bookworm-security main\n", text)
        self.assertIn("#hm-disabled deb http://deb.debian.org/debian sid main\n", text)
        self.assertIn("#hm-disabled deb [signed-by=/k.asc] https://download.docker.com", (d / "sources.list.d/docker.list").read_text())
        self.assertEqual((d / "sources.list.d/x.sources").read_text(),
                         "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm bookworm-updates\n"
                         "Components: main non-free non-free-firmware\n\nTypes: deb\nURIs: https://repo.example/apt\n"
                         "Suites: bullseye\nComponents: main\n#hm-disabled\nEnabled: no\n")
        self.assertEqual(sorted(f.name for f in (d / "preferences.d").iterdir()), ["unstable.hm-disabled"])
        self.assertEqual([l.split("\t")[1] for l in sh("list", "bookworm").splitlines()], ["debian"] * 3)
        (d / "sources.list").write_text("deb http://security.debian.org/debian-security buster/updates main\n")
        sh("rewrite", "buster", "bullseye")                                       # the suite was renamed
        self.assertEqual((d / "sources.list").read_text(),
                         "deb http://security.debian.org/debian-security bullseye-security main\n")

    def test_dist_upgrade_playbook(self):  # GitHub issue #84
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/dist-upgrade-debian.yml").read_text()
        pre, upgrade = pb.split("\n- name: Debian release upgrade\n")
        self.assertIn("any_errors_fatal: true", pre)
        self.assertIn("target_release == hm_next", pre)                           # one release at a time
        self.assertIn("ansible.builtin.meta: end_play\n      when: ansible_check_mode", upgrade)  # --check: pre-flight
        self.assertIn("serial: 1", upgrade)
        self.assertLess(upgrade.index("Snapshot"), upgrade.index("Point the Debian sources"))
        self.assertLess(upgrade.index("It removes nothing protected"), upgrade.index("systemd-run"))
        self.assertLess(upgrade.index("sshd configuration still valid"), upgrade.index("ansible.builtin.reboot"))
        self.assertIn("--force-confold", upgrade)
        self.assertIn("ansible/playbooks/dist-upgrade-debian.yml", (SCRIPTS / "init_repo.py").read_text())

    def test_dist_upgrade_ubuntu_playbook(self):  # GitHub issue #88
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/dist-upgrade-ubuntu.yml").read_text()
        pre, upgrade = pb.split("\n- name: Ubuntu release upgrade\n")
        self.assertIn("any_errors_fatal: true", pre)
        self.assertIn("hm_offered != target_release", pre)                        # Ubuntu decides the next release
        self.assertIn("'normal' if allow_non_lts | default(false) | bool else 'lts'", pre)
        self.assertIn("ansible.builtin.meta: end_play\n      when: ansible_check_mode", upgrade)
        self.assertIn("serial: 1", upgrade)
        order = [upgrade.index(t) for t in ("It offers {{ target_release }}", "- name: Snapshot\n",
                                            "- name: Back up the configuration", "DistUpgradeViewNonInteractive",
                                            "It removed nothing protected", "sshd configuration still valid",
                                            "ansible.builtin.reboot")]
        self.assertEqual(order, sorted(order))
        self.assertIn("RELEASE_UPGRADER_NO_SCREEN=1", upgrade)
        self.assertIn("ansible/playbooks/dist-upgrade-ubuntu.yml", (SCRIPTS / "init_repo.py").read_text())

    def test_routeros_restrict_playbook(self):  # GitHub issue #80
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/routeros-restrict-management.yml").read_text()
        order = [pb.index(t) for t in ("- name: Read the state\n", "- name: Safe to apply", "- name: Applying needs the user's yes",
                                       "- name: Limit the services", "- name: Read the state again", "- name: Everything planned")]
        self.assertEqual(order, sorted(order))
        self.assertIn("hm_me | length > 0 and hm_outside | length == 0", pb)           # never locks Ansible out
        self.assertIn("homelab_read_only | default(true)", pb)
        self.assertIn("find where !dynamic and name=", pb)                              # not the live connections
        self.assertEqual(pb.count("when: not ansible_check_mode") + pb.count("and not ansible_check_mode"), 5)
        self.assertIn("management_ranges: []", (SCRIPTS.parent / "assets/repo-template/homelab.yaml").read_text())
        self.assertIn("ansible/playbooks/routeros-restrict-management.yml", (SCRIPTS / "init_repo.py").read_text())

    def test_routeros_routerboot_playbook(self):  # GitHub issue #140
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/routeros-routerboot-upgrade.yml").read_text()
        order = [pb.index(t) for t in ("- name: Read the state\n", "- name: One device per run", "- name: Upgrade RouterBOOT\n",
                                       "- name: Applying needs the user's yes", "- name: Stage the firmware",
                                       "- name: The log says the firmware was upgraded", "- name: Reboot\n",
                                       "- name: Wait for the device to go down", "- name: Wait for SSH to come back",
                                       "- name: The new firmware is running")]
        self.assertEqual(order, sorted(order))
        self.assertIn("homelab_read_only | default(true)", pb)
        self.assertIn("serial: 1", pb)
        self.assertIn("routeros_routerboot_many | default(false)", pb)
        self.assertIn("routeros_routerboot_gateway | default(false)", pb)
        self.assertIn("route -n get default", pb)
        self.assertNotIn("check_mode: false", pb[pb.index("- name: Upgrade RouterBOOT\n"):])  # nothing runs under --check
        self.assertEqual(pb.count(":execute script="), 2)                    # no interactive prompt over network_cli
        self.assertIn("ansible/playbooks/routeros-routerboot-upgrade.yml", (SCRIPTS / "init_repo.py").read_text())

    def test_check_updates_target_scopes_every_play(self):  # GitHub issue #92
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/check-updates.yml").read_text()
        hosts = dict(re.findall(r'^- name: (.+)\n  hosts: "(.+)"$', pb, re.M))
        self.assertEqual(hosts["Pending updates on Linux"],
                         "{{ (target | replace(',', ':')) if target is defined else 'linux' }}:!windows:!appliances:!qnap")
        self.assertEqual(hosts["Pending updates on Windows (search only, installs nothing)"],
                         "{{ windows_target | default((target | replace(',', ':') ~ ':&windows') if target is defined "
                         "else 'windows') }}")
        self.assertIn("target | replace(',', ':') ~ ':&qnap'", hosts["Firmware and app versions on QNAP NAS (reads files only)"])
        self.assertTrue(hosts["Write discovery/updates.json"].startswith(
            "{{ (target | replace(',', ':')) if target is defined else 'linux:windows:qnap' }}"))

    def test_check_updates_comma_target_never_splits_a_pattern(self):  # GitHub issue #129
        # Ansible splits a pattern on commas first, so `a,b:&windows` intersects only b: wherever a target is
        # joined to more pattern terms, its commas must have become colons
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/check-updates.yml").read_text()
        hosts = re.findall(r'^  hosts: "(.+)"$', pb, re.M)
        self.assertEqual(len(hosts), 4)
        for h in hosts:
            for var in re.findall(r"\b(target|windows_target|qnap_target)\b(?! is defined)(?! \| default)", h):
                self.assertRegex(h, rf"\b{var} \| replace\(',', ':'\)")
            self.assertNotRegex(h, r"\btarget \| default\(")

    def test_set_fact_blocks_that_render_nothing_stay_strings(self):  # GitHub issue #136
        # Ansible turns a set_fact value whose Jinja block renders nothing into None, and `None | length` fails
        # the host: a block that may be empty goes in task vars, the fact is `default('', true)` of it
        for pb in sorted((SCRIPTS.parent / "assets/repo-template/ansible/playbooks").glob("*.yml")):
            text = pb.read_text()
            for task in re.split(r"\n    - name: ", text):
                if "ansible.builtin.set_fact:" not in task:
                    continue
                facts = task.split("ansible.builtin.set_fact:")[1].split("\n      vars:")[0]
                self.assertNotRegex(facts, r"\n        \w+: >-\n *\{%-? if", f"{pb.name}: {task.splitlines()[0]}")
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/patch-linux.yml").read_text()
        self.assertIn("hm_autoremove_skip: \"{{ hm_skip_why | default('', true) }}\"", pb)
        self.assertNotIn("hm_autoremove_skip | default('') |", pb)

    def test_patch_linux_names_sssd_socket_conflict(self):  # GitHub issue #142
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/patch-linux.yml").read_text()
        task = pb.split("- name: New failed SSSD units with the socket-activation conflict")[1].split("- name:")[0]
        self.assertIn("grep -q socket-activated", task)            # both SSSD 2.8 and 2.10 wordings say it
        self.assertIn("failed_when: false", task)
        pattern = re.search(r"select\('match', '([^']+)'\)", task).group(1)
        units = ["sssd-nss.socket", "sssd-pam-priv.socket", "sssd-pac.service", "sssd.service", "sssd-kcm.socket.d",
                 "chrony.service"]
        self.assertEqual([u for u in units if re.match(pattern, u)],
                         ["sssd-nss.socket", "sssd-pam-priv.socket", "sssd-pac.service"])
        check = pb.split("- name: No new failed units")[1].split("\n    - name:")[0]
        self.assertIn("Known SSSD socket conflict, not caused by the update", check)
        self.assertIn("selectattr('rc', 'eq', 0)", check)
        self.assertIn('"SSSD socket conflict"', check)
        self.assertLess(pb.index("New failed SSSD units"), pb.index("- name: No new failed units"))
        self.assertIn("### SSSD socket conflict", (SCRIPTS.parent / "references/patching.md").read_text())

    def test_check_updates_covers_qnap_read_only(self):  # GitHub issue #81
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/check-updates.yml").read_text()
        play = pb.split("- name: Firmware and app versions on QNAP NAS")[1].split("\n- name:")[0]
        self.assertIn("qnap_target | default((target | replace(',', ':') ~ ':&qnap') if target is defined else 'qnap')", play)
        self.assertIn("(':' ~ qnap_target | replace(',', ':')) if qnap_target is defined",
                      pb.split("- name: Write discovery/updates.json")[1])
        self.assertNotIn("become", play)                                         # raw only, as the NAS user
        modules = set(re.findall(r"^\s+(ansible\.builtin\.\w+):", play, re.M))
        self.assertEqual(modules, {"ansible.builtin.raw", "ansible.builtin.set_fact"})
        self.assertNotRegex(play, r"curl|wget|qpkg_cli|live_update|update\.qnap")  # asks no server, changes nothing
        self.assertIn("version_type='loose'", play)                              # newer only, not just different

    def test_bmc_playbook_reads_one_category_per_call(self):  # GitHub issue #74
        pb = (SCRIPTS.parent / "assets/repo-template/ansible/playbooks/bmc-info.yml").read_text()
        self.assertIn('category: "{{ item.category }}"', pb)
        self.assertIn("ignore_errors: true", pb)
        for c in ("Systems", "Chassis", "Manager", "Update"):
            self.assertIn(f"{{category: {c}, command:", pb)
        self.assertIn("/Thermal", pb.replace("'Thermal'", "/Thermal"))
        self.assertIn("PowerMetrics.AverageConsumedWatts", pb)
        gv = (SCRIPTS.parent / "assets/repo-template/ansible/inventory/managed/group_vars/bmc.yml").read_text()
        self.assertIn("bmc_secret_env ~ '_USER'", gv)


    def test_discovery_readme_lists_every_file_written_there(self):
        """Every discovery/ file a script or scaffolded playbook names matches an entry of discovery/README.md."""
        assets = SCRIPTS.parent / "assets"
        readme = (assets / "repo-template/discovery/README.md").read_text()

        def pattern(p):  # `network[-<site>].json`: [..] optional, <..> any name
            out = ""
            for tok in re.findall(r"<[^>]+>|\[|\]|[^<\[\]]+", p):
                out += "[^/]+" if tok.startswith("<") else "(?:" if tok == "[" else ")?" if tok == "]" else re.escape(tok)
            return re.compile(out + r"\Z")

        entries = [pattern(e) for e in re.findall(r"^- `([^`]+\.(?:json|md))`", readme, re.M)]
        self.assertGreater(len(entries), 5)
        files = [*SCRIPTS.glob("*.py"), *(assets / "repo-template/ansible/playbooks").rglob("*.yml")]
        seen = set()
        for f in files:
            for m in re.finditer(r'discovery(?:/|"\s*/\s*\(?f?")([\w\-\[\]<>{}.*]+?\.(?:json|md))', f.read_text()):
                name = re.sub(r"<[^>]+>|\{[^}]+\}|\b[A-Z]{2,}\b", "x", m.group(1)).replace("-*", "-x").replace("*", "")
                name = name.replace("[", "").replace("]", "")
                seen.add(name)
                self.assertTrue(any(e.match(name) for e in entries), f"{f.name}: discovery/{m.group(1)}")
        self.assertIn("bmc.json", seen)
        self.assertFalse([e for e in re.findall(r"^- `([^`]+)`", readme, re.M) if "site" in e])  # #75


    def test_old_discovery_readme_is_replaced_or_offered(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", str(d), "--components", "discovery", cwd=d)
        ids = lambda: [n["id"] for n in json.loads(run("upgrade_notes.py", "--json", "--all", cwd=d).stdout)]
        self.assertNotIn("discovery-readme-complete", ids())
        old = subprocess.run(["git", "show", "v0.27.0:skills/homelab-manager/assets/repo-template/discovery/README.md"],
                             cwd=ROOT, capture_output=True, text=True)
        if old.returncode:
            self.skipTest("release tags not available")
        readme = d / "discovery/README.md"
        readme.write_text(old.stdout)       # unedited old template: --sync-managed replaces it
        run("init_repo.py", str(d), "--sync-managed", cwd=d)
        self.assertIn("nothing needs adding to it", readme.read_text())
        readme.write_text(old.stdout + "- `guest-map.md` — added by hand\n")   # edited: offered instead
        run("init_repo.py", str(d), "--sync-managed", cwd=d)
        self.assertIn("added by hand", readme.read_text())
        self.assertIn("discovery-readme-complete", ids())


FAKE_NMAP = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_NMAP_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
out = args[args.index("-oX") + 1]
rows = "".join(f'<host><status state="up" reason="syn-ack"/><address addr="{ip}" addrtype="ipv4"/></host>'
               for ip in ("10.0.0.5", "10.0.0.9"))
open(out, "w").write(f"<nmaprun>{rows}</nmaprun>")
'''

# runs nmap_scan.main() with the probes nmap_scan sends itself faked, so tests send no packets (GitHub issue #128):
# FAKE_ICMP = addresses that answer the ICMP sweep, FAKE_ARP = `arp -an` output, FAKE_ROUTE = "en0" or "en0,gw"
NMAP_SCAN_RUNNER = r'''
import json, os, sys
sys.path.insert(0, os.environ["HM_SCRIPTS"])
import nmap_scan
answers = set(filter(None, os.environ.get("FAKE_ICMP", "").split(",")))
def fake_icmp(addrs, **kw):
    if os.environ.get("FAKE_ICMP") == "none":   # no unprivileged ICMP socket
        return None
    with open(os.environ["FAKE_NMAP_LOG"] + ".icmp", "a") as f:
        f.write(json.dumps(addrs) + "\n")
    return {a for a in addrs if a in answers}
nmap_scan.icmp_sweep = fake_icmp
nmap_scan.arp_table = lambda: nmap_scan.parse_arp(os.environ.get("FAKE_ARP", ""))
if "FAKE_ROUTE" in os.environ:
    iface, _, gw = os.environ["FAKE_ROUTE"].partition(",")
    nmap_scan.route_get = lambda ip: (iface or None, gw == "gw")
nmap_scan.reverse_names = lambda ips, **kw: {}
sys.argv = ["nmap_scan.py", *sys.argv[1:]]
sys.exit(nmap_scan.main())
'''


class PerSiteScanTests(unittest.TestCase):  # GitHub #72, #66: scans know their site, exclusions may name one
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "ansible,discovery", cwd=self.d)
        r = run("config_set.py", "network.authorized_ranges+=10.0.0.0/24",
                "sites+={name: home, ranges: [10.0.0.0/24]}", "sites+={name: offsite, ranges: [10.0.0.0/24]}",
                "network.excluded_hosts+=10.0.0.1", "network.excluded_hosts+={ip: 10.0.0.5, site: offsite}",
                "discovery.ignore_unmanaged+={ip: 10.0.0.9, site: home}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        bin_ = self.d / "bin"
        bin_.mkdir()
        (bin_ / "nmap").write_text(FAKE_NMAP)
        (bin_ / "nmap").chmod(0o755)
        self.log = self.d / "nmap.log"
        self.env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "FAKE_NMAP_LOG": str(self.log),
                    "HM_SCRIPTS": str(SCRIPTS), "FAKE_ICMP": "10.0.0.5,10.0.0.9"}
        self.runner = bin_ / "nmap_scan_runner.py"
        self.runner.write_text(NMAP_SCAN_RUNNER)
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib

    def nmap(self, *args, **env):
        return subprocess.run([sys.executable, str(self.runner), *args], cwd=self.d, env={**self.env, **env},
                              capture_output=True, text=True)

    def test_host_timeout(self):
        for args, want in [((), ["--host-timeout", "15m"]), (("--host-timeout", "5m"), ["--host-timeout", "5m"]),
                           (("--host-timeout", "0"), [])]:
            r = self.nmap("10.0.0.0/24", "--site", "home", "--profile", "services", *args)
            self.assertEqual(r.returncode, 0, r.stderr)
            argv = json.loads(self.log.read_text().splitlines()[-1])
            got = argv[argv.index("--host-timeout"):argv.index("--host-timeout") + 2] if "--host-timeout" in argv else []
            self.assertEqual(got, want, args)
        r = self.nmap("10.0.0.0/24", "--site", "home", "--tcp")    # a ping sweep has no per-host timeout
        self.assertNotIn("--host-timeout", json.loads(self.log.read_text().splitlines()[-1]))

    def test_ctrl_c_stops_nmap(self):
        sys.path.insert(0, str(SCRIPTS))
        import nmap_scan
        slow = self.d / "slow.py"
        slow.write_text("import time\nprint('Stats: 0:00:01 elapsed', flush=True)\ntime.sleep(60)\n")
        procs = []
        real_popen = subprocess.Popen

        def popen(*a, **kw):
            procs.append(real_popen(*a, **kw))
            return procs[-1]

        def interrupt(*a, **kw):
            raise KeyboardInterrupt
        with unittest.mock.patch.object(nmap_scan.subprocess, "Popen", popen), \
                unittest.mock.patch("builtins.print", interrupt), self.assertRaises(KeyboardInterrupt):
            nmap_scan.run_nmap([sys.executable, str(slow)])
        self.assertIsNotNone(procs[0].poll())   # the child is gone, not left running

    def scan(self, *args):
        r = self.nmap("10.0.0.0/24", "--tcp", *args)
        self.assertEqual(r.returncode, 0, r.stderr)
        last = json.loads(self.log.read_text().splitlines()[-1])
        return last[last.index("--exclude") + 1], r

    def test_entries_and_scope(self):
        h = self.h
        cfg = h.load_config(self.d)
        ex = lambda st: [str(n) for n in h.scan_scope(cfg, st)[1]]
        self.assertEqual(ex("home"), ["10.0.0.1/32"])
        self.assertEqual(ex("offsite"), ["10.0.0.1/32", "10.0.0.5/32"])
        self.assertEqual(ex(None), ["10.0.0.1/32", "10.0.0.5/32"])                  # site unknown: every entry
        self.assertEqual([str(n) for n in h.site_entries(cfg, "discovery.ignore_unmanaged", "offsite")], [])
        self.assertEqual(h.network_file("/r").name, "network.json")   # every site inside (#75)
        self.assertEqual(h.outside_site(cfg, h.site(cfg, "home"), ["10.0.0.0/25", "10.0.1.5"]), ["10.0.1.5"])
        found = "\n".join(h.site_ambiguities(cfg))
        self.assertIn("network.excluded_hosts: 10.0.0.1 is in ranges sites home and offsite share", found)
        self.assertNotIn("10.0.0.5 is in", found)                                   # names its site
        for bad in ({"ip": "10.0.0.7", "site": "moon"}, {"ip": "10.0.0.7"}):
            with self.assertRaises(h.ConfigError):
                h.sites({**cfg, "network": {**cfg["network"], "excluded_hosts": [bad]}})
        r = run("config_set.py", "network.excluded_hosts+={ip: 10.0.0.7, site: moon}", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)                                         # refused before writing
        import ssh_probe
        db = {"hosts": {"10.0.0.5": {"ports": [{"port": 22}]}}}
        self.assertEqual(ssh_probe.select(db, [], cfg, set(), False, 22, "home")[0], ["10.0.0.5"])
        self.assertEqual(ssh_probe.select(db, [], cfg, set(), False, 22, "offsite")[0], [])

    def test_address_ranges_in_exclusions(self):  # GitHub issue #124
        r = run("config_set.py", "network.excluded_hosts+=10.0.0.101-254",
                "network.excluded_hosts+={ip: 10.0.0.20-23, site: offsite}",
                "discovery.ignore_unmanaged+=10.0.0.30-31", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(" 10.0.0.101-254,", (self.d / "homelab.yaml").read_text())     # kept as written
        cfg = self.h.load_config(self.d)
        ex = [n for n in self.h.scan_scope(cfg, "home")[1]]
        import ipaddress
        covered = {str(a) for n in ex for a in n}
        self.assertEqual(covered, {"10.0.0.1"} | {f"10.0.0.{i}" for i in range(101, 255)})
        self.assertNotIn("10.0.0.20", {str(a) for n in self.h.scan_scope(cfg, "home")[1] for a in n})
        self.assertIn("10.0.0.21", {str(a) for n in self.h.scan_scope(cfg, "offsite")[1] for a in n})
        self.assertTrue(self.h.ignored_address(cfg, "10.0.0.31", "home"))
        self.assertFalse(self.h.ignored_address(cfg, "10.0.0.32", "home"))
        excl, _ = self.scan("--site", "home")
        self.assertIn("10.0.0.128/26", excl.split(","))
        self.assertTrue(all(ipaddress.ip_network(x) for x in excl.split(",")))      # nmap gets CIDR blocks
        with self.assertRaisesRegex(self.h.ConfigError, "a range a.b.c.x-y"):        # backwards range
            self.h.scan_scope({**cfg, "network": {**cfg["network"], "excluded_hosts": ["10.0.0.200-100"]}}, "home")
        with self.assertRaisesRegex(self.h.ConfigError, "'TVs' is one device"):      # a named device: one address
            self.h.sites({**cfg, "discovery": {"ignore_unmanaged": [{"ip": "10.0.0.40-41", "name": "TVs"}]}})
        with self.assertRaises(self.h.ConfigError):   # scan scope stays IPs and CIDRs
            self.h.scan_scope({**cfg, "network": {**cfg["network"], "authorized_ranges": ["10.0.0.1-50"]}})

    def test_ping_sweep_marks_missing_hosts_and_forget_drops_them(self):  # GitHub issue #127
        nmap = self.nmap
        net = self.h.network_file(self.d)
        home = self.h.site(self.h.load_config(self.d), "home")
        self.h.write_site_part(net, home, {"hosts": {ip: {"ip": ip, "last_seen": "2026-01-01T00:00:00+00:00"}
                                                     for ip in ("10.0.0.7", "10.0.0.1", "10.0.1.7")}})
        r = nmap("10.0.0.0/24", "--site", "home", "--tcp")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 known host(s) did not answer", r.stdout)
        hosts = self.h.site_part(net, home, "t")["hosts"]
        self.assertIn("missing_since", hosts["10.0.0.7"])          # inside the targets, did not answer
        self.assertNotIn("missing_since", hosts["10.0.0.1"])       # excluded: never scanned
        self.assertNotIn("missing_since", hosts["10.0.1.7"])       # outside the targets
        self.assertNotIn("missing_since", hosts["10.0.0.5"])       # answered
        first = hosts["10.0.0.7"]["missing_since"]
        hosts["10.0.0.7"]["missing_since"] = "2026-01-01T00:00:00+00:00"
        self.h.write_site_part(net, home, {"hosts": hosts})
        r = nmap("10.0.0.0/24", "--site", "home", "--profile", "services")   # --open: never marks
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("did not answer", r.stdout)
        self.assertEqual(self.h.site_part(net, home, "t")["hosts"]["10.0.0.7"]["missing_since"],
                         "2026-01-01T00:00:00+00:00")             # the first miss is kept
        self.assertTrue(first > "2026-01-01")
        before = self.log.read_text()
        self.assertNotEqual(nmap("--forget-missing", "30", "10.0.0.0/24", "--site", "home").returncode, 0)
        r = nmap("--forget-missing", "30", "--dry-run", "--site", "home")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("10.0.0.7", r.stdout)
        self.assertIn("10.0.0.7", self.h.site_part(net, home, "t")["hosts"])
        r = nmap("--forget-missing", "30", "--site", "home")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Dropped 1 host(s)", r.stdout)
        self.assertEqual(sorted(self.h.site_part(net, home, "t")["hosts"]),
                         ["10.0.0.1", "10.0.0.5", "10.0.0.9", "10.0.1.7"])
        self.assertEqual(self.log.read_text(), before)             # --forget-missing ran no nmap

    def test_ping_is_icmp_first_then_tcp_and_arp_on_request(self):  # GitHub issue #128
        net = self.h.network_file(self.d)
        home = self.h.site(self.h.load_config(self.d), "home")
        hosts = lambda: self.h.site_part(net, home, "t")["hosts"]
        r = self.nmap("10.0.0.0/24", "--site", "home")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.log.exists())                                    # ICMP only: no nmap
        self.assertIn("2 host(s) up (ICMP: 2)", r.stdout)
        self.assertIn("Re-run with --tcp", r.stdout)
        self.assertNotIn("--arp", r.stdout)                                    # routed (or unknown): no ARP hint
        r = self.nmap("10.0.0.0/24", "--site", "home", FAKE_ROUTE="en0")
        self.assertIn("or --arp (the Mac's ARP table", r.stdout)
        swept = json.loads(Path(str(self.log) + ".icmp").read_text().splitlines()[-1])
        self.assertEqual(len(swept), 253)                                      # .1-.254 minus the excluded .1
        self.assertNotIn("10.0.0.1", swept)
        self.assertEqual(hosts()["10.0.0.5"]["discovered_by"], ["icmp"])
        r = self.nmap("10.0.0.0/24", "--site", "home", "--tcp", FAKE_ICMP="10.0.0.9")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-PS22,80,443", " ".join(json.loads(self.log.read_text().splitlines()[-1])))
        self.assertIn("(ICMP: 1, TCP: 2)", r.stdout)
        self.assertEqual(hosts()["10.0.0.5"]["discovered_by"], ["tcp"])       # ICMP was sent and not answered
        self.assertEqual(hosts()["10.0.0.9"]["discovered_by"], ["icmp", "tcp"])
        r = self.nmap("10.0.0.0/24", "--site", "home", FAKE_ICMP="10.0.0.5")   # ICMP only again
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("missing_since", hosts()["10.0.0.9"])                    # answered ICMP before: missing now
        self.assertEqual(hosts()["10.0.0.5"]["discovered_by"], ["icmp", "tcp"])  # tcp not sent: kept
        h = hosts()
        h["10.0.0.6"] = {"ip": "10.0.0.6", "discovered_by": ["tcp"]}
        h["10.0.0.7"] = {"ip": "10.0.0.7"}                                      # from before 0.43.0
        self.h.write_site_part(net, home, {"hosts": h})
        r = self.nmap("10.0.0.0/24", "--site", "home", FAKE_ICMP="10.0.0.5")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("missing_since", hosts()["10.0.0.6"])                 # only TCP ever saw it
        self.assertNotIn("missing_since", hosts()["10.0.0.7"])                 # nmap's TCP probes found it
        r = self.nmap("10.0.0.0/24", "--site", "home", "--tcp", FAKE_ICMP="10.0.0.5")
        self.assertIn("missing_since", hosts()["10.0.0.6"])
        self.assertIn("missing_since", hosts()["10.0.0.7"])

        r = self.nmap("10.0.0.0/24", "--site", "home", "--arp", FAKE_ROUTE="en0,gw")
        self.assertEqual(r.returncode, 4)
        self.assertIn("reached through a gateway", r.stderr)
        arp = ("? (10.0.0.20) at 0:c:29:a:b:c on en0 ifscope [ethernet]\n"
               "? (10.0.0.9) at 52:54:0:12:34:56 on en0 ifscope [ethernet]\n"
               "? (10.0.0.30) at (incomplete) on en0 ifscope [ethernet]\n"
               "? (10.0.0.40) at 0:c:29:a:b:d on en1 ifscope [ethernet]\n"
               "? (10.0.0.1) at 0:c:29:a:b:e on en0 ifscope [ethernet]\n"
               "? (10.0.1.20) at 0:c:29:a:b:f on en0 ifscope [ethernet]\n")
        r = self.nmap("10.0.0.0/24", "--site", "home", "--arp", FAKE_ROUTE="en0", FAKE_ARP="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ARP table has no entry on en0", r.stderr)               # e.g. Local Network privacy
        self.assertIn("reached the network (ICMP answered), but macOS still hides the ARP table", r.stderr)  # #135
        self.assertIn("Re-run with the system Python: /usr/bin/python3 ", r.stderr)
        self.assertNotIn("allow it in System Settings", r.stderr)              # already allowed: nothing to do there
        r = self.nmap("10.0.0.0/24", "--site", "home", "--arp", FAKE_ROUTE="en0", FAKE_ARP="", FAKE_ICMP="none")
        self.assertIn("allow it in System Settings", r.stderr)                 # no ICMP: maybe not allowed yet
        self.assertIn("re-run with the system Python: /usr/bin/python3 ", r.stderr)
        r = self.nmap("10.0.0.0/24", "--site", "home", "--arp", FAKE_ROUTE="en0", FAKE_ARP=arp, FAKE_ICMP="10.0.0.9")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("ARP table has no entry", r.stderr)
        self.assertIn("(ICMP: 1, ARP: 2)", r.stdout)
        self.assertEqual(hosts()["10.0.0.20"]["discovered_by"], ["arp"])
        self.assertEqual(hosts()["10.0.0.20"]["mac"], "00:0C:29:0A:0B:0C")
        self.assertEqual(hosts()["10.0.0.9"]["discovered_by"], ["arp", "icmp", "tcp"])
        for ip in ("10.0.0.30", "10.0.0.40", "10.0.0.1", "10.0.1.20"):          # incomplete, other NIC, excluded,
            self.assertNotIn(ip, hosts())                                       # outside the targets
        self.assertIn("Re-run with --tcp", r.stdout)
        self.assertNotIn("--arp (", r.stdout)
        r = self.nmap("10.0.0.0/24", "--site", "home", "--arp", "--tcp", FAKE_ROUTE="en0", FAKE_ARP=arp)
        self.assertNotIn("Re-run", r.stdout)                                   # every probe sent

        r = self.nmap("10.0.0.0/24", "--site", "home", FAKE_ICMP="none")       # no ICMP socket: nmap's probes
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("(TCP: 2)", r.stdout)
        self.assertNotIn("missing_since", hosts()["10.0.0.20"])                # ARP-only: not probed this time

    def test_no_ping_and_profile_options(self):  # GitHub issue #128
        r = self.nmap("10.0.0.5", "--no-ping")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--no-ping goes with --profile services or os", r.stderr)
        for opt in ("--tcp", "--arp"):
            r = self.nmap("10.0.0.5", "--profile", "services", opt)
            self.assertEqual(r.returncode, 2)
            self.assertIn("go with the ping profile", r.stderr)
        r = self.nmap("10.0.0.0/24", "--profile", "services", "--no-ping")
        self.assertEqual(r.returncode, 4)
        self.assertIn("at most 16 addresses", r.stderr)
        self.assertFalse(self.log.exists())
        r = self.nmap("10.0.0.16/28", "--profile", "services", "--no-ping")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-Pn", json.loads(self.log.read_text().splitlines()[-1]))
        r = self.nmap("10.0.0.0/24", "--profile", "services")
        self.assertNotIn("-Pn", json.loads(self.log.read_text().splitlines()[-1]))
        net = self.h.network_file(self.d)
        home = self.h.site(self.h.load_config(self.d), "home")
        self.h.write_site_part(net, home, {"hosts": {"10.0.0.5": {"ip": "10.0.0.5"},
                                                     "10.0.0.6": {"ip": "10.0.0.6", "missing_since": "2026-01-01"}}})
        r = self.nmap("10.0.0.0/24", "--site", "home", "--profile", "services", "--only-live")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(self.log.read_text().splitlines()[-1])[-1:], ["10.0.0.5"])   # not the missing

    def test_site_scan_without_targets(self):  # GitHub #118: the site's ranges, clipped to the authorized ones
        r = run("config_set.py", "sites+={name: lab, ranges: [10.0.0.0/23, 10.9.0.0/24]}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = self.h.load_config(self.d)
        self.assertEqual(self.h.site_scan_ranges(cfg, "home"), (["10.0.0.0/24"], []))
        self.assertEqual(self.h.site_scan_ranges(cfg, "lab"),
                         (["10.0.0.0/24"], ["10.0.0.0/23 (scanning only 10.0.0.0/24)", "10.9.0.0/24"]))
        with self.assertRaises(self.h.ConfigError):
            self.h.site_scan_ranges(cfg, "moon")
        net = {"authorized_ranges": ["10.0.1.0/24", "10.0.0.0/16"]}
        with self.assertRaisesRegex(self.h.ConfigError, "has no ranges"):   # next to other sites: refused
            self.h.site_scan_ranges({"network": net, "sites": [{"name": "home"}, {"name": "lab"}]}, "lab")
        only = {"network": net, "sites": [{"name": "home"}]}
        self.assertEqual(self.h.site_scan_ranges(only, "home"), (["10.0.0.0/16"], []))   # GitHub #125
        nmap = self.nmap
        r = nmap("--site", "lab", "--profile", "services")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(self.log.read_text().splitlines()[-1])[-1], "10.0.0.0/24")
        self.assertIn("left out (not in network.authorized_ranges): 10.0.0.0/23 (scanning only 10.0.0.0/24), "
                      "10.9.0.0/24", r.stderr)
        self.assertNotIn("is this the right --site", r.stderr)
        self.assertEqual(sorted(json.loads((self.d / "discovery/network.json").read_text())["sites"]), ["lab"])
        r = nmap("--site=lab", "--only-live", "--profile", "services")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(self.log.read_text().splitlines()[-1])[-2:], ["10.0.0.5", "10.0.0.9"])
        self.assertIn("-Pn", json.loads(self.log.read_text().splitlines()[-1]))   # known hosts: no ping (#128)
        r = nmap("10.9.0.0/24", "--site", "lab")                                   # explicit targets: still refused
        self.assertEqual(r.returncode, 4)
        self.assertIn("outside the authorized ranges", r.stderr)
        r = nmap("--profile", "services")                                           # no targets, no site
        self.assertEqual(r.returncode, 3)
        self.assertIn("--site NAME", r.stderr)
        r = run("config_set.py", "sites+={name: vpn, ranges: [10.9.0.0/24]}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = nmap("--site", "vpn")
        self.assertEqual(r.returncode, 3)
        self.assertIn("nothing to scan", r.stderr)

    def test_scan_per_site_and_drift(self):
        excl, _ = self.scan("--site", "offsite")
        self.assertEqual(excl, "10.0.0.1/32,10.0.0.5/32")
        parts = lambda: json.loads((self.d / "discovery/network.json").read_text())["sites"]
        self.assertEqual(list(parts()), ["offsite"])
        self.assertEqual(sorted(parts()["offsite"]["hosts"]), ["10.0.0.5", "10.0.0.9"])
        self.assertEqual(list(self.d.glob("discovery/network-*.json")), [])        # no site in a file name (#75)
        excl, _ = self.scan("--site", "home")
        self.assertEqual(excl, "10.0.0.1/32")
        self.assertEqual(sorted(parts()), ["home", "offsite"])
        excl, _ = self.scan()
        self.assertEqual(excl, "10.0.0.1/32,10.0.0.5/32")                           # no --site: fail-safe
        hosts = self.d / "ansible/inventory/managed/hosts.yml"
        hosts.write_text(hosts.read_text().replace("    linux:\n", "    site_offsite:\n      hosts:\n"
                                                   "        web: {ansible_host: 10.0.0.5}\n    linux:\n", 1))
        r = run("drift_report.py", "--no-tofu", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        home = out[out.index("## Network devices not in managed inventory — site home"):]
        home, offsite = home.split("## Network devices not in managed inventory — site offsite")
        self.assertIn("- 10.0.0.5", home)          # the inventory host 10.0.0.5 is offsite's
        self.assertNotIn("10.0.0.9", home)         # ignored at home only
        self.assertIn("- 10.0.0.9", offsite)
        self.assertNotIn("10.0.0.5", offsite.split("##")[0])
        self.assertIn("| Network scan — site offsite |", out)
        import upgrade_notes
        note = next(n for n in upgrade_notes.all_notes() if n["id"] == "network-scans-per-site")
        self.assertTrue(upgrade_notes._check(note, self.h.load_config(self.d), self.d)[0])


class NmapLocalProbeTests(unittest.TestCase):  # GitHub issue #128
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import nmap_scan
        import ipaddress
        self.n, self.ip = nmap_scan, ipaddress

    def test_sweep_addresses(self):
        net = self.ip.ip_network
        self.assertEqual(len(self.n.sweep_addresses(["10.0.0.0/24"], [])), 254)
        self.assertEqual(self.n.sweep_addresses(["10.0.0.0/24"], [net("10.0.0.0/25"), net("10.0.0.128/26"),
                                                                  net("10.0.0.192/27"), net("10.0.0.224/28"),
                                                                  net("10.0.0.240/29")]),
                         [f"10.0.0.{i}" for i in range(248, 255)])
        self.assertEqual(self.n.sweep_addresses(["10.0.0.7", "10.0.0.6-8", "10.0.0.10/31"], []),
                         ["10.0.0.7", "10.0.0.6", "10.0.0.8", "10.0.0.10", "10.0.0.11"])
        self.assertEqual(len(self.n.sweep_addresses(["10.0.0.0/16"], [], limit=1000)), 1000)
        self.assertEqual(self.n.sweep_addresses(["fd00::/120"], []), [])        # ICMP sweep: IPv4 only

    def test_icmp_reply_type(self):
        echo = bytes([0, 0, 0, 0, 0x12, 0x34, 0, 1])
        self.assertEqual(self.n.icmp_reply_type(echo), 0)                       # Linux: no IP header
        self.assertEqual(self.n.icmp_reply_type(bytes([0x45]) + bytes(19) + echo), 0)   # macOS: with it
        self.assertEqual(self.n.icmp_reply_type(bytes([0x46]) + bytes(23) + bytes([3, 1, 0, 0])), 3)
        self.assertIsNone(self.n.icmp_reply_type(b""))
        hdr = bytes([8, 0, 0, 0, 0x12, 0x34, 0, 1]) + b"homelab-manager"
        pkt = hdr[:2] + self.n._icmp_checksum(hdr).to_bytes(2, "big") + hdr[4:]
        self.assertEqual(self.n._icmp_checksum(pkt), 0)

    def test_icmp_sweep(self):
        import errno, types
        n = self.n

        class Sock:
            AF_INET = SOCK_DGRAM = IPPROTO_ICMP = 0
            fail, queue, sent = None, [], []

            def __init__(self, *a):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def setblocking(self, flag):
                pass

            def sendto(self, pkt, addr):
                if Sock.fail:
                    raise OSError(Sock.fail, os.strerror(Sock.fail))
                Sock.sent.append(addr[0])
                if addr[0] in ("10.0.0.2", "10.0.0.3"):   # macOS: with the IP header
                    Sock.queue.append((bytes([0x45]) + bytes(19) + bytes([0]) + pkt[1:], (addr[0], 0)))
                Sock.queue.append((bytes([3, 1, 0, 0]), ("10.0.0.254", 0)))   # an unreachable from a router

            def recvfrom(self, size):
                if not Sock.queue:
                    raise BlockingIOError
                return Sock.queue.pop(0)

        fake = types.SimpleNamespace(socket=Sock, AF_INET=0, SOCK_DGRAM=0, IPPROTO_ICMP=0)
        sel = types.SimpleNamespace(select=lambda r, w, x, t: (r if Sock.queue else [], [], []))
        addrs = [f"10.0.0.{i}" for i in range(1, 6)]
        with unittest.mock.patch.object(n, "socket", fake), unittest.mock.patch.object(n, "select", sel):
            self.assertEqual(n.icmp_sweep(addrs, rate=10000, wait=0), {"10.0.0.2", "10.0.0.3"})
            self.assertEqual(Sock.sent.count("10.0.0.1"), 2)                    # unanswered: asked twice
            self.assertEqual(Sock.sent.count("10.0.0.2"), 1)
            Sock.fail = errno.EHOSTUNREACH
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIsNone(n.icmp_sweep(addrs, rate=10000, wait=0))      # nothing went out
            self.assertIn("Local Network privacy", err.getvalue())
            Sock.fail = errno.EHOSTDOWN                                         # own segment, ARP found nobody
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(n.icmp_sweep(addrs, rate=10000, wait=0), set())  # a sweep, not a blocked one
            self.assertEqual(err.getvalue(), "")

    def test_parse_arp(self):
        out = ("? (192.0.2.5) at 8:55:31:2b:39:83 on en0 ifscope [ethernet]\n"
               "? (192.0.2.6) at (incomplete) on en0 ifscope [ethernet]\n"
               "? (192.0.2.7) at d0:11:e5:94:5:95 on en0 ifscope permanent [ethernet]\n"
               "? (192.0.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
               "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n"
               "? (192.0.2.8) at 0:0:5e:0:1:1 on en0 ifscope [ethernet]\n"
               "gw.lan (198.51.100.1) at aa:bb:cc:dd:ee:ff [ether] on eth0\n")        # Linux net-tools
        self.assertEqual(self.n.parse_arp(out), {"192.0.2.5": ("08:55:31:2B:39:83", "en0"),
                                                 "192.0.2.8": ("00:00:5E:00:01:01", "en0"),
                                                 "198.51.100.1": ("AA:BB:CC:DD:EE:FF", "eth0")})

    def test_arp_hosts_and_proxy_arp(self):
        table = {f"10.0.0.{i}": (f"00:00:5E:00:01:{i:02X}", "en0") for i in range(2, 6)}
        table["10.0.0.9"] = ("00:00:5E:00:01:09", "en1")
        addrs = {f"10.0.0.{i}" for i in range(1, 255)}
        found, proxy = self.n.arp_hosts(table, {"en0"}, addrs, {"10.0.0.2"})
        self.assertEqual(sorted(found), ["10.0.0.3", "10.0.0.4", "10.0.0.5"])
        self.assertIsNone(proxy)
        same = {f"10.0.0.{i}": ("00:00:5E:00:01:01", "en0") for i in range(2, 40)}
        self.assertEqual(self.n.arp_hosts(same, {"en0"}, addrs, set()), ({}, "00:00:5E:00:01:01"))

    def test_mac_vendor(self):
        vendors = {"000C29": "VMware", "0050C2A": "Longer", "70B3D5123": "Longest"}
        self.assertEqual(self.n.mac_vendor("00:0C:29:0A:0B:0C", vendors), "VMware")
        self.assertEqual(self.n.mac_vendor("00:50:C2:A1:00:00", vendors), "Longer")
        self.assertEqual(self.n.mac_vendor("70:B3:D5:12:34:56", vendors), "Longest")
        self.assertIsNone(self.n.mac_vendor("12:85:75:45:2E:FF", vendors))    # locally administered (random)
        self.assertIsNone(self.n.mac_vendor("00:11:22:33:44:55", vendors))
        nmap = shutil.which("nmap")
        if nmap:                                                               # the real list, when installed
            self.assertTrue(len(self.n.mac_vendors(nmap)) > 1000)

    def test_ping_probes(self):
        self.assertIn("-PS" + self.n.DISCOVERY_PORTS, self.n.PROFILES["ping"])
        self.assertEqual(self.n.DISCOVERY_PORTS.split(",")[0], "22")


class NmapInterfaceTests(unittest.TestCase):  # issue 18
    def setUp(self):
        sys.path.insert(0, str(ROOT / "skills/homelab-manager/scripts"))
        import nmap_scan
        self.n = nmap_scan

    def test_parse_route(self):
        direct = "   route to: 10.0.10.5\ndestination: 10.0.10.0\n  interface: en0\n      flags: <UP,DONE,CLONING>\n"
        routed = "   route to: 10.0.20.5\n    gateway: 10.0.10.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC>\n"
        self.assertEqual(self.n.parse_route(direct), ("en0", False))
        self.assertEqual(self.n.parse_route(routed), ("en0", True))
        self.assertEqual(self.n.parse_route(""), (None, False))

    def test_probe_ip(self):
        self.assertEqual(self.n.probe_ip("10.0.10.0/24"), "10.0.10.1")
        self.assertEqual(self.n.probe_ip("10.0.10.5"), "10.0.10.5")
        self.assertEqual(self.n.probe_ip("10.0.10.20-30"), "10.0.10.21")

    def _xml(self, hosts):
        rows = "".join(f'<host><status state="up" reason="{r}"/><address addr="{ip}" addrtype="ipv4"/>'
                       + (f'<address addr="{m}" addrtype="mac"/>' if m else "") + "</host>" for ip, r, m in hosts)
        p = Path(tempfile.mkdtemp()) / "s.xml"
        p.write_text(f"<nmaprun>{rows}</nmaprun>")
        return p

    def test_proxy_arp_detected(self):
        same = [(f"10.0.10.{i}", "arp-response", "AA:BB:CC:00:00:01") for i in range(1, 40)]
        self.assertEqual(self.n.proxy_arp_mac(self._xml(same)), "aa:bb:cc:00:00:01")
        real = [(f"10.0.10.{i}", "arp-response", f"AA:BB:CC:00:00:{i:02x}") for i in range(1, 40)]
        self.assertIsNone(self.n.proxy_arp_mac(self._xml(real)))
        few = same[:5]
        self.assertIsNone(self.n.proxy_arp_mac(self._xml(few)))
        nomac = [(f"10.0.10.{i}", "syn-ack", None) for i in range(1, 40)]
        self.assertIsNone(self.n.proxy_arp_mac(self._xml(nomac)))

    def test_live_hosts(self):
        db = {"hosts": {"10.0.10.5": {}, "10.0.10.40": {}, "10.0.11.2": {}, "fe80::1": {}}}
        self.assertEqual(self.n.live_hosts(db, ["10.0.10.0/24"]), ["10.0.10.5", "10.0.10.40"])
        self.assertEqual(self.n.live_hosts(db, ["10.0.10.1-10"]), ["10.0.10.5"])

    def test_merge_guesses_from_all_scans(self):  # issue 21
        ports = [{"port": 22, "service": "ssh", "product": "OpenSSH Debian"},
                 {"port": 3128, "service": "http", "product": "Proxmox VE spiceproxy"}]
        svc = self.n.merge_host({}, {"ip": "10.0.10.2", "os": [], "ports": ports}, "services", "t1")
        self.assertEqual(svc["device_type_guess"], "hypervisor")
        os_scan = self.n.merge_host(svc, {"ip": "10.0.10.2", "os": [{"name": "Linux 6.x"}], "ports": ports}, "os", "t2")
        self.assertEqual(os_scan["device_type_guess"], "hypervisor")
        again = self.n.merge_host(os_scan, {"ip": "10.0.10.2", "os": [], "ports": ports[:1]}, "services", "t3")
        self.assertEqual(again["os"], [{"name": "Linux 6.x"}])   # earlier OS evidence kept and used
        ping = self.n.merge_host(os_scan, {"ip": "10.0.10.2", "os": [], "ports": []}, "ping", "t4")
        self.assertEqual(ping["device_type_guess"], "hypervisor")
        self.assertEqual(ping["first_seen"], "t1")

    def test_answer_clears_missing_mark(self):  # GitHub issue #127
        back = self.n.merge_host({"ip": "10.0.10.2", "missing_since": "t1"}, {"ip": "10.0.10.2", "os": [], "ports": []},
                                 "ping", "t2")
        self.assertNotIn("missing_since", back)
        db = {"hosts": {"10.0.10.5": {}, "10.0.10.6": {"missing_since": "t0"}, "10.0.10.1": {}, "10.0.11.2": {}}}
        gone = self.n.mark_missing(db, ["10.0.10.0/24"], [self.n.ipaddress.ip_network("10.0.10.1/32")], {"10.0.10.5"}, "t3")
        self.assertEqual(gone, ["10.0.10.6"])
        self.assertEqual(db["hosts"]["10.0.10.6"]["missing_since"], "t0")

    # GitHub issue #28: the gateway's OS fingerprint mustn't turn a Debian VM behind it into `network`
    GW_OS = [{"name": "Linux 4.15 - 5.19", "accuracy": 92}, {"name": "MikroTik RouterOS 7.2 - 7.14 (Linux 5.6.3)",
             "accuracy": 91}, {"name": "OpenWrt 21.02 (Linux 5.4)", "accuracy": 90}]

    def _vm(self, **kw):
        return {"ip": "10.0.20.11", "os": [dict(o) for o in self.GW_OS], **kw,
                "ports": [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "10.0p2 Debian 7+deb13u4"},
                          {"port": 8080, "service": "http", "product": "Apache Tomcat", "version": None}]}

    def test_debian_banner_beats_borrowed_routeros_guess(self):
        self.assertEqual(self.n.guess_type(self._vm()), "linux")
        self.assertEqual(self.n.guess_type(self._vm(os_suspect=["10.0.20.1"])), "linux")

    def test_ostype_and_windows_banner(self):
        h = {"os": [{"name": "MikroTik RouterOS 7"}], "os_suspect": ["10.0.20.1"],
             "ports": [{"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC", "ostype": "Windows"}]}
        self.assertEqual(self.n.guess_type(h), "windows")
        self.assertEqual(self.n.banner_os({"product": "Apache httpd", "version": "2.4.62", "ostype": "Linux"}), "linux")
        self.assertIsNone(self.n.banner_os({"product": "OpenSSH", "version": "9.6"}))

    def test_mac_with_airplay_is_macos_not_camera(self):  # GitHub issue #121
        mac = {"ports": [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "10.5"},
                         {"port": 88, "service": "tcpwrapped"}, {"port": 5000, "service": "rtsp"},
                         {"port": 5900, "service": "vnc", "product": "Apple remote desktop vnc", "ostype": "Mac OS X"},
                         {"port": 7000, "service": "rtsp"}]}
        self.assertEqual(self.n.guess_type(mac), "macos")
        self.assertEqual(self.n.banner_os({"product": "Apple remote desktop vnc", "ostype": "Mac OS X"}), "macos")
        self.assertIsNone(self.n.banner_os({"product": "Cisco IOS XR sshd"}))
        cam = {"ports": [{"port": 554, "service": "rtsp"}, {"port": 8554, "service": "rtsp"}]}
        self.assertEqual(self.n.guess_type(cam), "camera")
        hik = {"ports": [{"port": 22, "service": "ssh", "product": "OpenSSH"}, {"port": 554, "service": "rtsp"},
                         {"port": 80, "service": "http", "product": "Hikvision IP camera httpd"}]}
        self.assertEqual(self.n.guess_type(hik), "camera")

    def test_airplay_speaker_is_not_camera_or_network(self):  # GitHub issue #130
        speaker = {"ports": [{"port": 53, "service": "domain", "product": "dnsmasq"},
                             {"port": 5000, "service": "rtsp"}, {"port": 7000, "service": "rtsp"},
                             {"port": 49152, "service": "tcpwrapped"},
                             {"port": 49153, "service": "bandwidth-test", "product": "MikroTik bandwidth-test server"}]}
        self.assertEqual(self.n.guess_type(speaker), "media")                    # Apple, no Mac (#132)
        ports = [p["port"] for p in self.n.evidence_ports(speaker["ports"])]
        self.assertEqual(sorted(ports), [53, 7000])                              # the dynamic range doesn't count
        self.assertEqual(self.n.evidence_ports([{"port": 5000, "service": "rtsp"}]),
                         [{"port": 5000, "service": "rtsp"}])                    # one rtsp port alone stays rtsp
        btest = {"ports": [{"port": 2000, "service": "bandwidth-test", "product": "MikroTik bandwidth-test server"}]}
        self.assertEqual(self.n.guess_type(btest), "network")                   # on its own port it still counts

    def test_smart_home_devices(self):  # GitHub issue #132
        g = self.n.guess_type
        web = [{"port": 80, "service": "http"}]
        lwip = [{"name": "lwIP 1.4.1 - 2.0.3", "accuracy": 95}]
        self.assertEqual(g({"ports": web, "os": lwip}), "iot")                          # a plug, no MAC (routed)
        self.assertEqual(g({"vendor": "TP-Link Systems", "ports": web, "os": lwip}), "iot")  # beats the vendor
        self.assertEqual(g({"vendor": "TP-Link Systems", "ports": web}), "iot/network")   # can't tell
        self.assertEqual(g({"vendor": "TP-Link Technologies", "ports": web + [{"port": 22, "service": "ssh"}]}),
                         "network")
        self.assertEqual(g({"vendor": "Netatmo", "ports": [{"port": 5001, "service": "commplex-link"}]}), "iot")
        self.assertEqual(g({"vendor": "Xiaomi Electronics,CO.", "ports": []}), "iot")
        self.assertEqual(g({"vendor": "Sonos", "ports": [{"port": 1400, "service": "http", "product": "Sonos upnpd"}]}),
                         "media")
        airplay = [{"port": 5000, "service": "rtsp"}, {"port": 7000, "service": "rtsp"}]
        ios = [{"name": "Apple iOS 16.0", "accuracy": 96}]
        self.assertEqual(g({"vendor": "Apple", "ports": airplay, "os": ios}), "media")   # HomePod, Apple TV
        self.assertEqual(g({"vendor": "Apple", "ports": [{"port": 62078, "service": "iphone-sync"}], "os": ios}),
                         "macos")                                                         # an iPhone stays
        self.assertEqual(g({"ports": airplay + [{"port": 445, "service": "microsoft-ds"}],
                            "os": [{"name": "Apple macOS 13", "accuracy": 95}]}), "macos")  # a Mac
        ssh = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1 Debian 2"}]
        for nic in ("Proxmox Server Solutions GmbH", "VMware", "QEMU virtual NIC"):     # a VM's NIC says nothing
            self.assertEqual(g({"vendor": nic, "ports": ssh}), "linux")
        merged = self.n.merge_host({"ip": "10.0.0.5", "mac": "BC:24:11:00:00:01", "mac_source": "router"},
                                   {"ip": "10.0.0.5", "mac": "BC:24:11:00:00:01"}, "ping", "2026-11-19T00:00:00+00:00")
        self.assertNotIn("mac_source", merged)                                            # nmap saw it itself

    def test_real_router_keeps_network(self):
        gw = {"os": [dict(o) for o in self.GW_OS], "os_suspect": ["10.0.20.11"],
              "ports": [{"port": 22, "service": "ssh", "product": "MikroTik RouterOS sshd"},
                        {"port": 8291, "service": "unknown", "product": None}]}
        self.assertEqual(self.n.guess_type(gw), "network")
        alone = {"os": [{"name": "MikroTik RouterOS 7.2 - 7.14 (Linux 5.6.3)"}],   # no banner says otherwise
                 "ports": [{"port": 22, "service": "ssh", "product": "OpenSSH"}]}
        self.assertEqual(self.n.guess_type(alone), "network")

    def test_flag_shared_os(self):
        hosts = [{"ip": "10.0.20.1", "os": list(self.GW_OS)}, {"ip": "10.0.20.11", "os": list(self.GW_OS)},
                 {"ip": "10.0.20.12", "os": [{"name": "Linux 6.x"}]}, {"ip": "10.0.20.13", "os": []}]
        self.n.flag_shared_os(hosts)
        self.assertEqual(hosts[0]["os_suspect"], ["10.0.20.11"])
        self.assertEqual(hosts[1]["os_suspect"], ["10.0.20.1"])
        self.assertIs(hosts[2]["os_suspect"], False)
        self.assertNotIn("os_suspect", hosts[3])
        # a later services scan (no OS) keeps the flag; a clean os scan clears it
        merged = self.n.merge_host(hosts[1], {"ip": "10.0.20.11", "os": [], "ports": []}, "services", "t")
        self.assertEqual(merged["os_suspect"], ["10.0.20.1"])
        clean = self.n.merge_host(merged, {"ip": "10.0.20.11", "os": [{"name": "Linux 6.x"}], "os_suspect": False,
                                           "ports": []}, "os", "t2")
        self.assertIs(clean["os_suspect"], False)

    def test_parse_xml_reads_ostype(self):
        p = Path(tempfile.mkdtemp()) / "o.xml"
        p.write_text('<nmaprun><host><status state="up"/><address addr="10.0.20.11" addrtype="ipv4"/><ports>'
                     '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" '
                     'version="10.0p2 Debian 7+deb13u4" ostype="Linux"/></port></ports></host></nmaprun>')
        (h,) = self.n.parse_xml(p)
        self.assertEqual(h["ports"][0]["ostype"], "Linux")
        self.assertEqual(h["device_type_guess"], "linux")


FAKE_SSH = r'''#!/usr/bin/env python3
import json, os, sys
if "-G" in sys.argv:   # config lookup (GitHub issue #122): not a connection, not logged
    sys.stdout.write(os.environ.get("FAKE_SSH_G", "user admin\nidentityfile /nonexistent/id_ed25519\n"))
    sys.exit(0)
host = sys.argv[-3]
with open(os.environ["FAKE_SSH_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
script = sys.stdin.read()
assert "hm_probe=1" in script and sys.argv[-2:] == ["sh", "-s"]
replies = {
    "10.0.20.11": "hm_probe=1\nhostname=db01.example.test\nkernel=Linux 4.18.0\nos_id=rocky\nos_version=8.10\n"
                  "os_like=rhel centos fedora\nos_name=Rocky Linux 8.10 (Green Obsidian)\nvirt=kvm\n"
                  "python_default=/usr/bin/python3 Python 3.6.8\npython=/usr/bin/python3 Python 3.6.8\n"
                  "python=/usr/bin/python3.12 Python 3.12.5\npython=/usr/libexec/platform-python Python 3.6.8\n",
    "10.0.20.20": "hm_probe=1\nhostname=pve2\nkernel=Linux 6.8.12-4-pve\nos_id=debian\nos_version=12\n"
                  "os_name=Debian GNU/Linux 12 (bookworm)\nproduct=pve-manager/8.3.1/fb48e850ef9dde27 (running kernel: 6.8)\n"
                  "virt=none\npython_default=/usr/bin/python3 Python 3.11.2\n",
}
if host == "10.0.20.12":
    sys.stderr.write("admin@10.0.20.12: Permission denied (publickey).\n")
    sys.exit(255)
if host == "10.0.20.15":
    sys.stdout.write("bad command name sh (line 1 column 1)\n")
    sys.exit(1)
sys.stdout.write(replies[host])
'''


FAKE_SSH_ADD = r'''#!/usr/bin/env python3
import os, sys
if os.environ.get("FAKE_AGENT_EMPTY") and os.environ.get("SSH_AUTH_SOCK") != os.environ.get("FAKE_AGENT_FULL_SOCK"):
    print("The agent has no identities.")
    sys.exit(1)
print("256 SHA256:abc admin@mac (ED25519)")
'''


class SshProbeTests(unittest.TestCase):  # issue 25
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "ansible,discovery", cwd=self.d)
        run("config_set.py", "network.authorized_ranges+=10.0.20.0/24", "network.excluded_hosts+=10.0.20.99",
            "defaults.admin_user=admin", cwd=self.d)
        ssh = lambda: [{"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": None}]
        hosts = {
            "10.0.20.11": {"ip": "10.0.20.11", "ports": ssh(), "os": [], "hostnames": [], "last_profile": "services"},
            "10.0.20.12": {"ip": "10.0.20.12", "ports": ssh(), "os": [], "hostnames": [], "last_profile": "services"},
            "10.0.20.13": {"ip": "10.0.20.13", "ports": [{"port": 80, "proto": "tcp"}], "last_profile": "services"},
            "10.0.20.14": {"ip": "10.0.20.14", "ports": [], "last_profile": "ping"},
            "10.0.20.15": {"ip": "10.0.20.15", "ports": ssh(), "os": [], "hostnames": [], "last_profile": "services"},
            "10.0.20.17": {"ip": "10.0.20.17", "ports": ssh(), "last_profile": "services"},
            "10.0.20.99": {"ip": "10.0.20.99", "ports": ssh(), "last_profile": "services"},
            "10.0.30.5": {"ip": "10.0.30.5", "ports": ssh(), "last_profile": "services"},
        }
        (self.d / "discovery/network.json").write_text(json.dumps({"hosts": hosts}))
        (self.d / "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n        known:\n          ansible_host: 10.0.20.17\n")
        bin_ = self.d / "bin"
        bin_.mkdir()
        (bin_ / "ssh").write_text(FAKE_SSH)
        (bin_ / "ssh").chmod(0o755)
        (bin_ / "ssh-add").write_text(FAKE_SSH_ADD)
        (bin_ / "ssh-add").chmod(0o755)
        self.log = self.d / "ssh.log"
        self.env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "FAKE_SSH_LOG": str(self.log)}

    def probe(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "ssh_probe.py"), *args], cwd=self.d, env=self.env,
                              capture_output=True, text=True)

    def test_probes_ssh_hosts_in_range_and_merges(self):
        r = self.probe("10.0.20.0/24", "10.0.20.20")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("skip 10.0.20.13: no SSH seen on 22/tcp", r.stderr)
        self.assertIn("skip 10.0.20.14: only ping-scanned", r.stderr)
        self.assertIn("skip 10.0.20.17: already in the managed inventory", r.stderr)
        self.assertIn("skip 10.0.20.99: in network.excluded_hosts", r.stderr)
        self.assertNotIn("10.0.30.5", r.stderr + r.stdout)                          # not in the targets
        self.assertRegex(r.stdout, r"10\.0\.20\.11 +db01\.example\.test +Rocky Linux 8\.10.*3\.12\.5 \(python3 is 3\.6\.8\) +el8")
        self.assertIn("10.0.20.11 → /usr/bin/python3.12", r.stdout)
        self.assertIn("10.0.20.12       —                        auth failed", r.stdout)
        self.assertIn("10.0.20.15       —                        logged in, but `sh` did not run", r.stdout)
        self.assertRegex(r.stdout, r"10\.0\.20\.20 +pve2 +pve-manager.*proxmox_nodes")
        calls = [json.loads(l) for l in self.log.read_text().splitlines()]
        self.assertEqual(sorted(c[-3] for c in calls), ["10.0.20.11", "10.0.20.12", "10.0.20.15", "10.0.20.20"])
        for c in calls:
            self.assertIn("-T", c)
            self.assertIn("BatchMode=yes", c)
            self.assertIn("StrictHostKeyChecking=accept-new", c)
            kh = next(o for o in c if o.startswith("UserKnownHostsFile="))
            self.assertNotIn(".ssh", kh)                                            # throwaway known_hosts
            self.assertEqual(c[c.index("-l") + 1], "admin")                          # defaults.admin_user
        net = json.loads((self.d / "discovery/network.json").read_text())["sites"]["default"]["hosts"]
        self.assertEqual(net["10.0.20.20"]["device_type_guess"], "hypervisor")      # new host, from the probe
        self.assertEqual(net["10.0.20.11"]["ssh_probe"]["os_id"], "rocky")
        self.assertFalse(net["10.0.20.12"]["ssh_probe"]["ok"])
        self.assertNotIn("ssh_probe", net["10.0.20.13"])

    def test_empty_agent_says_no_key_loaded(self):  # GitHub issue #122
        env = {**self.env, "FAKE_AGENT_EMPTY": "1"}
        r = subprocess.run([sys.executable, str(SCRIPTS / "ssh_probe.py"), "10.0.20.12", "--no-write"], cwd=self.d,
                           env=env, capture_output=True, text=True)
        self.assertIn("warning: no SSH key to offer 1 host(s)", r.stderr)
        self.assertIn("auth failed (no SSH key loaded — ssh-add", r.stdout)
        self.assertNotIn("try --user", r.stdout)
        key = self.d / "id_ed25519"
        key.write_text("k")
        for extra in ({"FAKE_SSH_G": f"identityfile {key}\n"},                     # a key file on disk
                      {"FAKE_SSH_G": "identityagent ~/agent.sock\n",               # the agent ssh config names
                       "FAKE_AGENT_FULL_SOCK": os.path.expanduser("~/agent.sock")}):
            r = subprocess.run([sys.executable, str(SCRIPTS / "ssh_probe.py"), "10.0.20.12", "--no-write"],
                               cwd=self.d, env={**env, **extra}, capture_output=True, text=True)
            self.assertNotIn("warning: no SSH key", r.stderr, extra)
            self.assertIn("key not authorized for this user — try --user", r.stdout, extra)

    def test_draft_and_no_write(self):
        before = (self.d / "discovery/network.json").read_text()
        r = self.probe("10.0.20.11", "10.0.20.20", "--draft", "--no-write", "--user", "ops")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.d / "discovery/network.json").read_text(), before)
        self.assertIn('    el8:\n      hosts:\n        db01:  # Rocky Linux 8.10 (Green Obsidian)\n'
                      '          ansible_host: "10.0.20.11"\n          ansible_user: "ops"\n'
                      '          ansible_python_interpreter: "/usr/bin/python3.12"', r.stdout)
        self.assertIn("    proxmox_nodes:", r.stdout)
        data = json.loads(subprocess.run(["yq", "-o=json", "."], input=r.stdout, capture_output=True, text=True).stdout)
        self.assertEqual(sorted(data["all"]["children"]), ["el8", "proxmox_nodes"])

    def test_site_and_user_from_inventory(self):  # issue 82
        r = run("config_set.py", "network.authorized_ranges+=10.0.30.0/24", "sites+={name: home}",
                "sites+={name: offsite, ranges: [10.0.30.0/24]}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        net = self.d / "discovery/network.json"
        home = json.loads(net.read_text())
        off = {"hosts": {"10.0.30.5": {"ip": "10.0.30.5", "ports": [], "last_profile": "services"}},
               "updated_at": "2026-11-01T00:00:00+00:00", "note": "x"}
        net.write_text(json.dumps({"sites": {"home": home, "offsite": off}}))
        (self.d / "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n"
            "        known:\n          ansible_host: 10.0.20.17\n"
            "        far:\n          ansible_host: 10.0.30.5\n          ansible_user: ops\n"
            "    site_offsite:\n      hosts:\n        far:\n")
        r = self.probe("10.0.30.5", "10.0.20.11", "--include-managed")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("at site offsite as ops", r.stderr)
        self.assertIn("at site home as admin", r.stderr)
        users = {c[-3]: c[c.index("-l") + 1] for c in map(json.loads, self.log.read_text().splitlines())}
        self.assertEqual(users, {"10.0.30.5": "ops", "10.0.20.11": "admin"})   # inventory ansible_user, default
        parts = json.loads(net.read_text())["sites"]
        self.assertEqual(sorted(parts), ["home", "offsite"])
        self.assertEqual(parts["offsite"]["hosts"]["10.0.30.5"]["ssh_probe"]["user"], "ops")
        self.assertNotIn("ssh_probe", parts["home"]["hosts"]["10.0.30.5"])      # not filed under the default site
        self.assertIn("ssh_probe", parts["home"]["hosts"]["10.0.20.11"])
        r = self.probe("10.0.30.5", "--include-managed", "--site", "home", "--user", "root", "--no-write")
        self.assertIn("at site home as root", r.stderr)                         # --site and --user still win

    def test_templated_inventory_user_is_skipped(self):  # issue 101
        (self.d / "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  vars:\n    ansible_user: \"{{ homelab_admin_user | default(omit) }}\"\n"
            "  children:\n    appliances:\n      hosts:\n        box:\n          ansible_host: 10.0.20.11\n")
        r = self.probe("10.0.20.11", "--include-managed", "--no-write")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("{{", r.stderr)
        users = [c[c.index("-l") + 1] for c in map(json.loads, self.log.read_text().splitlines())]
        self.assertEqual(users, ["admin"])                                       # defaults.admin_user

    def test_scope(self):
        r = self.probe("10.0.30.0/24")
        self.assertEqual(r.returncode, 4)
        self.assertIn("outside the authorized ranges", r.stderr)
        self.assertFalse(self.log.exists())

    def test_python_rules(self):
        sys.path.insert(0, str(SCRIPTS))
        import ssh_probe as p
        self.assertEqual(p.min_target_python((2, 16)), (3, 6))
        self.assertEqual(p.min_target_python((2, 17)), (3, 7))
        self.assertEqual(p.min_target_python((2, 21)), (3, 8))
        old = {"python_default": {"path": "/usr/bin/python3", "version": "3.6.8"},
               "pythons": [{"path": "/usr/bin/python3", "version": "3.6.8"}]}
        self.assertEqual(p.python_advice(old, (3, 8)), ("3.6.8 — too old, needs 3.8+", None))
        self.assertEqual(p.python_advice(old, (3, 6)), ("3.6.8 ok", None))
        self.assertEqual(p.suggest_group({"os_id": "almalinux", "os_version": "9.4"}), "el9")
        self.assertEqual(p.suggest_group({"kernel": "FreeBSD 14.1-RELEASE", "os_freebsd": "14.1",
                                          "product": "pfSense 2.7.2"}), "appliances")
        self.assertEqual(p.suggest_group({"kernel": "FreeBSD 14.1-RELEASE", "os_freebsd": "14.1"}), "freebsd")


class SshProbeMergeTests(unittest.TestCase):  # GitHub issue #110
    def test_failure_keeps_last_good_facts(self):
        sys.path.insert(0, str(SCRIPTS))
        import ssh_probe
        good = {"ok": True, "hostname": "kvm1", "kernel": "Linux 5.10", "user": "root", "collected_at": "2026-01-01"}
        bad = {"ok": False, "error": "auth failed", "user": "admin", "collected_at": "2026-01-02"}
        kept = ssh_probe.merge_probe(good, bad)
        self.assertEqual(kept["hostname"], "kvm1")
        self.assertTrue(kept["ok"])
        self.assertEqual(kept["collected_at"], "2026-01-01")
        self.assertEqual((kept["last_error"], kept["last_error_at"], kept["last_error_user"]),
                         ("auth failed", "2026-01-02", "admin"))
        self.assertEqual(ssh_probe.merge_probe(kept, {**bad, "error": "x"})["last_error"], "x")
        self.assertEqual(ssh_probe.merge_probe(kept, good), good)            # a good probe clears the error
        self.assertEqual(ssh_probe.merge_probe(None, bad), bad)
        self.assertEqual(ssh_probe.merge_probe(bad, bad), bad)


class SshSafetyTests(unittest.TestCase):
    """Every ssh the scripts start forwards nothing, offers no password and takes the host after `--`."""

    def test_ssh_host(self):
        import hmlib
        self.assertEqual(hmlib.ssh_host(" pve1.home.arpa "), "pve1.home.arpa")
        for bad in ("-oProxyCommand=touch x", "", None, "a b", "host\n-o x"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                hmlib.ssh_host(bad)

    def test_probe_command(self):
        import hmlib
        import ssh_probe
        cmd = ssh_probe.ssh_command("10.0.10.5", "root", 22, 5, "/tmp/kh")
        self.assertEqual(cmd[cmd.index("--") + 1:], ["10.0.10.5", "sh", "-s"])
        for opt in ("ForwardAgent=no", "ClearAllForwardings=yes", "PasswordAuthentication=no"):
            self.assertIn(opt, cmd)
        opts = [x for x in hmlib.SSH_SAFE_OPTS if x != "-o"]
        self.assertEqual(opts, [x for x in cmd if x in opts])

    def test_inventory_host_never_an_option(self):
        import lxd_snapshot
        import routeros_audit
        with unittest.mock.patch("subprocess.run") as run_:
            self.assertEqual(lxd_snapshot.ssh_run({"address": "-oProxyCommand=x"}, "true", 5)[0], 255)
            ok, why = routeros_audit.ssh_run("-oProxyCommand=x", "admin", 22, 5, "/system/resource/print")
            self.assertFalse(ok)
            self.assertIn("not a host name", why)
            run_.assert_not_called()


if __name__ == "__main__":
    unittest.main()
