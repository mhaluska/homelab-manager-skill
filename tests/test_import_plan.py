"""Tests for tofu_import_plan.py: import blocks and tfvars entries for unmanaged guests (GitHub issue #149)."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import SCRIPTS, run  # noqa: E402

sys.path.insert(0, str(SCRIPTS))
import tofu_import_plan as tip  # noqa: E402

MAC1, MAC2 = "BC:24:11:00:00:01", "BC:24:11:00:00:02"


def vm(vmid, name, **conf):
    base = {"ostype": "l26", "cores": "2", "memory": "4096", "sockets": "1", "cpu": "x86-64-v2-AES", "agent": "1",
            "scsihw": "virtio-scsi-single", "onboot": "1", "serial0": "socket",
            "scsi0": "local-zfs:vm-%d-disk-0,discard=on,iothread=1,size=32G,ssd=1" % vmid,
            "ide2": "local-zfs:vm-%d-cloudinit,media=cdrom" % vmid,
            "net0": f"virtio={MAC1},bridge=vmbr0", "ipconfig0": "ip=dhcp"}
    base.update(conf)
    return {"type": "vm", "vmid": vmid, "name": name, "node": "pve1", "status": "running", "template": False,
            "tags": "", "config": {k: v for k, v in base.items() if v is not None}}


def lxc(vmid, name, **conf):
    base = {"ostype": "debian", "hostname": name, "arch": "amd64", "cores": "1", "memory": "512", "swap": "512",
            "rootfs": "local-zfs:subvol-%d-disk-0,size=8G" % vmid, "unprivileged": "1", "features": "nesting=1",
            "onboot": "1", "net0": f"name=eth0,bridge=vmbr0,hwaddr={MAC2},ip=dhcp,type=veth"}
    base.update(conf)
    return {"type": "lxc", "vmid": vmid, "name": name, "node": "pve1", "status": "running", "template": False,
            "tags": "", "config": {k: v for k, v in base.items() if v is not None}}


GUESTS = [
    vm(101, "app01", sockets="2", numa="1", protection="1", tags=None,
       description="[untrusted] Web ${app} %{x}\nsecond \"line\"",
       scsi1="tank:vm-101-disk-1,discard=on,iothread=1,size=100G",
       net0=f"virtio={MAC1},bridge=vmbr1,tag=10,firewall=1",
       ipconfig0="ip=10.0.10.21/24,gw=10.0.10.1"),
    vm(102, "win01", ostype="win11", bios="ovmf", efidisk0="local-zfs:vm-102-disk-1,size=1M"),
    vm(103, "multi", net1="virtio=BC:24:11:00:00:03,bridge=vmbr0"),
    vm(104, "virt", scsi0=None, virtio0="local-zfs:vm-104-disk-0,size=20G"),
    vm(106, "gpu", hostpci0="0000:01:00,pcie=1"),
    lxc(201, "dns01", cores="2", memory="1024", swap="256", onboot=None, features="nesting=1,keyctl=1",
        nameserver="10.0.10.1 1.1.1.1", searchdomain="home.arpa",
        net0=f"name=eth0,bridge=vmbr0,hwaddr={MAC2},ip=10.0.10.31/24,gw=10.0.20.1,tag=20,type=veth"),
    lxc(202, "nas", mp0="tank:subvol-202-disk-1,mp=/srv,size=500G"),
    vm(105, "present"),
    {**vm(9000, "tpl-rocky9"), "template": True},
]
GUESTS[0]["tags"] = "web;tofu"
GUESTS[5]["status"] = "stopped"

TFVARS = '''# Desired state. A brace in a comment: {
defaults = {
  node            = "pve1"
  datastore       = "local-zfs"
  bridge          = "vmbr0"
  admin_user      = "admin" # a comment with vm_id = 999
  ssh_public_keys = []
  dns_servers     = ["10.0.10.1"]
  ipv4_gateway    = "10.0.10.1"
}

base_images = {}

vms = {
  # "app01" = {
  #   vm_id = 101
  # }
  "present" = {
    vm_id          = 105
    template_vm_id = 9050
    description    = "has } and { in it"
  }
}

containers = {}
'''


class ImportPlanTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        r = run("init_repo.py", str(self.d), "--components", "proxmox,ansible", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.env = self.d / "tofu/environments/homelab"
        (self.env / "homelab.auto.tfvars").write_text(TFVARS)
        self.snapshot({"config_version": 2, "guests": GUESTS})

    def snapshot(self, data):
        (self.d / "discovery").mkdir(exist_ok=True)
        (self.d / "discovery/proxmox.json").write_text(json.dumps({"sites": {"default": data}}))

    def plan(self, *args):
        return run("tofu_import_plan.py", *args, cwd=self.d)

    def test_prints_imports_and_entries_without_writing(self):
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn('to = module.vm["app01"].proxmox_virtual_environment_vm.this\n  id = "pve1/101"', out)
        self.assertIn('to = module.lxc["dns01"].proxmox_virtual_environment_container.this\n  id = "pve1/201"', out)
        self.assertIn("2 guest(s) to import, 5 the modules can't represent, 1 already in homelab.auto.tfvars, "
                      "1 template(s) skipped", out)
        self.assertEqual((self.env / "homelab.auto.tfvars").read_text(), TFVARS)   # stdout only
        self.assertFalse((self.env / "imports.tf").exists())
        app = out[out.index('"app01" = {'):]
        app = app[:app.index("\n  }")]
        for line in ('vm_id          = 101', 'template_vm_id = 101', 'cores          = 2', 'memory_mib     = 4096',
                     'cpu_type       = "x86-64-v2-AES"', 'disk_gib       = 32',
                     'extra_disks    = [{ interface = "scsi1", size_gib = 100, datastore = "tank" }]',
                     'bridge         = "vmbr1"', 'vlan_id        = 10', f'mac_address    = "{MAC1}"',
                     'ipv4_address   = "10.0.10.21/24"', 'tags           = ["web"]', 'protection     = true',
                     # Proxmox text stays literal: no template sequences, quotes and newlines escaped
                     'description    = "Web $${app} %%{x}\\nsecond \\"line\\""'):
            self.assertIn(line, app)
        for absent in ("ipv4_gateway", "datastore      =", "node ", "on_boot", "started"):   # = the defaults
            self.assertNotIn(absent, app)
        self.assertIn("sockets 2: the module sets 1 socket", out)
        self.assertIn("numa=1", out)
        self.assertIn("net0 firewall=1", out)
        dns = out[out.index('"dns01" = {'):]
        dns = dns[:dns.index("\n  }")]
        for line in ('template_file_id = "local:vztmpl/imported.tar.zst"', 'swap_mib         = 256',
                     'vlan_id          = 20', f'mac_address      = "{MAC2}"', 'ipv4_gateway     = "10.0.20.1"',
                     'dns_servers      = ["10.0.10.1", "1.1.1.1"]', 'dns_domain       = "home.arpa"',
                     'started          = false', 'on_boot          = false'):
            self.assertIn(line, dns)
        self.assertNotIn("nesting", dns)
        self.assertIn("feature keyctl=1", out)
        blocked = out[out.index("Not importable"):]
        for text in ("VM 102 win01: OS type win11", "UEFI", "VM 103 multi: 2 network devices",
                     "VM 104 virt: root disk virtio0", "VM 106 gpu: passthrough (hostpci0)",
                     "container 202 nas: mount points (mp0)"):
            self.assertIn(text, blocked)
        self.assertNotIn("tpl-rocky9", out)
        self.assertNotIn('"present" = {', out)

    def test_guest_filter(self):
        r = self.plan("--guest", "app01", "--guest", "201")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('"app01" = {', r.stdout)
        self.assertIn('"dns01" = {', r.stdout)
        self.assertNotIn("win01", r.stdout)
        r = self.plan("--guest", "nope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("--guest nope: no such guest", r.stdout)
        r = self.plan("--site", "moon")
        self.assertEqual(r.returncode, 3)
        self.assertIn("no site 'moon'", r.stderr)

    def test_write_adds_and_never_edits(self):
        r = self.plan("--write")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Wrote tofu/environments/homelab/imports.tf: 2 import block(s)", r.stdout)
        imports = (self.env / "imports.tf").read_text()
        self.assertTrue(imports.startswith("# Generated by tofu_import_plan.py"))
        self.assertEqual(imports.count("import {"), 2)
        text = (self.env / "homelab.auto.tfvars").read_text()
        self.assertIn('  "present" = {\n    vm_id          = 105\n    template_vm_id = 9050\n'
                      '    description    = "has } and { in it"\n  }\n', text)       # untouched
        tv = tip.read_tfvars(text)
        self.assertEqual(tv["keys"], {"vms": {"present", "app01"}, "containers": {"dns01"}})
        self.assertEqual(tv["ids"], {105, 101, 201})
        self.assertEqual(tv["defaults"]["dns_servers"], ["10.0.10.1"])
        self.assertGreater(text.index('\n  "app01" = {'), text.index('"present" = {'))
        self.assertIn("containers = {\n  # 201 dns01", text)
        if shutil.which("tofu"):
            fmt = subprocess.run(["tofu", "fmt", "-check", "-diff", "imports.tf", "homelab.auto.tfvars"],
                                 cwd=self.env, capture_output=True, text=True)
            self.assertEqual(fmt.returncode, 0, fmt.stdout + fmt.stderr)
        # a second run finds them in tfvars: nothing new, nothing changed
        r = self.plan("--write")
        self.assertIn("0 guest(s) to import", r.stdout)
        self.assertIn("Nothing to write.", r.stdout)
        self.assertEqual((self.env / "imports.tf").read_text(), imports)
        self.assertEqual((self.env / "homelab.auto.tfvars").read_text(), text)

    def test_older_snapshot_or_template(self):
        self.snapshot({"guests": GUESTS})        # before 0.61.0: no cpu, protection, swap, DNS in the config
        r = self.plan()
        self.assertEqual(r.returncode, 3)
        self.assertIn("proxmox_inventory.py --details", r.stderr)
        self.snapshot({"config_version": 2, "guests": GUESTS})
        variables = self.env / "variables.tf"
        variables.write_text("\n".join(line for line in variables.read_text().splitlines()
                                       if "mac_address" not in line))
        r = self.plan("--guest", "app01")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("mac_address    =", r.stdout)
        self.assertIn("mac_address: not in this environment's variables.tf", r.stdout)

    def test_name_clash_and_bad_name(self):
        guests = [vm(110, "present"), vm(111, "bad_name!")]
        self.snapshot({"config_version": 2, "guests": guests})
        r = self.plan()
        self.assertIn("VM 110 present: vms already has an entry named present", r.stdout)
        self.assertIn("is not a valid map key", r.stdout)
        self.assertIn("0 guest(s) to import", r.stdout)

    def test_proxmox_text_stays_in_its_comment(self):
        self.snapshot({"config_version": 2, "guests": [vm(120, "inj", startup="order=1\n}\nevil = {")]})
        r = self.plan("--write")
        self.assertEqual(r.returncode, 0, r.stderr)
        text = (self.env / "homelab.auto.tfvars").read_text()
        self.assertEqual([line for line in text.splitlines() if "evil" in line],
                         ["  #   - startup order=1 } evil = {: the modules set no start order, the plan removes it"])
        self.assertEqual(tip.read_tfvars(text)["keys"]["vms"], {"present", "inj"})


class HclTests(unittest.TestCase):
    def test_insert_entries(self):
        self.assertEqual(tip.insert_entries("containers = {}\n", "containers", ["  # x"]),
                         "containers = {\n  # x\n}\n")
        self.assertEqual(tip.insert_entries("defaults = {}\n", "vms", ["  # x"]),
                         "defaults = {}\n\nvms = {\n  # x\n}\n")
        self.assertEqual(tip.insert_entries('vms = {\n  "a" = {\n    vm_id = 1\n  }\n}\n', "vms", ["  # x"]),
                         'vms = {\n  "a" = {\n    vm_id = 1\n  }\n\n  # x\n}\n')

    def test_entry_attributes(self):
        tf = (SCRIPTS.parent / "assets/repo-template/tofu/environments/homelab/variables.tf").read_text()
        attrs = tip.entry_attributes(tf)
        self.assertTrue({"vm_id", "mac_address", "cpu_type", "protection", "extra_disks"} <= attrs["vms"])
        self.assertTrue({"template_file_id", "mac_address", "dns_servers", "swap_mib"} <= attrs["containers"])
        self.assertNotIn("datastore_id", attrs["vms"])

    def test_ipv6(self):
        ctx = {"defaults": {"ipv6_gateway": "fe80::1"}, "node_datastores": False}
        def attrs(g):
            e = tip.lxc_entry(g, ctx) if g["type"] == "lxc" else tip.vm_entry(g, ctx)
            return dict(e.attrs), e.notes
        a, _ = attrs(lxc(301, "v6a", net0=f"name=eth0,bridge=vmbr0,hwaddr={MAC2},ip=dhcp,ip6=auto,type=veth"))
        self.assertEqual(a["ipv6_address"], "auto")
        self.assertNotIn("ipv6_gateway", a)
        a, _ = attrs(vm(302, "v6b", ipconfig0="ip=dhcp,ip6=fd00:10::21/64,gw6=fd00:10::1"))
        self.assertEqual((a["ipv6_address"], a["ipv6_gateway"]), ("fd00:10::21/64", "fd00:10::1"))
        a, notes = attrs(vm(303, "v6c", ipconfig0="ip=dhcp,ip6=fd00:10::22/64"))
        self.assertNotIn("ipv6_gateway", a)
        self.assertTrue(any("defaults.ipv6_gateway" in n for n in notes))
        a, notes = attrs(lxc(304, "v6d", net0=f"name=eth0,bridge=vmbr0,hwaddr={MAC2},ip=dhcp,ip6=manual,type=veth"))
        self.assertNotIn("ipv6_address", a)
        self.assertTrue(any("ip6=manual" in n for n in notes))

    def test_sizes_and_options(self):
        self.assertEqual(tip.whole(tip.gib("32G")), 32)
        self.assertEqual(tip.whole(tip.gib("1T")), 1024)
        self.assertEqual(tip.whole(tip.gib("2048M")), 2)
        self.assertIsNone(tip.whole(tip.gib("512M")))
        self.assertEqual(tip.options("local:vm-1-disk-0,size=8G"), ("local:vm-1-disk-0", {"size": "8G"}))


if __name__ == "__main__":
    unittest.main()
