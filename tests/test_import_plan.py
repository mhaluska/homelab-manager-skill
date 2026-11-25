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
    vm(103, "multi", net2="virtio=BC:24:11:00:00:03,bridge=vmbr0"),
    vm(104, "virt", scsi0=None, virtio0="local-zfs:vm-104-disk-0,size=20G"),
    vm(106, "gpu", hostpci0="0000:01:00,pcie=1"),
    lxc(201, "dns01", cores="2", memory="1024", swap="256", onboot=None, features="nesting=1,keyctl=1",
        nameserver="10.0.10.1 1.1.1.1", searchdomain="home.arpa",
        net0=f"name=eth0,bridge=vmbr0,hwaddr={MAC2},ip=10.0.10.31/24,gw=10.0.20.1,tag=20,type=veth"),
    lxc(202, "nas", mp0="tank:subvol-202-disk-1,mp=/srv,backup=1,mountoptions=noatime;nodev,size=500G",
        mp1="/mnt/media,mp=/media,ro=1"),
    lxc(203, "gap", mp0="tank:subvol-203-disk-1,mp=/a,size=8G", mp2="tank:subvol-203-disk-2,mp=/b,size=8G"),
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
        self.snapshot({"config_version": 3, "guests": GUESTS})

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
        self.assertIn("4 guest(s) to import, 4 the modules can't represent, 1 already in homelab.auto.tfvars, "
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
                     'sockets        = 2', 'numa           = true', 'firewall       = true',
                     # Proxmox text stays literal: no template sequences, quotes and newlines escaped
                     'description    = "Web $${app} %%{x}\\nsecond \\"line\\""'):
            self.assertIn(line, app)
        for absent in ("ipv4_gateway", "datastore      =", "node ", "on_boot", "started",   # = the defaults
                       "cloud_init_drive", "serial_socket", "cdrom", "scsi_hardware", "disk_ssd"):
            self.assertNotIn(absent, app)
        self.assertIn("# 101 app01: imported as is", out)
        dns = out[out.index('"dns01" = {'):]
        dns = dns[:dns.index("\n  }")]
        for line in ('template_file_id = "local:vztmpl/imported.tar.zst"', 'swap_mib         = 256',
                     'vlan_id          = 20', f'mac_address      = "{MAC2}"', 'ipv4_gateway     = "10.0.20.1"',
                     'dns_servers      = ["10.0.10.1", "1.1.1.1"]', 'dns_domain       = "home.arpa"',
                     'started          = false', 'on_boot          = false', 'keyctl           = true',
                     'console_mode     = "tty"'):
            self.assertIn(line, dns)
        self.assertNotIn("nesting", dns)
        nas = out[out.index('"nas" = {'):]
        nas = nas[:nas.index("\n  }")]
        self.assertIn('  mount_points = [\n'
                      '      { volume = "tank:subvol-202-disk-1", path = "/srv", size_gib = 500, backup = true, '
                      'mount_options = ["noatime", "nodev"] },\n'
                      '      { volume = "/mnt/media", path = "/media", read_only = true },\n'
                      '    ]', nas)
        blocked = out[out.index("Not importable"):]
        self.assertIn('    bios           = "ovmf"\n    efi_disk       = { type = "2m" }\n', out)
        for text in ("VM 103 multi: network devices net0, net2 have a gap",
                     "VM 104 virt: root disk virtio0", "VM 106 gpu: hostpci0 passes a raw PCI device (0000:01:00)",
                     "container 203 gap: mount points mp0, mp2 have a gap"):
            self.assertIn(text, blocked)
        self.assertNotIn("OS type", blocked)
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
        self.assertIn("Wrote tofu/environments/homelab/imports.tf: 4 import block(s)", r.stdout)
        imports = (self.env / "imports.tf").read_text()
        self.assertTrue(imports.startswith("# Generated by tofu_import_plan.py"))
        self.assertEqual(imports.count("import {"), 4)
        text = (self.env / "homelab.auto.tfvars").read_text()
        self.assertIn('  "present" = {\n    vm_id          = 105\n    template_vm_id = 9050\n'
                      '    description    = "has } and { in it"\n  }\n', text)       # untouched
        tv = tip.read_tfvars(text)
        self.assertEqual(tv["keys"], {"vms": {"present", "app01", "win01"}, "containers": {"dns01", "nas"}})
        self.assertEqual(tv["ids"], {105, 101, 102, 201, 202})
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
        for old in ({"guests": GUESTS},                     # before 0.61.0: no cpu, protection, swap, DNS
                    {"config_version": 2, "guests": GUESTS}):  # before 0.62.0: no LXC console settings
            self.snapshot(old)
            r = self.plan()
            self.assertEqual(r.returncode, 3)
            self.assertIn("proxmox_inventory.py --details", r.stderr)
        self.snapshot({"config_version": 3, "guests": GUESTS})
        variables = self.env / "variables.tf"
        variables.write_text("\n".join(line for line in variables.read_text().splitlines()
                                       if "mac_address" not in line))
        r = self.plan("--guest", "app01")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("mac_address    =", r.stdout)
        self.assertIn("mac_address: not in this environment's variables.tf", r.stdout)

    def test_older_template_without_import_settings(self):
        """An environment from before 0.62.0: what it would remove or rebuild blocks the entry, the rest is a note."""
        variables = self.env / "variables.tf"
        text = variables.read_text()
        start = text.index("    # settings an imported VM keeps")
        text = text[:start] + text[text.index("  }))", start):]
        start = text.index("    # settings an imported container keeps")
        text = text[:start] + text[text.index("  }))", start):]
        text = text.replace(text[text.index("    extra_disks = optional("):text.index("})), [])") + 8],
                            "    extra_disks    = optional(list(object({ interface = string, size_gib = number, "
                            "datastore = optional(string) })), [])")
        variables.write_text(text)
        self.assertNotIn("disk_cache", tip.entry_attributes(text)["vms"])
        self.snapshot({"config_version": 3, "guests": [
            vm(130, "old", sockets="2", ide2="none,media=cdrom",
               scsi1="local-zfs:vm-130-disk-1,cache=writeback,size=10G"),
            vm(131, "win", ostype="win10"),
            lxc(230, "data", mp0="local-zfs:subvol-230-disk-1,mp=/srv,size=8G")]})
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        old = r.stdout[r.stdout.index("# 130 old"):r.stdout.index("\n  }")]
        self.assertIn('extra_disks    = [{ interface = "scsi1", size_gib = 10 }]', old)
        self.assertIn("sockets, cloud_init_drive, cdrom, extra_disks options: not in this "
                      "environment's variables.tf", old)
        blocked = r.stdout[r.stdout.index("Not importable"):]
        self.assertIn("VM 131 win: os_type: not in this environment's variables.tf", blocked)
        self.assertIn("container 230 data: mount_points: not in this environment's variables.tf", blocked)

    def test_imported_settings(self):
        """What an older guest has and a cloned one doesn't: the entry keeps it instead of the module's defaults."""
        self.snapshot({"config_version": 3, "guests": [
            vm(140, "legacy", ostype="win10", sockets="2", numa="1", cpu="host,flags=+aes;-pcid", balloon="1024",
               tablet="0", agent="1,fstrim_cloned_disks=1", scsihw="virtio-scsi-pci", machine="q35",
               startup="order=2,up=30,down=60", ide2="nas:iso/install.iso,media=cdrom", serial0=None,
               ipconfig0=None, scsi0="local-zfs:vm-140-disk-0,cache=writeback,backup=0,size=32G",
               scsi1="local-zfs:vm-140-disk-1,discard=on,iothread=1,ssd=1,cache=writeback,size=10G",
               net0=f"virtio={MAC1},bridge=vmbr0,queues=4,mtu=9000,rate=50"),
            vm(141, "blank", ide2="none,media=cdrom", startup="3"),
            lxc(240, "priv", unprivileged="0", features=None, startup="up=15", cmode="shell", tty="4",
                net0=f"name=eth0,bridge=vmbr0,hwaddr={MAC2},ip=dhcp,firewall=1,mtu=1400,type=veth"),
            lxc(241, "fs", features="fuse=1,mknod=1,mount=nfs;cifs,nesting=1",
                mp0="/dev/zvol/tank/data,mp=/data,size=25G")]})
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout

        def entry(key):
            e = out[out.index(f'"{key}" = {{'):]
            return e[:e.index("\n  }")]
        legacy = entry("legacy")
        for line in ('os_type             = "win10"', 'sockets             = 2', 'numa                = true',
                     'cpu_type            = "host"', 'cpu_flags           = ["+aes", "-pcid"]',
                     'memory_floating_mib = 1024', 'tablet_device       = false', 'agent_trim          = true',
                     'scsi_hardware       = "virtio-scsi-pci"', 'machine             = "q35"',
                     'startup             = { order = 2, up_delay = 30, down_delay = 60 }',
                     'disk_cache          = "writeback"', 'disk_discard        = "ignore"',
                     'disk_iothread       = false', 'disk_ssd            = false', 'disk_backup         = false',
                     'extra_disks         = [{ interface = "scsi1", size_gib = 10, ssd = true, cache = "writeback" }]',
                     'cloud_init_drive    = false', 'cdrom               = "nas:iso/install.iso"',
                     'serial_socket       = false', 'queues              = 4', 'mtu                 = 9000'):
            self.assertIn(line, legacy)
        notes = out[out.index("# 140 legacy"):out.index('"legacy" = {')]
        self.assertEqual(notes.count("#   - "), 1)       # only what the modules really can't carry
        self.assertIn("net0 rate=50: the modules don't set it", notes)
        blank = entry("blank")
        self.assertIn('cdrom            = "none"', blank)
        self.assertIn("startup          = { order = 3 }", blank)
        priv = entry("priv")
        for line in ('unprivileged     = false', 'features         = false', 'console_mode     = "shell"',
                     'tty_count        = 4', 'startup          = { up_delay = 15 }', 'firewall         = true',
                     'mtu              = 1400'):
            self.assertIn(line, priv)
        self.assertIn("nesting          = false", priv)   # what an older template without `features` gets
        fs = entry("fs")
        for line in ('fuse             = true', 'mknod            = true', 'mount_types      = ["nfs", "cifs"]',
                     'mount_points     = [{ volume = "/dev/zvol/tank/data", path = "/data", size_gib = 25 }]'):
            self.assertIn(line, fs)
        self.assertNotIn("Not importable", out)

    def test_extra_nics(self):
        """net1, net2, ... become extra_nics in order; the entry's own NIC attributes stay net0's."""
        mac3, mac4, mac5 = "BC:24:11:00:00:03", "BC:24:11:00:00:04", "BC:24:11:00:00:05"
        self.snapshot({"config_version": 3, "guests": [
            vm(150, "router", ipconfig0="ip=10.0.10.25/24,gw=10.0.10.1",
               net1=f"e1000={mac3},bridge=vmbr1,tag=30,firewall=1,mtu=9000,queues=2,link_down=1",
               net2=f"virtio={mac4},bridge=vmbr0,rate=10", ipconfig2="ip=dhcp,ip6=auto"),
            vm(151, "nocloud", ide2=None, ipconfig0=None, net1=f"virtio={mac3},bridge=vmbr1,tag=40"),
            lxc(250, "proxy", net0=f"name=eth0,bridge=vmbr0,hwaddr={MAC2},ip=10.0.10.35/24,type=veth",
                net1=f"name=eth1,bridge=vmbr1,hwaddr={mac3},ip=192.0.2.35/24,gw=192.0.2.1,tag=20,firewall=1,"
                     "mtu=1400,type=veth",
                net2=f"name=wg,bridge=vmbr0,hwaddr={mac4},ip6=fd00:20::35/64,gw6=fd00:20::1,type=veth"),
            vm(152, "trunk", net1=f"virtio={mac5},bridge=vmbr1,trunks=10;20"),
            vm(153, "oldnic", net1=f"ne2k_pci={mac5},bridge=vmbr1"),
            lxc(251, "gapct", net2=f"name=eth2,bridge=vmbr0,hwaddr={mac5},ip=dhcp,type=veth")]})
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout

        def entry(key):
            e = out[out.index(f'"{key}" = {{'):]
            return e[:e.index("\n  }")]
        router = entry("router")
        for line in ('bridge         = "vmbr0"', f'mac_address    = "{MAC1}"', 'ipv4_address   = "10.0.10.25/24"',
                     '  extra_nics = [\n'
                     f'      {{ bridge = "vmbr1", vlan_id = 30, mac_address = "{mac3}", model = "e1000", '
                     'firewall = true, mtu = 9000, queues = 2, disconnected = true },\n'
                     f'      {{ mac_address = "{mac4}", ipv4_address = "dhcp", ipv6_address = "auto" }},\n'
                     '    ]'):
            if line.startswith("bridge"):
                self.assertNotIn(line, router)   # net0 on defaults.bridge: not set
            else:
                self.assertIn(line, router)
        notes = out[out.index("# 150 router"):out.index('"router" = {')]
        self.assertIn("net2 rate=10: the modules don't set it", notes)
        self.assertNotIn("link_down", notes)
        self.assertIn(f'extra_nics       = [{{ bridge = "vmbr1", vlan_id = 40, mac_address = "{mac3}" }}]',
                      entry("nocloud"))
        proxy = entry("proxy")
        for line in ('ipv4_address     = "10.0.10.35/24"\n    ipv4_gateway     = ""',   # the default route is eth1's
                     f'{{ bridge = "vmbr1", vlan_id = 20, mac_address = "{mac3}", firewall = true, mtu = 1400, '
                     'ipv4_address = "192.0.2.35/24", ipv4_gateway = "192.0.2.1" },',
                     f'{{ name = "wg", mac_address = "{mac4}", ipv6_address = "fd00:20::35/64", '
                     'ipv6_gateway = "fd00:20::1" },'):
            self.assertIn(line, proxy)
        self.assertNotIn('name = "eth1"', proxy)   # the default name by position
        notes = out[out.index("# 250 proxy"):out.index('"proxy" = {')]
        self.assertIn("net2 has no IPv4 setting: the modules set dhcp", notes)
        self.assertNotIn("defaults.ipv4_gateway", notes)
        blocked = out[out.index("Not importable"):]
        self.assertIn("VM 152 trunk: net1 carries VLAN trunks (10;20)", blocked)
        self.assertIn("VM 153 oldnic: net1 model ne2k_pci: not one the module knows", blocked)
        self.assertIn("container 251 gapct: network interfaces net0, net2 have a gap", blocked)
        self.assertIn("3 guest(s) to import, 3 the modules can't represent", out)

    def test_extra_nics_need_the_new_template(self):
        """An environment from before 0.63.0 has no extra_nics: the plan would remove the NICs, so no entry."""
        variables = self.env / "variables.tf"
        text = variables.read_text()
        for marker in ("    # NICs after the first", "    # interfaces after eth0"):
            start = text.index(marker)
            text = text[:start] + text[text.index("})), [])\n", start) + len("})), [])\n"):]
        variables.write_text(text)
        self.assertNotIn("extra_nics", tip.entry_attributes(text)["vms"])
        self.snapshot({"config_version": 3, "guests": [
            vm(160, "two", net1="virtio=BC:24:11:00:00:03,bridge=vmbr1"), vm(161, "one")]})
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("VM 160 two: extra_nics: not in this environment's variables.tf (older template; "
                      "init_repo.py --sync-managed updates it), the plan would remove the NICs", r.stdout)
        self.assertIn('"one" = {', r.stdout)

    def test_uefi_and_pci_devices(self):
        """bios, the EFI disk and the TPM state as the provider reads them; PCI devices by resource mapping only."""
        self.snapshot({"config_version": 3, "guests": [
            vm(170, "win11", ostype="win11", machine="q35", bios="ovmf", ide2=None, ipconfig0=None,
               efidisk0="local-zfs:vm-170-disk-1,efitype=4m,ms-cert=2023k,pre-enrolled-keys=1,size=1M",
               tpmstate0="tank:vm-170-disk-2,size=4M,version=v2.0"),
            {**vm(171, "gpu", machine="q35", hostpci0="mapping=gpu,pcie=1,romfile=vbios.rom,x-vga=1",
                  hostpci1="mapping=nic-10g,rombar=0,legacy-igd=1"), "node": "pve2"},
            vm(172, "oldtpm", tpmstate0="local-zfs:vm-172-disk-1,size=4M"),
            vm(173, "rawid", bios="ovmf", efidisk0="local-zfs:vm-173-disk-1,size=1M", hostpci0="host=0000:02:00.0"),
            vm(174, "gappci", hostpci0="mapping=a", hostpci2="mapping=b"),
            vm(175, "vgpu", hostpci0="mapping=gpu,mdev=nvidia-63"),
            vm(176, "usb", usb0="host=1234:5678"),
            vm(177, "bigefi", bios="ovmf", efidisk0="local-zfs:vm-177-disk-1,efitype=8m")]})
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout

        def entry(key):
            e = out[out.index(f'"{key}" = {{'):]
            return e[:e.index("\n  }")]
        win = entry("win11")
        for line in ('bios             = "ovmf"', 'efi_disk         = { type = "4m", pre_enrolled_keys = true }',
                     'tpm_state        = { datastore = "tank", version = "v2.0" }', 'machine          = "q35"'):
            self.assertIn(line, win)
        self.assertIn("# 170 win11: imported as is", out)     # ms-cert: the provider neither reads nor writes it
        gpu = entry("gpu")
        self.assertIn('  pci_devices = [\n'
                      '      { mapping = "gpu", pcie = true, rombar = true, rom_file = "vbios.rom", xvga = true },\n'
                      '      { mapping = "nic-10g" },\n    ]', gpu)
        self.assertIn('node           = "pve2"', gpu)
        notes = out[out.index("# 171 gpu"):out.index('"gpu" = {')]
        self.assertIn("hostpci1 legacy-igd=1: the module doesn't set it", notes)
        old = entry("oldtpm")
        self.assertIn("tpm_state      = {}", old)            # no version: v2.0 as the provider reads it
        self.assertNotIn("bios", old)
        self.assertNotIn("efi_disk", old)
        blocked = out[out.index("Not importable"):]
        self.assertIn('VM 173 rawid: hostpci0 passes a raw PCI device (0000:02:00.0): the modules take only resource '
                      'mappings (a raw ID needs root@pam). The user creates one in Proxmox (Datacenter → Resource '
                      'Mappings → PCI Devices), switches hostpci0 to it and takes a new snapshot '
                      '(references/proxmox.md "PCI passthrough")', blocked)
        self.assertNotIn("UEFI", blocked)
        self.assertIn("VM 174 gappci: PCI devices hostpci0, hostpci2 have a gap", blocked)
        self.assertIn("VM 175 vgpu: hostpci0 mediated device nvidia-63: the module has none", blocked)
        self.assertIn("VM 176 usb: USB passthrough (usb0): the module has none", blocked)
        self.assertIn("VM 177 bigefi: efidisk0 efitype=8m: the module knows 2m and 4m", blocked)
        self.assertIn("3 guest(s) to import, 5 the modules can't represent", out)
        r = self.plan("--write", "--guest", "win11", "--guest", "gpu", "--guest", "oldtpm")
        self.assertEqual(r.returncode, 0, r.stderr)
        if shutil.which("tofu"):
            fmt = subprocess.run(["tofu", "fmt", "-check", "-diff", "homelab.auto.tfvars"],
                                 cwd=self.env, capture_output=True, text=True)
            self.assertEqual(fmt.returncode, 0, fmt.stdout + fmt.stderr)

    def test_uefi_needs_the_new_template(self):
        """An environment from before 0.64.0: its plan would switch to SeaBIOS or remove the EFI disk, the TPM state
        or a device's ROM file, so no entry."""
        variables = self.env / "variables.tf"
        text = variables.read_text()
        start = text.index("    # UEFI (a Windows 11 VM")
        text = text[:start] + text[text.index("    # settings an imported VM keeps", start):]
        text = text.replace("rom_file = optional(string), ", "")
        variables.write_text(text)
        self.assertNotIn("efi_disk", tip.entry_attributes(text)["vms"])
        self.snapshot({"config_version": 3, "guests": [
            vm(180, "uefi", bios="ovmf", efidisk0="local-zfs:vm-180-disk-1,efitype=4m,size=1M",
               tpmstate0="local-zfs:vm-180-disk-2,size=4M,version=v2.0"),
            vm(181, "rom", hostpci0="mapping=gpu,romfile=vbios.rom"), vm(182, "plain")]})
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stderr)
        blocked = r.stdout[r.stdout.index("Not importable"):]
        for text in ("bios: not in this environment's variables.tf (older template; init_repo.py --sync-managed "
                     "updates it), the plan would switch the VM to SeaBIOS",
                     "efi_disk: not in this environment's variables.tf", "the plan would remove the EFI disk",
                     "tpm_state: not in this environment's variables.tf", "the plan would remove the TPM state",
                     "VM 181 rom: pci_devices rom_file: not in this environment's variables.tf"):
            self.assertIn(text, blocked)
        self.assertIn('"plain" = {', r.stdout)

    def test_name_clash_and_bad_name(self):
        guests = [vm(110, "present"), vm(111, "bad_name!")]
        self.snapshot({"config_version": 3, "guests": guests})
        r = self.plan()
        self.assertIn("VM 110 present: vms already has an entry named present", r.stdout)
        self.assertIn("is not a valid map key", r.stdout)
        self.assertIn("0 guest(s) to import", r.stdout)

    def test_proxmox_text_stays_in_its_comment(self):
        self.snapshot({"config_version": 3, "guests": [vm(120, "inj", startup="order=1\n}\nevil = {")]})
        r = self.plan("--write")
        self.assertEqual(r.returncode, 0, r.stderr)
        text = (self.env / "homelab.auto.tfvars").read_text()
        self.assertEqual([line for line in text.splitlines() if "evil" in line],
                         ["  #   - startup order=1 } evil = {: not order, up and down in seconds, the plan removes "
                          "it"])
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
        self.assertTrue({"vm_id", "mac_address", "cpu_type", "protection", "extra_disks", "disk_cache", "cdrom",
                         "cloud_init_drive", "startup", "os_type"} <= attrs["vms"])
        self.assertTrue({"template_file_id", "mac_address", "dns_servers", "swap_mib", "mount_points", "features",
                         "console_mode", "mtu"} <= attrs["containers"])
        for nested in ("datastore_id", "interface", "size_gib", "volume", "path", "order"):   # inside an object
            self.assertNotIn(nested, attrs["vms"] | attrs["containers"])

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

    def test_provider_defaults_read_as_unset(self):
        """OS type other and 512 MiB without ballooning: the provider's defaults, absent from the imported state, so
        the first plan sets them again; the entry says so."""
        ctx = {"defaults": {}, "node_datastores": False}
        notes = tip.vm_entry(vm(310, "fw", ostype="other", memory="512", balloon="0"), ctx).notes
        self.assertEqual([n.split(":")[0] for n in notes], ["OS type other", "memory 512 MiB without ballooning"])
        self.assertTrue(all("sets it again (nothing changes)" in n for n in notes))
        self.assertEqual(tip.vm_entry(vm(311, "big", memory="512", balloon="256"), ctx).notes, [])
        self.assertEqual(tip.vm_entry(vm(312, "lin"), ctx).notes, [])

    def test_sizes_and_options(self):
        self.assertEqual(tip.whole(tip.gib("32G")), 32)
        self.assertEqual(tip.whole(tip.gib("1T")), 1024)
        self.assertEqual(tip.whole(tip.gib("2048M")), 2)
        self.assertIsNone(tip.whole(tip.gib("512M")))
        self.assertEqual(tip.options("local:vm-1-disk-0,size=8G"), ("local:vm-1-disk-0", {"size": "8G"}))


if __name__ == "__main__":
    unittest.main()
