"""Tests for Several sites: --add-site, the default site, per-site OpenTofu environments."""
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
from helpers import ROOT, SCRIPTS, run, yq  # noqa: E402,F401

sys.path.insert(0, str(ROOT / "hooks"))
import guard  # noqa: E402,F401


class SitesTests(unittest.TestCase):  # issue 52
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib
        self.cfg = {"_root": "/nonexistent",
                    "proxmox": {"endpoint": "https://pve1.example:8006", "tokens": {"read_only": "proxmox-ro"}},
                    "sites": [{"name": "home"},
                              {"name": "offsite", "label": "Rented server", "ranges": ["192.0.2.0/24"],
                               "proxmox": {"endpoint": "https://pve-off.example:8006", "verify_tls": False,
                                           "tokens": {"read_only": "off-ro", "provisioning": "off-rw"}}},
                              {"name": "parents"}]}

    def test_sites(self):
        h = self.h
        self.assertEqual([s["name"] for s in h.sites(self.cfg)], ["home", "offsite", "parents"])
        self.assertEqual(h.site(self.cfg)["name"], "home")
        self.assertEqual(h.proxmox_site(self.cfg)["endpoint"], "https://pve1.example:8006")
        self.assertEqual(h.proxmox_site(self.cfg, "home")["_where"], "proxmox")
        off = h.proxmox_site(self.cfg, "offsite")
        self.assertEqual((off["endpoint"], off["_site"]), ("https://pve-off.example:8006", "offsite"))
        self.assertEqual(h.proxmox_token_name(off, "provisioning"), "off-rw")
        with self.assertRaises(h.ConfigError):
            h.proxmox_site(self.cfg, "parents")                    # no Proxmox there
        with self.assertRaises(h.ConfigError):
            h.site(self.cfg, "nope")
        self.assertEqual([p["_site"] for p in h.proxmox_sites(self.cfg)], ["home", "offsite"])
        self.assertEqual(h.site_of_secret(self.cfg, "off-ro")["_site"], "offsite")
        self.assertEqual(h.site_of_secret(self.cfg, "proxmox-rw")["_site"], "home")   # template default name
        self.assertEqual(h.site_of_address(self.cfg, "192.0.2.7")["name"], "offsite")
        self.assertIsNone(h.site_of_address(self.cfg, "10.0.0.1"))
        self.assertEqual(h.host_sites(["linux", "site_offsite"]), ["offsite"])
        self.assertEqual(h.proxmox_snapshot_file("/r").name, "proxmox.json")   # every site inside (#75)
        self.assertEqual([h.site_key(s) for s in h.sites(self.cfg)][:2], ["home", "offsite"])
        self.assertEqual(h.site_key(h.sites({"proxmox": {"endpoint": "x"}})[0]), "default")      # no sites:
        with self.assertRaises(h.ConfigError):
            h.sites({"sites": [{"name": "home"}, {"name": "default"}]})                  # reserved for the default
        single = h.sites({"proxmox": {"endpoint": "x"}})                  # no sites: one unnamed default
        self.assertEqual((len(single), single[0]["name"], single[0]["default"]), (1, "", True))

    def test_invalid_sites(self):
        h = self.h
        for bad in ([{"name": "Off-Site"}], [{"name": "a"}, {"name": "a"}], [{"label": "x"}],
                    "home", [{"name": "x", "ranges": ["nope"]}]):
            with self.assertRaises(h.ConfigError, msg=bad):
                h.sites({"sites": bad})
        with self.assertRaises(h.ConfigError):            # issue 64: the default site's Proxmox in one place only
            h.sites({"proxmox": {"endpoint": "a"}, "sites": [{"name": "home", "proxmox": {"endpoint": "x"}}]})

    def test_default_site_proxmox_in_sites(self):  # issue 64
        h = self.h
        cfg = {"_root": "/nonexistent", "proxmox": {"endpoint": "", "verify_tls": True,
                                                    "tokens": {"read_only": "proxmox-ro"}},   # template leftovers
               "sites": [{"name": "home", "proxmox": {"endpoint": "https://pve1.example:8006", "verify_tls": False,
                                                       "tokens": {"read_only": "home-ro"}}},
                         {"name": "offsite", "proxmox": {"endpoint": "https://pve-off.example:8006"}}]}
        px = h.proxmox_site(cfg)
        self.assertEqual((px["endpoint"], px["_where"], px["_site"]),
                         ("https://pve1.example:8006", "sites[home].proxmox", "home"))
        self.assertEqual(h.site_of_secret(cfg, "home-ro")["_site"], "home")
        self.assertEqual(h.config_value(cfg, "proxmox.endpoint"), "https://pve1.example:8006")
        self.assertEqual(h.config_value(self.cfg, "proxmox.endpoint"), "https://pve1.example:8006")  # top-level
        import ssl
        self.assertEqual(h.proxmox_ssl_context(cfg).verify_mode, ssl.CERT_NONE)    # default: the site's block

    def test_site_settings_env_and_vlans(self):
        h = self.h
        cfg = {**self.cfg, "vmid_ranges": {"vms": [100, 899], "templates": [9050, 9999]}, "vmid_scheme": "",
               "templates": {"keep_versions": 3, "build_network": {"ip": "10.0.10.250/24"}},
               "network": {"vlans": [{"id": 20, "name": "DMZ"}, {"id": 30, "name": "Backup", "site": "offsite"},
                                     {"id": 31, "name": "Backup", "site": "home"}]}}
        cfg["sites"] = [cfg["sites"][0], {**cfg["sites"][1], "vmid_ranges": {"vms": [2000, 2099]},
                                          "templates": {"build_network": {"ip": "192.0.2.250/24"}}}, cfg["sites"][2]]
        off = h.site_config(cfg, "offsite")
        self.assertEqual(off["vmid_ranges"], {"vms": [2000, 2099]})
        self.assertEqual(off["templates"], {"keep_versions": 3, "build_network": {"ip": "192.0.2.250/24"}})
        self.assertEqual(h.site_config(cfg, "parents")["vmid_ranges"], cfg["vmid_ranges"])   # no own: top-level
        self.assertEqual(h.next_vmid(off, "vms", {2000: "x"}), 2001)
        self.assertEqual((h.tofu_env(cfg), h.tofu_env(cfg, "home"), h.tofu_env(cfg, "offsite")),
                         ("homelab", "homelab", "offsite"))
        self.assertEqual(h.site_of_env(cfg, "offsite")["name"], "offsite")
        self.assertEqual(h.site_of_env(cfg, "homelab")["name"], "home")
        self.assertEqual(h.resolve_vlan(cfg, "backup", "offsite"), 30)
        self.assertEqual(h.resolve_vlan(cfg, "backup", "home"), 31)
        self.assertEqual(h.resolve_vlan(cfg, "dmz", "offsite"), 20)                   # no site: every site
        with self.assertRaises(h.ConfigError):
            h.resolve_vlan(cfg, "backup")                                              # ambiguous without a site
        self.assertEqual(h.vlan_label(cfg, 30, site_name="offsite"), "VLAN 30 Backup")
        for bad in ({"sites": [{"name": "home"}, {"name": "homelab"}]},                # = the default environment
                    {"sites": [{"name": "home", "vmid_ranges": {"vms": [1, 2]}}]},      # default: top-level keys
                    {"sites": [{"name": "home"}, {"name": "off", "vmid_ranges": [1, 2]}]},
                    {"sites": [{"name": "home"}], "network": {"vlans": [{"id": 5, "site": "moon"}]}},
                    {"network": {"vlans": [{"id": 5, "site": "home"}]}}):
            with self.assertRaises(h.ConfigError, msg=bad):
                h.sites(bad)

    def test_next_vmid_per_site(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", d, "--components", "proxmox", cwd=d)
        r = run("config_set.py", "sites+={name: home}",
                "sites+={name: offsite, proxmox: {endpoint: 'https://pve-off.example:8006'}}", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        snap = lambda ids: {"guests": [{"vmid": i, "type": "vm", "name": f"g{i}"} for i in ids]}
        Path(d, "discovery/proxmox.json").write_text(json.dumps({"sites": {"home": snap([100, 101]),
                                                                          "offsite": snap([100])}}))
        Path(d, "tofu/environments/homelab/homelab.auto.tfvars").write_text("vms = {\n  a = {\n    vm_id = 102\n  }\n}\n")
        Path(d, "tofu/environments/offsite").mkdir()
        Path(d, "tofu/environments/offsite/homelab.auto.tfvars").write_text("vms = {\n  b = {\n    vm_id = 101\n  }\n}\n")
        r = run("proxmox_inventory.py", "--next-vmid", "vms", cwd=d)
        self.assertEqual(r.stdout.strip(), "103", r.stderr)                 # not held back by the other site
        r = run("proxmox_inventory.py", "--next-vmid", "vms", "--site", "offsite", cwd=d)
        self.assertEqual(r.stdout.strip(), "102", r.stderr)
        r = run("config_set.py", "network.vlans+={id: 5, site: moon}", cwd=d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Nothing was written", r.stderr)

    def test_with_secrets_uses_the_site_of_the_token(self):
        import with_secrets
        cfg = {**self.cfg, "secrets": {n: {"service": "x", "kind": "proxmox_token"} for n in ("proxmox-ro", "off-ro")}}
        orig = self.h.read_secret
        self.h.read_secret = lambda c, n: "homelab@pve!ro=s3cret"
        try:
            home, _ = with_secrets.env_for(cfg, "proxmox-ro")
            off, _ = with_secrets.env_for(cfg, "off-ro")
        finally:
            self.h.read_secret = orig
        self.assertEqual(home["PROXMOX_VE_ENDPOINT"], "https://pve1.example:8006/")
        self.assertNotIn("PROXMOX_VE_INSECURE", home)
        self.assertEqual(off["PROXMOX_URL"], "https://pve-off.example:8006/api2/json")
        self.assertEqual(off["PROXMOX_VE_INSECURE"], "true")
        self.assertEqual((home["TF_VAR_proxmox_site"], off["TF_VAR_proxmox_site"], off["PKR_VAR_proxmox_site"]),
                         ("home", "offsite", "offsite"))
        cfg["proxmox"] = {**cfg["proxmox"], "endpoint": "https://pve1.example:8006, https://pve2.example:8006"}
        from unittest import mock
        with mock.patch.object(self.h, "read_secret", return_value="homelab@pve!ro=s3cret"), \
                mock.patch.object(self.h, "endpoint_reachable", side_effect=lambda ep: "pve2" in ep), \
                contextlib.redirect_stderr(io.StringIO()):
            home, _ = with_secrets.env_for(cfg, "proxmox-ro")
        self.assertEqual(home["PROXMOX_VE_ENDPOINT"], "https://pve2.example:8006/")   # GitHub issue 98

    def test_site_group_problems(self):
        import check_env
        inv = {"all": {"children": ["site_home", "site_offsite", "site_moon", "linux"]},
               "site_home": {"hosts": ["web01", "dup"]}, "site_offsite": {"children": ["offsite_dc"]},
               "offsite_dc": {"hosts": ["backup01", "dup"]}, "site_moon": {"hosts": ["rover"]},
               "linux": {"hosts": ["web01", "backup01"]}}
        problems = check_env.site_group_problems(inv, self.cfg)
        self.assertIn("group site_moon: homelab.yaml has no site 'moon' (sites:)", problems)
        self.assertIn("dup is in several site groups (site_home, site_offsite)", problems)
        self.assertEqual(len(problems), 2)

    def test_site_ambiguities(self):  # issue 63
        h = self.h
        inv = {"all": {"children": ["site_home", "site_offsite", "linux", "k8s"]},
               "site_home": {"children": ["home_rack"]}, "home_rack": {"hosts": ["web01", "k1"]},
               "site_offsite": {"hosts": ["k2", "off01"]}, "linux": {"hosts": ["web01", "loose1", "k3"]},
               "k8s": {"hosts": ["k1", "k2", "k3"]}}
        groups = h.inventory_groups(inv)
        self.assertEqual(groups["web01"], {"home_rack", "site_home", "linux"})          # parents included
        cfg = {**self.cfg, "clusters": [{"name": "k8s", "ansible_group": "k8s"}],
               "network": {"vlans": [{"id": 10, "name": "MGMT"}, {"id": 20, "name": "DMZ", "site": "home"},
                                     {"id": 21, "name": "DMZ", "site": "offsite"},
                                     {"id": 30, "name": "VPN", "site": "all"}, {"id": 31, "name": "vpn", "site": "home"}]}}
        cfg["sites"] = [{"name": "home", "ranges": ["10.0.0.0/16"]}, cfg["sites"][1],
                        {"name": "parents", "ranges": ["10.0.5.0/24"]}]
        found = h.site_ambiguities(cfg, groups)
        text = "\n".join(found)
        self.assertIn("VLAN 10 (MGMT) has no site", text)
        self.assertNotIn("VLAN 30", text.split("the name")[0])                          # site: all is deliberate
        self.assertIn("the name 'VPN' is used by VLANs 30, 31", text)
        self.assertNotIn("'DMZ'", text)                                                 # one per site: fine
        self.assertIn("home range 10.0.0.0/16 overlaps parents range 10.0.5.0/24", text)
        self.assertIn("2 inventory host(s) in no site_<name> group, so counted as the default site home: k3, loose1", text)
        self.assertIn("cluster k8s (group k8s) spans sites home, offsite", text)
        self.assertIn("cluster k8s (group k8s) has hosts in no site group (k3)", text)
        self.assertNotIn("offsite has no ranges", text)
        self.assertEqual(h.site_ambiguities({"network": {"vlans": [{"id": 10}]}}, groups), [])   # one site: nothing
        self.assertEqual(h.resolve_vlan(cfg, "MGMT", "offsite"), 10)
        with self.assertRaises(h.ConfigError):
            h.resolve_vlan(cfg, "vpn", "home")                                          # the ambiguity warned about
        self.assertEqual(h.resolve_vlan(cfg, "vpn", "offsite"), 30)
        with self.assertRaises(h.ConfigError):
            h.sites({"sites": [{"name": "home"}, {"name": "all"}]})                      # reserved
        import check_env
        res = check_env.check_site_ambiguity(cfg, inv)
        self.assertTrue(res and all(r["check"] == "sites:ambiguous" and r["ok"] is False for r in res))

    def test_draft_goes_into_the_site_group(self):
        import proxmox_to_inventory
        text = proxmox_to_inventory.to_yaml({"backup01": {"ansible_host": "192.0.2.2", "_os": "debian"}}, [],
                                            "onboarding", "discovery/proxmox.json (site offsite)", "site_offsite")
        self.assertIn("    site_offsite:\n      hosts:\n        backup01:", text)

    def test_drift_and_redaction_cover_every_site(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        run("init_repo.py", d, "--components", "proxmox,ansible,discovery", cwd=d)
        r = run("config_set.py", "proxmox.endpoint=https://pve1.example:8006", "sites+={name: home}",
                "sites+={name: offsite, label: Rented server, ranges: [192.0.2.0/24], "
                "proxmox: {endpoint: 'https://pve-off.example:8006'}}", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        guest = lambda vmid, name, tags: {"vmid": vmid, "name": name, "type": "vm", "node": "n1", "status": "running",
                                          "template": False, "tags": tags}
        snap = lambda guests: {"collected_at": "2026-01-01T00:00:00+00:00", "version": "9", "cluster": None,
                               "nodes": [], "networks": {}, "storage": [], "guests": guests, "backup_jobs": []}
        Path(d, "discovery/proxmox.json").write_text(json.dumps({"sites": {
            "home": snap([guest(100, "dns01", "tofu")]),
            "offsite": {"site": "offsite", **snap([guest(100, "offbackup", "")])}}}))
        Path(d, "ansible/inventory/managed/hosts.yml").write_text(
            "all:\n  children:\n    site_home:\n      hosts:\n        dns01: {ansible_host: 10.0.10.5}\n"
            "    site_offsite:\n      hosts:\n        dns01:\n    site_moon:\n      hosts:\n        rover: {ansible_host: 10.9.9.9}\n")
        host = {"mac": None, "hostnames": [], "device_type_guess": "server", "vendor": None}
        Path(d, "discovery/network.json").write_text(json.dumps({"updated_at": "x", "hosts": {"192.0.2.9": host}}))
        r = run("drift_report.py", "--no-tofu", cwd=d)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn("| Proxmox snapshot — site offsite (Rented server) | 2026-01-01", out)
        self.assertIn("## Proxmox ↔ OpenTofu — site offsite (Rented server) (by `tofu` tag", out)
        self.assertIn("offsite/100 vm `offbackup`", out)                     # same VMID, kept apart
        self.assertNotIn("home/100 vm `dns01` on", out)                       # tagged: managed
        self.assertIn("## Backups — site offsite (Rented server)", out)
        self.assertIn("`dns01` is in several site groups", out)
        self.assertIn("`rover` is in `site_moon`, but homelab.yaml has no site 'moon'", out)
        self.assertIn("192.0.2.9  — server [site offsite (Rented server)]", out)
        self.assertIn("**Site ambiguity", out)                                  # issue 63
        self.assertIn("sites: home has no ranges", out)
        import issues
        cfg = self.h.load_config(d)
        domains, hosts = issues.site_terms(cfg)
        self.assertIn("pve-off.example", hosts)
        self.assertIn("Rented server", hosts)
        self.assertIn("offbackup", hosts)


class DefaultSiteTests(unittest.TestCase):  # issue 65
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", self.d, "--components", "proxmox,ansible,discovery", cwd=self.d)
        r = run("config_set.py", "network.authorized_ranges+=10.0.10.0/24",
                "network.vlans+={id: 10, name: MGMT, cidr: 10.0.10.0/24}",
                "network.vlans+={id: 20, name: DMZ, cidr: 10.0.20.1/24}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        inv = Path(self.d, "ansible/inventory/managed")
        hosts = inv / "hosts.yml"
        hosts.write_text(hosts.read_text().replace("        rocky: {}", "        rocky:\n          hosts:\n"
                                                   "            web01: {ansible_host: 10.0.10.5}"))
        (inv / "tofu_hosts.yml").write_text("all:\n  children:\n    debian:\n      hosts:\n        tf01:\n"
                                            "          ansible_host: 10.0.20.7\n")
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib

    def test_name_default_site(self):
        h = self.h
        self.assertEqual(h.default_site_gaps(h.load_config(self.d), self.d), ["name", "ranges", "vlans", "group"])
        before = Path(self.d, "homelab.yaml").read_text()
        r = run("init_repo.py", self.d, "--name-default-site", "home", "--dry-run", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ranges: 10.0.10.0/24, 10.0.20.0/24", r.stdout)
        self.assertIn("vlans: site: home on 10 MGMT, 20 DMZ", r.stdout)
        self.assertIn("group: site_home in hosts.yml with 1 host(s): web01", r.stdout)
        self.assertIn("tofu_to_inventory.py (tf01)", r.stdout)
        self.assertEqual(Path(self.d, "homelab.yaml").read_text(), before)                  # dry run
        r = run("init_repo.py", self.d, "--name-default-site", "home", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = h.load_config(self.d)
        self.assertEqual(cfg["sites"], [{"name": "home", "ranges": ["10.0.10.0/24", "10.0.20.0/24"]}])
        self.assertEqual([v["site"] for v in cfg["network"]["vlans"]], ["home", "home"])
        self.assertIn("# optional, for more than one location", Path(self.d, "homelab.yaml").read_text())  # comment kept
        self.assertTrue(Path(self.d, "ansible/inventory/managed/group_vars/site_home.yml").is_file())
        ans, _ = h.load_ansible(Path(self.d))
        self.assertIn("site_home", ans["web01"]["_groups_all"])
        self.assertEqual(h.default_site_gaps(cfg, self.d), [])
        r = run("init_repo.py", self.d, "--name-default-site", "home", cwd=self.d)                # again: nothing to do
        self.assertIn("ranges: already", r.stdout)
        self.assertIn("every VLAN already names a site", r.stdout)
        self.assertIn("site_home exists; in no site group: tf01", r.stdout)
        self.assertNotEqual(run("init_repo.py", self.d, "--name-default-site", "office", cwd=self.d).returncode, 0)
        r = run("config_set.py", "network.vlans+={id: 30, name: IOT}", cwd=self.d)              # the only site
        self.assertIn("VLAN 30 gets site: home", r.stderr)
        self.assertEqual(h.load_config(self.d)["network"]["vlans"][-1]["site"], "home")

    def test_second_site_points_at_the_migration(self):
        h = self.h
        r = run("config_set.py", "sites+={name: home}", cwd=self.d)
        self.assertIn("init_repo.py --name-default-site", r.stderr)
        r = run("config_set.py", "sites+={name: offsite, ranges: [192.0.2.0/24]}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run("config_set.py", "network.vlans+={id: 40, name: OFF}", cwd=self.d)
        self.assertIn("VLAN 40 has no site", r.stderr)
        r = run("init_repo.py", self.d, "--add-site", "offsite", cwd=self.d)
        self.assertIn("The default site home isn't explicit yet (ranges, vlans, group)", r.stdout)
        import upgrade_notes
        note = next(n for n in upgrade_notes.all_notes() if n["id"] == "explicit-default-site")
        ok, ph = upgrade_notes._check(note, h.load_config(self.d), Path(self.d))
        self.assertEqual((ok, ph.get("site")), (True, "home"))
        r = run("init_repo.py", self.d, "--name-default-site", "home", "--steps", "ranges,vlans", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("group:", r.stdout)
        cfg = h.load_config(self.d)
        self.assertEqual([s["name"] for s in cfg["sites"]], ["home", "offsite"])
        self.assertEqual(cfg["sites"][0]["ranges"], ["10.0.10.0/24", "10.0.20.0/24"])
        self.assertEqual(cfg["sites"][1]["ranges"], ["192.0.2.0/24"])
        self.assertEqual([v["site"] for v in cfg["network"]["vlans"]], ["home", "home", "home"])
        self.assertEqual(h.default_site_gaps(cfg, self.d), ["group"])
        self.assertNotEqual(run("init_repo.py", self.d, "--name-default-site", "home", "--steps", "bogus",
                                cwd=self.d).returncode, 0)

    def test_ranges_inserted_into_a_block_item(self):
        import init_repo
        text = "a: 1\nsites:\n  - name: home   # here\n    label: Home\n  - name: off\nb: 2\n"
        out = init_repo._sites_with_ranges(text, [{}], "home", ["10.0.0.0/24"])
        self.assertEqual(out, "a: 1\nsites:\n  - name: home   # here\n    ranges: [10.0.0.0/24]\n"
                              "    label: Home\n  - name: off\nb: 2\n")
        self.assertIsNone(init_repo._sites_with_ranges("sites: [{name: home}]\n", [{}], "home", ["x"]))
        self.assertIsNone(init_repo._sites_with_ranges("sites:\n  - name: other\nnext:\n  - name: home\n", [{}],
                                                       "home", ["x"]))


class SiteTofuTests(unittest.TestCase):  # issue 52, part 2
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", self.d, "--components", "proxmox,ansible", cwd=self.d)
        r = run("config_set.py", "proxmox.endpoint=https://pve1.example:8006", "sites+={name: home}",
                "sites+={name: offsite, proxmox: {endpoint: 'https://pve-off.example:8006'}}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        sys.path.insert(0, str(SCRIPTS))
        import hmlib
        self.h = hmlib

    def test_add_site_and_check(self):
        import check_env
        cfg = self.h.load_config(self.d)
        self.assertEqual([r["ok"] for r in check_env.check_tofu_sites(cfg)], [False, None])  # homelab: no site.tf
        r = run("init_repo.py", self.d, "--add-site", "offsite", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('var.proxmox_site == "offsite"', Path(self.d, "tofu/environments/offsite/site.tf").read_text())
        self.assertIn('var.proxmox_site == "home"', Path(self.d, "tofu/environments/homelab/site.tf").read_text())
        self.assertTrue(Path(self.d, "tofu/environments/offsite/main.tf").is_file())
        self.assertIn("ansible_group_priority: 10",
                      Path(self.d, "ansible/inventory/managed/group_vars/site_offsite.yml").read_text())
        self.assertEqual([r["ok"] for r in check_env.check_tofu_sites(cfg)], [True, True])
        subprocess.run(["yq", "-i", '.opentofu.local.path = "~/st/state.tfstate"', str(Path(self.d, "homelab.yaml"))],
                       check=True)
        res = check_env.check_tofu_sites(self.h.load_config(self.d))
        self.assertEqual(res[-1]["check"], "tofu:state")
        self.assertFalse(res[-1]["ok"])
        r = run("init_repo.py", self.d, "--add-site", "home", cwd=self.d)     # issue 64: the default site's group_vars
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("group_vars/site_home.yml", r.stdout)
        self.assertNotIn("tofu/environments", r.stdout)
        self.assertNotEqual(run("init_repo.py", self.d, "--add-site", "moon", cwd=self.d).returncode, 0)

    def test_state_per_environment(self):
        run("init_repo.py", self.d, "--add-site", "offsite", cwd=self.d)
        init = lambda *a: run("tofu_init.py", "--print", *a, cwd=self.d)
        r = init("--site", "offsite")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("tofu/environments/offsite", r.stdout)
        self.assertIn("/offsite.tfstate", r.stdout)
        cfg = Path(self.d, "homelab.yaml")
        subprocess.run(["yq", "-i", f'.opentofu.local.path = "{self.d}/st/state.tfstate"', str(cfg)], check=True)
        self.assertEqual(init().returncode, 0)                                   # default env: as before
        r = init("--site", "offsite")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("has no {env}", r.stderr)
        subprocess.run(["yq", "-i", f'.opentofu.local.path = "{self.d}/st/{{env}}.tfstate"', str(cfg)], check=True)
        self.assertIn(f"{self.d}/st/offsite.tfstate", init("--site", "offsite").stdout)

    def test_tofu_hosts_per_site(self):
        import tofu_to_inventory
        text = tofu_to_inventory.to_yaml({"linux": {"web09": {"ansible_host": "192.0.2.9"}}}, "offsite", "site_offsite")
        self.assertIn("(offsite)", text.splitlines()[0])
        self.assertIn("    site_offsite:\n      hosts:\n        web09:", text)
        self.assertIn("children: {}", tofu_to_inventory.to_yaml({}, "offsite", "site_offsite"))

    def test_drift_compares_each_site_with_its_state(self):
        import drift_report
        state = {"values": {"root_module": {"child_modules": [{"resources": [
            {"type": "proxmox_virtual_environment_vm", "mode": "managed", "address": "module.vm[\"web09\"].x",
             "values": {"vm_id": 100, "name": "web09", "node_name": "n1", "started": True}}]}]}}}
        px = {"guests": [{"vmid": 100, "name": "web09", "type": "vm", "node": "n2", "status": "running",
                          "template": False, "cpus": None, "mem_gib": None},
                         {"vmid": 101, "name": "hand", "type": "vm", "node": "n1", "status": "running",
                          "template": False, "cpus": None, "mem_gib": None}]}
        lines, n = drift_report.compare_state(px, state, "offsite/")
        text = "\n".join(lines)
        self.assertIn("- offsite/101 vm `hand`", text)
        self.assertIn("offsite/100 `module.vm[\"web09\"].x`: node n1 → live n2", text)
        self.assertEqual(n, 2)
        Path(self.d, "discovery/proxmox.json").write_text(json.dumps({"sites": {"offsite": {"collected_at": "x", **px}}}))
        Path(self.d, "state.json").write_text(json.dumps(state))
        r = run("drift_report.py", "--tofu-json", "state.json", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("| OpenTofu state — site offsite | unavailable: no OpenTofu environment "
                      "(init_repo.py --add-site offsite) |", r.stdout)


if __name__ == "__main__":
    unittest.main()
