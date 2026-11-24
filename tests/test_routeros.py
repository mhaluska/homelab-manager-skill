"""Tests for routeros_audit.py."""
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


FAKE_ROS_SSH = r'''#!/usr/bin/env python3
import json, os, re, sys
if "-G" in sys.argv:                       # ssh -G: the user from ssh config
    print("hostname " + sys.argv[-1] + "\nuser cfguser\nport 22"); sys.exit(0)
host, cmd = sys.argv[-2], sys.argv[-1]
with open(os.environ["FAKE_SSH_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
if host == "10.0.0.9":
    sys.stderr.write("auditor@10.0.0.9: Permission denied (publickey).\n"); sys.exit(255)
chr_ = host == "10.0.0.2"
out = {
 "/system identity print without-paging": "  name: " + ("core-chr" if chr_ else "sw-rack") + "\n",
 "/system resource print without-paging": (
   "                   uptime: 3w2d4h\n                  version: " + ("7.15.3" if chr_ else "7.16.1") + " (stable)\n"
   "              free-memory: 400.0MiB\n             total-memory: 512.0MiB\n"
   "           free-hdd-space: " + ("80.0MiB" if chr_ else "3.1MiB") + "\n          total-hdd-space: 128.0MiB\n"
   "        architecture-name: " + ("x86_64" if chr_ else "arm") + "\n"
   "               board-name: " + ("CHR QEMU Standard PC (i440FX + PIIX, 1996)" if chr_ else "CRS326-24G-2S+") + "\n"),
 "/system routerboard print without-paging": "       routerboard: yes\n             model: CRS326-24G-2S+\n"
   "  current-firmware: 7.12\n  upgrade-firmware: 7.16.1\n",
 "/system package update print without-paging": "          channel: stable\n  installed-version: "
   + ("7.15.3" if chr_ else "7.16.1") + "\n     latest-version: 7.16.1\n",
 "/system license print without-paging": ("  system-id: abc\n      level: free\n  next-renewal-at: 2026-12-01 10:00:00\n"
   if chr_ else "  software-id: XYZ\n  level: 5\n"),
 "/interface print terse without-paging": " 0  R name=ether1 default-name=ether1 type=ether mtu=1500\n"
   " 1 X  name=ether2 default-name=ether2 type=ether mtu=1500\n",
 "/ip address print terse without-paging": " 0   address=10.0.0.1/24 network=10.0.0.0 interface=bridge\n",
 "/interface bridge print terse without-paging": " 0  R name=bridge vlan-filtering=yes comment=\"syntax error here\"\n",
 "/interface bridge vlan print terse without-paging": " 0   bridge=bridge vlan-ids=20 tagged=bridge,sfp1\n",
 "/interface vlan print terse without-paging": "",
 "/ip service print terse without-paging": (
   " 0   name=telnet port=23 address=\"\" vrf=main\n 1 X name=ftp port=21 address=\"\"\n"
   " 2   name=www port=80 address=10.0.0.0/24\n 3   name=ssh port=22 address=\"\"\n"),
 "/user print terse without-paging": " 0   name=admin group=full\n 1   name=auditor group=read\n",
 "/tool mac-server print without-paging": "  allowed-interface-list: " + ("MGMT" if chr_ else "all") + "\n",
 "/tool mac-server mac-winbox print without-paging": "  allowed-interface-list: MGMT\n",
 "/ip neighbor discovery-settings print without-paging": "  discover-interface-list: " + ("MGMT" if chr_ else "all")
   + "\n           protocol: cdp\n                     lldp\n",
 "/ip dhcp-server lease print terse without-paging": "" if chr_ else (
   " 0   address=10.0.0.40 mac-address=AA:BB:CC:00:00:01 host-name=LGwebOSTV comment=\"Living room TV\" status=bound\n"
   " 1 D address=10.0.0.41 mac-address=AA:BB:CC:00:00:02 host-name=\"ev';rm -rf ~;'charger\" status=bound\n"
   " 2 D address=10.0.0.99 mac-address=AA:BB:CC:00:00:03 host-name=phone status=bound\n"),
 "/ip arp print terse without-paging": " 0   address=10.0.0.42 mac-address=AA:BB:CC:00:00:02 interface=bridge\n",
 "/ip firewall filter print terse without-paging": "" if chr_ else (
   " 0    chain=input action=accept connection-state=established,related,untracked\n"
   " 1    chain=input action=drop connection-state=invalid\n"
   " 2    chain=input action=add-src-to-address-list protocol=tcp dst-port=1234 address-list=knock\n"
   " 3    chain=input action=accept protocol=tcp dst-port=22,8291 in-interface-list=MGMT\n"
   " 4    chain=input action=accept protocol=tcp dst-port=22 src-address-list=knock\n"
   " 5 X  chain=input action=accept protocol=tcp dst-port=22\n"
   " 6    chain=input action=accept protocol=icmp\n"
   " 7    chain=input action=accept protocol=tcp dst-port=80 src-address=10.0.0.0/24 comment=\"web ui\"\n"
   " 8    chain=input action=drop\n"
   " 9    chain=forward action=fasttrack-connection\n"),
 "/ip firewall nat print terse without-paging": "" if chr_ else (
   " 0    comment=web chain=dstnat action=dst-nat to-addresses=10.0.0.5 to-ports=443 protocol=tcp dst-port=443\n"),
}
flaky = os.environ.get("FAKE_ROS_FLAKY", "")   # "host:section": that section fails in the batch only (#131)
if cmd.startswith(':put "==hm:'):          # one session, every section after a marker (GitHub issue #131)
    for put, do in zip(*[iter(cmd.split("\n"))] * 2):
        section = re.fullmatch(r':put "==hm:(\w+)=="', put).group(1)
        inner = re.fullmatch(r':do \{ \[:parse "(.+)"\] \} on-error=\{ :put "==hm-error==" \}', do).group(1)
        print("==hm:" + section + "==")
        if inner not in out or (chr_ and "routerboard" in inner) or flaky == host + ":" + section:
            print("==hm-error==")
        else:
            sys.stdout.write(out[inner])
    sys.exit(0)
if cmd not in out or (chr_ and "routerboard" in cmd):
    print("bad command name routerboard (line 1 column 9)"); sys.exit(1)
sys.stdout.write(out[cmd])
'''


class RouterosAuditTests(unittest.TestCase):  # issue 26
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        import routeros_audit
        self.ra = routeros_audit
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        run("init_repo.py", str(self.d), "--components", "ansible,appliances", cwd=self.d)
        inv = self.d / "ansible/inventory/managed"
        (inv / "hosts.yml").write_text("all:\n  children:\n    appliances:\n      children:\n        routeros:\n"
                                       "          hosts:\n            sw-rack:\n              ansible_host: 10.0.0.1\n"
                                       "            chr1:\n              ansible_host: 10.0.0.2\n")
        (inv / "group_vars/routeros.yml").write_text("ansible_user: auditor\n")
        (inv / "hosts.yml").write_text((inv / "hosts.yml").read_text() + "    linux:\n      hosts:\n"
                                       "        web1:\n          ansible_host: 10.0.0.5\n")
        bin_ = self.d / "bin"
        bin_.mkdir()
        (bin_ / "ssh").write_text(FAKE_ROS_SSH)
        (bin_ / "ssh").chmod(0o755)
        self.log = self.d / "ssh.log"
        self.env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "FAKE_SSH_LOG": str(self.log)}

    def audit(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "routeros_audit.py"), *args], cwd=self.d,
                              env=self.env, capture_output=True, text=True)

    def test_leases_propose_names_for_unknown_addresses(self):  # GitHub issue 100
        (self.d / "discovery").mkdir(exist_ok=True)
        (self.d / "discovery/network.json").write_text(json.dumps({"hosts": {
            ip: {"ip": ip, "device_type_guess": "camera"} for ip in ("10.0.0.5", "10.0.0.40", "10.0.0.42", "10.0.0.77")}}))
        r = self.audit("--group", "routeros", "--no-write")
        self.assertNotIn("dhcp-server", self.log.read_text())                  # only with --leases
        self.assertNotIn("Names for unknown", r.stdout)
        r = self.audit("--group", "routeros", "--leases", "--no-write")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout[r.stdout.index("## Names for unknown scanned addresses"):]
        self.assertIn("2 of 3 unknown scanned address(es) have a DHCP lease name", out)
        self.assertIn("| 10.0.0.40 | Living room TV | aa:bb:cc:00:00:01 | – | sw-rack lease comment | camera |", out)
        self.assertIn("| 10.0.0.42 | evrm -rf charger | aa:bb:cc:00:00:02 | – | sw-rack lease host-name (leased 10.0.0.41) |",
                      out)                                                     # by ARP MAC; quotes and ; dropped
        self.assertNotIn("10.0.0.77 |", out)
        self.assertNotIn("10.0.0.5 |", out)                                    # an inventory host
        cmd = out[out.index("```bash\n") + 8:out.rindex("```")]
        self.assertEqual(cmd.count("'"), 4)                                    # two single-quoted arguments, nothing else
        args = shlex.split(cmd.replace("python3 $HM/scripts/config_set.py", "").replace("\\\n", " "))
        self.assertEqual(args, ['discovery.ignore_unmanaged+={ip: 10.0.0.40, name: "Living room TV", mac: "aa:bb:cc:00:00:01"}',
                                'discovery.ignore_unmanaged+={ip: 10.0.0.42, name: "evrm -rf charger", mac: "aa:bb:cc:00:00:02"}'])
        r = run("config_set.py", *args, cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.audit("--group", "routeros", "--leases")
        self.assertIn("No lease names any of the 1 unknown scanned address(es).", r.stdout)
        saved = json.loads((self.d / "discovery/routeros.json").read_text())["devices"]
        self.assertFalse({"leases", "arp"} & {k for d in saved.values() for k in list(d) + list(d["errors"])})

    def test_leases_scoped_to_range_or_vlan(self):  # GitHub issue #137
        (self.d / "discovery").mkdir(exist_ok=True)
        f = self.d / "discovery/network.json"
        hosts = {ip: {"ip": ip, "mac": None, "vendor": None, "ports": [], "os": [], "device_type_guess": "unknown"}
                 for ip in ("10.0.0.40", "10.0.0.42", "10.0.0.99")}
        f.write_text(json.dumps({"hosts": hosts}))
        r = run("config_set.py", "network.vlans+={id: 40, name: IoT, cidr: 10.0.0.32/28}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.audit("--group", "routeros", "--leases", "--no-write")
        self.assertIn("Would give 3 scanned host(s) without a MAC", r.stderr)            # unscoped: all of them
        self.assertIn("| 10.0.0.99 | phone |", r.stdout)
        r = self.audit("--group", "routeros", "--leases-only", "--vlan", "iot")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Gave 2 scanned host(s) in VLAN 40 IoT (10.0.0.32/28) without a MAC", r.stderr)
        self.assertNotIn("# RouterOS audit", r.stdout)                                     # no audit
        self.assertIn("Only inside VLAN 40 IoT (10.0.0.32/28) (--range/--vlan).", r.stdout)
        self.assertIn("2 of 2 unknown scanned address(es) have a DHCP lease name", r.stdout)
        self.assertNotIn("10.0.0.99", r.stdout)
        got = json.loads(f.read_text())["sites"]["default"]["hosts"]
        self.assertEqual(got["10.0.0.40"]["mac_source"], "router")
        self.assertIsNone(got["10.0.0.99"]["mac"])                                         # outside the VLAN
        self.assertFalse((self.d / "discovery/routeros.json").exists())                    # --leases-only
        sent = [json.loads(l)[-1] for l in self.log.read_text().splitlines()]
        self.assertIn("/ip dhcp-server lease print", sent[-1])
        self.assertNotIn("/ip service", sent[-1])                                          # only what it needs
        r = self.audit("sw-rack", "--leases-only", "--range", "10.0.0.96/28", "--no-write")   # by inventory name
        self.assertEqual(r.returncode, 0, r.stderr)
        call = json.loads(self.log.read_text().splitlines()[-1])
        self.assertEqual((call[-2], call[call.index("-l") + 1]), ("10.0.0.1", "auditor+ct512w"))
        self.assertIn("1 of 1 unknown scanned address(es)", r.stdout)
        self.assertIn("| 10.0.0.99 | phone |", r.stdout)
        r = self.audit("--group", "routeros", "10.0.0.1", "--leases-only", "--no-write")
        self.assertEqual(r.stderr.count("Inspecting 2 device(s)"), 1)                      # 10.0.0.1 = sw-rack, once
        r = self.audit("--group", "routeros", "--range", "10.0.0.0/24")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--range and --vlan limit --leases", r.stderr)
        r = self.audit("--group", "routeros", "--leases", "--vlan", "cameras")
        self.assertEqual(r.returncode, 3)
        self.assertIn("--vlan 'cameras': no VLAN with that ID or name and a cidr", r.stderr)
        cfg = {"network": {"vlans": [{"id": 40, "name": "IoT", "cidr": "10.0.0.32/28", "site": "a"},
                                     {"id": 41, "name": "IoT", "cidr": "10.0.1.0/24", "site": "b"},
                                     {"id": 42, "name": "iot", "cidr": "10.0.2.0/24", "site": "b"}]},
               "sites": [{"name": "a", "ranges": ["10.0.0.0/24"]}, {"name": "b", "ranges": ["10.0.1.0/24"]}]}
        nets, labels = self.ra.scope_networks(cfg, ["192.0.2.0/25"], ["IoT"], ["a"])        # the device's site only
        self.assertEqual(labels, ["192.0.2.0/25", "VLAN 40 IoT (10.0.0.32/28)"])
        with self.assertRaisesRegex(self.ra.hmlib.ConfigError, "ambiguous .* at site b"):
            self.ra.scope_networks(cfg, [], ["iot"], ["a", None])                           # no site: every site
        self.assertEqual(self.ra.scope_networks(cfg, [], ["41"], [None])[1], ["VLAN 41 IoT (10.0.1.0/24)"])
        self.assertTrue(self.ra.in_scope("10.0.0.40", nets))
        self.assertFalse(self.ra.in_scope("10.0.1.7", nets))
        self.assertFalse(self.ra.in_scope("2001:db8::1", nets))
        self.assertTrue(self.ra.in_scope("2001:db8::1", []))

    def test_one_session_retry_and_incomplete_leases(self):  # GitHub issue #131
        (self.d / "discovery").mkdir(exist_ok=True)
        (self.d / "discovery/network.json").write_text(json.dumps({"hosts": {
            ip: {"ip": ip, "device_type_guess": "unknown"} for ip in ("10.0.0.40", "10.0.0.77")}}))
        self.env["FAKE_ROS_FLAKY"] = "10.0.0.1:nat"
        r = self.audit("--group", "routeros", "--leases", "--no-write", "10.0.0.9")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(l)[-2:] for l in self.log.read_text().splitlines()]
        self.assertEqual(sorted(h for h, c in calls if c.startswith(":put")), ["10.0.0.1", "10.0.0.2", "10.0.0.9"])
        self.assertEqual([c for h, c in calls if not c.startswith(":put")],
                         ["/ip firewall nat print terse without-paging"])     # only the failed section, alone
        self.assertNotIn("nat:", r.stdout)                                     # the retry read it
        out = r.stdout[r.stdout.index("## Names for unknown scanned addresses"):]
        self.assertIn("**Incomplete:**", out)
        self.assertIn("- 10.0.0.9: not reachable (auth failed", out)
        self.assertIn("1 of 2 unknown scanned address(es) have a DHCP lease name", out)

    def test_leases_give_routed_hosts_a_mac(self):  # GitHub issue #132
        (self.d / "discovery").mkdir(exist_ok=True)
        hosts = {"10.0.0.42": {"ip": "10.0.0.42", "mac": None, "vendor": None, "ports": [], "os": [],
                               "device_type_guess": "unknown"},
                 "10.0.0.40": {"ip": "10.0.0.40", "mac": None, "vendor": None, "ports": [], "os": []},
                 "10.0.0.41": {"ip": "10.0.0.41", "mac": "02:00:00:00:00:09", "vendor": None, "ports": [], "os": []}}
        f = self.d / "discovery/network.json"
        f.write_text(json.dumps({"hosts": hosts}))
        r = self.audit("--group", "routeros", "--leases", "--no-write")
        self.assertIn("Would give 2 scanned host(s) without a MAC", r.stderr)
        self.assertEqual(json.loads(f.read_text()), {"hosts": hosts})                   # --no-write: unchanged
        r = self.audit("--group", "routeros", "--leases")
        self.assertEqual(r.returncode, 0, r.stderr)
        got = json.loads(f.read_text())["sites"]["default"]["hosts"]
        self.assertEqual((got["10.0.0.42"]["mac"], got["10.0.0.42"]["mac_source"]), ("AA:BB:CC:00:00:02", "router"))
        self.assertEqual(got["10.0.0.40"]["mac"], "AA:BB:CC:00:00:01")                 # a bound lease
        self.assertEqual(got["10.0.0.41"]["mac"], "02:00:00:00:00:09")                 # nmap's own is kept
        self.assertNotIn("mac_source", got["10.0.0.41"])
        self.assertIn("device_type_guess", got["10.0.0.40"])
        proxy = [{"address": f"10.0.1.{i}", "mac-address": "00:0C:42:00:00:01", "_flags": "DC"} for i in range(20)]
        devs = [{"host": "r1", "arp": proxy + [{"address": "10.0.0.7", "mac-address": "70:ee:50:12:34:56"},
                                               {"address": "10.0.0.8", "_flags": "D"},
                                               {"address": "10.0.0.9", "mac-address": "70:ee:50:12:34:57", "_flags": "I"}],
                 "leases": [{"address": "10.0.0.7", "mac-address": "70:EE:50:00:00:99", "status": "bound"},
                            {"address": "10.0.0.10", "mac-address": "70:EE:50:00:00:10", "status": "waiting"}]}]
        self.assertEqual(self.ra.router_macs(devs), {"10.0.0.7": ("70:EE:50:12:34:56", "r1")})  # ARP wins; no proxy ARP

    def test_batch_fallbacks(self):  # GitHub issue #131
        ra = self.ra
        detail = "board-name: hEX\nversion: 7.20\n"
        seen = []
        def old_router(h, u, p, t, cmd):                                       # ignores the script: no markers
            seen.append(cmd)
            return True, detail
        dev = ra.collect("r1", "u", 22, 5, runner=old_router)
        self.assertTrue(dev["reachable"])
        self.assertEqual(len(seen), 1 + len(ra.COMMANDS))                      # the script, then one per command
        def lost_leases(h, u, p, t, cmd):
            if cmd.startswith(":put"):
                return True, "".join(f"==hm:{s}==\n" + ("==hm-error==\n" if s in ("leases", "arp") else detail)
                                     for s in {**ra.COMMANDS, **ra.LEASE_COMMANDS})
            return False, "auth failed (key not authorized for this user — --user?)"
        dev = ra.collect("r1", "u", 22, 5, runner=lost_leases, leases=True)
        self.assertEqual(sorted(dev["errors"]), ["arp", "leases"])
        self.assertEqual(ra.unread_tables([{**dev, "identity": {"name": "core"}}]),
                         ["core: leases, arp (auth failed (key not authorized for this user — --user?))"])
        report = ra.proposal_report([], 3, False, ra.unread_tables([dev]))
        self.assertIn("- r1: leases, arp", report)
        report = ra.proposal_report([], 3, True, ["r1: leases (timeout)"])
        self.assertIn("No lease read names any of the 3 unknown scanned address(es).", report)
        self.assertEqual(ra.proposal_report([], 3, True, []).count("Incomplete"), 0)

    def test_live_connection_is_not_a_second_service(self):
        dev = {"reachable": True, "services": [
            {"name": "api", "port": "8728", "_flags": ""},
            {"name": "api", "port": "8728", "_flags": "Dc", "local": "10.9.0.1", "remote": "10.9.0.5:50150"}]}
        texts = [t for _, t in self.ra.findings(dev)]
        self.assertEqual(sum("plain-text service `api`" in t for t in texts), 1)
        self.assertEqual(self.ra.plaintext_enabled(dev), ["api"])

    def test_flash_by_device_class(self):  # GitHub issue #112
        f = lambda free, total, **kw: self.ra.flash_finding(self.ra.size_bytes(free), self.ra.size_bytes(total),
                                                            free, total, **kw)
        self.assertIsNone(f("2992.0KiB", "16.0MiB"))                    # normal on 16 MiB flash
        self.assertEqual(f("300.0KiB", "16.0MiB")[0], "info")
        self.assertIsNone(f("700.0KiB", "16.0MiB"))
        self.assertEqual(f("700.0KiB", "16.0MiB", min_free=2**20)[0], "info")
        self.assertEqual(f("3.1MiB", "128.0MiB")[0], "low")
        self.assertIsNone(f("80.0MiB", "128.0MiB"))
        run("config_set.py", "routeros_audit.min_free_flash=1MiB", cwd=self.d)
        self.assertEqual(self.ra.min_free_flash(self.ra.hmlib.load_config(self.d)), 2**20)
        run("config_set.py", "routeros_audit.min_free_flash=lots", cwd=self.d)
        with self.assertRaises(self.ra.hmlib.ConfigError):
            self.ra.min_free_flash(self.ra.hmlib.load_config(self.d))

    def test_recompute_without_connecting(self):  # GitHub issue #112
        (self.d / "discovery").mkdir(exist_ok=True)
        (self.d / "discovery/routeros.json").write_text(json.dumps({"devices": {"10.0.0.7": {
            "reachable": True, "resource": {"free-hdd-space": "2.5MiB", "total-hdd-space": "16.0MiB"},
            "findings": [{"severity": "medium", "text": "low free flash: 2.5MiB of 16.0MiB"}]}}}))
        r = self.audit("--recompute")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads((self.d / "discovery/routeros.json").read_text())["devices"]["10.0.0.7"]["findings"], [])
        self.assertFalse(self.log.exists() and self.log.read_text().strip())   # nothing collected

    def test_broken_routeros_json_is_kept(self):
        (self.d / "discovery").mkdir(exist_ok=True)
        f = self.d / "discovery/routeros.json"
        f.write_text('{"devices": {')
        r = self.audit("--recompute")
        self.assertEqual(r.returncode, 3)
        self.assertIn("routeros.json is not valid JSON", r.stderr)
        r = self.audit("--group", "routeros")                                  # checked before connecting
        self.assertEqual(r.returncode, 3)
        self.assertFalse(self.log.exists() and self.log.read_text().strip())
        self.assertEqual(f.read_text(), '{"devices": {')
        r = self.audit("--group", "routeros", "--no-write", "--jobs", "1")     # nothing to write: it runs
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_parsers(self):
        rows = self.ra.parse_terse(' 0 X name=ftp port=21 address=""\n 1   name=ssh comment="a b=c"\nFlags: X\n')
        self.assertEqual(rows, [{"name": "ftp", "port": "21", "address": "", "_flags": "X"},
                                {"name": "ssh", "comment": "a b=c", "_flags": ""}])
        self.assertEqual(self.ra.parse_detail("   board-name: CRS326\n  version: 7.16 (stable)\n"),
                         {"board-name": "CRS326", "version": "7.16 (stable)"})
        wrapped = "  name: a\r\n        b\r\n        c\r\n        -\r\n        1\r\n"   # issue 70: no pty, width 1
        self.assertEqual(self.ra.parse_detail(wrapped), {"name": "abc-1"})
        wrapped = "  version: 7\n           .\n           1\n            \n           (\n  arch: arm\n"
        self.assertEqual(self.ra.parse_detail(wrapped), {"version": "7.1 (", "arch": "arm"})
        self.assertEqual(self.ra.parse_detail("                   uptime: 3w\n                  version: 7.16\n"),
                         {"uptime": "3w", "version": "7.16"})
        self.assertEqual(self.ra.size_bytes("3.1MiB"), 3.1 * 2**20)
        self.assertEqual(self.ra.size_bytes("1024KiB"), 2**20)
        self.assertEqual(self.ra.parse_date("dec/01/2026 10:00:00"), self.ra.dt.date(2026, 12, 1))
        self.assertEqual(self.ra.parse_date("2026-12-01 10:00:00"), self.ra.dt.date(2026, 12, 1))

    def test_group_audit(self):
        r = self.audit("--group", "routeros", "10.0.0.9")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(l) for l in self.log.read_text().splitlines()]
        for c in calls:
            self.assertIn("-T", c)                                                   # no pty: raw-style hang
            self.assertIn("BatchMode=yes", c)
            if c[-2] != "10.0.0.9":
                self.assertEqual(c[c.index("-l") + 1], "auditor+ct512w")              # from group_vars/routeros.yml
            else:
                self.assertEqual(c[c.index("-l") + 1], "cfguser+ct512w")              # given directly: ssh -G
            for line in c[-1].split("\n"):                                          # read-only
                self.assertRegex(line, r'^(:put "==hm:\w+=="|:do \{ \[:parse "/[a-z /-]+ print( terse)? without-paging"\] '
                                       r'\} on-error=\{ :put "==hm-error==" \})$')
        self.assertEqual(sorted(c[-2] for c in calls), ["10.0.0.1", "10.0.0.2", "10.0.0.9"])  # one session each (#131)
        out = r.stdout
        self.assertIn("| 10.0.0.1 | sw-rack | CRS326-24G-2S+ | 7.16.1 (stable) | 7.12 | 3.1MiB |", out)
        self.assertIn("| 10.0.0.2 | core-chr | CHR QEMU", out)
        self.assertIn("**Version drift:** 7.15.3: 10.0.0.2; 7.16.1: 10.0.0.1", out)
        sw = out[out.index("## 10.0.0.1"):out.index("## 10.0.0.2")]
        self.assertIn("**high** — plain-text service `telnet` enabled (port 23, from any address): disable it and use ssh", sw)
        self.assertIn("**low** — plain-text service `www` enabled (port 80, limited to 10.0.0.0/24): disable it and use www-ssl · `plaintext-www`\n", sw)
        self.assertNotIn("`ftp`", sw)                                                 # disabled (X flag)
        self.assertIn("RouterBOOT firmware 7.12 is behind 7.16.1", sw)
        self.assertIn("**low** — low free flash: 3.1MiB of 128.0MiB", sw)
        self.assertIn("default user `admin` is enabled", sw)
        self.assertIn("- Fix: `ansible-playbook playbooks/routeros-disable-services.yml -l sw-rack "   # GitHub #79
                      "-e '{\"routeros_disable_services\": [\"telnet\", \"www\"]}' --check`", sw)
        self.assertIn("-l chr1 ", out[out.index("## 10.0.0.2"):])
        self.assertIn("**low** — `ssh` reachable from any address (port 22): limit it to the management network "   # #80
                      "(IPv4 input firewall for port 22: accept in-interface-list=MGMT; accept src-address-list=knock; "
                      "drop the rest) · `ssh-any-address`", sw)                                     # GitHub #138
        self.assertIn("at least limit it to the management network (IPv4 input firewall for port 23: drop the rest)", sw)
        self.assertIn("(IPv4 input firewall for port 22: no rule: accepted)", out[out.index("## 10.0.0.2"):])
        self.assertIn("**medium** — MAC server (MAC Telnet) on all interfaces", sw)
        self.assertIn("**low** — neighbour discovery (MNDP/CDP/LLDP) on all interfaces", sw)
        self.assertNotIn("MAC Winbox on all", sw)
        self.assertIn("- Limit: `ansible-playbook playbooks/routeros-restrict-management.yml -l sw-rack --check`", sw)
        self.assertIn("- Upgrade: `ansible-playbook playbooks/routeros-routerboot-upgrade.yml -l sw-rack --check`", sw)  # #140
        self.assertIn("`playbooks/routeros-routerboot-upgrade.yml` (stages it and reboots: approval) · `routerboot-7.16.1`", sw)
        self.assertNotIn("routeros-routerboot-upgrade.yml -l chr1", out)                           # CHR: no RouterBOOT
        self.assertNotIn("on all interfaces", out[out.index("## 10.0.0.2"):out.index("## 10.0.0.9")])
        live = {"services": [{"name": "ssh", "_flags": "D", "remote": "10.0.0.7:5000"},
                             {"name": "ssh", "_flags": "", "address": "10.0.99.0/24"},
                             {"name": "winbox", "_flags": "", "address": ""}, {"name": "api-ssl", "_flags": "X"}]}
        self.assertEqual(self.ra.open_management(live), ["winbox"])          # live connections and limited ones don't count
        self.assertNotIn("- Fix:", out[out.index("## 10.0.0.9"):])                   # not inspected
        dev = {"services": [{"name": "api", "_flags": ""}, {"name": "ssh", "_flags": ""}]}
        self.assertIn("add the device to the `routeros` group", self.ra.fix_hint(dev, None))
        self.assertIn('["api"]', self.ra.fix_hint(dev, "r1"))
        self.assertIsNone(self.ra.fix_hint({"services": [{"name": "api", "_flags": "X"}]}, "r1"))
        chr_ = out[out.index("## 10.0.0.2"):]
        self.assertIn("RouterOS 7.16.1 available on channel stable (installed 7.15.3", chr_)
        self.assertIn("CHR licence level `free`", chr_)
        self.assertNotIn("routerboard", chr_)
        self.assertIn("## 10.0.0.9\n- **high** — not inspected: auth failed", out)
        db = json.loads((self.d / "discovery/routeros.json").read_text())["devices"]
        self.assertEqual(sorted(db), ["10.0.0.1", "10.0.0.2", "10.0.0.9"])
        self.assertEqual(db["10.0.0.1"]["bridges"][0]["vlan-filtering"], "yes")      # comment didn't look like an error
        self.assertEqual(db["10.0.0.1"]["bridge_vlans"][0]["tagged"], "bridge,sfp1")

    def test_accepted_findings(self):  # GitHub issue #138
        inv = self.d / "ansible/inventory/managed"
        (inv / "host_vars").mkdir(exist_ok=True)
        (inv / "host_vars/sw-rack.yml").write_text(
            "routeros_audit_accept: [SSH-any-address, default-admin, plaintext-telnet, winbox-any-address]\n")
        r = self.audit("--group", "routeros")
        self.assertEqual(r.returncode, 0, r.stderr)
        sw = r.stdout[r.stdout.index("## 10.0.0.1"):r.stdout.index("## 10.0.0.2")]
        self.assertNotIn("**high** — plain-text service `telnet`", sw)
        self.assertNotIn("default user `admin`", sw)
        self.assertIn("- Accepted (routeros_audit_accept): `plaintext-telnet` (high), `ssh-any-address` (low), "
                      "`default-admin` (low)", sw)
        self.assertIn("not found any more (remove them?): `winbox-any-address`", sw)
        self.assertIn('"routeros_disable_services": ["www"]', sw)                      # telnet accepted: not fixed
        self.assertIn("| 10.0.0.1 | sw-rack | CRS326-24G-2S+ | 7.16.1 (stable) | 7.12 | 3.1MiB | 5 |", r.stdout)
        chr_ = r.stdout[r.stdout.index("## 10.0.0.2"):]
        self.assertIn("default user `admin` is enabled: use named accounts and disable it · `default-admin`", chr_)
        db = json.loads((self.d / "discovery/routeros.json").read_text())["devices"]
        f = {x["key"]: x for x in db["10.0.0.1"]["findings"]}
        self.assertTrue(f["default-admin"]["accepted"])
        self.assertNotIn("accepted", f["plaintext-www"])
        self.assertNotIn("accepted", {x["key"]: x for x in db["10.0.0.2"]["findings"]}["default-admin"])
        sys.path.insert(0, str(SCRIPTS))
        import overview
        docs = {"routeros.json": {"devices": db}, "bmc.json": {}, "updates.json": {}}
        self.assertEqual(overview.ros_state(db["10.0.0.1"]), "5 audit findings, 3 accepted")
        warn = [w for w in overview.glance_warnings(docs, {}, {}) if w.startswith("RouterOS")]
        self.assertEqual(warn, ["RouterOS audit: 1 high, 3 medium"])                   # only chr1's telnet: sw-rack's is accepted
        (inv / "host_vars/sw-rack.yml").write_text("routeros_audit_accept: plaintext-www\n")
        r = self.audit("--recompute")                                                  # a changed list, no SSH
        self.assertEqual(r.returncode, 0, r.stderr)
        f = {x["key"]: x for x in json.loads((self.d / "discovery/routeros.json").read_text())["devices"]["10.0.0.1"]["findings"]}
        self.assertEqual([k for k, x in f.items() if x.get("accepted")], ["plaintext-www"])
        self.assertEqual(self.ra.accept_lists({"r1": {"ansible_host": "10.0.0.7", "routeros_audit_accept": ["{{ x }}", " "]}}), {})

    def test_input_firewall_evidence(self):  # GitHub issue #138
        fw = lambda rules, port=22: self.ra.input_firewall({"filter": rules, "errors": {}}, port)
        self.assertIsNone(self.ra.input_firewall({"errors": {}}, 22))                        # not read
        self.assertIsNone(self.ra.input_firewall({"filter": [], "errors": {"filter": "timeout"}}, 22))
        self.assertTrue(fw([{"chain": "input", "action": "drop", "in-interface-list": "!LAN"}]).endswith(
            "drop in-interface-list=!LAN; accepted otherwise (end of chain)"))                 # default config
        self.assertTrue(fw([{"chain": "input", "action": "jump", "jump-target": "mgmt"},
                            {"chain": "input", "action": "drop"}]).endswith(": jump to mgmt (not followed)"))
        rules = [{"chain": "input", "action": "accept", "protocol": "udp"},
                 {"chain": "input", "action": "accept", "protocol": "!udp", "dst-port": "8000-8100"},
                 {"chain": "input", "action": "accept", "dst-port": "!22", "src-address": "192.0.2.0/24"},
                 {"chain": "input", "action": "accept", "connection-state": "!established", "src-address": "198.51.100.1"},
                 {"chain": "input", "action": "accept"}]
        self.assertTrue(fw(rules).endswith(": accept src-address=198.51.100.1; accept the rest"))
        self.assertTrue(fw(rules, 8080).endswith(": accept the rest"))                       # !udp, in 8000-8100
        self.assertIn(": accept src-address=192.0.2.0/24; accept src-address=198.51.100.1;", fw(rules, 23))  # !22
        many = [{"chain": "input", "action": "accept", "src-address": f"192.0.2.{i}"} for i in range(9)]
        self.assertEqual(fw(many).count(";"), 6)                                             # five, …, the last
        self.assertTrue(self.ra.port_matches("x", 22))                                       # unreadable: may match

    def test_licence_deadline(self):  # issue 71: next-renewal-at is only the next renewal attempt
        dev = {"reachable": True, "errors": {}, "resource": {"board-name": "CHR"},
               "license": {"level": "p10", "next-renewal-at": "2026-12-07 10:00:00", "deadline-at": "2027-01-06"}}
        day = self.ra.dt.date
        self.assertEqual(self.ra.findings(dev, day(2026, 11, 18)), [])                # renewal soon: healthy
        f = self.ra.findings(dev, day(2026, 12, 20))
        self.assertEqual([s for s, _ in f], ["medium"])
        self.assertIn("deadline 2027-01-06: within 30 days", f[0][1])
        self.assertEqual([s for s, _ in self.ra.findings(dev, day(2027, 1, 7))], ["high"])
        f = self.ra.licence_findings("p10", "2027-03-01", "2026-12-07", day(2026, 12, 10))  # renewal passed, not moved
        self.assertEqual([k for k, s, _ in f], ["licence-renewal-overdue"])
        self.assertIn("renewal was due 2026-12-07", f[0][2])
        dev["license"] = {"level": "p1", "next-renewal-at": "soon"}
        self.assertEqual([s for s, _ in self.ra.findings(dev, day(2026, 11, 18))], ["info"])

    def test_templated_user_is_not_passed(self):
        sys.path.insert(0, str(SCRIPTS))
        self.assertEqual(self.ra.group_hosts(self.d, "linux"), [("10.0.0.5", None, None, None)])  # all.yml's {{ … }}

    def test_all_unreachable(self):
        r = self.audit("10.0.0.9", "--no-write")
        self.assertEqual(r.returncode, 2)
        self.assertFalse((self.d / "discovery/routeros.json").exists())


if __name__ == "__main__":
    unittest.main()
