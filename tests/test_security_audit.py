"""Tests for security_audit.py and the security-audit.yml template (GitHub issue #139)."""
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "homelab-manager" / "scripts"
TEMPLATE = ROOT / "skills" / "homelab-manager" / "assets" / "repo-template"
sys.path.insert(0, str(SCRIPTS))
import overview  # noqa: E402
import security_audit as sa  # noqa: E402

# What security-audit.yml keeps for a Debian host with most problems (documentation addresses only)
WEAK = """@@os
name|Debian GNU/Linux 13 (trixie)
virt|lxc
@@sshd
passwordauthentication yes
kbdinteractiveauthentication no
usepam yes
permitrootlogin yes
permitemptypasswords no
x11forwarding yes
@@accounts
password|root
password|pi
empty|guest
uid0|toor
@@sudo
pi ALL=(ALL) NOPASSWD: ALL
%sudo\tALL=(ALL:ALL) NOPASSWD: ALL
zabbix ALL = NOPASSWD: /usr/sbin/unbound-control
@@firewall
unit|firewalld|inactive
unit|ufw|inactive
unit|nftables|active
nft|input|accept|0|0
@@autoupdate
pm|apt
apt|APT::Periodic::Update-Package-Lists "1";
pkg|unattended-upgrades|
timer|apt-daily-upgrade.timer|enabled|active
timer|dnf-automatic.timer||inactive
@@listen
tcp   LISTEN 0      511          0.0.0.0:6379      0.0.0.0:*    users:(("redis-server",pid=10,fd=6))
tcp   LISTEN 0      128        127.0.0.1:11211     0.0.0.0:*    users:(("memcached",pid=11,fd=26))
tcp   LISTEN 0      4096            [::]:111          [::]:*    users:(("rpcbind",pid=1,fd=4))
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=9,fd=13))
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=5,fd=3))
@@samba
share|[global]
opt|map to guest = Bad User
share|[Media]
opt|guest ok = Yes
opt|read only = No
opt|path = /srv/media
share|[photos]
opt|guest ok = Yes
share|[office]
opt|guest ok = Yes
opt|writeable = yes
opt|hosts allow = 192.0.2.0/24
share|[printers]
opt|guest ok = Yes
@@nfs
/srv/nfs/a-very-long-export-path-that-wraps
\t\t<world>(sync,wdelay,hide,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)
/srv/backup   \t192.0.2.10(sync,wdelay,hide,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)
@@containers
docker|/watchtower|containrrr/watchtower:latest|false|bridge|/var/run/docker.sock /etc/localtime
docker|/agent|example/agent:1.0|true|host|
docker|/tunnel|cloudflare/cloudflared:2025.1.0|false|host|
@@tunnel
cloudflared|cloudflared version 2024.6.1 (built 2024-06-12-1200 UTC)|active
wireguard|wg0|
@@other
fail2ban|inactive
@@end""".splitlines()

GOOD = """@@os
name|Rocky Linux 9.6 (Blue Onyx)
@@sshd
passwordauthentication no
kbdinteractiveauthentication no
usepam yes
permitrootlogin without-password
@@accounts
password|root
@@sudo
ansible ALL=(ALL) NOPASSWD: ALL
@@firewall
unit|firewalld|active
unit|ufw|inactive
unit|nftables|inactive
nft|filter_INPUT|accept|12|2
@@autoupdate
pm|dnf
timer|dnf-automatic.timer|enabled|active
dnf|apply_updates = yes
@@listen
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=5,fd=3))
@@end""".splitlines()


def keys(found):
    return {k: s for k, s, _ in found}


class ParseAndJudgeTests(unittest.TestCase):
    today = dt.date(2026, 11, 21)

    def test_weak_host(self):
        facts = sa.parse_host({"output": WEAK})
        f = keys(sa.host_findings(facts, self.today))
        self.assertEqual(f["ssh-password-auth"], "medium")
        self.assertEqual(f["ssh-root-login"], "medium")                      # root has a password SSH accepts
        self.assertEqual(f["ssh-x11-forwarding"], "info")
        self.assertEqual(f["empty-password-guest"], "high")
        self.assertEqual(f["uid0-toor"], "high")
        self.assertEqual(f["password-pi"], "low")
        self.assertNotIn("password-root", f)                                 # covered by ssh-root-login
        self.assertEqual(f["sudo-nopasswd-pi"], "medium")                    # password + SSH passwords + ALL
        self.assertEqual(f["sudo-nopasswd-group-sudo"], "low")
        self.assertEqual(f["sudo-nopasswd-zabbix"], "info")                  # one command only
        self.assertEqual(f["no-firewall"], "low")                            # nftables active, empty input chain
        self.assertEqual(f["no-auto-updates"], "low")
        self.assertEqual(f["listen-redis"], "medium")
        self.assertNotIn("listen-memcached", f)                              # loopback only
        self.assertNotIn("listen-rpcbind", f)                                # an NFS server needs it
        self.assertEqual(f["smb-guest-write-media"], "medium")
        self.assertEqual(f["smb-guest-photos"], "low")
        self.assertEqual(f["smb-guest-write-office"], "low")                 # limited by hosts allow
        self.assertNotIn("smb-guest-printers", f)
        self.assertEqual(f["nfs-world-srv-nfs-a-very-long-export-path-that-wraps"], "medium")  # client on the next line
        self.assertEqual(f["nfs-no-root-squash-srv-backup"], "low")
        self.assertEqual(f["container-socket-watchtower"], "medium")
        self.assertEqual(f["container-privileged-agent"], "medium")
        self.assertEqual(f["cloudflared-2024.6.1"], "low")
        self.assertEqual(f["cloudflared-2025.1.0"], "low")                   # the image tag of a container
        self.assertEqual([t["kind"] for t in facts["tunnels"]], ["cloudflared", "wireguard", "cloudflared (container)"])
        self.assertEqual([s["address"] for s in facts["listen"]][2:4], ["::", "127.0.0.53"])
        text = dict((k, t) for k, _, t in sa.host_findings(facts, self.today))
        self.assertIn("`%sudo ALL=(ALL:ALL) NOPASSWD: ALL`", text["sudo-nopasswd-group-sudo"])   # tab collapsed
        self.assertIn("tcp 0.0.0.0 (process redis-server)", text["listen-redis"])

    def test_good_host(self):
        f = keys(sa.host_findings(sa.parse_host({"output": GOOD}), self.today))
        self.assertEqual(f, {"sudo-nopasswd-ansible": "low"})               # key-only SSH, firewall, dnf-automatic
        rpc = WEAK[:WEAK.index("@@nfs")] + ["@@end"]
        self.assertEqual(keys(sa.host_findings(sa.parse_host({"output": rpc}), self.today))["listen-rpcbind"], "low")

    def test_firewall_and_updates_edge_cases(self):
        fw = lambda **kw: sa.firewall_state({"units": {}, "nft": [], "iptables": None, "ufw": None, "pvefw": None, **kw})
        self.assertEqual(fw(units={"firewalld": "inactive"})[0], False)       # no nft or iptables command at all
        self.assertIsNone(fw()[0])
        self.assertTrue(fw(iptables={"policy": "ACCEPT", "rules": 3, "drops": 0, "pvefw": 1})[0])   # pve-firewall jump
        self.assertTrue(fw(pvefw="Status: enabled/running")[0])
        self.assertIn("2 nft input chains: policy accept/drop", fw(nft=[
            {"chain": "INPUT", "policy": "accept", "rules": 0, "drops": 0},
            {"chain": "input", "policy": "drop", "rules": 4, "drops": 0}])[1])
        au = lambda **kw: sa.auto_updates({"pm": [], "apt": {}, "pkg": None, "timers": {}, "dnf": {}, **kw})
        self.assertIsNone(au()[0])                                           # neither apt nor dnf
        self.assertTrue(au(pm=["apt"], pkg="install ok installed", apt={"APT::Periodic::Unattended-Upgrade": "1"},
                           timers={"apt-daily-upgrade.timer": {"enabled": "enabled"}})[0])
        self.assertTrue(au(pm=["dnf"], timers={"dnf-automatic-install.timer": {"enabled": "enabled"}})[0])
        self.assertFalse(au(pm=["dnf"], timers={"dnf-automatic.timer": {"enabled": "enabled"}})[0])   # download only
        pve = WEAK + ["@@firewall", "pvefw|Status: disabled/running"]
        self.assertNotIn("no-auto-updates", keys(sa.host_findings(sa.parse_host({"output": pve}), self.today)))
        self.assertIsNone(sa.ssh_password({"passwordauthentication": "yes", "authenticationmethods": "publickey,password"}))

    def test_untrusted_output(self):
        evil = ["@@os", "name|x\x1b[31m" + "A" * 1000, "@@containers", "docker|/a|b`c|false|host|", "@@end"]
        facts = sa.parse_host({"output": evil})
        self.assertNotIn("\x1b", facts["os"])
        self.assertLess(len(facts["os"]), 420)
        self.assertEqual(sa.key_part("We|ird Name/..!"), "we-ird-name")
        self.assertEqual(sa.md("a|b<script>"), "a\\|b&lt;script>")

    def test_mac(self):
        outputs = {"fdesetup": "FileVault is Off.\n", "--getglobalstate": "Firewall is disabled. (State = 0)\n",
                   "--getstealthmode": "Firewall stealth mode is off\n",
                   "csrutil": "System Integrity Protection status: enabled.\n", "spctl": "assessments enabled\n",
                   "defaults": "someone\n", "ssh-add": "256 SHA256:x a (ED25519)\n",
                   "softwareupdate": "Software Update Tool\n\n* Label: macOS Tahoe 27.2.2-25C99\n\tTitle: …\n"}

        class R:
            def __init__(self, out):
                self.returncode, self.stdout, self.stderr = 0, out, ""

        def run(cmd, **kw):
            return R(next(v for k, v in outputs.items() if k in cmd or k == cmd[0]))
        st = sa.mac_checks(True, run=run)
        self.assertEqual((st["filevault"], st["firewall"], st["stealth"], st["sip"], st["gatekeeper"]),
                         ("off", False, False, True, True))
        self.assertTrue(st["auto_login"])
        self.assertNotIn("someone", json.dumps(st))                          # never the auto-login user's name
        self.assertEqual(st["agent_keys"], 1)
        f = keys(sa.mac_findings(st))
        self.assertEqual(f, {"mac-filevault-off": "info", "mac-firewall-off": "low",
                             "macos-update-macos-tahoe-27.2.2-25c99": "medium"})
        self.assertEqual(keys(sa.mac_findings({"filevault": "off", "auto_login": False, "sip": False})),
                         {"mac-filevault-off": "low", "mac-sip-off": "high"})


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        r = subprocess.run([sys.executable, str(SCRIPTS / "init_repo.py"), str(self.d), "--components", "ansible"],
                           cwd=self.d, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        subprocess.run([sys.executable, str(SCRIPTS / "config_set.py"),
                        "sites+={name: home}", "sites+={name: lab}"], cwd=self.d, capture_output=True, text=True)
        inv = self.d / "ansible/inventory/managed"
        (inv / "hosts.yml").write_text(
            "all:\n  children:\n    linux:\n      hosts:\n        web1:\n          ansible_host: 192.0.2.5\n"
            "        db1:\n          ansible_host: 192.0.2.6\n        lab1:\n          ansible_host: 198.51.100.5\n"
            "    site_lab:\n      hosts:\n        lab1:\n")
        (inv / "host_vars").mkdir()
        (inv / "host_vars/web1.yml").write_text("security_audit_accept: [SSH-password-auth, listen-redis, gone-key]\n")
        (self.d / "discovery").mkdir(exist_ok=True)
        self.db = self.d / "discovery/security.json"
        self.db.write_text(json.dumps({"collected_at": "2026-11-21T07:00:00+00:00", "hosts": {
            "web1": {"output": WEAK, "collected_at": "2026-11-21T07:00:00+00:00", "site": None},
            "db1": {"output": GOOD, "collected_at": "2026-11-20T07:00:00+00:00", "site": None},
            "lab1": {"error": "unreachable: timed out", "collected_at": "2026-11-21T07:00:00+00:00", "site": "lab"}}}))

    def audit(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "security_audit.py"), "--no-mac", *args], cwd=self.d,
                              capture_output=True, text=True)

    def test_report_and_accepted(self):
        r = self.audit()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn("2 Linux host(s) from `security-audit.yml` (collected 2026-11-20 to 2026-11-21), 1 not reachable",
                      out)
        self.assertNotIn("`ssh-password-auth`", out[:out.index("## Hosts")])             # accepted on web1
        self.assertIn("- web1: `ssh-password-auth` (medium), `listen-redis` (medium)", out)
        self.assertIn("- web1: in security_audit_accept but not found any more (remove them?): `gone-key`", out)
        self.assertIn("· `sudo-nopasswd-ansible`", out)
        self.assertIn("## Not checked\n\n- lab1: unreachable: timed out", out)
        self.assertIn("| db1 | home | Rocky Linux 9.6 (Blue Onyx) | no | without-password | yes | yes | 1 | – |", out)
        self.assertIn("## Still to check by hand", out)
        db = json.loads(self.db.read_text())["hosts"]
        f = {x["key"]: x for x in db["web1"]["findings"]}
        self.assertTrue(f["ssh-password-auth"]["accepted"])
        self.assertNotIn("accepted", f["ssh-root-login"])
        self.assertNotIn("findings", db["lab1"])
        self.assertEqual(db["web1"]["output"], WEAK)                                    # the raw data stays
        docs = {"security.json": json.loads(self.db.read_text()), "bmc.json": {}, "routeros.json": {},
                "updates.json": {}}
        c = overview.security_counts(docs)
        self.assertEqual(c["accepted"], 2)
        warn = [w for w in overview.glance_warnings(docs, {}, {}) if w.startswith("Security")]
        self.assertEqual(warn, [f"Security audit: {c['high']} high, {c['medium']} medium"])

    def test_site_report_file(self):
        r = self.audit("--site", "lab", "--report")
        self.assertEqual(r.returncode, 0, r.stderr)
        today = dt.date.today().isoformat()
        rep = self.d / f"docs/security-audit-{today}-lab.md"
        self.assertTrue(rep.is_file())
        self.assertIn("# Security audit — lab — ", rep.read_text())
        self.assertNotIn("web1", rep.read_text())
        home = self.audit("--site", "home", "--no-write").stdout          # the default site: no site_ group
        self.assertIn("| web1 | home |", home)
        self.assertNotIn("lab1", home)
        rep.write_text("edited by hand\n")
        r = self.audit("--site", "lab", "--report")
        self.assertEqual(r.returncode, 5)
        self.assertEqual(rep.read_text(), "edited by hand\n")                           # never overwritten
        self.assertEqual(self.audit("--site", "lab", "--report", "--force").returncode, 0)
        self.assertNotEqual(rep.read_text(), "edited by hand\n")

    def test_errors(self):
        self.assertEqual(self.audit("--site", "nowhere").returncode, 3)
        self.assertEqual(self.audit("--host", "ghost").returncode, 4)
        self.db.unlink()
        r = self.audit()
        self.assertEqual(r.returncode, 4)
        self.assertIn("security-audit.yml", r.stderr)
        self.assertEqual(self.audit("--no-write", "--host", "web1").returncode, 4)
        self.assertFalse(self.db.exists())


class TemplateTests(unittest.TestCase):
    def test_playbook_reads_only(self):
        pb = (TEMPLATE / "ansible/playbooks/security-audit.yml").read_text()
        self.assertIn("check_mode: false", pb)
        self.assertIn("changed_when: false", pb)
        self.assertIn("{% raw %}", pb)                                                  # docker's {{.Name}}
        body = pb[pb.index("{% raw %}"):pb.index("{% endraw %}")]
        for word in (r"\brm\b", r"> */(?!dev/null)", r"\btee\b", r"sed -i", r"systemctl (start|stop|restart|enable)",
                     r"apt-get (install|upgrade|update|remove)", r"\bdnf (install|upgrade|remove)", r"\bchmod\b",
                     r"\buseradd\b", r"\bpasswd\s+-"):
            self.assertIsNone(re.search(word, body), word)
        self.assertNotIn("print $2", body.replace('"password|" $1', ""))               # never the hash field
        self.assertIn("security_merged", pb)
        self.assertIn("prev | combine(", pb)                                             # the Mac's checks stay

    def test_scaffolded_with_ansible(self):
        sys.path.insert(0, str(SCRIPTS))
        import init_repo
        self.assertIn("ansible/playbooks/security-audit.yml", init_repo.COMPONENTS["ansible"][2])


if __name__ == "__main__":
    unittest.main()
