"""Tests for security_audit.py and the security-audit.yml template (GitHub issue #139)."""
import datetime as dt
import io
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



class FakePVE:
    """GET answers by path (documentation names and addresses only); a missing path is a 403."""
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def _get(self, path, **params):
        import urllib.error
        self.calls.append((path, params))
        key = path + ("?" + "&".join(f"{k}={v}" for k, v in sorted(params.items())) if params else "")
        for k in (key, path):
            if k in self.answers:
                return self.answers[k]
        raise urllib.error.HTTPError(path, 403, "forbidden", {}, io.BytesIO(b"{}"))

    def get(self, path, **params):
        return self._get(path, **params)


PVE_ANSWERS = {
    "/version": {"version": "9.1.4"},
    "/access/permissions": {"/": {"Sys.Audit": 1, "VM.Audit": 1}},
    "/access/permissions?userid=root@pam": {"/": {"Permissions.Modify": 1, "Sys.Audit": 1}},
    "/access/permissions?userid=root@pam!pdm-admin": {"/": {"Permissions.Modify": 1}},
    "/access/permissions?userid=root@pam!mon": {"/": {"Sys.Audit": 1}},
    "/access/permissions?userid=ops@ldap": {"/": {"Permissions.Modify": 1}},
    "/access/permissions?userid=ops@ldap!ci": {"/": {"Permissions.Modify": 1}},
    "/access/permissions?userid=ops@ldap!old": {"/": {}},
    "/access/permissions?userid=homelab@pve": {"/": {"Sys.Audit": 1}},
    "/access/permissions?userid=homelab@pve!ro": {"/": {"Sys.Audit": 1}},
    "/access/permissions?userid=gone@pve": {"/": {"Permissions.Modify": 1}},
    "/access/users": [
        {"userid": "root@pam", "enable": 1, "expire": 0, "realm-type": "pam", "email": "root@example.test",
         "tokens": [{"tokenid": "pdm-admin", "privsep": 0, "expire": 0}, {"tokenid": "mon", "privsep": 1}]},
        {"userid": "ops@ldap", "enable": 1, "expire": 0, "realm-type": "ldap", "firstname": "Some", "comment": "x",
         "tokens": [{"tokenid": "ci", "privsep": 0}, {"tokenid": "old", "privsep": 1, "expire": 1000}]},
        {"userid": "homelab@pve", "realm-type": "pve", "tokens": [{"tokenid": "ro", "privsep": 1}]},
        {"userid": "gone@pve", "enable": 0, "realm-type": "pve"}],
    "/access/tfa": [{"userid": "homelab@pve", "entries": [{"type": "totp", "id": "a"}], "totp-locked": True}],
    "/access/domains": [{"realm": "pam", "type": "pam"}, {"realm": "ldap", "type": "ldap"}],
    "/access/domains/ldap": {"type": "ldap", "secure": 1},
    "/access/domains/pam": {"type": "pam"},
    "/cluster/firewall/options": {"enable": 1, "policy_in": "ACCEPT"},
    "/nodes": [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"},
               {"node": "pve3", "status": "offline"}],
    "/nodes/pve1/firewall/options": {"enable": 0},
    "/nodes/pve2/firewall/options": {},
    "/cluster/resources": [
        {"type": "lxc", "vmid": 101, "name": "web", "node": "pve1", "status": "running"},
        {"type": "lxc", "vmid": 102, "name": "db", "node": "pve1", "status": "running"},
        {"type": "lxc", "vmid": 103, "name": "safe", "node": "pve2", "status": "running"},
        {"type": "lxc", "vmid": 104, "name": "spare", "node": "pve2", "status": "stopped"},
        {"type": "lxc", "vmid": 900, "name": "tpl", "node": "pve2", "template": 1},
        {"type": "qemu", "vmid": 200, "name": "vm", "node": "pve1"},
        {"type": "qemu", "vmid": 201, "name": "win", "node": "pve1", "status": "running"},
        {"type": "qemu", "vmid": 202, "name": "fixed", "node": "pve1", "status": "running"},
        {"type": "qemu", "vmid": 203, "name": "partial", "node": "pve2", "status": "stopped"},
        {"type": "qemu", "vmid": 204, "name": "nokeys", "node": "pve2", "status": "running"},
        {"type": "qemu", "vmid": 205, "name": "legacy", "node": "pve2", "status": "running"},
        {"type": "qemu", "vmid": 901, "name": "efi-tpl", "node": "pve2", "template": 1}],
    "/nodes/pve1/qemu/200/config": {"ostype": "l26", "scsi0": "local-lvm:vm-200-disk-0"},
    "/nodes/pve1/qemu/201/config": {"ostype": "win11", "efidisk0": "local-lvm:vm-201-disk-0,efitype=4m,"
                                    "pre-enrolled-keys=1,size=4M"},
    "/nodes/pve1/qemu/202/config": {"ostype": "l26", "efidisk0": "local-lvm:vm-202-disk-0,efitype=4m,"
                                    "ms-cert=2023k,pre-enrolled-keys=1,size=4M"},
    "/nodes/pve2/qemu/203/config": {"ostype": "l26", "efidisk0": "local-lvm:vm-203-disk-0,efitype=4m,"
                                    "ms-cert=2023w,pre-enrolled-keys=1,size=4M"},
    "/nodes/pve2/qemu/204/config": {"ostype": "l26", "efidisk0": "local-lvm:vm-204-disk-0,efitype=4m,"
                                    "pre-enrolled-keys=0,size=4M"},
    "/nodes/pve2/qemu/205/config": {"ostype": "l26", "efidisk0": "local-lvm:vm-205-disk-0,size=1M"},
    "/nodes/pve2/qemu/901/config": {"ostype": "l26", "efidisk0": "local-lvm:base-901-disk-0,efitype=4m,"
                                    "pre-enrolled-keys=1,size=4M"},
    "/nodes/pve1/lxc/101/config": {"features": "nesting=1,mount=nfs;cifs", "net0": "name=eth0,ip=192.0.2.21/24",
                                   "lxc": [["lxc.apparmor.profile", "unconfined"], ["lxc.cap.drop", ""],
                                           ["lxc.mount.entry", "/dev/x dev/x none bind"]]},
    "/nodes/pve1/lxc/102/config": {"net0": "name=eth0,ip=dhcp"},
    "/nodes/pve2/lxc/103/config": {"unprivileged": 1, "features": "nesting=1", "net0": "name=eth0,ip=192.0.2.23/24"},
    "/nodes/pve2/lxc/104/config": {"net0": "name=eth0,ip=192.0.2.21/24"},
}


class ProxmoxTests(unittest.TestCase):
    def collect(self, **change):
        return sa.pve_collect(FakePVE({**PVE_ANSWERS, **change}))

    def test_collect(self):
        fake = FakePVE(PVE_ANSWERS)
        d = sa.pve_collect(fake)
        self.assertTrue(all(c[0].startswith("/") for c in fake.calls))
        text = json.dumps(d)
        for private in ("example.test", "Some", "comment"):
            self.assertNotIn(private, text)                                  # never e-mail, names or comments
        users = {u["userid"]: u for u in d["users"]}
        self.assertTrue(users["root@pam"]["admin"] and users["ops@ldap"]["admin"])
        self.assertFalse(users["homelab@pve"]["admin"])
        self.assertEqual([(t["id"], t["privsep"], t["admin"]) for t in users["root@pam"]["tokens"]],
                         [("pdm-admin", False, True), ("mon", True, False)])
        self.assertEqual(d["tfa"], {"homelab@pve": {"types": ["totp"], "locked": True}})
        self.assertEqual(d["realms"]["ldap"], {"type": "ldap", "tfa": None})
        self.assertEqual(d["firewall"], {"enable": True, "policy_in": "ACCEPT"})
        self.assertEqual(d["nodes"], {"pve1": {"firewall": False}, "pve2": {"firewall": True}})
        lxc = {c["vmid"]: c for c in d["lxc"]}
        self.assertEqual(sorted(lxc), [101, 102, 103, 104])                 # no template, no VM
        self.assertEqual(lxc[101]["ips"], ["192.0.2.21"])
        self.assertEqual(lxc[102]["ips"], [])                                # dhcp
        self.assertTrue(lxc[103]["unprivileged"])
        efi = {v["vmid"]: v for v in d["efi"]}
        self.assertEqual(sorted(efi), [201, 202, 203, 204, 205, 901])        # 200 has no EFI disk
        self.assertEqual((efi[201]["pre_enrolled"], efi[201]["ms_cert"], efi[201]["windows"]), (True, None, True))
        self.assertEqual((efi[203]["ms_cert"], efi[203]["windows"]), ("2023w", False))
        self.assertFalse(efi[204]["pre_enrolled"])
        self.assertTrue(efi[901]["template"])
        self.assertNotIn("vm-201-disk-0", text)                              # volume names are not kept
        self.assertNotIn("unread", d)
        no_audit = self.collect(**{"/access/permissions": {"/vms": {"VM.Audit": 1}}})
        self.assertIsNone(no_audit["tfa"])                                   # [] would mean "nobody", not "unknown"
        self.assertIn("second factors", no_audit["unread"])
        gone = {k: v for k, v in PVE_ANSWERS.items() if k != "/cluster/firewall/options"}
        d = sa.pve_collect(FakePVE(gone))
        self.assertIsNone(d["firewall"])
        self.assertEqual(d["unread"]["firewall"], "HTTP 403")

    def test_findings(self):
        d = self.collect()
        f = {k: (s, w) for k, s, _, w in sa.pve_findings(d, now=2000)}
        self.assertEqual(f["pve-no-tfa-root-pam"], ("medium", "Proxmox"))
        self.assertEqual(f["pve-no-tfa-ops-ldap"], ("medium", "Proxmox"))
        self.assertNotIn("pve-no-tfa-homelab-pve", f)                        # has TOTP, and no admin
        self.assertNotIn("pve-no-tfa-gone-pve", f)                           # disabled
        self.assertEqual(f["pve-tfa-locked-homelab-pve"][0], "info")
        self.assertEqual(f["pve-root-token-pdm-admin"][0], "medium")
        self.assertEqual(f["pve-root-token-mon"][0], "low")
        self.assertEqual(f["pve-token-privsep-ops-ldap-ci"][0], "low")
        self.assertEqual(f["pve-token-expired-ops-ldap-old"][0], "info")
        self.assertNotIn("pve-token-privsep-homelab-pve-ro", f)
        self.assertEqual(f["pve-firewall-accept-in"][0], "info")
        self.assertEqual(f["pve-node-firewall-off-pve1"], ("low", "pve1"))
        self.assertNotIn("pve-firewall-off", f)
        self.assertEqual(f["lxc-privileged-101"], ("medium", "web"))
        self.assertEqual(f["lxc-privileged-102"], ("low", "db"))
        self.assertNotIn("lxc-privileged-103", f)                            # unprivileged
        text = {k: t for k, _, t, _ in sa.pve_findings(d, now=2000)}
        self.assertIn("`nesting=1`, `mount=nfs;cifs`, `lxc.apparmor.profile: unconfined`, `lxc.cap.drop: (empty)`",
                      text["lxc-privileged-101"])
        self.assertNotIn("lxc.mount.entry", text["lxc-privileged-101"])
        # Secure Boot EFI disks without the Microsoft 2023 certificates (GitHub issue #145)
        self.assertEqual(f["pve-efi-ms-cert-201"], ("medium", "win"))
        self.assertEqual(f["pve-efi-ms-cert-203"], ("low", "partial"))      # stopped
        self.assertEqual(f["pve-efi-ms-cert-901"], ("low", "efi-tpl"))      # template
        for vmid in (200, 202, 204, 205):                                    # none, 2023k, no keys, legacy 2 MB
            self.assertNotIn(f"pve-efi-ms-cert-{vmid}", f)
        self.assertIn("qm enroll-efi-keys 201", text["pve-efi-ms-cert-201"])
        self.assertIn("BitLocker", text["pve-efi-ms-cert-201"])
        self.assertIn("2011", text["pve-efi-ms-cert-201"])
        self.assertIn("partly enrolled (`ms-cert=2023w`)", text["pve-efi-ms-cert-203"])
        self.assertNotIn("BitLocker", text["pve-efi-ms-cert-203"])
        self.assertIn("each clone", text["pve-efi-ms-cert-901"])
        self.assertNotIn("Proxmox VE 9", text["pve-efi-ms-cert-201"])
        old = {k: t for k, _, t, _ in sa.pve_findings(dict(d, version="8.4.1"), now=2000)}
        self.assertIn("needs Proxmox VE 9", old["pve-efi-ms-cert-201"])
        self.assertFalse(any(k.startswith("pve-efi") for k, *_ in sa.pve_findings(dict(d, efi=None), now=2000)))
        exposed = {"192.0.2.21": ["r1 tcp 443"]}
        f = {k: s for k, s, _, _ in sa.pve_findings(d, exposed, verify_tls=False, now=2000)}
        self.assertEqual(f["lxc-privileged-101"], "high")                    # weakened and forwarded
        self.assertEqual(f["lxc-privileged-104"], "low")                     # same address, but stopped
        self.assertEqual(f["pve-tls-verify-off"], "low")
        off = dict(d, firewall={"enable": False, "policy_in": "DROP"}, tfa=None)
        f = {k: s for k, s, _, _ in sa.pve_findings(off, now=2000)}
        self.assertEqual(f["pve-firewall-off"], "low")
        self.assertNotIn("pve-node-firewall-off-pve1", f)                    # the datacenter's is off anyway
        self.assertEqual(f["pve-tfa-unreadable"], "info")
        self.assertFalse(any(k.startswith("pve-no-tfa") for k in f))


ROUTEROS = {"devices": {"192.0.2.1": {"identity": {"name": "r1"}, "collected_at": "2026-11-21T07:00:00", "nat": [
    {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "3390", "to-addresses": "192.0.2.5",
     "to-ports": "3389", "_flags": ""},
    {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "443,8443", "to-addresses": "192.0.2.21",
     "src-address-list": "!TRUSTED", "_flags": ""},
    {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "22", "to-addresses": "192.0.2.6",
     "src-address-list": "TRUSTED", "_flags": ""},
    {"chain": "dstnat", "action": "dst-nat", "to-addresses": "192.0.2.53", "connection-mark": "dns", "_flags": ""},
    {"chain": "dstnat", "action": "dst-nat", "to-addresses": "192.0.2.99", "_flags": ""},
    {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "139,445", "to-addresses": "192.0.2.7",
     "_flags": ""},
    {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "80", "to-addresses": "192.0.2.8",
     "_flags": "X"}],
    "findings": [{"key": "plaintext-www", "severity": "medium", "text": "plain-text service `www`"},
                 {"key": "ssh-any-address", "severity": "low", "text": "ssh", "accepted": True},
                 {"key": "x", "severity": "info", "text": "info only"}]}}}


class JoinTests(unittest.TestCase):
    def cfg(self):
        return {"_root": "/nonexistent", "sites": [{"name": "home", "ranges": ["192.0.2.0/24"]},
                                                   {"name": "lab", "ranges": ["198.51.100.0/24"]}]}

    def test_forwards(self):
        fwds = sa.port_forwards(self.cfg(), ROUTEROS["devices"])
        self.assertEqual([(x["to"], x["any_source"]) for x in fwds],
                         [("192.0.2.5", True), ("192.0.2.21", True), ("192.0.2.6", False), ("192.0.2.53", False),
                          ("192.0.2.99", True), ("192.0.2.7", True)])                # the disabled one is gone
        self.assertEqual(fwds[0]["ports"], {3389})                                  # the target's port (to-ports)
        self.assertEqual({x["site"] for x in fwds}, {"home"})
        f = {k: (s, w) for k, s, _, w in sa.forward_findings(fwds, {"192.0.2.5": "term1"})}
        self.assertEqual(f, {"forward-rdp-term1": ("high", "term1"), "forward-all-192.0.2.99": ("high", "192.0.2.99"),
                             "forward-smb-192.0.2.7": ("high", "192.0.2.7")})        # 139 and 445: one finding
        self.assertEqual(sa.exposure(fwds)["home"]["192.0.2.21"], ["r1 tcp 443,8443"])
        self.assertNotIn("192.0.2.6", sa.exposure(fwds)["home"])

    def test_network_and_updates(self):
        net = {"hosts": {"192.0.2.30": {"last_seen": "2026-11-20T10:00:00", "ports": [
            {"port": 23, "proto": "tcp"}, {"port": 111, "proto": "tcp"}, {"port": 11211, "proto": "tcp"}]},
            "192.0.2.5": {"ports": [{"port": 6379, "proto": "tcp"}]}}}
        f = {k: s for k, s, _, _ in sa.network_findings(net, {"192.0.2.5"}, {"192.0.2.30": "cam1"})}
        self.assertEqual(f, {"net-telnet-cam1": "high", "net-memcached-cam1": "medium"})   # no rpcbind, no audited host
        u = {"security": 3, "reboot_required": True, "reboot_reasons": ["linux-image"], "collected_at": "2026-11-20"}
        self.assertEqual({k: s for k, s, _ in sa.update_findings(u)},
                         {"security-updates": "low", "reboot-required": "info"})
        self.assertEqual(sa.update_findings(u, ["r1 tcp 443"])[0][1], "medium")
        self.assertEqual(sa.update_findings({"security": 0}), [])
        self.assertEqual(sa.update_findings({"error": "unreachable", "security": 3}), [])

    def test_site_accepts(self):
        import hmlib
        cfg = self.cfg()
        self.assertEqual(sa.site_accepts(cfg), {})
        cfg["security_audit"] = {"accept": ["Pve-Firewall-Off"]}
        self.assertEqual(sa.site_accepts(cfg), {"*": {"pve-firewall-off"}})
        cfg["security_audit"] = {"accept": {"lab": ["lxc-privileged-5"]}}
        self.assertEqual(sa.site_accepts(cfg), {"lab": {"lxc-privileged-5"}})
        cfg["security_audit"] = {"accept": {"nowhere": ["x"]}}
        with self.assertRaises(hmlib.ConfigError):
            sa.site_accepts(cfg)
        found = sa.as_dicts([("a", "low", "t", "web"), ("b", "low", "t", "Proxmox"), ("c", "low", "t")],
                            {"b"}, {"web": {"a"}})
        self.assertEqual([x.get("accepted") for x in found], [True, True, None])

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

    def test_proxmox_joins_and_history(self):
        db = json.loads(self.db.read_text())
        db["proxmox"] = {"home": {**sa.pve_collect(FakePVE(PVE_ANSWERS)), "collected_at": "2026-11-21T07:00:00+00:00"}}
        self.db.write_text(json.dumps(db))
        disc = self.d / "discovery"
        (disc / "routeros.json").write_text(json.dumps(ROUTEROS))
        (disc / "updates.json").write_text(json.dumps({"collected_at": "2026-11-21T07:00:00", "hosts": {
            "web1": {"security": 2, "collected_at": "2026-11-21T07:00:00"}, "db1": {"security": 1}}}))
        (disc / "network.json").write_text(json.dumps({"sites": {"home": {"updated_at": "2026-11-20T10:00:00", "hosts": {
            "192.0.2.30": {"last_seen": "2026-11-20T10:00:00", "ports": [{"port": 23, "proto": "tcp"}]},
            "192.0.2.5": {"ports": [{"port": 2375, "proto": "tcp"}]}}}}}))
        subprocess.run(["yq", "-i", '.security_audit.accept.home = ["pve-root-token-pdm-admin", "stale-site-key"]',
                        "homelab.yaml"], cwd=self.d, check=True)
        r = self.audit("--no-proxmox", "--report")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn("Proxmox at home (read-only token)", out)
        self.assertIn("| home | 9.1.4 | 3 (2 admin, 0 of them with TFA) |", out)              # one disabled
        self.assertIn("forwards tcp 3390 from any address to web1 (192.0.2.5) port 3389 (rdp)", out)
        self.assertIn("- 2 security updates pending (check-updates.yml, 2026-11-21): patch it (patch-linux.yml); a "
                      "port forward reaches it from any address (r1 tcp 3390) — web1 · `security-updates`", out)
        self.assertIn("1 security update pending (check-updates.yml, 2026-11-21): patch it (patch-linux.yml) "
                      "— db1 · `security-updates`", out)                         # low: not forwarded
        self.assertIn("— 192.0.2.30 · `net-telnet-192.0.2.30`", out)
        self.assertNotIn("net-docker-api", out)                                      # web1 is audited by the playbook
        self.assertIn("## Routers", out)
        self.assertIn("— r1 · `plaintext-www`", out)
        self.assertNotIn("ssh-any-address", out)                                     # accepted on the router
        self.assertIn("- site home: `pve-root-token-pdm-admin` (medium)", out)
        self.assertIn("in security_audit.accept but not found any more (remove them?): `stale-site-key`", out)
        self.assertIn("— Proxmox · `pve-no-tfa-root-pam`", out.replace("Proxmox home", "Proxmox"))
        saved = json.loads(self.db.read_text())
        self.assertEqual(saved["proxmox"]["home"]["version"], "9.1.4")              # the collected data stays
        site = {x["key"]: x for x in saved["sites"]["home"]["findings"]}
        self.assertEqual(site["forward-rdp-web1"]["where"], "web1")
        record = saved["audits"]["all"]["findings"]
        self.assertIn("web1 · forward-rdp-web1", record)
        self.assertIn("Proxmox home · pve-no-tfa-root-pam", record)
        self.assertIn("r1 · plaintext-www", record)
        self.assertNotIn("Proxmox home · pve-root-token-pdm-admin", record)         # accepted
        docs = {"security.json": saved, "bmc.json": {}, "routeros.json": {}, "updates.json": {}}
        c = overview.security_counts(docs)
        self.assertEqual(c["accepted"], 3)                                           # two on web1, one at the site
        self.assertGreaterEqual(c["medium"], len([x for x in record if "pve-no-tfa" in x]))
        ros = json.loads(json.dumps(ROUTEROS))
        ros["devices"]["192.0.2.1"]["nat"].pop(0)                                    # the RDP forward is closed
        (disc / "routeros.json").write_text(json.dumps(ros))
        db = json.loads(self.db.read_text())
        db["hosts"]["web1"]["output"] = WEAK + ["@@listen", "tcp LISTEN 0 1 0.0.0.0:23 0.0.0.0:*"]
        self.db.write_text(json.dumps(db))
        out = self.audit("--no-proxmox", "--report", "--force").stdout
        today = dt.date.today().isoformat()
        since = out[out.index(f"## Since the audit of {today}"):out.index("## High")]
        self.assertIn("- New: web1 · listen-telnet", since)
        self.assertIn("web1 · forward-rdp-web1", since.split("Gone")[1])
        self.assertNotIn("Since the audit", self.audit("--no-proxmox", "--site", "lab", "--no-write").stdout)

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
