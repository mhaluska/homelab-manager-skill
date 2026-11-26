"""Tests for zabbix_api.py audit (zbx_audit.py) and its findings in security_audit.py (GitHub issue #173)."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "homelab-manager" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import overview  # noqa: E402
import security_audit as sa  # noqa: E402
import zbx_audit  # noqa: E402
import zbxlib  # noqa: E402

NOW = 1_800_000_000.0
DAY = 86400


class FakeClient(zbxlib.Client):
    """A client whose answers come from {method: result or callable(params)}; never touches the network."""

    def __init__(self, answers: dict, role: str = "ro"):
        super().__init__("https://zabbix.example.test", "token", role)
        self.answers = answers

    def call(self, method, params=None):
        if self.role == "ro" and not zbxlib.is_read(method):
            raise zbxlib.ZabbixError(f"{method} is a write: the read-only token never calls it")
        self.calls.append(method)
        if method not in self.answers:
            raise zbxlib.ZabbixError("No permissions", data="No permissions to call " + method)
        a = self.answers[method]
        return a(params or {}) if callable(a) else a


def zhost(hostid, name, group, tls="1", available="1"):
    return {"hostid": hostid, "host": name, "name": name, "status": "0", "tls_connect": tls, "tls_accept": tls,
            "hostgroups": [{"name": group}], "interfaces": [{"type": "1", "available": available}]}


ZHOSTS = [zhost("101", "web1", "Home"), zhost("102", "db1", "Home", tls="2"), zhost("103", "nas1", "Stock")]
HEALTH = {"zabbix[queue]": "40", "zabbix[queue,10m]": "150", "zabbix[wcache,history,pused]": "80",
          "zabbix[rcache,buffer,pused]": "95", "zabbix[process,poller,avg,busy]": "76.5",
          "zabbix[process,trapper,avg,busy]": "3"}


def item_get(p):
    keys = (p.get("filter") or {}).get("key_")
    if keys == "agent.version":
        return [{"hostid": "101", "lastvalue": "8.2.1"}, {"hostid": "102", "lastvalue": "7.0.5"}]
    if keys == ["zabbix[queue]", "zabbix[queue,10m]"]:
        assert p.get("templated") is False      # template items have no data
        return [{"hostid": "10047", "lastclock": "0"}, {"hostid": "10084", "lastclock": str(int(NOW))}]
    assert p["hostids"] == ["10084"]
    return [{"key_": k, "lastvalue": v, "lastclock": str(int(NOW)), "state": "0"} for k, v in HEALTH.items()]


RO = {"apiinfo.version": "8.0.3",
      "host.get": lambda p: [{"host": "Zabbix server"}] if p.get("hostids") else ZHOSTS,
      "item.get": item_get,
      "proxy.get": [{"name": "edge", "operating_mode": "0", "tls_connect": "1", "tls_accept": "1",
                     "lastaccess": str(int(NOW - 3600)), "version": "7.0.1", "compatibility": "2"}]}
ADMIN = {"user.get": [{"userid": "1", "username": "Admin", "role": {"type": "3"},
                       "usrgrps": [{"name": "Zabbix administrators", "users_status": "0", "gui_access": "0"}]},
                      {"userid": "2", "username": "guest", "role": {"type": "1"},
                       "usrgrps": [{"name": "Guests", "users_status": "0", "gui_access": "0"}]},
                      {"userid": "3", "username": "ops", "role": {"type": "3"}, "usrgrps": []}],
         "authentication.get": {"mfa_status": "0"},
         "usergroup.get": [],
         "token.get": [{"name": "old", "userid": "3", "status": "0", "lastaccess": str(int(NOW - 200 * DAY)),
                        "created_at": "1", "expires_at": "0"},
                       {"name": "fresh", "userid": "3", "status": "0", "lastaccess": str(int(NOW - DAY)),
                        "created_at": "1", "expires_at": str(int(NOW + 30 * DAY))},
                       {"name": "off", "userid": "1", "status": "1", "lastaccess": "0", "created_at": "1",
                        "expires_at": "0"}]}
CFG = {"zabbix": {"url": "https://zabbix.example.test", "host_match": [{"pattern": "{short}"}],
                  "managed_scope": {"host_groups": ["Home"]}}}
INV = {"web1": {"groups": ["linux"]}, "db1": {"groups": ["linux"]}, "nas1": {"groups": ["linux"]}}


def fake_tls(url, ctx):
    return {"scheme": "https", "verified": True, "cert_days": 10}


def keys(found):
    return {k: s for k, s, *_ in found}


class CollectTests(unittest.TestCase):
    def test_collect_with_admin(self):
        ro, adm = FakeClient(RO), FakeClient(ADMIN)
        d = zbx_audit.collect(ro, CFG, INV, adm, now=NOW, tls=fake_tls)
        self.assertEqual((d["version"], d["line"], d["lts"], d["supported"]), ("8.0.3", "8.0", True, True))
        self.assertEqual([h["name"] for h in d["hosts"]], ["db1", "web1"])          # nas1: not in the scope
        web = next(h for h in d["hosts"] if h["name"] == "web1")
        self.assertEqual((web["agent_version"], web["tls_connect"], web["agent"]), ("8.2.1", "1", "available"))
        self.assertEqual(d["health"]["host"], "Zabbix server")
        self.assertEqual(d["health"]["items"]["queue_10m"], 150.0)
        self.assertIn("trend_cache_pused", d["health"]["missing"])
        self.assertEqual(d["admin"]["admin_user"], {"exists": True, "enabled": True})
        self.assertTrue(d["admin"]["guest"]["enabled"])
        self.assertEqual(d["admin"]["super_admins"], ["Admin", "ops"])
        self.assertEqual(d["admin"]["mfa"]["configured"], False)
        self.assertEqual(d["not_checked"], [])
        for c in (ro, adm):                                    # reads only
            self.assertTrue(all(zbxlib.is_read(m) for m in c.calls), c.calls)
        json.dumps(d)                                          # it goes into a JSON file

    def test_without_admin_or_health(self):
        ro = dict(RO, **{"item.get": lambda p: [] if (p.get("filter") or {}).get("type") else item_get(p)})
        d = zbx_audit.collect(FakeClient(ro), CFG, INV, None, now=NOW, tls=fake_tls)
        self.assertNotIn("admin", d)
        self.assertFalse(d["health"]["visible"])
        self.assertEqual(len(d["not_checked"]), 2)
        self.assertIn("admin token", d["not_checked"][1])

    def test_admin_read_denied(self):
        d = zbx_audit.collect(FakeClient(RO), CFG, INV, FakeClient({}), now=NOW, tls=fake_tls)
        self.assertIn("user.get", d["admin"]["error"])
        self.assertNotIn("zabbix-no-mfa", keys(sa.zabbix_findings(d, now=NOW)))

    def test_read_only_client_refuses_writes(self):
        cfg = dict(CFG, secrets={})
        self.assertIsNone(zbx_audit.read_only_client(cfg, "admin", env={}))
        c = zbx_audit.read_only_client(cfg, "admin", env={"ZABBIX_ADMIN_TOKEN": "t"})
        self.assertEqual(c.role, "ro")                         # the admin token, but only for reads
        with self.assertRaises(zbxlib.ZabbixError):
            c.call("user.update", {"userid": "1"})
        self.assertEqual(c.calls, [])                          # refused before anything is sent

    def test_frontend_plain_http(self):
        self.assertEqual(zbx_audit.frontend_tls("http://zabbix.example.test/api_jsonrpc.php", None),
                         {"scheme": "http"})


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.d = zbx_audit.collect(FakeClient(RO), CFG, INV, FakeClient(ADMIN), now=NOW, tls=fake_tls)

    def test_findings(self):
        found = sa.zabbix_findings(self.d, now=NOW)
        k = keys(found)
        self.assertEqual(k["zabbix-cert-expiring"], "medium")
        self.assertEqual(k["zabbix-agent-unencrypted"], "low")
        self.assertEqual([f[3] for f in found if f[0] == "zabbix-agent-unencrypted"], ["web1"])   # db1 has PSK
        self.assertEqual([f[3] for f in found if f[0] == "zabbix-agent-newer-than-server"], ["web1"])
        self.assertEqual(k["zabbix-proxy-unencrypted-edge"], "low")
        self.assertEqual(k["zabbix-proxy-silent-edge"], "medium")
        self.assertEqual(k["zabbix-proxy-version-edge"], "low")
        self.assertEqual(k["zabbix-health-queue"], "medium")
        self.assertEqual(k["zabbix-health-history-cache"], "low")
        self.assertEqual(k["zabbix-health-config-cache"], "medium")
        self.assertEqual(k["zabbix-health-poller-busy"], "low")
        self.assertNotIn("zabbix-health-trapper-busy", k)
        self.assertEqual(k["zabbix-admin-user-enabled"], "low")
        self.assertEqual(k["zabbix-guest-access"], "medium")
        self.assertEqual(k["zabbix-no-mfa"], "low")
        text = {f[0]: f[2] for f in found}
        self.assertIn("old (ops)", text["zabbix-tokens-unused"])
        self.assertNotIn("fresh", text["zabbix-tokens-unused"])
        self.assertNotIn("off", text["zabbix-tokens-no-expiry"])           # disabled tokens don't count
        self.assertIn("never tries a password", text["zabbix-admin-user-enabled"])
        self.assertNotIn("zabbix-standard-release", k)

    def test_versions_and_frontend(self):
        k = keys(sa.zabbix_findings({"version": "7.4.2", "line": "7.4", "supported": True, "lts": False,
                                     "frontend": {"scheme": "http"}}))
        self.assertEqual(k, {"zabbix-standard-release": "info", "zabbix-frontend-http": "medium"})
        k = keys(sa.zabbix_findings({"version": "6.0.30", "supported": False,
                                     "frontend": {"scheme": "https", "verified": False, "cert_days": 20}}))
        self.assertEqual(k, {"zabbix-unsupported-version": "medium", "zabbix-tls-not-verified": "low",
                             "zabbix-cert-expiring": "low"})
        k = keys(sa.zabbix_findings({"version": "8.0.0", "frontend": {"scheme": "https", "cert_error": "expired"},
                                     "health": {"items": {"queue_10m": 3}},
                                     "hosts": [{"name": "old1", "enabled": True, "agent": "available",
                                                "tls_connect": "2", "tls_accept": "2", "agent_version": "5.0.1"},
                                               {"name": "off1", "enabled": False, "agent_version": "9.0"}]}))
        self.assertEqual(k, {"zabbix-cert-invalid": "medium", "zabbix-agent-old": "low"})   # a short queue is normal


AGENT_WIDE = """agent|agent2|active
key|agent2|Server=192.0.2.10,0.0.0.0/0
key|agent2|ServerActive=192.0.2.10
key|agent2|DenyKey=system.run[rm *]
key|agent2|AllowKey=system.run[*]
key|agent2|AllowRoot=1
userparams|agent2|3""".splitlines()

AGENT_SAFE = """agent|agentd|active
key|agentd|Server=192.0.2.10,198.51.100.0/24
key|agentd|DenyKey=system.run[*]
key|agentd|AllowKey=system.run[*]
key|agentd|TLSAccept=psk
key|agentd|TLSConnect=psk
userparams|agentd|0""".splitlines()


class AgentConfigTests(unittest.TestCase):
    def test_parse(self):
        za = sa.parse_zabbix_agent(AGENT_WIDE + ["junk", "key|other|Server=x"])
        ag = za["agents"]["Agent 2"]
        self.assertEqual(list(za["agents"]), ["Agent 2"])
        self.assertEqual(ag["server"], ["192.0.2.10", "0.0.0.0/0"])
        self.assertEqual(ag["rules"], [("deny", "system.run[rm *]"), ("allow", "system.run[*]")])
        self.assertEqual((ag["allow_root"], ag["user_parameters"], ag["state"]), ("1", 3, "active"))

    def test_wide_system_run(self):
        k = keys(sa.zabbix_agent_findings(sa.parse_zabbix_agent(AGENT_WIDE)))
        self.assertEqual(k, {"zabbix-agent-system-run": "high", "zabbix-agent-server-wide": "medium",
                             "zabbix-agent-allow-root": "medium", "zabbix-agent-no-tls": "info"})

    def test_deny_first_and_tls(self):
        self.assertEqual(sa.zabbix_agent_findings(sa.parse_zabbix_agent(AGENT_SAFE)), [])   # /24 isn't wide

    def test_remote_commands_narrow_server(self):
        lines = ["key|agentd|Server=192.0.2.10", "key|agentd|AllowKey=system.run[*]", "key|agentd|EnableRemoteCommands=1",
                 "key|agentd|TLSAccept=unencrypted,psk"]
        k = keys(sa.zabbix_agent_findings(sa.parse_zabbix_agent(lines)))
        self.assertEqual(k, {"zabbix-agent-system-run": "medium", "zabbix-agent-remote-commands": "medium"})
        self.assertEqual(sa.zabbix_agent_findings(None), [])
        self.assertEqual(sa.zabbix_agent_findings({"agents": {}}), [])

    def test_wide(self):
        self.assertTrue(sa._wide("0.0.0.0/0"))
        self.assertTrue(sa._wide("::/0"))
        self.assertTrue(sa._wide("10.0.0.0/8"))
        self.assertFalse(sa._wide("192.0.2.0/24"))
        self.assertFalse(sa._wide("192.0.2.10"))
        self.assertFalse(sa._wide("zabbix.example.test"))


HOST_OUT = """@@os
name|Debian GNU/Linux 13 (trixie)
@@sshd
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin no
@@zabbix-agent
""".splitlines() + AGENT_WIDE + ["@@end"]


class SecurityAuditTests(unittest.TestCase):
    """security_audit.py reads discovery/zabbix-audit.json, honours both accept lists and writes the findings."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        r = subprocess.run([sys.executable, str(SCRIPTS / "init_repo.py"), str(self.d), "--components", "ansible"],
                           cwd=self.d, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        inv = self.d / "ansible/inventory/managed"
        (inv / "hosts.yml").write_text("all:\n  children:\n    linux:\n      hosts:\n        web1:\n"
                                       "          ansible_host: 192.0.2.5\n        db1:\n"
                                       "          ansible_host: 192.0.2.6\n")
        (inv / "host_vars").mkdir()
        (inv / "host_vars/db1.yml").write_text("security_audit_accept: [zabbix-agent-unencrypted]\n")
        disc = self.d / "discovery"
        disc.mkdir(exist_ok=True)
        (disc / "security.json").write_text(json.dumps({"hosts": {"web1": {
            "output": HOST_OUT, "collected_at": "2026-11-21T07:00:00+00:00", "site": None}}}))
        data = zbx_audit.collect(FakeClient(RO), CFG, INV, FakeClient(ADMIN), now=NOW, tls=fake_tls)
        for h in data["hosts"]:
            h["tls_connect"] = h["tls_accept"] = "1"
        (disc / "zabbix-audit.json").write_text(json.dumps(data))
        subprocess.run(["yq", "-i", '.zabbix.url = "https://zabbix.example.test" | '
                        '.security_audit.zabbix_accept = ["zabbix-no-mfa", "zabbix-gone"]', "homelab.yaml"],
                       cwd=self.d, check=True)

    def audit(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "security_audit.py"), "--no-mac", "--no-proxmox", *args],
                              cwd=self.d, capture_output=True, text=True)

    def test_report_accepts_and_counts(self):
        r = self.audit()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        body = out[:out.index("## Hosts")] if "## Hosts" in out else out
        self.assertIn("Zabbix 8.0.3 (`zabbix-audit.json`, ", out)
        self.assertIn("· `zabbix-agent-system-run`", body)                          # from the playbook
        self.assertIn("— web1 · `zabbix-agent-unencrypted`", body)                   # db1 accepted it
        self.assertIn("— Zabbix · `zabbix-guest-access`", body)
        self.assertNotIn("· `zabbix-no-mfa`", body[:body.index("## Accepted")] if "## Accepted" in body else body)
        self.assertIn("- Zabbix: `zabbix-no-mfa` (low)", out)
        self.assertIn("not found any more (remove them?): `zabbix-gone`", out)
        self.assertIn("- db1 (Zabbix): `zabbix-agent-unencrypted` (low)", out)
        self.assertNotIn("db1: in security_audit_accept but not found any more", out)
        db = json.loads((self.d / "discovery/security.json").read_text())
        server = db["zabbix"]["server"]
        self.assertEqual(server["version"], "8.0.3")
        f = {(x["key"], x.get("where")): x for x in server["findings"]}
        self.assertTrue(f[("zabbix-no-mfa", "Zabbix")]["accepted"])
        self.assertTrue(f[("zabbix-agent-unencrypted", "db1")]["accepted"])
        self.assertNotIn("accepted", f[("zabbix-agent-unencrypted", "web1")])
        self.assertNotIn("stale", server)
        docs = {"security.json": db, "bmc.json": {}, "routeros.json": {}, "updates.json": {}}
        c = overview.security_counts(docs)
        self.assertEqual(c["accepted"], 2)
        self.assertGreaterEqual(c["medium"], 4)          # guest, proxy silent, queue, config cache …
        self.assertEqual(c["high"], 1)                   # web1's wide system.run

    def test_todo_without_audit_file(self):
        (self.d / "discovery/zabbix-audit.json").unlink()
        r = self.audit("--no-write")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("zabbix_api.py audit", r.stdout)
        self.assertNotIn("Zabbix 8.0", r.stdout)


if __name__ == "__main__":
    unittest.main()
