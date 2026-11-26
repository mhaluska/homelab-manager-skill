"""Zabbix: client safety, host matching, the managed scope, plan/apply (GitHub issues #168–#174).

    python3 -m unittest tests.test_zabbix -v
"""
import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import SCRIPTS  # noqa: E402

sys.path.insert(0, str(SCRIPTS))
import hmlib  # noqa: E402
import zbxlib  # noqa: E402
import zbx_sync  # noqa: E402
import zbx_ops  # noqa: E402
import zabbix_api  # noqa: E402


class FakeZabbix(zbxlib.Client):
    """An in-memory Zabbix 8.0 for the methods the scripts call. Writes are recorded in .writes."""

    def __init__(self, data=None, role="ro", version="8.0.0"):
        super().__init__("https://zabbix.test", "token", role)
        self.data = copy.deepcopy(data or base_data())
        self.writes = []
        self._ver = version
        self._next = 90000

    def nid(self):
        self._next += 1
        return str(self._next)

    def call(self, method, params=None):
        if self.role == "ro" and not zbxlib.is_read(method):
            raise zbxlib.ZabbixError(f"{method} is a write: the read-only token never calls it")
        self.calls.append(method)
        d = self.data
        if method == "apiinfo.version":
            return self._ver
        if method.endswith(".get"):
            api = method[:-4]
            if api == "usermacro" and params.get("globalmacro"):
                return d.get("globalmacro", [])
            rows = d.get(api, [])
            if params and params.get("countOutput"):
                return str(len(rows))
            if api == "host" and params.get("hostids"):
                rows = [r for r in rows if r["hostid"] in params["hostids"]]
            if api == "problem" and "hostids" in params:
                rows = [r for r in rows if set(r.get("_hostids", [])) & set(params["hostids"])]
            return copy.deepcopy(rows)
        self.writes.append((method, copy.deepcopy(params)))
        api, verb = method.split(".", 1)
        idf = {"hostgroup": "groupids", "templategroup": "groupids", "host": "hostids", "template": "templateids",
               "usermacro": "hostmacroids", "hostinterface": "interfaceids", "httptest": "httptestids",
               "item": "itemids", "trigger": "triggerids", "service": "serviceids", "sla": "slaids",
               "maintenance": "maintenanceids", "event": "eventids"}.get(api, api + "ids")
        if verb == "create":
            return {idf: [self.nid()]}
        return {idf: ["1"]}


def host(hostid, name, groups, templates=(), tags=None, ip="10.0.0.1", status="0", macros=None):
    return {"hostid": hostid, "host": name, "name": name, "status": status, "maintenance_status": "0",
            "active_available": "1", "proxyid": "0", "inventory_mode": "-1", "inventory": [],
            "hostgroups": [{"groupid": str(100 + i), "name": g} for i, g in enumerate(groups)],
            "parentTemplates": [{"templateid": str(500 + i), "host": t} for i, t in enumerate(templates)],
            "tags": [{"tag": k, "value": v} for k, v in (tags or {}).items()], "macros": macros or [],
            "interfaces": [{"interfaceid": hostid + "1", "type": "1", "main": "1", "useip": "1", "ip": ip, "dns": "",
                            "port": "10050", "available": "1"}]}


def base_data():
    return {
        "hostgroup": [{"groupid": "100", "name": "Home/KVM"}, {"groupid": "101", "name": "Linux servers"},
                      {"groupid": "102", "name": "Other/KVM"}],
        "templategroup": [{"groupid": "200", "name": "Templates/Home/OS"}, {"groupid": "201", "name": "Templates/Other"}],
        "template": [
            {"templateid": "500", "host": "Linux by Zabbix agent", "templategroups": [{"name": "Templates/Operating systems"}],
             "parentTemplates": [], "macros": [], "tags": []},
            {"templateid": "501", "host": "Home Linux", "templategroups": [{"name": "Templates/Home/OS"}],
             "parentTemplates": [{"templateid": "500", "host": "Linux by Zabbix agent"}], "macros": [],
             "tags": [{"tag": "managed-by", "value": "homelab-manager"}]},
            {"templateid": "502", "host": "Other Linux", "templategroups": [{"name": "Templates/Other"}],
             "parentTemplates": [], "macros": [], "tags": []}],
        "host": [host("10001", "web1.home.arpa", ["Home/KVM"], ["Home Linux"]),
                 host("10002", "db1.home.arpa", ["Linux servers", "Other/KVM"], ["Home Linux"], ip="10.0.0.2"),
                 host("10003", "web1.other.example", ["Other/KVM"], ["Other Linux"]),
                 host("10004", "old1.home.arpa", ["Home/KVM"], [])],
        "proxy": [], "httptest": [], "item": [], "service": [], "sla": [], "problem": [], "trigger": [],
        "maintenance": [],
    }


CFG = {"_root": "/nonexistent", "site": {"domain": "home.arpa"},
       "zabbix": {"url": "https://zabbix.test/api_jsonrpc.php",
                  "host_match": [{"pattern": "{host}.home.arpa"}],
                  "managed_scope": {"host_groups": ["Home/*"], "shared_host_groups": ["Linux servers"],
                                    "template_groups": ["Templates/Home/*"]}},
       "network": {"authorized_ranges": ["10.0.0.0/24"]},
       "secrets": {"zabbix-ro": {"service": "x", "kind": "env", "env": "ZABBIX_RO_TOKEN"},
                   "snmp": {"service": "y", "kind": "env", "env": "SNMP_COMMUNITY"}}}
INV = {"web1": {"ansible_host": "10.0.0.1", "groups": ["linux"]},
       "db1": {"ansible_host": "10.0.0.2", "groups": ["linux", "db"]},
       "new1": {"ansible_host": "10.0.0.9", "groups": ["linux"]}}


class ClientTests(unittest.TestCase):
    def test_read_only_client_refuses_writes_before_sending(self):
        c = zbxlib.Client("https://zabbix.invalid", "t", "ro")
        with self.assertRaises(zbxlib.ZabbixError) as e:
            c.call("host.update", {"hostid": "1"})
        self.assertIn("read-only", str(e.exception))
        self.assertEqual(c.calls, [])        # nothing went out
        for m in ("host.get", "apiinfo.version", "configuration.export"):
            self.assertTrue(zbxlib.is_read(m))
        for m in ("host.create", "configuration.import", "configuration.importcompare", "event.acknowledge"):
            self.assertFalse(zbxlib.is_read(m))

    def test_api_url_and_versions(self):
        self.assertEqual(zbxlib.api_url("https://z.example/"), "https://z.example/api_jsonrpc.php")
        self.assertEqual(zbxlib.api_url("https://z.example/api_jsonrpc.php"), "https://z.example/api_jsonrpc.php")
        self.assertTrue(zbxlib.supported("8.0.3"))
        self.assertTrue(zbxlib.supported("7.0.0"))
        self.assertFalse(zbxlib.supported("6.0.30"))

    def test_denied(self):
        self.assertTrue(zbxlib.ZabbixError("x", -32500, 'No permissions to call "host.update".').denied)
        self.assertFalse(zbxlib.ZabbixError("x", -32602, "No permissions to referred object").denied)

    def test_http_round_trip(self):
        """The real client against a local JSON-RPC server: Bearer header, no token for apiinfo.version."""
        import http.server
        import threading
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((body["method"], self.headers.get("Authorization")))
                res = {"jsonrpc": "2.0", "id": body["id"]}
                if body["method"] == "apiinfo.version":
                    res["result"] = "8.0.1"
                else:
                    res["error"] = {"code": -32500, "message": "Application error.",
                                    "data": 'No permissions to call "host.update".'}
                out = json.dumps(res).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = zbxlib.Client(f"http://127.0.0.1:{srv.server_port}", "secret-token", "rw")
        self.assertEqual(c.version(), "8.0.1")
        with self.assertRaises(zbxlib.ZabbixError) as e:
            c.call("host.update", {"hostid": "0"})
        self.assertTrue(e.exception.denied)
        self.assertEqual(seen, [("apiinfo.version", None), ("host.update", "Bearer secret-token")])


class MatchTests(unittest.TestCase):
    def zhosts(self):
        return base_data()["host"]

    def test_pattern_rule_and_unmatched(self):
        m = zbxlib.match_hosts(CFG["zabbix"], INV, self.zhosts())
        self.assertEqual(sorted(m.pairs), ["db1", "web1"])
        self.assertEqual(m.pairs["web1"]["host"], "web1.home.arpa")     # not web1.other.example
        self.assertEqual(m.unmatched_inventory, ["new1"])
        self.assertIn("old1.home.arpa", [z["host"] for z in m.unmatched_zabbix])

    def test_short_name_alone_never_matches(self):
        z = {"host_match": [{"interface_ip": True}]}
        hosts = self.zhosts()
        m = zbxlib.match_hosts(z, {"web1": {"ansible_host": "10.0.0.7"}}, hosts)   # IP disagrees
        self.assertEqual(m.pairs, {})

    def test_interface_rule_needs_ip_and_short_name(self):
        z = {"host_match": [{"interface_ip": True}]}
        hosts = [h for h in self.zhosts() if h["hostid"] != "10003"]
        m = zbxlib.match_hosts(z, {"web1": {"ansible_host": "10.0.0.1"}}, hosts)
        self.assertEqual(m.pairs["web1"]["hostid"], "10001")

    def test_ambiguous_is_reported_not_matched(self):
        z = {"host_match": [{"interface_ip": True}]}
        m = zbxlib.match_hosts(z, {"web1": {"ansible_host": "10.0.0.1"}}, self.zhosts())  # both web1.* on .1
        self.assertEqual(m.pairs, {})
        self.assertEqual(m.ambiguous[0]["inventory"], "web1")

    def test_override_var_and_regex_and_sites(self):
        z = {"host_match": [{"pattern": "{host}.lab.example", "sites": ["lab"]},
                            {"regex": r"^(?P<host>[a-z0-9]+)\.other\.example$"}]}
        inv = {"web1": {"groups": ["site_lab"]}, "db1": {"zabbix_host_name": "db1.home.arpa"}}
        m = zbxlib.match_hosts(z, inv, self.zhosts())
        self.assertEqual(m.pairs["web1"]["host"], "web1.other.example")   # lab rule finds nothing, regex does
        self.assertEqual(m.pairs["db1"]["host"], "db1.home.arpa")
        self.assertEqual(zbxlib.new_host_name(z, "x1", {"groups": ["site_lab"]}), "x1.lab.example")
        self.assertIsNone(zbxlib.new_host_name(z, "x1", {}))

    def test_two_inventory_hosts_claiming_one_zabbix_host(self):
        z = {"host_match": [{"regex": r"^(?P<host>web1)\.home\.arpa$"}]}
        inv = {"web1": {}, "web1b": {"zabbix_host_name": "web1.home.arpa"}}
        m = zbxlib.match_hosts(z, inv, self.zhosts())
        self.assertEqual(m.pairs, {})
        self.assertTrue(any("several" in a["why"] for a in m.ambiguous))


class ScopeTests(unittest.TestCase):
    def test_scope(self):
        s = zbxlib.Scope(CFG["zabbix"])
        self.assertTrue(s.own_group("Home"))
        self.assertTrue(s.own_group("Home/PVE/KVM"))
        self.assertFalse(s.own_group("Homer"))
        self.assertFalse(s.own_group("Linux servers"))
        self.assertTrue(s.host_group("Linux servers"))
        hosts = {h["hostid"]: h for h in base_data()["host"]}
        self.assertTrue(s.host_managed(hosts["10002"], True))     # shared group + matched
        self.assertFalse(s.host_managed(hosts["10002"], False))   # shared group, not matched
        self.assertFalse(s.host_managed(hosts["10003"], True))    # other owner's group only


class PlanTests(unittest.TestCase):
    def plan(self, conf, data=None, inv=INV, admin=False):
        c = FakeZabbix(data)
        st = zbx_sync.read_state(c, c if admin else None)
        return zbx_sync.build_plan(CFG, conf, st, inv, admin=admin), c

    def test_no_change_and_scope_errors(self):
        p, c = self.plan({"hosts": {"web1": {"groups": ["Home/KVM"], "templates": ["Home Linux"]}}})
        self.assertEqual(p.ops, [])
        self.assertEqual(p.errors, [])
        self.assertFalse(any(not zbxlib.is_read(m) for m in c.calls))   # planning only reads
        p, _ = self.plan({"hosts": {"web1": {"groups": ["Other/KVM"]}}, "host_groups": ["Other/New"]})
        self.assertTrue(any("outside managed_scope" in e for e in p.errors))
        self.assertEqual(len([e for e in p.errors if "outside" in e]), 2)

    def test_out_of_scope_groups_are_kept(self):
        p, _ = self.plan({"hosts": {"db1": {"groups": ["Home/KVM"]}}})
        upd = p.ops[0]
        self.assertEqual(upd["method"], "host.update")
        names = [g["$hostgroup"] for g in upd["params"]["groups"]]
        self.assertIn("Other/KVM", names)          # not ours: stays
        self.assertNotIn("Linux servers", names)   # ours (shared): removed as asked
        self.assertIn("Home/KVM", names)

    def test_new_host_template_unlink_tags_macros(self):
        conf = {"profiles": {"linux": {"templates": ["Home Linux"], "tags": {"os": "linux"}}},
                "hosts": {"new1": {"groups": ["Home/KVM"], "macros": {"{$A}": "1", "{$S}": {"secret": "snmp"}}},
                          "web1": {"templates": []}}}
        p, _ = self.plan(conf)
        by = {(o["target"], o["method"]): o for o in p.ops}
        create = by[("new1", "host.create")]["params"]
        self.assertEqual(create["host"], "new1.home.arpa")
        self.assertEqual(create["templates"], [{"$template": "Home Linux"}])
        self.assertIn({"tag": "managed-by", "value": "homelab-manager"}, create["tags"])
        self.assertEqual(create["interfaces"][0]["ip"], "10.0.0.9")
        macros = [o for o in p.ops if o["method"] == "usermacro.create"]
        self.assertEqual({m["params"]["macro"] for m in macros}, {"{$A}", "{$S}"})
        secret = next(m for m in macros if m["params"]["macro"] == "{$S}")
        self.assertEqual(secret["params"]["value"], {"$secret": "snmp"})   # never the value in the plan
        # the profile adds to web1's own entry: its templates stay (Home Linux), its tags get os=linux
        upd = by[("web1", "host.update")]["params"]
        self.assertNotIn("templates", upd)
        self.assertIn({"tag": "os", "value": "linux"}, upd["tags"])
        self.assertNotIn("db1", {o["target"] for o in p.ops})       # in the profile's group but not listed

    def test_unlink_clears_and_is_destructive(self):
        p, _ = self.plan({"hosts": {"web1": {"templates": ["Linux by Zabbix agent"]}}})
        op = p.ops[0]
        self.assertTrue(op["destructive"])
        self.assertEqual(op["params"]["templates_clear"], [{"$template": "Home Linux"}])
        p, _ = self.plan({"hosts": {"web1": {"templates": ["Linux by Zabbix agent"], "unlink": "keep"}}})
        self.assertNotIn("templates_clear", p.ops[0]["params"])

    def test_decommission_and_absent(self):
        p, _ = self.plan({"hosts": {"web1": {"status": "decommissioned"}}})
        op = p.ops[0]
        self.assertEqual(op["params"]["status"], "1")
        self.assertIn("decommissioned", [t["tag"] for t in op["params"]["tags"]])
        p, _ = self.plan({"hosts": {"web1": {"status": "absent"}}})
        self.assertEqual((p.ops[0]["method"], p.ops[0]["params"], p.ops[0]["destructive"]),
                         ("host.delete", ["10001"], True))

    def test_wrappers(self):
        conf = {"wrappers": {"Home DB": {"group": "Templates/Home/OS", "links": ["Linux by Zabbix agent"],
                                         "macros": {"{$X}": "5"}},
                             "Other Linux": {"group": "Templates/Home/OS"},
                             "Bad": {"group": "Templates/Other"}}}
        p, _ = self.plan(conf)
        self.assertTrue(any(o["method"] == "template.create" and o["target"] == "Home DB" for o in p.ops))
        self.assertTrue(any("not ours" in e for e in p.errors))      # Other Linux lives outside the scope
        self.assertTrue(any("Bad" in e and "template_groups" in e for e in p.errors))

    def test_web_cert_services_sla(self):
        conf = {"hosts": {"web1": {}},
                "web": [{"name": "Site", "host": "web1", "url": "https://site.example/", "tls_expiry_days": 21}],
                "services": [{"name": "Top", "children": ["Leaf"]}, {"name": "Leaf",
                                                                       "problem_tags": [{"tag": "svc", "value": "x"}]}],
                "slas": [{"name": "Core", "slo": 99.9, "service_tags": [{"tag": "svc", "value": "x"}]}]}
        p, _ = self.plan(conf)
        methods = [o["method"] for o in p.ops]
        self.assertIn("httptest.create", methods)
        self.assertEqual(methods.count("item.create"), 2)
        self.assertIn("trigger.create", methods)
        svc = [o["target"] for o in p.ops if o["method"] == "service.create"]
        self.assertEqual(svc, ["Leaf", "Top"])                      # children first
        self.assertIn("sla.create", methods)
        p, _ = self.plan({"web": [{"name": "X", "host": "db9", "url": "https://x/"}]})
        self.assertTrue(any("isn't a managed" in e for e in p.errors))

    def test_admin_objects_and_drule_scope(self):
        conf = {"global_macros": {"{$G}": "1"},
                "objects": {"drule": [{"name": "LAN", "params": {"iprange": "10.0.0.1-254"}},
                                      {"name": "Far", "params": {"iprange": "192.168.9.0/24"}}]}}
        p, _ = self.plan(conf)
        self.assertEqual(p.ops, [])
        self.assertTrue(any("--admin" in n for n in p.notes))
        p, _ = self.plan(conf, admin=True)
        self.assertTrue(all(o["admin"] for o in p.ops))
        self.assertEqual({o["target"] for o in p.ops}, {"{$G}", "LAN"})
        self.assertTrue(any("authorized_ranges" in e for e in p.errors))


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        (self.d / "zabbix").mkdir()
        self.cfg = {**CFG, "_root": str(self.d)}

    def write_conf(self, conf):
        (self.d / "zabbix" / "config.yaml").write_text(json.dumps(conf))   # JSON is YAML

    def test_resolve_and_run(self):
        conf = {"host_groups": ["Home/New"],
                "hosts": {"new1": {"groups": ["Home/New"], "templates": ["Home Linux"],
                                   "macros": {"{$S}": {"secret": "snmp"}}}}}
        self.write_conf(conf)
        c = FakeZabbix(role="rw")
        plan, st = zbx_sync.compute(self.cfg, c, None, INV, False)
        self.assertEqual(plan.errors, [])
        res = zbx_sync.Resolver(c, st, self.cfg, env={"SNMP_COMMUNITY": "s3cret"})
        for o in plan.ops:
            zbx_sync.check_ids(o, plan)
            res.created(o, c.call(o["method"], res(o["params"])))
        methods = [m for m, _ in c.writes]
        self.assertEqual(methods, ["hostgroup.create", "host.create", "usermacro.create"])
        create = c.writes[1][1]
        self.assertEqual(create["groups"], [{"groupid": "90001"}])       # the group created first
        self.assertEqual(create["templates"], [{"templateid": "501"}])
        macro = c.writes[2][1]
        self.assertEqual(macro["hostid"], "90002")
        self.assertEqual(macro["value"], "s3cret")

    def test_missing_secret_fails_before_writes(self):
        res = zbx_sync.Resolver(FakeZabbix(role="rw"), zbx_sync.read_state(FakeZabbix()), self.cfg, env={})
        with self.assertRaises(zbx_sync.PlanError):
            res({"$secret": "snmp"})

    def test_check_ids_refuses_foreign_ids(self):
        p = zbx_sync.Plan()
        p.allow("host", "10001")
        zbx_sync.check_ids({"kind": "host", "target": "x", "action": "update", "method": "host.update",
                            "params": {"hostid": "10001"}}, p)
        for op in ({"kind": "host", "target": "x", "action": "update", "method": "host.update",
                    "params": {"hostid": "10003"}},
                   {"kind": "host", "target": "x", "action": "delete", "method": "host.delete", "params": ["10003"]},
                   {"kind": "web", "target": "x", "action": "create", "method": "httptest.create",
                    "params": {"hostid": "10003"}}):
            with self.assertRaises(zbx_sync.PlanError):
                zbx_sync.check_ids(op, p)

    def test_fingerprint_detects_edits(self):
        ops = [{"kind": "host", "action": "update", "params": {"hostid": "1"}}]
        f = zbx_sync.fingerprint(ops)
        ops[0]["params"]["hostid"] = "2"
        self.assertNotEqual(f, zbx_sync.fingerprint(ops))


if __name__ == "__main__":
    unittest.main()


class OpsTests(unittest.TestCase):
    """maintenance, gate and ack (GitHub issues #169, #170): only managed hosts, windows that end by themselves."""

    def setUp(self):
        self.c = FakeZabbix(role="rw")
        self.patches = [(zbxlib, "connect", lambda cfg, role="ro", env=None: self.c),
                        (zabbix_api, "inventory", lambda root, cfg: copy.deepcopy(INV))]
        self.saved = [(m, n, getattr(m, n)) for m, n, _ in self.patches]
        for m, n, f in self.patches:
            setattr(m, n, f)

    def tearDown(self):
        for m, n, f in self.saved:
            setattr(m, n, f)

    def args(self, **kw):
        import argparse
        base = {"action": "start", "hosts": [], "guests_of": None, "hours": None, "name": None, "phase": "pre",
                "min": None, "since": None, "settle": 0, "host": None, "message": "", "commit": None, "close": False}
        return argparse.Namespace(**{**base, **kw})

    def problem(self, eventid, hostid, severity="4", manual_close="0", clock=1000, acked="0"):
        self.c.data["problem"].append({"eventid": eventid, "objectid": "t" + eventid, "name": "Disk full",
                                       "severity": severity, "clock": str(clock), "acknowledged": acked,
                                       "suppressed": "0", "_hostids": [hostid]})
        self.c.data["trigger"].append({"triggerid": "t" + eventid, "manual_close": manual_close,
                                       "hosts": [{"hostid": hostid}]})

    def test_window_only_for_managed_hosts_and_ends_by_itself(self):
        with _quiet():
            zbx_ops.cmd_maintenance(self.args(hosts=["web1", "new1"], name="patch web1", hours=2), CFG)
        (method, params), = self.c.writes
        self.assertEqual(method, "maintenance.create")
        self.assertEqual(params["name"], "homelab-manager patch web1")
        self.assertEqual(params["hosts"], [{"hostid": "10001"}])          # new1 is not in Zabbix
        self.assertLessEqual(params["active_till"] - params["active_since"], 2 * 3600 + 60)
        with self.assertRaises(hmlib.ConfigError):
            zbx_ops.cmd_maintenance(self.args(hosts=["web1"], hours=48), CFG)

    def test_stop_deletes_only_its_own_window(self):
        self.c.data["maintenance"] = [{"maintenanceid": "7", "name": "homelab-manager patch web1", "hosts": []}]
        with _quiet():
            zbx_ops.cmd_maintenance(self.args(action="stop", name="patch web1"), CFG)
        self.assertEqual(self.c.writes, [("maintenance.delete", ["7"])])

    def test_guest_short_names_and_shared_group_host(self):
        inv = {"web1.lab": {}, "db1": {}}
        zabbix_api.inventory = lambda root, cfg: inv
        cfg = copy.deepcopy(CFG)
        cfg["zabbix"]["host_match"] = [{"pattern": "{short}.home.arpa"}]
        found, skipped = zbx_ops.managed_hosts(self.c, cfg, ["web1", "db1", "ghost"])
        self.assertEqual(sorted(found), ["db1", "web1.lab"])             # db1: shared group, matched → managed
        self.assertEqual(skipped, ["ghost"])

    def test_gate_pre_stops_on_open_problems_at_the_floor(self):
        self.problem("1", "10001", severity="2")                           # warning: below high
        with _quiet():
            self.assertEqual(zbx_ops.cmd_gate(self.args(hosts=["web1"]), CFG), 0)
        self.problem("3", "10001", severity="5", acked="1")               # known: passes
        with _quiet():
            self.assertEqual(zbx_ops.cmd_gate(self.args(hosts=["web1"]), CFG), 0)
        self.problem("2", "10001", severity="4")
        with _quiet():
            self.assertEqual(zbx_ops.cmd_gate(self.args(hosts=["web1"]), CFG), 1)
        self.assertEqual(self.c.writes, [])

    def test_gate_post_only_new_problems_and_agent(self):
        self.problem("2", "10001", severity="4", clock=1000)
        with _quiet():
            self.assertEqual(zbx_ops.cmd_gate(self.args(phase="post", hosts=["web1"], since=2000), CFG), 0)
            self.c.data["host"][0]["active_available"] = "2"
            self.c.data["host"][0]["interfaces"][0]["available"] = "2"
            self.assertEqual(zbx_ops.cmd_gate(self.args(phase="post", hosts=["web1"], since=2000), CFG), 1)

    def test_ack_closes_only_where_the_trigger_allows(self):
        self.problem("1", "10001", manual_close="1")
        self.problem("2", "10001", manual_close="0")
        with _quiet():
            zbx_ops.cmd_ack(self.args(host="web1", message="disk extended", commit="abc123", close=True,
                                      min="information"), CFG)
        acts = {tuple(p["eventids"]): p for m, p in self.c.writes}
        self.assertEqual(acts[("1",)]["action"] & 1, 1)                    # closed
        self.assertEqual(acts[("2",)]["action"] & 1, 0)                    # only acknowledged
        self.assertIn("abc123", acts[("1",)]["message"])
        with self.assertRaises(hmlib.ConfigError):
            zbx_ops.cmd_ack(self.args(host="new1", message="x", min="information"), CFG)

    def test_read_role_falls_back_to_the_rw_token(self):
        cfg = copy.deepcopy(CFG)
        self.saved_connect = [f for m, n, f in self.saved if n == "connect"][0]
        env = {"ZABBIX_RW_TOKEN": "t"}
        orig = zbxlib.Client.version
        zbxlib.Client.version = lambda self: "8.0.0"
        try:
            c = self.saved_connect(cfg, "ro", env)
        finally:
            zbxlib.Client.version = orig
        self.assertEqual((c.role, c.token), ("ro", "t"))


class _quiet:
    def __enter__(self):
        import io
        import contextlib
        self.cm = contextlib.ExitStack()
        self.cm.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.cm.enter_context(contextlib.redirect_stderr(io.StringIO()))
        return self

    def __exit__(self, *exc):
        self.cm.close()
