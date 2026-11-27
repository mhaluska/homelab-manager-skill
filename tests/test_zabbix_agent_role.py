"""The zabbix_agent2 role's settings logic (tasks/settings.yml), run on localhost with made-up agent configs, package
states and facts: which configuration counts, Server/ServerActive by mode, HostMetadata (GitHub issues #178, #179)."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import SCRIPTS  # noqa: E402

ROLES = SCRIPTS.parent / "assets/repo-template/ansible/roles"
MAIN, DROPIN, CLASSIC = "/etc/zabbix/zabbix_agent2.conf", "/etc/zabbix/zabbix_agent2.d/homelab-manager.conf", \
    "/etc/zabbix/zabbix_agentd.conf"
FAKE_FACTS = '''#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
m = AnsibleModule(argument_spec={"facts": {"type": "dict", "required": True}})
m.exit_json(changed=False, ansible_facts=m.params["facts"])
'''
PLAY = '''- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - fake_facts:
        facts: "{{ facts }}"
    - ansible.builtin.include_role:
        name: zabbix_agent2
        tasks_from: settings
    - ansible.builtin.copy:
        dest: "{{ out_dir }}/{{ inventory_hostname }}.json"
        content: >-
          {{ {'settings': zbx_settings, 'sources': zbx_sources, 'leftover': zbx_leftover, 'metadata': zbx_metadata,
              'unmatched': zbx_metadata_unmatched | bool, 'userparams': zbx_userparams} | to_json }}
      delegate_to: localhost
'''


def facts(running=(), distro="Debian", major="13", virt=("guest", "lxc")):
    return {"system": "Linux", "os_family": "Debian" if distro in ("Debian", "Ubuntu") else "RedHat",
            "distribution": distro, "distribution_major_version": major,
            "virtualization_role": virt[0], "virtualization_type": virt[1],
            "services": {f"{s}.service": {"state": "running"} for s in running}}


def read(files: dict[str, str]) -> dict:
    return {"results": [{"item": {"item": p}, "content": base64.b64encode(t.encode()).decode()}
                        for p, t in files.items()]}


@unittest.skipUnless(shutil.which("ansible-playbook"), "needs ansible-playbook")
class AgentSettingsTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        pb = self.d / "ansible/playbooks"
        (pb / "library").mkdir(parents=True)
        (pb / "library/fake_facts.py").write_text(FAKE_FACTS)
        (pb / "t.yml").write_text(PLAY)
        (self.d / "out").mkdir()
        self.agent = {"version": "8.0"}

    def run_role(self, hosts: dict[str, dict], autoreg=None, extra=()):
        (self.d / "homelab.yaml").write_text(json.dumps(
            {"zabbix": {"url": "https://z.test", "host_match": [{"pattern": "{host}.lab"}], "agent": self.agent}}))
        if autoreg is not None:
            (self.d / "discovery").mkdir(exist_ok=True)
            (self.d / "discovery/zabbix.json").write_text(json.dumps({"autoregistration": autoreg}))
        inv = {"all": {"hosts": {}, "children": {"proxmox_nodes": {"hosts": {}}, "site_home": {"hosts": {}}}}}
        for name, h in hosts.items():
            hv = {"ansible_python_interpreter": "auto_silent",
                  "out_dir": str(self.d / "out"), "facts": h.get("facts") or facts(),
                  "zbx_read": read(h.get("files") or {}), "zbx_inc_read": {"results": []},
                  "zbx_pkg_state": {"stdout": "\n".join(h.get("pkgs", [])), "stdout_lines": h.get("pkgs", [])}}
            inv["all"]["hosts"][name] = hv
            for g in h.get("groups", []):
                inv["all"]["children"][g]["hosts"][name] = {}
        (self.d / "inv.json").write_text(json.dumps(inv))
        env = dict(os.environ, ANSIBLE_ROLES_PATH=str(ROLES), ANSIBLE_LOCALHOST_WARNING="0",
                   ANSIBLE_INVENTORY_UNPARSED_WARNING="0", ANSIBLE_NOCOLOR="1")
        r = subprocess.run(["ansible-playbook", "-i", str(self.d / "inv.json"), str(self.d / "ansible/playbooks/t.yml"),
                            *extra], capture_output=True, text=True, env=env, timeout=300)
        return r, {n: json.loads((self.d / "out" / f"{n}.json").read_text())
                   for n in hosts if (self.d / "out" / f"{n}.json").exists()}

    def test_server_active_and_modes(self):   # GitHub issue #178
        self.agent.update(server="10.0.0.5", server_active="proxy.lab:10051")
        r, out = self.run_role({"h1": {"pkgs": ["zabbix-agent2 ii"], "files": {MAIN: "Server=127.0.0.1\n"}}})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(out["h1"]["settings"]["Server"], "10.0.0.5")
        self.assertEqual(out["h1"]["settings"]["ServerActive"], "proxy.lab:10051")
        del self.agent["server_active"]
        _, out = self.run_role({"h1": {}})
        self.assertEqual(out["h1"]["settings"]["ServerActive"], "10.0.0.5")          # falls back to server
        self.agent["mode"] = "passive"
        _, out = self.run_role({"h1": {"files": {MAIN: "ServerActive=old.lab\n"}, "pkgs": ["zabbix-agent2 ii"]}})
        self.assertEqual(out["h1"]["settings"]["ServerActive"], "")                    # left out of the drop-in
        self.agent.update(mode="active", server_active="z.lab")
        _, out = self.run_role({"h1": {}})
        self.assertEqual((out["h1"]["settings"]["Server"], out["h1"]["settings"]["ServerActive"]), ("", "z.lab"))
        self.agent["mode"] = "sometimes"
        r, out = self.run_role({"h1": {}})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("zabbix.agent.mode is sometimes", r.stdout)

    def test_settings_come_from_the_running_agent(self):   # GitHub issue #179
        self.agent["server"] = ""
        stale = {MAIN: "Server=10.9.9.9\nHostMetadata=:Linux:Debian10:LXC:\nTimeout=10\n",
                 CLASSIC: "Server=10.0.0.5\nHostMetadata=:Linux:Debian13:LXC:\nUserParameter=x.y,echo 1\n"}
        r, out = self.run_role({
            "removed": {"files": stale, "pkgs": ["zabbix-agent ii", "zabbix-agent2 rc"],
                        "facts": facts(running=["zabbix-agent"])},
            "beside": {"files": stale, "pkgs": ["zabbix-agent ii", "zabbix-agent2 ii"],
                       "facts": facts(running=["zabbix-agent"])},
            "switched": {"files": stale, "pkgs": ["zabbix-agent ii", "zabbix-agent2 ii"],
                         "facts": facts(running=["zabbix-agent2"])}})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for name in ("removed", "beside"):
            s = out[name]["settings"]
            self.assertEqual((s["Server"], s["HostMetadata"]), ("10.0.0.5", ":Linux:Debian13:LXC:"), name)
            self.assertNotIn("Timeout", s, name)
            self.assertEqual(out[name]["userparams"], ["UserParameter=x.y,echo 1"])
        self.assertEqual(out["removed"]["leftover"], [MAIN])
        self.assertEqual(out["beside"]["leftover"], [])                    # not read while classic runs, not left over
        self.assertEqual(out["switched"]["settings"]["Server"], "10.9.9.9")             # Agent 2 runs: its file
        self.assertEqual(out["switched"]["settings"]["Timeout"], "10")

    def test_host_metadata_pattern_only_for_hosts_without(self):   # GitHub issue #179
        self.agent.update(server="z.lab", host_metadata=":{os}:{distro}{major}:{virt}:")
        hosts = {"bare": {}, "has": {"files": {MAIN: "HostMetadata=:Linux:Old:\n"}, "pkgs": ["zabbix-agent2 ii"]},
                 "node": {"groups": ["proxmox_nodes"], "facts": facts(virt=("host", "kvm"))},
                 "vm": {"facts": facts(distro="Rocky", major="9", virt=("guest", "kvm"))}}
        autoreg = [{"name": "LXC", "enabled": True, "eval": "and", "metadata": [
                        {"op": "contains", "value": ":Linux:"}, {"op": "contains", "value": ":LXC:"}]},
                   {"name": "KVM", "enabled": True, "eval": "and", "metadata": [
                        {"op": "contains", "value": ":KVM:"}, {"op": "not contains", "value": ":HETZNER:"}]},
                   {"name": "PVE", "enabled": True, "eval": "or", "metadata": [{"op": "contains", "value": ":Proxmox:"}]}]
        r, out = self.run_role(hosts, autoreg=autoreg)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(out["bare"]["metadata"], ":Linux:Debian13:LXC:")
        self.assertEqual(out["has"]["metadata"], ":Linux:Old:")                       # kept
        self.assertEqual(out["node"]["metadata"], ":Linux:Debian13:Proxmox:")
        self.assertEqual(out["vm"]["metadata"], ":Linux:Rocky9:KVM:")
        self.assertEqual({n: o["unmatched"] for n, o in out.items()},
                         {"bare": False, "has": True, "node": False, "vm": False})    # :Linux:Old: has no :LXC:
        _, out = self.run_role(hosts, autoreg=autoreg, extra=["-e", "zabbix_agent_host_metadata_force=true"])
        self.assertEqual(out["has"]["metadata"], ":Linux:Debian13:LXC:")
        self.agent["host_metadata"] = "site={site} os={distro}{major}"
        _, out = self.run_role({"bare": {"groups": ["site_home"]}},
                               autoreg=autoreg + [{"name": "Win", "enabled": True, "eval": "and/or",
                                                   "metadata": [{"op": "matches", "value": "^Windows"}]}])
        self.assertEqual(out["bare"]["metadata"], "site=home os=Debian13")
        self.assertTrue(out["bare"]["unmatched"])                                       # no action would take it
        self.agent["host_metadata"] = ""
        _, out = self.run_role({"bare": {}}, autoreg=autoreg)
        self.assertEqual(out["bare"]["metadata"], "")                                   # no pattern: no metadata
        self.assertFalse(out["bare"]["unmatched"])


if __name__ == "__main__":
    unittest.main()
