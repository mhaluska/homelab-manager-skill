# zabbix/

Zabbix monitoring as data, managed by the homelab-manager skill (references/monitoring.md).

- `config.yaml`: what the skill manages on the Zabbix server: host groups, wrapper templates, hosts (groups,
  templates, tags, macros, interfaces, inventory, proxy, status), web and TLS checks, services and SLAs, and with
  the admin token global macros and objects. Write the first version from what the server has now with
  `zabbix_api.py init-config`, so the first `plan` shows no changes. A key that is present is managed exactly; a key
  left out is left alone.
- `plan.json`: the last `zabbix_api.py plan`, applied once with `zabbix_api.py apply zabbix/plan.json` after your
  yes, then deleted (not committed).
- `export/`: `zabbix_api.py export`, the managed part of the server as Zabbix has it, without secret values; and
  `rollback-*.yaml`, the version of a template before `template-import` replaced it.
- `templates/`: official template files `zabbix_api.py template-fetch` downloaded, before they are imported.

Secret values (a macro's password, an SNMP community) are never written here: `{secret: <name>}` names a
`secrets:` entry of kind env in `homelab.yaml`, and `apply` runs under `with_secrets.py` with it.
