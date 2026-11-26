# Zabbix API users for homelab-manager

How the skill reaches your Zabbix server, and what it may change there. Keep this page up to date when you
change a user, a token or the managed scope (the skill fills in the parts marked _to fill in_ with you).

Server: _to fill in_ (version, host). API URL: `zabbix.url` in `homelab.yaml` (`…/api_jsonrpc.php`; find it with
`python3 $HM/scripts/zabbix_api.py probe https://<frontend>`).

## Users and tokens

Three API users, each with its own token. The skill reads with the first one; the second one writes, always after
you said yes to a shown plan; the third one is optional, for objects only a Super admin may change (global macros,
actions, media types, network discovery, regular expressions).

| User | User type | Role | Permissions | Keychain item → env (`with_secrets.py`) |
|---|---|---|---|---|
| `homelab-ro` | Admin | API access with an allow-list: `*.get`, `configuration.export`; no UI actions | read on the host and template groups the skill should see | `homelab/zabbix-ro` → `ZABBIX_RO_TOKEN` |
| `homelab-rw` | Admin | all API methods; actions: acknowledge problems, close problems, manage maintenance | read-write on the managed host and template groups only | `homelab/zabbix-rw` → `ZABBIX_RW_TOKEN` |
| `homelab-admin` (optional) | Super admin | all API methods | – | `homelab/zabbix-admin` → `ZABBIX_ADMIN_TOKEN` |

Create them in the frontend: *Users → User roles* (a role per user), *Users → User groups* (the permissions),
*Users → Users*, then *Users → API tokens* (one token per user; an expiry date is better than none). The names in
`homelab.yaml` `zabbix.secrets` and `secrets:` must match the keychain items.

Give `homelab-rw` write rights on the managed groups only, if your server allows it: then Zabbix enforces the
scope too. With broader rights the scope is enforced only by the skill's scripts.

Check them (read-only; write rights are probed on an ID that doesn't exist, nothing changes):

```bash
python3 $HM/scripts/with_secrets.py zabbix-ro zabbix-rw -- python3 $HM/scripts/zabbix_api.py check
```

Decisions: _to fill in_ (e.g. tokens without expiry accepted, broad rights intended).

## Managed scope

`zabbix.managed_scope` in `homelab.yaml`. Only these are ever written; everything else is read-only.

| | Patterns (`Home/*` = Home and everything under it) |
|---|---|
| Own host groups (`host_groups`) | _to fill in_ |
| Shared host groups (`shared_host_groups`): a host in them is managed only when it matches an inventory host | _to fill in_ |
| Template groups (`template_groups`) | _to fill in_ |

Not managed (other owners or domains on the same server): _to fill in_.

## Host names

How Zabbix host names relate to the inventory: `zabbix.host_match`, tried in order (references/monitoring.md
"Matching hosts"). A short name alone never matches, because other domains on a shared server can reuse it.

1. _to fill in_, e.g. `{host}.example.lan`

## Templates

Official or generic templates are not edited or linked to hosts directly: a wrapper template in your own template
group links them, and thresholds, macros and tags live in the wrapper (`wrappers:` in `zabbix/config.yaml`).

## Storing or rotating a token (on this Mac)

```bash
security add-generic-password -U -T /usr/bin/security -a "$USER" -s homelab/zabbix-ro -w
```

The same for `homelab/zabbix-rw` and `homelab/zabbix-admin`. Nothing comes after `-w`, so it prompts for the
value and the token stays out of the shell history.
