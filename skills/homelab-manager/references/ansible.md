# Ansible

Run from `ansible/` (it holds `ansible.cfg`). SSH via the Mac's agent; no passwords in Git.
Install collections once: `ansible-galaxy collection install -r requirements.yml -p collections`.

## Inventory

- `inventory/managed/hosts.yml` — hand-maintained: groups, non-Proxmox hosts, Windows, appliances.
- `inventory/managed/tofu_hosts.yml` — generated from OpenTofu (`tofu_to_inventory.py`); don't edit.
- `group_vars/` — non-secret variables. Secrets, if a role needs one, come from the keychain at
  runtime (`lookup('ansible.builtin.pipe', …)` is NOT acceptable — it prints in verbose mode);
  use `with_secrets.py <name> -- ansible-playbook …` and read the env var with
  `lookup('ansible.builtin.env', 'VAR')`, marked `no_log: true` on tasks that use it.
- A host goes into managed inventory only on purpose (user said so, or OpenTofu created it).

## Running playbooks

```bash
ansible-playbook playbooks/<play>.yml --syntax-check
ansible-playbook playbooks/<play>.yml -e target=<group> --check --diff     # dry run
ansible-playbook playbooks/<play>.yml -e target=<group>                    # real run
```
- Always `--check --diff` first for changes and show the user the summary (hosts × changed tasks).
  Some tasks can't run in check mode (they depend on earlier changes): say so.
- Start with one host (`-l <host>`) when introducing a new role, then the rest.
- `serial` for anything that restarts services on a cluster group.
- Recap line per host is the result; `failed`/`unreachable` must be explained.

## Writing roles

`roles/<name>/{tasks,handlers,defaults,templates,meta}/`. Idempotent (second run =
0 changed), check-mode safe, OS-family branches via `ansible_os_family`, handlers for
restarts, `defaults/main.yml` documents every variable. Prefer modules over
`command`/`shell`; when shell is unavoidable, set `changed_when`.
Use well-known Galaxy collections when they're maintained; avoid random Galaxy roles.

## Example: "Install Zabbix Agent 2 on all managed Linux hosts"

1. Ask/discover: Zabbix server address (not in config → ask; add `zabbix.server` to
   `group_vars/all.yml`), Zabbix version to match the server, PSK or not (PSK = secret →
   keychain item + `with_secrets.py`).
2. Role `zabbix_agent2`: add the official Zabbix repo per OS family (Rocky: `rpm` repo; Debian/
   Ubuntu: `zabbix-release` deb), install `zabbix-agent2`, template
   `/etc/zabbix/zabbix_agent2.conf` (Server, ServerActive, Hostname = inventory_hostname),
   open 10050/tcp (firewalld/ufw if active), enable + start, handler restart.
3. Playbook `playbooks/zabbix-agent2.yml` (`hosts: "{{ target | default('linux') }}"`).
4. `--check --diff` on all, real run on one host, verify (`systemctl is-active zabbix-agent2`,
   `ss -ltn | grep 10050`), then the rest. Installing on many hosts is an approval item.
5. Add `zabbix-agent2` to `health_services` for those groups. Commit role + playbook + vars.

## Users, SSH keys, packages, services

Same pattern: role or task file, check mode, one host, all hosts, verify, commit.
Changing `sshd_config`: validate with `validate: /usr/sbin/sshd -t -f %s` and keep the
current session open until a new connection succeeds — locking yourself out of a headless
homelab is a bad day.

## Kubernetes nodes

Joining/leaving a cluster, drain and uncordon are cluster operations (approval). Drain via
`kubernetes.core.k8s_drain` delegated to a host with kubeconfig, one node at a time.
