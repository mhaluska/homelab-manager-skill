# Ansible

Run from `ansible/` (it holds `ansible.cfg`). SSH via the Mac's agent; no passwords in Git.
Install collections once: `ansible-galaxy collection install -r requirements.yml -p collections`.
`requirements.yml` pins each collection below its next major version. Raising a bound is its own change: read
that release's breaking changes, then `--syntax-check` and a `--check` run of the playbooks that use it.

## Inventory

- `inventory/managed/hosts.yml` — hand-maintained: groups, non-Proxmox hosts, Windows, appliances.
- `inventory/managed/tofu_hosts.yml` — generated from OpenTofu (`tofu_to_inventory.py`); don't edit. Another
  site's environment: `tofu_hosts-<site>.yml`, its hosts also in `site_<site>`.
- `group_vars/` — non-secret variables. Secrets, if a role needs one, come from the keychain at
  runtime (`lookup('ansible.builtin.pipe', …)` is NOT acceptable — it prints in verbose mode);
  use `with_secrets.py <name> -- ansible-playbook …` and read the env var with
  `lookup('ansible.builtin.env', 'VAR')`, marked `no_log: true` on tasks that use it.
- A host goes into managed inventory only on purpose (user said so, or OpenTofu created it).
- Several locations: `site_<name>` groups, one per host at most; once the default site is named, new hosts go
  in its `site_<name>` too (references/proxmox.md "Several sites").

## Onboarding existing hosts

"Set up Ansible for the Linux servers" when they already run (not created by OpenTofu):
1. Fresh snapshot: `proxmox_inventory.py --details` (guest config + reported IPs).
2. Draft: `python3 $HM/scripts/proxmox_to_inventory.py [--vlan 20] [--range 10.0.20.0/24] [--type lxc]`
   prints YAML for running Linux guests (IP from the static config, else the guest agent / LXC
   interfaces) in group `onboarding`, and lists what it skipped (Windows/other ostype, stopped, no IP,
   already managed). Show the list; adding hosts to the managed inventory needs the user's yes.
3. Probe OS and Python, read-only, for these and for hosts nmap found outside Proxmox:
   ```bash
   python3 $HM/scripts/ssh_probe.py 10.0.20.0/24 [--user admin]   # SSH hosts network.json knows in the range
   python3 $HM/scripts/ssh_probe.py 10.0.20.11 10.0.20.12 --draft  # given hosts → YAML draft by OS group
   ```
   Same as `raw` (no Python needed) over `ssh -T`, agent keys only, a timeout per host and a throwaway
   known_hosts; csh root shells work. It shows the Python this ansible-core can use, the
   `ansible_python_interpreter` to set when `python3` is too old, an OS group, and merges into network.json
   (better `device_type_guess`). `auth failed` = key not authorized or wrong user (`no SSH key loaded`: the agent is empty, `ssh-add` first): fix, don't skip.
   `sh did not run` = no POSIX shell (RouterOS, switches): an appliance, not a Linux host.
   Put the reviewed hosts in `hosts.yml`. The probe trusts no host key: `ansible.cfg` checks them, so before
   the first run accept each once (`ssh -o StrictHostKeyChecking=accept-new <host> true`) on a network you trust.
4. Move each host into an OS group (`debian`, `ubuntu`, `rocky`, or version-specific `el8`, `el9`) under
   `linux`, and drop the `onboarding` group. `ansible linux -m ansible.builtin.setup -a filter=ansible_distribution*`
   confirms Python modules work.

Target Python vs the Mac's ansible-core (`ansible --version`): 2.16 runs on Python 3.6+, 2.17 needs 3.7+,
2.18–2.19 need 3.8+, newer releases drop more (check the ansible-core support matrix). EL8 (RHEL, Rocky,
Alma, CentOS Stream 8) ships 3.6: with 2.17+ install a newer Python from AppStream —
`ansible el8 -b -m raw -a 'dnf -y install python3.12'` (a change: approval) — and set
`ansible_python_interpreter: /usr/bin/python3.12` in `group_vars/el8.yml`. `dnf` and `package_facts` keep
working (they re-run under the system Python for its bindings). Same for other old releases (Ubuntu 18.04,
Debian 10). `check_env.py` flags hosts in EL8-named groups without an interpreter set.

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
0 changed), check-mode safe, OS-family branches via `ansible_facts.os_family` (never the injected `ansible_*` fact vars: removed in ansible-core 2.24), handlers for
restarts, `defaults/main.yml` documents every variable. Prefer modules over
`command`/`shell`; when shell is unavoidable, set `changed_when`.
Use well-known Galaxy collections when they're maintained; avoid random Galaxy roles.

## Example: "Install Zabbix Agent 2 on all managed Linux hosts"

The `monitoring` component ships the role `zabbix_agent2` and `playbooks/zabbix-agent2.yml`: see
references/monitoring.md "Agent 2" (settings in `homelab.yaml` `zabbix.agent`, switching from the classic agent).

## Users, SSH keys, packages, services

Same pattern: role or task file, check mode, one host, all hosts, verify, commit.
Changing `sshd_config`: validate with `validate: /usr/sbin/sshd -t -f %s` and keep the
current session open until a new connection succeeds — locking yourself out of a headless
homelab is a bad day.

## Kubernetes nodes

Joining/leaving a cluster, drain and uncordon are cluster operations (approval). Drain via
`kubernetes.core.k8s_drain` delegated to a host with kubeconfig, one node at a time.
