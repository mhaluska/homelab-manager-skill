# Windows hosts and appliances

## Windows

- Connection: OpenSSH Server on Windows + key from the Mac's agent (`group_vars/windows.yml`:
  `ansible_connection: ssh`, `ansible_shell_type: powershell`). No WinRM passwords in Git.
  If a host only has WinRM, store its credentials in the keychain and run via `with_secrets.py`.
- Modules: `ansible.windows.*`, `community.windows.*` (`win_ping`, `win_feature`, `win_service`,
  `win_package`, `win_updates`, `win_regedit`).
- Proxmox Windows VMs: VirtIO drivers + QEMU guest agent; cloud-init → `cloudbase-init` (a
  Windows template build is a separate Packer `proxmox-iso` flow; add it when first needed).
- Reboots: `ansible.windows.win_reboot` — approval item, the guard asks.

## Appliances (NAS, firewall, switches, BMC/IPMI, printers, IoT)

Default stance: **inventory and read-only checks**.
- Discovery finds them (`device_type_guess`: nas, firewall, network, bmc, printer, iot).
  Add the ones the user cares about to `appliances` in `hosts.yml` with `appliance_type`,
  `vendor`, and how to reach them (`ansible_network_os` / API URL).
- Read-only checks that are fine: reachability, firmware version via API/SNMP/SSH `show`
  commands, certificate expiry, open ports.
- Configuration changes only with a vendor collection the user has agreed on
  (e.g. `community.routeros`, `fortinet.fortios`, `community.general.opnsense*`), `--check`
  first, approval always — a bad firewall or switch push can cut off the Mac itself.
- BMC/IPMI: power actions are reboots → approval. Never change BMC users/network.

## MikroTik RouterOS (routers, CRS switches, CHR)

Identify and audit, read-only:
```bash
python3 $HM/scripts/routeros_audit.py 10.0.10.1 10.0.10.2 [--user audit]
python3 $HM/scripts/routeros_audit.py --group routeros     # hosts, users and ports from the inventory
```
It prints a Markdown report (save it as `docs/security-audit-<date>.md` when the user wants one) and keeps
the data in `discovery/routeros.json`. Fixing a finding is a change: `/system routerboard upgrade` and a
RouterOS upgrade need a reboot (approval), disabling a service can cut off whoever uses it — ask first.
Use a dedicated user in group `read` for audits.

Ansible on RouterOS:
- Use `community.routeros` over `ansible_connection: ansible.netcommon.network_cli` with
  `ansible_network_os: community.routeros.routeros` (needs `ansible-pylibssh` or paramiko; agent keys work)
  on RouterOS 6 and 7, hardware and CHR. `community.routeros.facts` and `.command` cover read-only checks.
- Never `raw` or the `ssh` connection: RouterOS waits for a terminal that never answers and the task hangs
  forever. For plain SSH use `ssh -T` with a timeout (as the audit script does).
- `community.routeros.command` always reports `changed`, even for `print`: add `changed_when: false`.
- Put `ansible_user` for the devices in `group_vars/<group>.yml`, not as a group var inside `hosts.yml`:
  `group_vars/all.yml` sets `ansible_user` and a group_vars file wins over inventory-file group vars.
- `/system routerboard` doesn't exist on CHR: guard such commands with the board name from
  `/system resource print`.
