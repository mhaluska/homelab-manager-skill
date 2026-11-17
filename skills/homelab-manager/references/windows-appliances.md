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

## BMCs (HPE iLO, Dell iDRAC, Supermicro, Lenovo XCC) over Redfish

Read-only health and firmware from this Mac over HTTPS; no ipmitool, no SSH into the BMC.
1. Confirm Redfish: `curl -sk https://<bmc>/redfish/v1/` answers without a login (RedfishVersion, Vendor).
   iLO 4 (fw 2.x+), iDRAC 8+, Supermicro X10+ and XCC support it; older ones: IPMI only (read with
   `ipmitool … sdr list`/`fru`, power commands need approval).
2. Ask the user for a **read-only BMC account** (iLO "Login" privilege only, iDRAC "Read Only", Supermicro
   "User"); the user stores `user:password` in the keychain (`homelab/bmc`) and you map it in homelab.yaml:
   `config_set.py 'secrets.bmc={service: homelab/bmc, kind: user_password, env: BMC}'`. One account name and
   password for all BMCs; different ones → one secret per group (`env` BMC_HPE, and the group's bmc_user/
   bmc_password vars read `BMC_HPE_USER`/`BMC_HPE_PASSWORD`).
3. Add the BMCs to the `bmc` group (child of `appliances`) in hosts.yml, `ansible_host` = address.
4. `with_secrets.py bmc -- ansible-playbook playbooks/bmc-info.yml` → `discovery/bmc.json` (system model,
   power state, health, PSUs, thermals, BMC and BIOS/firmware versions). Self-signed certificates are
   accepted (`bmc_validate_certs: false` in group_vars/bmc.yml); set true once the CA is trusted.
5. Report health problems and outdated firmware; firmware updates and power actions
   (`community.general.redfish_command`, `ipmitool power`) are approval items (the guard asks).
Keep BMCs on a management network: the drift report flags BMCs found elsewhere.

## Controller-managed devices (UniFi APs and switches)

The UniFi Network controller owns their configuration: anything changed on the device itself is overwritten
on the next provision, so never configure them over SSH or with Ansible modules. Read-only status only:
1. Controller: the user creates an API key (Network → Settings → Control Plane → Integrations), stores it in
   the keychain (`homelab/unifi-api`), and you map it:
   `config_set.py 'secrets.unifi-api={service: homelab/unifi-api, kind: env, env: UNIFI_API_KEY}'`.
   Set `unifi_api_url` in `group_vars/unifi.yml` (UniFi OS consoles: `https://<host>/proxy/network/integration/v1`;
   with no hosts in the `unifi` group pass `-e unifi_api_url=…`).
2. Devices (optional): add them to the `unifi` group (child of `appliances`) with the SSH user from the
   controller's device authentication settings. Only `ansible.builtin.raw` works (no Python on the device).
3. `with_secrets.py unifi-api -- ansible-playbook playbooks/unifi-info.yml` → `discovery/unifi.json`
   (controller version, sites, devices with model, firmware, state, IP) and each SSH device's status.
4. Changes (adoption, `set-inform`, firmware upgrades, factory reset, port or WLAN settings) go through the
   controller — its UI by the user, or its API after the user's yes (the guard asks).
Other controller-managed gear (Omada, Aruba Instant On, Meraki) follows the same rule: read from the
controller, change only through it.

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
