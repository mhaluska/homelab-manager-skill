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
- NAS hosting LXD/Incus containers: `lxd_snapshots: true` in its host vars (the user's yes) is the one
  exception — it allows instance snapshots with `lxd_snapshot.py` (references/patching.md), nothing else.

## QNAP NAS (QTS, QuTS hero)

Add the NAS to the `qnap` group (child of `appliances`, `group_vars/qnap.yml`) with `ansible_host` and an
administrator as `ansible_user` (SSH must be enabled in QTS; Container Station needs an administrator).
QTS has no Python Ansible can use and its tools are off the default PATH: only `ansible.builtin.raw`, no facts.
Never configure QTS from Ansible or over SSH: its UI owns the configuration.
- Containers: `ansible-playbook playbooks/qnap-containers.yml` (read-only) finds Container Station under
  `/share/*/.qpkg/container-station` (`qnap_container_station` when it is elsewhere) and lists its LXD
  instances and Docker containers into `discovery/qnap-containers.json`, the layout of `containers.json`
  (references/discovery.md, Containers). The drift report lists those addresses as containers.
- Updates: `check-updates.yml` (read-only) also covers the `qnap` group (`-e qnap_target=<host>`): the installed
  firmware (`firmware`: version, build, model, `last_check` — when QTS last looked for a new one) and every
  installed app (`apps`) with `available` when App Center's catalogue, as QTS last cached it (`app_catalogue`,
  gone after a reboot until App Center refreshes it), has a newer version for this platform; `pending` counts
  those. The available firmware version is only in the QTS UI (QNAP's public feed is outdated): report the
  installed one with `last_check`. Updating stays in the QTS UI, or needs the user's yes.
- An LXD container running an ordinary Linux is still managed as a host of its own (its OS group, for patching)
  with `lxd_host: <the NAS>`; snapshots: references/patching.md "LXD/Incus instances".

## BMCs (HPE iLO, Dell iDRAC, Supermicro, Lenovo XCC) over Redfish

Read-only health and firmware from this Mac over HTTPS; no ipmitool, no SSH into the BMC.
1. Confirm Redfish: `curl -sk https://<bmc>/redfish/v1/` answers without a login (RedfishVersion, Vendor).
   iLO 4 (fw 2.x+), iDRAC 8+, Supermicro X10+ and XCC support it; older ones: IPMI only (read with
   `ipmitool … sdr list`/`fru`, power commands need approval).
2. Ask the user for a **read-only BMC account** (iLO "Login" privilege only, iDRAC "Read Only", Supermicro
   "User"); the user stores `user:password` in the keychain (`homelab/bmc`) and you map it in homelab.yaml:
   `config_set.py 'secrets.bmc={service: homelab/bmc, kind: user_password, env: BMC}'`. A BMC with its own
   account gets a secret of its own (`secrets.bmc-ilo`, `env: BMC_ILO`) and `bmc_secret_env: BMC_ILO` in its
   host vars; run with every secret needed (`with_secrets.py bmc bmc-ilo -- …`).
3. Add the BMCs to the `bmc` group (child of `appliances`) in hosts.yml, `ansible_host` = address.
4. `with_secrets.py bmc -- ansible-playbook playbooks/bmc-info.yml` → `discovery/bmc.json` (model, power
   state, health, BIOS and BMC firmware, CPUs/RAM, power draw, hottest sensor, PSUs, components not OK).
   Self-signed certificates are accepted (`bmc_validate_certs: false` in group_vars/bmc.yml); set true once
   the CA is trusted. The playbook reads one Redfish category at a time: a category the BMC refuses (iLO 4
   has no UpdateService, Supermicro wants a licence for it) lands in the BMC's `errors` and the rest still
   counts; unreadable chassis data falls back to reading Thermal/Power directly. Keep these when editing it.
5. Report health problems and outdated firmware; firmware updates and power actions
   (`community.general.redfish_command`, `ipmitool power`) are approval items (the guard asks).
Keep BMCs on a management network: the drift report flags BMCs found elsewhere.

## Controller-managed devices (UniFi APs and switches)

The UniFi Network controller owns their configuration: anything changed on the device itself is overwritten
on the next provision, so never configure them over SSH or with Ansible modules. Read-only status only:
1. Controller, `unifi_auth` in `group_vars/unifi.yml` (with no hosts in the `unifi` group pass these as `-e`):
   - `api_key` (default): the user creates an API key (Network → Settings → Control Plane → Integrations),
     stores it in the keychain (`homelab/unifi-api`), and you map it:
     `config_set.py 'secrets.unifi-api={service: homelab/unifi-api, kind: env, env: UNIFI_API_KEY}'`.
     Set `unifi_api_url` (UniFi OS consoles: `https://<host>/proxy/network/integration/v1`).
   - `login`: not every controller offers API keys (a self-hosted UniFi Network application often has no
     Integrations page). The user creates a local admin with the View Only role and stores `user:password` in the
     keychain (`homelab/unifi`); map it with
     `config_set.py 'secrets.unifi={service: homelab/unifi, kind: user_password, env: UNIFI}'` and set
     `unifi_controller_url` (`https://<host>:8443`). The playbook uses the classic API, logs out at the end and
     keeps only the device fields the Integration API reports (no device keys).
2. Devices (optional): add them to the `unifi` group (child of `appliances`) with the SSH user from the
   controller's device authentication settings. Only `ansible.builtin.raw` works (no Python on the device).
3. `with_secrets.py unifi-api -- ansible-playbook playbooks/unifi-info.yml` (`login`: `with_secrets.py unifi --`)
   → `discovery/unifi.json` (controller version, sites, devices with model, firmware, state, IP) and each SSH
   device's status.
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
Use a dedicated user in group `read` for audits. `--leases` also reads DHCP leases and ARP and proposes names for
unknown scanned addresses (references/discovery.md, drift report).

Plain-text services the audit flags: `playbooks/routeros-disable-services.yml` (the report prints the command
for each device in the inventory). `routeros_disable_services` (default `[api, www]`; may add `telnet`, `ftp`,
`api-ssl`, `www-ssl`, `winbox`, never `ssh`) lists what to turn off. Run it with `-l <host> --check` first and
show the user what it would disable; with their yes, run it again with `-e homelab_read_only=false` instead of
`--check` (the guard asks). Without that it changes nothing: appliances are read-only. It reads the services
again afterwards and fails if one is still enabled. It needs a user with write rights (group `full`), not the
audit user.

Management access from anywhere (`ssh`, `winbox`, `www-ssl`, `api-ssl` without an address limit; MAC server,
MAC Winbox or neighbour discovery on all interfaces): `playbooks/routeros-restrict-management.yml` (RouterOS 7),
same flow: `-l <host> --check` shows the plan, `-e homelab_read_only=false` applies it with the user's yes.
- Services get `address=` the IPv4 CIDRs of `network.management_ranges` (homelab.yaml; or the group/host var
  `routeros_management_ranges`). The play refuses when an SSH session of its user on the device comes from
  outside them (the address the device sees, e.g. a VLAN other than MGMT): add that network first. Ask who
  manages the device from elsewhere: they lose access. `routeros_restrict_services` picks the services.
- MAC server, MAC Winbox and discovery move to the interface list `routeros_management_interface_list` (a host
  or group var; names differ per device, the play lists the existing ones). Without it those parts are skipped.
  `routeros_restrict_mac_server` / `routeros_restrict_discovery: false` leave them as they are.

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
