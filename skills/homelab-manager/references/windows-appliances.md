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
