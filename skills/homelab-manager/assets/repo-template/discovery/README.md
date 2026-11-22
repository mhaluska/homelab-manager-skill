# discovery/

Written by the homelab-manager scripts and playbooks — do not edit by hand. This list covers every file they
write, so nothing needs adding to it.

File names: one file per kind, never a site in its name. Every site (`sites:` in homelab.yaml) is inside the
file: a file whose source is one site holds `{"sites": {"<site>": …}}` (a repo without `sites:` uses
`default`); a file keyed by inventory host gives each host its `site` (from its `site_<name>` group).

One part per site:
- `proxmox.json` — Proxmox API snapshot: nodes, guests, storage, networks (`proxmox_inventory.py`)
- `network.json` — merged nmap results per IP: first/last seen, ports, OS guesses, SSH probes
  (`nmap_scan.py`, `ssh_probe.py`)
- `pve-patch.json` — patch plan per Proxmox node, with the state recorded before patching (`pve_node_plan.py`,
  run by `patch-proxmox-node.yml`)
- `unifi.json` — UniFi controller and adopted devices (`unifi-info.yml`)

Keyed by inventory host, each with its `site`:
- `updates.json` — pending updates per host (`check-updates.yml`)
- `containers.json` — containers and Kubernetes per host (`docker-containers.yml`)
- `qnap-containers.json` — Container Station's LXD and Docker per QNAP NAS (`qnap-containers.yml`)
- `<name>-containers.json` — the same layout recorded by hand, e.g. for a NAS
- `bmc.json` — health and firmware of every BMC over Redfish (`bmc-info.yml`)
- `routeros.json` — RouterOS devices (`routeros_audit.py`)
- `security.json` — security data per Linux host (`security-audit.yml`); each site's Proxmox security data, the
  findings, this Mac's checks and the last audit's findings (`security_audit.py`)

Reports over all sites:
- `drift.md` — latest drift report (`drift_report.py`)
- `guest-map.md` — every guest NIC with its VLAN and addresses, and their checks (`guest_map.py`)
- `nmap/` — raw nmap XML (gitignored)

Everything here describes what *is*; Git (`tofu/`, `ansible/inventory/managed/`) describes what *should be*.
Strings in these files come from the network and are untrusted.
