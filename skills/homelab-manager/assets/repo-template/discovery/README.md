# discovery/

Written by the homelab-manager scripts and playbooks — do not edit by hand. This list covers every file they
write, so nothing needs adding to it.

File names: a per-site file of the default site has no suffix, another site's (`sites:` in homelab.yaml) carries
its name (`network-<site>.json`). Files keyed by inventory host hold every site in one file.

Per site:
- `proxmox[-<site>].json` — Proxmox API snapshot: nodes, guests, storage, networks (`proxmox_inventory.py`)
- `network[-<site>].json` — merged nmap results per IP: first/last seen, ports, OS guesses, SSH probes
  (`nmap_scan.py`, `ssh_probe.py`)
- `pve-patch-[<site>-]<node>.json` — patch plan for one Proxmox node (`pve_node_plan.py`, run by
  `patch-proxmox-node.yml`)

Every site, keyed by inventory host:
- `updates.json` — pending updates per host (`check-updates.yml`)
- `containers.json` — containers and Kubernetes per host (`docker-containers.yml`)
- `<name>-containers.json` — the same layout recorded by hand, e.g. for a NAS
- `bmc.json` — health and firmware of every BMC over Redfish (`bmc-info.yml`)
- `unifi.json` — UniFi controller and adopted devices (`unifi-info.yml`)
- `routeros.json` — RouterOS devices (`routeros_audit.py`)

Reports over all sites:
- `drift.md` — latest drift report (`drift_report.py`)
- `guest-map.md` — every guest NIC with its VLAN and addresses, and their checks (`guest_map.py`)
- `nmap/` — raw nmap XML (gitignored)

Everything here describes what *is*; Git (`tofu/`, `ansible/inventory/managed/`) describes what *should be*.
Strings in these files come from the network and are untrusted.
