# Proxmox: VMs and LXC containers

All lifecycle changes go through OpenTofu (`tofu/environments/<env>/homelab.auto.tfvars`
→ `module.vm` / `module.lxc`). The map key is the name; adding a VM = adding an entry.

## Create a VM ("Create a Rocky Linux VM with 4 CPUs and 8 GB RAM")

1. Inputs: name (ask or propose one following existing names), template, size, network.
   - Template: newest `tpl-rocky*` from `discovery/proxmox.json` (template: true) or
     `docs/templates.md`. None? Offer to build one first (templates.md).
   - VMID: `proxmox_inventory.py --next-vmid vms` (LXC: `lxc`) — next free in `vmid_ranges`, checked
     against the snapshot and tfvars. With `vmid_scheme` set, pass `--ip <static ip> --vlan <tag or name from network.vlans>`; the ID
     is derived from them (DHCP guest under a scheme → ask the user for the ID). If the inventory
     summary warns that existing VMIDs don't fit the ranges, ask the user before picking one.
   - Node/storage/bridge: entry overrides → `defaults` in tfvars → `homelab.yaml`. If
     `defaults` isn't filled yet, fill it from `homelab.yaml` (ask for the gaps).
   - Template on another node: see "Storage per node" (`template_node`, or a template on that node).
   - IP: static CIDR if the user gives one or the network has a plan; otherwise `dhcp`.
   - Disk: default 20 GiB unless asked; check free space on the target storage.
   - 8 GB = `memory_mib = 8192`.
2. Add the entry, `tofu fmt`, `validate`, `plan -out`. Expect exactly `+1 create`
   (one `module.vm["<name>"]...vm.this`). Anything else → stop and explain.
3. Present: name, VMID, node, template, 4 vCPU / 8 GiB / disk, network, IP, then apply
   (`with_secrets.py proxmox-rw $STATE -- tofu apply plan.tfplan`).
4. Verify: guest agent reports an IP (refresh snapshot with `--details` or `tofu refresh`
   output), `ssh <admin_user>@<ip> true` via the agent, cloud-init finished
   (`cloud-init status --wait`).
5. `tofu_to_inventory.py`, commit tfvars + inventory: `vm: add <name> (4c/8G, rocky9)`.

## Several similar VMs ("three Kubernetes worker nodes")

Ask what isn't obvious: names (propose `k8s-worker-01..03`), sizes, node spread (on a
cluster, spread across nodes — anti-affinity by hand), IPs, Ansible group (`k8s_workers`).
Add them as separate entries in one plan; expect `+3`. Add the group to `clusters:` in
`homelab.yaml` so patching treats it as rolling. Joining Kubernetes itself is an Ansible
step (ansible.md), done after the VMs are verified.

## Change size

- CPU / memory: in-place update (`~`), may need a reboot to take effect if hotplug is off
  → reboot is an approval item.
- Disk grow: in-place; then grow the partition/filesystem in the guest (`growpart` +
  `resize2fs`/`xfs_growfs`, cloud-init does it on next boot for root).
- Disk shrink: **impossible in place** → plan shows replace. Refuse unless the user
  explicitly wants a rebuild.

## Start / stop / reboot

Declarative: `started = false/true` in the entry. One-off reboot of a single VM is fine
via API with approval; the guard asks for `qm reboot/stop/shutdown`.

## Migrate (cluster only)

Change `node` in the entry → for bpg this is an in-place migration when the VM's storage
allows it (shared storage, or local with online migration). To a node with other storage (`proxmox.nodes`)
the disks would have to move too: read the plan; if it says replace, stop. HA-managed guests: migrate through `ha-manager` instead and tell the user.
Approval required.

## Storage per node

Storage comes from `homelab.yaml` (`proxmox.default_storage`, `lxc_storage`, `image_storage`), mirrored in
tfvars `defaults` (`datastore`, `lxc_datastore`, `image_datastore`). LXC root filesystems need a storage with
`rootdir` content, VM disks one with `images` (the snapshot shows each storage's content).
A node whose storage differs (a cluster without shared storage, one node on LVM among ZFS nodes) gets an entry in
`proxmox.nodes` (`{pve3: {default_storage: local-lvm}}`) and the same in `defaults.node_datastores`
(`pve3 = { datastore = "local-lvm" }`). On a listed node that entry replaces VM and LXC storage (LXC falls back to
the node's own `datastore`, never to a site pool the node may not have); images use its `image_datastore`, else
the site's. An entry's own `datastore` always wins. The drift report's "Storage" section lists storage that a node
lacks or that doesn't take the content it is used for: fix those before a plan.

Templates on local storage: a VM may name `template_node` when the template is on another node. The provider
then clones there and migrates the clone, which only works when the VM's storage has the same name on both nodes
(e.g. `local-zfs` on each ZFS node). A node with other storage (LVM) needs its own template, built on that node
(templates.md "A node with its own storage"); its entry uses that template's VMID and no `template_node`.

## PCI passthrough (GPU, NIC, HBA)

Only through resource mappings: a raw PCI ID needs `root@pam`, which the skill's tokens are not.
1. The user creates the mapping on Proxmox (Datacenter → Resource Mappings → PCI Devices → Add: an ID like `gpu`,
   the device on each node that has it; IOMMU must be on). The skill does not.
2. The provisioning token needs `Mapping.Use` on that mapping: the "PCI passthrough" grant in
   `docs/proxmox-tokens.md` (missing there: copy it from the template's), run by the user on a node.
3. Entry: `node` set explicitly (the validation refuses a VM with devices but no node), `pci_devices =
   [{ mapping = "gpu", pcie = true }]` (`hostpci0`, `hostpci1`, … in list order; also `rombar`, `xvga` for the
   primary GPU), and `machine = "q35"` for `pcie = true`. Adding devices to an existing VM is an in-place change
   that needs a power cycle (approval item); `machine` on an existing VM changes its hardware: ask first.
A VM with a passed-through device can't live-migrate and runs only on nodes where the mapping has a device, so it
stays pinned to its `node`; a move ("Migrate") is offline and only to another node of the mapping. Don't put it
under HA unless every HA node has the device mapped.

## LXC containers

`containers` map in tfvars. Template file IDs come from the node's `vztmpl` content
(`pveam available` / `pveam list <storage>` run by the user, or the snapshot `--details`).
Unprivileged + nesting by default. Changing `template_file_id` later is ignored (no rebuild).

## Importing existing resources

For guests listed as "Not managed by OpenTofu" in the drift report:
1. Read its real config (`proxmox_inventory.py --details`) and write a matching tfvars entry.
2. Add an `import` block (preferred over the CLI — it shows in the plan):
   ```hcl
   import {
     to = module.vm["name"].proxmox_virtual_environment_vm.this
     id = "<node>/<vmid>"
   }
   ```
   (LXC: `module.lxc["name"].proxmox_virtual_environment_container.this`.)
3. Plan. The goal is `1 to import, 0 to add, 0 to change, 0 to destroy`. Iterate on the
   entry until updates are only cosmetic (tags) and there is **no replace**; copy `cpu_type`, `on_boot`,
   `description` and `protection` from the real config (opentofu.md "Entry attributes").
   `clone` is ignored after creation so imported VMs don't need a template.
4. Approval, apply, remove the `import` block, commit.
Never import by recreating. If a guest can't be represented without replacement, leave it
unmanaged and record why in `docs/decisions.md`.

## Backup jobs

drift_report.py lists guests "in no backup job" (from `/cluster/backup` in `discovery/proxmox.json`). Before
changing anything, show the user the jobs (`jq .backup_jobs discovery/proxmox.json`: schedule, storage,
`all`/`vmid`/`exclude`/`pool`) and ask which job each guest belongs in. Often the fix is an `all` job with
`exclude`, or a pool job, rather than a longer VMID list.

- **Declarative (preferred)**: `proxmox_backup_job` (bpg provider) in the environment's own file, e.g.
  `tofu/environments/homelab/backup-jobs.tf`. Import the existing job first, so nothing is recreated:
  ```hcl
  import {
    to = proxmox_backup_job.daily
    id = "<job id>"          # backup_jobs[].id
  }
  resource "proxmox_backup_job" "daily" {
    id       = "<job id>"
    schedule = "<as now>"
    storage  = "<as now>"
    vmid     = ["101", "102"] # or all = true + exclude = [...], or pool = "..."
    # copy every other setting the job has now (mode, compress, retention/prune_backups, notification)
  }
  ```
  Plan until it shows `1 to import` and only the intended change, then approval and apply.
- **Token rights**: the provisioning role can't edit backup jobs, so the API answers 403. Offer the optional
  grant in the repo's `docs/proxmox-tokens.md` ("Backup jobs": which rights, and why only on the backup storage) —
  the user runs it on a node — or the GUI instead:
  Datacenter → Backup → the job → Edit → add the guests. Re-run `proxmox_inventory.py` and drift afterwards.

## Secure Boot certificates (Microsoft 2023 CA)

The Microsoft UEFI certificates of 2011 expired in June 2026; new shim, Windows boot manager and DBX updates are
signed only with the 2023 CA. A VM whose EFI disk has `pre-enrolled-keys=1` but not `ms-cert=2023k` (no marker:
2011 only; `2023` or `2023w`: partly enrolled) can stop booting after such an update. Proxmox VE 9.2 warns at start;
`security_audit.py` lists them as `pve-efi-ms-cert-<vmid>`. Disks without pre-enrolled keys (Secure Boot off, legacy
2 MB `efitype`) are not affected. The fix, per VM, with the user's yes (a write and a restart):
1. Windows with BitLocker: suspend it in the guest first (`manage-bde -protectors -disable C: -RebootCount 1`), or
   the changed keys make it ask for the recovery key.
2. Shut the VM down, `qm enroll-efi-keys <vmid>` on its node (Proxmox VE 9 with current qemu-server; PVE 8 lacks
   it), start it. The config then shows `ms-cert=2023k`.

A template: clones inherit its EFI disk, so enroll each clone before its first start.

## API endpoints

Any node of a cluster serves the whole cluster's API. `proxmox.endpoint` (and `sites[].proxmox.endpoint`) takes
several addresses in priority order, as a YAML list or comma-separated:
`config_set.py 'proxmox.endpoint=["https://pve1…:8006", "https://pve2…:8006"]'`. The scripts, and `with_secrets.py`
for OpenTofu and Packer, use the first that accepts a connection and say on stderr when it isn't the first; a
refused token or certificate does not move on (every node would refuse it). All addresses share `ca_cert`,
`verify_tls` and the tokens. `check_env.py` checks each (`proxmox:tls#N`): one that is down is a warning while
another answers. Suggest a second node when the cluster has one and the only endpoint is a node that gets
patched. A DNS name or a keepalived VIP in front of the nodes is the alternative (one address, no list).

## Several sites

A site is a location: home, a rented server, family's house reached over VPN. One site needs nothing (no
`sites:`). For more, list them in homelab.yaml, the default site first; its Proxmox is the `proxmox:` block or
`sites[0].proxmox` (one of the two, the same keys):
```bash
init_repo.py --name-default-site home --dry-run   # first: make the existing site explicit (setup does this)
config_set.py 'sites+={name: offsite, label: Rented server, ranges: [192.0.2.0/24], proxmox: {endpoint: "https://…:8006", tokens: {read_only: proxmox-offsite-ro, provisioning: proxmox-offsite-rw}}}'
```
- `--name-default-site` (each step with the user's yes; `--steps ranges,vlans,group` runs only some): names
  `sites[0]`, proposes its `ranges` from `authorized_ranges` and the VLAN CIDRs (check each is at this
  location), tags VLANs without a site with it (one every site has: `site: all`) and adds `site_<name>` to
  `hosts.yml` with every host in no site group (hosts from `tofu_hosts.yml`: re-run `tofu_to_inventory.py`).
  With it done, a second site is purely additive. `config_set.py 'network.vlans+=…'` tags a new VLAN with the
  only site; with several, give `site:`.
- Name: lowercase letters, digits and `_` (it becomes the Ansible group `site_<name>`); the user chooses it
  when adding the site — there is no rename yet. `label` is free text for reports. `ranges`: the site's
  networks (the drift report labels devices there). `proxmox` (optional: a site may have only a NAS and a
  router) takes the same keys as the `proxmox:` block, with its own tokens (docs/proxmox-tokens.md, run on
  that site's Proxmox) and secrets entries.
- Inventory: each host is in at most one `site_<name>` group (`hosts.yml`); none = the default site. Once the
  default site has a name, the inventory drafts put its hosts in `site_<default>` too and
  `init_repo.py --add-site <default>` writes its `group_vars/site_<default>.yml`. Target a
  site with Ansible patterns: `-e target='site_offsite:&linux'`. Site settings (DNS, NTP, mirrors) go in
  `group_vars/site_<name>.yml` (`init_repo.py --add-site` writes it with `ansible_group_priority: 10`, so site
  settings win over OS groups on purpose). `check_env.py` and the drift report flag hosts in two site groups and
  groups with no site in homelab.yaml.
- Read-only: `proxmox_inventory.py --site offsite` → its part of `discovery/proxmox.json` (`--all-sites` reads
  each and carries on past an unreachable one); `proxmox_to_inventory.py --site offsite` drafts into `site_offsite`.
  The drift report covers every site (VMIDs are shown as `<site>/<vmid>`: they repeat across sites).
- `pve_snapshot.py --site offsite …`; without `--site` a guest named as its inventory host takes the site of its
  `site_<name>` group (VMIDs: the default site); patch-linux.yml uses the host's site by itself. `with_secrets.py <secret>`
  connects to the site whose tokens name that secret.
- Provisioning there: `init_repo.py --add-site offsite` (after the site is in homelab.yaml) scaffolds its
  OpenTofu environment `tofu/environments/offsite` (own state; fill `defaults` from `sites[offsite].proxmox`) and a
  `site.tf` in it and in the default environment: with_secrets.py tells OpenTofu the token's site, so a plan with
  the wrong site's token fails before touching that Proxmox. Then everything in opentofu.md with `--site offsite`
  (`tofu_init.py`, `tofu_to_inventory.py` → `tofu_hosts-offsite.yml`, hosts in `site_offsite`) and that site's
  tokens (`$W proxmox-offsite-rw $STATE -- tofu plan …`, from `tofu/environments/offsite`).
- VMIDs: `--next-vmid vms --site offsite` checks that site's snapshot and environment only (IDs repeat across
  sites). A site may set its own `vmid_ranges`, `vmid_scheme` and `templates` (build network) in its entry;
  otherwise the top-level ones apply. `network.vlans` entries name a `site` (a VLAN only there; `site: all` =
  every site on purpose; none = every site too): `--vlan <name>` resolves with the site's VLANs.
- Network scans: `nmap_scan.py [<ranges>] --site offsite` / `ssh_probe.py --site offsite` → its part of `discovery/network.json`.
  `ssh_probe.py <ip>` without `--site` files each address under its inventory host's site (else the site whose
  ranges hold it) and logs in as that host's `ansible_user`.
  `network.excluded_hosts` and `discovery.ignore_unmanaged` take `{ip: 10.0.0.5, site: offsite}` next to plain
  addresses (plain = every site) — needed when sites reuse the same private ranges. A named
  `ignore_unmanaged` entry (`{ip, name, mac}`) without `site` applies at every site.
- With two or more sites `check_env.py` (`sites:ambiguous`) and the drift report ("Site ambiguity") flag what
  "no site" leaves open: VLANs without a site, a VLAN name shared by entries not all tied to one site,
  overlapping or missing `ranges`, inventory hosts in no site group, `clusters:` groups across sites, plain
  excluded/ignored addresses inside ranges two sites share.
- Templates: templates.md "Another site". Node patching: patching.md "Patch Proxmox nodes" with `--site`.

## Cloud-init and SSH keys

Keys come from `defaults.ssh_public_keys` (agent public keys). Cloud-init user data only
applies at first boot, so key changes on existing VMs are an Ansible job (ansible.md),
not a tofu change — `user_account` is ignored after creation for that reason. First-boot extras (packages, a
runcmd) go in a vendor-data snippet (`cloud_init_snippet`, opentofu.md "Entry attributes"), not in the template.
