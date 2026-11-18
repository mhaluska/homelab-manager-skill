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
   entry until updates are only cosmetic (tags, description) and there is **no replace**.
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
- **Token rights**: editing a job needs `Datastore.Allocate` on the job's storage (plus `VM.Backup` on the
  pool for pool jobs); the provisioning role doesn't have it, so the API answers 403. Offer the optional grant
  in `docs/proxmox-tokens.md` ("Backup jobs") — the user runs it on a node — or the GUI instead:
  Datacenter → Backup → the job → Edit → add the guests. Re-run `proxmox_inventory.py` and drift afterwards.

## Several sites

A site is a location: home, a rented server, family's house reached over VPN. One site needs nothing (no
`sites:`). For more, list them in homelab.yaml, the default site first; its Proxmox is the `proxmox:` block or
`sites[0].proxmox` (one of the two, the same keys):
```bash
config_set.py 'sites+={name: home}'      # first time only: name the existing site
config_set.py 'sites+={name: offsite, label: Rented server, ranges: [192.0.2.0/24], proxmox: {endpoint: "https://…:8006", tokens: {read_only: proxmox-offsite-ro, provisioning: proxmox-offsite-rw}}}'
```
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
- Read-only: `proxmox_inventory.py --site offsite` → `discovery/proxmox-offsite.json` (`--all-sites` reads each
  and carries on past an unreachable one); `proxmox_to_inventory.py --site offsite` drafts into `site_offsite`.
  The drift report covers every site (VMIDs are shown as `<site>/<vmid>`: they repeat across sites).
- `pve_snapshot.py --site offsite …`; patch-linux.yml uses the host's site by itself. `with_secrets.py <secret>`
  connects to the site whose tokens name that secret.
- Provisioning there: `init_repo.py --add-site offsite` (after the site is in homelab.yaml) scaffolds its
  OpenTofu environment `tofu/environments/offsite` (own state; fill `defaults` from `sites[offsite].proxmox`) and a
  `site.tf` in it and in the default environment: with_secrets.py tells OpenTofu the token's site, so a plan with
  the wrong site's token fails before touching that Proxmox. Then everything in opentofu.md with `--site offsite`
  (`tofu_init.py`, `tofu_to_inventory.py` → `tofu_hosts-offsite.yml`, hosts in `site_offsite`) and that site's
  tokens (`$W proxmox-offsite-rw $STATE -- tofu plan …`, from `tofu/environments/offsite`).
- VMIDs: `--next-vmid vms --site offsite` checks that site's snapshot and environment only (IDs repeat across
  sites). A site may set its own `vmid_ranges`, `vmid_scheme` and `templates` (build network) in its entry;
  otherwise the top-level ones apply. `network.vlans` entries may name a `site` (a VLAN only there; none = every
  site): `--vlan <name>` resolves with the site's VLANs.
- Templates: templates.md "Another site". Node patching: patching.md "Patch Proxmox nodes" with `--site`.

## Cloud-init and SSH keys

Keys come from `defaults.ssh_public_keys` (agent public keys). Cloud-init user data only
applies at first boot, so key changes on existing VMs are an Ansible job (ansible.md),
not a tofu change — `user_account` is ignored after creation for that reason.
