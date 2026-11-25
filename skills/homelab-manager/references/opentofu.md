# OpenTofu

Layout: `tofu/modules/{proxmox-vm,proxmox-lxc,cloud-image-base}`, one environment per
directory under `tofu/environments/` (default `homelab`; another site: its name, proxmox.md "Several sites").
Provider: `bpg/proxmox`.
Desired state is data in `homelab.auto.tfvars`; edit data, not module calls. Besides guests and base images it
holds `lxc_templates` (proxmox.md "LXC containers") and `backup_jobs` (`backup-jobs.tf`, proxmox.md "Backup jobs").

## Entry attributes

Optional per `vms`/`containers` entry (the default is what the template always did, so leaving them out changes
nothing): `ipv4_gateway` (else `defaults.ipv4_gateway`; a guest on another VLAN needs its own), `on_boot` (true),
`protection` (false), `description`, `mac_address` (else Proxmox picks one; an imported guest keeps its own);
VMs also `cpu_type` (`x86-64-v2-AES`), `pci_devices` and `machine`
(proxmox.md "PCI passthrough"); containers `dns_servers`/`dns_domain` (else the node's DNS). `protection = true` sets the Proxmox protection flag: Proxmox refuses to delete the guest or
its disks, so a plan that destroys it fails at apply. Offer it for guests whose loss hurts (DNS, the NAS, the
state bucket); turning it off is its own change and plan.

Settings an imported guest keeps (`tofu_import_plan.py` sets them from the snapshot; left out, the module plans what
it always did). Both kinds: `startup = { order, up_delay, down_delay }` (seconds), the NIC's `firewall` and `mtu`.
VMs: `os_type` (`l26`; e.g. `win11`, `other`), `sockets`, `numa`, `cpu_flags` (`["+aes"]`),
`memory_floating_mib` (ballooning minimum), `scsi_hardware` (`virtio-scsi-single`), `tablet_device`, `agent_trim`
(fstrim after a disk move), `queues` (NIC multiqueue); the root disk's `disk_cache` (none), `disk_discard` (`on`),
`disk_iothread` (true), `disk_ssd` (true), `disk_backup` (false: backups skip it), and the same `cache`, `discard`,
`iothread`, `ssd`, `backup` per `extra_disks` item (default: discard on, iothread, no ssd flag). A VM that never
had cloud-init: `cloud_init_drive = false` (no drive; the address, DNS, admin user and snippets then don't apply,
the guest keeps its own), `serial_socket = false` (no serial0), `cdrom` (its drive on ide2: `"none"` or an ISO
file ID; only without the cloud-init drive, which uses ide2).
Containers: `keyctl`, `fuse`, `mknod`, `mount_types` (`["nfs", "cifs"]`) next to `nesting`; `features = false`
for no features line at all (a privileged container without one: Proxmox lets only root@pam change a privileged
container's features); `console_mode` (`tty`), `tty_count`, `console`; `mount_points`, a list numbered mp0, mp1,
... in order: `{ volume, path, size_gib, backup, read_only, mount_options, acl, quota, replicate, shared }`, where
`volume` is a storage for a new volume, the volume ID of an existing one (`tank:subvol-202-disk-1`) or a host path
for a bind mount (adding or changing one needs root@pam). Removing or reordering items changes the container's
mount points, and a removed volume's data may go with it: treat it like a disk change (approval).

IPv6 (both kinds): `ipv6_address` is `auto` (SLAAC), `dhcp` (DHCPv6) or address/prefix (`fd00:10::21/64`);
`ipv6_gateway` (else `defaults.ipv6_gateway`, often the router's link-local `fe80::1`) is used only with a static
address, since SLAAC and DHCPv6 take it from the router advertisement. Without `ipv6_address` the guest gets no
IPv6 settings (as before). On an existing VM it only changes the cloud-init drive, which the guest reads at a later
boot; read the plan and tell the user (a container gets it right away).

Several NICs (both kinds): the entry's `bridge`, `vlan_id`, `mac_address`, `ipv4_*`, `ipv6_*`, `firewall` and `mtu`
(VM `queues`) stay the first NIC (net0, a container's eth0); `extra_nics` lists the others, net1, net2, ... in
order: `{ bridge (else defaults.bridge), vlan_id, mac_address, firewall, mtu, ipv4_address, ipv4_gateway,
ipv6_address, ipv6_gateway }`, plus for a VM `model` (`virtio`; `e1000`, `e1000e`, `rtl8139`, `vmxnet3`), `queues`
and `disconnected` (link down), for a container `name` (else eth1, eth2, ... by position). An extra NIC's gateways
are its own, never the defaults; when the default route is on one of them, set the entry's `ipv4_gateway = ""` (no
gateway on the first NIC instead of `defaults.ipv4_gateway`). A VM's extra NIC addresses go to cloud-init
(ipconfig1, ...) and have none unless set; a container's extra interface gets `dhcp` unless set. The provider
numbers NICs by position, so there is no gap (net0, net2): inserting or removing an item renumbers the later NICs,
and a VM's guest may see a renumbered NIC as a new one (another PCI slot): add at the end, remove only with approval.

Cloud-init snippets (VMs): `cloud_init_snippet` names a file in `tofu/snippets/` (example:
`example-vendor-data.yaml`) passed as vendor data, which merges with the built-in user data, so the admin user
and keys keep working. `cloud_init_user_snippet` passes user data instead, which replaces the admin user and keys:
the file must create them itself, or the VM is locked out. Propose vendor data unless the user needs user data.
Both need `defaults.snippets_datastore` (homelab.yaml `proxmox.snippets_storage`, per site; a storage whose
content includes `snippets` in `discovery/proxmox.json`, else the user enables it: Datacenter → Storage → Edit →
Content) and SSH to the node (providers.tf, the agent's key). The file is uploaded as `vm-<vmid>-vendor-data.yaml`
(or `-user-data`), on the VM's node. Like the user account it counts at creation only: editing the file or the
attribute later changes nothing on the VM (Ansible does that). Removing the attribute from an existing VM deletes
the uploaded file the VM still points to, and Proxmox then can't rebuild its cloud-init drive (the VM may not
start): keep it in the entry for the VM's life.

The variables refuse a bad `ipv4_address` (not `dhcp` or address/prefix), a bad `ipv6_address` or `ipv6_gateway`,
`vlan_id` outside 1–4094, a VMID below 100, an extra disk on `scsi0` or an unknown bus, an `extra_nics` item with
a bad MAC, VLAN, address, model or a container interface name used twice (or eth0), and an unknown
`checksum_algorithm`; the error names the entry.
A static address without a gateway (on any NIC), or with one outside its subnet, is a warning in the plan ("Check
block assertion failed"): set the entry's `ipv4_gateway`, or tell the user the guest has no default route. So is
an IPv4 gateway on more than one NIC (several default routes).

## Running

Always through the secrets wrapper, from the environment directory. `$STATE` = the
`opentofu.state_secret` when `state_backend: s3`, nothing for local state (SKILL.md §5):
```bash
W="python3 $HM/scripts/with_secrets.py"
$W $STATE -- python3 $HM/scripts/tofu_init.py      # once, and after provider/backend changes (local: no $W needed)
tofu fmt -recursive ../../ && tofu validate        # no secrets needed
$W proxmox-rw $STATE -- tofu plan -out=plan.tfplan -no-color
$W proxmox-rw $STATE -- tofu apply plan.tfplan
rm plan.tfplan
```
- `-auto-approve` is denied by the guard. The saved plan is the approval artefact.
- Read-only questions (`plan -refresh-only`, `output`, `show`) can use `proxmox-ro`.
- `.terraform.lock.hcl` is committed; run `tofu init -upgrade` only on purpose, and say so.

## State

State holds resource details (and sometimes cloud-init data), so it never goes into Git.
`backend.tf` only names the backend type; `tofu_init.py` passes the settings from homelab.yaml.
- **local** (default): `~/.local/share/homelab/tofu-state/<site>/<env>.tfstate` on this Mac
  (`opentofu.local.path` overrides; with several environments it must contain `{env}`, as must a set
  `opentofu.s3.key` — tofu_init.py refuses otherwise), directory mode 700, file locking. Make sure Time Machine (or
  another backup) covers it; losing it means re-importing every resource (the repo's `docs/recovery.md`).
- **s3**: any S3-compatible bucket — MinIO, Garage, AWS (`opentofu.s3.*`), locking via a lockfile
  next to the state (`use_lockfile`), credentials `ACCESS_KEY_ID:SECRET_ACCESS_KEY` in the keychain
  (`homelab/s3-state`, kind `s3_credentials`). Turn on bucket versioning so old states can be restored.
- Switching backend: change `opentofu.state_backend`, then `tofu_init.py -- -migrate-state` — that
  moves state, so explain it and get a yes first. `tofu_init.py` rewrites `backend.tf` to match.
- Locked state: someone/something else is running. Do not `force-unlock` without approval and
  without checking nothing is running (`ps aux | grep tofu`).

## Plan review — detail

Classify each change. Common causes of unexpected **replace** with bpg:
| Attribute | Why it replaces | Fix |
|---|---|---|
| map key renamed | address changed | `moved { from = module.vm["a"] to = module.vm["b"] }` |
| `vm_id`, `node_name` (non-migratable) | identity | revert the change |
| disk shrink | impossible in place | revert, or approved rebuild |
| `clone` block | (ignored in our module) | check a hand-written resource didn't miss `ignore_changes` |
| LXC `operating_system`, `unprivileged` | container rebuild | revert, or approved rebuild |
| LXC `dns_servers`/`dns_domain` on an existing container | may rebuild with some provider versions | read the plan; revert unless a rebuild is approved |
A destroy or replace of a guest with `protection = true` fails at apply: turn protection off in a separate,
approved change first. A destroy of `…proxmox_virtual_environment_file.cloud_init` while its VM stays means a
snippet attribute was removed: put it back (the VM still uses the file).

Unexpected `~ update` on many resources usually means a provider upgrade or a default
changed — explain, don't apply blindly.

## Imports

Use `import {}` blocks (proxmox.md has the address/ID format). `tofu import` CLI and
`tofu state rm/mv` need approval (the guard asks). Never remove something from state
to "fix" a plan; that leaves an orphan resource.

## Adding modules

Only when a need repeats (e.g. Proxmox pools, SDN, firewall). Same conventions: module
owns one concern, variables typed and documented, `lifecycle.ignore_changes` for
attributes that must not trigger rebuilds, `tofu validate` + `fmt` clean, docs updated.
