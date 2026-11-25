# Proxmox API tokens

Run on a Proxmox node as root (the skill shows these commands; you run them).
Token secrets are shown once — store them straight in the keychain of the management Mac.

Both tokens use privilege separation (`--privsep 1`): a token's effective rights are the
**intersection** of its own ACL and its user's ACL. So every role is granted twice — to the user
and to the token. Without the user ACL the tokens get nothing (403 on every call). The user has
no password, so it cannot log in; only its tokens are used. Check a token's effective rights with
`pveum user token permissions homelab@pve <tokenid>`.

Several sites (`sites:` in homelab.yaml): run the same steps on each site's Proxmox, store its tokens under
their own keychain items and secrets names (e.g. `proxmox-offsite-ro`), and name those in the site's
`proxmox.tokens`.

## Read-only (discovery, drift)

```bash
pveum user add homelab@pve --comment "homelab-manager"
pveum user token add homelab@pve ro --privsep 1 --comment "read-only discovery"
pveum acl modify / --users homelab@pve --roles PVEAuditor
pveum acl modify / --tokens 'homelab@pve!ro' --roles PVEAuditor
```
Keychain value: `homelab@pve!ro=<secret>` →
`security add-generic-password -U -T /usr/bin/security -a "$USER" -s homelab/proxmox-ro -w`
PVEAuditor also covers the storage health OVERVIEW.md shows (ZFS pools, disk SMART and wear, replication, Ceph:
`Sys.Audit`); the PBS datastores need a PBS token (last section).

Optional — VM IPs from the QEMU guest agent (`proxmox_inventory.py --details`, drift report's
guest ↔ network matching). On Proxmox VE 9 PVEAuditor already includes `VM.GuestAgent.Audit`: nothing
to do. Only if the inventory says the agent IPs were not read (`guest_ip_sources.agent` is not `ok`, e.g.
on 8.x, which needs `VM.Monitor`), add a role **on `/`, next to PVEAuditor**:
```bash
pveum role add HomelabAgentAudit -privs "VM.Audit VM.GuestAgent.Audit"   # 8.x: "VM.Audit VM.Monitor"
pveum acl modify / --users homelab@pve --roles HomelabAgentAudit
pveum acl modify / --tokens 'homelab@pve!ro' --roles HomelabAgentAudit
```
Never grant it on a narrower path (`/vms`, `/pool/…`) alone: an ACL on a more specific path replaces the
role inherited from `/`, so the token loses `VM.Audit` there and the inventory sees no guests. Undo the
`/vms` grant an older version of this doc suggested:
`pveum acl delete /vms --users homelab@pve --roles HomelabAgentAudit` and the same with
`--tokens 'homelab@pve!ro'`.

## Provisioning (OpenTofu, Packer)

```bash
pveum role add HomelabProvisioner -privs "Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit \
  Pool.Audit SDN.Use Sys.Audit Sys.Modify \
  VM.Allocate VM.Audit VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType \
  VM.Config.Memory VM.Config.Network VM.Config.Options VM.Console VM.Migrate VM.PowerMgmt VM.Snapshot"
pveum user token add homelab@pve rw --privsep 1 --comment "provisioning"
pveum acl modify / --users homelab@pve --roles HomelabProvisioner
pveum acl modify / --tokens 'homelab@pve!rw' --roles HomelabProvisioner
```
`Sys.Modify` is needed only for downloading cloud images to storage (download-url); you can drop it
and download images manually if you prefer the token not to have it.
Privilege names change between Proxmox releases (e.g. `VM.Monitor` was removed in 9.x);
if `pveum role add` rejects one, drop it and note it here.
Keychain service: `homelab/proxmox-rw`.

Narrow it further by granting the ACLs (user and token) on a pool (`/pool/homelab`) and specific
storages instead of `/` once the layout is settled.

### Backup jobs (optional)

Only if the skill should manage vzdump backup jobs (`proxmox_backup_job`, adding unbacked guests the drift
report finds). Creating or editing a job needs `Datastore.Allocate` on the job's storage: it also lets the token
change or remove that storage's definition, so grant it on the backup storage only, never on `/`. An ACL on
a more specific path replaces the role inherited from `/` there, so the role carries the provisioning
storage rights too:
```bash
pveum role add HomelabBackupJobs -privs "Datastore.Allocate Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit"
pveum acl modify /storage/<backup-storage> --users homelab@pve --roles HomelabBackupJobs
pveum acl modify /storage/<backup-storage> --tokens 'homelab@pve!rw' --roles HomelabBackupJobs
```
Pool-based jobs also need `VM.Backup` on `/pool/<pool>`. Without this grant, edit jobs in the GUI
(Datacenter → Backup).

### PCI passthrough (optional)

Only for VMs with `pci_devices` (a GPU, NIC or HBA through a resource mapping, Datacenter → Resource Mappings).
Using a mapping needs `Mapping.Use` on it; grant it per mapping, `<mapping>` being its ID (e.g. `gpu`):
```bash
pveum role add HomelabMappingUse -privs "Mapping.Use"
pveum acl modify /mapping/pci/<mapping> --users homelab@pve --roles HomelabMappingUse
pveum acl modify /mapping/pci/<mapping> --tokens 'homelab@pve!rw' --roles HomelabMappingUse
```
Raw PCI IDs (no mapping) need `root@pam`; the skill doesn't use them.

## Proxmox Backup Server (optional, read-only)

Only if OVERVIEW.md should check the PBS datastores behind your `pbs` storages: GC, prune and verify job runs and
snapshots waiting for verification (`proxmox_inventory.py`). The Proxmox VE token can't read them. Run on each PBS
as root; the role `DatastoreAudit` only reads (no backup, restore, prune or delete). As on Proxmox VE, grant it to
the user and to the token:
```bash
proxmox-backup-manager user create homelab@pbs --comment "homelab-manager"
proxmox-backup-manager user generate-token homelab@pbs ro
proxmox-backup-manager acl update /datastore DatastoreAudit --auth-id homelab@pbs
proxmox-backup-manager acl update /datastore DatastoreAudit --auth-id 'homelab@pbs!ro'
```
Check with `proxmox-backup-manager user permissions 'homelab@pbs!ro' --path /datastore`.
Keychain value: `homelab@pbs!ro:<secret>` →
`security add-generic-password -U -T /usr/bin/security -a "$USER" -s homelab/pbs-ro -w`; then in homelab.yaml
`secrets.pbs-ro: {service: homelab/pbs-ro, kind: pbs_token}` and `pbs: [{server: <address>, token: pbs-ro}]`, with
the server as the Proxmox storage names it. The PBS certificate is checked against the fingerprint that storage
pins (as Proxmox VE does); a PBS with a certificate from your own CA can set `ca_cert` in its `pbs:` entry instead.
Several PBS hosts: one token and secret each.
