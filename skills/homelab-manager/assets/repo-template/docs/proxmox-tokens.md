# Proxmox API tokens

Run on a Proxmox node as root (the skill shows these commands; you run them).
Token secrets are shown once — store them straight in the keychain of the management Mac.

Both tokens use privilege separation (`--privsep 1`): a token's effective rights are the
**intersection** of its own ACL and its user's ACL. So every role is granted twice — to the user
and to the token. Without the user ACL the tokens get nothing (403 on every call). The user has
no password, so it cannot log in; only its tokens are used. Check a token's effective rights with
`pveum user token permissions homelab@pve <tokenid>`.

## Read-only (discovery, drift)

```bash
pveum user add homelab@pve --comment "homelab-manager"
pveum user token add homelab@pve ro --privsep 1 --comment "read-only discovery"
pveum acl modify / --users homelab@pve --roles PVEAuditor
pveum acl modify / --tokens 'homelab@pve!ro' --roles PVEAuditor
```
Keychain value: `homelab@pve!ro=<secret>` →
`security add-generic-password -U -T /usr/bin/security -a "$USER" -s homelab/proxmox-ro -w`

Optional — VM IPs from the QEMU guest agent (`proxmox_inventory.py --details`, drift report's
guest ↔ network matching). PVEAuditor may not include the agent privilege; grant it if the
inventory says the agent IPs were not read (`VM.GuestAgent.Audit` on Proxmox VE 9, `VM.Monitor` on 8.x):
```bash
pveum role add HomelabAgentAudit -privs "VM.GuestAgent.Audit"
pveum acl modify /vms --users homelab@pve --roles HomelabAgentAudit
pveum acl modify /vms --tokens 'homelab@pve!ro' --roles HomelabAgentAudit
```

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
