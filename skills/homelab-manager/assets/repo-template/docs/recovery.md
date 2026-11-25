# Recovery

What to do when the management Mac, the OpenTofu state or the keychain items are lost, and how to prove a backup
can be restored. Each step that changes something (a Proxmox node, a guest, the keychain, a host, this repo) is
shown first and runs only after your yes; the skill's guard asks for the risky ones too.

## Keep ready (check now, not during a recovery)

| What | Where it is kept | Checked |
|---|---|---|
| This repository | its Git remote (`git.auto_push: true`, or push after each change) | |
| OpenTofu state | local: `~/.local/share/homelab/tofu-state/` covered by Time Machine; S3: bucket versioning on | |
| Keychain item values (`secrets:` in homelab.yaml) | a password manager, or "recreate at the source" (Proxmox tokens) | |
| SSH key for the hosts | a second authorized key kept offline, or the console of each host | |
| Proxmox `root@pam` login | password manager (needed to create new tokens) | |

## A lost Mac

1. Install the tools on the new Mac (Homebrew; `check_env.py` lists what is missing), Claude Code and the plugin:
   `/plugin marketplace add mhaluska/homelab-manager-skill`, `/plugin install homelab-manager@homelab-manager-skill`.
2. Clone this repository and turn its secret check back on: `git config core.hooksPath scripts/git-hooks`.
3. A new SSH key (`ssh-keygen -t ed25519`, `ssh-add`); put its public key on the hosts through the offline key or
   the console, then remove the lost Mac's key from every `authorized_keys` (an Ansible run, with your yes).
4. Rebuild the keychain items ("Rebuilding the keychain items" below).
5. OpenTofu state: S3 backend → `python3 $HM/scripts/tofu_init.py` finds it; local state → restore
   `~/.local/share/homelab/tofu-state/` from the Mac's backup, else "A lost OpenTofu state" below.
6. Check: `check_env.py --keychain`, `proxmox_inventory.py`, `tofu plan` in each environment (expect no changes),
   `ansible-playbook playbooks/ping.yml`.
7. Revoke what the lost Mac held, even though its keychain is encrypted: the old Proxmox tokens
   (`pveum user token remove homelab@pve <tokenid>` once the new ones work), the GitHub CLI login (github.com →
   Settings → Applications → Authorized OAuth Apps: revoke GitHub CLI, then `gh auth login` again), S3 keys, BMC
   and UniFi passwords. Note the date in `docs/decisions.md`.

## A lost OpenTofu state

The guests still run; OpenTofu just no longer knows it manages them.
1. Apply nothing: a plan without state wants to create every guest again.
2. Restore the state if any copy exists: Time Machine (local), an older object version (S3), then `tofu plan`.
3. Otherwise import each guest again (the skill's references/proxmox.md "Importing existing resources"): an
   `import {}` block per entry
   (`module.vm["<name>"].proxmox_virtual_environment_vm.this` / `module.lxc["<name>"]...container.this`,
   id `<node>/<vmid>`), the base images and backup jobs the same way.
4. `tofu plan` must show only imports, no add, no replace, no destroy; review any in-place change before applying.
5. Make sure the state is backed up from now on (table above).

## Rebuilding the keychain items

List them: `yq '.secrets' homelab.yaml` (service name and kind of each; the values were never in Git).
- Proxmox tokens: a token secret is shown only once, so make new tokens on a node (docs/proxmox-tokens.md, same
  roles and ACLs for the token and its user), store each:
  `security add-generic-password -U -T /usr/bin/security -a "$USER" -s <service> -w`, then remove the old ones.
  Give the new tokens an expiry (`--expire <epoch>`); `check_env.py` warns before it passes.
- S3 state keys, BMC, UniFi and other passwords: from the password manager, else reset them at the source.
- Check: `check_env.py --keychain` (every item readable, in the right format, no GUI prompt).

## Restore test (a backup is only good once restored)

Restore a copy of one guest beside the original, never over it. Each step runs after your yes.
1. Pick a guest and its newest backup: `proxmox_inventory.py --details` (last backup per guest), then on a node
   `pvesm list <backup storage> --vmid <vmid>` (read-only).
2. Pick a free VMID outside the OpenTofu ranges (`pvesh get /cluster/nextid`), and an isolated bridge: one without
   ports or uplink (e.g. `vmbr99` with `bridge-ports none`, added once on the node with your yes), so the copy
   cannot answer on the original's address.
3. Restore with new MAC addresses and without starting it:
   VM `qmrestore <backup> <new vmid> --unique 1 --storage <storage>`;
   container `pct restore <new vmid> <backup> --unique 1 --storage <storage>`.
4. Before the first boot, move every network interface to the isolated bridge and turn off start at boot:
   `qm set <new vmid> --net0 virtio,bridge=vmbr99 --onboot 0` (one `--netN` per interface; containers
   `pct set <new vmid> --net0 name=eth0,bridge=vmbr99,ip=dhcp --onboot 0`). Drop any PCI or USB passthrough.
5. Boot it (`qm start` / `pct start`) and check from the node: the console or `qm guest cmd <new vmid> ping`,
   that it boots to its services (`systemctl is-system-running`), and that the data is there and as recent as the
   backup (e.g. the newest files, a database row count).
6. Remove the copy: `qm stop <new vmid>` and `qm destroy <new vmid> --purge` (`pct` for a container). Read the
   VMID twice: it must be the copy.
7. Note the result below.

| Date | Guest | Backup | Result |
|---|---|---|---|
