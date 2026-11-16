# VM templates (Packer)

Two layers, both immutable:

1. **Base** — the official cloud image imported as a Proxmox template by OpenTofu
   (`base_images` in tfvars, VMIDs in `vmid_ranges.base_images`). Name `base-<distro><ver>-<date>`.
2. **Template** — Packer `proxmox-clone` of a base: updated packages, `qemu-guest-agent`,
   `cloud-init`, cleaned. Name `tpl-<distro><ver>-<date>`, VMIDs in `vmid_ranges.templates`.

VMs clone a specific template VMID; `clone` is ignored after creation, so a new template
never rebuilds existing VMs.

## Official images (verify URLs and checksums at build time — they move)

| Distro | Image | Checksums | Default user |
|---|---|---|---|
| Rocky 9 | `https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2` | `CHECKSUM` in same dir | `rocky` |
| Rocky 10 | `…/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2` | `CHECKSUM` | `rocky` |
| Debian 13 | `https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2` | `SHA512SUMS` | `debian` |
| Ubuntu 24.04 | `https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img` (qcow2) | `SHA256SUMS` | `ubuntu` |

Prefer a dated/versioned URL over `latest` in tfvars, and always set `checksum`, so the
base is reproducible. Fetch the checksum file with `curl -fsSL` (no secrets involved).

## Build or update a template ("Update the Rocky Linux Packer template")

1. Inspect: existing `tpl-rocky*` and `base-rocky*` (snapshot + `docs/templates.md`).
   Which VMs use which template is not tracked by Proxmox after cloning — use the
   `template_vm_id` values in tfvars.
2. Base still current? If the distro has a newer point release, add a new `base_images`
   entry (new name + VMID) → plan (`+2`: download + VM) → apply with approval.
   Otherwise reuse the existing base — package updates happen in Packer anyway.
3. Generate `packer/linux/site.pkrvars.hcl` from `homelab.yaml` (node, storage,
   `templates.build_network`). Build IP must be free: check `discovery/network.json` and
   ping it first.
4. Next template VMID in range, `build_date=$(date +%Y%m%d)`. If a template with that name
   already exists (second build today), append `-2`; never use `-force`.
5. ```bash
   cd packer/linux && packer init . && packer validate <vars> .
   python3 $HM/scripts/with_secrets.py proxmox-rw -- packer build <vars> .
   ```
   Builds take 5–15 minutes: run in the background and report when done.
6. Verify: template exists, agent enabled; optionally clone a throwaway test VM
   (with approval), check `cloud-init status`, `systemctl is-active qemu-guest-agent`, SSH,
   then destroy it (with approval).
7. Record a row in `docs/templates.md` (name, VMID, date, base, notes) and commit.
8. Existing VMs keep their old template. Offer — don't do — moving tfvars defaults for
   *new* VMs to the new template.

## Retiring templates

Keep `templates.keep_versions` per distro. A template may be deleted only when no tfvars
entry references its VMID and no linked clones exist (`--details` shows `base-…` disk
references). Deletion is an approval item. Bases follow the same rule against templates.

## Failures

- SSH timeout: build IP wrong/taken, bridge/VLAN wrong, or image default user mismatch.
- `403`: provisioning token lacks `VM.Clone`/`Datastore.AllocateSpace` on the storage.
- Cloud-init didn't run: base lacks a cloud-init drive — `cloud-image-base` adds one; a base
  created by hand might not.
- Packer leaves a half-built VM on failure: it's in the template VMID range; tell the user,
  delete with approval.
