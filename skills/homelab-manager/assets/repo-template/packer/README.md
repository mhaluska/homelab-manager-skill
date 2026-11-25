# packer/

Versioned VM templates built from official cloud images.

1. OpenTofu imports the official cloud image as a **base** template (`tofu/…/homelab.auto.tfvars` → `base_images`).
2. Packer `proxmox-clone` clones the base, boots it with a temporary static IP, installs
   cloud-init + QEMU guest agent + updates, makes SSH key-only (`sshd_hardening`), sets automatic updates
   (`unattended_updates`: distro, security or off), cleans and trims it, and saves a **new** template
   `tpl-<distro><version>-<date>` with a new VMID. Existing templates are never overwritten.
3. The build is recorded in `docs/templates.md`.

```bash
cd packer/linux
packer init .
with_secrets.py proxmox-rw -- packer build -var-file=distros/rocky9.pkrvars.hcl -var-file=site.pkrvars.hcl \
  -var base_vm_id=9000 -var vm_id=9051 -var build_date=20261116 .
```
`site.pkrvars.hcl` (node, storage, build network, `sshd_hardening`, `unattended_updates`) is generated from
`homelab.yaml` (`templates:`) by the skill.
Another site (`sites:` in homelab.yaml) has its own `site-<name>.pkrvars.hcl` with `site = "<name>"`; build with
that site's token (`with_secrets.py <its provisioning secret>`) — a token of another site makes the build fail.
