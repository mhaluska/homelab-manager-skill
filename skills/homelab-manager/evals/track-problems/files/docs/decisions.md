# Decisions

| Date | Decision | Why |
|---|---|---|
| (init) | OpenTofu state outside Git: local file on the Mac (default) or an S3-compatible bucket | State holds sensitive data; never in Git. Local is simplest (back up with Time Machine); S3 adds locking and off-Mac copies |
| (init) | Two Proxmox tokens: read-only + provisioning | Discovery physically cannot change anything |
| (init) | Templates are immutable and versioned (`tpl-<distro><ver>-<date>`) | Updating a template never rebuilds existing VMs |
| (init) | Official cloud images imported by OpenTofu, customised by Packer `proxmox-clone` | No ISO installs to maintain |
| (init) | Secrets only in the macOS login keychain | No external secrets manager needed |
