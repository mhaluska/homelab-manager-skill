# Decisions

| Date | Decision | Why |
|---|---|---|
| (init) | OpenTofu state in GitLab-managed state backend | Encrypted, locked, versioned, off the Mac Mini, never in Git |
| (init) | Two Proxmox tokens: read-only + provisioning | Discovery physically cannot change anything |
| (init) | Templates are immutable and versioned (`tpl-<distro><ver>-<date>`) | Updating a template never rebuilds existing VMs |
| (init) | Official cloud images imported by OpenTofu, customised by Packer `proxmox-clone` | No ISO installs to maintain |
| (init) | Secrets only in the macOS login keychain | No external secrets manager needed |
