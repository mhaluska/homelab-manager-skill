# homelab-infrastructure

Infrastructure as code for the homelab, operated conversationally through Claude Code
with the `homelab-manager` plugin.

| Path | Purpose |
|---|---|
| `homelab.yaml` | Site configuration: enabled components, networks, Proxmox endpoint, defaults, keychain item names |
| `ISSUES.md` | Problems found while managing the homelab; can be reported as GitHub issues |
| `discovery/` | Generated snapshots: `proxmox.json`, `network.json`, `updates.json`, `drift.md` |
| `packer/` | VM template builds (official cloud images → versioned templates) |
| `tofu/` | OpenTofu modules and environments (state on the Mac outside the repo, or in an S3 bucket — never in Git) |
| `ansible/` | Inventory, playbooks and roles for configuration and patching |
| `scripts/` | Repository helpers (git hooks) |
| `docs/` | Decisions, runbooks, Proxmox token setup |

Secrets live only in the macOS keychain of the management Mac; `homelab.yaml` names them.
