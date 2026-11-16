# OpenTofu

Layout: `tofu/modules/{proxmox-vm,proxmox-lxc,cloud-image-base}`, one environment per
directory under `tofu/environments/` (default `homelab`). Provider: `bpg/proxmox`.
Desired state is data in `homelab.auto.tfvars`; edit data, not module calls.

## Running

Always through the secrets wrapper, from the environment directory:
```bash
W="python3 $HM/scripts/with_secrets.py"
$W gitlab-state -- tofu init                       # once, and after provider changes
tofu fmt -recursive ../../ && tofu validate        # no secrets needed
$W proxmox-rw gitlab-state -- tofu plan -out=plan.tfplan -no-color
$W proxmox-rw gitlab-state -- tofu apply plan.tfplan
rm plan.tfplan
```
- `-auto-approve` is denied by the guard. The saved plan is the approval artefact.
- Read-only questions (`plan -refresh-only`, `output`, `show`) can use `proxmox-ro`.
- `.terraform.lock.hcl` is committed; run `tofu init -upgrade` only on purpose, and say so.

## State

- Default: GitLab-managed state (`backend "http" {}` configured by `TF_HTTP_*`).
  The project needs a token with `api` scope (Maintainer) stored as `homelab/gitlab-state`.
  GitLab keeps versions and locks; state never touches Git or the Mac's disk long-term.
- Locked state: someone/something else is running. Do not `force-unlock` without approval and
  without checking nothing is running (`ps aux | grep tofu`).
- `opentofu.state_backend: local` alternative: local state with OpenTofu state encryption
  (key via `TF_ENCRYPTION` from keychain) plus backups — only if GitLab isn't available.

## Plan review — detail

Classify each change. Common causes of unexpected **replace** with bpg:
| Attribute | Why it replaces | Fix |
|---|---|---|
| map key renamed | address changed | `moved { from = module.vm["a"] to = module.vm["b"] }` |
| `vm_id`, `node_name` (non-migratable) | identity | revert the change |
| disk shrink | impossible in place | revert, or approved rebuild |
| `clone` block | (ignored in our module) | check a hand-written resource didn't miss `ignore_changes` |
| LXC `operating_system`, `unprivileged` | container rebuild | revert, or approved rebuild |

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
