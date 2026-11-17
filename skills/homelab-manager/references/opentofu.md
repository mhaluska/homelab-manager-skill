# OpenTofu

Layout: `tofu/modules/{proxmox-vm,proxmox-lxc,cloud-image-base}`, one environment per
directory under `tofu/environments/` (default `homelab`; another site: its name, proxmox.md "Several sites").
Provider: `bpg/proxmox`.
Desired state is data in `homelab.auto.tfvars`; edit data, not module calls.

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
  another backup) covers it; losing it means re-importing every resource.
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
