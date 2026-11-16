# homelab-manager-skill

Claude Code plugin that turns Claude into the infrastructure orchestrator for a personal
homelab: Proxmox VE, Packer templates, OpenTofu, Ansible, nmap discovery, drift detection
and patching — operated conversationally from the Claude desktop/mobile apps on a headless Mac.

## Install

```
/plugin marketplace add https://github.com/mhaluska/homelab-manager-skill.git
/plugin install homelab-manager@homelab-manager-skill
```
(Private repo: the Mac's SSH agent needs a key with read access to it.)

Then open Claude Code in an empty `homelab-infrastructure` repository and say e.g.
*"set up this repo for my homelab"*. The skill asks which parts you use (Proxmox/OpenTofu, Packer,
Ansible, discovery, Windows, appliances, Kubernetes), scaffolds only those, checks tools and keychain
access, and asks for the configuration it can't discover. Parts can be enabled later.

Problems the skill finds are recorded in `ISSUES.md` in that repository; ask *"open ISSUE-3 on GitLab"*
to turn one into a GitLab issue, or *"report issues to GitLab"* to send everything new since the
last report — matching GitLab issues get an update note instead of a duplicate (via `glab`, after you confirm).

## What's inside

| Path | |
|---|---|
| `skills/homelab-manager/SKILL.md` | Entry point: workflow, safety rules, routing |
| `skills/homelab-manager/references/` | Per-domain guides (discovery, proxmox, templates, opentofu, ansible, patching, windows/appliances, security) |
| `skills/homelab-manager/scripts/` | Stdlib-only Python helpers (inventory, scans, drift, secrets wrapper, env check, repo init) |
| `skills/homelab-manager/assets/repo-template/` | Scaffold for the `homelab-infrastructure` repository |
| `hooks/guard.py` | PreToolUse hook enforcing the hard safety rules |
| `tests/` | Unit tests (`python3 -m unittest discover -s tests`) |
| `skills/homelab-manager/evals/` | Behaviour test cases (`claude plugin eval`) |

## Safety model

Guidance in the skill, enforcement in the hook. `hooks/guard.py` runs before every Bash
command Claude issues (in any project, while the plugin is enabled) and:

- **denies**: nmap targets outside `network.authorized_ranges` (or any nmap with no config —
  asks outside a homelab repo), `-iR`/decoys, `tofu/terraform … -auto-approve`, printing keychain
  secrets (`security … -w`), reading private SSH keys;
- **asks the user**: `tofu apply` without a saved plan or whose plan deletes/replaces, destroy,
  state edits, imports, `qm`/`pct`/`pvesh`/`ha-manager`/`pvesm` writes, ZFS destroy, Proxmox API
  writes, reboots/shutdowns, patch/upgrade playbooks outside `--check`, `packer build -force`,
  force-push, `curl | sh`, root or NSE nmap scans, creating/closing GitLab issues;
- scans **scripts that a command executes** with the same rules, so generated scripts can't bypass it.

It is defence in depth, not a sandbox: it inspects command text, so the restricted Proxmox
tokens and the user's review of plans remain the real boundaries.

## Requirements (checked by `check_env.py`)

macOS with Homebrew: `opentofu`, `hashicorp/tap/packer`, `ansible`, `nmap`, `yq`, `jq`, git, `glab` (for GitLab issues);
an SSH agent with the homelab key; auto-login (unlocked login keychain).
