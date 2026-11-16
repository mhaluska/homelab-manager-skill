# homelab-manager-skill

Claude Code plugin that turns Claude into the infrastructure orchestrator for a personal
homelab: Proxmox VE, Packer templates, OpenTofu, Ansible, nmap discovery, drift detection
and patching — operated conversationally from the Claude desktop/mobile apps on a headless Mac
(the control machine must be macOS, see [Requirements](#requirements-checked-by-check_envpy)).

## Install

```
/plugin marketplace add mhaluska/homelab-manager-skill
/plugin install homelab-manager@homelab-manager-skill
```
(Public GitHub repository, no SSH key or token needed.)

**Which install scope?** Start Claude Code in your `homelab-infrastructure` repository (an empty
folder is fine for a first setup) and install there:

| Scope | Use it? | Why |
|---|---|---|
| **local** — *for you, in this repo only* | **Recommended** | Active only in the homelab repo. Setup then records the plugin in the repo's committed `.claude/settings.json`, so other clones of the repo offer to install it too. |
| project — *for all collaborators* | Fine | Writes the same committed `.claude/settings.json` right away; setup adds its safety rules to it. |
| user — *for you, everywhere* | Not recommended | The plugin's safety hook checks every shell command and the update check runs at every session start, so you'd get its approval prompts (force-push, reboots, `curl \| sh`, …) in unrelated projects too. |

Updates: once a day the plugin checks for a newer release and tells you; then run
`/plugin marketplace update homelab-manager-skill`. Release notes: [Releases](https://github.com/mhaluska/homelab-manager-skill/releases).
When an update changes what the plugin puts in your homelab repo, the next session tells you and
Claude applies it after you agree (`init_repo.py --sync-managed`).

Then open Claude Code in an empty `homelab-infrastructure` repository and say e.g.
*"set up this repo for my homelab"*. The skill asks which parts you use (Proxmox/OpenTofu, Packer,
Ansible, discovery, Windows, appliances, Kubernetes), scaffolds only those, checks tools and keychain
access, and asks for the configuration it can't discover. Parts can be enabled later.

Problems in your homelab (drift, audit findings, failed runs) are reported in chat and in
`discovery/drift.md` / `docs/security-audit-<date>.md`. Problems with **the skill itself** (a script
that crashes, the safety hook blocking something legitimate, wrong instructions, a template that
doesn't validate) are noted in `ISSUES.md` of your homelab repo; say *"report skill issues"* and
Claude sends them to [this repository's issues](https://github.com/mhaluska/homelab-manager-skill/issues)
with `gh`. Before anything is sent it redacts IPs, MACs, your domain, host and guest names, user
name and secrets, checks for an existing issue to comment on instead of duplicating, and shows you
the exact text. You can also open one by hand with the *Problem with the skill* form.

OpenTofu state never goes into Git: by default it is a file on the Mac outside the repository
(`~/.local/share/homelab/tofu-state/`); setup can instead put it in any S3-compatible bucket (MinIO, Garage, AWS).

## What's inside

| Path | |
|---|---|
| `skills/homelab-manager/SKILL.md` | Entry point: workflow, safety rules, routing |
| `skills/homelab-manager/references/` | Per-domain guides (discovery, proxmox, templates, opentofu, ansible, patching, windows/appliances, security) |
| `skills/homelab-manager/scripts/` | Stdlib-only Python helpers (inventory, scans, drift, secrets wrapper, env check, repo init) |
| `skills/homelab-manager/assets/repo-template/` | Scaffold for the `homelab-infrastructure` repository |
| `hooks/guard.py` | PreToolUse hook enforcing the hard safety rules |
| `hooks/skill_problem.py` | PostToolUse hook: when a bundled script crashes or fails, reminds Claude to note it in `ISSUES.md` right away |
| `hooks/update_check.py` | SessionStart hook: at most once a day, checks the Git remote for a newer `vX.Y.Z` tag and tells you; flags homelab repos that need a one-time update after a plugin upgrade |
| `agents/homelab-runner.md` | Subagent on the latest **Haiku** for fully specified commands/scripts |
| `agents/homelab-analyst.md` | Subagent on the latest **Sonnet** for delegated work that needs reasoning |
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
  force-push, `curl | sh`, root or NSE nmap scans, reporting skill issues, other GitHub issue writes,
  GitHub API writes, labels, releases and repository settings, adding a range to `authorized_ranges`;
  **denies** printing the `gh` token;
- scans **scripts that a command executes** with the same rules, so generated scripts can't bypass it.

It is defence in depth, not a sandbox: it inspects command text, so the restricted Proxmox
tokens and the user's review of plans remain the real boundaries.

## Requirements (checked by `check_env.py`)

macOS with Homebrew: `opentofu`, `hashicorp/tap/packer`, `ansible`, `nmap`, `yq`, `jq`, git, `gh` (to report skill issues);
an SSH agent with the homelab key; auto-login (unlocked login keychain).

**macOS only (for now).** Secrets are read from the macOS login keychain (`security`), and setup,
environment checks and install hints assume macOS with Homebrew. Linux, and Windows via WSL2, would
need another secret store (e.g. `pass`, Secret Service or 1Password CLI); that is not supported yet.
The machines you *manage* can be anything: Linux, Windows and appliances.

## License

MIT — see [LICENSE](LICENSE).
