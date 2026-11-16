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
(Public GitHub repository, no SSH key or token needed.) Updates: once a day the plugin checks for a newer release and tells you; then run
`/plugin marketplace update homelab-manager-skill`. Release notes: [Releases](https://github.com/mhaluska/homelab-manager-skill/releases).

Then open Claude Code in an empty `homelab-infrastructure` repository and say e.g.
*"set up this repo for my homelab"*. The skill asks which parts you use (Proxmox/OpenTofu, Packer,
Ansible, discovery, Windows, appliances, Kubernetes), scaffolds only those, checks tools and keychain
access, and asks for the configuration it can't discover. Parts can be enabled later.

Problems the skill finds are recorded in `ISSUES.md` in that repository; ask *"open ISSUE-3 on GitHub"*
to turn one into a GitHub issue, or *"report issues to GitHub"* to send everything new since the
last report — matching GitHub issues get a comment instead of a duplicate (via `gh`, after you confirm).
Every issue follows one template (Summary, Affected, Evidence, Impact, Proposed fix, Verify), so
*"fix ISSUE-3"* can start straight from the evidence; the homelab repo gets a matching GitHub issue
form, and *"fix GitHub issue #12"* imports one you opened by hand.

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
| `hooks/update_check.py` | SessionStart hook: at most once a day, checks the Git remote for a newer `vX.Y.Z` tag and tells you |
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
  force-push, `curl | sh`, root or NSE nmap scans, creating/closing/commenting GitHub issues,
  GitHub API writes, labels, releases and repository settings; **denies** printing the `gh` token;
- scans **scripts that a command executes** with the same rules, so generated scripts can't bypass it.

It is defence in depth, not a sandbox: it inspects command text, so the restricted Proxmox
tokens and the user's review of plans remain the real boundaries.

## Requirements (checked by `check_env.py`)

macOS with Homebrew: `opentofu`, `hashicorp/tap/packer`, `ansible`, `nmap`, `yq`, `jq`, git, `gh` (for GitHub issues);
an SSH agent with the homelab key; auto-login (unlocked login keychain).

**macOS only (for now).** Secrets are read from the macOS login keychain (`security`), and setup,
environment checks and install hints assume macOS with Homebrew. Linux, and Windows via WSL2, would
need another secret store (e.g. `pass`, Secret Service or 1Password CLI); that is not supported yet.
The machines you *manage* can be anything: Linux, Windows and appliances.

## License

MIT — see [LICENSE](LICENSE).
