# Changelog

## 0.7.0 — 2026-11-16
- New `config_set.py` edits `homelab.yaml` without reflowing it (#1): `yq -i` rewrote the whole file —
  blank lines and comment alignment were lost, and `authorized_ranges: [] # e.g. …` became a block list
  whose comment jumped to `gateway`. It changes only the lines of the keys it edits (`path=value`,
  `list+=item`, `list-=item`, `--delete`, `--dry-run`), keeps each inline comment on its key, and checks
  the result with yq before writing. Setup and `--sync-managed` use it too, so new repos keep the
  template's layout. Existing files that yq already reflowed stay as they are.
- Skill problems are logged when they happen, not only when you ask (#2): SKILL.md makes it a rule to run
  `issues.py add` in the same turn whenever Claude works around the skill; a new PostToolUse hook
  (`hooks/skill_problem.py`) reminds Claude when a bundled script crashes or fails; a guard denial says
  how to note a false alarm.
- Guard: asks before adding a range to `network.authorized_ranges` (`config_set.py` or `yq -i`), as the
  approval list already required.

## 0.6.0 — 2026-11-16
- `ISSUES.md` now tracks problems with **the skill itself** — a script that crashed or gave wrong
  results, the guard blocking something legitimate (or letting something dangerous through), a template
  that doesn't validate, wrong or missing instructions, setup trouble. *"Report skill issues"* sends
  them to this plugin's GitHub repository (`issues.py report`): it comments on an existing matching
  issue instead of duplicating, never creates labels, and redacts IP and MAC addresses, the site
  domain, host and guest names, the user name, home path and secrets first. `--dry-run` shows the
  exact text; the guard asks before anything is sent. Each entry gets an Environment section (plugin,
  macOS and tool versions, components). `issues.report: false` keeps everything local.
- Homelab problems (drift, audit findings, failed runs) are no longer tracked in a file: they are
  reported in chat and in `discovery/drift.md` / `docs/security-audit-<date>.md`.
- The homelab repo no longer gets a GitHub issue form; this repository has a *Problem with the skill* form.
- Existing repos: the session-start hook says when a repo needs a one-time update, and
  `init_repo.py --sync-managed` applies it after you agree — old ISSUES.md entries move to
  `docs/issues-archive.md`, the `issues:` block in homelab.yaml, the ISSUES.md rule in CLAUDE.md and
  README.md are updated, and the old plugin-managed issue form is removed (unless you edited it).
- Setup no longer asks about issue tracking.

## 0.5.2 — 2026-11-16
- Setup asks about components in two multi-select questions (core: Proxmox, Packer templates, Ansible,
  discovery; extras: Windows, appliances, Kubernetes), one checkbox per component — no more merged options
  that needed the free-text "Other" field.

## 0.5.1 — 2026-11-16
- Fix: when `.claude/settings.json` already existed in the homelab repo (e.g. the plugin was installed with
  project scope before setup), `init_repo.py` skipped it and the template's safety rules (never read private
  keys or state, ask before `tofu apply`/`packer build`) were lost. They are now merged in; existing rules stay.
- README: which install scope to choose (local recommended; user scope applies the safety hook everywhere).

## 0.5.0 — 2026-11-16
- Moved to GitHub: public repository `mhaluska/homelab-manager-skill`, install over HTTPS
  (`/plugin marketplace add mhaluska/homelab-manager-skill`).
- Issues go to GitHub with `gh`: `issues.py open` / `report` create issues,
  comment on matching ones, and create missing `severity:*` / `area:*` labels. `check_env.py` checks `gh auth status`.
- Guard: asks before `gh issue` writes, label/release/repo/secret changes and GitHub API writes; denies
  printing the `gh` token (`gh auth token`, `--show-token`).
- OpenTofu state: **local** state file on the Mac outside the repository (default)
  or any **S3-compatible** bucket (MinIO, Garage, AWS) with lockfile locking. New `tofu_init.py` runs
  `tofu init` with the backend from homelab.yaml; new secret kind `s3_credentials`.
- Releases: pushing a `vX.Y.Z` tag publishes a GitHub release with that version's CHANGELOG section.
- Template pre-commit hook also blocks GitHub tokens and AWS access keys.
- Issue template: every ISSUES.md entry and GitHub issue has Summary, Affected, Evidence, Impact,
  Proposed fix and Verify (`issues.py template`; missing sections are marked unknown), so a later session
  can fix it from the evidence. The homelab repo gets a matching GitHub issue form, kept current with
  `init_repo.py --sync-managed`. `issues.py pull <n>` imports a GitHub issue (owner/collaborators only
  unless `--any-author`) so "fix GitHub issue #12" works.
- License: MIT.

## 0.4.0 — 2026-11-16
- Update check: a SessionStart hook compares the installed version with the highest `vX.Y.Z` tag on
  the plugin's Git remote, at most once a day (cached in `~/.cache/homelab-manager/`, failed checks
  retried after 6 h), and tells the user when a newer release exists. `update_check.py --force` checks now.
- Cheaper subagents: `homelab-runner` (latest Haiku) for exactly specified commands and scripts,
  `homelab-analyst` (latest Sonnet) for delegated work that needs judgement. SKILL.md §10 says when to
  use which; subagents never approve anything.

## 0.3.0 — 2026-11-16
- `issues.py report`: sends issues added or changed since the last report to the issue tracker. For each it
  first looks for the same or a similar existing issue (same key, already linked, similar title; open or closed)
  and comments on it instead of creating a duplicate; otherwise creates one. `--dry-run` shows the
  plan; `--match`/`--new` override. On success a `reported-through` timestamp marker is written to
  ISSUES.md so old issues aren't reported again; failures leave the marker for a retry.
- Guard asks before `issues.py report` (except `--dry-run`).

## 0.2.0 — 2026-11-16
- Interactive setup: the skill asks which parts the homelab uses (Proxmox/OpenTofu, Packer templates, Ansible,
  discovery, Windows, appliances, Kubernetes), state backend and issue tracking, then scaffolds only those.
  `init_repo.py --components … / --add-components …`; choices recorded under `components:` in homelab.yaml.
- ISSUES.md: problems found (drift, audits, failed runs, config bugs) are recorded via `issues.py`
  (dedupe keys, severities, sanitised text) and can be opened in the issue tracker after the user agrees.
- Guard: asks before creating/closing tracker issues, API writes and `issues.py open`; denies printing the CLI token.
- check_env.py reports the issue-tracker CLI and its login.
- Patching: `patch_exclude` (set per group, e.g. kubelet/kubeadm/kubectl on k8s nodes) — dnf exclude / apt hold.
  Hook paths resolved with `path_join` (fixes an ansible-lint crash).
- Drift report: falls back to the `tofu` tag when state is unreachable; new Backups section (backup storage,
  vzdump jobs covering every guest). proxmox_inventory.py collects backup jobs (read-only).
- Report only what actually ran; skipped or assumed steps are labelled as such.

## 0.1.1 — 2026-11-16
- Fix: template pre-commit hook flagged its own source as a secret, so the first commit of a new repo failed.
- Fix: cluster hooks (k8s drain/uncordon) now run without sudo (`include_tasks … apply: become: false`);
  hook paths are relative to `ansible/` as written in homelab.yaml. Example k8s hooks added to the template.
- Add `kubernetes.core` to Ansible requirements; `patch-linux.yml --syntax-check` works without `-e target`.
- Scanning an authorized range the user asked for no longer needs a second confirmation.

## 0.1.0 — 2026-11-16
- Initial skill `homelab-manager`: orchestration workflow, approval rules, routing to 8 domain references.
- Read-only discovery: `proxmox_inventory.py`, scope-checked `nmap_scan.py`, `drift_report.py`.
- `check_env.py` with keychain self-test; `with_secrets.py` keychain → env with output redaction.
- `init_repo.py` + repository template: homelab.yaml, OpenTofu modules (VM, LXC, cloud-image base; bpg/proxmox ≥ 0.122),
  remote OpenTofu state backend, Packer proxmox-clone template build (Rocky/Debian/Ubuntu), Ansible inventory,
  check-updates and rolling patch playbooks, secret-blocking pre-commit hook.
- `hooks/guard.py` PreToolUse safety hook with unit tests.
