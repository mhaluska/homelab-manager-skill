# Changelog

## 0.13.0 — 2026-11-17
- Fix ([#24](https://github.com/mhaluska/homelab-manager-skill/issues/24)): `issues.py add` with the key of an
  open entry now replaces its title, kind and body (the old title was kept) and says what changed; an `add`
  without a body keeps the recorded details and only refreshes Environment.
- Fix ([#21](https://github.com/mhaluska/homelab-manager-skill/issues/21)): `nmap_scan.py --profile os` no longer
  downgrades a `hypervisor` guess to `linux`. A product name that identifies the box (Proxmox, TrueNAS, iDRAC…)
  wins over generic Linux evidence, and `device_type_guess` is recomputed from everything known about the host,
  so a later scan never loses what an earlier one found. Re-run a scan to re-guess existing hosts.
- Fix ([#22](https://github.com/mhaluska/homelab-manager-skill/issues/22)): `check-updates.yml -e target=<group>`
  no longer rewrites `discovery/updates.json` with only that group. Results are merged: hosts checked now
  replace their entry, the others keep theirs, each with its own `collected_at`; hosts gone from the inventory
  are dropped. Existing repos: the upgrade advisor offers the new final play of the (user-owned) playbook.
- Onboarding existing hosts ([#20](https://github.com/mhaluska/homelab-manager-skill/issues/20)): new read-only
  `proxmox_to_inventory.py [--vlan N] [--range CIDR] [--type vm|lxc] [--node N]` drafts inventory entries
  (`ansible_host`, `proxmox_vmid/node/kind`) for running Linux guests in `discovery/proxmox.json` and lists
  the ones it skipped (non-Linux ostype, stopped, no IP, already managed). Nothing is written to `hosts.yml`.
  `check_env.py` flags hosts in an EL8-named group (`el8`, `rocky8`, `centos_stream8` …) without
  `ansible_python_interpreter` when the installed ansible-core (2.17+) can no longer use EL8's Python 3.6.

## 0.12.4 — 2026-11-17
- Fix ([#18](https://github.com/mhaluska/homelab-manager-skill/issues/18)): `nmap_scan.py --profile os` no longer
  ARP-sweeps through a local VM bridge whose router answers for every address. It scans from the interface
  `route get` gives for the targets (new `--interface/-e` overrides; targets on several interfaces must be
  scanned separately), adds `--disable-arp-ping` for targets behind a gateway, and refuses to merge a result
  where one MAC answered ARP for nearly every host (exit 5). Long scans print nmap's progress every 30 s.
  New `--only-live` scans only the hosts `network.json` already has inside the targets.
- Fix ([#19](https://github.com/mhaluska/homelab-manager-skill/issues/19)): the guard no longer reads the values
  of nmap options such as `--stats-every 30s`, `--min-hostgroup`, `--max-os-tries` or `--script-timeout` as
  scan targets, and `--script-timeout`/`--script-args` alone no longer count as running NSE scripts.

## 0.12.3 — 2026-11-17
- Discovery ([#17](https://github.com/mhaluska/homelab-manager-skill/issues/17)): `device_type_guess` recognises
  more management controllers from service banners (HP "Integrated Lights-Out", AMI MegaRAC, Lenovo XClarity,
  model numbers such as iDRAC9/iLO5) and uses factory-default reverse-DNS names (`uap-`, `usw-`, `udm-` … →
  `network`; `ilo-`, `idrac-`, `bmc-` … → `bmc`). The drift report marks BMCs among unmanaged devices.
  Re-run `nmap_scan.py --profile services` to re-guess existing hosts.

## 0.12.2 — 2026-11-17
- Fix ([#14](https://github.com/mhaluska/homelab-manager-skill/issues/14)): the optional guest-agent section of `docs/proxmox-tokens.md` granted `HomelabAgentAudit`
  on `/vms`. An ACL on a narrower path replaces the role inherited from `/`, so the read-only token lost
  `VM.Audit` and the inventory saw no guests. The section now says PVEAuditor already covers the guest agent
  on Proxmox VE 9, grants any extra role on `/` next to PVEAuditor, and shows how to undo the `/vms` grant.
  The upgrade advisor offers the section only when the inventory says agent IPs were not read, and flags
  docs that still have the `/vms` lines. `proxmox_inventory.py` warns when it sees no guests and names the
  ACL that hides them.
- Fix ([#15](https://github.com/mhaluska/homelab-manager-skill/issues/15)): `issues.py report` no longer redacts the word after "token:" (or "password:", …) in
  prose; with a colon only values that look like secrets are removed, and `Redacted:` counts the secrets.
  A closing quote after a redacted value is kept.
- Fix ([#16](https://github.com/mhaluska/homelab-manager-skill/issues/16)): `issues.py report <ID>` no longer moves the reported-through marker past other unsent
  entries. Each sent entry records `reported_at`, and an entry without a GitHub link is always offered, so
  ones the old behaviour skipped come back on the next `report`.
- Existing repos: if `docs/proxmox-tokens.md` has the `/vms` lines, `init_repo.py --sync-managed --dry-run`
  suggests replacing them and undoing the grant on Proxmox.

## 0.12.1 — 2026-11-17
- Fix ([#13](https://github.com/mhaluska/homelab-manager-skill/issues/13)): `issues.py fixed` missed an issue
  the installed release links when an older CHANGELOG section mentioned the same `#N` in prose (0.5.0's
  "fix GitHub issue #12" hid 0.12.0's fix of #12). Only real links count now (`[#N](…)`, `…/issues/N`), and
  any linking release newer than the entry's last-seen version marks it fixed, not just the oldest one.

## 0.12.0 — 2026-11-17
- Upgrade advisor ([#11](https://github.com/mhaluska/homelab-manager-skill/issues/11)): after a plugin upgrade
  `init_repo.py --sync-managed --dry-run` no longer answers "nothing to change" while a release has opt-in
  changes for the repo. Besides the one-time updates it applies itself, it lists **suggestions** (never
  applied by it): new homelab.yaml keys (`vmid_scheme`, with the scheme inferred from your existing VMIDs),
  template sections missing from your own docs (the guest-agent privilege in `docs/proxmox-tokens.md`),
  snapshots made by an older version to regenerate, and manual steps. They come from the machine-readable
  `assets/upgrade-notes.json`; `upgrade_notes.py [--all] [--json]` shows them alone. A real run records
  `upgrades.reviewed` in homelab.yaml so the same suggestions aren't offered again; new repos start reviewed.
  The session-start hook mentions pending suggestions too.
- Fixed skill issues ([#12](https://github.com/mhaluska/homelab-manager-skill/issues/12)): new
  `issues.py fixed [--apply] [--github]` finds reported entries whose GitHub issue the installed release's
  CHANGELOG links (newer than the version they were last seen with) and resolves them with `--apply`;
  `--github` also lists ones closed as completed but not in the installed release yet. `issues.py list`,
  `report --dry-run`, `--sync-managed` and the session-start hook point them out. Entries seen again now
  record the plugin version (`last_seen_version`), so a fix older than that isn't claimed.
- Existing repos: the next session offers the update; `upgrades.reviewed` is added to homelab.yaml on the
  first real `--sync-managed` run that shows suggestions.

## 0.11.0 — 2026-11-16
- Fix ([#9](https://github.com/mhaluska/homelab-manager-skill/issues/9)): the guard split commands on `|`, `;`
  and newlines even inside quotes and heredocs, so `grep -E "(tofu|nmap|yq)"` or an issue body mentioning nmap
  was refused as a scan with no targets. It now parses commands like the shell: quoted text, comments and
  heredoc bodies that are only data (`cat <<EOF > file`, `--body "$(cat <<'EOF' …)"`) are not commands.
  Heredocs a shell or interpreter runs (`bash <<EOF`, `cat <<EOF | sh`, `ssh host <<EOF`) are still checked,
  and now so are `bash -c '…'`, `eval …`, `ssh host '…'`, `$(…)`, backticks, subshells and `if`/`do` bodies.
  Redirections (`2>&1`, `> out.txt`) are no longer taken for nmap targets.
- Fix ([#8](https://github.com/mhaluska/homelab-manager-skill/issues/8)): the skill-problem hook blamed a bundled
  script for any Python traceback in the same command (e.g. an inline `python3 -c`). It now names a script only
  when the traceback runs through its file under `homelab-manager/scripts/`, and stays quiet otherwise.
- `issues.py report` redacts Proxmox identifiers ([#10](https://github.com/mhaluska/homelab-manager-skill/issues/10)):
  VMIDs, VLAN tags (any number after `VLAN`, `tag=`, `trunks=`, `vmbr0.`; known tags of 3+ digits anywhere),
  node, storage, pool and non-default bridge names from `discovery/proxmox.json`, as numbered placeholders
  (`<vmid-1>`, `<vlan-2>`, `<node-1>`) that stay the same across title, body and comments. The preview ends with
  a `Redacted: 2 VMIDs, 3 VLANs, …` line.
- Proxmox guests ↔ network discovery ([#7](https://github.com/mhaluska/homelab-manager-skill/issues/7)):
  `proxmox_inventory.py --details` reads the IPs running guests report (QEMU guest agent for VMs with
  `agent=1`, `/interfaces` for LXC). Without the agent privilege it records which one is missing
  (`VM.GuestAgent.Audit`, `VM.Monitor` on 8.x) instead of failing; `docs/proxmox-tokens.md` has an optional
  section granting it (existing repos: copy it from the plugin's template if you want VM IPs).
  `drift_report.py` has a new *Proxmox guests ↔ network* section matching scanned addresses to guests by
  config/agent IP, MAC and DNS name; matched guests no longer appear as unknown network devices.
- VMID conventions ([#6](https://github.com/mhaluska/homelab-manager-skill/issues/6)): optional `vmid_scheme`
  in homelab.yaml (e.g. `"{vlan}{octet:03d}"` → 1020015 for VLAN 1020, x.x.x.15) replaces `vmid_ranges` for VMs
  and LXC. `proxmox_inventory.py --next-vmid vms|lxc [--ip … --vlan …]` gives the ID for a new guest (scheme, or
  next free in range), checked against the snapshot and tfvars. The inventory summary warns when most existing
  VMIDs fall outside the ranges and suggests a scheme that explains them.

## 0.10.0 — 2026-11-16
- Fix ([#5](https://github.com/mhaluska/homelab-manager-skill/issues/5)): `docs/proxmox-tokens.md` granted
  the roles only to the privilege-separated tokens. A privsep token gets the intersection of its own and
  its user's rights, so both tokens had none (403 on every call). The template now grants each role to
  the user `homelab@pve` too and explains why. On a 403, `proxmox_inventory.py` reads the token's
  effective rights (`/access/permissions`) and prints the missing `pveum acl modify … --users …` command;
  a 401 now says the token or secret is wrong.
- Existing repos: `init_repo.py --sync-managed` adds the user ACL line above each token ACL line in
  `docs/proxmox-tokens.md` (keeping your paths and roles) and the explanation. Run the new lines on Proxmox.
- `check_env.py` checks the Proxmox certificate ([#4](https://github.com/mhaluska/homelab-manager-skill/issues/4)):
  Python uses OpenSSL's CA bundle, not the macOS keychain, so a private CA trusted in the keychain still
  failed with `CERTIFICATE_VERIFY_FAILED`. When the issuer is in the System or login keychain and
  verification passes with it, the check prints the `security find-certificate` export and the
  `config_set.py` command for `proxmox.ca_cert`; it also reports hostname mismatches. `proxmox.ca_cert`
  may now use `~` or a path relative to the repo root.

## 0.9.1 — 2026-11-16
- Fix ([#3](https://github.com/mhaluska/homelab-manager-skill/issues/3)): the `skill_issues.md` header
  refresh in `init_repo.py --sync-managed` dropped the `reported-through` marker, so `issues.py report`
  treated every open entry as never reported and could comment on GitHub issues a second time. The
  marker is now kept (it is only dropped for pre-0.6.0 files, where it belonged to the homelab's repo).
- Repos already synced with 0.9.0: `--sync-managed` restores the newest marker from the file's git
  history.

## 0.9.0 — 2026-11-16
- `skill_issues.md` now also collects **ideas to improve the skill**, as two new kinds: `improvement`
  (an existing script, flag, reference or template could work better) and `idea` (something missing).
  Claude notes one unasked when the work or the conversation shows it — a step done by hand that a
  script could do, a question or task no reference covers, an unsupported component or appliance, or
  the user's *"it would be nice if…"* / *"note an idea for the skill"* — written generically, never the
  site's own to-do list. Ideas have their own sections (Summary, Context, Proposal, optional Benefit;
  `issues.py template --kind idea`), are reported like problems (`[improvement]` / `[idea]` titles,
  `enhancement` label when the reporter may triage), and `issues.py list --ideas|--problems` filters them.
  This repository has a new *Idea for the skill* issue form.
- Existing repos: `init_repo.py --sync-managed` (offered by the session-start hook) refreshes the
  `skill_issues.md` header and updates the rule in CLAUDE.md and the row in README.md; entries are kept.

## 0.8.0 — 2026-11-16
- `ISSUES.md` is now **`skill_issues.md`**: the old name looked like the homelab repo's own issue list,
  but the file only holds problems with the homelab-manager skill. New repos get the new name.
- Existing repos: the session-start hook offers the one-time update, and `init_repo.py --sync-managed`
  renames the file (`git mv` when it is tracked, so its history follows), sets `issues.file`, and
  updates the mentions in the repo's CLAUDE.md and README.md. A custom `issues.file` is left alone.
  Until then `issues.py` keeps using the old `ISSUES.md`.

## 0.7.0 — 2026-11-16
- New `config_set.py` edits `homelab.yaml` without reflowing it ([#1](https://github.com/mhaluska/homelab-manager-skill/issues/1)): `yq -i` rewrote the whole file —
  blank lines and comment alignment were lost, and `authorized_ranges: [] # e.g. …` became a block list
  whose comment jumped to `gateway`. It changes only the lines of the keys it edits (`path=value`,
  `list+=item`, `list-=item`, `--delete`, `--dry-run`), keeps each inline comment on its key, and checks
  the result with yq before writing. Setup and `--sync-managed` use it too, so new repos keep the
  template's layout. Existing files that yq already reflowed stay as they are.
- Skill problems are logged when they happen, not only when you ask ([#2](https://github.com/mhaluska/homelab-manager-skill/issues/2)): SKILL.md makes it a rule to run
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
