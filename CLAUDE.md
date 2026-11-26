# Developing homelab-manager-skill

- Plugin layout: repo root is both marketplace (`.claude-plugin/marketplace.json`) and plugin
  (`.claude-plugin/plugin.json`). Bump `version` in plugin.json and add a CHANGELOG entry for every release,
  then tag the release commit `vX.Y.Z` (annotated) and push the tag with `main`.
  `python3 .github/release.py X.Y.Z` does it all but the push: it dates a `## Unreleased` CHANGELOG section,
  bumps plugin.json, regenerates the template history when the template changed, runs the tests, commits
  `Release X.Y.Z` and tags; then `git push origin main vX.Y.Z`.
  Pushing the tag runs `.github/workflows/release.yml`: it checks plugin.json matches the tag and
  publishes a GitHub release with that version's CHANGELOG section (`.github/release_notes.py`).
  Run the unit tests locally before tagging (they target macOS). Push at most 3 tags at once.
- CHANGELOG sections (0.65.0 on) are written for people, not as a diff log; `release_notes.py` turns the
  section into the GitHub release and `tests/test_release_tools.py` checks the layout:
  ```
  ## 0.65.0 — 2026-11-27

  One or two sentences: what this release is about, in plain words.

  ### New | ### Improved | ### Fixed        (only the ones that have entries, in this order)
  - **What the user gets, as a short headline.** One to three plain sentences: what changes for them and when
    it matters. Script names and flags in backticks; internals only when the user acts on them.
    ([#123](https://github.com/mhaluska/homelab-manager-skill/issues/123))

  ### Upgrading                             (optional: what an existing repo needs, by hand or with a yes)
  ```
  One bullet per user-visible change, at most ~4 lines; detail belongs in `references/`, not here.
  `python3 .github/release_notes.py --lint` checks the top section; `release.py` refuses a section that fails it.
- A release that changes `assets/repo-template/` regenerates `assets/template-history.json`
  (`python3 .github/template_history.py`, needs the release tags locally) after the version bump; a test fails
  until it is current. `--sync-managed` replaces repo files that match a released template with no local edits.
- A release that adds something existing repos must adopt by hand (new homelab.yaml key, a section of a
  user-owned template doc, a snapshot format, a step on Proxmox) gets an entry in
  `skills/homelab-manager/assets/upgrade-notes.json`; changes `--sync-managed` can make itself go in
  `init_repo.upgrades()` instead.
- Hosting: GitHub (`mhaluska/homelab-manager-skill`, public). Issues via `gh`, never `glab`.
- Commits: use the identity in this clone's `git config user.name/user.email` (set by the maintainer).
- Scripts: Python 3 stdlib only (the target Mac has no pip packages); YAML via `yq`.
- Keep SKILL.md under ~250 lines; domain detail goes to `references/`, one file per domain, no duplication.
- Every guard rule change needs a test in `tests/test_guard.py`. Run `python3 -m unittest discover -s tests`.
- Template changes: `.github/validate_template.sh` scaffolds every component into a temp dir and runs
  `tofu validate`, `packer validate` (dummy PROXMOX_* env), `ansible-playbook --syntax-check`, `tofu fmt -check`,
  `packer fmt -check`. CI (`.github/workflows/tests.yml`) runs it and the unit tests on every push and PR.
- English only: code, identifiers, comments, docs, commit messages, issues and PRs. CI checks pull requests
  (`.github/check_english.py`); deliberate non-English samples get a `lang: allow` marker on the line.
- Never put real IPs, hostnames, tokens or site data in this repo — they belong in the user's
  `homelab-infrastructure/homelab.yaml`.
