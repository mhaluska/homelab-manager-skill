# Developing homelab-manager-skill

- Plugin layout: repo root is both marketplace (`.claude-plugin/marketplace.json`) and plugin
  (`.claude-plugin/plugin.json`). Bump `version` in plugin.json and add a CHANGELOG entry for every release,
  then tag the release commit `vX.Y.Z` (annotated) and push the tag with `main`.
  Pushing the tag runs `.github/workflows/release.yml`: it checks plugin.json matches the tag and
  publishes a GitHub release with that version's CHANGELOG section (`.github/release_notes.py`).
  Run the unit tests locally before tagging (they target macOS). Push at most 3 tags at once.
- Hosting: GitHub (`mhaluska/homelab-manager-skill`, public). Issues via `gh`, never `glab`.
- Commits: use the identity in this clone's `git config user.name/user.email` (set by the maintainer).
- Scripts: Python 3 stdlib only (the target Mac has no pip packages); YAML via `yq`.
- Keep SKILL.md under ~250 lines; domain detail goes to `references/`, one file per domain, no duplication.
- Every guard rule change needs a test in `tests/test_guard.py`. Run `python3 -m unittest discover -s tests`.
- Template changes: scaffold into a temp dir and run `tofu validate`, `packer validate`
  (dummy PROXMOX_* env), `ansible-playbook --syntax-check`, `tofu fmt -check`, `packer fmt -check`.
- Never put real IPs, hostnames, tokens or site data in this repo — they belong in the user's
  `homelab-infrastructure/homelab.yaml`.
