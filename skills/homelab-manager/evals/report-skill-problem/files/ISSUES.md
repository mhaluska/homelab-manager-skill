# Issues with the homelab-manager skill

Problems with the **skill itself** — a script that crashed or gave wrong results, the safety hook
blocking something legitimate (or letting something dangerous through), a template that doesn't
validate, instructions that were wrong or missing, a setup step that misbehaved. They can be sent
to the plugin's GitHub repository so they get fixed.

Problems in the homelab (drift, audit findings, failed runs) are not tracked here: Claude reports
them in chat and in `discovery/drift.md` / `docs/security-audit-<date>.md`.

- Note one: *"the skill got X wrong, write it down"* — Claude adds it with `issues.py`.
- Send new/changed ones: *"report skill issues"* — sanitised (no IPs, host names, user names,
  secrets), checked against existing GitHub issues first, shown to you before anything is sent.
- Managed by `issues.py`; edit the text under an issue freely, keep the `<!-- issue … -->` lines.


| ID | Kind | Title | Status | GitHub |
|---|---|---|---|---|
| — | | No issues recorded yet. | | |
