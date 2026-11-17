# Contributing

Thanks for helping with homelab-manager. The developer notes are in [CLAUDE.md](CLAUDE.md): plugin layout,
tests, template validation, releases.

## English only

This repository is English-only, so anyone can read, search and review it:

- code, identifiers, comments and docs;
- commit messages, pull request titles and descriptions;
- issues and comments.

The skill itself works in any language: users talk to it in their own language, and their
`homelab-infrastructure` repo uses theirs (`site.language`). Only what comes to this repository is English.
Skill issues filed with `issues.py` are written in English by Claude.

How it's checked:

- **Pull requests**: the *Language check* workflow runs `.github/check_english.py` on the lines a pull request
  adds, its commit messages, title and description. It flags letters outside English and text dominated by
  another language's function words. It can't tell a non-English identifier in plain ASCII (`pocet_hostov`)
  from an English one, so reviewers check names.
- **Issues**: the *Issue language* workflow labels issues that aren't English with `needs-english` and asks for
  an English version; the label goes away once the issue is edited.
- **Claude Code**: with the plugin enabled, `hooks/guard.py` denies non-English `gh issue`/`gh pr` text aimed at
  this repository.

Deliberate exceptions, such as test samples for the check itself: put `lang: allow` on the line, or, for a whole
file, its path in `.github/language-allowlist`. Run the check locally before pushing:

```bash
python3 .github/check_english.py diff origin/main HEAD
```
