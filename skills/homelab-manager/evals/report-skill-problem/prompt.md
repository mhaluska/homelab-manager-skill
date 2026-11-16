---
tags: [homelab-manager]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

drift_report.py just crashed for me with `KeyError: 'backup_jobs'` while checking dns01 (10.0.10.5). That's a bug in your skill — write it down and report it to the skill's GitHub.

Input files: (repository contents)
