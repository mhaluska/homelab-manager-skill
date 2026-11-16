---
tags: [homelab-manager]
max_turns: 40
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

Set up this repo for my homelab. I only use Proxmox (with OpenTofu) and Ansible for my Linux servers — no Packer, no Kubernetes, no Windows, no appliances. Keep the OpenTofu state in GitLab, and I want problems tracked as GitLab issues with glab.

Input files: (repository contents)
