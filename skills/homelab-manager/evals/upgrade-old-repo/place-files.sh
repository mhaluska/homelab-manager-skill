#!/usr/bin/env bash
# A repository scaffolded by an older plugin version, committed: files/ is that old template on purpose.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cp -R "$here/files/." .
git init -qb main
git -c user.name=Homelab -c user.email=homelab@example.com add -A
git -c user.name=Homelab -c user.email=homelab@example.com commit -qm "homelab-infrastructure"
git config core.hooksPath scripts/git-hooks
