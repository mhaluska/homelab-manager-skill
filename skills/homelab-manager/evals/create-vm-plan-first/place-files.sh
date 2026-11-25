#!/usr/bin/env bash
# The current repo template (init_repo.py), this case's homelab.yaml values merged in, then its own files over
# it (inventory, tfvars, discovery data). Template files stay out of files/, so the case always runs on today's template.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
python3 "$here/../../scripts/init_repo.py" . >/dev/null   # every component
yq -i '. *= load("'"$here"'/homelab-values.yaml")' homelab.yaml
[ ! -d "$here/files" ] || cp -R "$here/files/." .
rm -rf .git   # this case runs outside a Git repository
