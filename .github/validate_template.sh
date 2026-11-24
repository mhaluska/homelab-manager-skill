#!/usr/bin/env bash
# Scaffold the repo template with every component into a temporary directory and validate it:
# tofu fmt/validate, packer fmt/validate (each distro var file), ansible-playbook --syntax-check.
#
#     .github/validate_template.sh [--keep]
#
# Needs tofu, packer, ansible-playbook, yq and network access for `tofu init` and `packer init` (providers and
# plugins). Ansible collections from requirements.yml must be installed (CI installs them; locally:
# ansible-galaxy collection install -r <scaffold>/ansible/requirements.yml). Exit 0 when every check passes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
[ "${1:-}" = "--keep" ] || trap 'rm -rf "$WORK"' EXIT
REPO="$WORK/repo"
fail=0
step() { echo "== $*"; }
check() { if ! "$@"; then echo "FAILED: $*" >&2; fail=1; fi; }

step "scaffold"
python3 "$ROOT/skills/homelab-manager/scripts/init_repo.py" "$REPO" \
  --components proxmox,templates,ansible,discovery,windows,appliances,kubernetes >/dev/null

step "OpenTofu"
check tofu fmt -check -recursive "$REPO/tofu"
for env in "$REPO"/tofu/environments/*/; do
  check tofu -chdir="$env" init -backend=false -input=false >/dev/null
  check tofu -chdir="$env" validate
done

step "Packer"
export PROXMOX_URL=https://192.0.2.10:8006/api2/json PROXMOX_USERNAME='ci@pve!ci' PROXMOX_TOKEN=00000000-0000-0000-0000-000000000000
# per-site and per-build values the skill passes from homelab.yaml (documentation addresses only)
site_vars=(-var node=pve1 -var storage=local-lvm -var bridge=vmbr0 -var build_ip=192.0.2.250/24
           -var build_gateway=192.0.2.1 -var base_vm_id=9000 -var vm_id=9100 -var build_date=20260101)
check packer fmt -check -recursive "$REPO/packer"
for dir in "$REPO"/packer/*/; do
  [ -n "$(ls "$dir"/*.pkr.hcl 2>/dev/null)" ] || continue
  check packer init "$dir" >/dev/null
  vars=("$dir"distros/*.pkrvars.hcl)
  if [ -e "${vars[0]}" ]; then
    for v in "${vars[@]}"; do check packer validate "${site_vars[@]}" -var-file="$v" "$dir"; done
  else
    check packer validate "${site_vars[@]}" "$dir"
  fi
done

step "Ansible"
cd "$REPO/ansible"
for pb in playbooks/*.yml; do
  if ! ansible-playbook --syntax-check -i inventory "$pb" >/dev/null 2>"$WORK/ansible.err"; then
    cat "$WORK/ansible.err" >&2; echo "FAILED: syntax check of $pb" >&2; fail=1
  fi
done

[ "$fail" = 0 ] && echo "template OK" || echo "template checks failed" >&2
exit "$fail"
