# OpenTofu state backend: local. Never stored in Git.
# Settings come from homelab.yaml (opentofu.*) via scripts — don't edit them in here:
#   python3 $HM/scripts/tofu_init.py
terraform {
  backend "local" {}
}
