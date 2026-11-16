# GitLab-managed OpenTofu state. Address, lock URLs and the access token come from
# TF_HTTP_* environment variables set by with_secrets.py (secret "gitlab-state"),
# so nothing about the backend credentials is stored in this repository.
#
#   with_secrets.py gitlab-state -- tofu init
#   with_secrets.py proxmox-rw gitlab-state -- tofu plan -out=plan.tfplan
terraform {
  backend "http" {}
}
