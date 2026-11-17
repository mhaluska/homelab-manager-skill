# Endpoint and API token come from PROXMOX_VE_ENDPOINT / PROXMOX_VE_API_TOKEN
# (with_secrets.py, secret "proxmox-rw"). Some operations (snippets upload, some
# disk imports) need SSH to the node; the provider then uses the local SSH agent.
provider "proxmox" {
  ssh {
    agent    = true
    username = var.proxmox_ssh_user
  }
}
