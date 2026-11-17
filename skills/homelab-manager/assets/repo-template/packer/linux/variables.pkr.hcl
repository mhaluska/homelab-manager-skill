# Proxmox connection: PROXMOX_URL / PROXMOX_USERNAME / PROXMOX_TOKEN from with_secrets.py.
variable "insecure_skip_tls_verify" {
  type    = bool
  default = false
}

# --- distro (distros/*.pkrvars.hcl)
variable "distro" { type = string }         # rocky | debian | ubuntu
variable "distro_version" { type = string } # 9, 13, 2404, …
variable "ssh_username" { type = string }   # cloud image default user: rocky, debian, ubuntu

# --- site (site.pkrvars.hcl, generated from homelab.yaml; another site: site-<name>.pkrvars.hcl with `site`)
variable "site" {
  type    = string
  default = ""
}
variable "proxmox_site" { # set by with_secrets.py: the site of the Proxmox token
  type    = string
  default = ""
}
variable "node" { type = string }
variable "storage" { type = string }
variable "bridge" { type = string }
variable "build_ip" {
  type        = string
  description = "Static CIDR for the build VM, e.g. 10.0.10.250/24 (cloud images have no guest agent to report a DHCP address)."
}
variable "build_gateway" { type = string }

# --- per build
variable "base_vm_id" { type = number }
variable "vm_id" { type = number }
variable "build_date" { type = string } # YYYYMMDD, part of the template name
