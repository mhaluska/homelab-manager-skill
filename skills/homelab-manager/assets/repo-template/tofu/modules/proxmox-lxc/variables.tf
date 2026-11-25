variable "hostname" { type = string }
variable "node" { type = string }
variable "vm_id" {
  type = number
  validation {
    condition     = var.vm_id >= 100 && var.vm_id == floor(var.vm_id)
    error_message = "vm_id must be a whole number of 100 or more (Proxmox VMIDs start at 100)."
  }
}
variable "template_file_id" {
  type        = string
  description = "e.g. local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst. Ignored after creation."
}
variable "os_type" {
  type    = string
  default = "debian"
}
variable "unprivileged" {
  type    = bool
  default = true
}
variable "nesting" {
  type    = bool
  default = true
}
variable "cores" {
  type    = number
  default = 1
}
variable "memory_mib" {
  type    = number
  default = 512
}
variable "swap_mib" {
  type    = number
  default = 512
}
variable "datastore" { type = string }
variable "disk_gib" {
  type    = number
  default = 8
}
variable "bridge" { type = string }
variable "vlan_id" {
  type    = number
  default = null
  validation {
    condition     = var.vlan_id == null || try(var.vlan_id >= 1 && var.vlan_id <= 4094 && var.vlan_id == floor(var.vlan_id), false)
    error_message = "vlan_id must be 1 to 4094, or null for no tag."
  }
}
variable "ipv4_address" {
  type        = string
  default     = "dhcp"
  description = "\"dhcp\" or CIDR, e.g. 10.0.10.21/24"
  validation {
    condition     = var.ipv4_address == "dhcp" || can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$", var.ipv4_address)) && can(cidrhost(var.ipv4_address, 0))
    error_message = "ipv4_address must be \"dhcp\" or an IPv4 address with its prefix length, e.g. 10.0.10.21/24."
  }
}
variable "ipv4_gateway" {
  type    = string
  default = null
}
variable "dns_servers" {
  type        = list(string)
  default     = []
  nullable    = false
  description = "Empty: the container uses the node's DNS settings."
}
variable "dns_domain" {
  type    = string
  default = null
}
variable "ssh_public_keys" { type = list(string) }
variable "tags" {
  type    = list(string)
  default = []
}
variable "description" {
  type     = string
  default  = "Managed by OpenTofu (homelab-infrastructure)"
  nullable = false
}
variable "started" {
  type    = bool
  default = true
}
variable "on_boot" {
  type     = bool
  default  = true
  nullable = false
}
variable "protection" {
  type        = bool
  default     = false
  nullable    = false
  description = "Proxmox protection flag: the guest and its disks can't be removed until it is turned off again."
}
