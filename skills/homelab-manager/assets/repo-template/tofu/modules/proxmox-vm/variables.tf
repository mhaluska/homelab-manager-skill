variable "name" { type = string }
variable "node" { type = string }
variable "vm_id" {
  type = number
  validation {
    condition     = var.vm_id >= 100 && var.vm_id == floor(var.vm_id)
    error_message = "vm_id must be a whole number of 100 or more (Proxmox VMIDs start at 100)."
  }
}
variable "template_vm_id" {
  type        = number
  description = "VMID of the versioned template to clone. Changing it later does NOT rebuild the VM (ignored after creation)."
}
variable "template_node" {
  type    = string
  default = null
}
variable "cores" {
  type    = number
  default = 2
}
variable "cpu_type" {
  type     = string
  default  = "x86-64-v2-AES"
  nullable = false
}
variable "memory_mib" {
  type    = number
  default = 2048
}
variable "datastore" { type = string }
variable "disk_gib" {
  type        = number
  default     = 20
  description = "Can grow in place; shrinking forces replacement."
}
variable "extra_disks" {
  type    = list(object({ interface = string, size_gib = number, datastore = optional(string) }))
  default = []
  validation {
    condition     = alltrue([for d in var.extra_disks : can(regex("^(scsi([1-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5])$", d.interface))])
    error_message = "extra_disks interface must be scsi1-scsi30, virtio0-virtio15 or sata0-sata5 (scsi0 is the root disk)."
  }
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
variable "ipv6_address" {
  type        = string
  default     = null
  description = "null: no IPv6 settings (as before); \"dhcp\" (DHCPv6), \"auto\" (SLAAC) or CIDR, e.g. fd00:10::21/64"
  validation {
    condition     = var.ipv6_address == null || try(contains(["dhcp", "auto"], var.ipv6_address) || strcontains(var.ipv6_address, ":") && can(regex("/\\d{1,3}$", var.ipv6_address)) && can(cidrhost(var.ipv6_address, 0)), false)
    error_message = "ipv6_address must be \"dhcp\", \"auto\" (SLAAC) or an IPv6 address with its prefix length, e.g. fd00:10::21/64."
  }
}
variable "ipv6_gateway" {
  type        = string
  default     = null
  description = "Only with a static ipv6_address (dhcp and auto take the router's advertisement)."
  validation {
    condition     = var.ipv6_gateway == null || try(strcontains(var.ipv6_gateway, ":") && can(cidrhost("${var.ipv6_gateway}/128", 0)), false)
    error_message = "ipv6_gateway must be an IPv6 address without a prefix length, e.g. fe80::1."
  }
}
variable "dns_servers" {
  type    = list(string)
  default = []
}
variable "dns_domain" {
  type    = string
  default = null
}
variable "admin_user" { type = string }
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
