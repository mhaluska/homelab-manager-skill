variable "name" { type = string }
variable "node" { type = string }
variable "vm_id" { type = number }
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
  type    = string
  default = "x86-64-v2-AES"
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
}
variable "bridge" { type = string }
variable "vlan_id" {
  type    = number
  default = null
}
variable "ipv4_address" {
  type        = string
  default     = "dhcp"
  description = "\"dhcp\" or CIDR, e.g. 10.0.10.21/24"
}
variable "ipv4_gateway" {
  type    = string
  default = null
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
  type    = string
  default = "Managed by OpenTofu (homelab-infrastructure)"
}
variable "started" {
  type    = bool
  default = true
}
variable "on_boot" {
  type    = bool
  default = true
}
