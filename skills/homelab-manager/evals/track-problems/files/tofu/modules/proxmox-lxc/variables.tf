variable "hostname" { type = string }
variable "node" { type = string }
variable "vm_id" { type = number }
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
}
variable "ipv4_address" {
  type    = string
  default = "dhcp"
}
variable "ipv4_gateway" {
  type    = string
  default = null
}
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
