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
variable "mac_address" {
  type        = string
  default     = null
  description = "MAC address of the NIC; empty: Proxmox picks one. An imported guest keeps its own (tofu_import_plan.py)."
  validation {
    condition     = var.mac_address == null || can(regex("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", var.mac_address))
    error_message = "mac_address must be six hex pairs separated by colons, e.g. BC:24:11:0A:00:15."
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

# Settings an imported container keeps (tofu_import_plan.py). Each default plans what earlier versions planned.
variable "features" {
  type        = bool
  default     = true
  nullable    = false
  description = "false: no features line (nesting and the other flags ignored), as on a privileged container without one."
}
variable "keyctl" {
  type    = bool
  default = null
}
variable "fuse" {
  type    = bool
  default = null
}
variable "mknod" {
  type    = bool
  default = null
}
variable "mount_types" {
  type        = list(string)
  default     = null
  description = "File systems the container may mount (features mount=), e.g. [\"nfs\", \"cifs\"]."
}
variable "startup" {
  type = object({
    order      = optional(number)
    up_delay   = optional(number)
    down_delay = optional(number)
  })
  default     = null
  description = "Start order and delays in seconds (Proxmox startup: order, up, down); null: none."
}
variable "console_mode" {
  type        = string
  default     = null
  description = "tty, console or shell (Proxmox cmode); with tty_count and console null: no console block."
  validation {
    condition     = var.console_mode == null || contains(["tty", "console", "shell"], coalesce(var.console_mode, "tty"))
    error_message = "console_mode must be tty, console or shell."
  }
}
variable "tty_count" {
  type    = number
  default = null
}
variable "console" {
  type        = bool
  default     = null
  description = "Attach /dev/console (Proxmox console)."
}
variable "mount_points" {
  type = list(object({
    volume        = string           # a storage (a new volume) or its volume ID, or a host path (bind mount)
    path          = string           # inside the container
    size_gib      = optional(number) # volume mount points only
    backup        = optional(bool)
    read_only     = optional(bool)
    mount_options = optional(list(string))
    acl           = optional(bool)
    quota         = optional(bool)
    replicate     = optional(bool)
    shared        = optional(bool)
  }))
  default  = []
  nullable = false
  validation {
    condition     = alltrue([for m in var.mount_points : startswith(m.path, "/") && m.volume != ""])
    error_message = "mount_points: each needs a volume (a storage or a host path) and an absolute path inside the container."
  }
}
variable "firewall" {
  type        = bool
  default     = null
  description = "The interface's Proxmox firewall flag; null: the provider's default (off)."
}
variable "mtu" {
  type        = number
  default     = null
  description = "The interface's MTU; null: the bridge's."
}
