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
  type = list(object({
    interface = string
    size_gib  = number
    datastore = optional(string)
    # options as for the root disk; the defaults are what extra disks have always had (no ssd flag, no cache)
    discard  = optional(string, "on")
    iothread = optional(bool, true)
    ssd      = optional(bool)
    cache    = optional(string)
    backup   = optional(bool)
  }))
  default = []
  validation {
    condition     = alltrue([for d in var.extra_disks : can(regex("^(scsi([1-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5])$", d.interface))])
    error_message = "extra_disks interface must be scsi1-scsi30, virtio0-virtio15 or sata0-sata5 (scsi0 is the root disk)."
  }
  validation {
    condition     = alltrue([for d in var.extra_disks : contains(["on", "ignore"], d.discard) && contains(["none", "directsync", "writethrough", "writeback", "unsafe"], coalesce(d.cache, "none"))])
    error_message = "extra_disks: discard must be on or ignore; cache none, directsync, writethrough, writeback or unsafe."
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
variable "cloud_init_snippet" {
  type        = string
  default     = null
  description = "Path of a cloud-init vendor data file, merged with the built-in user data (admin user, keys). Ignored after creation."
}
variable "cloud_init_user_snippet" {
  type        = string
  default     = null
  description = "Path of a cloud-init user data file. It replaces the built-in user data: it must create the admin user and keys itself. Ignored after creation."
}
variable "machine" {
  type        = string
  default     = null
  description = "Machine type, e.g. q35 (needed for pcie devices); null leaves it to the provider, as before."
}
variable "pci_devices" {
  type = list(object({
    mapping = string                # a PCI resource mapping (Datacenter → Resource Mappings), not a raw ID
    pcie    = optional(bool, false) # PCIe port: needs machine q35
    rombar  = optional(bool)
    xvga    = optional(bool) # primary GPU of the VM
  }))
  default  = []
  nullable = false
  validation {
    condition     = length(var.pci_devices) <= 16 && alltrue([for d in var.pci_devices : can(regex("^[A-Za-z][A-Za-z0-9_.-]*$", d.mapping))])
    error_message = "pci_devices: at most 16, each naming a PCI resource mapping by its ID, e.g. gpu."
  }
}
variable "snippets_datastore" {
  type        = string
  default     = null
  description = "Storage with snippets content the snippet files are uploaded to (over SSH, on var.node)."
}

# Settings an imported guest keeps (tofu_import_plan.py). Each default plans what earlier versions planned.
variable "sockets" {
  type        = number
  default     = null
  description = "CPU sockets (vCPUs = sockets x cores); null: the provider's 1."
}
variable "numa" {
  type    = bool
  default = null
}
variable "cpu_flags" {
  type        = list(string)
  default     = null
  description = "CPU flags, e.g. [\"+aes\", \"-pcid\"]; null: none."
}
variable "memory_floating_mib" {
  type        = number
  default     = null
  description = "Ballooning minimum (Proxmox balloon); null: none set."
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
variable "disk_discard" {
  type     = string
  default  = "on"
  nullable = false
  validation {
    condition     = contains(["on", "ignore"], var.disk_discard)
    error_message = "disk_discard must be on or ignore."
  }
}
variable "disk_iothread" {
  type     = bool
  default  = true
  nullable = false
}
variable "disk_ssd" {
  type     = bool
  default  = true
  nullable = false
}
variable "disk_cache" {
  type        = string
  default     = null
  description = "Root disk cache mode; null: none."
  validation {
    condition     = contains(["none", "directsync", "writethrough", "writeback", "unsafe"], coalesce(var.disk_cache, "none"))
    error_message = "disk_cache must be none, directsync, writethrough, writeback or unsafe."
  }
}
variable "disk_backup" {
  type        = bool
  default     = null
  description = "false: backups skip the root disk; null: the provider's default (included)."
}
variable "scsi_hardware" {
  type     = string
  default  = "virtio-scsi-single"
  nullable = false
  validation {
    condition     = contains(["lsi", "lsi53c810", "virtio-scsi-pci", "virtio-scsi-single", "megasas", "pvscsi"], var.scsi_hardware)
    error_message = "scsi_hardware must be lsi, lsi53c810, virtio-scsi-pci, virtio-scsi-single, megasas or pvscsi."
  }
}
variable "tablet_device" {
  type        = bool
  default     = null
  description = "USB tablet for the console pointer; null: the provider's default (on)."
}
variable "cloud_init_drive" {
  type        = bool
  default     = true
  nullable    = false
  description = "false: no cloud-init drive (an imported VM without one); addresses, DNS, admin user and snippets then don't apply."
}
variable "serial_socket" {
  type        = bool
  default     = true
  nullable    = false
  description = "A serial0 socket (the console of cloud images); false: no serial port (an imported VM without one)."
}
variable "cdrom" {
  type        = string
  default     = null
  description = "CD-ROM drive on ide2: \"none\" (empty) or an ISO file ID; needs cloud_init_drive = false. null: no drive."
  validation {
    condition     = var.cdrom == null || try(var.cdrom == "none" || can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]*:iso/.+$", var.cdrom)), false)
    error_message = "cdrom must be \"none\" (an empty drive) or an ISO file ID, e.g. local:iso/debian-13.iso."
  }
}
variable "firewall" {
  type        = bool
  default     = null
  description = "The NIC's Proxmox firewall flag; null: the provider's default (off)."
}
variable "mtu" {
  type        = number
  default     = null
  description = "The NIC's MTU; null: the bridge's."
}
variable "queues" {
  type        = number
  default     = null
  description = "The NIC's multiqueue count (virtio); null: none."
}
variable "extra_nics" {
  type = list(object({
    bridge       = string
    vlan_id      = optional(number)
    mac_address  = optional(string) # empty: Proxmox picks one
    model        = optional(string, "virtio")
    firewall     = optional(bool)
    mtu          = optional(number)
    queues       = optional(number)
    disconnected = optional(bool) # link down
    # cloud-init ipconfigN; null: no settings for the NIC. The gateway is the NIC's own (no defaults).
    ipv4_address = optional(string)
    ipv4_gateway = optional(string)
    ipv6_address = optional(string)
    ipv6_gateway = optional(string)
  }))
  default     = []
  nullable    = false
  description = "NICs after the first (net1, net2, ... in list order)."
  validation {
    condition = length(var.extra_nics) <= 31 && alltrue([for n in var.extra_nics : (
      contains(["virtio", "e1000", "e1000e", "rtl8139", "vmxnet3"], n.model)
      && (n.vlan_id == null || try(n.vlan_id >= 1 && n.vlan_id <= 4094 && n.vlan_id == floor(n.vlan_id), false))
      && (n.mac_address == null || can(regex("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", n.mac_address)))
      && (n.ipv4_address == null || n.ipv4_address == "dhcp" || can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$", n.ipv4_address)) && can(cidrhost(n.ipv4_address, 0)))
      && (n.ipv4_gateway == null || can(regex("^(\\d{1,3}\\.){3}\\d{1,3}$", n.ipv4_gateway)) && can(cidrhost("${n.ipv4_gateway}/32", 0)))
      && (n.ipv6_address == null || try(contains(["dhcp", "auto"], n.ipv6_address) || strcontains(n.ipv6_address, ":") && can(regex("/\\d{1,3}$", n.ipv6_address)) && can(cidrhost(n.ipv6_address, 0)), false))
      && (n.ipv6_gateway == null || try(strcontains(n.ipv6_gateway, ":") && can(cidrhost("${n.ipv6_gateway}/128", 0)), false))
    )])
    error_message = "extra_nics: at most 31; model virtio, e1000, e1000e, rtl8139 or vmxnet3; vlan_id 1 to 4094; mac_address six hex pairs; ipv4_address \"dhcp\" or CIDR, ipv4_gateway an address; ipv6_address \"dhcp\", \"auto\" or CIDR, ipv6_gateway an address."
  }
}
variable "agent_trim" {
  type        = bool
  default     = null
  description = "Guest agent fstrim after a disk move or clone (fstrim_cloned_disks); null: the provider's default (off)."
}
variable "os_type" {
  type     = string
  default  = "l26"
  nullable = false
  validation {
    condition     = contains(["l24", "l26", "other", "solaris", "w2k", "w2k3", "w2k8", "win7", "win8", "win10", "win11", "wvista", "wxp"], var.os_type)
    error_message = "os_type must be a Proxmox OS type: l26 (Linux), other, win10, win11, ..."
  }
}
