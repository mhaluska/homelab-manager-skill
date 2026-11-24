variable "proxmox_ssh_user" {
  type    = string
  default = "root"
}

variable "defaults" {
  description = "Site defaults, mirrored from homelab.yaml by the homelab-manager skill."
  type = object({
    node            = string
    datastore       = string
    image_datastore = optional(string)
    lxc_datastore   = optional(string)      # LXC root filesystems (needs rootdir content); empty: datastore
    node_datastores = optional(map(object({ # per node: homelab.yaml proxmox.nodes
      datastore       = string
      lxc_datastore   = optional(string)
      image_datastore = optional(string)
    })), {})
    bridge          = string
    admin_user      = string
    ssh_public_keys = list(string)
    dns_servers     = optional(list(string), [])
    dns_domain      = optional(string)
    ipv4_gateway    = optional(string)
  })
}

variable "base_images" {
  description = "Official cloud images imported as base templates (input for Packer)."
  type = map(object({
    distro             = string
    vm_id              = number
    image_url          = string
    image_file_name    = string
    checksum           = optional(string)
    checksum_algorithm = optional(string, "sha256")
    # true only for a base imported before checksums were required: no check of the download
    allow_unverified_image = optional(bool, false)
    content_type           = optional(string, "import")
    node                   = optional(string)
  }))
  default = {}
}

variable "vms" {
  description = "Virtual machines. The map key is the VM name — renaming a key needs a `moved` block, or it is a replacement."
  type = map(object({
    vm_id          = number
    template_vm_id = number
    template_node  = optional(string) # node holding the template, when it is not the VM's node
    node           = optional(string)
    cores          = optional(number, 2)
    memory_mib     = optional(number, 2048)
    disk_gib       = optional(number, 20)
    extra_disks    = optional(list(object({ interface = string, size_gib = number, datastore = optional(string) })), [])
    datastore      = optional(string)
    bridge         = optional(string)
    vlan_id        = optional(number)
    ipv4_address   = optional(string, "dhcp")
    tags           = optional(list(string), [])
    ansible_groups = optional(list(string), [])
    started        = optional(bool, true)
  }))
  default = {}
}

variable "containers" {
  description = "LXC containers. The map key is the hostname."
  type = map(object({
    vm_id            = number
    template_file_id = string
    os_type          = optional(string, "debian")
    node             = optional(string)
    cores            = optional(number, 1)
    memory_mib       = optional(number, 512)
    swap_mib         = optional(number, 512)
    disk_gib         = optional(number, 8)
    datastore        = optional(string)
    bridge           = optional(string)
    vlan_id          = optional(number)
    ipv4_address     = optional(string, "dhcp")
    unprivileged     = optional(bool, true)
    nesting          = optional(bool, true)
    tags             = optional(list(string), [])
    ansible_groups   = optional(list(string), [])
    started          = optional(bool, true)
  }))
  default = {}
}
