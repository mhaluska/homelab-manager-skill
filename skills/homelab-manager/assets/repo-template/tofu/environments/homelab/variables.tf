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
    ipv6_gateway    = optional(string) # static ipv6_address entries
    # homelab.yaml proxmox.snippets_storage: cloud-init snippets of VMs (needs snippets content)
    snippets_datastore = optional(string)
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
  validation {
    condition     = length([for k, v in var.base_images : k if !contains(["md5", "sha1", "sha224", "sha256", "sha384", "sha512"], v.checksum_algorithm)]) == 0
    error_message = "base_images ${join(", ", [for k, v in var.base_images : k if !contains(["md5", "sha1", "sha224", "sha256", "sha384", "sha512"], v.checksum_algorithm)])}: checksum_algorithm must be md5, sha1, sha224, sha256, sha384 or sha512."
  }
}

variable "lxc_templates" {
  description = "LXC templates downloaded to Proxmox storage; a container names one in its template attribute."
  type = map(object({
    url                = string                     # one dated build, e.g. http://download.proxmox.com/images/system/debian-13-standard_13.1-2_amd64.tar.zst
    checksum           = string                     # required: sha512sum from Proxmox's aplinfo index, or the distribution's SHA256SUMS
    checksum_algorithm = optional(string, "sha512") # sha256 for SHA256SUMS
    file_name          = optional(string)           # empty: the url's file name
    node               = optional(string)           # empty: defaults.node; the template must be on the container's node (or on shared storage)
    datastore          = optional(string)           # needs vztmpl content; empty: the node's image datastore
  }))
  default = {}
  validation {
    condition     = length([for k, v in var.lxc_templates : k if !contains(["md5", "sha1", "sha224", "sha256", "sha384", "sha512"], v.checksum_algorithm)]) == 0
    error_message = "lxc_templates ${join(", ", [for k, v in var.lxc_templates : k if !contains(["md5", "sha1", "sha224", "sha256", "sha384", "sha512"], v.checksum_algorithm)])}: checksum_algorithm must be md5, sha1, sha224, sha256, sha384 or sha512."
  }
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
    ipv4_gateway   = optional(string) # empty: defaults.ipv4_gateway
    ipv6_address   = optional(string) # empty: no IPv6 settings; "dhcp", "auto" (SLAAC) or CIDR
    ipv6_gateway   = optional(string) # static ipv6_address only; empty: defaults.ipv6_gateway
    cpu_type       = optional(string) # empty: x86-64-v2-AES
    description    = optional(string) # empty: "Managed by OpenTofu (homelab-infrastructure)"
    tags           = optional(list(string), [])
    ansible_groups = optional(list(string), [])
    started        = optional(bool, true)
    on_boot        = optional(bool, true)
    protection     = optional(bool, false) # Proxmox refuses to remove the guest while it is set
    # files in tofu/snippets/, first boot only: vendor data merges with the built-in user data (admin user,
    # keys); user data replaces it and must create the admin user and keys itself
    cloud_init_snippet      = optional(string)
    cloud_init_user_snippet = optional(string)
    # PCI passthrough by resource mapping (Datacenter → Resource Mappings); the VM then needs an explicit node
    pci_devices = optional(list(object({ mapping = string, pcie = optional(bool, false), rombar = optional(bool), xvga = optional(bool) })), [])
    machine     = optional(string) # e.g. q35 (pcie devices need it); empty: as before
  }))
  default = {}
  validation {
    condition     = length([for k, v in var.vms : k if !(v.ipv4_address == "dhcp" || can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$", v.ipv4_address)) && can(cidrhost(v.ipv4_address, 0)))]) == 0
    error_message = "vms ${join(", ", [for k, v in var.vms : k if !(v.ipv4_address == "dhcp" || can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$", v.ipv4_address)) && can(cidrhost(v.ipv4_address, 0)))])}: ipv4_address must be \"dhcp\" or an IPv4 address with its prefix length, e.g. 10.0.10.21/24."
  }
  validation {
    condition     = length([for k, v in var.vms : k if !(v.ipv6_address == null || try(contains(["dhcp", "auto"], v.ipv6_address) || strcontains(v.ipv6_address, ":") && can(regex("/\\d{1,3}$", v.ipv6_address)) && can(cidrhost(v.ipv6_address, 0)), false)) || !(v.ipv6_gateway == null || try(strcontains(v.ipv6_gateway, ":") && can(cidrhost("${v.ipv6_gateway}/128", 0)), false))]) == 0
    error_message = "vms ${join(", ", [for k, v in var.vms : k if !(v.ipv6_address == null || try(contains(["dhcp", "auto"], v.ipv6_address) || strcontains(v.ipv6_address, ":") && can(regex("/\\d{1,3}$", v.ipv6_address)) && can(cidrhost(v.ipv6_address, 0)), false)) || !(v.ipv6_gateway == null || try(strcontains(v.ipv6_gateway, ":") && can(cidrhost("${v.ipv6_gateway}/128", 0)), false))])}: ipv6_address must be \"dhcp\", \"auto\" (SLAAC) or an IPv6 address with its prefix length, e.g. fd00:10::21/64; ipv6_gateway an IPv6 address, e.g. fe80::1."
  }
  validation {
    condition     = length([for k, v in var.vms : k if v.vlan_id != null && !try(v.vlan_id >= 1 && v.vlan_id <= 4094 && v.vlan_id == floor(v.vlan_id), false)]) == 0
    error_message = "vms ${join(", ", [for k, v in var.vms : k if v.vlan_id != null && !try(v.vlan_id >= 1 && v.vlan_id <= 4094 && v.vlan_id == floor(v.vlan_id), false)])}: vlan_id must be 1 to 4094 (leave it out for no tag)."
  }
  validation {
    condition     = length([for k, v in var.vms : k if !(v.vm_id >= 100 && v.vm_id == floor(v.vm_id)) || !(v.template_vm_id >= 100 && v.template_vm_id == floor(v.template_vm_id))]) == 0
    error_message = "vms ${join(", ", [for k, v in var.vms : k if !(v.vm_id >= 100 && v.vm_id == floor(v.vm_id)) || !(v.template_vm_id >= 100 && v.template_vm_id == floor(v.template_vm_id))])}: vm_id and template_vm_id must be whole numbers of 100 or more."
  }
  validation {
    condition     = length([for k, v in var.vms : k if !alltrue([for d in v.extra_disks : can(regex("^(scsi([1-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5])$", d.interface))])]) == 0
    error_message = "vms ${join(", ", [for k, v in var.vms : k if !alltrue([for d in v.extra_disks : can(regex("^(scsi([1-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5])$", d.interface))])])}: extra_disks interface must be scsi1-scsi30, virtio0-virtio15 or sata0-sata5 (scsi0 is the root disk)."
  }
  validation {
    condition     = length([for k, v in var.vms : k if !alltrue([for f in [v.cloud_init_snippet, v.cloud_init_user_snippet] : f == null || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", f))])]) == 0
    error_message = "vms ${join(", ", [for k, v in var.vms : k if !alltrue([for f in [v.cloud_init_snippet, v.cloud_init_user_snippet] : f == null || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", f))])])}: cloud_init_snippet and cloud_init_user_snippet name a file in tofu/snippets/ (no path), e.g. \"docker-host.yaml\"."
  }
  validation {
    condition     = length([for k, v in var.vms : k if length(v.pci_devices) > 0 && (v.node == null || !alltrue([for d in v.pci_devices : can(regex("^[A-Za-z][A-Za-z0-9_.-]*$", d.mapping))]) || anytrue([for d in v.pci_devices : d.pcie]) && !startswith(coalesce(v.machine, "pc"), "q35"))]) == 0
    error_message = "vms ${join(", ", [for k, v in var.vms : k if length(v.pci_devices) > 0 && (v.node == null || !alltrue([for d in v.pci_devices : can(regex("^[A-Za-z][A-Za-z0-9_.-]*$", d.mapping))]) || anytrue([for d in v.pci_devices : d.pcie]) && !startswith(coalesce(v.machine, "pc"), "q35"))])}: pci_devices need the VM's node set (a device belongs to one node), each mapping named by its ID (e.g. gpu), and machine = \"q35\" for pcie = true."
  }
}

variable "containers" {
  description = "LXC containers. The map key is the hostname."
  type = map(object({
    vm_id            = number
    template_file_id = optional(string) # a template already on storage, e.g. local:vztmpl/…; or:
    template         = optional(string) # a key of lxc_templates (downloaded by OpenTofu)
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
    ipv4_gateway     = optional(string)           # empty: defaults.ipv4_gateway
    ipv6_address     = optional(string)           # empty: no IPv6 settings; "dhcp", "auto" (SLAAC) or CIDR
    ipv6_gateway     = optional(string)           # static ipv6_address only; empty: defaults.ipv6_gateway
    dns_servers      = optional(list(string), []) # empty: the node's DNS settings
    dns_domain       = optional(string)
    description      = optional(string) # empty: "Managed by OpenTofu (homelab-infrastructure)"
    unprivileged     = optional(bool, true)
    nesting          = optional(bool, true)
    tags             = optional(list(string), [])
    ansible_groups   = optional(list(string), [])
    started          = optional(bool, true)
    on_boot          = optional(bool, true)
    protection       = optional(bool, false) # Proxmox refuses to remove the container while it is set
  }))
  default = {}
  validation {
    condition     = length([for k, v in var.containers : k if !(v.ipv4_address == "dhcp" || can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$", v.ipv4_address)) && can(cidrhost(v.ipv4_address, 0)))]) == 0
    error_message = "containers ${join(", ", [for k, v in var.containers : k if !(v.ipv4_address == "dhcp" || can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}$", v.ipv4_address)) && can(cidrhost(v.ipv4_address, 0)))])}: ipv4_address must be \"dhcp\" or an IPv4 address with its prefix length, e.g. 10.0.10.31/24."
  }
  validation {
    condition     = length([for k, v in var.containers : k if !(v.ipv6_address == null || try(contains(["dhcp", "auto"], v.ipv6_address) || strcontains(v.ipv6_address, ":") && can(regex("/\\d{1,3}$", v.ipv6_address)) && can(cidrhost(v.ipv6_address, 0)), false)) || !(v.ipv6_gateway == null || try(strcontains(v.ipv6_gateway, ":") && can(cidrhost("${v.ipv6_gateway}/128", 0)), false))]) == 0
    error_message = "containers ${join(", ", [for k, v in var.containers : k if !(v.ipv6_address == null || try(contains(["dhcp", "auto"], v.ipv6_address) || strcontains(v.ipv6_address, ":") && can(regex("/\\d{1,3}$", v.ipv6_address)) && can(cidrhost(v.ipv6_address, 0)), false)) || !(v.ipv6_gateway == null || try(strcontains(v.ipv6_gateway, ":") && can(cidrhost("${v.ipv6_gateway}/128", 0)), false))])}: ipv6_address must be \"dhcp\", \"auto\" (SLAAC) or an IPv6 address with its prefix length, e.g. fd00:10::31/64; ipv6_gateway an IPv6 address, e.g. fe80::1."
  }
  validation {
    condition     = length([for k, v in var.containers : k if v.vlan_id != null && !try(v.vlan_id >= 1 && v.vlan_id <= 4094 && v.vlan_id == floor(v.vlan_id), false)]) == 0
    error_message = "containers ${join(", ", [for k, v in var.containers : k if v.vlan_id != null && !try(v.vlan_id >= 1 && v.vlan_id <= 4094 && v.vlan_id == floor(v.vlan_id), false)])}: vlan_id must be 1 to 4094 (leave it out for no tag)."
  }
  validation {
    condition     = length([for k, v in var.containers : k if !(v.vm_id >= 100 && v.vm_id == floor(v.vm_id))]) == 0
    error_message = "containers ${join(", ", [for k, v in var.containers : k if !(v.vm_id >= 100 && v.vm_id == floor(v.vm_id))])}: vm_id must be a whole number of 100 or more."
  }
  validation {
    condition     = length([for k, v in var.containers : k if(v.template == null) == (v.template_file_id == null)]) == 0
    error_message = "containers ${join(", ", [for k, v in var.containers : k if(v.template == null) == (v.template_file_id == null)])}: set either template_file_id (a template on storage) or template (a key of lxc_templates)."
  }
}
