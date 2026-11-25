# Storage per node (homelab.yaml proxmox.nodes; a cluster without shared storage, a node with other disks):
# a node listed in defaults.node_datastores takes its storage from that entry (LXC falls back to the node's
# datastore, images to the site's image_datastore); other nodes use the site defaults. An entry's own
# datastore always wins.
locals {
  vm_node = { for k, v in var.vms : k => coalesce(v.node, var.defaults.node) }
  ct_node = { for k, v in var.containers : k => coalesce(v.node, var.defaults.node) }
  bi_node = { for k, v in var.base_images : k => coalesce(v.node, var.defaults.node) }
  lt_node = { for k, v in var.lxc_templates : k => coalesce(v.node, var.defaults.node) }
  nds     = var.defaults.node_datastores
  storage = { for n in toset(concat(values(local.vm_node), values(local.ct_node), values(local.bi_node), values(local.lt_node))) : n => {
    vm    = try(local.nds[n].datastore, var.defaults.datastore)
    lxc   = try(coalesce(local.nds[n].lxc_datastore, local.nds[n].datastore), coalesce(var.defaults.lxc_datastore, var.defaults.datastore))
    image = coalesce(try(local.nds[n].image_datastore, null), var.defaults.image_datastore, try(local.nds[n].datastore, null), var.defaults.datastore)
  } }
}

module "base_image" {
  source   = "../../modules/cloud-image-base"
  for_each = var.base_images

  name               = each.key
  distro             = each.value.distro
  node               = local.bi_node[each.key]
  vm_id              = each.value.vm_id
  image_url          = each.value.image_url
  image_file_name    = each.value.image_file_name
  checksum           = each.value.checksum
  checksum_algorithm = each.value.checksum_algorithm
  image_content_type = each.value.content_type
  image_datastore    = local.storage[local.bi_node[each.key]].image
  datastore          = local.storage[local.bi_node[each.key]].vm
  bridge             = var.defaults.bridge

  allow_unverified_image = each.value.allow_unverified_image
}

# LXC templates (vztmpl) downloaded by the node from the url, checked against the checksum. A container uses one
# only at creation (template_file_id is ignored afterwards), so removing an entry deletes the file and nothing else.
resource "proxmox_download_file" "lxc_template" {
  for_each = var.lxc_templates

  content_type        = "vztmpl"
  node_name           = local.lt_node[each.key]
  datastore_id        = coalesce(each.value.datastore, local.storage[local.lt_node[each.key]].image)
  url                 = each.value.url
  file_name           = each.value.file_name
  checksum            = each.value.checksum
  checksum_algorithm  = each.value.checksum_algorithm
  overwrite           = false
  overwrite_unmanaged = false
}

module "vm" {
  source   = "../../modules/proxmox-vm"
  for_each = var.vms

  name            = each.key
  node            = local.vm_node[each.key]
  vm_id           = each.value.vm_id
  template_vm_id  = each.value.template_vm_id
  template_node   = each.value.template_node
  cores           = each.value.cores
  memory_mib      = each.value.memory_mib
  disk_gib        = each.value.disk_gib
  extra_disks     = each.value.extra_disks
  datastore       = coalesce(each.value.datastore, local.storage[local.vm_node[each.key]].vm)
  bridge          = coalesce(each.value.bridge, var.defaults.bridge)
  vlan_id         = each.value.vlan_id
  mac_address     = each.value.mac_address
  ipv4_address    = each.value.ipv4_address
  ipv4_gateway    = each.value.ipv4_gateway != null ? each.value.ipv4_gateway : var.defaults.ipv4_gateway
  ipv6_address    = each.value.ipv6_address
  ipv6_gateway    = each.value.ipv6_gateway != null ? each.value.ipv6_gateway : var.defaults.ipv6_gateway
  dns_servers     = var.defaults.dns_servers
  dns_domain      = var.defaults.dns_domain
  admin_user      = var.defaults.admin_user
  ssh_public_keys = var.defaults.ssh_public_keys
  cpu_type        = each.value.cpu_type
  description     = each.value.description
  tags            = each.value.tags
  started         = each.value.started
  on_boot         = each.value.on_boot
  protection      = each.value.protection

  snippets_datastore      = var.defaults.snippets_datastore
  cloud_init_snippet      = each.value.cloud_init_snippet == null ? null : "${path.root}/../../snippets/${each.value.cloud_init_snippet}"
  cloud_init_user_snippet = each.value.cloud_init_user_snippet == null ? null : "${path.root}/../../snippets/${each.value.cloud_init_user_snippet}"

  pci_devices = each.value.pci_devices
  machine     = each.value.machine
}

module "lxc" {
  source   = "../../modules/proxmox-lxc"
  for_each = var.containers

  hostname         = each.key
  node             = local.ct_node[each.key]
  vm_id            = each.value.vm_id
  template_file_id = each.value.template != null ? proxmox_download_file.lxc_template[each.value.template].id : each.value.template_file_id
  os_type          = each.value.os_type
  cores            = each.value.cores
  memory_mib       = each.value.memory_mib
  swap_mib         = each.value.swap_mib
  disk_gib         = each.value.disk_gib
  datastore        = coalesce(each.value.datastore, local.storage[local.ct_node[each.key]].lxc)
  bridge           = coalesce(each.value.bridge, var.defaults.bridge)
  vlan_id          = each.value.vlan_id
  mac_address      = each.value.mac_address
  ipv4_address     = each.value.ipv4_address
  ipv4_gateway     = each.value.ipv4_gateway != null ? each.value.ipv4_gateway : var.defaults.ipv4_gateway
  ipv6_address     = each.value.ipv6_address
  ipv6_gateway     = each.value.ipv6_gateway != null ? each.value.ipv6_gateway : var.defaults.ipv6_gateway
  dns_servers      = each.value.dns_servers
  dns_domain       = each.value.dns_domain
  unprivileged     = each.value.unprivileged
  nesting          = each.value.nesting
  ssh_public_keys  = var.defaults.ssh_public_keys
  description      = each.value.description
  tags             = each.value.tags
  started          = each.value.started
  on_boot          = each.value.on_boot
  protection       = each.value.protection
}
