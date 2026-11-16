module "base_image" {
  source   = "../../modules/cloud-image-base"
  for_each = var.base_images

  name               = each.key
  distro             = each.value.distro
  node               = coalesce(each.value.node, var.defaults.node)
  vm_id              = each.value.vm_id
  image_url          = each.value.image_url
  image_file_name    = each.value.image_file_name
  checksum           = each.value.checksum
  checksum_algorithm = each.value.checksum_algorithm
  image_content_type = each.value.content_type
  image_datastore    = coalesce(var.defaults.image_datastore, var.defaults.datastore)
  datastore          = var.defaults.datastore
  bridge             = var.defaults.bridge
}

module "vm" {
  source   = "../../modules/proxmox-vm"
  for_each = var.vms

  name            = each.key
  node            = coalesce(each.value.node, var.defaults.node)
  vm_id           = each.value.vm_id
  template_vm_id  = each.value.template_vm_id
  cores           = each.value.cores
  memory_mib      = each.value.memory_mib
  disk_gib        = each.value.disk_gib
  extra_disks     = each.value.extra_disks
  datastore       = coalesce(each.value.datastore, var.defaults.datastore)
  bridge          = coalesce(each.value.bridge, var.defaults.bridge)
  vlan_id         = each.value.vlan_id
  ipv4_address    = each.value.ipv4_address
  ipv4_gateway    = var.defaults.ipv4_gateway
  dns_servers     = var.defaults.dns_servers
  dns_domain      = var.defaults.dns_domain
  admin_user      = var.defaults.admin_user
  ssh_public_keys = var.defaults.ssh_public_keys
  tags            = each.value.tags
  started         = each.value.started
}

module "lxc" {
  source   = "../../modules/proxmox-lxc"
  for_each = var.containers

  hostname         = each.key
  node             = coalesce(each.value.node, var.defaults.node)
  vm_id            = each.value.vm_id
  template_file_id = each.value.template_file_id
  os_type          = each.value.os_type
  cores            = each.value.cores
  memory_mib       = each.value.memory_mib
  swap_mib         = each.value.swap_mib
  disk_gib         = each.value.disk_gib
  datastore        = coalesce(each.value.datastore, var.defaults.datastore)
  bridge           = coalesce(each.value.bridge, var.defaults.bridge)
  vlan_id          = each.value.vlan_id
  ipv4_address     = each.value.ipv4_address
  ipv4_gateway     = var.defaults.ipv4_gateway
  unprivileged     = each.value.unprivileged
  nesting          = each.value.nesting
  ssh_public_keys  = var.defaults.ssh_public_keys
  tags             = each.value.tags
  started          = each.value.started
}
