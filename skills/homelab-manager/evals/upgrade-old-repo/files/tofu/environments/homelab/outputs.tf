# Consumed by tofu_to_inventory.py → ansible/inventory/managed/tofu_hosts.yml
output "ansible_hosts" {
  value = merge(
    { for k, m in module.vm : k => {
      ansible_host = m.ipv4
      groups       = var.vms[k].ansible_groups
      vm_id        = m.vm_id
      node         = m.node
      kind         = "vm"
    } },
    { for k, m in module.lxc : k => {
      ansible_host = m.ipv4
      groups       = var.containers[k].ansible_groups
      vm_id        = m.vm_id
      node         = m.node
      kind         = "lxc"
    } },
  )
}

output "base_images" {
  value = { for k, m in module.base_image : k => m.vm_id }
}
