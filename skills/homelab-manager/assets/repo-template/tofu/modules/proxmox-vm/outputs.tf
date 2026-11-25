output "vm_id" { value = proxmox_virtual_environment_vm.this.vm_id }
output "name" { value = proxmox_virtual_environment_vm.this.name }
output "node" { value = proxmox_virtual_environment_vm.this.node_name }
output "ipv4" {
  description = "Static address of the first NIC, else of the first extra NIC with one, else the first non-loopback address reported by the guest agent."
  value = var.ipv4_address != "dhcp" ? split("/", var.ipv4_address)[0] : try(
    [for n in var.extra_nics : split("/", n.ipv4_address)[0] if n.ipv4_address != null && n.ipv4_address != "dhcp"][0],
    [for ip in flatten(proxmox_virtual_environment_vm.this.ipv4_addresses) : ip if ip != "127.0.0.1"][0], null
  )
}
