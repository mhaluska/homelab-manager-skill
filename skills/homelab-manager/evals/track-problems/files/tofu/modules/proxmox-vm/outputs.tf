output "vm_id" { value = proxmox_virtual_environment_vm.this.vm_id }
output "name" { value = proxmox_virtual_environment_vm.this.name }
output "node" { value = proxmox_virtual_environment_vm.this.node_name }
output "ipv4" {
  description = "Static address, or the first non-loopback address reported by the guest agent."
  value = var.ipv4_address != "dhcp" ? split("/", var.ipv4_address)[0] : try(
    [for ip in flatten(proxmox_virtual_environment_vm.this.ipv4_addresses) : ip if ip != "127.0.0.1"][0], null
  )
}
