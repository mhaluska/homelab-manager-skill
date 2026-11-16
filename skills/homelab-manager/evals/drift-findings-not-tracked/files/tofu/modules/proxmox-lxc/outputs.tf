output "vm_id" { value = proxmox_virtual_environment_container.this.vm_id }
output "hostname" { value = var.hostname }
output "node" { value = var.node }
output "ipv4" { value = var.ipv4_address != "dhcp" ? split("/", var.ipv4_address)[0] : null }
