output "vm_id" { value = proxmox_virtual_environment_container.this.vm_id }
output "hostname" { value = var.hostname }
output "node" { value = var.node }
output "ipv4" {
  description = "Static address of eth0, else of the first extra interface with one."
  value = var.ipv4_address != "dhcp" ? split("/", var.ipv4_address)[0] : try(
    [for n in var.extra_nics : split("/", n.ipv4_address)[0] if n.ipv4_address != null && n.ipv4_address != "dhcp"][0], null
  )
}
