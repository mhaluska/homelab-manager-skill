resource "proxmox_virtual_environment_container" "this" {
  node_name     = var.node
  migrate       = true # a node change migrates the guest; without it the provider re-creates it
  vm_id         = var.vm_id
  description   = var.description
  tags          = sort(distinct(concat(["tofu"], var.tags)))
  unprivileged  = var.unprivileged
  started       = var.started
  start_on_boot = var.on_boot
  protection    = var.protection

  features {
    nesting = var.nesting
  }

  cpu {
    cores = var.cores
  }

  memory {
    dedicated = var.memory_mib
    swap      = var.swap_mib
  }

  disk {
    datastore_id = var.datastore
    size         = var.disk_gib
  }

  network_interface {
    name        = "eth0"
    bridge      = var.bridge
    vlan_id     = var.vlan_id
    mac_address = var.mac_address
  }

  operating_system {
    template_file_id = var.template_file_id
    type             = var.os_type
  }

  initialization {
    hostname = var.hostname
    ip_config {
      ipv4 {
        address = var.ipv4_address
        gateway = var.ipv4_address == "dhcp" ? null : var.ipv4_gateway
      }
      dynamic "ipv6" {
        for_each = var.ipv6_address == null ? [] : [1]
        content {
          address = var.ipv6_address
          gateway = contains(["dhcp", "auto"], var.ipv6_address) ? null : var.ipv6_gateway
        }
      }
    }
    dynamic "dns" {
      for_each = length(var.dns_servers) > 0 || var.dns_domain != null ? [1] : []
      content {
        servers = length(var.dns_servers) > 0 ? var.dns_servers : null
        domain  = var.dns_domain
      }
    }
    user_account {
      keys = var.ssh_public_keys
    }
  }

  lifecycle {
    ignore_changes = [operating_system[0].template_file_id, initialization[0].user_account]
  }
}

# A warning in the plan, not an error: a container on an isolated network may have no gateway on purpose.
check "static_address_gateway" {
  assert {
    condition = var.ipv4_address == "dhcp" || try(
      cidrhost(var.ipv4_address, 0) == cidrhost("${var.ipv4_gateway}/${split("/", var.ipv4_address)[1]}", 0), false
    )
    error_message = "Container ${var.hostname}: static address ${var.ipv4_address} has ${var.ipv4_gateway == null ? "no gateway (defaults.ipv4_gateway)" : "gateway ${var.ipv4_gateway} outside its subnet"}, so it has no default route."
  }
}
