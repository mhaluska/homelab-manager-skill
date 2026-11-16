resource "proxmox_virtual_environment_container" "this" {
  node_name     = var.node
  vm_id         = var.vm_id
  description   = var.description
  tags          = sort(distinct(concat(["tofu"], var.tags)))
  unprivileged  = var.unprivileged
  started       = var.started
  start_on_boot = true

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
    name    = "eth0"
    bridge  = var.bridge
    vlan_id = var.vlan_id
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
    }
    user_account {
      keys = var.ssh_public_keys
    }
  }

  lifecycle {
    ignore_changes = [operating_system[0].template_file_id, initialization[0].user_account]
  }
}
