resource "proxmox_virtual_environment_vm" "this" {
  name        = var.name
  node_name   = var.node
  vm_id       = var.vm_id
  description = var.description
  tags        = sort(distinct(concat(["tofu"], var.tags)))
  started     = var.started
  on_boot     = var.on_boot

  clone {
    vm_id     = var.template_vm_id
    node_name = var.template_node
    full      = true
  }

  agent {
    enabled = true
  }

  cpu {
    cores = var.cores
    type  = var.cpu_type
  }

  memory {
    dedicated = var.memory_mib
  }

  scsi_hardware = "virtio-scsi-single"

  disk {
    datastore_id = var.datastore
    interface    = "scsi0"
    size         = var.disk_gib
    discard      = "on"
    iothread     = true
    ssd          = true
  }

  dynamic "disk" {
    for_each = var.extra_disks
    content {
      datastore_id = coalesce(disk.value.datastore, var.datastore)
      interface    = disk.value.interface
      size         = disk.value.size_gib
      discard      = "on"
      iothread     = true
      file_format  = "raw"
    }
  }

  network_device {
    bridge  = var.bridge
    vlan_id = var.vlan_id
    model   = "virtio"
  }

  operating_system {
    type = "l26"
  }

  serial_device {}

  initialization {
    datastore_id = var.datastore
    ip_config {
      ipv4 {
        address = var.ipv4_address
        gateway = var.ipv4_address == "dhcp" ? null : var.ipv4_gateway
      }
    }
    dns {
      servers = length(var.dns_servers) > 0 ? var.dns_servers : null
      domain  = var.dns_domain
    }
    user_account {
      username = var.admin_user
      keys     = var.ssh_public_keys
    }
  }

  lifecycle {
    # The template is only the starting point. A new template version must never
    # rebuild running VMs, and cloud-init user data only applies at first boot.
    ignore_changes = [clone, initialization[0].user_account]
  }
}
