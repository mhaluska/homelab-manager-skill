resource "proxmox_virtual_environment_vm" "this" {
  name        = var.name
  node_name   = var.node
  migrate     = true # a node change migrates the guest; without it the provider re-creates it
  vm_id       = var.vm_id
  description = var.description
  tags        = sort(distinct(concat(["tofu"], var.tags)))
  started     = var.started
  on_boot     = var.on_boot
  protection  = var.protection

  clone {
    vm_id     = var.template_vm_id
    node_name = var.template_node
    full      = true
  }

  agent {
    enabled = true
    trim    = var.agent_trim
  }

  cpu {
    cores   = var.cores
    sockets = var.sockets
    type    = var.cpu_type
    flags   = var.cpu_flags
    numa    = var.numa
  }

  memory {
    dedicated = var.memory_mib
    floating  = var.memory_floating_mib
  }

  dynamic "startup" {
    for_each = var.startup == null ? [] : [var.startup]
    content {
      order      = startup.value.order
      up_delay   = startup.value.up_delay
      down_delay = startup.value.down_delay
    }
  }

  scsi_hardware = var.scsi_hardware
  tablet_device = var.tablet_device

  disk {
    datastore_id = var.datastore
    interface    = "scsi0"
    size         = var.disk_gib
    discard      = var.disk_discard
    iothread     = var.disk_iothread
    ssd          = var.disk_ssd
    cache        = var.disk_cache
    backup       = var.disk_backup
  }

  dynamic "disk" {
    for_each = var.extra_disks
    content {
      datastore_id = coalesce(disk.value.datastore, var.datastore)
      interface    = disk.value.interface
      size         = disk.value.size_gib
      discard      = disk.value.discard
      iothread     = disk.value.iothread
      ssd          = disk.value.ssd
      cache        = disk.value.cache
      backup       = disk.value.backup
      file_format  = "raw"
    }
  }

  # An imported VM may keep its CD-ROM drive on ide2 (then without the cloud-init drive, which uses ide2).
  dynamic "cdrom" {
    for_each = var.cdrom == null ? [] : [var.cdrom]
    content {
      interface = "ide2"
      file_id   = cdrom.value
    }
  }

  network_device {
    bridge      = var.bridge
    vlan_id     = var.vlan_id
    model       = "virtio"
    mac_address = var.mac_address
    firewall    = var.firewall
    mtu         = var.mtu
    queues      = var.queues
  }

  # net1, net2, ... in list order: the provider numbers network devices by position (no gaps)
  dynamic "network_device" {
    for_each = var.extra_nics
    content {
      bridge       = network_device.value.bridge
      vlan_id      = network_device.value.vlan_id
      model        = network_device.value.model
      mac_address  = network_device.value.mac_address
      firewall     = network_device.value.firewall
      mtu          = network_device.value.mtu
      queues       = network_device.value.queues
      disconnected = network_device.value.disconnected
    }
  }

  operating_system {
    type = var.os_type
  }

  dynamic "serial_device" {
    for_each = var.serial_socket ? [1] : []
    content {}
  }

  # PCI passthrough through resource mappings (Datacenter → Resource Mappings) only: raw device IDs need root@pam.
  machine = var.machine
  dynamic "hostpci" {
    for_each = var.pci_devices
    content {
      device  = "hostpci${hostpci.key}"
      mapping = hostpci.value.mapping
      pcie    = hostpci.value.pcie
      rombar  = hostpci.value.rombar
      xvga    = hostpci.value.xvga
    }
  }

  # The cloud-init drive (ide2): addresses, DNS and the admin user at first boot. An imported VM without one keeps
  # none (cloud_init_drive = false): its settings then come from the guest itself.
  dynamic "initialization" {
    for_each = var.cloud_init_drive ? [1] : []
    content {
      datastore_id = var.datastore
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
      # ipconfig1, ipconfig2, ... of the extra NICs by position, up to the last one with an address (Proxmox has
      # no trailing empty ones)
      dynamic "ip_config" {
        for_each = slice(var.extra_nics, 0, local.extra_ip_configs)
        content {
          dynamic "ipv4" {
            for_each = ip_config.value.ipv4_address == null ? [] : [1]
            content {
              address = ip_config.value.ipv4_address
              gateway = ip_config.value.ipv4_address == "dhcp" ? null : ip_config.value.ipv4_gateway
            }
          }
          dynamic "ipv6" {
            for_each = ip_config.value.ipv6_address == null ? [] : [1]
            content {
              address = ip_config.value.ipv6_address
              gateway = contains(["dhcp", "auto"], ip_config.value.ipv6_address) ? null : ip_config.value.ipv6_gateway
            }
          }
        }
      }
      dns {
        servers = length(var.dns_servers) > 0 ? var.dns_servers : null
        domain  = var.dns_domain
      }
      # A user-data snippet replaces the built-in user data (the provider refuses both), so it must create the
      # admin user and keys itself. Vendor data merges with it.
      dynamic "user_account" {
        for_each = var.cloud_init_user_snippet == null ? [1] : []
        content {
          username = var.admin_user
          keys     = var.ssh_public_keys
        }
      }
      vendor_data_file_id = try(proxmox_virtual_environment_file.cloud_init["vendor"].id, null)
      user_data_file_id   = try(proxmox_virtual_environment_file.cloud_init["user"].id, null)
    }
  }

  lifecycle {
    # The template is only the starting point. A new template version must never
    # rebuild running VMs, and cloud-init user data only applies at first boot.
    ignore_changes = [clone, initialization[0].user_account, initialization[0].vendor_data_file_id,
    initialization[0].user_data_file_id]
    precondition {
      condition     = !anytrue([for d in var.pci_devices : d.pcie]) || startswith(coalesce(var.machine, "pc"), "q35")
      error_message = "VM ${var.name}: pci_devices with pcie = true need machine = \"q35\"."
    }
    precondition {
      condition     = var.cloud_init_drive ? var.cdrom == null : var.cloud_init_snippet == null && var.cloud_init_user_snippet == null
      error_message = "VM ${var.name}: ${var.cloud_init_drive ? "a cdrom needs cloud_init_drive = false (both use ide2)" : "cloud-init snippets need the cloud-init drive (cloud_init_drive = true)"}."
    }
  }
}

# Cloud-init snippets (vendor and user data) from tofu/snippets/, uploaded over SSH to the node's snippets storage
# under a name with the VMID, so entries never share a file. Like the user account they count at first boot only:
# later edits of the file are not uploaded. The VM keeps pointing at the uploaded file, so it must stay while the
# VM exists (Proxmox reads it whenever it rebuilds the cloud-init drive).
resource "proxmox_virtual_environment_file" "cloud_init" {
  for_each     = { for k, f in { vendor = var.cloud_init_snippet, user = var.cloud_init_user_snippet } : k => f if f != null }
  content_type = "snippets"
  datastore_id = var.snippets_datastore
  node_name    = var.node

  source_file {
    path      = each.value
    file_name = "vm-${var.vm_id}-${each.key}-data.yaml"
  }

  lifecycle {
    ignore_changes = [source_file]
    precondition {
      condition     = var.snippets_datastore != null
      error_message = "VM ${var.name}: a cloud-init snippet needs defaults.snippets_datastore (homelab.yaml proxmox.snippets_storage, a storage with snippets content)."
    }
    precondition {
      condition     = fileexists(each.value)
      error_message = "VM ${var.name}: cloud-init snippet ${each.value} not found (files live in tofu/snippets/)."
    }
  }
}

locals {
  extra_ip_configs = max(0, [for i, n in var.extra_nics : i + 1 if n.ipv4_address != null || n.ipv6_address != null]...)
  extra_gateways   = [for n in var.extra_nics : n.ipv4_gateway if n.ipv4_gateway != null && n.ipv4_address != null && n.ipv4_address != "dhcp"]
}

# Warnings in the plan, not errors: a guest on an isolated network may have no gateway on purpose (a gateway on an
# extra NIC counts), and several default routes may be deliberate.
check "static_address_gateway" {
  assert {
    condition = var.ipv4_address == "dhcp" || length(local.extra_gateways) > 0 || try(
      cidrhost(var.ipv4_address, 0) == cidrhost("${var.ipv4_gateway}/${split("/", var.ipv4_address)[1]}", 0), false
    )
    error_message = "VM ${var.name}: static address ${var.ipv4_address} has ${var.ipv4_gateway == null ? "no gateway (defaults.ipv4_gateway)" : "gateway ${var.ipv4_gateway} outside its subnet"}, so it has no default route."
  }
  assert {
    condition     = length(local.extra_gateways) + (var.ipv4_address != "dhcp" && var.ipv4_gateway != null ? 1 : 0) <= 1
    error_message = "VM ${var.name}: an IPv4 gateway on more than one NIC gives the guest several default routes."
  }
}
