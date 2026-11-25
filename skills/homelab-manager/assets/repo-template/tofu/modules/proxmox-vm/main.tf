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

  initialization {
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

  lifecycle {
    # The template is only the starting point. A new template version must never
    # rebuild running VMs, and cloud-init user data only applies at first boot.
    ignore_changes = [clone, initialization[0].user_account, initialization[0].vendor_data_file_id,
    initialization[0].user_data_file_id]
    precondition {
      condition     = !anytrue([for d in var.pci_devices : d.pcie]) || startswith(coalesce(var.machine, "pc"), "q35")
      error_message = "VM ${var.name}: pci_devices with pcie = true need machine = \"q35\"."
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

# A warning in the plan, not an error: a guest on an isolated network may have no gateway on purpose.
check "static_address_gateway" {
  assert {
    condition = var.ipv4_address == "dhcp" || try(
      cidrhost(var.ipv4_address, 0) == cidrhost("${var.ipv4_gateway}/${split("/", var.ipv4_address)[1]}", 0), false
    )
    error_message = "VM ${var.name}: static address ${var.ipv4_address} has ${var.ipv4_gateway == null ? "no gateway (defaults.ipv4_gateway)" : "gateway ${var.ipv4_gateway} outside its subnet"}, so it has no default route."
  }
}
