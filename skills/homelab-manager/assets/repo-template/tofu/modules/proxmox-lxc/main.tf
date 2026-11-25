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

  # features = false: no features line at all (an imported privileged container without one; Proxmox lets only
  # root@pam change a privileged container's features).
  dynamic "features" {
    for_each = var.features ? [1] : []
    content {
      nesting = var.nesting
      keyctl  = var.keyctl
      fuse    = var.fuse
      mknod   = var.mknod
      mount   = var.mount_types
    }
  }

  dynamic "startup" {
    for_each = var.startup == null ? [] : [var.startup]
    content {
      order      = startup.value.order
      up_delay   = startup.value.up_delay
      down_delay = startup.value.down_delay
    }
  }

  dynamic "console" {
    for_each = var.console_mode == null && var.tty_count == null && var.console == null ? [] : [1]
    content {
      type      = var.console_mode
      tty_count = var.tty_count
      enabled   = var.console
    }
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

  # mp0, mp1, ... in list order: a volume on a storage (volume = the storage, size_gib) or a bind mount of a host
  # directory (volume = its path; adding one needs root@pam).
  dynamic "mount_point" {
    for_each = var.mount_points
    content {
      volume        = mount_point.value.volume
      path          = mount_point.value.path
      size          = mount_point.value.size_gib == null ? null : "${mount_point.value.size_gib}G"
      backup        = mount_point.value.backup
      read_only     = mount_point.value.read_only
      mount_options = mount_point.value.mount_options
      acl           = mount_point.value.acl
      quota         = mount_point.value.quota
      replicate     = mount_point.value.replicate
      shared        = mount_point.value.shared
    }
  }

  network_interface {
    name        = "eth0"
    bridge      = var.bridge
    vlan_id     = var.vlan_id
    mac_address = var.mac_address
    firewall    = var.firewall
    mtu         = var.mtu
  }

  # net1, net2, ... in list order: the provider numbers interfaces by position (no gaps)
  dynamic "network_interface" {
    for_each = var.extra_nics
    content {
      name        = network_interface.value.name
      bridge      = network_interface.value.bridge
      vlan_id     = network_interface.value.vlan_id
      mac_address = network_interface.value.mac_address
      firewall    = network_interface.value.firewall
      mtu         = network_interface.value.mtu
    }
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
    # one per extra interface, in the same order. The provider pairs them by position among the interfaces that
    # have an address, so each has IPv4 settings (dhcp by default).
    dynamic "ip_config" {
      for_each = var.extra_nics
      content {
        ipv4 {
          address = ip_config.value.ipv4_address
          gateway = ip_config.value.ipv4_address == "dhcp" ? null : ip_config.value.ipv4_gateway
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

locals {
  extra_gateways = [for n in var.extra_nics : n.ipv4_gateway if n.ipv4_gateway != null && n.ipv4_address != null && n.ipv4_address != "dhcp"]
}

# Warnings in the plan, not errors: a container on an isolated network may have no gateway on purpose (a gateway on
# an extra interface counts), and several default routes may be deliberate.
check "static_address_gateway" {
  assert {
    condition = var.ipv4_address == "dhcp" || length(local.extra_gateways) > 0 || try(
      cidrhost(var.ipv4_address, 0) == cidrhost("${var.ipv4_gateway}/${split("/", var.ipv4_address)[1]}", 0), false
    )
    error_message = "Container ${var.hostname}: static address ${var.ipv4_address} has ${try(length(var.ipv4_gateway), 0) == 0 ? "no gateway (defaults.ipv4_gateway)" : "gateway ${var.ipv4_gateway} outside its subnet"}, so it has no default route."
  }
  assert {
    condition     = length(local.extra_gateways) + (var.ipv4_address != "dhcp" && try(length(var.ipv4_gateway), 0) > 0 ? 1 : 0) <= 1
    error_message = "Container ${var.hostname}: an IPv4 gateway on more than one interface gives it several default routes."
  }
}
