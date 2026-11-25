# IPv6 of VMs and containers (GitHub issue #155), planned against a mocked Proxmox provider.
mock_provider "proxmox" {}

variables {
  defaults = {
    node            = "pve1"
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExam ci"]
    ipv4_gateway    = "192.0.2.1"
  }
  base_images = {}
}

# Without ipv6_address the guests get no IPv6 settings, as before.
run "vm_without_ipv6" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "app01"
    node            = "pve1"
    vm_id           = 101
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.initialization[0].ip_config[0].ipv6) == 0
    error_message = "VM must not get IPv6 settings unless the entry sets ipv6_address"
  }
}

run "lxc_without_ipv6" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct01"
    node             = "pve1"
    vm_id            = 201
    template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
  }
  assert {
    condition     = length(proxmox_virtual_environment_container.this.initialization[0].ip_config[0].ipv6) == 0
    error_message = "LXC must not get IPv6 settings unless the entry sets ipv6_address"
  }
}

run "vm_static_ipv6" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "app01"
    node            = "pve1"
    vm_id           = 101
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    ipv6_address    = "2001:db8:10::21/64"
    ipv6_gateway    = "fe80::1"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.initialization[0].ip_config[0].ipv6[0].address == "2001:db8:10::21/64"
    error_message = "VM static IPv6 address not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.initialization[0].ip_config[0].ipv6[0].gateway == "fe80::1"
    error_message = "VM IPv6 gateway not applied"
  }
}

# SLAAC and DHCPv6 take the gateway from the router advertisement: a gateway set anyway is not passed on.
run "lxc_slaac" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct01"
    node             = "pve1"
    vm_id            = 201
    template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
    ipv6_address     = "auto"
    ipv6_gateway     = "fe80::1"
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.initialization[0].ip_config[0].ipv6[0].address == "auto"
    error_message = "LXC SLAAC not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.initialization[0].ip_config[0].ipv6[0].gateway == null
    error_message = "LXC SLAAC must not set a gateway"
  }
}

# Entries take ipv6_address / ipv6_gateway; the gateway falls back to defaults.ipv6_gateway.
run "environment_ipv6_entries" {
  command = plan
  variables {
    defaults = {
      node            = "pve1"
      datastore       = "local-zfs"
      bridge          = "vmbr0"
      admin_user      = "admin"
      ssh_public_keys = []
      ipv6_gateway    = "2001:db8:10::1"
    }
    vms = {
      v6static = { vm_id = 101, template_vm_id = 9050, ipv6_address = "2001:db8:10::21/64" }
      v6dhcp   = { vm_id = 102, template_vm_id = 9050, ipv6_address = "dhcp" }
    }
    containers = {
      c6 = { vm_id = 201, template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst", ipv6_address = "2001:db8:10::31/64",
      ipv6_gateway = "fe80::1" }
    }
  }
}

run "bad_ipv6_values" {
  command = plan
  variables {
    vms = { v6 = { vm_id = 101, template_vm_id = 9050, ipv6_address = "2001:db8::5" } }
    containers = { c6 = { vm_id = 201, template_file_id = "local:vztmpl/x.tar.zst", ipv6_address = "2001:db8::6/64",
    ipv6_gateway = "192.0.2.1" } }
  }
  expect_failures = [var.vms, var.containers]
}
