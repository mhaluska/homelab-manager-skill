# Guests with more than one NIC (extra_nics, GitHub issue #149), planned against a mocked Proxmox provider. The
# entry's own NIC attributes stay the first NIC (net0 / eth0); extra_nics are net1, net2, ... in list order.
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

# Without extra_nics a guest plans one NIC and one ip_config, as before.
run "vm_one_nic_as_before" {
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
    ipv4_address    = "192.0.2.21/24"
    ipv4_gateway    = "192.0.2.1"
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.network_device) == 1 && proxmox_virtual_environment_vm.this.network_device[0].model == "virtio" && proxmox_virtual_environment_vm.this.network_device[0].disconnected == null
    error_message = "VM without extra_nics must keep one virtio NIC"
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.initialization[0].ip_config) == 1
    error_message = "VM without extra_nics must keep one ip_config"
  }
  assert {
    condition     = output.ipv4 == "192.0.2.21"
    error_message = "ipv4 output must stay the first NIC's address"
  }
}

run "lxc_one_nic_as_before" {
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
    condition     = length(proxmox_virtual_environment_container.this.network_interface) == 1 && proxmox_virtual_environment_container.this.network_interface[0].name == "eth0"
    error_message = "LXC without extra_nics must keep one interface, eth0"
  }
  assert {
    condition     = length(proxmox_virtual_environment_container.this.initialization[0].ip_config) == 1
    error_message = "LXC without extra_nics must keep one ip_config"
  }
}

# One extra NIC with its own cloud-init address and the gateway; the first NIC on DHCP.
run "vm_one_extra_nic" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "router01"
    node            = "pve1"
    vm_id           = 102
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    extra_nics = [{ bridge = "vmbr1", vlan_id = 20, mac_address = "BC:24:11:0A:00:16", firewall = true, mtu = 9000, queues = 4,
    ipv4_address = "198.51.100.5/24", ipv4_gateway = "198.51.100.1", ipv6_address = "auto" }]
  }
  assert {
    condition = (length(proxmox_virtual_environment_vm.this.network_device) == 2
      && proxmox_virtual_environment_vm.this.network_device[0].bridge == "vmbr0"
      && proxmox_virtual_environment_vm.this.network_device[1].bridge == "vmbr1"
      && proxmox_virtual_environment_vm.this.network_device[1].vlan_id == 20
      && proxmox_virtual_environment_vm.this.network_device[1].mac_address == "BC:24:11:0A:00:16"
      && proxmox_virtual_environment_vm.this.network_device[1].model == "virtio"
      && proxmox_virtual_environment_vm.this.network_device[1].firewall
      && proxmox_virtual_environment_vm.this.network_device[1].mtu == 9000
    && proxmox_virtual_environment_vm.this.network_device[1].queues == 4)
    error_message = "VM extra NIC must be net1 with its own settings"
  }
  assert {
    condition = (length(proxmox_virtual_environment_vm.this.initialization[0].ip_config) == 2
      && proxmox_virtual_environment_vm.this.initialization[0].ip_config[0].ipv4[0].address == "dhcp"
      && proxmox_virtual_environment_vm.this.initialization[0].ip_config[1].ipv4[0].address == "198.51.100.5/24"
      && proxmox_virtual_environment_vm.this.initialization[0].ip_config[1].ipv4[0].gateway == "198.51.100.1"
      && proxmox_virtual_environment_vm.this.initialization[0].ip_config[1].ipv6[0].address == "auto"
    && proxmox_virtual_environment_vm.this.initialization[0].ip_config[1].ipv6[0].gateway == null)
    error_message = "VM extra NIC must get ipconfig1"
  }
  assert {
    condition     = output.ipv4 == "198.51.100.5"
    error_message = "ipv4 output must fall back to the extra NIC's static address when the first NIC uses DHCP"
  }
}

# Two extra NICs: the one without an address still holds its ip_config position when a later one has one; trailing
# NICs without an address get none (Proxmox has no empty ipconfigN).
run "vm_two_extra_nics" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "router02"
    node            = "pve1"
    vm_id           = 103
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    ipv4_address    = "192.0.2.22/24"
    ipv4_gateway    = "192.0.2.1"
    extra_nics = [
      { bridge = "vmbr1", model = "e1000", disconnected = true },
      { bridge = "vmbr2", ipv4_address = "dhcp" },
    ]
  }
  assert {
    condition = (length(proxmox_virtual_environment_vm.this.network_device) == 3
      && proxmox_virtual_environment_vm.this.network_device[1].model == "e1000"
      && proxmox_virtual_environment_vm.this.network_device[1].disconnected
      && proxmox_virtual_environment_vm.this.network_device[1].vlan_id == null
      && proxmox_virtual_environment_vm.this.network_device[2].bridge == "vmbr2"
    && proxmox_virtual_environment_vm.this.network_device[2].disconnected == null)
    error_message = "VM extra NICs must be net1 and net2 in list order"
  }
  assert {
    condition = (length(proxmox_virtual_environment_vm.this.initialization[0].ip_config) == 3
      && length(proxmox_virtual_environment_vm.this.initialization[0].ip_config[1].ipv4) == 0
      && length(proxmox_virtual_environment_vm.this.initialization[0].ip_config[1].ipv6) == 0
    && proxmox_virtual_environment_vm.this.initialization[0].ip_config[2].ipv4[0].address == "dhcp")
    error_message = "VM ip_config must keep the positions of the NICs"
  }
  assert {
    condition     = output.ipv4 == "192.0.2.22"
    error_message = "ipv4 output must stay the first NIC's address"
  }
}

run "vm_extra_nics_without_addresses" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name             = "fw01"
    node             = "pve1"
    vm_id            = 104
    template_vm_id   = 9050
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    admin_user       = "admin"
    ssh_public_keys  = []
    cloud_init_drive = false
    extra_nics       = [{ bridge = "vmbr1", vlan_id = 30 }, { bridge = "vmbr1", vlan_id = 40 }]
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.network_device) == 3 && length(proxmox_virtual_environment_vm.this.initialization) == 0
    error_message = "VM without cloud-init drive must get its NICs and no ip_config"
  }
}

run "lxc_two_extra_nics" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct02"
    node             = "pve1"
    vm_id            = 202
    template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
    ipv4_address     = "192.0.2.31/24"
    ipv4_gateway     = "" # none: the gateway is on eth1
    extra_nics = [
      { name = "eth1", bridge = "vmbr1", vlan_id = 20, mac_address = "BC:24:11:0A:00:17", firewall = true, mtu = 1400,
      ipv4_address = "198.51.100.31/24", ipv4_gateway = "198.51.100.1" },
      { name = "mgmt", bridge = "vmbr2", ipv6_address = "2001:db8:20::31/64", ipv6_gateway = "2001:db8:20::1" },
    ]
  }
  assert {
    condition = (length(proxmox_virtual_environment_container.this.network_interface) == 3
      && proxmox_virtual_environment_container.this.network_interface[0].name == "eth0"
      && proxmox_virtual_environment_container.this.network_interface[1].name == "eth1"
      && proxmox_virtual_environment_container.this.network_interface[1].bridge == "vmbr1"
      && proxmox_virtual_environment_container.this.network_interface[1].vlan_id == 20
      && proxmox_virtual_environment_container.this.network_interface[1].mac_address == "BC:24:11:0A:00:17"
      && proxmox_virtual_environment_container.this.network_interface[1].firewall
      && proxmox_virtual_environment_container.this.network_interface[1].mtu == 1400
    && proxmox_virtual_environment_container.this.network_interface[2].name == "mgmt")
    error_message = "LXC extra interfaces must be net1 and net2 in list order"
  }
  assert {
    condition = (length(proxmox_virtual_environment_container.this.initialization[0].ip_config) == 3
      && proxmox_virtual_environment_container.this.initialization[0].ip_config[0].ipv4[0].gateway == ""
      && proxmox_virtual_environment_container.this.initialization[0].ip_config[1].ipv4[0].address == "198.51.100.31/24"
      && proxmox_virtual_environment_container.this.initialization[0].ip_config[1].ipv4[0].gateway == "198.51.100.1"
      && proxmox_virtual_environment_container.this.initialization[0].ip_config[2].ipv4[0].address == "dhcp"
    && proxmox_virtual_environment_container.this.initialization[0].ip_config[2].ipv6[0].gateway == "2001:db8:20::1")
    error_message = "LXC ip_config must follow the interfaces, each with IPv4 settings"
  }
  assert {
    condition     = output.ipv4 == "192.0.2.31"
    error_message = "ipv4 output must stay eth0's address"
  }
}

# A gateway on two NICs is a warning (several default routes), not an error.
run "lxc_two_gateways_warn" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct03"
    node             = "pve1"
    vm_id            = 203
    template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
    ipv4_address     = "192.0.2.32/24"
    ipv4_gateway     = "192.0.2.1"
    extra_nics       = [{ name = "eth1", bridge = "vmbr1", ipv4_address = "198.51.100.32/24", ipv4_gateway = "198.51.100.1" }]
  }
  expect_failures = [check.static_address_gateway]
}

# Entries: extra NICs default to defaults.bridge (and virtio), an LXC interface's name to eth<position> (the
# module's validation refuses a missing name or bridge, a duplicate name, an unknown model).
run "environment_nic_entries" {
  command = plan
  variables {
    vms = {
      plain = { vm_id = 101, template_vm_id = 9050, ipv4_address = "192.0.2.21/24" }
      multi = { vm_id = 102, template_vm_id = 9050, extra_nics = [{ vlan_id = 20 }, { bridge = "vmbr1", model = "vmxnet3", ipv4_address = "198.51.100.42/24" }] }
    }
    containers = {
      ct = { vm_id = 201, template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst",
      extra_nics = [{ ipv4_address = "198.51.100.41/24" }, { name = "wg", bridge = "vmbr1" }] }
    }
  }
  assert {
    condition     = output.ansible_hosts["plain"].ansible_host == "192.0.2.21" && output.ansible_hosts["multi"].ansible_host == "198.51.100.42"
    error_message = "ansible_host must be the first NIC's static address, else an extra NIC's"
  }
  assert {
    condition     = output.ansible_hosts["ct"].ansible_host == "198.51.100.41"
    error_message = "ansible_host must fall back to an extra interface's static address"
  }
}

run "bad_nic_entries" {
  command = plan
  variables {
    vms = { v = { vm_id = 101, template_vm_id = 9050, extra_nics = [{ vlan_id = 5000, mac_address = "BC:24:11:0A:00", model = "ne2k" }] } }
    containers = { c = { vm_id = 201, template_file_id = "local:vztmpl/x.tar.zst",
    extra_nics = [{ name = "eth0", ipv4_address = "198.51.100.5", ipv6_gateway = "198.51.100.1" }] } }
  }
  expect_failures = [var.vms, var.containers]
}

run "bad_nic_entry_addresses" {
  command = plan
  variables {
    vms        = { v = { vm_id = 101, template_vm_id = 9050, extra_nics = [{ ipv4_address = "dhcp6" }] } }
    containers = { c = { vm_id = 201, template_file_id = "local:vztmpl/x.tar.zst", extra_nics = [{ name = "eth1" }, { name = "eth1" }] } }
  }
  expect_failures = [var.vms, var.containers]
}

run "bad_module_nics" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct04"
    node             = "pve1"
    vm_id            = 204
    template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
    extra_nics       = [{ name = "this-name-is-too-long", bridge = "vmbr1", ipv4_gateway = "198.51.100.1/24" }]
  }
  expect_failures = [var.extra_nics]
}
