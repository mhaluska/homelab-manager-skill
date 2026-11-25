# Plan-only checks of the template's environment with a mocked Proxmox provider (no API, no state).
# validate_template.sh copies this file into the scaffolded environment's tests/ directory and runs `tofu test`.
mock_provider "proxmox" {}

variables {
  defaults = {
    node            = "pve1"
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExam ci"]
    dns_servers     = ["192.0.2.1"]
    dns_domain      = "home.arpa"
    ipv4_gateway    = "192.0.2.1"
  }
  base_images = {}
}

# Module inputs the environment leaves null (an entry without the attribute) plan what earlier versions planned.
run "vm_defaults_unchanged" {
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
    ipv4_address    = "192.0.2.21/24"
    ipv4_gateway    = "192.0.2.1"
    admin_user      = "admin"
    ssh_public_keys = []
    cpu_type        = null
    description     = null
    on_boot         = null
    protection      = null
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.cpu[0].type == "x86-64-v2-AES"
    error_message = "VM cpu type default changed"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.on_boot == true && proxmox_virtual_environment_vm.this.protection == false
    error_message = "VM on_boot or protection default changed"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.description == "Managed by OpenTofu (homelab-infrastructure)"
    error_message = "VM description default changed"
  }
}

run "lxc_defaults_unchanged" {
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
    description      = null
    on_boot          = null
    protection       = null
    dns_servers      = null
    dns_domain       = null
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.start_on_boot == true && proxmox_virtual_environment_container.this.protection == false
    error_message = "LXC start_on_boot or protection default changed"
  }
  assert {
    condition     = length(proxmox_virtual_environment_container.this.initialization[0].dns) == 0
    error_message = "LXC must not get a dns block unless the entry sets one"
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.description == "Managed by OpenTofu (homelab-infrastructure)"
    error_message = "LXC description default changed"
  }
}

run "lxc_options" {
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
    on_boot          = false
    protection       = true
    dns_servers      = ["192.0.2.53"]
    dns_domain       = "lab.example"
  }
  assert {
    condition     = !proxmox_virtual_environment_container.this.start_on_boot && proxmox_virtual_environment_container.this.protection
    error_message = "LXC on_boot or protection not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.initialization[0].dns[0].domain == "lab.example"
    error_message = "LXC dns not applied"
  }
}

# The environment accepts entries with and without the new attributes.
run "environment_entries" {
  command = plan
  variables {
    vms = {
      app01 = { vm_id = 101, template_vm_id = 9050, ipv4_address = "192.0.2.21/24" }
      app02 = { vm_id = 102, template_vm_id = 9050, ipv4_address = "198.51.100.22/24", ipv4_gateway = "198.51.100.1",
      vlan_id = 20, cpu_type = "host", on_boot = false, protection = true, description = "app", extra_disks = [{ interface = "scsi1", size_gib = 10 }] }
    }
    containers = {
      ct01 = { vm_id = 201, template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst" }
      ct02 = { vm_id = 202, template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst", protection = true,
      dns_servers = ["192.0.2.53"], dns_domain = "lab.example", ipv4_address = "192.0.2.32/24" }
    }
  }
}

run "bad_vm_values" {
  command = plan
  variables {
    vms = { bad = { vm_id = 42, template_vm_id = 9050, ipv4_address = "10.0.0.5", vlan_id = 5000,
    extra_disks = [{ interface = "scsi0", size_gib = 10 }] } }
    containers = {}
  }
  expect_failures = [var.vms]
}

run "bad_container_values" {
  command = plan
  variables {
    vms        = {}
    containers = { bad = { vm_id = 201, template_file_id = "local:vztmpl/x.tar.zst", ipv4_address = "dhcp4" } }
  }
  expect_failures = [var.containers]
}

run "bad_checksum_algorithm" {
  command = plan
  variables {
    vms         = {}
    containers  = {}
    base_images = { b = { distro = "debian", vm_id = 9000, image_url = "https://example.com/x.qcow2", image_file_name = "x.qcow2", checksum = "00", checksum_algorithm = "sha-256" } }
  }
  expect_failures = [var.base_images]
}
