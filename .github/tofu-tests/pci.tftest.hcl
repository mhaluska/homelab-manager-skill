# PCI passthrough by resource mapping (GitHub issue #155), planned against a mocked Proxmox provider.
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
  containers  = {}
}

run "vm_without_pci" {
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
    condition     = length(proxmox_virtual_environment_vm.this.hostpci) == 0 && proxmox_virtual_environment_vm.this.machine == null
    error_message = "a VM without pci_devices must get no hostpci and no machine type"
  }
}

run "vm_gpu_mapping" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "gpu01"
    node            = "pve1"
    vm_id           = 101
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    machine         = "q35"
    pci_devices     = [{ mapping = "gpu", pcie = true }, { mapping = "nic-10g" }]
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.hostpci[0].device == "hostpci0" && proxmox_virtual_environment_vm.this.hostpci[0].mapping == "gpu" && proxmox_virtual_environment_vm.this.hostpci[0].pcie
    error_message = "first mapping not passed as hostpci0"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.hostpci[1].device == "hostpci1" && proxmox_virtual_environment_vm.this.hostpci[1].id == null
    error_message = "second mapping not passed as hostpci1, or a raw ID set"
  }
}

run "vm_pcie_without_q35" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "gpu01"
    node            = "pve1"
    vm_id           = 101
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    pci_devices     = [{ mapping = "gpu", pcie = true }]
  }
  expect_failures = [proxmox_virtual_environment_vm.this]
}

run "environment_pci_entry" {
  command = plan
  variables {
    vms = {
      gpu01 = { vm_id = 101, template_vm_id = 9050, node = "pve1", machine = "q35", pci_devices = [{ mapping = "gpu", pcie = true }] }
    }
  }
}

# A ROM file (romfile, under /usr/share/kvm/ on the node), e.g. a GPU's vBIOS; a path out of that folder is refused.
run "vm_rom_file" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "gpu01"
    node            = "pve1"
    vm_id           = 101
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    pci_devices     = [{ mapping = "gpu", rombar = true, rom_file = "vbios.rom" }, { mapping = "nic-10g" }]
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.hostpci[0].rom_file == "vbios.rom" && proxmox_virtual_environment_vm.this.hostpci[0].rombar && proxmox_virtual_environment_vm.this.hostpci[1].rom_file == null
    error_message = "rom_file must reach hostpci0 only"
  }
}

run "bad_rom_file" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "gpu01"
    node            = "pve1"
    vm_id           = 101
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    pci_devices     = [{ mapping = "gpu", rom_file = "../../etc/passwd" }]
  }
  expect_failures = [var.pci_devices]
}

# A device belongs to one node: the entry must name it; a raw PCI ID is not a mapping.
run "bad_pci_entries" {
  command = plan
  variables {
    vms = {
      nonode = { vm_id = 101, template_vm_id = 9050, pci_devices = [{ mapping = "gpu" }] }
      rawid  = { vm_id = 102, template_vm_id = 9050, node = "pve1", pci_devices = [{ mapping = "0000:01:00.0" }] }
    }
  }
  expect_failures = [var.vms]
}
