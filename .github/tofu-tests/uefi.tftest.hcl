# UEFI VMs: bios, an EFI disk and a TPM state (GitHub issue #149), planned against a mocked Proxmox provider.
# Without them a VM plans what it always did: SeaBIOS, no EFI disk, no TPM.
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

run "vm_seabios_as_before" {
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
    condition = (proxmox_virtual_environment_vm.this.bios == "seabios"
      && length(proxmox_virtual_environment_vm.this.efi_disk) == 0
    && length(proxmox_virtual_environment_vm.this.tpm_state) == 0)
    error_message = "a VM without bios, efi_disk and tpm_state must stay SeaBIOS without EFI disk and TPM"
  }
}

# An older OVMF VM: a 2m EFI disk without Secure Boot keys, on the root disk's storage.
run "vm_ovmf_efi_disk" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "uefi01"
    node            = "pve1"
    vm_id           = 102
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    bios            = "ovmf"
    efi_disk        = { type = "2m" }
  }
  assert {
    condition = (proxmox_virtual_environment_vm.this.bios == "ovmf"
      && proxmox_virtual_environment_vm.this.efi_disk[0].datastore_id == "local-zfs"
      && proxmox_virtual_environment_vm.this.efi_disk[0].type == "2m"
      && !proxmox_virtual_environment_vm.this.efi_disk[0].pre_enrolled_keys
    && length(proxmox_virtual_environment_vm.this.tpm_state) == 0)
    error_message = "efi_disk must default to the root disk's storage, without pre-enrolled keys and without a TPM"
  }
}

# A Windows 11 VM: OVMF, a 4m EFI disk with pre-enrolled keys, a TPM v2.0 and q35.
run "vm_windows11" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name             = "win01"
    node             = "pve1"
    vm_id            = 103
    template_vm_id   = 9060
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    admin_user       = "admin"
    ssh_public_keys  = []
    os_type          = "win11"
    machine          = "q35"
    cloud_init_drive = false
    bios             = "ovmf"
    efi_disk         = { pre_enrolled_keys = true }
    tpm_state        = { datastore = "tank" }
  }
  assert {
    condition = (proxmox_virtual_environment_vm.this.efi_disk[0].type == "4m"
      && proxmox_virtual_environment_vm.this.efi_disk[0].pre_enrolled_keys
      && proxmox_virtual_environment_vm.this.efi_disk[0].datastore_id == "local-zfs"
      && proxmox_virtual_environment_vm.this.tpm_state[0].version == "v2.0"
      && proxmox_virtual_environment_vm.this.tpm_state[0].datastore_id == "tank"
    && proxmox_virtual_environment_vm.this.machine == "q35")
    error_message = "a Windows 11 VM must get a 4m EFI disk with keys and a TPM v2.0 on its own storage"
  }
}

run "bad_module_uefi" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "bad01"
    node            = "pve1"
    vm_id           = 104
    template_vm_id  = 9050
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    bios            = "uefi"
    efi_disk        = { type = "8m" }
    tpm_state       = { version = "v2" }
  }
  expect_failures = [var.bios, var.efi_disk, var.tpm_state]
}

# Entries: left out, the attributes are the module's defaults; an EFI disk's and a TPM's datastore default to the
# entry's root disk storage.
run "environment_uefi_entries" {
  command = plan
  variables {
    vms = {
      plain = { vm_id = 101, template_vm_id = 9050 }
      old   = { vm_id = 102, template_vm_id = 102, bios = "ovmf", efi_disk = { type = "2m" } }
      win = { vm_id = 103, template_vm_id = 9060, datastore = "tank", os_type = "win11", machine = "q35", bios = "ovmf",
      efi_disk = { pre_enrolled_keys = true }, tpm_state = {} }
    }
  }
}

run "bad_uefi_entries" {
  command = plan
  variables {
    vms = {
      bios = { vm_id = 101, template_vm_id = 9050, bios = "uefi" }
      efi  = { vm_id = 102, template_vm_id = 9050, bios = "ovmf", efi_disk = { type = "1m" } }
      tpm  = { vm_id = 103, template_vm_id = 9050, tpm_state = { version = "2.0" } }
    }
  }
  expect_failures = [var.vms]
}
