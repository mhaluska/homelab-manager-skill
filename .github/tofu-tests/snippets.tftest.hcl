# Cloud-init snippets of VMs (GitHub issue #154), planned against a mocked Proxmox provider. The paths are relative
# to the environment directory, where `tofu test` runs: the template's tofu/snippets/example-vendor-data.yaml.
mock_provider "proxmox" {
  # a made-up ID would fail the VM's file ID check
  mock_resource "proxmox_virtual_environment_file" {
    defaults = { id = "local:snippets/vm-101-vendor-data.yaml" }
  }
}

variables {
  defaults = {
    node               = "pve1"
    datastore          = "local-zfs"
    bridge             = "vmbr0"
    admin_user         = "admin"
    ssh_public_keys    = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExam ci"]
    ipv4_gateway       = "192.0.2.1"
    snippets_datastore = "local"
  }
  base_images = {}
  containers  = {}
}

# No snippet: no upload, the built-in user account as before.
run "vm_without_snippets" {
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
    condition     = length(proxmox_virtual_environment_file.cloud_init) == 0
    error_message = "a VM without snippets must not upload one"
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.initialization[0].user_account) == 1
    error_message = "a VM without a user-data snippet keeps the built-in user account"
  }
}

# Vendor data: uploaded under the VMID's name, the built-in user account stays.
run "vm_vendor_snippet" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name               = "app01"
    node               = "pve1"
    vm_id              = 101
    template_vm_id     = 9050
    datastore          = "local-zfs"
    bridge             = "vmbr0"
    admin_user         = "admin"
    ssh_public_keys    = []
    snippets_datastore = "local"
    cloud_init_snippet = "../../snippets/example-vendor-data.yaml"
  }
  assert {
    condition     = keys(proxmox_virtual_environment_file.cloud_init) == ["vendor"]
    error_message = "the vendor snippet must be uploaded"
  }
  assert {
    condition     = proxmox_virtual_environment_file.cloud_init["vendor"].source_file[0].file_name == "vm-101-vendor-data.yaml" && proxmox_virtual_environment_file.cloud_init["vendor"].content_type == "snippets"
    error_message = "the vendor snippet must be a snippets file named after the VMID"
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.initialization[0].user_account) == 1
    error_message = "vendor data must keep the built-in user account"
  }
}

# User data replaces the built-in user account (the provider refuses both).
run "vm_user_snippet" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name                    = "app01"
    node                    = "pve1"
    vm_id                   = 101
    template_vm_id          = 9050
    datastore               = "local-zfs"
    bridge                  = "vmbr0"
    admin_user              = "admin"
    ssh_public_keys         = []
    snippets_datastore      = "local"
    cloud_init_user_snippet = "../../snippets/example-vendor-data.yaml"
  }
  assert {
    condition     = keys(proxmox_virtual_environment_file.cloud_init) == ["user"]
    error_message = "the user snippet must be uploaded"
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.initialization[0].user_account) == 0
    error_message = "a user-data snippet replaces the built-in user account"
  }
}

run "environment_snippet_entry" {
  command = plan
  variables {
    vms = {
      app01 = { vm_id = 101, template_vm_id = 9050, cloud_init_snippet = "example-vendor-data.yaml" }
      app02 = { vm_id = 102, template_vm_id = 9050 }
    }
  }
}

run "snippet_without_storage" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name               = "app01"
    node               = "pve1"
    vm_id              = 101
    template_vm_id     = 9050
    datastore          = "local-zfs"
    bridge             = "vmbr0"
    admin_user         = "admin"
    ssh_public_keys    = []
    cloud_init_snippet = "../../snippets/example-vendor-data.yaml"
  }
  expect_failures = [proxmox_virtual_environment_file.cloud_init]
}

run "missing_snippet_file" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name               = "app01"
    node               = "pve1"
    vm_id              = 101
    template_vm_id     = 9050
    datastore          = "local-zfs"
    bridge             = "vmbr0"
    admin_user         = "admin"
    ssh_public_keys    = []
    snippets_datastore = "local"
    cloud_init_snippet = "../../snippets/no-such-file.yaml"
  }
  expect_failures = [proxmox_virtual_environment_file.cloud_init]
}

run "bad_snippet_name" {
  command = plan
  variables {
    vms = { app01 = { vm_id = 101, template_vm_id = 9050, cloud_init_snippet = "../secrets.yaml" } }
  }
  expect_failures = [var.vms]
}
