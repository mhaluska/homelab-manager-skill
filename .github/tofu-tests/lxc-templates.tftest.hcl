# LXC templates downloaded by OpenTofu (GitHub issue #155), planned against a mocked Proxmox provider.
mock_provider "proxmox" {
  # a made-up ID would fail the container's template file ID check
  mock_resource "proxmox_download_file" {
    defaults = { id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst" }
  }
}

variables {
  defaults = {
    node            = "pve1"
    datastore       = "local-zfs"
    image_datastore = "local"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExam ci"]
    ipv4_gateway    = "192.0.2.1"
  }
  base_images = {}
  vms         = {}
}

run "template_download" {
  command = plan
  variables {
    lxc_templates = {
      debian13 = { url = "http://download.proxmox.com/images/system/debian-13-standard_13.1-2_amd64.tar.zst", checksum = "00" }
      alpine = { url = "https://images.example.com/alpine-3.22-default_20260101_amd64.tar.xz", checksum = "11", checksum_algorithm = "sha256",
      node = "pve2", datastore = "nfs-templates" }
    }
    containers = {
      ct01 = { vm_id = 201, template = "debian13" }
      ct02 = { vm_id = 202, template_file_id = "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst" }
    }
  }
  assert {
    condition     = proxmox_download_file.lxc_template["debian13"].content_type == "vztmpl" && proxmox_download_file.lxc_template["debian13"].checksum_algorithm == "sha512"
    error_message = "LXC templates must be vztmpl downloads checked with sha512 by default"
  }
  assert {
    condition     = proxmox_download_file.lxc_template["debian13"].datastore_id == "local" && proxmox_download_file.lxc_template["debian13"].node_name == "pve1"
    error_message = "an LXC template without node/datastore goes to the default node's image datastore"
  }
  assert {
    condition     = proxmox_download_file.lxc_template["alpine"].datastore_id == "nfs-templates" && proxmox_download_file.lxc_template["alpine"].node_name == "pve2"
    error_message = "an LXC template's own node and datastore win"
  }
  assert {
    condition     = !proxmox_download_file.lxc_template["debian13"].overwrite_unmanaged
    error_message = "an LXC template download must not replace a file it doesn't manage"
  }
}

run "template_and_file_id" {
  command = plan
  variables {
    lxc_templates = {}
    containers = {
      both    = { vm_id = 201, template = "debian13", template_file_id = "local:vztmpl/x.tar.zst" }
      neither = { vm_id = 202 }
    }
  }
  expect_failures = [var.containers]
}

run "bad_template_checksum_algorithm" {
  command = plan
  variables {
    lxc_templates = { t = { url = "https://images.example.com/x.tar.xz", checksum = "00", checksum_algorithm = "sha-256" } }
    containers    = {}
  }
  expect_failures = [var.lxc_templates]
}
