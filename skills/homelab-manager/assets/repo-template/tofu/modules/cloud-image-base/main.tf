# Official cloud image → a "base" template. Packer (proxmox-clone) builds the
# versioned, customised templates from this base. Bases are immutable too: a new
# image release gets a new module instance with a new name and VMID.
resource "proxmox_download_file" "image" {
  content_type        = var.image_content_type
  datastore_id        = var.image_datastore
  node_name           = var.node
  url                 = var.image_url
  file_name           = var.image_file_name
  checksum            = var.checksum
  checksum_algorithm  = var.checksum == null ? null : var.checksum_algorithm
  overwrite           = false
  overwrite_unmanaged = false

  lifecycle {
    precondition {
      condition     = var.checksum != null || var.allow_unverified_image
      error_message = "Base image ${var.name}: set checksum (from the distribution's CHECKSUM or SHA256SUMS file) so a tampered or truncated download is refused, or allow_unverified_image = true."
    }
  }
}

resource "proxmox_virtual_environment_vm" "base" {
  name        = var.name
  node_name   = var.node
  vm_id       = var.vm_id
  template    = true
  started     = false
  description = "Base image ${var.image_file_name} from ${var.image_url}. Managed by OpenTofu."
  tags        = ["tofu", "base-image", var.distro]

  agent {
    enabled = true
  }

  cpu {
    cores = 2
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = 2048
  }

  scsi_hardware = "virtio-scsi-single"

  disk {
    datastore_id = var.datastore
    interface    = "scsi0"
    import_from  = proxmox_download_file.image.id
    size         = var.disk_gib
    discard      = "on"
    iothread     = true
  }

  network_device {
    bridge = var.bridge
    model  = "virtio"
  }

  initialization {
    datastore_id = var.datastore
    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }
  }

  operating_system {
    type = "l26"
  }

  serial_device {}

  vga {
    type = "serial0"
  }
}
