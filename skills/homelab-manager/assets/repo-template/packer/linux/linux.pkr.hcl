locals {
  template_name = "tpl-${var.distro}${var.distro_version}-${var.build_date}"
  # A site file (site-<name>.pkrvars.hcl) sets `site`; with_secrets.py sets proxmox_site from the token's site.
  # Another site's token fails here ("Error in function call", regex) before anything is cloned.
  site_note = var.site == "" ? "" : " Site ${regex("^${var.site}$", var.proxmox_site)}."
}

source "proxmox-clone" "linux" {
  insecure_skip_tls_verify = var.insecure_skip_tls_verify
  node                     = var.node
  clone_vm_id              = var.base_vm_id
  full_clone               = true
  vm_id                    = var.vm_id
  vm_name                  = local.template_name
  template_name            = local.template_name
  template_description     = "Built by Packer from base VMID ${var.base_vm_id} on ${var.build_date}. homelab-infrastructure/packer/linux${local.site_note}"
  tags                     = "template;${var.distro}"

  cores           = 2
  memory          = 2048
  cpu_type        = "x86-64-v2-AES"
  scsi_controller = "virtio-scsi-single"
  qemu_agent      = true
  os              = "l26"

  network_adapters {
    bridge = var.bridge
    model  = "virtio"
  }

  cloud_init              = true
  cloud_init_storage_pool = var.storage
  ipconfig {
    ip      = var.build_ip
    gateway = var.build_gateway
  }

  # Packer generates a temporary key pair and injects it via cloud-init.
  ssh_username = var.ssh_username
  ssh_host     = split("/", var.build_ip)[0]
  ssh_timeout  = "15m"
  task_timeout = "10m"
}

build {
  sources = ["source.proxmox-clone.linux"]

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo env {{ .Vars }} {{ .Path }}"
    script          = "${path.root}/scripts/provision.sh"
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo env {{ .Vars }} {{ .Path }}"
    script          = "${path.root}/scripts/cleanup.sh"
  }

  post-processor "manifest" {
    output     = "${path.root}/manifest.json"
    strip_path = true
    custom_data = {
      template_name = local.template_name
      vm_id         = var.vm_id
      base_vm_id    = var.base_vm_id
      distro        = "${var.distro}${var.distro_version}"
    }
  }
}
