# Desired state of the homelab. Edited by the homelab-manager skill (and by you).
# No secrets here — tokens come from the keychain at runtime.

defaults = {
  node            = "pve1"
  datastore       = "local-zfs"
  image_datastore = "local"
  bridge          = "vmbr0"
  admin_user      = "marek"
  ssh_public_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly marek@macmini"]
  dns_servers     = ["10.0.10.1"]
  dns_domain      = "home.arpa"
  ipv4_gateway    = "10.0.10.1"
}

# example (old):
# defaults = {
#   node            = "pve1"
#   datastore       = "local-zfs"
#   image_datastore = "local"
#   bridge          = "vmbr0"
#   admin_user      = "admin"
#   ssh_public_keys = ["ssh-ed25519 AAAA... marek@macmini"]
#   dns_servers     = ["10.0.10.1"]
#   dns_domain      = "home.arpa"
#   ipv4_gateway    = "10.0.10.1"
# }

base_images = {
  # "base-rocky9-20261116" = {
  #   distro          = "rocky"
  #   vm_id           = 9000
  #   image_url       = "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"
  #   image_file_name = "rocky9-genericcloud-20261116.qcow2"
  #   checksum        = "<sha256 from CHECKSUM file>"
  # }
}

vms = {
  "dns01" = {
    vm_id          = 100
    template_vm_id = 9049
    cores          = 1
    memory_mib     = 1024
    disk_gib       = 10
    ipv4_address   = "10.0.10.20/24"
    tags           = ["debian"]
    ansible_groups = ["debian"]
  }
  "git01" = {
    vm_id          = 101
    template_vm_id = 9050
    cores          = 4
    memory_mib     = 8192
    disk_gib       = 80
    ipv4_address   = "10.0.10.21/24"
    tags           = ["rocky"]
    ansible_groups = ["rocky"]
  }
  "monitor" = {
    vm_id          = 102
    template_vm_id = 9050
    cores          = 2
    memory_mib     = 4096
    disk_gib       = 40
    ipv4_address   = "10.0.10.22/24"
    tags           = ["rocky"]
    ansible_groups = ["rocky"]
  }
  # "app01" = {
  #   vm_id          = 101
  #   template_vm_id = 9050          # tpl-rocky9-20261116
  #   cores          = 4
  #   memory_mib     = 8192
  #   disk_gib       = 40
  #   ipv4_address   = "10.0.10.21/24"
  #   tags           = ["rocky"]
  #   ansible_groups = ["rocky"]
  # }
}

containers = {}
