# Desired state of the homelab. Edited by the homelab-manager skill (and by you).
# No secrets here — tokens come from the keychain at runtime.

# Filled from homelab.yaml on first use.
# defaults = {
#   node            = "pve1"
#   datastore       = "local-zfs"
#   image_datastore = "local"
#   lxc_datastore   = "local-zfs"            # optional, LXC root filesystems
#   node_datastores = {                      # optional, a node with other storage (proxmox.nodes)
#     pve3 = { datastore = "local-lvm" }
#   }
#   bridge          = "vmbr0"
#   admin_user      = "admin"
#   ssh_public_keys = ["ssh-ed25519 AAAA... marek@macmini"]
#   dns_servers     = ["10.0.10.1"]
#   dns_domain      = "home.arpa"
#   ipv4_gateway    = "10.0.10.1"
#   ipv6_gateway    = "fe80::1"              # optional, for entries with a static ipv6_address
#   snippets_datastore = "local"             # optional, proxmox.snippets_storage (needs snippets content)
# }

base_images = {
  # "base-rocky9-20261112" = {
  #   distro          = "rocky"
  #   vm_id           = 9000
  #   image_url       = "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2"   # dated, never latest
  #   image_file_name = "rocky9-genericcloud-20261112.qcow2"
  #   checksum        = "<sha256 from CHECKSUM file>"   # required (allow_unverified_image = true skips the check)
  # }
}

vms = {
  # "app01" = {
  #   vm_id          = 101
  #   template_vm_id = 9050          # tpl-rocky9-20261116
  #   cores          = 4
  #   memory_mib     = 8192
  #   disk_gib       = 40
  #   ipv4_address   = "10.0.10.21/24"
  #   tags           = ["rocky"]
  #   ansible_groups = ["rocky"]
  #   # optional: ipv4_gateway (else defaults), vlan_id, cpu_type ("x86-64-v2-AES"), on_boot (true),
  #   # protection (false; true: Proxmox refuses to delete it), description, started (true), extra_disks,
  #   # ipv6_address ("dhcp", "auto" for SLAAC, or CIDR) and ipv6_gateway (static only; else defaults),
  #   # cloud_init_snippet (vendor data file in tofu/snippets/, first boot only; cloud_init_user_snippet
  #   # replaces the admin user and keys), pci_devices ([{ mapping = "gpu", pcie = true }], needs node and
  #   # machine = "q35")
  # }
}

lxc_templates = {
  # "debian-13-standard-13.1-2" = {
  #   url      = "http://download.proxmox.com/images/system/debian-13-standard_13.1-2_amd64.tar.zst"
  #   checksum = "<sha512sum from Proxmox's aplinfo index>"   # required; checksum_algorithm (sha512) for others
  #   # optional: node (else defaults), datastore (needs vztmpl content; else image_datastore), file_name
  # }
}

containers = {
  # "dns01" = {
  #   vm_id            = 201
  #   template_file_id = "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst"   # or template = "<lxc_templates key>"
  #   ipv4_address     = "10.0.10.31/24"
  #   # optional: ipv4_gateway, vlan_id, dns_servers / dns_domain (else the node's), on_boot (true),
  #   # protection (false), description, cores, memory_mib, swap_mib, disk_gib, unprivileged, nesting,
  #   # ipv6_address ("dhcp", "auto" for SLAAC, or CIDR) and ipv6_gateway (static only; else defaults)
  # }
}

# vzdump jobs (backup-jobs.tf). Import an existing job before its first plan; the key is its job ID.
backup_jobs = {
  # "backup-3f2a9c1e-5b7d" = {
  #   schedule = "21:00"
  #   storage  = "pbs1"
  #   all      = true          # or vmid = [101, 102], or pool = "..."
  #   exclude  = [105]
  #   # copy every other setting the job has: mode, compress, prune_backups, notes_template, comment, ...
  # }
}
