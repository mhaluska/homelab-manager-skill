# Settings an imported guest keeps (tofu_import_plan.py, GitHub issue #149), planned against a mocked Proxmox provider.
# The *_as_before runs pass null for every new input, as the environment does for an entry without them: the guest
# must plan exactly what earlier versions planned.
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

run "vm_new_inputs_null_as_before" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name                = "app01"
    node                = "pve1"
    vm_id               = 101
    template_vm_id      = 9050
    datastore           = "local-zfs"
    bridge              = "vmbr0"
    admin_user          = "admin"
    ssh_public_keys     = []
    extra_disks         = [{ interface = "scsi1", size_gib = 10, discard = null, iothread = null, ssd = null, cache = null, backup = null }]
    os_type             = null
    sockets             = null
    numa                = null
    cpu_flags           = null
    memory_floating_mib = null
    startup             = null
    scsi_hardware       = null
    disk_cache          = null
    disk_discard        = null
    disk_iothread       = null
    disk_ssd            = null
    disk_backup         = null
    tablet_device       = null
    agent_trim          = null
    firewall            = null
    mtu                 = null
    queues              = null
    cloud_init_drive    = null
    serial_socket       = null
    cdrom               = null
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.cpu[0].sockets == null && proxmox_virtual_environment_vm.this.cpu[0].numa == null && proxmox_virtual_environment_vm.this.cpu[0].flags == null && proxmox_virtual_environment_vm.this.memory[0].floating == null
    error_message = "VM cpu or memory got a setting earlier versions didn't plan"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.scsi_hardware == "virtio-scsi-single" && proxmox_virtual_environment_vm.this.tablet_device == null && proxmox_virtual_environment_vm.this.operating_system[0].type == "l26" && length(proxmox_virtual_environment_vm.this.startup) == 0 && proxmox_virtual_environment_vm.this.agent[0].enabled && proxmox_virtual_environment_vm.this.agent[0].trim == null
    error_message = "VM controller, tablet, OS type, startup or agent changed"
  }
  assert {
    condition = (proxmox_virtual_environment_vm.this.disk[0].discard == "on" && proxmox_virtual_environment_vm.this.disk[0].iothread && proxmox_virtual_environment_vm.this.disk[0].ssd
    && proxmox_virtual_environment_vm.this.disk[0].cache == null && proxmox_virtual_environment_vm.this.disk[0].backup == null)
    error_message = "root disk options changed"
  }
  assert {
    condition = (proxmox_virtual_environment_vm.this.disk[1].discard == "on" && proxmox_virtual_environment_vm.this.disk[1].iothread && proxmox_virtual_environment_vm.this.disk[1].ssd == null
    && proxmox_virtual_environment_vm.this.disk[1].cache == null && proxmox_virtual_environment_vm.this.disk[1].backup == null && proxmox_virtual_environment_vm.this.disk[1].file_format == "raw")
    error_message = "extra disk options changed"
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.initialization) == 1 && length(proxmox_virtual_environment_vm.this.serial_device) == 1 && length(proxmox_virtual_environment_vm.this.cdrom) == 0
    error_message = "VM must keep its cloud-init drive and serial socket and get no CD-ROM"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.network_device[0].firewall == null && proxmox_virtual_environment_vm.this.network_device[0].mtu == null && proxmox_virtual_environment_vm.this.network_device[0].queues == null
    error_message = "VM NIC got a setting earlier versions didn't plan"
  }
}

run "vm_imported_settings" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name                = "old01"
    node                = "pve1"
    vm_id               = 110
    template_vm_id      = 110
    datastore           = "local-zfs"
    bridge              = "vmbr0"
    admin_user          = "admin"
    ssh_public_keys     = []
    os_type             = "win11"
    sockets             = 2
    numa                = true
    cpu_flags           = ["+aes", "-pcid"]
    memory_floating_mib = 1024
    startup             = { order = 2, up_delay = 30 }
    scsi_hardware       = "virtio-scsi-pci"
    disk_cache          = "writeback"
    disk_ssd            = false
    disk_iothread       = false
    disk_backup         = false
    tablet_device       = false
    agent_trim          = true
    firewall            = true
    mtu                 = 9000
    queues              = 4
    cloud_init_drive    = false
    serial_socket       = false
    cdrom               = "none"
    extra_disks         = [{ interface = "scsi1", size_gib = 100, cache = "writeback", ssd = true, backup = false, discard = "ignore" }]
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.cpu[0].sockets == 2 && proxmox_virtual_environment_vm.this.cpu[0].numa && proxmox_virtual_environment_vm.this.cpu[0].flags == tolist(["+aes", "-pcid"]) && proxmox_virtual_environment_vm.this.memory[0].floating == 1024
    error_message = "VM sockets, numa, flags or ballooning not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.startup[0].order == 2 && proxmox_virtual_environment_vm.this.startup[0].up_delay == 30 && proxmox_virtual_environment_vm.this.startup[0].down_delay == null
    error_message = "VM startup not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.operating_system[0].type == "win11" && proxmox_virtual_environment_vm.this.scsi_hardware == "virtio-scsi-pci" && !proxmox_virtual_environment_vm.this.tablet_device && proxmox_virtual_environment_vm.this.agent[0].trim
    error_message = "VM OS type, controller, tablet or agent trim not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.disk[0].cache == "writeback" && !proxmox_virtual_environment_vm.this.disk[0].ssd && !proxmox_virtual_environment_vm.this.disk[0].iothread && !proxmox_virtual_environment_vm.this.disk[0].backup
    error_message = "root disk options not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.disk[1].cache == "writeback" && proxmox_virtual_environment_vm.this.disk[1].ssd && !proxmox_virtual_environment_vm.this.disk[1].backup && proxmox_virtual_environment_vm.this.disk[1].discard == "ignore" && proxmox_virtual_environment_vm.this.disk[1].iothread
    error_message = "extra disk options not applied"
  }
  assert {
    condition     = length(proxmox_virtual_environment_vm.this.initialization) == 0 && length(proxmox_virtual_environment_vm.this.serial_device) == 0 && proxmox_virtual_environment_vm.this.cdrom[0].interface == "ide2" && proxmox_virtual_environment_vm.this.cdrom[0].file_id == "none"
    error_message = "VM must keep no cloud-init drive and no serial port, and its CD-ROM on ide2"
  }
  assert {
    condition     = proxmox_virtual_environment_vm.this.network_device[0].firewall && proxmox_virtual_environment_vm.this.network_device[0].mtu == 9000 && proxmox_virtual_environment_vm.this.network_device[0].queues == 4
    error_message = "VM NIC settings not applied"
  }
}

# Both use ide2.
run "vm_cdrom_with_cloud_init" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name            = "old01"
    node            = "pve1"
    vm_id           = 110
    template_vm_id  = 110
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
    cdrom           = "local:iso/debian-13.iso"
  }
  expect_failures = [proxmox_virtual_environment_vm.this]
}

run "vm_bad_imported_values" {
  command = plan
  module {
    source = "../../modules/proxmox-vm"
  }
  variables {
    name             = "old01"
    node             = "pve1"
    vm_id            = 110
    template_vm_id   = 110
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    admin_user       = "admin"
    ssh_public_keys  = []
    cloud_init_drive = false
    disk_cache       = "fast"
    os_type          = "linux"
    cdrom            = "debian-13.iso"
  }
  expect_failures = [var.disk_cache, var.os_type, var.cdrom]
}

run "lxc_new_inputs_null_as_before" {
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
    features         = null
    keyctl           = null
    fuse             = null
    mknod            = null
    mount_types      = null
    mount_points     = null
    startup          = null
    console_mode     = null
    tty_count        = null
    console          = null
    firewall         = null
    mtu              = null
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.features[0].nesting && proxmox_virtual_environment_container.this.features[0].keyctl == null && proxmox_virtual_environment_container.this.features[0].fuse == null && proxmox_virtual_environment_container.this.features[0].mknod == null && proxmox_virtual_environment_container.this.features[0].mount == null
    error_message = "LXC features changed: only nesting, as before"
  }
  assert {
    condition     = length(proxmox_virtual_environment_container.this.startup) == 0 && length(proxmox_virtual_environment_container.this.console) == 0 && length(proxmox_virtual_environment_container.this.mount_point) == 0
    error_message = "LXC got a startup, console or mount point earlier versions didn't plan"
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.network_interface[0].firewall == null && proxmox_virtual_environment_container.this.network_interface[0].mtu == null
    error_message = "LXC interface got a setting earlier versions didn't plan"
  }
}

run "lxc_imported_settings" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct02"
    node             = "pve1"
    vm_id            = 202
    template_file_id = "local:vztmpl/imported.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
    keyctl           = true
    fuse             = true
    mount_types      = ["nfs", "cifs"]
    startup          = { order = 3, up_delay = 5, down_delay = 60 }
    console_mode     = "tty"
    firewall         = true
    mtu              = 1400
    mount_points = [
      { volume = "local-zfs:subvol-202-disk-1", path = "/srv/data", size_gib = 500, backup = true, mount_options = ["noatime"] },
      { volume = "/mnt/media", path = "/media", read_only = true },
    ]
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.features[0].nesting && proxmox_virtual_environment_container.this.features[0].keyctl && proxmox_virtual_environment_container.this.features[0].fuse && proxmox_virtual_environment_container.this.features[0].mount == tolist(["nfs", "cifs"])
    error_message = "LXC features not applied"
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.startup[0].order == 3 && proxmox_virtual_environment_container.this.startup[0].down_delay == 60 && proxmox_virtual_environment_container.this.console[0].type == "tty" && proxmox_virtual_environment_container.this.console[0].tty_count == null
    error_message = "LXC startup or console not applied"
  }
  assert {
    condition = (proxmox_virtual_environment_container.this.mount_point[0].volume == "local-zfs:subvol-202-disk-1" && proxmox_virtual_environment_container.this.mount_point[0].size == "500G"
      && proxmox_virtual_environment_container.this.mount_point[0].backup && proxmox_virtual_environment_container.this.mount_point[0].mount_options == tolist(["noatime"])
    && proxmox_virtual_environment_container.this.mount_point[1].path == "/media" && proxmox_virtual_environment_container.this.mount_point[1].size == null && proxmox_virtual_environment_container.this.mount_point[1].read_only)
    error_message = "LXC mount points not applied in list order"
  }
  assert {
    condition     = proxmox_virtual_environment_container.this.network_interface[0].firewall && proxmox_virtual_environment_container.this.network_interface[0].mtu == 1400
    error_message = "LXC interface settings not applied"
  }
}

# A privileged container imported without a features line keeps none.
run "lxc_no_features" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct03"
    node             = "pve1"
    vm_id            = 203
    template_file_id = "local:vztmpl/imported.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
    unprivileged     = false
    features         = false
  }
  assert {
    condition     = length(proxmox_virtual_environment_container.this.features) == 0
    error_message = "features = false must plan no features block"
  }
}

run "lxc_bad_imported_values" {
  command = plan
  module {
    source = "../../modules/proxmox-lxc"
  }
  variables {
    hostname         = "ct04"
    node             = "pve1"
    vm_id            = 204
    template_file_id = "local:vztmpl/imported.tar.zst"
    datastore        = "local-zfs"
    bridge           = "vmbr0"
    ssh_public_keys  = []
    console_mode     = "serial"
    mount_points     = [{ volume = "local-zfs", path = "srv", size_gib = 8 }]
  }
  expect_failures = [var.console_mode, var.mount_points]
}

# The environment passes every attribute through; entries without them plan as before (vm_new_inputs_null_as_before).
run "environment_imported_entries" {
  command = plan
  variables {
    vms = {
      old01 = { vm_id = 110, template_vm_id = 110, os_type = "other", sockets = 2, numa = true, cpu_flags = ["+aes"],
        memory_floating_mib = 1024, startup = { order = 1 }, scsi_hardware = "lsi", disk_cache = "writeback", disk_ssd = false,
        disk_iothread       = false, disk_discard = "ignore", disk_backup = false, tablet_device = false, agent_trim = true,
        firewall            = true, mtu = 1500, queues = 2, cloud_init_drive = false, serial_socket = false, cdrom = "none",
      extra_disks = [{ interface = "scsi1", size_gib = 10, ssd = true, cache = "writeback", backup = false }] }
      app01 = { vm_id = 101, template_vm_id = 9050, extra_disks = [{ interface = "scsi1", size_gib = 10 }] }
    }
    containers = {
      ct02 = { vm_id = 202, template_file_id = "local:vztmpl/imported.tar.zst", keyctl = true, fuse = true, mknod = true,
        mount_types = ["nfs"], startup = { up_delay = 15 }, console_mode = "tty", tty_count = 4, console = true, firewall = true,
      mtu = 1500, mount_points = [{ volume = "local-zfs:subvol-202-disk-1", path = "/srv", size_gib = 8, replicate = false }] }
      ct03 = { vm_id = 203, template_file_id = "local:vztmpl/imported.tar.zst", unprivileged = false, features = false }
    }
  }
}
