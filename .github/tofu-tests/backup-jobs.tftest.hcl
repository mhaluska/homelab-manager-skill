# Backup jobs as data (GitHub issue #151), planned against a mocked Proxmox provider.
mock_provider "proxmox" {}

variables {
  defaults = {
    node            = "pve1"
    datastore       = "local-zfs"
    bridge          = "vmbr0"
    admin_user      = "admin"
    ssh_public_keys = []
  }
  base_images = {}
  vms         = {}
  containers  = {}
}

run "no_backup_jobs" {
  command = plan
  assert {
    condition     = length(proxmox_backup_job.this) == 0
    error_message = "no job is managed until one is listed"
  }
}

run "backup_jobs" {
  command = plan
  variables {
    backup_jobs = {
      "backup-daily" = { schedule = "21:00", storage = "pbs1", all = true, exclude = [105, 9000], mode = "snapshot",
      prune_backups = { "keep-daily" = "7" }, notes_template = "{{guestname}}" }
      "backup-weekly" = { schedule = "sat 02:00", storage = "nas-backup", vmid = [101, 102], enabled = false }
      "backup-pool"   = { schedule = "03:30", storage = "nas-backup", pool = "critical" }
    }
  }
  assert {
    condition     = proxmox_backup_job.this["backup-daily"].id == "backup-daily" && proxmox_backup_job.this["backup-daily"].exclude == tolist(["105", "9000"])
    error_message = "the map key is the job ID; VMIDs go to the provider as strings"
  }
  assert {
    condition     = proxmox_backup_job.this["backup-weekly"].vmid == tolist(["101", "102"]) && !proxmox_backup_job.this["backup-weekly"].enabled
    error_message = "vmid or enabled not passed on"
  }
  assert {
    condition     = proxmox_backup_job.this["backup-pool"].pool == "critical" && proxmox_backup_job.this["backup-pool"].vmid == null
    error_message = "pool job not passed on"
  }
}

run "bad_backup_jobs" {
  command = plan
  variables {
    backup_jobs = {
      none      = { schedule = "21:00", storage = "pbs1" }
      two       = { schedule = "21:00", storage = "pbs1", all = true, vmid = [101] }
      lowid     = { schedule = "21:00", storage = "pbs1", vmid = [42] }
      exclusive = { schedule = "21:00", storage = "pbs1", vmid = [101], exclude = [102] }
      mode      = { schedule = "21:00", storage = "pbs1", all = true, mode = "live" }
    }
  }
  expect_failures = [var.backup_jobs]
}
