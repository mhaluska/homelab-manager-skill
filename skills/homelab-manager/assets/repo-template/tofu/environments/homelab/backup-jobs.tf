# Scheduled vzdump backup jobs of this site's cluster (Datacenter → Backup), as data in homelab.auto.tfvars:
#   backup_jobs = { "<job id>" = { schedule = "21:00", storage = "pbs1", all = true, exclude = [105] } }
# Empty by default: nothing is managed until a job is listed. Import an existing job before its first plan
# (references/proxmox.md "Backup jobs"); its ID is backup_jobs[].id in discovery/proxmox.json. Changing jobs needs
# the optional grant in docs/proxmox-tokens.md ("Backup jobs").
variable "backup_jobs" {
  description = "vzdump backup jobs by job ID. An attribute left out keeps the job's current value where Proxmox has a default."
  type = map(object({
    schedule                  = string # systemd calendar event, e.g. "21:00" or "sat 02:00"
    storage                   = string # backup storage (vzdump or PBS)
    enabled                   = optional(bool)
    all                       = optional(bool)         # every guest (of node, when set), minus exclude
    vmid                      = optional(list(number)) # or these guests
    pool                      = optional(string)       # or the guests of a pool
    exclude                   = optional(list(number)) # with all or pool
    node                      = optional(string)       # only guests on this node
    mode                      = optional(string)       # snapshot, suspend or stop
    compress                  = optional(string)       # zstd, lzo, gzip or 0
    prune_backups             = optional(map(string))  # e.g. { "keep-daily" = "7", "keep-weekly" = "4" }
    notes_template            = optional(string)       # e.g. "{{guestname}}"
    comment                   = optional(string)
    protected                 = optional(bool)
    repeat_missed             = optional(bool)
    mailto                    = optional(list(string))
    mailnotification          = optional(string)
    notification_mode         = optional(string)
    bwlimit                   = optional(number)
    zstd                      = optional(number)
    pbs_change_detection_mode = optional(string)
    fleecing                  = optional(object({ enabled = optional(bool), storage = optional(string) }))
    performance               = optional(object({ max_workers = optional(number), pbs_entries_max = optional(number) }))
  }))
  default = {}
  validation {
    condition     = length([for k, v in var.backup_jobs : k if length([for s in [v.all == true, length(coalesce(v.vmid, [])) > 0, v.pool != null] : s if s]) != 1]) == 0
    error_message = "backup_jobs ${join(", ", [for k, v in var.backup_jobs : k if length([for s in [v.all == true, length(coalesce(v.vmid, [])) > 0, v.pool != null] : s if s]) != 1])}: choose the guests one way: all = true, vmid = [...] or pool = \"...\"."
  }
  validation {
    condition     = length([for k, v in var.backup_jobs : k if !alltrue([for i in concat(coalesce(v.vmid, []), coalesce(v.exclude, [])) : i >= 100 && i == floor(i)]) || length(coalesce(v.exclude, [])) > 0 && v.all != true && v.pool == null]) == 0
    error_message = "backup_jobs ${join(", ", [for k, v in var.backup_jobs : k if !alltrue([for i in concat(coalesce(v.vmid, []), coalesce(v.exclude, [])) : i >= 100 && i == floor(i)]) || length(coalesce(v.exclude, [])) > 0 && v.all != true && v.pool == null])}: vmid and exclude take VMIDs (whole numbers of 100 or more); exclude only goes with all or pool."
  }
  validation {
    condition     = length([for k, v in var.backup_jobs : k if v.mode != null && !contains(["snapshot", "suspend", "stop"], coalesce(v.mode, "snapshot"))]) == 0
    error_message = "backup_jobs ${join(", ", [for k, v in var.backup_jobs : k if v.mode != null && !contains(["snapshot", "suspend", "stop"], coalesce(v.mode, "snapshot"))])}: mode must be snapshot, suspend or stop."
  }
}

resource "proxmox_backup_job" "this" {
  for_each = var.backup_jobs

  id                        = each.key
  schedule                  = each.value.schedule
  storage                   = each.value.storage
  enabled                   = each.value.enabled
  all                       = each.value.all
  vmid                      = each.value.vmid == null ? null : [for i in each.value.vmid : tostring(i)]
  pool                      = each.value.pool
  exclude                   = each.value.exclude == null ? null : [for i in each.value.exclude : tostring(i)]
  node                      = each.value.node
  mode                      = each.value.mode
  compress                  = each.value.compress
  prune_backups             = each.value.prune_backups
  notes_template            = each.value.notes_template
  comment                   = each.value.comment
  protected                 = each.value.protected
  repeat_missed             = each.value.repeat_missed
  mailto                    = each.value.mailto
  mailnotification          = each.value.mailnotification
  notification_mode         = each.value.notification_mode
  bwlimit                   = each.value.bwlimit
  zstd                      = each.value.zstd
  pbs_change_detection_mode = each.value.pbs_change_detection_mode
  fleecing                  = each.value.fleecing
  performance               = each.value.performance
}
