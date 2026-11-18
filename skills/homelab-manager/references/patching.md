# Patching and updates

## "Find systems missing security updates" (read-only)

```bash
cd ansible && ansible-playbook playbooks/check-updates.yml          # Linux, Windows, QNAP
ansible-playbook playbooks/check-updates.yml -e target=rocky       # subset (prefer this to -l; both write)
```
Merges into `discovery/updates.json`: a subset run updates only its hosts, the others keep their last
result; check each host's `collected_at` before calling it current. Report a table: host, OS, security updates, total, reboot
pending (with `reboot_reasons`), services to restart (`restart_pending`), `low_space`. Sort by security count.
A reboot is due when a newer kernel than the running one is installed (plain Debian has no
`/var/run/reboot-required`), `needs-restarting -r` says so (EL) or the flag file exists. `restart_pending` lists
services whose processes still map deleted binaries or libraries: they run the old (maybe vulnerable) code.
A host that failed or was unreachable gets `error` (the failing step and reason) and `last_ok_at` instead of
counts; the play's last task lists them. They are findings too: report them in the table. Commit the JSON.
QNAP NAS entries carry `firmware` and `apps` instead of package counts (references/windows-appliances.md, QNAP NAS).

## "Patch all Linux servers"

1. Fresh `check-updates.yml` → who actually needs patches. Skip hosts with nothing pending.
2. Group the targets:
   - **Independent hosts** — in parallel batches of `ansible.patch_serial` (homelab.yaml; new repos 5,
     unset = 1); `-e patch_serial=<n|n%>` overrides it for one run. The playbook forces 1 (and refuses a
     larger `-e patch_serial`) for cluster members, `patch_requires_approval` hosts and runs with hooks.
   - **Cluster groups** (`clusters:` in homelab.yaml, plus anything obviously clustered:
     k8s, etcd, Galera/Patroni, Proxmox nodes) — separate run per cluster, `serial: 1`,
     with that cluster's `pre_hook`/`post_hook` from `homelab.yaml` (drain/uncordon, maintenance mode):
     `-e target=k8s_workers -e pre_hook=playbooks/hooks/k8s-drain.yml -e post_hook=playbooks/hooks/k8s-uncordon.yml`.
     Hook paths are relative to `ansible/`. Hooks run on this Mac without sudo (`kubectl` with the
     user's kubeconfig); check `kubectl get nodes` works and node names match inventory names
     (or set `k8s_node_name`) before starting. Keep a full update from upgrading Kubernetes:
     set `patch_exclude: [kubelet, kubeadm, kubectl]` in that group's `group_vars/<group>.yml`
     (the playbook excludes them on dnf and holds them on apt). Never set it as a play var or
     with `-e` scoped wrongly — play vars override group_vars.
     Other clusters (keepalived/VRRP proxies, DNS pairs, DB replicas) pass their entry's settings the same way:
     `-e reboot=always -e health_check=playbooks/hooks/vrrp-health.yml -e order=vip_holder_last -e vip=<ip>`
     (plus `-e snapshot=true` for Proxmox guests). The node holding the VIP goes last, so the VIP moves once;
     after each node the health check (services, optional containers not restart-looping, exactly one VIP
     holder, the VIP answering from this Mac) must pass, or the roll stops there. A cluster without a
     ready-made check: write `playbooks/hooks/<name>-health.yml` like vrrp-health.yml (retry, then fail).
   - **Proxmox nodes** — never via this playbook (it refuses hosts with `patch_requires_approval`):
     use "Patch Proxmox nodes" below, one node at a time, each node an explicit approval.
   - **Critical singletons** the user cares about (DNS, the Git server, the gateway): ask
     whether to include them, and patch them last.
3. Plan for the user: the batch size (state it: the batch can't change mid-run without interrupting the
   package manager), security-only or full, reboot policy.
   Reboots default **off** (`reboot=never`; `if_required` reboots when needed, `always` every host — old
   name `allow_reboot=true` = `if_required`); the run reports `reboot_pending` with the reason and
   `restart_pending`. Offer `-e restart_services=true` (restarts those services, except dbus and logind, when
   the host isn't rebooted anyway): no reboot needed, but each service restarts briefly.
   Offer a pre-patch snapshot (`-e snapshot=true -e hm_scripts=$HM/scripts`): a disk-only snapshot
   `prepatch-<date>` of each host right before its update. Proxmox guests: `pve_snapshot.py` (guest = inventory
   short name or host var `proxmox_vmid`; needs snapshot-capable storage and the provisioning token; a host in a
   `site_<name>` group uses that site's Proxmox). One site at a time: `-e target='site_offsite:&linux'`. Hosts with
   the host var `lxd_host`: `lxd_snapshot.py` (see "LXD/Incus instances" below). Before anything else the run
   checks every target (`pve_snapshot.py check` / `lxd_snapshot.py check`, read-only, also by hand) and refuses
   with the list of hosts that can't be snapshotted: not a Proxmox guest and no `lxd_host`, a container with a
   bind or device mount point, a disk on storage without snapshots, an LXD host without the opt-in, or a `dir`
   pool too full for the copy. Leave them out of the target, or with the user's yes for exactly those hosts
   add `-e snapshot_missing=skip` (patched without a snapshot). Tell the user what the LXD snapshots won't
   contain (the run prints it: bind-mounted data, custom volumes).
   Clean-up: after the reboot (or when there is none) the run autoremoves packages nothing needs, so the old
   kernel goes too (`-e autoremove=false` skips it). It simulates it first and skips it on a host (reported as
   `autoremove skipped`, not a failure) when it would remove a package matching `autoremove_protect`
   (authentication, NSS/PAM, sudo, SSH, systemd, networking) or more than `autoremove_max` (20) packages:
   a removed `freeipa-client` leaves SSSD autoremovable, and removing it locks out an IPA `ansible_user`.
   Free space: before anything is snapshotted or patched the run checks every target for `patch_min_free_mb`
   (500) free on `/` and `/var` and `patch_min_free_boot_mb` (100) on a separate `/boot`, and refuses with the
   list (a full disk mid-batch leaves the batch's other hosts updated but not rebooted or checked).
   check-updates shows `free_mb` and `low_space`: offer `-e clean_cache=true` (cleans the package cache on
   those hosts first) or ask the user to free space. A run stopped part-way can be repeated with the same
   `-e snapshot=true`: a guest that already has that day's `prepatch-<date>` snapshot keeps it.
   Before patching, review check-updates' `autoremove_protected` (and `autoremove_packages`): show the user
   any host that has some, and leave it to them (a package to mark manual with `apt-mark manual`, or a
   removal they want). check-updates also shows `config_leftovers`; offer `-e purge=true` only when the
   user wants the configuration of removed Debian packages gone as well.
4. Approval (the guard asks for any patch run outside `--check`).
5. Run: `ansible-playbook playbooks/patch-linux.yml -e target=<group> [-e security_only=true]`.
   The playbook stops on the first failure (`max_fail_percentage: 0`) and checks failed
   systemd units and `health_services` after each host. A unit counts only when it failed after the update
   and not before; in LXC guests kernel-module and kernel-filesystem units that fail on every boot don't
   count. A oneshot named as new may still be such a unit: check `journalctl -b -u <unit>`, and only if the
   update did not cause it, add it to `failed_units_ignore` (group_vars) with the user's yes.
   After a reboot it first waits for the boot to finish, and a `health_services` unit still `activating`
   gets time to come up: both up to `health_timeout` seconds (default 300, group_vars or `-e`). Raise it
   for services that start slower (FreeIPA takes 1–2 minutes); a unit that ends `failed` fails at once.
   Docker/Podman containers that ran before must run again; Docker containers that stay down get one restart
   of containerd and then Docker (needed after a containerd upgrade), else the host fails with each
   container's state and error.
   Proxmox LXC guests: an in-guest reboot can leave the container stopped. Pass `-e hm_scripts=$HM/scripts`
   with any reboot: after `lxc_reboot_timeout` (300 s) the run starts a stopped container once through the API
   (`pve_guest.py start`, provisioning token) and reports it, instead of failing after 900 s.
6. Reboots: a separate, approved run with `-e reboot=if_required` (or the cluster's `reboot`), one cluster member at a
   time (`serial: 1` is the default; never raise it for cluster groups). Wait for health
   checks to pass before the next host — the playbook does this.
7. Re-run `check-updates.yml` to verify, commit `discovery/updates.json`, report.
8. Snapshots: once the hosts are verified, offer to remove them — they grow with every write and slow the
   guest's storage: `pve_snapshot.py list <guests>`, then `pve_snapshot.py delete <guests> --name prepatch-<date>`
   (the user's yes; the guard asks). A failed update: `pve_snapshot.py rollback <guest> --name …` (the user's yes;
   the changes since are lost; a guest that was running is started again and its final status printed,
   `--no-start` leaves it stopped). LXD/Incus hosts: the same with
   `lxd_snapshot.py list|delete|restore`.

Snapshots by hand ("snapshot web01 before I change it"): `pve_snapshot.py create <guest…> [--name …]`
(`lxd_snapshot.py create <host…>` for LXD/Incus instances); `list` and `check` are read-only.

### LXD/Incus instances

Containers (or VMs) on a plain LXD/Incus host or a QNAP NAS (Container Station's LXD) are snapshotted on that
host by `lxd_snapshot.py list|check|create|delete|restore <inventory host…> [--name N]`, over SSH with agent keys.
Set up once, each change with the user's yes:
1. The instance is in the managed inventory (its OS group, for patching) with host vars `lxd_host: <inventory
   name of the LXD/Incus host>`, and `lxd_instance` when its LXD name differs from the short host name
   (`lxd_project` for a non-default project). `lxc list` on the host shows the names.
2. The LXD/Incus host is in the inventory (`appliances` for a NAS) with `ansible_host`/`ansible_user`, and
   `lxd_snapshots: true`: appliances are read-only by default, this allows snapshots there and nothing else.
   `lxd_cli` when the client isn't found (`incus`, `lxc`, QNAP's `/share/*/.qpkg/container-station/bin/lxc`),
   `lxd_sudo: true` when the SSH user needs `sudo -n` for it.
3. `lxd_snapshot.py check <host>` (read-only) — the first run against a host also shows that its LXD answers
   `query`. Report its warnings: `dir` storage copies the whole root filesystem (slow, needs that much free
   space; it refuses when it can't fit), disk devices are not in the snapshot (bind-mounted data, custom
   volumes: back them up separately if the update touches them), scheduled snapshots on ZFS.
Restore (`restore <host> --name N`, the user's yes) restarts a running instance and loses its changes since. On
ZFS only the newest snapshot can be restored: it refuses while newer ones exist; deleting those first is a
separate yes. TrueNAS (its middleware manages Incus) and Synology (Docker only) are not covered: use their own
dataset snapshots. A release upgrade of an instance: the next section (it snapshots with `lxd_snapshot.py`).

## Debian release upgrade (e.g. 11 → 12 → 13)

`playbooks/dist-upgrade-debian.yml`, one release per run, one host at a time. An end-of-life release first gets
a plan the user agrees to: which hosts, in which order (a jump host or one with central authentication last),
when (the services on it are down during the upgrade and the reboot).
1. Pre-flight, read-only: `ansible-playbook playbooks/dist-upgrade-debian.yml -e target=<host>
   -e target_release=<next codename> -e hm_scripts=$HM/scripts --check`. It refuses a release that isn't the
   next one, Ubuntu, Proxmox nodes, short space (`dist_upgrade_min_free_mb`, default 2000 on / and /var),
   pending updates of the current release (patch-linux.yml first), `dpkg --audit` problems, held packages
   (`held_ok=true` keeps them held), a failing `sshd -t`, and foreign APT sources or pin files: third-party
   repositories, other releases (sid, testing), mirrors outside debian.org (list a local mirror or cache in
   `debian_mirrors`). Show them to the user: `foreign_sources=disable` switches them off for the upgrade,
   `keep` leaves them (only when each already has a repository for the new release).
2. The upgrade (the guard asks): the same command without `--check`, plus `-e foreign_sources=…` as agreed.
   It snapshots (`snapshot=false` only with the user's yes), backs up the APT, SSH, PAM/NSS, SSSD, Kerberos
   and sudo configuration to `/root/hm-dist-upgrade-<release>-<date>.tar.gz`, rewrites the Debian sources
   (bookworm adds `non-free-firmware` where `non-free` was), simulates and stops, with the old sources put
   back, if the upgrade would remove a package matching `autoremove_protect`, then runs `upgrade
   --without-new-pkgs` and `full-upgrade` with `--force-confold` in the transient unit `hm-dist-upgrade`
   (survives an sshd restart; log `/var/log/hm-dist-upgrade.log`, `dist_upgrade_timeout` default 3600 s).
   Then `dpkg --audit`, `sshd -t` before the reboot, the reboot (`reboot=false`: later), the new release,
   `health_services` and no new failed units.
3. Report `review_config` (the maintainer's versions of changed configuration files, `*.dpkg-dist`: merge what
   matters), `autoremovable` and the disabled sources. Re-enable a foreign source once it has a repository
   for the new release: change its suite, remove the `#hm-disabled ` prefix (one-line format) or the
   `#hm-disabled` and `Enabled: no` lines (deb822), and drop `.hm-disabled` from pin files; then `apt-get
   update`. Then `check-updates.yml`, patch-linux.yml for the autoremove, and the next release in a new run.
   Remove the snapshot after a good run (the user's yes).
Rollback: the snapshot (`pve_snapshot.py rollback` / `lxd_snapshot.py restore`, the user's yes). Ubuntu: the
next section.

## Ubuntu release upgrade (e.g. 22.04 → 24.04)

`playbooks/dist-upgrade-ubuntu.yml` runs `do-release-upgrade`, one release per run, one host at a time; plan
the order and time with the user as for Debian. Ubuntu decides the next release: `target_release` must be the
one `do-release-upgrade -c` offers. With `Prompt=lts` (the default; the playbook sets it) that is the next LTS,
offered only from its first point release (24.04.1): before that, wait, don't force it with `-d`.
`allow_non_lts=true` (`Prompt=normal`) allows an interim release, only when the user wants one.
1. Pre-flight, read-only: `ansible-playbook playbooks/dist-upgrade-ubuntu.yml -e target=<host>
   -e target_release=<codename> -e hm_scripts=$HM/scripts --check`. It refuses Debian, Proxmox nodes, a missing
   `do-release-upgrade`, short space (`dist_upgrade_min_free_mb`, default 3000), pending updates, `dpkg --audit`
   problems, held packages (`held_ok=true`), a failing `sshd -t`, and, when `Prompt` already has the value the
   run needs, an offer other than `target_release`.
2. The upgrade (the guard asks): the same command without `--check`. It sets `Prompt` and checks the offer again
   (puts the prompt back and stops on a mismatch), snapshots, backs up the configuration (as for Debian, plus
   `/etc/update-manager` and `/etc/netplan`) and the installed package list to `/root/hm-dist-upgrade-<release>-
   <date>.{tar.gz,packages}`, then runs `do-release-upgrade -f DistUpgradeViewNonInteractive` in the transient
   unit `hm-dist-upgrade` (log `/var/log/hm-dist-upgrade.log` and `/var/log/dist-upgrade/`, `dist_upgrade_timeout`
   default 5400 s). Run this way it opens no second sshd on port 1022 and needs no `screen`. It disables
   third-party sources (PPAs) itself and keeps local configuration. There is no reliable dry run, so the run
   compares the package list afterwards: a removed package matching `autoremove_protect` stops it before the
   reboot (install the replacement, or roll back). Then `dpkg --audit`, `sshd -t`, the reboot, the new release,
   `health_services` and no new failed units.
3. Report `removed`, `sources_disabled` (re-enable each PPA once it has a build for the new release: uncomment
   the line or drop `Enabled: no`, then `apt-get update`), `review_config` and `autoremovable`, as for Debian.
   Remove the snapshot after a good run (the user's yes).

## Patch Proxmox nodes

One node per run; the next only after the previous one is back and its guests are restored. A node of another
site (`site_<name>` group): add `--site <name>` to both scripts; the playbook takes that site's plan by itself.
1. `proxmox_inventory.py --details`, then `pve_node_plan.py <node>` (read-only). It refuses while the
   cluster isn't quorate or another node is offline. Show the user the plan: per guest **migrate → node**
   (running, all disks on shared storage, no passthrough or local ISO; spread by relative free memory,
   never above `--max-mem-pct`, default 85), **ha** (HA node maintenance moves it), **stop** (pinned to
   the node: shut down cleanly, started again after), **stays-stopped**. `--no-migrate` stops instead
   of migrating. Migration needs compatible CPU types; HA guests on local disks need replication.
   A standalone node (no cluster) has nowhere to move guests: every running one is down during the reboot —
   say so and agree a time with the user.
2. Approval for the node and the plan.
3. Upgrade only (guests keep running), reports `reboot_needed` and the plan as `planned_migrate` /
   `planned_ha` / `planned_stop` (`migrated`, `ha` and `stopped_and_restored` stay empty: nothing moved):
   `ansible-playbook playbooks/patch-proxmox-node.yml -e proxmox_patch_node=<host>`
4. Reboot run, a separate approval: add `-e allow_reboot=true`. The playbook checks the plan against
   the live cluster (stale → refresh steps 1–2), records the guests in the node's plan (`state_before` in
   `discovery/pve-patch.json`), moves them off, reboots, waits for quorum and Proxmox services, restores them,
   migrates them back (`-e migrate_back=false` leaves them where they are) and asserts every guest that ran runs again.
   A guest that won't shut down cleanly aborts the run before the reboot, with the stopped ones started again.
5. Report: migrated, stopped/restored, still pending. Commit `discovery/pve-patch.json`.

## Windows

`ansible.windows.win_updates` — search is in check-updates.yml. Installing is a separate,
approved play (`category_names: [SecurityUpdates, CriticalUpdates]`, `reboot: false` unless
allowed). Domain controllers and other clustered Windows roles: one at a time.

## Appliances

Firmware updates for NAS/firewall/switch/BMC are vendor-specific and risky: report available
versions if the vendor API/CLI shows them, and give the user steps; don't automate unless
there's a tested role and explicit approval.

## When things go wrong

A host fails mid-patch → the play stops; nothing else is touched. Report what failed, the
host's state (package manager lock? broken dependency? service down?), and propose a fix.
Never retry a cluster member's reboot loop more than once without the user.
List failed, skipped and unreachable hosts in your report (check-updates writes them to
`discovery/updates.json` with `error`); the next run picks them up again. A playbook or hook of the skill that is itself
broken is a skill problem for `skill_issues.md` (SKILL.md §6).
