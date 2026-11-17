# Patching and updates

## "Find systems missing security updates" (read-only)

```bash
cd ansible && ansible-playbook playbooks/check-updates.yml          # Linux + Windows
ansible-playbook playbooks/check-updates.yml -e target=rocky       # subset (prefer this to -l; both write)
```
Merges into `discovery/updates.json`: a subset run updates only its hosts, the others keep their last
result; check each host's `collected_at` before calling it current. Report a table: host, OS, security updates, total, reboot
pending (with `reboot_reasons`), services to restart (`restart_pending`). Sort by security count.
A reboot is due when a newer kernel than the running one is installed (plain Debian has no
`/var/run/reboot-required`), `needs-restarting -r` says so (EL) or the flag file exists. `restart_pending` lists
services whose processes still map deleted binaries or libraries: they run the old (maybe vulnerable) code.
A host that failed or was unreachable gets `error` (the failing step and reason) and `last_ok_at` instead of
counts; the play's last task lists them. They are findings too: report them in the table. Commit the JSON.

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
   Proxmox guests: offer a pre-patch snapshot (`-e snapshot=true -e hm_scripts=$HM/scripts`): a disk-only
   snapshot `prepatch-<date>` of each guest right before its update (guest = inventory short name or host var
   `proxmox_vmid`; needs snapshot-capable storage and the provisioning token).
   Clean-up: after the reboot (or when there is none) the run autoremoves packages nothing needs, so the old
   kernel goes too (`-e autoremove=false` skips it). check-updates shows `autoremovable` and
   `config_leftovers`; offer `-e purge=true` only when the user wants the configuration of removed
   Debian packages gone as well.
4. Approval (the guard asks for any patch run outside `--check`).
5. Run: `ansible-playbook playbooks/patch-linux.yml -e target=<group> [-e security_only=true]`.
   The playbook stops on the first failure (`max_fail_percentage: 0`) and checks failed
   systemd units and `health_services` after each host. A unit counts only when it failed after the update
   and not before; in LXC guests kernel-module and kernel-filesystem units that fail on every boot don't
   count. A oneshot named as new may still be such a unit: check `journalctl -b -u <unit>`, and only if the
   update did not cause it, add it to `failed_units_ignore` (group_vars) with the user's yes.
   Docker/Podman containers that ran before must run again; Docker containers that stay down get one restart
   of containerd and then Docker (needed after a containerd upgrade), else the host fails with each
   container's state and error.
6. Reboots: a separate, approved run with `-e reboot=if_required` (or the cluster's `reboot`), one cluster member at a
   time (`serial: 1` is the default; never raise it for cluster groups). Wait for health
   checks to pass before the next host — the playbook does this.
7. Re-run `check-updates.yml` to verify, commit `discovery/updates.json`, report.
8. Snapshots: once the hosts are verified, offer to remove them — they grow with every write and slow the
   guest's storage: `pve_snapshot.py list <guests>`, then `pve_snapshot.py delete <guests> --name prepatch-<date>`
   (the user's yes; the guard asks). A failed update: `pve_snapshot.py rollback <guest> --name …` (the user's yes;
   the changes since are lost, and a VM is left stopped — start it afterwards).

Snapshots by hand ("snapshot web01 before I change it"): `pve_snapshot.py create <guest…> [--name …]`;
`list` is read-only.

## Patch Proxmox nodes

One node per run; the next only after the previous one is back and its guests are restored.
1. `proxmox_inventory.py --details`, then `pve_node_plan.py <node>` (read-only). It refuses while the
   cluster isn't quorate or another node is offline. Show the user the plan: per guest **migrate → node**
   (running, all disks on shared storage, no passthrough or local ISO; spread by relative free memory,
   never above `--max-mem-pct`, default 85), **ha** (HA node maintenance moves it), **stop** (pinned to
   the node: shut down cleanly, started again after), **stays-stopped**. `--no-migrate` stops instead
   of migrating. Migration needs compatible CPU types; HA guests on local disks need replication.
2. Approval for the node and the plan.
3. Upgrade only (guests keep running), reports `reboot_needed`:
   `ansible-playbook playbooks/patch-proxmox-node.yml -e proxmox_patch_node=<host>`
4. Reboot run, a separate approval: add `-e allow_reboot=true`. The playbook checks the plan against
   the live cluster (stale → refresh steps 1–2), records the guests in `discovery/pve-patch-<node>-state.json`,
   moves them off, reboots, waits for quorum and Proxmox services, restores them, migrates them back
   (`-e migrate_back=false` leaves them where they are) and asserts every guest that ran runs again.
   A guest that won't shut down cleanly aborts the run before the reboot, with the stopped ones started again.
5. Report: migrated, stopped/restored, still pending. Commit the plan and state files.

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
