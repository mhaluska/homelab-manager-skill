# Patching and updates

## "Find systems missing security updates" (read-only)

```bash
cd ansible && ansible-playbook playbooks/check-updates.yml          # Linux + Windows
ansible-playbook playbooks/check-updates.yml -e target=rocky       # subset
```
Writes `discovery/updates.json`. Report a table: host, OS, security updates, total, reboot
pending. Sort by security count. Unreachable hosts are findings too. Commit the JSON.

## "Patch all Linux servers"

1. Fresh `check-updates.yml` → who actually needs patches. Skip hosts with nothing pending.
2. Group the targets:
   - **Independent hosts** — can go in parallel batches (`-e patch_serial=25%`).
   - **Cluster groups** (`clusters:` in homelab.yaml, plus anything obviously clustered:
     k8s, etcd, Galera/Patroni, Proxmox nodes) — separate run per cluster, `serial: 1`,
     with that cluster's `pre_hook`/`post_hook` from `homelab.yaml` (drain/uncordon, maintenance mode):
     `-e target=k8s_workers -e pre_hook=playbooks/hooks/k8s-drain.yml -e post_hook=playbooks/hooks/k8s-uncordon.yml`.
     Hook paths are relative to `ansible/`. Hooks run on this Mac without sudo (`kubectl` with the
     user's kubeconfig); check `kubectl get nodes` works and node names match inventory names
     (or set `k8s_node_name`) before starting. Hold/versionlock kubelet/kubeadm/kubectl packages
     so a full update doesn't upgrade Kubernetes by accident.
   - **Proxmox nodes** — never via this playbook automatically: migrate guests off, patch,
     reboot, verify quorum, next node — each node an explicit approval.
   - **Critical singletons** the user cares about (DNS, the GitLab host, the gateway): ask
     whether to include them, and patch them last.
3. Plan for the user: hosts per batch, security-only or full, reboot policy.
   Reboots default **off** (`allow_reboot=false`); the run reports `reboot_pending`.
4. Approval (the guard asks for any patch run outside `--check`).
5. Run: `ansible-playbook playbooks/patch-linux.yml -e target=<group> [-e security_only=true]`.
   The playbook stops on the first failure (`max_fail_percentage: 0`) and checks failed
   systemd units and `health_services` after each host.
6. Reboots: a separate, approved run with `-e allow_reboot=true`, one cluster member at a
   time (`serial: 1` is the default; never raise it for cluster groups). Wait for health
   checks to pass before the next host — the playbook does this.
7. Re-run `check-updates.yml` to verify, commit `discovery/updates.json`, report.

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
Record failed or skipped hosts in `ISSUES.md` (`--area patching --key patch:<host>`), and unreachable hosts
from check-updates too.
