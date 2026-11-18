# Changelog

## 0.29.0 — 2026-11-18
- Discovery files never carry a site in their name ([#75](https://github.com/mhaluska/homelab-manager-skill/issues/75)): one file per kind with every site inside.
  `proxmox.json`, `network.json`, `pve-patch.json` and `unifi.json` hold `{"sites": {"<site>": …}}` (a repo
  without `sites:` uses `default`); each script writes only its site's part and keeps the others. Replaces
  `proxmox-<site>.json`, `network-<site>.json` and `pve-patch-[<site>-]<node>.json` with its `-state.json`
  (the state before patching is now `state_before` in the node's plan). Files keyed by inventory host
  (`updates`, `containers`, `bmc`, `routeros`) give each host its `site`. The site name `default` is reserved
  for the default site.
- `init_repo.py --sync-managed` moves existing per-site files into the new ones; a file still in the old
  layout is read as the default site's.
- Upgrade notes (copies with local edits): `patch-proxmox-node.yml` (reads `pve-patch.json`), `unifi-info.yml`,
  the host `site` tag in `check-updates.yml` / `docker-containers.yml` / `bmc-info.yml`, `discovery/README.md`.

## 0.28.1 — 2026-11-18
- BMC playbook keeps the vendor workarounds of #32 ([#74](https://github.com/mhaluska/homelab-manager-skill/issues/74)): `bmc-info.yml` reads one Redfish category per
  call, so a BMC that refuses one (iLO 4 has no UpdateService, Supermicro X10 wants a DCMS licence for it) still
  reports the rest and the refusal lands in its `errors`; unreadable chassis data (invalid UTF-8 in `Chassis/1`)
  falls back to reading Thermal/Power directly; power draw prefers `PowerMetrics.AverageConsumedWatts`; BMC and
  BIOS versions come from Manager/System. `discovery/bmc.json` gets a fuller summary: model, power state,
  health, firmware, CPUs/RAM, power draw, hottest sensor, PSUs and components not OK.
- BMCs with their own account: `bmc_secret_env` in host vars names the secret's env (`group_vars/bmc.yml`).
- Upgrade note (repos with the 0.28.0 `bmc-info.yml` and local edits): take the template; `bmc-one-file` now
  says the template keeps these workarounds.

## 0.28.0 — 2026-11-18
- Discovery layout ([#73](https://github.com/mhaluska/homelab-manager-skill/issues/73)): `discovery/README.md` lists every file the scripts and playbooks write there, with the
  naming rule: a per-site file (`proxmox`, `network`, `pve-patch`) has no site in its name for the default site
  and the site's name for the others; files keyed by inventory host (`updates`, `containers`, `bmc`, `unifi`,
  `routeros`) hold every site in one file. A test keeps the README complete. Not renamed: the proposed
  `<site>-<kind>` names for every file, including the default site.
- Upgrade note (repos whose `bmc-info.yml` writes one file per BMC): replace it with the template, which merges
  every BMC into `discovery/bmc.json`, and remove the per-BMC files.
- Upgrade note (repos with an edited older `discovery/README.md`): replace it with the template; unedited copies
  are replaced by `--sync-managed`.

## 0.27.0 — 2026-11-18
- Sites: network scans know their site ([#72](https://github.com/mhaluska/homelab-manager-skill/issues/72)). `nmap_scan.py --site NAME` and `ssh_probe.py --site NAME` write
  `discovery/network-<name>.json` for a site other than the default (which keeps `network.json`) and warn about
  targets outside that site's `ranges`. The drift report lists unmanaged devices per site, checked against that
  site's inventory hosts, guests and ignores; `guest_map.py` and issue redaction read every site's file. The
  guard knows `--site` takes a value.
- Sites: `network.excluded_hosts` and `discovery.ignore_unmanaged` accept `{ip, site}` entries next to plain
  addresses ([#66](https://github.com/mhaluska/homelab-manager-skill/issues/66)), for sites that reuse the same private ranges. A scan without `--site` applies every site's
  exclusions, so it never excludes less than intended. `check_env.py` warns about plain entries inside ranges two
  sites share.
- Upgrade note (repos with two or more sites): rescan the other sites with `--site`.

## 0.26.0 — 2026-11-18
- Sites: the default site is explicit from the start ([#65](https://github.com/mhaluska/homelab-manager-skill/issues/65)). New `init_repo.py --name-default-site NAME
  [--steps ranges,vlans,group] [--dry-run]` names `sites[0]`, proposes its `ranges` from `authorized_ranges` and
  the VLAN CIDRs, tags VLANs without a site with it and adds `site_<name>` to `hosts.yml` with every inventory
  host in no site group. Setup runs it; `--add-site` points at it when the default site isn't explicit yet.
  `config_set.py 'network.vlans+=…'` tags a new VLAN with the only site, and asks for one when there are several.
- Sites: with two or more, `check_env.py` (`sites:ambiguous`) and the drift report ("Site ambiguity") flag what
  "no site" leaves open ([#63](https://github.com/mhaluska/homelab-manager-skill/issues/63)): VLANs without a site, a VLAN name shared by entries not all tied to one site,
  overlapping or missing site `ranges`, inventory hosts in no site group (parent groups now count) and
  `clusters:` groups across sites. `network.vlans` takes `site: all` for a VLAN every site has on purpose
  (`all` is no longer a valid site name).
- Upgrade note (repos with two or more sites): make the default site explicit with `--name-default-site`.

## 0.25.0 — 2026-11-18
- `issues.py fixed --github` also lists reported entries whose GitHub issue was closed as not planned or as a
  duplicate ([#69](https://github.com/mhaluska/homelab-manager-skill/issues/69)), apart from the fixed ones, with the follow-up issues a maintainer named when closing
  (split into …) and a ready `resolve` command. `--apply` never resolves them: the user decides. Only issue
  numbers from the owner's, members' or collaborators' comments are read, never comment text.
- Sites ([#64](https://github.com/mhaluska/homelab-manager-skill/issues/64)): the default site's Proxmox may be described in `sites[0].proxmox` like every other site's
  (the top-level `proxmox:` block stays valid; one of the two). Once the default site has a name,
  `tofu_to_inventory.py` puts its hosts in `site_<default>` like `proxmox_to_inventory.py`, and
  `init_repo.py --add-site <default>` writes `group_vars/site_<default>.yml`.
- `routeros_audit.py`:
  - kept only the first character of the identity (and could cut other values) on RouterOS 7 ([#70](https://github.com/mhaluska/homelab-manager-skill/issues/70)):
    without a pty RouterOS wraps output at a width of 1. It logs in as `<user>+ct512w` (the user from `ssh -G`
    when not given) and the parser joins wrapped values.
  - the CHR licence finding used `next-renewal-at`, the next automatic renewal attempt, as the deadline
    ([#71](https://github.com/mhaluska/homelab-manager-skill/issues/71)), so every healthy CHR was flagged for a month. It uses `deadline-at` (high once passed, medium
    within 30 days) and flags a renewal only once it is overdue.

## 0.24.0 — 2026-11-18
- `init_repo.py --sync-managed` replaces a template file you never edited with the current one instead of
  suggesting a manual merge ([#68](https://github.com/mhaluska/homelab-manager-skill/issues/68)). It knows every released version of each template file
  (`assets/template-history.json`, git blob hashes), adds new template files the replaced one uses (such as
  `tasks/restart-check.yml`), and lists the upgrade notes the replacement settles, with any step still left.
  Files with local edits, new opt-in files, `homelab.yaml`, `skill_issues.md` and `docs/proxmox-tokens.md` are
  never replaced.
- Upgrade suggestions stay offered until each is applied or declined ([#67](https://github.com/mhaluska/homelab-manager-skill/issues/67)): `--sync-managed` had recorded
  `upgrades.reviewed` as soon as it listed them, so a postponed one was never offered again. New
  `upgrade_notes.py --decline ID` / `--done ID` (`upgrades.declined`, `upgrades.done` in homelab.yaml);
  `upgrades.reviewed` moves only when none is left.
- Upgrade note: run `upgrade_notes.py --all` once to find suggestions an earlier run hid.

## 0.23.0 — 2026-11-18
- Guard: a Python script or heredoc is checked by the commands it actually starts ([#60](https://github.com/mhaluska/homelab-manager-skill/issues/60)): `subprocess`,
  `os.system` and `exec*` calls and nmap argv lists, with the line named in the reason. The word nmap in strings,
  comments or column labels is no scan any more, and a heredoc fed to a script (`python3 issues.py add <<EOF`) is
  data, not code. nmap targets only known at run time ask.
- Guest addresses ([#56](https://github.com/mhaluska/homelab-manager-skill/issues/56), [#61](https://github.com/mhaluska/homelab-manager-skill/issues/61)): `proxmox_inventory.py --details` lists an LXC container's
  configured `ip=` next to what Proxmox reports (one address per interface, so a keepalived VIP could hide the
  container's own) and marks the others `extra`. `proxmox_to_inventory.py` picks `ansible_host` on a NIC of the
  guest's config (by MAC), inside the site's ranges / `authorized_ranges`, not on a tunnel, bridge or container
  interface (WireGuard, Docker), instead of the lowest address.
- `patch-linux.yml`:
  - autoremove is simulated first and skipped on a host (reported, not failed) when it would remove a package
    matching `autoremove_protect` (SSSD, NSS/PAM, Kerberos, sudo, SSH, systemd, networking) or more than
    `autoremove_max` (20) packages ([#58](https://github.com/mhaluska/homelab-manager-skill/issues/58)): a removed `freeipa-client` had left SSSD autoremovable.
  - free space on `/`, `/var` and `/boot` of every target is checked before anything is snapshotted or patched
    (`patch_min_free_mb`, `patch_min_free_boot_mb`; `-e clean_cache=true` cleans the package cache first)
    ([#57](https://github.com/mhaluska/homelab-manager-skill/issues/57)).
  - a Proxmox LXC guest that stays stopped after its in-guest reboot is started once through the API (with
    `hm_scripts`, after `lxc_reboot_timeout`) instead of failing after 900 s ([#59](https://github.com/mhaluska/homelab-manager-skill/issues/59)).
- `check-updates.yml` reports `autoremove_packages`, `autoremove_protected`, `free_mb` and `low_space`.
- `pve_snapshot.py rollback` starts a guest that was running again and prints its final status (`--no-start`);
  new `pve_guest.py status|start` ([#59](https://github.com/mhaluska/homelab-manager-skill/issues/59)).
- New `guest_map.py` ([#62](https://github.com/mhaluska/homelab-manager-skill/issues/62)): `discovery/guest-map.md`, every guest NIC with VLAN, bridge and addresses
  (config, agent, LXC, RouterOS by MAC), with findings: addresses outside their VLAN's cidr, unknown tags, NICs
  without an address, stale or VIP `ansible_host`, VMIDs off `vmid_scheme`. The drift report points to it.
- Upgrade notes for `patch-linux.yml` and `check-updates.yml`: `init_repo.py --sync-managed`.

## 0.22.0 — 2026-11-18
- `patch-linux.yml` waits for slow services after a reboot ([#53](https://github.com/mhaluska/homelab-manager-skill/issues/53)):
  it waits until the boot has finished (`systemctl is-system-running`), and `health_services` units still
  `activating` get time to come up, both up to `health_timeout` seconds (default 300, group_vars or `-e`).
  A unit that ends `failed` still fails at once.
- Storage for LXC and per node ([#54](https://github.com/mhaluska/homelab-manager-skill/issues/54)):
  - `homelab.yaml`: `proxmox.lxc_storage` (LXC root filesystems; empty = `default_storage`) and `proxmox.nodes`
    for a node whose storage differs (a cluster without shared storage, one node on LVM among ZFS nodes);
    also under `sites[].proxmox`.
  - OpenTofu environment: `defaults.lxc_datastore` and `defaults.node_datastores`; a listed node takes VM, LXC
    and base image storage from its entry. VMs may name `template_node` (clone there, then migrate: same
    storage name on both nodes); a node with other storage gets its own template.
  - The drift report's new Storage section lists storage a node lacks or that doesn't take `images` / `rootdir`.
- Upgrade notes for `patch-linux.yml` and the OpenTofu environments: `init_repo.py --sync-managed`.

## 0.21.0 — 2026-11-17
- Sites, part 2 ([#52](https://github.com/mhaluska/homelab-manager-skill/issues/52)): provisioning and node patching at other sites.
  - `init_repo.py --add-site N` scaffolds the site's OpenTofu environment `tofu/environments/N` (its own state)
    and `group_vars/site_N.yml`. `with_secrets.py` sets `TF_VAR_proxmox_site` / `PKR_VAR_proxmox_site` from the
    token's site, and a `site.tf` in each environment refuses a plan with another site's token.
  - `tofu_init.py --site N`, `tofu_to_inventory.py --site N` (→ `tofu_hosts-N.yml`, hosts in `site_N`; another
    environment no longer overwrites `tofu_hosts.yml`). A set `opentofu.local.path` / `opentofu.s3.key` must
    contain `{env}` once there are several environments, so they never share a state.
  - The drift report compares each site with its own state; `check_env.py` checks each site's environment.
  - VMIDs: `--next-vmid … --site N` uses that site's snapshot and environment; a site may set its own
    `vmid_ranges`, `vmid_scheme` and `templates`. `network.vlans` entries may name a `site`.
  - Packer: `packer/linux/site-N.pkrvars.hcl` with `site = "N"`; a token of another site fails the build.
  - `pve_node_plan.py --site N` (→ `pve-patch-N-<node>.json`); `patch-proxmox-node.yml` takes the plan of the
    node's site and supports standalone nodes (no cluster).
- Upgrade notes for `patch-proxmox-node.yml` and the Packer template: `init_repo.py --sync-managed`.

## 0.20.0 — 2026-11-17
- Sites ([#52](https://github.com/mhaluska/homelab-manager-skill/issues/52), part 1): new optional `sites:` in homelab.yaml for more than one location (a rented server,
  family's house), the default site first; each other site may have its own `proxmox` block with its own tokens,
  a `label` and its network `ranges`. Inventory hosts belong to a site through the Ansible group `site_<name>`
  (none: the default site), so plays can target a site (`-e target='site_offsite:&linux'`).
  - `proxmox_inventory.py --site N` / `--all-sites` → `discovery/proxmox-<site>.json`;
    `proxmox_to_inventory.py --site N` drafts into `site_<name>`.
  - `pve_snapshot.py --site N`; `patch-linux.yml -e snapshot=true` checks and snapshots each guest on its own
    site. `with_secrets.py` connects to the site whose tokens name the secret.
  - The drift report covers every site (`<site>/<vmid>`, as VMIDs repeat), labels devices by site ranges and
    flags hosts in several site groups or in a group with no site; `check_env.py` checks TLS per site.
  - `config_set.py` refuses invalid site names; `issues.py` redacts every site's names, endpoints and data.
  - Not yet: OpenTofu, Packer, VMID allocation and node patching for other sites (part 2).
- Upgrade note for `patch-linux.yml`: `init_repo.py --sync-managed`.

## 0.19.0 — 2026-11-17
- LXD/Incus snapshots ([#44](https://github.com/mhaluska/homelab-manager-skill/issues/44)): new `lxd_snapshot.py list|check|create|delete|restore <host…>` for containers
  on a plain LXD/Incus host or a QNAP NAS (Container Station). Host vars: `lxd_host` (and optional `lxd_instance`,
  `lxd_project`) on the instance; `lxd_snapshots: true` on its host opts that appliance in (optional `lxd_cli`,
  `lxd_sudo`). It uses `<cli> query` over SSH, so LXD and Incus behave alike. check reports the storage driver,
  `dir` pools too full for the copy, disks the snapshot doesn't contain and scheduled snapshots; restore refuses
  on ZFS while newer snapshots exist.
- `patch-linux.yml -e snapshot=true` snapshots hosts with `lxd_host` with it, after the same pre-flight check
  as Proxmox guests.
- Guard: asks before `lxd_snapshot.py delete|restore` and before `lxc`/`incus` delete, restore or API writes
  (`query -X PUT|PATCH|DELETE`), also over SSH.
- TrueNAS and Synology are out of scope (references/patching.md "LXD/Incus instances").
- Upgrade note for `patch-linux.yml`: `init_repo.py --sync-managed`.

## 0.18.0 — 2026-11-17
- Snapshot pre-flight ([#49](https://github.com/mhaluska/homelab-manager-skill/issues/49)): new read-only `pve_snapshot.py check <guests> [--json]` reports every guest
  (ok, not a Proxmox guest, or not snapshottable with the reason, e.g. a bind or device mount point).
  `patch-linux.yml -e snapshot=true` runs it for all targets before the first batch and refuses with the list;
  `-e snapshot_missing=skip` patches those hosts without a snapshot. patching.md describes LXD/Incus snapshots by
  hand ([#44](https://github.com/mhaluska/homelab-manager-skill/issues/44)).
- Containers after patching ([#50](https://github.com/mhaluska/homelab-manager-skill/issues/50)): `patch-linux.yml` fails a host whose Docker/Podman containers ran before
  the update and don't run after it; Docker containers that stay down first get one restart of containerd and
  then Docker (needed after a containerd upgrade).
- Failed units ([#51](https://github.com/mhaluska/homelab-manager-skill/issues/51)): `patch-linux.yml` compares failed units by name, and doesn't count units that fail on
  every boot in LXC containers or are listed in the new `failed_units_ignore` (group_vars). The message names
  oneshot units that may fail on every boot.
- Fix ([#48](https://github.com/mhaluska/homelab-manager-skill/issues/48)): `check-updates.yml` writes `discovery/updates.json` also when run with `--limit` (`-l <host>`).
- Upgrade notes for the playbooks and `failed_units_ignore`: `init_repo.py --sync-managed`.

## 0.17.0 — 2026-11-17
- Patching batches ([#45](https://github.com/mhaluska/homelab-manager-skill/issues/45)): `patch-linux.yml` takes the batch size for independent hosts from new
  `ansible.patch_serial` in homelab.yaml (new repos: 5; unset: 1), or `-e patch_serial`. Cluster members,
  `patch_requires_approval` hosts and runs with hooks always go one at a time; a larger `-e patch_serial` is refused.
- Old kernels ([#46](https://github.com/mhaluska/homelab-manager-skill/issues/46)): `patch-linux.yml` autoremoves (apt and dnf) after the reboot, when the old kernel is no
  longer running (`-e autoremove=false` skips it); `-e purge=true` also purges configuration left by removed
  Debian packages. `check-updates.yml` reports `autoremovable` and `config_leftovers`.
- Fix ([#43](https://github.com/mhaluska/homelab-manager-skill/issues/43)): `check-updates.yml` writes failed and unreachable hosts to `discovery/updates.json` with `error`
  and `last_ok_at`, and lists them at the end; Debian package lists are refreshed with `apt-get`, so archived
  releases that can't install `python3-apt` still report.
- Fix ([#41](https://github.com/mhaluska/homelab-manager-skill/issues/41)): `proxmox_inventory.py` stores backup job `vmid`/`exclude` as lists of IDs, no longer cut at 200
  characters; `drift_report.py` warns about cut-off lists in older snapshots instead of reporting covered guests
  as unbacked, and honours per-job `exclude` and pool jobs.
- Backup jobs ([#42](https://github.com/mhaluska/homelab-manager-skill/issues/42)): references/proxmox.md "Backup jobs" (import the job as `proxmox_backup_job`, or the GUI);
  `docs/proxmox-tokens.md` offers an optional `Datastore.Allocate` grant on the backup storage only. The drift
  report points there.
- Containers ([#40](https://github.com/mhaluska/homelab-manager-skill/issues/40)): new read-only `playbooks/docker-containers.yml` (Docker/Podman containers and Kubernetes
  runtimes → `discovery/containers.json`). The drift report lists container addresses, also from hand-written
  `discovery/<nas>-containers.json`, instead of calling them unmanaged; discovery.md covers NAS container hosts.
- Fix ([#47](https://github.com/mhaluska/homelab-manager-skill/issues/47)): `issues.py report` no longer redacts plain words a site also uses as names ("storage", "host") in
  running text, never redacts inside a placeholder (`<<host>>`), lists the plain words it redacted, and takes
  `--keep WORD`.
- Upgrade notes for the playbooks, `ansible.patch_serial` and the token doc: `init_repo.py --sync-managed`.

## 0.16.0 — 2026-11-17
- Language: new `site.language` in homelab.yaml (setup asks, or takes the language the user writes in). Claude
  replies and writes docs, commit messages and new code comments in it; identifiers and plugin-managed files
  stay English. Skill issues are always English: `issues.py add`/`report` refuse non-English text (Claude
  translates it), and the guard denies non-English `gh issue`/`gh pr` writes to the plugin repository.
- English-only repository: a `Language check` workflow fails pull requests whose added lines, commit messages,
  title or description aren't English (`.github/check_english.py`, heuristic; `lang: allow` marks deliberate
  samples), and non-English issues get the `needs-english` label and a comment. See `CONTRIBUTING.md`.
- Fix ([#35](https://github.com/mhaluska/homelab-manager-skill/issues/35)): `check-updates.yml`, `patch-linux.yml` and `patch-proxmox-node.yml` read facts via
  `ansible_facts.*`; ansible-core 2.24 drops injected fact variables.
- Fix ([#36](https://github.com/mhaluska/homelab-manager-skill/issues/36)): `check-updates.yml` counts EL security updates from `dnf check-update --security` packages only,
  not header or metadata lines.
- Fix ([#38](https://github.com/mhaluska/homelab-manager-skill/issues/38)): new `tasks/restart-check.yml` sees a reboot is due when a newer kernel is installed (plain
  Debian has no `/var/run/reboot-required`), and lists services still running replaced binaries or libraries
  (`restart_pending`). `patch-linux.yml -e restart_services=true` restarts them when the host isn't rebooted.
- Secondary addresses ([#31](https://github.com/mhaluska/homelab-manager-skill/issues/31)): host var `hm_extra_ips` (VIPs, extra NICs) is listed in `drift_report.py` and
  no longer reported as ghost hosts; `drift_report.py --stale` tells whether the report is older than its inputs.
- Guest snapshots ([#37](https://github.com/mhaluska/homelab-manager-skill/issues/37)): new `pve_snapshot.py list|create|delete|rollback` (disk-only, waits for each Proxmox
  task); `patch-linux.yml -e snapshot=true` snapshots each Proxmox guest right before updating it. Deleting
  and rolling back need the user's yes (the guard asks).
- Rolling cluster patches ([#39](https://github.com/mhaluska/homelab-manager-skill/issues/39)): `patch-linux.yml` takes `reboot=never|if_required|always`,
  `order=vip_holder_last` with `vip` (the VIP moves once) and a `health_check` hook after each host; new
  `hooks/vrrp-health.yml` for keepalived pairs. `clusters:` entries in homelab.yaml can name these settings.
- VLAN names ([#34](https://github.com/mhaluska/homelab-manager-skill/issues/34)): optional `network.vlans` (id, name, cidr); `--vlan` accepts names, the drift report
  labels addresses with them and `issues.py` redacts them. RouterOS: steps, no automatic collector.
- BMCs ([#32](https://github.com/mhaluska/homelab-manager-skill/issues/32)): `bmc` inventory group and read-only `playbooks/bmc-info.yml` (Redfish: health, power, PSUs,
  thermals, firmware → `discovery/bmc.json`); secret kind `user_password`. Redfish and IPMI power actions ask.
- UniFi ([#33](https://github.com/mhaluska/homelab-manager-skill/issues/33)): `unifi` group (raw SSH only) and read-only `playbooks/unifi-info.yml` (controller Integration
  API → `discovery/unifi.json`). Changes go through the controller; the guard asks for `set-inform`,
  `syswrapper.sh`, firmware upgrades and API writes. Marking controller-managed devices in drift: later.
- Existing repos: `init_repo.py --sync-managed --dry-run` lists the opt-in changes (new playbooks, CLAUDE.md
  language rule, `site.language`, `network.vlans`).

## 0.15.0 — 2026-11-17
- Full scan ([#29](https://github.com/mhaluska/homelab-manager-skill/issues/29)): `references/discovery.md` describes a full scan of a range — ping, services,
  `os --only-live` (its own yes), Proxmox guest mapping and a read-only `ssh_probe.py` — summarised per host as
  managed, candidate (with OS group), auth failed, no POSIX shell or no SSH. When the user only says "scan",
  Claude asks once: network only or full. Onboarding stays a separate yes.
- Fix ([#28](https://github.com/mhaluska/homelab-manager-skill/issues/28)): `nmap_scan.py` no longer lets a borrowed OS fingerprint override what the host says.
  An OS named in a service banner (`OpenSSH … Debian`) or nmap's `ostype` (now stored per port) counts like an
  OS match; an appliance OS guess (RouterOS…) is ignored when a banner names the OS and nothing else on the
  host shows an appliance. On routed `os` scans, hosts whose OS guess list is identical to another host's
  (the gateway answering for them) get `os_suspect` in `network.json`, and those guesses weigh little.
- Fix ([#30](https://github.com/mhaluska/homelab-manager-skill/issues/30)): `issues.py report` no longer redacts nmap OS guesses, port banners and ssh_probe's OS
  and product as host names; reverse-DNS names from `network.json` (`hostnames`) are now redacted.

## 0.14.0 — 2026-11-17
- Opt-in `git.auto_push` ([#27](https://github.com/mhaluska/homelab-manager-skill/issues/27)): when true, every
  verified commit of the operating loop is pushed to the remote (never forced) and the branch checked not to be
  ahead; a failed push is reported. Setup asks for it when the repo has a remote; existing repos are offered it
  by the upgrade advisor. `check_env.py` reports commits not pushed to the upstream (a failure with auto_push)
  and commits on the upstream missing locally.
- Probe discovered hosts over SSH ([#25](https://github.com/mhaluska/homelab-manager-skill/issues/25)): new
  read-only `ssh_probe.py [targets] [--user U] [--draft] [--include-managed]` logs in to the hosts
  `discovery/network.json` knows with SSH open (or a given address; targets must be authorized) and reads
  hostname, OS, product (Proxmox, OPNsense, pfSense, TrueNAS), virtualisation and every Python it finds. It
  runs what Ansible's `raw` would, over plain `ssh -T` with agent keys only, a hard timeout per host, a
  throwaway known_hosts (nothing added to `~/.ssh/known_hosts`) and the probe on stdin to `sh -s`, so csh
  root shells work. It shows the Python the installed ansible-core can use (and the `ansible_python_interpreter`
  to set when the default `python3` is too old, e.g. EL8), suggests an OS group (`el8`, `debian`,
  `proxmox_nodes`, `appliances` …), merges the result into `network.json` and `--draft` prints an inventory
  draft. `device_type_guess` now also uses what the host reported. The guard checks its targets against
  `authorized_ranges` like `nmap_scan.py`'s.
- MikroTik RouterOS audit ([#26](https://github.com/mhaluska/homelab-manager-skill/issues/26)): new read-only
  `routeros_audit.py <hosts> [--group G] [--user U]` inspects routers, CRS switches and CHR over SSH: identity,
  resource, RouterBOOT, package update status, licence, interfaces, addresses, bridges/VLANs, IP services and
  users. It runs only `print` commands, one `ssh -T` each (no pty, which is what makes Ansible's `raw` hang on
  RouterOS) with a hard timeout, skips `/system routerboard` on CHR and carries on when one command fails.
  Findings: plain-text telnet/ftp/www/api enabled, RouterBOOT behind RouterOS, a known RouterOS update, low
  free flash, the default `admin` user, CHR licence level and a renewal within 30 days, and version drift
  across devices. Writes `discovery/routeros.json` and prints a Markdown report.

## 0.13.0 — 2026-11-17
- Fix ([#24](https://github.com/mhaluska/homelab-manager-skill/issues/24)): `issues.py add` with the key of an
  open entry now replaces its title, kind and body (the old title was kept) and says what changed; an `add`
  without a body keeps the recorded details and only refreshes Environment.
- Fix ([#21](https://github.com/mhaluska/homelab-manager-skill/issues/21)): `nmap_scan.py --profile os` no longer
  downgrades a `hypervisor` guess to `linux`. A product name that identifies the box (Proxmox, TrueNAS, iDRAC…)
  wins over generic Linux evidence, and `device_type_guess` is recomputed from everything known about the host,
  so a later scan never loses what an earlier one found. Re-run a scan to re-guess existing hosts.
- Fix ([#22](https://github.com/mhaluska/homelab-manager-skill/issues/22)): `check-updates.yml -e target=<group>`
  no longer rewrites `discovery/updates.json` with only that group. Results are merged: hosts checked now
  replace their entry, the others keep theirs, each with its own `collected_at`; hosts gone from the inventory
  are dropped. Existing repos: the upgrade advisor offers the new final play of the (user-owned) playbook.
- Onboarding existing hosts ([#20](https://github.com/mhaluska/homelab-manager-skill/issues/20)): new read-only
  `proxmox_to_inventory.py [--vlan N] [--range CIDR] [--type vm|lxc] [--node N]` drafts inventory entries
  (`ansible_host`, `proxmox_vmid/node/kind`) for running Linux guests in `discovery/proxmox.json` and lists
  the ones it skipped (non-Linux ostype, stopped, no IP, already managed). Nothing is written to `hosts.yml`.
  `check_env.py` flags hosts in an EL8-named group (`el8`, `rocky8`, `centos_stream8` …) without
  `ansible_python_interpreter` when the installed ansible-core (2.17+) can no longer use EL8's Python 3.6.
  `references/ansible.md` has a new "Onboarding existing hosts" section: draft, probe OS and Python with
  `raw`, OS-based groups, target Python per ansible-core version and the EL8 fix (`python3.12` from AppStream).
- Proxmox node patching ([#23](https://github.com/mhaluska/homelab-manager-skill/issues/23)): new read-only
  `pve_node_plan.py <node> [--max-mem-pct 85] [--no-migrate]` decides per guest of the node: live/restart
  migration (running, shared storage only, no passthrough or local ISO), placed largest memory first on the
  node with the lowest relative memory use and never above the limit; HA node maintenance for HA-managed
  guests; clean shutdown and restore for the rest; stopped guests stay stopped. It shows autostart and
  storage per guest, refuses while the cluster isn't quorate or another node is offline, and writes
  `discovery/pve-patch-<node>.json`. `proxmox_inventory.py --details` now records passthrough devices,
  EFI/TPM/unused disks and the startup order it needs.
  New `ansible/playbooks/patch-proxmox-node.yml -e proxmox_patch_node=<host> [-e allow_reboot=true]` executes
  that plan after checking it against the live cluster (quorum, all nodes online, same guests running):
  upgrades packages while guests run, and only when a reboot is needed and allowed moves guests off
  (migrate, HA maintenance, clean shutdown in reverse startup order — if one fails the stopped ones are
  started again and nothing reboots), reboots, waits for quorum and Proxmox services, restores guests and
  migrates them back (`-e migrate_back=false` leaves them), then asserts every guest that ran runs again.
  It records the state before patching in `discovery/pve-patch-<node>-state.json`. Upgrade notes can now
  offer files a release added (`file_missing`); existing repos are offered the new playbook.
  `patch-linux.yml` refuses hosts with `patch_requires_approval: true` (new `group_vars/proxmox_nodes.yml`
  sets it for Proxmox nodes) unless they are named in `-e patch_approved=<host,…>`, so a broad target
  can't patch and reboot a hypervisor; the upgrade advisor offers the pre-task to existing repos.
  `references/patching.md` has a "Patch Proxmox nodes" procedure for both.

## 0.12.4 — 2026-11-17
- Fix ([#18](https://github.com/mhaluska/homelab-manager-skill/issues/18)): `nmap_scan.py --profile os` no longer
  ARP-sweeps through a local VM bridge whose router answers for every address. It scans from the interface
  `route get` gives for the targets (new `--interface/-e` overrides; targets on several interfaces must be
  scanned separately), adds `--disable-arp-ping` for targets behind a gateway, and refuses to merge a result
  where one MAC answered ARP for nearly every host (exit 5). Long scans print nmap's progress every 30 s.
  New `--only-live` scans only the hosts `network.json` already has inside the targets.
- Fix ([#19](https://github.com/mhaluska/homelab-manager-skill/issues/19)): the guard no longer reads the values
  of nmap options such as `--stats-every 30s`, `--min-hostgroup`, `--max-os-tries` or `--script-timeout` as
  scan targets, and `--script-timeout`/`--script-args` alone no longer count as running NSE scripts.

## 0.12.3 — 2026-11-17
- Discovery ([#17](https://github.com/mhaluska/homelab-manager-skill/issues/17)): `device_type_guess` recognises
  more management controllers from service banners (HP "Integrated Lights-Out", AMI MegaRAC, Lenovo XClarity,
  model numbers such as iDRAC9/iLO5) and uses factory-default reverse-DNS names (`uap-`, `usw-`, `udm-` … →
  `network`; `ilo-`, `idrac-`, `bmc-` … → `bmc`). The drift report marks BMCs among unmanaged devices.
  Re-run `nmap_scan.py --profile services` to re-guess existing hosts.

## 0.12.2 — 2026-11-17
- Fix ([#14](https://github.com/mhaluska/homelab-manager-skill/issues/14)): the optional guest-agent section of `docs/proxmox-tokens.md` granted `HomelabAgentAudit`
  on `/vms`. An ACL on a narrower path replaces the role inherited from `/`, so the read-only token lost
  `VM.Audit` and the inventory saw no guests. The section now says PVEAuditor already covers the guest agent
  on Proxmox VE 9, grants any extra role on `/` next to PVEAuditor, and shows how to undo the `/vms` grant.
  The upgrade advisor offers the section only when the inventory says agent IPs were not read, and flags
  docs that still have the `/vms` lines. `proxmox_inventory.py` warns when it sees no guests and names the
  ACL that hides them.
- Fix ([#15](https://github.com/mhaluska/homelab-manager-skill/issues/15)): `issues.py report` no longer redacts the word after "token:" (or "password:", …) in
  prose; with a colon only values that look like secrets are removed, and `Redacted:` counts the secrets.
  A closing quote after a redacted value is kept.
- Fix ([#16](https://github.com/mhaluska/homelab-manager-skill/issues/16)): `issues.py report <ID>` no longer moves the reported-through marker past other unsent
  entries. Each sent entry records `reported_at`, and an entry without a GitHub link is always offered, so
  ones the old behaviour skipped come back on the next `report`.
- Existing repos: if `docs/proxmox-tokens.md` has the `/vms` lines, `init_repo.py --sync-managed --dry-run`
  suggests replacing them and undoing the grant on Proxmox.

## 0.12.1 — 2026-11-17
- Fix ([#13](https://github.com/mhaluska/homelab-manager-skill/issues/13)): `issues.py fixed` missed an issue
  the installed release links when an older CHANGELOG section mentioned the same `#N` in prose (0.5.0's
  "fix GitHub issue #12" hid 0.12.0's fix of #12). Only real links count now (`[#N](…)`, `…/issues/N`), and
  any linking release newer than the entry's last-seen version marks it fixed, not just the oldest one.

## 0.12.0 — 2026-11-17
- Upgrade advisor ([#11](https://github.com/mhaluska/homelab-manager-skill/issues/11)): after a plugin upgrade
  `init_repo.py --sync-managed --dry-run` no longer answers "nothing to change" while a release has opt-in
  changes for the repo. Besides the one-time updates it applies itself, it lists **suggestions** (never
  applied by it): new homelab.yaml keys (`vmid_scheme`, with the scheme inferred from your existing VMIDs),
  template sections missing from your own docs (the guest-agent privilege in `docs/proxmox-tokens.md`),
  snapshots made by an older version to regenerate, and manual steps. They come from the machine-readable
  `assets/upgrade-notes.json`; `upgrade_notes.py [--all] [--json]` shows them alone. A real run records
  `upgrades.reviewed` in homelab.yaml so the same suggestions aren't offered again; new repos start reviewed.
  The session-start hook mentions pending suggestions too.
- Fixed skill issues ([#12](https://github.com/mhaluska/homelab-manager-skill/issues/12)): new
  `issues.py fixed [--apply] [--github]` finds reported entries whose GitHub issue the installed release's
  CHANGELOG links (newer than the version they were last seen with) and resolves them with `--apply`;
  `--github` also lists ones closed as completed but not in the installed release yet. `issues.py list`,
  `report --dry-run`, `--sync-managed` and the session-start hook point them out. Entries seen again now
  record the plugin version (`last_seen_version`), so a fix older than that isn't claimed.
- Existing repos: the next session offers the update; `upgrades.reviewed` is added to homelab.yaml on the
  first real `--sync-managed` run that shows suggestions.

## 0.11.0 — 2026-11-16
- Fix ([#9](https://github.com/mhaluska/homelab-manager-skill/issues/9)): the guard split commands on `|`, `;`
  and newlines even inside quotes and heredocs, so `grep -E "(tofu|nmap|yq)"` or an issue body mentioning nmap
  was refused as a scan with no targets. It now parses commands like the shell: quoted text, comments and
  heredoc bodies that are only data (`cat <<EOF > file`, `--body "$(cat <<'EOF' …)"`) are not commands.
  Heredocs a shell or interpreter runs (`bash <<EOF`, `cat <<EOF | sh`, `ssh host <<EOF`) are still checked,
  and now so are `bash -c '…'`, `eval …`, `ssh host '…'`, `$(…)`, backticks, subshells and `if`/`do` bodies.
  Redirections (`2>&1`, `> out.txt`) are no longer taken for nmap targets.
- Fix ([#8](https://github.com/mhaluska/homelab-manager-skill/issues/8)): the skill-problem hook blamed a bundled
  script for any Python traceback in the same command (e.g. an inline `python3 -c`). It now names a script only
  when the traceback runs through its file under `homelab-manager/scripts/`, and stays quiet otherwise.
- `issues.py report` redacts Proxmox identifiers ([#10](https://github.com/mhaluska/homelab-manager-skill/issues/10)):
  VMIDs, VLAN tags (any number after `VLAN`, `tag=`, `trunks=`, `vmbr0.`; known tags of 3+ digits anywhere),
  node, storage, pool and non-default bridge names from `discovery/proxmox.json`, as numbered placeholders
  (`<vmid-1>`, `<vlan-2>`, `<node-1>`) that stay the same across title, body and comments. The preview ends with
  a `Redacted: 2 VMIDs, 3 VLANs, …` line.
- Proxmox guests ↔ network discovery ([#7](https://github.com/mhaluska/homelab-manager-skill/issues/7)):
  `proxmox_inventory.py --details` reads the IPs running guests report (QEMU guest agent for VMs with
  `agent=1`, `/interfaces` for LXC). Without the agent privilege it records which one is missing
  (`VM.GuestAgent.Audit`, `VM.Monitor` on 8.x) instead of failing; `docs/proxmox-tokens.md` has an optional
  section granting it (existing repos: copy it from the plugin's template if you want VM IPs).
  `drift_report.py` has a new *Proxmox guests ↔ network* section matching scanned addresses to guests by
  config/agent IP, MAC and DNS name; matched guests no longer appear as unknown network devices.
- VMID conventions ([#6](https://github.com/mhaluska/homelab-manager-skill/issues/6)): optional `vmid_scheme`
  in homelab.yaml (e.g. `"{vlan}{octet:03d}"` → 1020015 for VLAN 1020, x.x.x.15) replaces `vmid_ranges` for VMs
  and LXC. `proxmox_inventory.py --next-vmid vms|lxc [--ip … --vlan …]` gives the ID for a new guest (scheme, or
  next free in range), checked against the snapshot and tfvars. The inventory summary warns when most existing
  VMIDs fall outside the ranges and suggests a scheme that explains them.

## 0.10.0 — 2026-11-16
- Fix ([#5](https://github.com/mhaluska/homelab-manager-skill/issues/5)): `docs/proxmox-tokens.md` granted
  the roles only to the privilege-separated tokens. A privsep token gets the intersection of its own and
  its user's rights, so both tokens had none (403 on every call). The template now grants each role to
  the user `homelab@pve` too and explains why. On a 403, `proxmox_inventory.py` reads the token's
  effective rights (`/access/permissions`) and prints the missing `pveum acl modify … --users …` command;
  a 401 now says the token or secret is wrong.
- Existing repos: `init_repo.py --sync-managed` adds the user ACL line above each token ACL line in
  `docs/proxmox-tokens.md` (keeping your paths and roles) and the explanation. Run the new lines on Proxmox.
- `check_env.py` checks the Proxmox certificate ([#4](https://github.com/mhaluska/homelab-manager-skill/issues/4)):
  Python uses OpenSSL's CA bundle, not the macOS keychain, so a private CA trusted in the keychain still
  failed with `CERTIFICATE_VERIFY_FAILED`. When the issuer is in the System or login keychain and
  verification passes with it, the check prints the `security find-certificate` export and the
  `config_set.py` command for `proxmox.ca_cert`; it also reports hostname mismatches. `proxmox.ca_cert`
  may now use `~` or a path relative to the repo root.

## 0.9.1 — 2026-11-16
- Fix ([#3](https://github.com/mhaluska/homelab-manager-skill/issues/3)): the `skill_issues.md` header
  refresh in `init_repo.py --sync-managed` dropped the `reported-through` marker, so `issues.py report`
  treated every open entry as never reported and could comment on GitHub issues a second time. The
  marker is now kept (it is only dropped for pre-0.6.0 files, where it belonged to the homelab's repo).
- Repos already synced with 0.9.0: `--sync-managed` restores the newest marker from the file's git
  history.

## 0.9.0 — 2026-11-16
- `skill_issues.md` now also collects **ideas to improve the skill**, as two new kinds: `improvement`
  (an existing script, flag, reference or template could work better) and `idea` (something missing).
  Claude notes one unasked when the work or the conversation shows it — a step done by hand that a
  script could do, a question or task no reference covers, an unsupported component or appliance, or
  the user's *"it would be nice if…"* / *"note an idea for the skill"* — written generically, never the
  site's own to-do list. Ideas have their own sections (Summary, Context, Proposal, optional Benefit;
  `issues.py template --kind idea`), are reported like problems (`[improvement]` / `[idea]` titles,
  `enhancement` label when the reporter may triage), and `issues.py list --ideas|--problems` filters them.
  This repository has a new *Idea for the skill* issue form.
- Existing repos: `init_repo.py --sync-managed` (offered by the session-start hook) refreshes the
  `skill_issues.md` header and updates the rule in CLAUDE.md and the row in README.md; entries are kept.

## 0.8.0 — 2026-11-16
- `ISSUES.md` is now **`skill_issues.md`**: the old name looked like the homelab repo's own issue list,
  but the file only holds problems with the homelab-manager skill. New repos get the new name.
- Existing repos: the session-start hook offers the one-time update, and `init_repo.py --sync-managed`
  renames the file (`git mv` when it is tracked, so its history follows), sets `issues.file`, and
  updates the mentions in the repo's CLAUDE.md and README.md. A custom `issues.file` is left alone.
  Until then `issues.py` keeps using the old `ISSUES.md`.

## 0.7.0 — 2026-11-16
- New `config_set.py` edits `homelab.yaml` without reflowing it ([#1](https://github.com/mhaluska/homelab-manager-skill/issues/1)): `yq -i` rewrote the whole file —
  blank lines and comment alignment were lost, and `authorized_ranges: [] # e.g. …` became a block list
  whose comment jumped to `gateway`. It changes only the lines of the keys it edits (`path=value`,
  `list+=item`, `list-=item`, `--delete`, `--dry-run`), keeps each inline comment on its key, and checks
  the result with yq before writing. Setup and `--sync-managed` use it too, so new repos keep the
  template's layout. Existing files that yq already reflowed stay as they are.
- Skill problems are logged when they happen, not only when you ask ([#2](https://github.com/mhaluska/homelab-manager-skill/issues/2)): SKILL.md makes it a rule to run
  `issues.py add` in the same turn whenever Claude works around the skill; a new PostToolUse hook
  (`hooks/skill_problem.py`) reminds Claude when a bundled script crashes or fails; a guard denial says
  how to note a false alarm.
- Guard: asks before adding a range to `network.authorized_ranges` (`config_set.py` or `yq -i`), as the
  approval list already required.

## 0.6.0 — 2026-11-16
- `ISSUES.md` now tracks problems with **the skill itself** — a script that crashed or gave wrong
  results, the guard blocking something legitimate (or letting something dangerous through), a template
  that doesn't validate, wrong or missing instructions, setup trouble. *"Report skill issues"* sends
  them to this plugin's GitHub repository (`issues.py report`): it comments on an existing matching
  issue instead of duplicating, never creates labels, and redacts IP and MAC addresses, the site
  domain, host and guest names, the user name, home path and secrets first. `--dry-run` shows the
  exact text; the guard asks before anything is sent. Each entry gets an Environment section (plugin,
  macOS and tool versions, components). `issues.report: false` keeps everything local.
- Homelab problems (drift, audit findings, failed runs) are no longer tracked in a file: they are
  reported in chat and in `discovery/drift.md` / `docs/security-audit-<date>.md`.
- The homelab repo no longer gets a GitHub issue form; this repository has a *Problem with the skill* form.
- Existing repos: the session-start hook says when a repo needs a one-time update, and
  `init_repo.py --sync-managed` applies it after you agree — old ISSUES.md entries move to
  `docs/issues-archive.md`, the `issues:` block in homelab.yaml, the ISSUES.md rule in CLAUDE.md and
  README.md are updated, and the old plugin-managed issue form is removed (unless you edited it).
- Setup no longer asks about issue tracking.

## 0.5.2 — 2026-11-16
- Setup asks about components in two multi-select questions (core: Proxmox, Packer templates, Ansible,
  discovery; extras: Windows, appliances, Kubernetes), one checkbox per component — no more merged options
  that needed the free-text "Other" field.

## 0.5.1 — 2026-11-16
- Fix: when `.claude/settings.json` already existed in the homelab repo (e.g. the plugin was installed with
  project scope before setup), `init_repo.py` skipped it and the template's safety rules (never read private
  keys or state, ask before `tofu apply`/`packer build`) were lost. They are now merged in; existing rules stay.
- README: which install scope to choose (local recommended; user scope applies the safety hook everywhere).

## 0.5.0 — 2026-11-16
- Moved to GitHub: public repository `mhaluska/homelab-manager-skill`, install over HTTPS
  (`/plugin marketplace add mhaluska/homelab-manager-skill`).
- Issues go to GitHub with `gh`: `issues.py open` / `report` create issues,
  comment on matching ones, and create missing `severity:*` / `area:*` labels. `check_env.py` checks `gh auth status`.
- Guard: asks before `gh issue` writes, label/release/repo/secret changes and GitHub API writes; denies
  printing the `gh` token (`gh auth token`, `--show-token`).
- OpenTofu state: **local** state file on the Mac outside the repository (default)
  or any **S3-compatible** bucket (MinIO, Garage, AWS) with lockfile locking. New `tofu_init.py` runs
  `tofu init` with the backend from homelab.yaml; new secret kind `s3_credentials`.
- Releases: pushing a `vX.Y.Z` tag publishes a GitHub release with that version's CHANGELOG section.
- Template pre-commit hook also blocks GitHub tokens and AWS access keys.
- Issue template: every ISSUES.md entry and GitHub issue has Summary, Affected, Evidence, Impact,
  Proposed fix and Verify (`issues.py template`; missing sections are marked unknown), so a later session
  can fix it from the evidence. The homelab repo gets a matching GitHub issue form, kept current with
  `init_repo.py --sync-managed`. `issues.py pull <n>` imports a GitHub issue (owner/collaborators only
  unless `--any-author`) so "fix GitHub issue #12" works.
- License: MIT.

## 0.4.0 — 2026-11-16
- Update check: a SessionStart hook compares the installed version with the highest `vX.Y.Z` tag on
  the plugin's Git remote, at most once a day (cached in `~/.cache/homelab-manager/`, failed checks
  retried after 6 h), and tells the user when a newer release exists. `update_check.py --force` checks now.
- Cheaper subagents: `homelab-runner` (latest Haiku) for exactly specified commands and scripts,
  `homelab-analyst` (latest Sonnet) for delegated work that needs judgement. SKILL.md §10 says when to
  use which; subagents never approve anything.

## 0.3.0 — 2026-11-16
- `issues.py report`: sends issues added or changed since the last report to the issue tracker. For each it
  first looks for the same or a similar existing issue (same key, already linked, similar title; open or closed)
  and comments on it instead of creating a duplicate; otherwise creates one. `--dry-run` shows the
  plan; `--match`/`--new` override. On success a `reported-through` timestamp marker is written to
  ISSUES.md so old issues aren't reported again; failures leave the marker for a retry.
- Guard asks before `issues.py report` (except `--dry-run`).

## 0.2.0 — 2026-11-16
- Interactive setup: the skill asks which parts the homelab uses (Proxmox/OpenTofu, Packer templates, Ansible,
  discovery, Windows, appliances, Kubernetes), state backend and issue tracking, then scaffolds only those.
  `init_repo.py --components … / --add-components …`; choices recorded under `components:` in homelab.yaml.
- ISSUES.md: problems found (drift, audits, failed runs, config bugs) are recorded via `issues.py`
  (dedupe keys, severities, sanitised text) and can be opened in the issue tracker after the user agrees.
- Guard: asks before creating/closing tracker issues, API writes and `issues.py open`; denies printing the CLI token.
- check_env.py reports the issue-tracker CLI and its login.
- Patching: `patch_exclude` (set per group, e.g. kubelet/kubeadm/kubectl on k8s nodes) — dnf exclude / apt hold.
  Hook paths resolved with `path_join` (fixes an ansible-lint crash).
- Drift report: falls back to the `tofu` tag when state is unreachable; new Backups section (backup storage,
  vzdump jobs covering every guest). proxmox_inventory.py collects backup jobs (read-only).
- Report only what actually ran; skipped or assumed steps are labelled as such.

## 0.1.1 — 2026-11-16
- Fix: template pre-commit hook flagged its own source as a secret, so the first commit of a new repo failed.
- Fix: cluster hooks (k8s drain/uncordon) now run without sudo (`include_tasks … apply: become: false`);
  hook paths are relative to `ansible/` as written in homelab.yaml. Example k8s hooks added to the template.
- Add `kubernetes.core` to Ansible requirements; `patch-linux.yml --syntax-check` works without `-e target`.
- Scanning an authorized range the user asked for no longer needs a second confirmation.

## 0.1.0 — 2026-11-16
- Initial skill `homelab-manager`: orchestration workflow, approval rules, routing to 8 domain references.
- Read-only discovery: `proxmox_inventory.py`, scope-checked `nmap_scan.py`, `drift_report.py`.
- `check_env.py` with keychain self-test; `with_secrets.py` keychain → env with output redaction.
- `init_repo.py` + repository template: homelab.yaml, OpenTofu modules (VM, LXC, cloud-image base; bpg/proxmox ≥ 0.122),
  remote OpenTofu state backend, Packer proxmox-clone template build (Rocky/Debian/Ubuntu), Ansible inventory,
  check-updates and rolling patch playbooks, secret-blocking pre-commit hook.
- `hooks/guard.py` PreToolUse safety hook with unit tests.
