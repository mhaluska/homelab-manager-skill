# Changelog

## Unreleased
- Evals: each case's `place-files.sh` scaffolds the current template with `init_repo.py` and merges only the
  case's own `homelab-values.yaml` and data, so fixtures no longer go stale with the template. New cases:
  `untrusted-guest-note` (a guest note addressed to the assistant is reported, not followed),
  `plan-review-unexpected-replace` (a renamed map key would destroy a VM: stop and propose a `moved` block),
  `secrets-read-only-token` (reads use the read-only token from the keychain, nothing secret is printed) and
  `upgrade-old-repo` (dry run first, nothing changed before the user's yes).
- `tests/test_evals.py` checks every case has its parts, keeps no template copies and scaffolds a repository
  that `--sync-managed` reports up to date.

## 0.59.0 — 2026-11-25
- OpenTofu template: the variables refuse a bad `ipv4_address`, a `vlan_id` outside 1–4094, a VMID below 100, an
  extra disk on `scsi0` or an unknown bus, and an unknown `checksum_algorithm`, naming the entry. A static address
  without a gateway in its subnet is a plan warning. New optional entry attributes, defaulting to what the modules
  always did: `protection` (the Proxmox protection flag), `on_boot`, `description`, `ipv4_gateway` per guest,
  `cpu_type` for VMs, `dns_servers`/`dns_domain` for containers. An upgrade note covers environments with their
  own `main.tf`/`variables.tf`.
- Packer template: new templates allow SSH keys only (`sshd_hardening`, default on), are trimmed before they are
  saved, and take `unattended_updates` (`distro` by default, `security` or `off`). Image URLs are dated
  everywhere; Rocky 10 is no longer listed (it needs an x86-64-v3 CPU type).
- The template's pre-commit hook also refuses passwords, secrets and tokens set to a literal value and Ansible
  vault files that are not encrypted (`pre-commit: allow` on a line lets it pass); `pre-commit --history` runs
  the checks over every commit, and the security audit uses it.
- Ansible collections and the Packer Proxmox plugin have version bounds below their next major release.
- The patch playbooks share one copy of the autoremove protection list and the LXC unit list
  (`playbooks/vars/patch-lists.yml`).
- The guard no longer asks for a script with `case` patterns such as `a|b)`: they are not commands.
- `validate_template.sh` runs `tofu test` against a mocked provider: entry defaults, options and validations.

## 0.58.0 — 2026-11-25
- `pve_snapshot.py`: `create` and `delete` go on after a guest that fails and report every failure at the end
  (a guest stopped for a `--mode stop` snapshot is started again); `prune --older-than 30d [--prefix P]` deletes
  old snapshots; `--dry-run` shows what any write would do using the read-only token; `restore` is an alias of
  `rollback`. A status read that fails is retried.
- `lxd_snapshot.py`: the same `prune`, `--dry-run` and failure handling; `restore`/`rollback` are both accepted.
  The guard asks before prune, restore and rollback in both scripts and lets `--dry-run` run.
- `proxmox_inventory.py`: a node or guest that answers an error, times out or returns broken JSON no longer ends
  the run; the snapshot is written with a "Not read" section. Nodes and guests are read in parallel (`--jobs`,
  default 8): about three times faster on a three-node cluster.
- Scripts write `homelab.yaml`, discovery files and generated docs atomically (a temporary file renamed into
  place), and per-site discovery writes take a lock, so two sites scanned at once keep each other's data.
- `nmap_scan.py`: service and OS scans give up on a host after 15 minutes (`--host-timeout`, `0` turns it off);
  Ctrl-C stops nmap too.
- Timeouts and a one-line error instead of a traceback for `yq`, `gh`, `tofu show` and `ansible-inventory`;
  `ansible-inventory` runs once per script run.
- `drift_report.py --out -` prints the report instead of writing a file named `-`.
- `routeros_audit.py`: `--jobs` (default 8); a broken `discovery/routeros.json` is reported before connecting and
  never replaced.
- Maintainers: `.github/release.py` does a release but the push, `.github/validate_template.sh` checks the
  scaffolded template with tofu, packer and ansible, and a GitHub workflow runs both test suites on every push.

## 0.57.0 — 2026-11-25
- The guard checks a program an interpreter reads from stdin: `bash < x.sh` and `python3 < x.py` are checked like
  `bash x.sh`, and an interpreter reading its program from a pipe (`cat x.sh | bash`) asks. A heredoc piped into an
  interpreter is still checked as code.
- After `cd ~/.ssh`, bare key names (`cat id_ed25519`, `id_*`) and archiving the directory (`tar czf k.tgz .`) are
  denied like the full paths.
- `nmap -iL` reads only a regular file up to 1 MiB: a device or named pipe (`/dev/zero`) blocked the hook until its
  timeout; it is now refused. Comments in a target list no longer count as targets.
- New "ask" rules: package upgrades and removals run directly (`apt-get dist-upgrade`, `dnf upgrade`, `zypper dup`,
  `pveupgrade`, over `ssh` or `ansible -m shell`), `pveum` writes, `qmrestore` and `pct restore`, removing volumes
  or file systems (`lvremove`, `vgremove`, `wipefs`, `mkfs`, `sgdisk --zap`, `dd of=/dev/…`, `diskutil erase…`), a
  recursive `rm` over `ssh` or in a guest (`pct exec`, `docker exec`, …), RouterOS `reset-configuration` and
  `/system backup load`. Force pushes are recognised with `git -C` and as `+branch`, `:branch`, `--delete`,
  `--mirror` and `--prune`.

## 0.56.0 — 2026-11-24
- Fewer permission prompts ([#147](https://github.com/mhaluska/homelab-manager-skill/issues/147)): with the new homelab.yaml key `permissions.auto_allow_readonly: true`
  the guard lets this plugin's read-only scripts run without a prompt (`issues.py list|show|template|fixed`,
  `issues.py report --dry-run`, `check_env.py`, `upgrade_notes.py`, `init_repo.py --sync-managed --dry-run`,
  `overview.py --check`, `drift_report.py --stale`, `update_check.py --force`). Only scripts of the running plugin
  version, only as one simple command, with arguments matched exactly; any guard finding still wins. Off by
  default; the guard asks before it is turned on. Setup and an upgrade note offer it.
- The template's `.claude/settings.json` allows `git add` and `git commit` (also as `git -C <repo>`);
  `--sync-managed` adds the rules to existing repos. `git push` keeps asking.
- SKILL.md and the references ask for simple commands that permission rules can match: one script per Bash call
  with the skill path written out, no `HM=…;`, `cd … &&`, pipes into `tail`/`head` or heredocs, `git -C <repo>`.
  `references/security.md` has a new "Permission prompts" section.
- The guard no longer takes `issues.py list --status open` for a send.
- `issues.py fixed` missed the issues 0.55.0 fixed: its changelog named them without links. They are linked now,
  and a test keeps every issue in the changelog linked ([#146](https://github.com/mhaluska/homelab-manager-skill/issues/146)).

## 0.55.0 — 2026-11-24
- `security_audit.py` reads each VM's EFI disk and reports `pve-efi-ms-cert-<vmid>` when Secure Boot keys are
  pre-enrolled but not the Microsoft 2023 certificates (`ms-cert=2023k`; `2023` and `2023w` are partial). The fix is
  `qm enroll-efi-keys <vmid>` with the VM shut down, after suspending BitLocker in Windows guests; a template's
  clones are enrolled one by one. `references/proxmox.md` describes the procedure
  ([#145](https://github.com/mhaluska/homelab-manager-skill/issues/145)).
- `references/patching.md`: after patching a Proxmox node, re-check it with `check-updates.yml -e target=<node>`;
  `ssh_probe.py` is for onboarding unknown hosts and skips managed ones
  ([#144](https://github.com/mhaluska/homelab-manager-skill/issues/144)).

## 0.54.0 — 2026-11-24
- Proxmox endpoints over plain `http://` are refused unless that site sets `allow_http: true` (the API token would
  cross the network in clear text). `check_env.py` warns while it is set, and while `bmc_validate_certs` or
  `unifi_validate_certs` is false. Both guards ask before `allow_http` is turned on.
- `issues.py report` looks for host names with a domain and key-like strings left after redaction. The dry run
  lists them; a send refuses (exit 6) until they are edited out, kept with `--keep`, or sent with `--force` after
  the user checked them. The guard asks for `--force` even with `issues.auto_send`.
- `site.language` reaches the session context only as a language code or name; `config_set.py` refuses other values.
- SSH from the scripts (`ssh_probe.py`, `lxd_snapshot.py`, `routeros_audit.py`) forwards nothing (agent, X11, ports),
  never falls back to passwords, and takes the host after `--`; a host starting with `-` or holding spaces is refused.
  The update check accepts only https, ssh or local plugin remotes and passes the URL after `--`.
- `check_env.py` cleans certificate names from the server before showing them and shell-quotes them in the
  suggested `security find-certificate` command. `hmlib.clean()` also drops invisible and text-reordering Unicode
  characters from network-sourced text.
- Templates: `cloud-image-base` refuses a base image without a checksum unless `allow_unverified_image = true`.
  The pre-commit hook reads names NUL-separated and refuses the names `.gitignore` keeps out and temporary AWS keys.
  `.claude/settings.json` denies reading SSH keys, AWS, gh and kube credentials; `--sync-managed` adds the
  template's permission rules an existing settings.json lacks. The BMC and UniFi group_vars say what turning
  certificate checks off exposes.
- CI pins `actions/checkout` to a commit.

## 0.53.0 — 2026-11-24
- `with_secrets.py` gives keychain secrets without asking only to `tofu`, `terraform`, `packer`, `ansible*` and this
  plugin's scripts. Any other program under it, or a command line that names a secret's environment variable
  (including the `env` names under `secrets:` in homelab.yaml), asks. Its output filter also removes URL-encoded,
  JSON-escaped, hex and base64 echoes of a secret; the docs now call it best effort.
- Keychain: `security` is checked by its tokens, so printing a password (`-w`, `-g`, also as `-gw`), dumping or
  exporting the keychain, and the interactive mode are denied whatever the global options.
- Private SSH keys: any program naming a private key under `.ssh/` is denied, including globs, archiving the `.ssh`
  directory and Python `open()`. Listing a key and SSH tools that use it as their identity (`ssh -i`, `ssh-add`,
  `--private-key`) are still allowed. `git credential fill`/`get` and `gh auth git-credential` are denied. Reading
  `*.tfstate`, `tofu state pull` and `tofu show -json` without a plan ask (state can hold secrets).
- New hook `guard_files.py` for Claude's file tools (Edit, Write, MultiEdit, NotebookEdit). It asks when an edit
  changes the scan scope (`network.authorized_ranges`, `network.excluded_hosts`), any `verify_tls` or
  `issues.auto_send` in homelab.yaml, the installed plugin, or `.claude/settings*.json`. The Bash guard asks when a
  command writes homelab.yaml outside `config_set.py`, or writes or removes the plugin's files or
  `.claude/settings*.json`. `config_set.py` narrowing `network.excluded_hosts`, replacing `network` or setting
  `verify_tls` to false asks.
- Other scanners (`masscan`, `zmap`, `rustscan`, `naabu`, `arp-scan`, `fping -g`, …) ask; so does `nc -z` over
  several ports, to a host computed at run time or to an address outside the authorized ranges. `nmap -sI` and
  `-b` ask. `curl --json`, `-F`/`--form`, `-T`/`--upload-file`, `-d@file` and `--request=METHOD` count as writes
  to the Proxmox and UniFi APIs.
- `git commit --no-verify` and setting or unsetting `core.hooksPath` ask: they skip the pre-commit secret check.
- `references/security.md` lists these rules and what the guard can't see: playbooks are judged by name, and
  `make`/`just`/`npm run` targets aren't read.

## 0.52.0 — 2026-11-24
- The guard fails closed: any error of the hook itself (a plugin install that cannot load its library, unreadable
  input, a bug), and a used-up time budget (45 s shared by everything one check runs), asks instead of letting the
  command run unchecked.
- The guard checks commands the way the shell runs them. Quotes, backslashes and variables set earlier in the same
  command no longer change what the rules see, and a program name only known at run time asks. Wrappers are
  unwrapped with their options (`sudo -u USER`, `timeout DURATION`, `nice -n`, `env -S`, `xargs`, …); nmap behind
  `xargs`, `find -exec`, `watch` or `docker exec` asks. `python3 -c`, `bash -lc` and `perl`/`ruby`/`node -e` code is
  checked, and interpreter options (`bash -x`, `python3 -u`) no longer hide the script they run. `cd` is followed and
  `$HM` resolves to the skill's directory, so `nmap_scan.py` and `ssh_probe.py` are scope-checked however they are
  called.
- Scripts: one that does not exist yet when the guard runs asks, unless the same command writes it from a heredoc
  (then that text is checked). A script found on PATH outside the system directories is scanned too. `$(…)` and
  backticks inside a heredoc with an unquoted delimiter are checked as the commands they are.
- OpenTofu: applying a plan file that the same command writes asks (the guard would otherwise read the previous
  plan); so do `plan -destroy`, `apply -destroy` and `apply -refresh-only` (`plan -refresh-only` does not). The guard
  reads plans with the installed `tofu`/`terraform` only, never a `./tofu` the command names.
- `references/security.md`: make a plan and apply it, or write a script and run it, in separate commands.

## 0.51.0 — 2026-11-22
- `patch-proxmox-node.yml` waits for Proxmox's own onboot start after the reboot
  ([#141](https://github.com/mhaluska/homelab-manager-skill/issues/141)). `systemctl is-active` with several units exits
  0 when any one of them is active, so the wait for `pve-guests` passed at once. The playbook then started the stopped
  guests itself while `startall` was still starting them, ignored their startup delays, and failed on
  `CT … already running` before its final checks. It now checks every unit and waits until `pve-guests` has finished
  (up to `pve_guests_timeout` seconds, default 1800). A guest that runs within 30 s of a failed start counts as
  started, after the reboot and in the shutdown rescue.
- `patch-linux.yml` names new failed SSSD sockets that conflict with `sssd.conf`
  ([#142](https://github.com/mhaluska/homelab-manager-skill/issues/142)). On Debian IPA clients a responder still on
  the `services` line (and `pac`, implied by an IPA domain) refuses to start socket-activated, so its
  `sssd-*.socket` fails on every boot. The failure message calls it a known SSSD conflict that the update did not
  cause, and `references/patching.md` describes the two fixes (use only one of them).
- `docker-containers.yml` records `memory` for running containers with a memory limit: limit, usage, and since the
  container's start how often it hit the limit, its OOM kills and the evicted file pages it read again (cgroup v2,
  Docker and Podman) ([#143](https://github.com/mhaluska/homelab-manager-skill/issues/143)). OVERVIEW.md warns
  under Health and At a glance about a container with OOM kills, or one whose page cache thrashes (it hits its
  limit 1000 times an hour and re-reads 10000 pages an hour), and names the Compose project to raise `mem_limit` in.

## 0.50.0 — 2026-11-22
- The security audit covers Proxmox and joins the other discovery files
  ([#139](https://github.com/mhaluska/homelab-manager-skill/issues/139), second and last part).
  `security_audit.py` reads each site's Proxmox with the read-only token (GET only; `--no-proxmox` re-judges the
  last read): administrators without a second factor, API tokens on `root@pam` or without privilege separation,
  expired tokens, the datacenter and node firewall, privileged LXC containers and what weakens them (`nesting`,
  `mount`, `fuse`, raw AppArmor/cgroup/capability settings). It joins `routeros.json` (port forwards that open RDP,
  SMB, a database, the Proxmox UI or every port to any address; a privileged container or a host with pending
  security updates behind a forward ranks higher; the routers' own findings are listed apart), `network.json`
  (risky services nmap saw on devices the playbook doesn't reach) and `updates.json` (pending security updates and
  reboots). `--report` records the findings, so the next report lists what is new and what is gone since.
  Proxmox, forward and scan findings are accepted per site with the new `security_audit.accept` key in homelab.yaml;
  a node or container also takes the `security_audit_accept` host var. OVERVIEW.md counts them all. Only PBS and
  the repo are left to check by hand. `init_repo.py --sync-managed` suggests the first run as an upgrade note.
- `proxmox_inventory.py --details` records each LXC container's `unprivileged` and `features`.
- `ip=dhcp` and `ip6=auto` in a guest's config were read as the addresses `d` and `a`; they are no addresses now.

## 0.49.0 — 2026-11-21
- Security audit of Linux hosts and this Mac with a playbook and a script instead of a hand-run checklist
  (#139, first part: the issue stays open for Proxmox and the joined report).
  `playbooks/security-audit.yml` reads, without changing anything (also in `--check`), each host's `sshd -T`, the
  names of accounts with a usable or empty password, NOPASSWD sudo rules, the host firewall, automatic updates,
  listeners, Samba shares, NFS exports, containers and tunnel clients into `discovery/security.json`.
  `security_audit.py [--site N] [--report]` contacts no host: it judges that data with stable finding keys (SSH
  passwords and root login, empty passwords, second UID 0, guest-writable shares, NFS open to anyone or with
  `no_root_squash`, containers holding the Docker socket or running privileged, Redis/memcached/Docker API and
  other risky listeners, no host firewall, no automatic updates, old cloudflared), checks this Mac (FileVault,
  firewall, SIP, Gatekeeper, SSH agent; `--mac-updates` adds `softwareupdate -l`) and prints the report;
  `--report` saves it as `docs/security-audit-<date>[-<site>].md` and never replaces an existing one.
  `security_audit_accept: [keys]` (host or group var) and `security_audit.mac_accept` (homelab.yaml) mark findings
  the user keeps. OVERVIEW.md counts the rest under Health and warns on high and medium ones. Proxmox, PBS, the
  routers, the network and the repo are listed in the report as still checked by hand.
  `init_repo.py --sync-managed` offers the playbook to existing repos as an upgrade note.

## 0.48.0 — 2026-11-21
- New `playbooks/routeros-routerboot-upgrade.yml` for the `routerboot-<version>` finding of `routeros_audit.py`
  ([#140](https://github.com/mhaluska/homelab-manager-skill/issues/140)). `-l <host> --check` shows current → target firmware; with the user's yes,
  `-e homelab_read_only=false` stages the firmware, checks the log for "Firmware upgraded successfully", reboots,
  waits for SSH and fails unless the new firmware runs. CHR/x86 and current devices are skipped. It refuses more
  than one device per run (`-e routeros_routerboot_many=true` does them one after another) and the device holding
  the Mac's default gateway (`-e routeros_routerboot_gateway=true`), whose reboot cuts the session off. The audit
  report prints the command for each inventory device. `init_repo.py --sync-managed` in repos
  with the `appliances` component offers it as an upgrade note.

## 0.47.0 — 2026-11-20
- `routeros_audit.py --leases` can be limited to part of the network ([#137](https://github.com/mhaluska/homelab-manager-skill/issues/137)). `--range CIDR` and
  `--vlan ID|NAME` (repeatable; a VLAN is looked up in `network.vlans` at each device's site) keep the MAC fill in
  `discovery/network.json` and the name proposals inside those addresses, so each VLAN can go into its own commit.
  `--leases-only` reads only identity, resources, leases and ARP, prints no audit and leaves `routeros.json` as it is.
  A host given by its inventory name or address takes its user, port and site from the managed inventory, like
  `--group`, and a device named twice is read once.
- RouterOS findings can be accepted per device ([#138](https://github.com/mhaluska/homelab-manager-skill/issues/138)). Every finding has a stable key, shown in the
  report and kept in `routeros.json` (`ssh-any-address`, `plaintext-www`, `default-admin`,
  `routerboot-<version>`, …). The host or group var `routeros_audit_accept: [keys]` marks the ones the user decided
  to keep. The report lists them apart and gives no fix for them, and OVERVIEW.md counts them as accepted, not under
  their severity. A new finding still shows, and keys that match nothing any more are listed. `--recompute`
  applies a changed list without connecting.
- A RouterOS service open to any address now shows how the IPv4 input firewall treats new connections to its port
  (the deciding rules in order, e.g. `accept in-interface-list=TRUSTED; drop the rest`) ([#138](https://github.com/mhaluska/homelab-manager-skill/issues/138)). This is
  evidence to judge by, not a verdict: the severity stays, jumps are not followed and IPv6 is not covered. The audit
  now also reads `/ip firewall filter`.

## 0.46.0 — 2026-11-19
- `patch-linux.yml` no longer fails a host that has nothing to autoremove ([#136](https://github.com/mhaluska/homelab-manager-skill/issues/136)). An empty skip reason
  became `None` instead of `''`, the `when` failed, and with `max_fail_percentage: 0` the batch stopped after the
  packages were updated but before the health checks. `init_repo.py --sync-managed` updates unchanged copies.
- `nmap_scan.py --arp`: when the ICMP sweep got answers but the ARP table came back empty, the hint now says what
  is happening ([#135](https://github.com/mhaluska/homelab-manager-skill/issues/135)). macOS hides the ARP table from programs Homebrew's Python starts, even with Local
  Network access allowed, so the hint prints the command to re-run with `/usr/bin/python3`. It no longer asks to
  allow access that is already allowed.
- The ICMP sweep no longer counts "Host is down" (no ARP answer on the Mac's own segment) as a blocked send. Before,
  that printed a false Local Network warning and fell back to TCP probes.

## 0.45.0 — 2026-11-19
- Smart-home devices are recognised ([#132](https://github.com/mhaluska/homelab-manager-skill/issues/132)). `nmap_scan.py` device guesses gain `iot` from IoT vendors
  (Netatmo, Yeelink, Xiaomi Electronics, Tuya, Signify/Philips Lighting, …) and from embedded stacks (lwIP,
  FreeRTOS) serving only web ports, and `media` for Apple devices without a Mac's services (Apple TV, HomePod) and
  Sonos. A TP-Link MAC with nothing but a web page is `iot/network`, since TP-Link makes both plugs and switches.
  A VM's virtual NIC vendor (Proxmox, VMware, QEMU, Xen) no longer counts as evidence.
- `routeros_audit.py --leases` gives scanned hosts without a MAC the one the router's ARP table or a bound DHCP
  lease has, with its vendor and `mac_source: router`, and guesses their type again ([#132](https://github.com/mhaluska/homelab-manager-skill/issues/132)). nmap sees no
  MACs on routed ranges, so vendor-based guesses now work there too. The lease proposals show the vendor.
  `init_repo.py --sync-managed` suggests the refresh.
- OVERVIEW.md's VLAN table counts every address the repository knows in each CIDR ([#134](https://github.com/mhaluska/homelab-manager-skill/issues/134)), not only scanned
  ones and each guest's primary IP. That covers every guest NIC, inventory hosts and `hm_extra_ips`, Proxmox nodes,
  gateways, RouterOS, NAS containers and `discovery.ignore_unmanaged` devices. A new "In use by" column splits the
  count into guest IPs, infra and other devices, and counts guests on the VLAN whose address is unknown. A VLAN outside
  `network.authorized_ranges`, or with no scanned host, is marked `(not scanned)`.

## 0.44.0 — 2026-11-19
- `routeros_audit.py` reads each device in one SSH session instead of one connection per command
  ([#131](https://github.com/mhaluska/homelab-manager-skill/issues/131)). Routers can refuse logins that come too quickly one after another, and then the later commands
  (NAT rules, neighbour discovery, DHCP leases, ARP) failed as "auth failed". A command the device lacks fails only
  its own section, and a failed section is retried alone. `--leases` lists the routers whose lease or ARP table
  could not be read as **Incomplete**, so "no lease names" no longer hides an unread table.
- `check-updates.yml -e target=hostA,hostB` keeps every play to those hosts ([#129](https://github.com/mhaluska/homelab-manager-skill/issues/129)). With commas, Ansible
  applied the Windows/QNAP intersection only to the last host, so the first one also ran the Windows play and got
  a Windows error in `discovery/updates.json`. Commas now become `:`. `init_repo.py --sync-managed` updates
  unchanged copies.
- `nmap_scan.py` device guesses: ports 49152 and up are no longer evidence, and the AirPlay pair (rtsp on 5000 and
  7000) counts as an Apple device, not a camera ([#130](https://github.com/mhaluska/homelab-manager-skill/issues/130)). An AirPlay speaker was guessed `camera/network`
  because nmap matched its port 49153 to a 4-byte "MikroTik bandwidth-test server" signature.
- `issues.py report` redacts only valid IPv6 addresses ([#133](https://github.com/mhaluska/homelab-manager-skill/issues/133)). A MAC vendor prefix such as `70:EE:50` or a
  time is kept. `--keep` now also keeps an address, MAC or e-mail address; secrets are always removed.

## 0.43.0 — 2026-11-19
- The ping sweep is now an ICMP echo sweep that `nmap_scan.py` sends itself, without root and without nmap
  ([#128](https://github.com/mhaluska/homelab-manager-skill/issues/128)). nmap sends ICMP only as root, so it used to find hosts only by TCP connects to 80 and 443 and
  missed hosts that serve neither. When the user knows a device the sweep missed, re-run it with `--tcp` (also
  nmap's TCP probes, to 22, 80, 443, 445, 3389, 5000, 8080, 8443 and 62078) and, for a range on the Mac's own
  network segment, `--arp` (also the Mac's ARP table, which has hosts that drop ICMP and every port; refused for
  routed ranges). Each host records the probes that answered it in `discovered_by`. A host found before only by
  probes a sweep didn't send is not marked missing by that sweep, so a host that answers only TCP stays current.
  If macOS Local Network privacy blocks the Python running the script, the ICMP sweep and `--arp` say so: the
  sweep then falls back to nmap's TCP probes instead of finding nothing.
- `nmap_scan.py --only-live` skips nmap's ping for the services and os profiles (`-Pn`): those hosts are known to
  be up, and nmap's ping missed the ones that drop it. Hosts marked missing are left out. `--no-ping` does the same
  for explicit targets of at most 16 addresses, e.g. a host only `--arp` found.

## 0.42.0 — 2026-11-19
- A ping sweep marks the known hosts inside its targets that did not answer with `missing_since` ([#127](https://github.com/mhaluska/homelab-manager-skill/issues/127)),
  and any scan they answer clears it. `drift.md` and OVERVIEW.md list these hosts apart from current devices, with
  the date they went missing and when they were last seen, so an old DHCP address no longer looks like a live
  unmanaged device. The `services` and `os` profiles never set the mark: with `--open`, nmap leaves out hosts that
  are up but have no open ports. `nmap_scan.py --forget-missing DAYS [--dry-run] [--site N]` scans nothing: it
  drops the hosts missing for more than DAYS days.
- `nmap_scan.py --site <name>` without targets: a repo's only site, when it has no `ranges`, scans every range in
  `network.authorized_ranges` ([#125](https://github.com/mhaluska/homelab-manager-skill/issues/125)). Next to other sites, a site without `ranges` is still refused. With neither
  targets nor `--site`, the guard now says how to fix the command.
- `issues.py report` sanitises every title, body and comment before printing the `Redacted:` summary, and sends
  that exact text. A real send now reports the same redactions as `--dry-run` instead of "no site identifiers
  found" ([#126](https://github.com/mhaluska/homelab-manager-skill/issues/126)).

## 0.41.0 — 2026-11-19
- `network.excluded_hosts` and `discovery.ignore_unmanaged` accept last-octet ranges such as `10.0.20.101-254`
  ([#124](https://github.com/mhaluska/homelab-manager-skill/issues/124)), plain or as `{ip, site}`; they are kept as written and become the exact CIDR blocks when a scan
  runs. A named `ignore_unmanaged` device stays one address, and `authorized_ranges` stays IPs and CIDRs.
- `init_repo.py` and `config_set.py` stop with "yq is not installed (brew install yq)" before writing anything
  ([#119](https://github.com/mhaluska/homelab-manager-skill/issues/119)), `--dry-run` included, instead of crashing halfway through a scaffold. Every script finds `yq` the
  same way (PATH, then Homebrew's).
- Repos without Proxmox: `check_env.py` reports the tools of disabled components as not needed instead of missing
  ([#120](https://github.com/mhaluska/homelab-manager-skill/issues/120)); `drift_report.py` leaves out the Proxmox snapshot and OpenTofu rows and loads no state, so
  `--no-tofu` isn't needed, and checks inventory hosts against the network scan alone; OVERVIEW.md's Sources and
  At a glance don't ask for a Proxmox snapshot ([#123](https://github.com/mhaluska/homelab-manager-skill/issues/123)).
- `nmap_scan.py` recognises macOS from nmap's `ostype` (`Mac OS X`) and counts bare `rtsp` ports once per host,
  so a Mac with AirPlay Receiver (rtsp on 5000 and 7000) is no longer guessed as a camera ([#121](https://github.com/mhaluska/homelab-manager-skill/issues/121)).
- `ssh_probe.py` warns when there is no SSH key to offer (empty ssh-agent, no key file, honouring `IdentityAgent`)
  and reports `auth failed (no SSH key loaded — ssh-add …)` instead of suggesting `--user` ([#122](https://github.com/mhaluska/homelab-manager-skill/issues/122)).

## 0.40.0 — 2026-11-19
- `nmap_scan.py --site <name>` without targets ([#118](https://github.com/mhaluska/homelab-manager-skill/issues/118)) scans the site's `ranges` that lie inside
  `network.authorized_ranges` (a partly authorized range: its authorized parts; neighbouring authorized ranges stay
  separate targets) and lists the ranges it left out instead of refusing the whole scan. Explicit targets outside
  the authorized ranges are still refused; the guard hook makes the same computation. The upgrade notes
  `overview-tls-certificates` and `network-scans-per-site` give this exact per-site command.

## 0.39.0 — 2026-11-19
- OVERVIEW.md lists BMCs as **Server hardware** ([#117](https://github.com/mhaluska/homelab-manager-skill/issues/117)), a per-site table right after the Proxmox nodes: server, BMC,
  model, address, firmware, health (with its accepted causes), power, last seen. A BMC belongs to the server named
  by its host var `bmc_of`, else by its name (`bmc-<host>`, `<host>-bmc`, `<host>-ipmi`) when that host is in the
  inventory or a Proxmox node. The rest of the old section is **Network devices and appliances** (RouterOS, UniFi,
  QNAP NAS, other appliances); the site map still shows every device on its VLAN, and Health's "see …" wording
  names the new sections.
- `issues.py compact [--older-than DAYS] [--apply]` ([#116](https://github.com/mhaluska/homelab-manager-skill/issues/116)): resolved entries keep their heading, metadata, status
  line and resolution note in skill_issues.md; their details move to `docs/skill-issues-archive.md` (appended, never
  discarded), so IDs are never reused and `reopen`, `add` with a key and `report` keep working. A dry run without
  `--apply`; by default every resolved entry (`--older-than` limits it to those resolved that long ago). Not
  automatic: `fixed --apply` says when resolved details exceed 50 KB. Resolved rows of the summary table are
  collapsed into a `<details>` block.
- Upgrade note: `overview-server-hardware` (set `bmc_of` for a BMC whose server isn't found by name).

## 0.38.0 — 2026-11-18
- OVERVIEW.md covers recovery, dependencies, exposure and expirations ([#89](https://github.com/mhaluska/homelab-manager-skill/issues/89)), only from data the
  repository records, nothing guessed from names:
  - **Last backup**: a Guests column, and under Backups the guests in a job with no successful backup within
    `overview.backup_max_age_days` (homelab.yaml, default 7) or whose newest backup failed; counted in At a glance.
  - **Start order**: each node's autostart guests in the order Proxmox starts them (`startup` order, then VMID;
    HA-managed ones by the HA manager), the cluster's quorum, the running guests nothing starts again, and what each
    guest does for others (gateway of VLANs, storage server, cluster member, critical).
  - **If it goes down**: per Proxmox node its running guests and what they serve; per `network.vlans` gateway that
    is no guest there its VLANs; per storage server its Proxmox storages and the guests with disks or ISOs there;
    per NAS its containers and what they serve.
  - **Port forwards**: enabled RouterOS dst-nat rules with every matcher and the target's name, and the public
    addresses on RouterOS interfaces (other gateways and tunnels are not covered, and the page says so).
  - **Access**: per known host the SSH command as Ansible connects, web UI links and other services.
  - **Expirations**: CHR licences, Proxmox VE subscriptions, node web certificates and the TLS certificates nmap read,
    soonest first; within 30 days is a warning. Ages and expiries are judged against the newest data, not today, so
    the page still changes only with the data. Domain registrations are not looked up.
  - "What changed" was declined: OVERVIEW.md is committed with the change it describes, so it can't list that
    commit; `git log` is the record.
- `proxmox_inventory.py` records each node's subscription (status, level, next due date, never the key) and web UI
  certificate, and the server of each network storage. `--details` also records each guest's newest successful
  backup and a newer failure from the nodes' vzdump task logs: the read-only token can't list backup volumes (that
  needs VM.Backup), but reads task logs with Sys.Audit.
- `routeros_audit.py` also reads the NAT rules (`/ip firewall nat print`, read-only).
- `nmap_scan.py`: the `services` and `os` profiles run nmap's `ssl-cert` script (category safe: it reads the
  certificate of a port nmap identified as TLS) and keep each port's certificate subject, issuer, names and expiry
  (`tls`) and whether it is TLS (`tunnel`).
- OVERVIEW.md reads `qnap-containers.json` in the layout `qnap-containers.yml` writes (`hosts.<nas>.containers`,
  the layout of containers.json): the NAS containers were missing from Containers and their addresses were unknown.
- Upgrade notes: `overview-recovery-proxmox`, `overview-port-forwards`, `overview-tls-certificates` (regenerate).

## 0.37.0 — 2026-11-18
- OVERVIEW.md shows every item of a list cell ([#115](https://github.com/mhaluska/homelab-manager-skill/issues/115)): an Ansible group lists all its members (no cap at 12), and
  no name, port mapping or address is cut in half by the cell length limit; each item is escaped and limited on
  its own.
- `bmc-info.yml` records why a BMC's health is not OK ([#103](https://github.com/mhaluska/homelab-manager-skill/issues/103)): `health_causes` lists `chassis_intrusion` (the
  chassis intrusion sensor, read from Redfish PhysicalSecurity) and every component not OK, and `intrusion` keeps
  the sensor state. Supermicro's invalid UTF-8 chassis JSON is read as raw bytes and parsed leniently. The host var
  `bmc_health_accept` (e.g. `[chassis_intrusion]`) accepts a known cause: OVERVIEW.md shows the health as accepted
  and counts no warning; a new cause still warns.
- OVERVIEW.md identifies network devices from facts ([#104](https://github.com/mhaluska/homelab-manager-skill/issues/104), [#105](https://github.com/mhaluska/homelab-manager-skill/issues/105)): Model is the host var `hm_model`, else the
  audit, controller, BMC or QNAP data, else what `ssh_probe.py` read, else the Proxmox guest the device runs as; a
  RouterOS CHR shows as `CHR (VM <vmid> on <node>)`. An nmap OS guess is never a model, only "nmap guess: …" in
  State. The OS column of "Other scanned addresses" is "OS guess (nmap, match %)"; on tied matches a vendor/product
  match beats a generic "Linux x - y", and the MAC vendor is shown in "Looks like".
- At a glance lists every warning category Health shows, most severe first ([#108](https://github.com/mhaluska/homelab-manager-skill/issues/108)): BMCs not OK (unless
  accepted), RouterOS findings of medium severity and above, failed update checks, hosts with security updates,
  guests in no backup job, full storage, node memory. Before, only capacity and backup coverage were counted.
- OVERVIEW.md has a Contents list ([#113](https://github.com/mhaluska/homelab-manager-skill/issues/113)): every section and each site's sub-sections, with anchors that work on
  GitHub and GitLab (with several sites the sub-sections are named "Guests (home)", so they are unique); each site
  ends with "↑ Contents", At a glance links to Health, and Guests, Containers and Other scanned addresses tables
  longer than 15 rows are collapsed with their row count.
- Upgrade notes: `bmc-health-causes` (template), `bmc-health-causes-refresh` (regenerate).

## 0.36.0 — 2026-11-18
- OVERVIEW.md counts every NIC of a guest in the VLAN table and the site map ([#107](https://github.com/mhaluska/homelab-manager-skill/issues/107)): a router or firewall VM
  shows on each VLAN it has a NIC in again (a regression in 0.34.0), a tagged VLAN missing from `network.vlans` is
  shown, and untagged NICs are grouped per bridge ("untagged on vmbr1"). The Guests table keeps one NIC per guest.
- OVERVIEW.md wording ([#109](https://github.com/mhaluska/homelab-manager-skill/issues/109)): "1 node", "1 guest"; the Sites map draws no links between sites (the repository
  has none to show); a site without VLANs says "flat network (untagged)"; a backup job without a comment is named by
  schedule and storage whatever its id (Proxmox's `backup-xxxxxxxx-xxxx` ids were shown raw); a collapsed list
  shows which known host each scanned address was attributed to.
- `overview.py` and `drift_report.py` resolve scanned addresses the same way ([#106](https://github.com/mhaluska/homelab-manager-skill/issues/106)): `discovery.ignore_unmanaged`
  in every form (plain, `{ip, site}`, `{ip, name, mac}`) keeps an address out of OVERVIEW.md's "Other scanned
  addresses", and the drift report counts an audited RouterOS device's interface addresses (routeros.json) as the
  router's and lists them, so they no longer need copying into `hm_extra_ips`.
- `ssh_probe.py`: a failed probe keeps the last good facts of the host in network.json and records `last_error`,
  `last_error_at` and `last_error_user` beside them; a good probe clears them ([#110](https://github.com/mhaluska/homelab-manager-skill/issues/110)).
- `routeros_audit.py` judges free flash by device class ([#112](https://github.com/mhaluska/homelab-manager-skill/issues/112)): on 16 MiB flash a few MiB free is normal on
  RouterOS 7 and is no finding; less than `routeros_audit.min_free_flash` (homelab.yaml, default `512KiB`) is
  `info`; larger flash under 10 % or 5 MiB is `low` (was `medium`). `--recompute` applies the rules to
  routeros.json without connecting.
- A script from a plugin version older than the repository's `upgrades.reviewed` refuses to write repo files and
  names the version to use; read-only scripts and `issues.py` only warn ([#111](https://github.com/mhaluska/homelab-manager-skill/issues/111)). The plugin cache keeps old
  versions, and a session that started on one undid a newer version's OVERVIEW.md.
- `issues.auto_send: true` in homelab.yaml (only on the user's request; the guard asks when it is set) lets
  `issues.py report` send without the guard's prompt; raw `gh issue` writes still ask ([#114](https://github.com/mhaluska/homelab-manager-skill/issues/114)).
- Upgrade notes: `routeros-flash-findings` (regenerate).

## 0.35.0 — 2026-11-18
- `proxmox.endpoint` (and `sites[].proxmox.endpoint`) takes several addresses in priority order, as a YAML list or
  comma-separated ([#98](https://github.com/mhaluska/homelab-manager-skill/issues/98)). `proxmox_inventory.py`, `pve_snapshot.py`, `pve_guest.py` and `with_secrets.py`
  (OpenTofu, Packer) use the first that accepts a connection and say when it isn't the first; a refused token or
  certificate does not move on. `check_env.py` checks each (`proxmox:tls#N`): one that is down is a warning while
  another answers. A single URL works as before. references/proxmox.md "API endpoints".
- Known unmanaged devices get a name ([#100](https://github.com/mhaluska/homelab-manager-skill/issues/100)): `discovery.ignore_unmanaged` takes `{ip, name, mac}` (`site`
  optional). The drift report lists them as known devices and recognises one by MAC at a new DHCP address;
  OVERVIEW.md shows them under Network devices instead of "Other scanned addresses".
  `routeros_audit.py --leases` reads the routers' DHCP leases and ARP table and proposes names for unknown scanned
  addresses (lease comment, else host-name, reduced to plain characters) with the `config_set.py` command to record
  the ones the user confirms; leases and ARP are not kept in routeros.json.
- `docker-containers.yml` and `qnap-containers.yml` record each Compose project's working directory and config files
  ([#102](https://github.com/mhaluska/homelab-manager-skill/issues/102)); OVERVIEW.md has a Compose column. references/discovery.md: a container with Compose labels is
  stopped, started or recreated only through `docker compose` in its working directory, never plain `docker`.
- OVERVIEW.md lists a NAS Docker container's networks as text instead of a Python list.
- Upgrade notes: `containers-compose-paths` (template, edited copies), `containers-compose-refresh` (regenerate).

## 0.34.1 — 2026-11-18
- `ssh_probe.py` no longer uses a Jinja template from the inventory as the SSH user ([#101](https://github.com/mhaluska/homelab-manager-skill/issues/101)): an
  `ansible_user` such as `"{{ homelab_admin_user | default(omit) }}"` (ansible-inventory does not render templates)
  is skipped, so the user comes from `defaults.admin_user`.
- `config_set.py` selects a list entry by name or id ([#99](https://github.com/mhaluska/homelab-manager-skill/issues/99)): `'sites[offsite].proxmox.ca_cert=…'`,
  `'network.vlans[20].gw=…'`, `--delete 'network.vlans[DMZ]'`; an entry that is missing or not unique is refused,
  naming the entries. `check_env.py` prints the exact `config_set.py` command for a site's `ca_cert`.

## 0.34.0 — 2026-11-18
- OVERVIEW.md shows what the repository knows instead of raw scan output:
  - Network devices ([#94](https://github.com/mhaluska/homelab-manager-skill/issues/94)) start from the inventory groups `routeros`, `unifi`, `bmc`, `qnap` and
    `appliances`, enriched from routeros.json (model from routerboard or board-name, RouterOS version, findings),
    unifi.json, bmc.json (model, firmware, health) and updates.json (QNAP model and firmware). A device without data
    says "not audited" / "no data" with the command to run.
  - "Other scanned addresses" ([#96](https://github.com/mhaluska/homelab-manager-skill/issues/96)) lists only addresses nothing names: inventory hosts and their
    `hm_extra_ips`, Proxmox node and guest addresses (every NIC), cluster VIPs, VLAN gateways, RouterOS interface
    addresses, NAS containers and scanned hosts whose hostname is a known host's are left out (and counted). New Name
    column; OS is the best nmap match with its accuracy instead of a Python list.
  - Health ([#95](https://github.com/mhaluska/homelab-manager-skill/issues/95)) always lists Proxmox nodes and critical hosts (kernel, when checked, "up to date"), marks
    update data a week older than the newest check as stale, names inventory hosts without update data (not checked
    yet / not covered by `check-updates.yml`), and adds BMC health, RouterOS updates available and a one-line drift
    summary.
  - Guests ([#97](https://github.com/mhaluska/homelab-manager-skill/issues/97)): VLAN and IP come from the same NIC (netN in numeric order, preferring the NIC holding the
    inventory `ansible_host`); QNAP Container Station containers (qnap-containers.json) under Containers; a long
    list of ranges is a count; backup jobs show their comment (or "job N" for a generated id) and a guest count; the
    node table has PVE version, kernel and addresses.
  - The site map ([#93](https://github.com/mhaluska/homelab-manager-skill/issues/93)) groups VLANs under their gateway (`network.vlans[].gw`) in columns of five, joins
    devices to their VLAN by address and folds VLANs without guests, addresses or devices into one node: roughly as
    wide as tall instead of one long strip.
- `proxmox_inventory.py` records each node's Proxmox VE version and kernel and each backup job's comment, and a plain
  refresh keeps the guests' reported addresses along with their config; it dropped them before ([#97](https://github.com/mhaluska/homelab-manager-skill/issues/97)).
- `pve_node_plan.py` lists the node's local LVM-thin storages with the guests that stop on them and the node's
  uptime; `patch-proxmox-node.yml` refuses a pool with a health flag set or metadata 90 % used before stopping
  anything, and `-e thin_check=true` runs `thin_check` on a metadata snapshot of each active pool ([#91](https://github.com/mhaluska/homelab-manager-skill/issues/91)).
  references/patching.md "LVM-thin pools".
- `drift_report.py --stale` also reports a stale OVERVIEW.md ([#89](https://github.com/mhaluska/homelab-manager-skill/issues/89)).
- `routeros_audit.py`: an open connection to a service (a dynamic `/ip service` row) no longer counts as a second
  enabled service, so a plain-text finding is not reported twice.
- Upgrade notes: `patch-proxmox-node-lvm-thin` (template, edited copies), `inventory-node-versions` (regenerate).

## 0.33.1 — 2026-11-18
- `patch-proxmox-node.yml` no longer leaves a node's guests stopped ([#90](https://github.com/mhaluska/homelab-manager-skill/issues/90)): "Nothing runs on the node any
  more" polls `/cluster/resources` (12 × 10 s; pvestatd lags ~10 s behind a shutdown) and shares a rescue with the
  shutdowns. If either fails, the stopped guests are started again in startup order, HA maintenance is turned off
  and the run stops before the reboot, naming what still runs.
- `check-updates.yml -e target=X` keeps every play to X ([#92](https://github.com/mhaluska/homelab-manager-skill/issues/92)): the Linux play skips windows, appliances and qnap
  hosts in X; the Windows and QNAP plays run only on X's windows/qnap hosts unless `windows_target` /
  `qnap_target` are given. A single-host check no longer contacts every NAS.
- Upgrade note (template, edited copies): `patch-proxmox-node-empty-rescue`.

## 0.33.0 — 2026-11-18
- Overview page ([#87](https://github.com/mhaluska/homelab-manager-skill/issues/87)): `overview.py` writes `OVERVIEW.md` in the repository root, one readable page
  about the whole homelab from what the repo already holds (homelab.yaml, `discovery/*.json`, the managed
  inventory). Per site: a Mermaid map (routers, VLANs, Proxmox nodes with guest counts per VLAN, UniFi devices),
  VLANs with addresses used, nodes, storage (⚠ from 80 % full), guests (VLAN, IP, autostart, HA, tags), backup jobs
  and guests in none, network devices and other scanned addresses; with several sites a sites diagram first. Then
  containers, Ansible groups, clusters and critical hosts, health (pending updates, reboots, RouterOS findings,
  capacity and backup warnings, links to drift.md, guest-map.md and the latest security audit) and when each source
  was collected. Deterministic output (no "generated at" time); `--check` exits 1 when stale. Untrusted names are
  escaped for Markdown and Mermaid. New `overview.redact` in homelab.yaml masks addresses, MACs, the domain and the
  Proxmox hosts for a shared or public repo. The operating loop (step 9) regenerates it with every change.
  references/discovery.md "Overview page".
- Upgrade note (opt-in): `overview-md`.

## 0.32.0 — 2026-11-18
- Ubuntu release upgrade ([#88](https://github.com/mhaluska/homelab-manager-skill/issues/88)): `playbooks/dist-upgrade-ubuntu.yml -e target=<host>
  -e target_release=<codename>`, one release per run, one host at a time. `target_release` must be the release
  `do-release-upgrade -c` offers with `Prompt=lts` (the next LTS, from its first point release;
  `allow_non_lts=true`: `Prompt=normal`). With `--check` it is a read-only pre-flight (Ubuntu only, not a Proxmox
  node, free space, the current release patched, `dpkg --audit`, held packages, `sshd -t`, the offered release).
  The upgrade (the guard asks) sets the prompt and checks the offer (both put back on a mismatch), snapshots,
  backs up the configuration and the installed package list, and runs `do-release-upgrade -f
  DistUpgradeViewNonInteractive` in a transient systemd unit (no second sshd on port 1022, no `screen`). There is
  no reliable dry run, so a removed package matching `autoremove_protect` stops the run before the reboot. Then
  `sshd -t`, the reboot, the new release, `health_services` and failed units. references/patching.md "Ubuntu
  release upgrade".
- Upgrade note (opt-in): `dist-upgrade-ubuntu`.

## 0.31.1 — 2026-11-18
- `pve_node_plan.py` refuses a snapshot without guest config before planning ([#85](https://github.com/mhaluska/homelab-manager-skill/issues/85)): it prints only "refresh with
  `proxmox_inventory.py --details`" instead of a table listing every guest as `migrate (shared storage only)`.
  A plain `proxmox_inventory.py` run keeps each guest's config from the previous `--details` snapshot (same VMID
  and type) and stamps it `details_at`; the summary and the plan show its age.
- `patch-proxmox-node.yml` upgrade-only run ([#86](https://github.com/mhaluska/homelab-manager-skill/issues/86)): `migrated`, `ha` and `stopped_and_restored` are empty
  unless the node rebooted; the plan is reported as `planned_migrate`, `planned_ha` and `planned_stop`.

## 0.31.0 — 2026-11-18
- Debian release upgrade ([#84](https://github.com/mhaluska/homelab-manager-skill/issues/84)): `playbooks/dist-upgrade-debian.yml -e target=<host>
  -e target_release=<next codename>`, one release per run, one host at a time. With `--check` it is a read-only
  pre-flight (next release only, Debian only, not a Proxmox node, free space, the current release patched,
  `dpkg --audit`, held packages, `sshd -t`, foreign APT sources and pin files). The upgrade (the guard asks)
  snapshots the guest, backs up the APT/SSH/PAM/SSSD/Kerberos/sudo configuration, rewrites the Debian sources
  (`tasks/debian-sources.sh`; `foreign_sources=disable|keep`), stops before anything changes if the upgrade would
  remove a package matching `autoremove_protect`, runs `upgrade --without-new-pkgs` and `full-upgrade
  --force-confold` in a transient systemd unit that survives an sshd restart, checks `sshd -t` before the reboot,
  then the new release, `health_services` and failed units. Ubuntu is not covered. references/patching.md
  "Debian release upgrade".
- RouterOS management access ([#80](https://github.com/mhaluska/homelab-manager-skill/issues/80)): `routeros_audit.py` flags `ssh`, `winbox`, `www-ssl` and `api-ssl`
  without an address limit, and the MAC server, MAC Winbox or neighbour discovery on all interfaces, with the
  command that fixes it. New `playbooks/routeros-restrict-management.yml` (RouterOS 7) limits the services to the
  new `network.management_ranges` (homelab.yaml) and MAC/discovery to `routeros_management_interface_list` (per
  device), each part behind its own switch. It runs `--check` first and applies only with
  `-e homelab_read_only=false`. It refuses when its own SSH session comes from outside the ranges, so it can't
  lock Ansible out, and it reads the state back afterwards.
- QNAP NAS ([#81](https://github.com/mhaluska/homelab-manager-skill/issues/81)): `check-updates.yml` also covers the `qnap` group (raw only, reads files): the installed
  QTS / QuTS hero firmware with the time QTS last checked for a new one, and each installed app with the newest
  version for this platform in App Center's catalogue as QTS cached it, when that is newer (`pending`). The
  available firmware version stays in the QTS UI (QNAP's public feed is outdated); nothing asks QNAP's servers.
- Upgrade notes (opt-in): `dist-upgrade-debian`, `routeros-restrict-management`, `qnap-update-report`.

## 0.30.1 — 2026-11-18
- `ssh_probe.py <ip>` without `--site` files each address under its own site ([#82](https://github.com/mhaluska/homelab-manager-skill/issues/82)): its inventory host's
  `site_<name>` group, else the site whose `ranges` hold it, else the default site; a range goes to the site holding
  its first address. It logs in as `--user`, else the inventory host's `ansible_user`, else `defaults.admin_user`.
  Before, a host of another site was probed as the default user and merged into the default site's part.
- `init_repo.py --sync-managed` drops the redundant `"site"` key the 0.29.0 move left inside a site's part of
  `discovery/network.json` (the next probe or scan of that site dropped it, as an unexpected diff).
- `pve_snapshot.py <guest>` without `--site` uses the site of the guest's inventory `site_<name>` group (else of its
  `ansible_host`) instead of reporting "not a Proxmox guest" on the default site ([#83](https://github.com/mhaluska/homelab-manager-skill/issues/83)). VMIDs still use the
  default site; guests of different sites are refused.

## 0.30.0 — 2026-11-18
- RouterOS remediation ([#79](https://github.com/mhaluska/homelab-manager-skill/issues/79)): `playbooks/routeros-disable-services.yml` disables the plain-text IP
  services `routeros_audit.py` flags (`routeros_disable_services`, default `api`, `www`; never `ssh`). Run it with
  `--check` first. It changes nothing unless run with `-e homelab_read_only=false`, and it reads the services
  again afterwards. The audit report prints the command for each device in the inventory. `requirements.yml`
  gains `ansible.netcommon` and `community.routeros`.
- Guard: a playbook run with `homelab_read_only=false` asks, unless it is in `--check` mode.
- QNAP NAS ([#78](https://github.com/mhaluska/homelab-manager-skill/issues/78)): a `qnap` group (`group_vars/qnap.yml`, raw only) and the read-only
  `playbooks/qnap-containers.yml`. It lists Container Station's LXD instances and Docker containers into
  `discovery/qnap-containers.json` (the `containers.json` layout), so the drift report lists their addresses as
  containers.
- Upgrade notes (opt-in): `routeros-disable-services`, `qnap-containers`.

## 0.29.1 — 2026-11-18
- `init_repo.py --sync-managed` no longer says "has local edits, so --sync-managed did not replace it" about a
  file the same run replaces ([#76](https://github.com/mhaluska/homelab-manager-skill/issues/76)). A note about several files stays a suggestion while an edited one is
  left and names only those: `host-files-site-tag` now checks `check-updates.yml`, `docker-containers.yml` and
  `bmc-info.yml`, not only the first. Upgrade notes get an optional `edited` sentence, and `file_lacks` takes a
  list of `[path, text]` pairs.
- UniFi controllers without API keys ([#77](https://github.com/mhaluska/homelab-manager-skill/issues/77)): `unifi-info.yml` takes `unifi_auth: login` (in
  `group_vars/unifi.yml`) for a self-hosted UniFi Network application with no Integrations page. It reads the
  classic API with a read-only local admin (`secrets.unifi`, kind `user_password`, env `UNIFI`;
  `unifi_controller_url`) and logs out at the end. It writes the same per-site part of `discovery/unifi.json`,
  with only the device fields the Integration API reports (no device keys). `api_key` stays the default.
- `unifi-info.yml` no longer fails on its first run, before `discovery/unifi.json` exists. `bmc-info.yml` no
  longer stops at a Redfish sensor without `Status`.
- Guard: write requests to the classic UniFi API (`/api/s/<site>/cmd|rest|set|upd|group`) ask, like
  Integration API writes.
- Upgrade notes: `unifi-per-site` keeps a classic-login copy on `unifi_auth: login` instead of an API key the
  controller can't create; `unifi-login-mode` offers the template to repos that adapted their own copy.

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
