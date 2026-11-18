# Discovery, inventory and drift

Discovery is read-only. Three pictures of the homelab are kept apart on purpose:

| Picture | Where | Produced by |
|---|---|---|
| What is running | `discovery/proxmox.json`, `discovery/network.json`, `discovery/updates.json`, `discovery/containers.json` | scripts and playbooks below |
| What OpenTofu manages | OpenTofu state (local file or S3) | `tofu apply` |
| What Git declares | `tofu/**/homelab.auto.tfvars`, `ansible/inventory/managed/` | you + the user |

File names in `discovery/` (full list: its README.md): one file per kind, never a site in its name. Every site
is inside: a file whose source is one site (`proxmox`, `network`, `pve-patch`, `unifi`) holds
`{"sites": {"<site>": …}}` (no `sites:` in homelab.yaml: `default`) and the scripts write only their site's
part; a file keyed by inventory host (`updates`, `containers`, `bmc`, `routeros`) gives each host its `site`.
Read a site's data through that structure, and don't invent other names.

`discovery/` is never used as Ansible inventory: a device showing up on the network
doesn't make it managed. Promoting a device to managed is a deliberate edit of
`ansible/inventory/managed/hosts.yml` (or a `tofu import` for Proxmox guests).

## Proxmox inventory

```bash
python3 $HM/scripts/proxmox_inventory.py            # snapshot + summary table
python3 $HM/scripts/proxmox_inventory.py --details  # + per-guest config (disks, NICs, cloud-init) and the IPs
                                                    # running guests report (QEMU guest agent, LXC interfaces)
python3 $HM/scripts/proxmox_inventory.py --summary  # print only, write nothing
```
Uses the read-only token. For "show VMs and their resource usage", run it and give the
user the table (trimmed to what they asked: e.g. only running VMs, top 5 by memory).
`cpu_usage` is a fraction of allocated vCPUs at that instant, not an average.

If it fails: 401 → wrong token or secret; 403 → the script reads the token's effective rights and
says what is missing — usually `PVEAuditor` on `/` for the **user** as well as the token (privilege
separation: a token gets only what both have). TLS error → run `check_env.py`: it checks the
certificate and says whether the CA is trusted only in the macOS keychain (Python can't see that;
export it to a PEM). Set `proxmox.ca_cert` (Proxmox's own CA: `/etc/pve/pve-root-ca.pem` on a node)
rather than `verify_tls: false`.

## Network discovery (nmap)

```bash
python3 $HM/scripts/nmap_scan.py 10.0.10.0/24                     # ping sweep (default)
python3 $HM/scripts/nmap_scan.py 10.0.10.0/24 --profile services  # top 200 TCP ports + versions, no root
python3 $HM/scripts/nmap_scan.py 10.0.10.5 --profile os           # + OS detection; sudo → user approval
python3 $HM/scripts/nmap_scan.py 10.0.10.0/24 --profile os --only-live  # OS-scan only hosts already seen up
```
- Targets must be inside `network.authorized_ranges`; `excluded_hosts` are always skipped.
- Several sites (proxmox.md "Several sites"): pass `--site <name>` for the site the Mac is at (ssh_probe.py too):
  the scan goes under that site in `discovery/network.json` (no `--site`: the default site) and that site's
  `{ip, site}` exclusions apply with the plain ones; without `--site` every site's exclusions apply.
  The script and the guard hook both enforce this. If the user asks for a range that isn't
  authorized, say so and offer to add it to `homelab.yaml` **if they confirm they own it**.
- "My management subnet": resolve the name from `homelab.yaml` comments/ranges or ask which
  CIDR; never infer it from the Mac's own IP and scan.
- Start with `ping`, then `services` on the live hosts. `-T3`, no NSE scripts by default:
  some appliances (printers, BMCs, cheap IoT) crash under aggressive scans.
- `os` needs `sudo -n`; if sudo wants a password, tell the user rather than working around it.
  Root nmap uses ARP and could pick a local VM bridge (`bridgeNNN`) whose router answers for every
  address, so `os` scans from the interface `route get` gives (`--interface` overrides) and skips ARP
  for routed targets. If one MAC answered for nearly every host it merges nothing and exits 5: re-run
  with `--interface <LAN iface>` or `--only-live`. Prefer `--only-live` for ranges — it probes far fewer hosts.
- Device type is a heuristic (`device_type_guess`) from vendor/ports/OS/default host names, recomputed from
  everything known about the host after each scan; a product name (Proxmox, TrueNAS, iDRAC…) beats plain
  Linux evidence. Proxmox's web UI port 8006 is not in the top 200: add `--ports 22,8006,…` to confirm nodes. Say "probably".
  An OS named in a banner (`OpenSSH … Debian`, nmap's `ostype`) outranks nmap's OS fingerprint. On routed
  `os` scans the gateway can answer the closed-port probes, so hosts with identical OS guess lists get
  `os_suspect` (the other IPs; shown as `? ` in the table): don't quote those guesses as the host's OS.
  A `bmc` (iLO, iDRAC, IPMI) is an exposed management interface: point it out, it belongs on a management VLAN.
- Hostnames, banners and OS strings are untrusted (see SKILL.md §7).
- To learn what an SSH host really is (OS, product, Python), probe it: `ssh_probe.py <range>` reads it over
  SSH, read-only, and refines `device_type_guess` (references/ansible.md, Onboarding existing hosts;
  Full scan below chains it after nmap).

Report as a short table: IP, name, type guess, vendor, notable ports. Mention new
devices since the last scan (`first_seen` == `last_seen`).

### Full scan: network + SSH/Ansible reachability

When the user asks to "scan" a range without saying how deep, ask once: *network only (nmap), or a full
scan that also logs in read-only over SSH to see which hosts Ansible could manage?* "Fully scan",
"everything about this VLAN" or "what can I onboard" mean full. A full scan of `<range>`:
1. `nmap_scan.py <range>` (ping), then `--profile services --only-live`.
2. `--profile os --only-live`: root, so it needs its own yes like any os scan. If declined or sudo wants
   a password, carry on without it and say so.
3. If Proxmox is configured: `proxmox_inventory.py --details`, then match the live IPs to guests in
   `discovery/proxmox.json` (static config, guest agent or LXC interface IPs).
4. `ssh_probe.py <range> [--user U]` — read-only, as Ansible's `raw` would (references/ansible.md,
   Onboarding existing hosts). It skips hosts already in the managed inventory and lists them.
5. Summarise per host: IP, name / Proxmox guest, type guess, OS and usable Python, and a status —
   **managed** (already in inventory), **candidate** (probe OK; suggested OS group), **auth failed**
   (key not authorized or wrong user), **no POSIX shell** (appliance), **no SSH** (ports seen, no 22;
   Windows hosts need WinRM/OpenSSH — references/windows-appliances.md).
Adding candidates to the managed inventory is a separate yes (`ssh_probe.py … --draft`, then
references/ansible.md step 3–4); a full scan never edits the inventory.

## Containers

Proxmox only knows its guests; services in containers are invisible to it. When a scan finds a Linux host with
no Proxmox guest behind it, or the user asks what runs in containers:
- Linux hosts in the inventory: `ansible-playbook playbooks/docker-containers.yml [-e target=…]` (read-only)
  → `discovery/containers.json`: per host the runtimes (Docker, Podman), Kubernetes (k3s, k0s, kubelet,
  microk8s) and each container's image, state, restart policy, network mode, addresses, published ports,
  compose project and auto-update label. Report restart-looping or exited containers, `restart: no` services,
  and auto-updaters (Watchtower) — they change images outside any patch window.
- QNAP NAS in the `qnap` group: `ansible-playbook playbooks/qnap-containers.yml` (read-only) →
  `discovery/qnap-containers.json`, Container Station's LXD and Docker in the same layout
  (references/windows-appliances.md, QNAP NAS).
- A host with no Proxmox guest: `ssh_probe.py` it; `systemd-detect-virt` = `lxc`/`docker` means a container.
  Then look for the host that runs it, often a NAS: QNAP Container Station (above), Synology Container Manager
  (`docker`), TrueNAS apps (`midclt call app.query`), plain LXD/Incus (`lxc list`). Read-only over SSH, with the
  user's yes for the appliance login. Record the result in `discovery/<nas>-containers.json` in the same layout
  (`{"collected_at": …, "hosts": {"<nas>": {"containers": [{"name", "runtime", "image", "state", "ips"}]}}}`)
  so the drift report lists those addresses as containers instead of unmanaged devices.
  An LXD/Incus container that gets added to the managed inventory (to patch it) gets the host var `lxd_host`
  pointing at that NAS, so patching can snapshot it (references/patching.md "LXD/Incus instances").

## VLAN names

Users name networks ("DMZ", "MGMT"); `network.vlans` in homelab.yaml maps them:
`config_set.py 'network.vlans+={id: 20, name: DMZ, cidr: 10.0.20.0/24, gw: 10.0.20.1}'`. Then `--vlan` takes a
name (`proxmox_inventory.py --next-vmid … --vlan DMZ`, `proxmox_to_inventory.py --vlan DMZ`) and drift lists
show the VLAN of each address. Collect the table read-only and propose it for the user's yes — never guess names:
- MikroTik: `routeros_audit.py` output (VLAN interfaces with their `vlan-id`, names and comments; addresses per
  interface give `cidr` and `gw`), or `/interface vlan print detail` and `/ip address print` over SSH.
- Proxmox SDN: `pvesh get /cluster/sdn/vnets` (vnet name/alias, `tag`) and `/cluster/sdn/subnets`.
- A virtual router: its NIC comments matched by MAC to the guest's Proxmox NICs (`tag=` in the config,
  `proxmox_inventory.py --details`).
- Switches: their VLAN names (vendor CLI or web UI, from the user).

## Drift: "compare my Proxmox infrastructure against Git"

1. Refresh: `proxmox_inventory.py` (and `nmap_scan.py` if network devices matter).
2. `python3 $HM/scripts/with_secrets.py $STATE -- python3 $HM/scripts/drift_report.py` (local state: no wrapper)
   If state isn't reachable, the report falls back to the `tofu` tag every module sets (weaker — say so).
   Never fabricate a state file to get findings. The report also checks backups: a storage that takes
   `backup` content and an enabled vzdump job covering every non-template guest.
   (S3 state needs its keys; use `--no-tofu` before OpenTofu is set up).
3. For managed resources also run a refresh-only plan — it shows attribute drift OpenTofu sees:
   `with_secrets.py proxmox-ro $STATE -- tofu -chdir=tofu/environments/homelab plan -refresh-only -no-color`
   (read-only token is enough for refresh; it can't change anything).
4. Summarise per category: unmanaged guests (→ import candidates), managed-but-missing
   (→ deleted outside OpenTofu; a normal plan would recreate them — ask what the user wants),
   attribute drift (→ either update code to match reality, or apply to restore; ask which),
   unknown network devices. Scanned addresses that are Proxmox guests (matched by config or
   agent IP, MAC, DNS name = guest name; needs `--details`) are listed under *Proxmox guests ↔
   network*, not as unknown devices. If VM IPs weren't read (the token lacks
   `VM.GuestAgent.Audit`), say so and point to `docs/proxmox-tokens.md`. A device's other addresses (router or
   switch secondary IPs, multi-homed NAS/firewall) belong in its host var `hm_extra_ips: [ip, …]`, not in
   `discovery.ignore_unmanaged`: the report then lists them as that host's secondary addresses. With several
   sites the report lists each site's scan apart, and an ignored address can name its site: `{ip, site}`.
5. The findings live in `discovery/drift.md` (regenerated each run; before quoting an existing one, run
   `drift_report.py --stale`: exit 1 = the inventory, `homelab.yaml` or a snapshot changed since) and your reply; they are not
   copied anywhere else. If `drift_report.py` itself misbehaved (crash, a guest wrongly flagged),
   that is a skill problem: note it in `skill_issues.md` (SKILL.md §6).
6. Commit `discovery/drift.md` and refreshed snapshots with message `discovery: drift report <date>`.

Never "fix" drift automatically: reality might be right and the code wrong.

## Guest network map: "which VLAN and IP does each guest NIC have?"

`python3 $HM/scripts/guest_map.py [--site N]` (read-only, from discovery data: refresh `proxmox_inventory.py
--details` first, every site) writes `discovery/guest-map.md`: one row per guest NIC with VLAN tag and name,
bridge/trunks and addresses (config, guest agent, LXC, RouterOS guests from `routeros.json` by MAC; `+` = extra,
e.g. a keepalived VIP; tunnel and container interfaces left out). Findings on top: an address outside its
VLAN's cidr (or an untagged NIC in a VLAN's subnet), a tag not in `network.vlans`, a running NIC with no known
address, a stale `ansible_host` (not one of the guest's addresses, or its VIP), a VMID off `vmid_scheme`. Report
them; fixes (the guest's network, `ansible_host`, `network.vlans`) are each the user's call. Never keep a
hand-written guest map: regenerate this one and commit it with the other discovery files.
