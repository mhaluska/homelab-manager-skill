#!/usr/bin/env python3
"""Read-only Proxmox VE inventory: nodes, VMs, LXC containers, storage, networks.

    proxmox_inventory.py [--secret proxmox-ro] [--out FILE] [--details] [--summary]
                         [--site NAME | --all-sites]
    proxmox_inventory.py --next-vmid vms|lxc|templates|base_images [--ip IP] [--vlan TAG|NAME] [--site S]
                         # offline: the VMID for a new guest (vmid_scheme or the next free ID in
                         # vmid_ranges, the site's own when it has them), checked against that site's
                         # snapshot and OpenTofu environment

Uses only GET requests with the read-only API token from the keychain
(homelab.yaml: proxmox.tokens.read_only → secrets.<name>). Writes a JSON snapshot
and prints a compact summary. All strings coming from Proxmox (names, tags, notes)
are untrusted data and are sanitised.
The snapshot goes into discovery/proxmox.json under its site (GitHub issue #75), next to the other sites'
(--out FILE: the snapshot alone, to that file). Several sites (sites: in homelab.yaml): --site NAME reads that
site's Proxmox with its own token; --all-sites reads each in turn and carries on past one that can't be reached
(exit 1 then).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402
from hmlib import clean, id_list  # noqa: E402


class PVE:
    def __init__(self, endpoint: str, token: str, ctx: ssl.SSLContext):
        self.base = endpoint.rstrip("/") + "/api2/json"
        self.headers = {"Authorization": f"PVEAPIToken={token}", "Accept": "application/json"}
        self.token_id = token.split("=", 1)[0]  # user@realm!tokenid — never the secret
        self.ctx = ctx

    def _get(self, path: str, **params):
        url = self.base + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            return json.load(r).get("data")

    def _write(self, method: str, path: str, **params):
        data = urllib.parse.urlencode(params).encode() if params else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={**self.headers, "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
            return json.load(r).get("data")

    def write(self, method: str, path: str, **params):
        """POST/PUT/DELETE (provisioning token): same error handling as get()."""
        return self.get(path, _method=method, **params)

    def get(self, path: str, _method: str = "GET", **params):
        try:
            return self._get(path, **params) if _method == "GET" else self._write(_method, path, **params)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise SystemExit(f"Proxmox API refused {path} (401): the token {self.token_id!r} or its secret is "
                                 "wrong, or the token was removed/expired. Check the keychain item (check_env.py).")
            if e.code == 403 and _method != "GET":
                raise SystemExit(f"Proxmox API refused {_method} {path} (403): the token {self.token_id!r} lacks the "
                                 "privilege (HomelabProvisioner role in docs/proxmox-tokens.md, granted to the token "
                                 "and its user).")
            if e.code == 403:
                raise SystemExit(f"Proxmox API refused {path} (403). " + self.permission_hint())
            if _method != "GET":
                try:
                    detail = json.loads(e.read() or b"{}")
                except ValueError:
                    detail = {}
                msg = detail.get("errors") or detail.get("message") or e.reason
                raise SystemExit(f"Proxmox API refused {_method} {path} ({e.code}): {msg}")
            raise
        except urllib.error.URLError as e:
            hint = (" — run check_env.py: it tells whether the CA is trusted only in the macOS keychain"
                    if isinstance(e.reason, ssl.SSLCertVerificationError) else "")
            raise SystemExit(f"Cannot reach Proxmox at {self.base}: {e.reason}{hint}")

    def permission_hint(self) -> str:
        """Explain a 403 using the token's effective permissions (GET /access/permissions needs no privilege)."""
        user = self.token_id.split("!", 1)[0]
        need = "The read-only token needs PVEAuditor on /"
        try:
            perms = self._get("/access/permissions")
        except (urllib.error.URLError, ValueError, OSError):
            perms = None
        if perms == {} or (isinstance(perms, dict) and not any(perms.values())):
            return (f"The token {self.token_id!r} has no effective permissions at all. With privilege separation a "
                    f"token gets only what both it and its user have, so grant the role to the user too: "
                    f"pveum acl modify / --users {user} --roles PVEAuditor (see docs/proxmox-tokens.md).")
        if isinstance(perms, dict):
            paths = ", ".join(sorted(perms)[:5])
            return (f"{need}; it has permissions only on: {paths}. Remember the user {user} needs the role too "
                    f"(privilege separation). Check with: pveum user token permissions {user} "
                    f"{self.token_id.split('!', 1)[-1]}")
        return f"{need}, granted to both the token and its user {user} (privilege separation)."


AGENT_PRIV = "VM.GuestAgent.Audit (Proxmox VE 9; VM.Monitor on 8.x)"


def agent_enabled(conf: dict) -> bool:
    v = str(conf.get("agent") or "0")
    return v.split(",")[0] in ("1", "enabled=1") or "enabled=1" in v


def usable_ip(ip: str) -> bool:
    ip = ip.split("/")[0].lower()
    return bool(ip) and not ip.startswith(("127.", "169.254.", "fe80:")) and ip != "::1"


def guest_ips(pve: "PVE", g: dict, kind: str, conf: dict, sources: dict) -> list[dict]:
    """Addresses a running guest reports: QEMU guest agent for VMs (agent=1), /interfaces for LXC.
    Read-only; a 403 is recorded once in `sources` with the missing privilege instead of failing."""
    out = []
    if kind == "qemu":
        if not agent_enabled(conf) or sources["agent"].startswith("forbidden"):
            return out
        try:
            data = pve._get(f"/nodes/{g['node']}/qemu/{g['vmid']}/agent/network-get-interfaces") or {}
        except urllib.error.HTTPError as e:
            if e.code == 403:
                sources["agent"] = (f"forbidden: the read-only token (and its user) need {AGENT_PRIV} on / "
                                    "(next to PVEAuditor) to read VM IPs from the guest agent")
            return out  # 500: agent not running in the guest
        except (urllib.error.URLError, OSError, ValueError):
            return out
        sources["agent"] = "ok"
        for nic in data.get("result") or []:
            if nic.get("name") == "lo":
                continue
            for a in nic.get("ip-addresses") or []:
                if usable_ip(str(a.get("ip-address") or "")):
                    out.append({"iface": clean(nic.get("name")), "mac": clean(nic.get("hardware-address")),
                                "ip": clean(a.get("ip-address")), "source": "agent"})
    else:
        # Proxmox reports one address per family and interface, so a second one (e.g. a keepalived VIP) can
        # hide the container's own: its configured ip= is listed too, and other reported addresses on that
        # interface are marked extra (GitHub issue #61)
        configured: dict[str, set[str]] = {}
        for k in sorted(conf, key=lambda k: int(k[3:]) if k[3:].isdigit() else 0):
            if not re.fullmatch(r"net\d+", k):
                continue
            opts = dict(o.split("=", 1) for o in str(conf[k]).split(",") if "=" in o)
            for key in ("ip", "ip6"):
                ip = opts.get(key, "").split("/")[0]
                if re.fullmatch(r"[0-9A-Fa-f.:]+", ip) and usable_ip(ip):  # not dhcp / manual / auto
                    configured.setdefault(opts.get("name", ""), set()).add(ip.lower())
                    out.append({"iface": clean(opts.get("name")), "mac": clean((opts.get("hwaddr") or "").lower()),
                                "ip": clean(ip), "source": "config"})
        try:
            data = pve._get(f"/nodes/{g['node']}/lxc/{g['vmid']}/interfaces") or []
        except (urllib.error.URLError, OSError, ValueError):
            return out
        sources["lxc"] = "ok"
        for nic in data:
            if nic.get("name") == "lo":
                continue
            name = str(nic.get("name") or "")
            for key in ("inet", "inet6"):
                val = nic.get(key) or ""
                for ip in (val if isinstance(val, list) else str(val).split()):
                    ip = str(ip).split("/")[0]
                    if not usable_ip(ip) or ip.lower() in configured.get(name, set()):
                        continue
                    out.append({"iface": clean(name), "mac": clean(nic.get("hwaddr")), "ip": clean(ip), "source": "lxc",
                                **({"extra": True} if configured.get(name) else {})})
    return out


def no_guests_hint(pve: "PVE") -> str | None:
    """Why the token may see no guests at all: no VM.Audit, typically because an ACL on a narrower path
    (/vms, /vms/<id>, /pool/…) replaced the PVEAuditor role inherited from / (GitHub issue #14)."""
    try:
        perms = pve._get("/access/permissions")
    except (urllib.error.URLError, ValueError, OSError):
        return None
    if not isinstance(perms, dict):
        return None
    narrow = sorted(p for p, privs in perms.items()
                    if p.startswith("/vms") and isinstance(privs, dict) and "VM.Audit" not in privs)
    if narrow:
        return (f"no guests visible: the token's ACL on {', '.join(narrow[:3])} lacks VM.Audit. An ACL on a narrower "
                "path replaces the role inherited from /, so grant extra roles on / next to PVEAuditor instead "
                "(docs/proxmox-tokens.md), or remove that ACL with pveum acl delete")
    if "VM.Audit" not in (perms.get("/") or {}):
        return "no guests visible: the token has no VM.Audit on / (PVEAuditor on / for both the user and the token)"
    return None


CONFIG_PREFIXES = ("net", "scsi", "virtio", "sata", "ide", "rootfs", "mp", "ipconfig",  # network, disks
                   "efidisk", "tpmstate", "unused", "hostpci", "usb", "dev")       # + what pins a guest to its node
CONFIG_KEYS = {"agent", "ostype", "ciuser", "sshkeys", "boot", "machine", "bios", "cores", "sockets", "memory",
               "onboot", "startup", "description"}


def guest_config(conf: dict) -> dict:
    """The parts of a guest config the snapshot keeps: network, disks, passthrough devices, boot settings."""
    out = {k: clean(v, 300) for k, v in conf.items()
           if k.startswith(CONFIG_PREFIXES) or k in CONFIG_KEYS}
    if "description" in out:
        out["description"] = "[untrusted] " + out["description"]
    return out


def gib(b):
    return round((b or 0) / 1024**3, 1)


def collect(pve: PVE, details: bool) -> dict:
    version = pve.get("/version") or {}
    status = pve.get("/cluster/status") or []
    cluster = next((s for s in status if s.get("type") == "cluster"), None)
    resources = pve.get("/cluster/resources") or []

    nodes, guests, storage = [], [], []
    for r in resources:
        t = r.get("type")
        if t == "node":
            nodes.append({"node": clean(r.get("node")), "status": r.get("status"), "cpus": r.get("maxcpu"),
                          "cpu_usage": round(r.get("cpu") or 0, 3), "mem_gib": gib(r.get("maxmem")),
                          "mem_used_gib": gib(r.get("mem")), "uptime_s": r.get("uptime")})
        elif t in ("qemu", "lxc"):
            guests.append({"type": "vm" if t == "qemu" else "lxc", "vmid": r.get("vmid"), "name": clean(r.get("name")),
                           "node": clean(r.get("node")), "status": r.get("status"), "template": bool(r.get("template")),
                           "cpus": r.get("maxcpu"), "cpu_usage": round(r.get("cpu") or 0, 3),
                           "mem_gib": gib(r.get("maxmem")), "mem_used_gib": gib(r.get("mem")),
                           "disk_gib": gib(r.get("maxdisk")), "tags": clean(r.get("tags")), "pool": clean(r.get("pool")),
                           "hastate": r.get("hastate"), "uptime_s": r.get("uptime")})
        elif t == "storage":
            storage.append({"storage": clean(r.get("storage")), "node": clean(r.get("node")), "type": r.get("plugintype"),
                            "shared": bool(r.get("shared")), "content": r.get("content"), "status": r.get("status"),
                            "size_gib": gib(r.get("maxdisk")), "used_gib": gib(r.get("disk"))})

    networks = {}
    for n in nodes:
        if n["status"] != "online":
            continue
        try:
            nets = pve.get(f"/nodes/{n['node']}/network") or []
        except SystemExit:
            nets = []
        try:  # GitHub issue #97: the node's own Proxmox VE version and running kernel (Sys.Audit, PVEAuditor)
            ns = pve.get(f"/nodes/{n['node']}/status") or {}
        except SystemExit:
            ns = {}
        n["pveversion"] = clean(ns.get("pveversion"))
        n["kernel"] = clean((ns.get("current-kernel") or {}).get("release") or ns.get("kversion"))
        networks[n["node"]] = [{"iface": clean(x.get("iface")), "type": x.get("type"), "cidr": x.get("cidr"),
                                "gateway": x.get("gateway"), "bridge_ports": clean(x.get("bridge_ports")),
                                "vlan_aware": bool(x.get("bridge_vlan_aware")), "active": bool(x.get("active"))}
                               for x in nets]

    try:  # scheduled vzdump jobs (PVEAuditor can read them); None = could not read
        backup_jobs = [{"id": clean(j.get("id")), "enabled": j.get("enabled", 1) not in (0, "0"),
                        "schedule": clean(j.get("schedule")), "storage": clean(j.get("storage")),
                        "all": bool(j.get("all")), "vmid": id_list(j.get("vmid")), "exclude": id_list(j.get("exclude")),
                        "pool": clean(j.get("pool")), "node": clean(j.get("node")),
                        "comment": clean(j.get("comment"))}
                       for j in (pve.get("/cluster/backup") or [])]
    except SystemExit:
        backup_jobs = None

    ip_sources = {"agent": "not queried", "lxc": "not queried"}
    if details:  # per-guest config: network, disks, cloud-init, agent — still read-only
        for g in guests:
            kind = "qemu" if g["type"] == "vm" else "lxc"
            try:
                conf = pve.get(f"/nodes/{g['node']}/{kind}/{g['vmid']}/config") or {}
            except SystemExit:
                continue
            g["config"] = guest_config(conf)
            if g["status"] == "running":
                g["ips"] = guest_ips(pve, g, kind, conf, ip_sources)

    warnings = [w for w in [None if guests else no_guests_hint(pve)] if w]
    return {"collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "source": "proxmox-api", "version": version.get("version"),
            "cluster": {"name": clean(cluster.get("name")), "nodes": cluster.get("nodes"), "quorate": cluster.get("quorate")}
            if cluster else None,
            "nodes": sorted(nodes, key=lambda x: x["node"] or ""),
            "guests": sorted(guests, key=lambda x: x["vmid"] or 0),
            "storage": sorted(storage, key=lambda x: (x["node"] or "", x["storage"] or "")),
            "networks": networks, "backup_jobs": backup_jobs,
            **({"guest_ip_sources": ip_sources} if details else {}), **({"warnings": warnings} if warnings else {})}


def keep_details(old: dict | None, new: dict) -> dict:
    """A run without --details keeps each guest's config from the previous snapshot (same VMID and type) and
    stamps when it was read (details_at), so a plain refresh doesn't strip what pve_node_plan.py needs."""
    if not old or any("config" in g for g in new.get("guests") or []):
        return new
    configs = {(g.get("vmid"), g.get("type")): g["config"] for g in old.get("guests") or [] if "config" in g}
    if not configs:
        return new
    kept = 0
    for g in new.get("guests") or []:
        conf = configs.get((g.get("vmid"), g.get("type")))
        if conf is not None:
            g["config"] = conf
            kept += 1
    if kept:
        new["details_at"] = old.get("details_at") or old.get("collected_at")
    return new


def used_vmids(cfg: dict, site_name: str | None = None) -> dict[int, str]:
    """{vmid: who} at one site: its Proxmox snapshot and every vm_id / template_vm_id in its OpenTofu environment
    (the default site: every environment that isn't another site's). VMIDs repeat across sites."""
    root = Path(cfg["_root"])
    s = hmlib.site(cfg, site_name)
    used = {}
    try:
        snap = hmlib.site_part(hmlib.proxmox_snapshot_file(root), s) or {}
        for g in snap.get("guests") or []:
            if isinstance(g.get("vmid"), int):
                used[g["vmid"]] = f"{g.get('type')} {g.get('name')} (Proxmox)"
    except (OSError, hmlib.ConfigError):
        pass
    envs = root / "tofu" / "environments"
    other = {x["name"] for x in hmlib.sites(cfg) if not x["default"]}
    dirs = [envs / s["name"]] if not s["default"] else \
        [d for d in sorted(envs.glob("*")) if d.is_dir() and d.name not in other]
    for d in dirs:
        for f in sorted(d.glob("**/*.tfvars")):
            for m in re.finditer(r"^\s*vm_id\s*=\s*(\d+)", f.read_text(errors="replace"), re.M):
                used.setdefault(int(m.group(1)), f"{f.relative_to(root)}")
    return used


def summary(inv: dict, cfg: dict | None = None) -> str:
    lines = [f"Proxmox VE {inv['version']} — " + (f"cluster {inv['cluster']['name']} ({inv['cluster']['nodes']} nodes, "
             f"quorate={bool(inv['cluster']['quorate'])})" if inv["cluster"] else "standalone node")]
    lines.append("\nNodes:")
    for n in inv["nodes"]:
        lines.append(f"  {n['node']:<12} {n['status']:<8} {n['cpus']} CPU ({n['cpu_usage']*100:.0f}%)  "
                     f"{n['mem_used_gib']}/{n['mem_gib']} GiB")
    lines.append("\nGuests:")
    lines.append(f"  {'VMID':>5} {'TYPE':<4} {'NAME':<24} {'NODE':<10} {'STATUS':<8} {'CPU':>4} {'CPU%':>5} {'MEM GiB':>11} {'DISK':>6}")
    for g in inv["guests"]:
        name = (g["name"] or "") + (" [tpl]" if g["template"] else "")
        lines.append(f"  {g['vmid']:>5} {g['type']:<4} {name[:24]:<24} {g['node']:<10} {g['status']:<8} {g['cpus'] or 0:>4} "
                     f"{g['cpu_usage']*100:>4.0f}% {g['mem_used_gib']:>5}/{g['mem_gib']:<5} {g['disk_gib']:>6}")
    lines.append("\nStorage:")
    for s in inv["storage"]:
        pct = (s["used_gib"] / s["size_gib"] * 100) if s["size_gib"] else 0
        lines.append(f"  {s['storage']:<16} {s['node']:<10} {s['type'] or '':<8} {'shared' if s['shared'] else 'local':<6} "
                     f"{s['used_gib']}/{s['size_gib']} GiB ({pct:.0f}%)  [{s['content']}]")
    fit = hmlib.vmid_fit(hmlib.site_config(cfg, inv.get("site")), inv["guests"]) if cfg else None
    if fit:
        lines.append(f"\nVMIDs: {fit}")
    agent = (inv.get("guest_ip_sources") or {}).get("agent", "")
    if agent.startswith("forbidden"):
        lines.append(f"\nGuest agent IPs not read — {agent}.")
    if inv.get("details_at"):
        lines.append(f"\nGuest config kept from the --details run of {inv['details_at']} (refresh with --details).")
    for w in inv.get("warnings") or []:
        lines.append(f"\nWarning: {w}.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", help="secret name (default: proxmox.tokens.read_only)")
    ap.add_argument("--out", help="write the snapshot alone to this file (default: its site in discovery/proxmox.json)")
    ap.add_argument("--details", action="store_true", help="also fetch each guest's config")
    ap.add_argument("--summary", action="store_true", help="print the human summary only, write nothing")
    ap.add_argument("--next-vmid", choices=["vms", "lxc", "templates", "base_images"],
                    help="print the VMID for a new guest of this kind (no API call)")
    ap.add_argument("--site", help="the site to read (sites: in homelab.yaml; default: the default site)")
    ap.add_argument("--all-sites", action="store_true", help="read every site that has a Proxmox")
    ap.add_argument("--ip", help="with --next-vmid: the new guest's static IP (for vmid_scheme)")
    ap.add_argument("--vlan", help="with --next-vmid: the new guest's VLAN tag or name from network.vlans (vmid_scheme)")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        if a.next_vmid:
            s = hmlib.site(cfg, a.site)
            print(hmlib.next_vmid(hmlib.site_config(cfg, a.site), a.next_vmid, used_vmids(cfg, a.site), ip=a.ip,
                                  vlan=hmlib.resolve_vlan(cfg, a.vlan, s["name"])))
            return 0
        if a.all_sites and (a.site or a.out or a.secret):
            ap.error("--all-sites reads every site with its own token and file: no --site, --out or --secret")
        targets = hmlib.proxmox_sites(cfg) if a.all_sites else [hmlib.proxmox_site(cfg, a.site)]
        if not targets:
            raise hmlib.ConfigError("no site has a Proxmox endpoint in homelab.yaml.")
    except hmlib.ConfigError as e:
        print(f"proxmox_inventory: {e}", file=sys.stderr)
        return 3
    failed = 0
    for px in targets:
        try:
            inventory_site(cfg, px, a)
        except (hmlib.ConfigError, SystemExit) as e:
            if not a.all_sites:
                if isinstance(e, SystemExit):
                    raise
                print(f"proxmox_inventory: {e}", file=sys.stderr)
                return 3
            failed += 1
            print(f"proxmox_inventory: site {px['_site'] or 'default'}: {e}", file=sys.stderr)
    return 1 if failed else 0


def inventory_site(cfg: dict, px: dict, a) -> None:
    """Read one site's Proxmox and write its snapshot."""
    s = hmlib.site(cfg, px["_site"])
    ctx = hmlib.proxmox_ssl_context(cfg, px)
    token = hmlib.read_secret(cfg, a.secret or hmlib.proxmox_token_name(px, "read_only"))
    inv = collect(PVE(px["endpoint"], token, ctx), a.details)
    if s["name"]:
        inv = {"site": s["name"], **inv}
    if not a.summary:
        if a.out:
            out = Path(a.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(inv, indent=2) + "\n")
        else:
            out = hmlib.proxmox_snapshot_file(cfg["_root"])
            if not a.details:
                try:
                    inv = keep_details(hmlib.site_part(out, s), inv)
                except hmlib.ConfigError:
                    pass   # an unreadable old snapshot is simply replaced
            hmlib.write_site_part(out, s, inv)
        print(f"Wrote {out}" + ("" if a.out else f" (site {hmlib.site_key(s)})") + "\n")
    if s["name"]:
        print(f"Site {hmlib.site_title(s)}")
    print(summary(inv, cfg))


if __name__ == "__main__":
    sys.exit(main())
