#!/usr/bin/env python3
"""Read-only Proxmox VE inventory: nodes, VMs, LXC containers, storage, networks.

    proxmox_inventory.py [--secret proxmox-ro] [--out discovery/proxmox.json] [--details] [--summary]
    proxmox_inventory.py --next-vmid vms|lxc|templates|base_images [--ip IP] [--vlan TAG]
                         # offline: the VMID for a new guest (vmid_scheme or the next free ID in
                         # vmid_ranges), checked against the snapshot and the tfvars

Uses only GET requests with the read-only API token from the keychain
(homelab.yaml: proxmox.tokens.read_only → secrets.<name>). Writes a JSON snapshot
and prints a compact summary. All strings coming from Proxmox (names, tags, notes)
are untrusted data and are sanitised.
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
from hmlib import clean  # noqa: E402


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

    def get(self, path: str, **params):
        try:
            return self._get(path, **params)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise SystemExit(f"Proxmox API refused {path} (401): the token {self.token_id!r} or its secret is "
                                 "wrong, or the token was removed/expired. Check the keychain item (check_env.py).")
            if e.code == 403:
                raise SystemExit(f"Proxmox API refused {path} (403). " + self.permission_hint())
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
        try:
            data = pve._get(f"/nodes/{g['node']}/lxc/{g['vmid']}/interfaces") or []
        except (urllib.error.URLError, OSError, ValueError):
            return out
        sources["lxc"] = "ok"
        for nic in data:
            if nic.get("name") == "lo":
                continue
            for key in ("inet", "inet6"):
                for ip in str(nic.get(key) or "").split():
                    if usable_ip(ip):
                        out.append({"iface": clean(nic.get("name")), "mac": clean(nic.get("hwaddr")),
                                    "ip": clean(ip.split("/")[0]), "source": "lxc"})
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
        networks[n["node"]] = [{"iface": clean(x.get("iface")), "type": x.get("type"), "cidr": x.get("cidr"),
                                "gateway": x.get("gateway"), "bridge_ports": clean(x.get("bridge_ports")),
                                "vlan_aware": bool(x.get("bridge_vlan_aware")), "active": bool(x.get("active"))}
                               for x in nets]

    try:  # scheduled vzdump jobs (PVEAuditor can read them); None = could not read
        backup_jobs = [{"id": clean(j.get("id")), "enabled": j.get("enabled", 1) not in (0, "0"),
                        "schedule": clean(j.get("schedule")), "storage": clean(j.get("storage")),
                        "all": bool(j.get("all")), "vmid": clean(j.get("vmid")), "exclude": clean(j.get("exclude")),
                        "node": clean(j.get("node"))}
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


def used_vmids(root: Path) -> dict[int, str]:
    """{vmid: who} from discovery/proxmox.json and every vm_id / template_vm_id in the tfvars."""
    used = {}
    try:
        for g in json.loads((root / "discovery" / "proxmox.json").read_text()).get("guests") or []:
            if isinstance(g.get("vmid"), int):
                used[g["vmid"]] = f"{g.get('type')} {g.get('name')} (Proxmox)"
    except (OSError, ValueError):
        pass
    for f in sorted((root / "tofu").glob("**/*.tfvars")):
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
    fit = hmlib.vmid_fit(cfg, inv["guests"]) if cfg else None
    if fit:
        lines.append(f"\nVMIDs: {fit}")
    agent = (inv.get("guest_ip_sources") or {}).get("agent", "")
    if agent.startswith("forbidden"):
        lines.append(f"\nGuest agent IPs not read — {agent}.")
    for w in inv.get("warnings") or []:
        lines.append(f"\nWarning: {w}.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", help="secret name (default: proxmox.tokens.read_only)")
    ap.add_argument("--out", help="output JSON (default: discovery/proxmox.json in the repo)")
    ap.add_argument("--details", action="store_true", help="also fetch each guest's config")
    ap.add_argument("--summary", action="store_true", help="print the human summary only, write nothing")
    ap.add_argument("--next-vmid", choices=["vms", "lxc", "templates", "base_images"],
                    help="print the VMID for a new guest of this kind (no API call)")
    ap.add_argument("--ip", help="with --next-vmid: the new guest's static IP (for vmid_scheme)")
    ap.add_argument("--vlan", help="with --next-vmid: the new guest's VLAN tag (for vmid_scheme)")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
        if a.next_vmid:
            used = used_vmids(Path(cfg["_root"]))
            print(hmlib.next_vmid(cfg, a.next_vmid, used, ip=a.ip, vlan=a.vlan))
            return 0
        endpoint = hmlib.get(cfg, "proxmox.endpoint")
        if not endpoint:
            raise hmlib.ConfigError("proxmox.endpoint is empty in homelab.yaml.")
        ctx = hmlib.proxmox_ssl_context(cfg)
        token = hmlib.read_secret(cfg, a.secret or hmlib.get(cfg, "proxmox.tokens.read_only", "proxmox-ro"))
    except hmlib.ConfigError as e:
        print(f"proxmox_inventory: {e}", file=sys.stderr)
        return 3
    pve = PVE(endpoint, token, ctx)
    inv = collect(pve, a.details)
    if not a.summary:
        out = Path(a.out) if a.out else Path(cfg["_root"]) / "discovery" / "proxmox.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(inv, indent=2) + "\n")
        print(f"Wrote {out}\n")
    print(summary(inv, cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
