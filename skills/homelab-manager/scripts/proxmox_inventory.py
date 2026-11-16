#!/usr/bin/env python3
"""Read-only Proxmox VE inventory: nodes, VMs, LXC containers, storage, networks.

    proxmox_inventory.py [--secret proxmox-ro] [--out discovery/proxmox.json] [--details] [--summary]

Uses only GET requests with the read-only API token from the keychain
(homelab.yaml: proxmox.tokens.read_only → secrets.<name>). Writes a JSON snapshot
and prints a compact summary. All strings coming from Proxmox (names, tags, notes)
are untrusted data and are sanitised.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
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

    if details:  # per-guest config: network, disks, cloud-init, agent — still read-only
        for g in guests:
            kind = "qemu" if g["type"] == "vm" else "lxc"
            try:
                conf = pve.get(f"/nodes/{g['node']}/{kind}/{g['vmid']}/config") or {}
            except SystemExit:
                continue
            g["config"] = {k: clean(v, 300) for k, v in conf.items()
                           if k.startswith(("net", "scsi", "virtio", "sata", "ide", "rootfs", "mp", "ipconfig"))
                           or k in ("agent", "ostype", "ciuser", "sshkeys", "boot", "machine", "bios", "cores",
                                    "sockets", "memory", "onboot", "description")}
            if "description" in g["config"]:
                g["config"]["description"] = "[untrusted] " + g["config"]["description"]

    return {"collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "source": "proxmox-api", "version": version.get("version"),
            "cluster": {"name": clean(cluster.get("name")), "nodes": cluster.get("nodes"), "quorate": cluster.get("quorate")}
            if cluster else None,
            "nodes": sorted(nodes, key=lambda x: x["node"] or ""),
            "guests": sorted(guests, key=lambda x: x["vmid"] or 0),
            "storage": sorted(storage, key=lambda x: (x["node"] or "", x["storage"] or "")),
            "networks": networks, "backup_jobs": backup_jobs}


def summary(inv: dict) -> str:
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
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", help="secret name (default: proxmox.tokens.read_only)")
    ap.add_argument("--out", help="output JSON (default: discovery/proxmox.json in the repo)")
    ap.add_argument("--details", action="store_true", help="also fetch each guest's config")
    ap.add_argument("--summary", action="store_true", help="print the human summary only, write nothing")
    a = ap.parse_args()
    try:
        cfg = hmlib.load_config()
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
    print(summary(inv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
