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
Each node's subscription (status, level, next due date), web UI certificate and each network storage's server
are read too, and storage health (GitHub issue #152): each node's ZFS pools (state, errors, last scrub) and disks (SMART
health, wear), replication jobs, and Ceph health where a storage uses the cluster's own Ceph — all with Sys.Audit; a
read that fails is one note in storage_health, not an error. A `pbs` storage's datastore (GC, prune and verify job
runs, snapshots verified and the newest verified one; GitHub issue #151) is read from the Proxmox Backup Server with a
read-only PBS token when `pbs:` in homelab.yaml names that server; its certificate is pinned to the storage's
fingerprint.
--details also reads every guest's config (with LXC `unprivileged` and `features`) and addresses, and its newest successful backup and a newer failure
from the nodes' vzdump task logs (last_backup, backup_error: GitHub issue #89; the read-only token can't list
backup volumes, which need VM.Backup, but reads task logs with Sys.Audit).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
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


class PveError(SystemExit):
    """A Proxmox API call failed (HTTP error, timeout, unreachable, not JSON). A SystemExit, so a script that does
    not catch it ends with the message; collect() records it per node and guest and goes on."""


def body_and_close(e: urllib.error.HTTPError) -> bytes:
    """The body of an error response (kept on the error, so it can be read again), then close it."""
    if not hasattr(e, "hm_body"):
        try:
            e.hm_body = e.read() or b""
        except (OSError, ValueError):
            e.hm_body = b""
        e.close()
    return e.hm_body


class PVE:
    def __init__(self, endpoint: str, token: str, ctx: ssl.SSLContext):
        self.base = endpoint.rstrip("/") + "/api2/json"
        self.headers = {"Authorization": f"PVEAPIToken={token}", "Accept": "application/json"}
        self.token_id = token.split("=", 1)[0]  # user@realm!tokenid — never the secret
        self.ctx = ctx

    def _get(self, path: str, **params):
        url = self.base + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
                return json.load(r).get("data")
        except urllib.error.HTTPError as e:
            body_and_close(e)   # an open error response would leak its connection
            raise

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
            body = body_and_close(e)
            if e.code == 401:
                raise PveError(f"Proxmox API refused {path} (401): the token {self.token_id!r} or its secret is "
                               "wrong, or the token was removed/expired. Check the keychain item (check_env.py).")
            if e.code == 403 and _method != "GET":
                raise PveError(f"Proxmox API refused {_method} {path} (403): the token {self.token_id!r} lacks "
                               "the privilege (HomelabProvisioner role in docs/proxmox-tokens.md, granted to the "
                               "token and its user).")
            if e.code == 403:
                raise PveError(f"Proxmox API refused {path} (403). " + self.permission_hint())
            try:
                detail = json.loads(body or b"{}")
            except ValueError:
                detail = {}
            msg = clean(str(detail.get("errors") or detail.get("message") or e.reason), 200)
            raise PveError(f"Proxmox API refused {'' if _method == 'GET' else _method + ' '}{path} ({e.code}): "
                           f"{msg}")
        except urllib.error.URLError as e:
            hint = (" — run check_env.py: it tells whether the CA is trusted only in the macOS keychain"
                    if isinstance(e.reason, ssl.SSLCertVerificationError) else "")
            raise PveError(f"Cannot reach Proxmox at {self.base}: {e.reason}{hint}")
        except (TimeoutError, OSError) as e:   # a read timeout or a dropped connection after it was established
            raise PveError(f"Proxmox API {path}: {e or type(e).__name__}")
        except ValueError:
            raise PveError(f"Proxmox API {path}: the answer is not valid JSON")

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
                   "efidisk", "tpmstate", "unused", "hostpci", "usb", "dev",       # + what pins a guest to its node
                   "serial")
CONFIG_KEYS = {"agent", "ostype", "ciuser", "sshkeys", "boot", "machine", "bios", "cores", "sockets", "memory",
               "onboot", "startup", "description",
               "unprivileged", "features",   # LXC: a privileged container with nesting is a security finding (#139)
               # what an OpenTofu entry copies (tofu_import_plan.py, GitHub issue #149)
               "cpu", "protection", "balloon", "numa", "tablet", "swap", "hostname", "nameserver", "searchdomain",
               "arch"}
CONFIG_VERSION = 2   # 2: the config holds the keys tofu_import_plan.py copies (0.61.0)


def guest_config(conf: dict) -> dict:
    """The parts of a guest config the snapshot keeps: network, disks, passthrough devices, boot settings."""
    out = {k: clean(v, 300) for k, v in conf.items()
           if k.startswith(CONFIG_PREFIXES) or k in CONFIG_KEYS}
    if "description" in out:
        out["description"] = "[untrusted] " + out["description"]
    return out


def gib(b):
    return round((b or 0) / 1024**3, 1)


BACKUP_TASKS = 10   # vzdump tasks read per node, newest first, while a guest there has no successful backup yet
_ARCHIVE_TIME = re.compile(r"creating .*archive '(?:vm|ct)/\d+/(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)'")


def parse_backup_log(lines: list[str], started: int | None) -> dict[int, dict]:
    """{vmid: {ok, at, storage[, error]}} from one vzdump task log (GitHub issue #89). A PBS archive name holds the
    backup time (UTC); other targets get the task's start time. "ERROR: Backup of VM N failed - why" is a
    failure; other ERROR lines inside a guest's backup (a guest-agent freeze) are not."""
    storage, vmid, out = "", None, {}
    at0 = dt.datetime.fromtimestamp(started, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if started else ""
    for line in lines:
        m = re.search(r"starting new backup job: vzdump .*--storage (\S+)", line)
        if m:
            storage = clean(m.group(1))
        m = re.search(r"Starting Backup of VM (\d+)", line)
        if m:
            vmid = int(m.group(1))
            out[vmid] = {"ok": False, "at": at0, "storage": storage}
            continue
        m = _ARCHIVE_TIME.search(line)
        if m and vmid in out:
            out[vmid]["at"] = m.group(1)
        m = re.search(r"Finished Backup of VM (\d+)", line)
        if m and int(m.group(1)) in out:
            out[int(m.group(1))]["ok"] = True
        m = re.search(r"ERROR: Backup of VM (\d+) failed - (.*)", line)
        if m:
            out.setdefault(int(m.group(1)), {"at": at0, "storage": storage}).update(ok=False, error=clean(m.group(2), 200))
    return out


def last_backups(pve: PVE, nodes: list[dict], guests: list[dict]) -> tuple[dict[int, dict], str]:
    """Newest successful backup and a newer failure per guest from the nodes' vzdump task logs (GitHub issue #89).
    Backup volumes themselves are listed only to VM.Backup + Datastore.AllocateSpace, which a read-only token
    lacks; the task list and logs need Sys.Audit (PVEAuditor). Returns ({vmid: {last_backup, backup_error}}, how)."""
    found: dict[int, dict] = {}
    on_node: dict = {}
    for g in guests:
        if not g.get("template") and isinstance(g.get("vmid"), int):
            on_node.setdefault(g.get("node"), set()).add(g["vmid"])
    read = 0
    for n in nodes:
        if n["status"] != "online":
            continue
        try:
            tasks = pve._get(f"/nodes/{n['node']}/tasks", typefilter="vzdump", limit=50) or []
        except (urllib.error.URLError, OSError, ValueError) as e:
            return found, f"not read: {getattr(e, 'code', '') or e}"
        for t in tasks[:BACKUP_TASKS]:
            if on_node.get(n["node"], set()) <= {v for v, r in found.items() if "last_backup" in r}:
                break
            if t.get("status") is None:   # still running
                continue
            try:
                log = pve._get(f"/nodes/{n['node']}/tasks/{urllib.parse.quote(str(t.get('upid')), safe='')}/log",
                               limit=20000) or []
            except (urllib.error.URLError, OSError, ValueError):
                continue
            read += 1
            for vmid, r in parse_backup_log([str(x.get("t") or "") for x in log], t.get("starttime")).items():
                rec = found.setdefault(vmid, {})
                if "last_backup" in rec:
                    continue
                if r.get("ok"):
                    rec["last_backup"] = {"at": r["at"], "storage": r["storage"]}
                elif "backup_error" not in rec:
                    rec["backup_error"] = {"at": r["at"], "storage": r["storage"], "error": r.get("error") or "unfinished"}
    return found, f"ok ({read} vzdump task logs)"


def dn_name(dn) -> str:
    """CN (else O) of an OpenSSL one-line DN, /C=CZ/O=Home/CN=Proxmox VE → Proxmox VE."""
    parts = dict(p.split("=", 1) for p in str(dn or "").split("/") if "=" in p)
    return clean(parts.get("CN") or parts.get("O"), 120) or ""


def web_certificate(pve: PVE, node: str) -> dict | None:
    """The certificate a node's web UI (port 8006) serves: pveproxy-ssl.pem when one is installed, else pve-ssl.pem
    (GitHub issue #89: expirations; Sys.Audit)."""
    try:
        certs = {c.get("filename"): c for c in pve._get(f"/nodes/{node}/certificates/info") or []}
    except (urllib.error.URLError, OSError, ValueError):
        return None
    c = certs.get("pveproxy-ssl.pem") or certs.get("pve-ssl.pem")
    if not c or not isinstance(c.get("notafter"), int):
        return None
    return {"file": c.get("filename"), "subject": dn_name(c.get("subject")), "issuer": dn_name(c.get("issuer")),
            "not_after": dt.datetime.fromtimestamp(c["notafter"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def subscription(pve: PVE, node: str) -> dict | None:
    """A node's subscription status, level and next due date (GitHub issue #89); never the key or server ID."""
    try:
        sub = pve._get(f"/nodes/{node}/subscription") or {}
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return {k: clean(sub.get(src)) for k, src in (("status", "status"), ("level", "level"), ("next_due", "nextduedate"))
            if sub.get(src)}


# --------------------------------------------------------------------------- storage health (GitHub issue #152)

AUDIT_PRIV = "Sys.Audit on / (PVEAuditor)"
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov",
                                       "dec"), 1)}
_SCAN_DONE = re.compile(r"scrub repaired \S+ in .*? with (\d+) errors on \w+ (\w+) +(\d+) [\d:]+ (\d{4})")


def http_reason(e: Exception) -> str:
    """'403', '500 binary not installed: /usr/bin/ceph-mon', 'timed out': why a read failed, short."""
    if isinstance(e, urllib.error.HTTPError):
        return f"{e.code} {clean(e.reason, 120)}".strip()
    return clean(str(getattr(e, "reason", None) or e or type(e).__name__), 120)


def health_get(pve: PVE, path: str, notes: dict, key: str, where: str, default=None):
    """GET for the storage health reads: a refusal or failure becomes one note in `notes[key]` (no exception, nothing
    in `errors`: a node without Ceph or replication answers an error, which is no reason to warn)."""
    try:
        data = pve._get(path)
    except (urllib.error.URLError, OSError, ValueError) as e:
        code = getattr(e, "code", None)
        why = (f"forbidden: the read-only token needs {AUDIT_PRIV}" if code == 403 else http_reason(e))
        notes.setdefault(key, []).append(f"{where}: {why}" if where else why)
        return default
    return data if data is not None else ([] if default is None else default)   # read, possibly empty


def zfs_scan(scan: str) -> dict:
    """The last scrub from a zpool scan line: {scrub_at (date), scrub_errors} for a finished scrub, scrub_running,
    or nothing ('none requested', a resilver)."""
    first = " ".join(str(scan or "").split())
    m = _SCAN_DONE.search(first)
    if m and m.group(2).lower()[:3] in _MONTHS:
        try:
            at = dt.date(int(m.group(4)), _MONTHS[m.group(2).lower()[:3]], int(m.group(3))).isoformat()
            return {"scrub_at": at, "scrub_errors": int(m.group(1))}
        except ValueError:
            return {}
    return {"scrub_running": True} if first.startswith("scrub in progress") else {}


def bad_vdevs(node: dict, out: list | None = None) -> list[str]:
    """Disks (leaf devices) of a pool that are not ONLINE (or a spare AVAIL) or have read/write/checksum errors."""
    out = [] if out is None else out
    for c in node.get("children") or []:
        state = str(c.get("state") or "")
        errs = [str(c.get(k) or 0) for k in ("read", "write", "cksum")]
        if c.get("leaf") and ((state and state not in ("ONLINE", "AVAIL")) or any(e not in ("0", "") for e in errs)):
            out.append(clean(f"{c.get('name')} {state}" + (f" (read/write/cksum {'/'.join(errs)})"
                                                            if any(e != "0" for e in errs) else ""), 120))
        bad_vdevs(c, out)
    return out


def node_zfs(pve: PVE, node: str, notes: dict) -> list[dict] | None:
    pools = health_get(pve, f"/nodes/{node}/disks/zfs", notes, "zfs", node)
    if pools is None:
        return None
    out = []
    for p in pools:
        name = str(p.get("name") or "")
        d = health_get(pve, f"/nodes/{node}/disks/zfs/{urllib.parse.quote(name, safe='')}", notes, "zfs",
                       f"{node} pool {clean(name)}", {})
        rec = {"pool": clean(name), "state": clean(d.get("state") or p.get("health")),
               "size_gib": gib(p.get("size")), "alloc_gib": gib(p.get("alloc"))}
        if d:
            rec["errors"] = clean(d.get("errors"), 200)
            rec["scan"] = clean(" ".join(str(d.get("scan") or "").split()), 200)
            rec.update(zfs_scan(d.get("scan")))
            bad = bad_vdevs(d)
            if bad:
                rec["bad_devices"] = bad[:10]
        out.append(rec)
    return sorted(out, key=lambda x: x["pool"] or "")


def node_disks(pve: PVE, node: str, notes: dict) -> list[dict] | None:
    """SMART health and wear of a node's disks. Proxmox's `wearout` is the life left (100 = new); wear_pct is the
    part used, as the GUI shows it."""
    disks = health_get(pve, f"/nodes/{node}/disks/list", notes, "disks", node)
    if disks is None:
        return None
    out = []
    for x in disks:
        w = x.get("wearout")
        try:
            wear = 100 - int(w) if str(w).strip().lstrip("-").isdigit() else None
        except ValueError:
            wear = None
        out.append({"dev": clean(x.get("devpath")), "type": clean(x.get("type")), "model": clean(x.get("model"), 60),
                    "health": clean(x.get("health")), "used": clean(x.get("used")),
                    **({"wear_pct": wear} if wear is not None else {})})
    return sorted(out, key=lambda x: x["dev"] or "")


def iso(ts) -> str | None:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") \
        if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > 0 else None


def replication(pve: PVE, nodes: list[dict], notes: dict) -> list[dict] | None:
    """Storage replication jobs with their last sync and failures (status per source node)."""
    conf = health_get(pve, "/cluster/replication", notes, "replication", "", [])
    if "replication" in notes:
        return None
    if not conf:
        return []
    disabled = {str(j.get("id")) for j in conf if j.get("disable") not in (None, 0, "0", False)}
    out, seen = [], set()
    for n in nodes:
        if n["status"] != "online":
            continue
        for j in health_get(pve, f"/nodes/{n['node']}/replication", notes, "replication", n["node"], []):
            seen.add(str(j.get("id")))
            out.append({"id": clean(j.get("id")), "guest": j.get("guest"), "source": clean(j.get("source") or n["node"]),
                        "target": clean(j.get("target")), "enabled": str(j.get("id")) not in disabled,
                        "last_sync": iso(j.get("last_sync")),
                        "next_sync": iso(j.get("next_sync")), "fail_count": j.get("fail_count") or 0,
                        **({"error": clean(j.get("error"), 200)} if j.get("error") else {})})
    for j in conf:   # a job whose source node is offline has no status
        if str(j.get("id")) not in seen:
            out.append({"id": clean(j.get("id")), "guest": j.get("guest"), "source": clean(j.get("source")),
                        "target": clean(j.get("target")), "enabled": str(j.get("id")) not in disabled,
                        "status": "no status (source node not read)"})
    return sorted(out, key=lambda x: x["id"] or "")


def ceph_status(pve: PVE, notes: dict) -> dict | None:
    st = health_get(pve, "/cluster/ceph/status", notes, "ceph", "")
    if not isinstance(st, dict):
        return None
    h = st.get("health") or {}
    checks = [{"check": clean(k), "severity": clean(v.get("severity")),
               "message": clean(((v.get("summary") or {}).get("message")), 200)}
              for k, v in sorted((h.get("checks") or {}).items()) if isinstance(v, dict) and not v.get("muted")]
    return {"health": clean(h.get("status")), "checks": checks}


# --------------------------------------------------------------------------- Proxmox Backup Server (GitHub issue #151)

class PbsError(Exception):
    def __init__(self, msg: str, code: int | None = None):
        super().__init__(msg)
        self.code = code


def pbs_token(value: str) -> str:
    """user@realm!tokenid:secret as PBS wants it in its Authorization header ('=' after the token id works too)."""
    tid, _, rest = value.partition("!")
    if not rest or ":" in rest:
        return value
    return tid + "!" + rest.replace("=", ":", 1)


class PBS:
    """Read-only Proxmox Backup Server API (GET only). With a fingerprint (the Proxmox storage's, or pbs[].fingerprint)
    the certificate is pinned to it, as Proxmox VE itself does; without one it is verified against ca_cert or the
    system CAs. The token is sent only after the certificate checked out."""

    def __init__(self, host: str, port: int, token: str, ctx: ssl.SSLContext | None, fingerprint: str = ""):
        self.host, self.port = host, int(port or 8007)
        self.headers = {"Authorization": f"PBSAPIToken={pbs_token(token)}", "Accept": "application/json"}
        self.fingerprint = re.sub(r"[^0-9a-f]", "", str(fingerprint or "").lower())
        self.ctx = ssl._create_unverified_context() if self.fingerprint else (ctx or ssl.create_default_context())

    def _get(self, path: str, **params):
        import hashlib
        import http.client
        url = "/api2/json" + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        conn = http.client.HTTPSConnection(f"[{self.host}]" if ":" in self.host else self.host, self.port,
                                           context=self.ctx, timeout=30)
        try:
            conn.connect()
            if self.fingerprint:
                seen = hashlib.sha256(conn.sock.getpeercert(binary_form=True) or b"").hexdigest()
                if seen != self.fingerprint:
                    raise PbsError(f"its certificate's fingerprint is not the one the Proxmox storage pins "
                                   f"({':'.join(seen[i:i + 2] for i in range(0, 64, 2))})")
            conn.request("GET", url, headers=self.headers)
            r = conn.getresponse()
            body = r.read()
            if r.status != 200:
                raise PbsError(f"{r.status} {clean(r.reason, 120)}", r.status)
            return json.loads(body or b"{}").get("data")
        except (OSError, http.client.HTTPException) as e:
            raise PbsError(http_reason(e)) from None
        except ValueError:
            raise PbsError("the answer is not valid JSON") from None
        finally:
            conn.close()

    def get(self, path: str, **params):
        try:
            return self._get(path, **params)
        except PbsError as e:
            if e.code == 401:
                raise PbsError("401: the PBS token or its secret is wrong, or the token was removed", 401) from None
            if e.code == 403:
                raise PbsError("403: the PBS token (and its user) need the DatastoreAudit role on /datastore "
                               "(docs/proxmox-tokens.md)", 403) from None
            raise


def pbs_job(j: dict) -> dict:
    """A PBS job's (GC, prune, verify) last run: state OK / an error / running (an UPID without a result yet)."""
    state = j.get("last-run-state")
    if not state and (j.get("last-run-upid") or j.get("upid")) and not j.get("last-run-endtime"):
        state = "running"
    return {k: v for k, v in (("id", clean(j.get("id"))), ("schedule", clean(j.get("schedule"))),
                              ("ns", clean(j.get("ns"))), ("state", clean(state, 200)),
                              ("at", iso(j.get("last-run-endtime"))), ("next", iso(j.get("next-run"))),
                              ("enabled", False if j.get("disable") else None)) if v not in (None, "")}


def pbs_datastore(pbs: PBS, store: str, ns: str, jobs: dict) -> dict:
    """One datastore (namespace) as the overview judges it: GC, prune and verify job runs and its snapshots'
    verification (counts and the newest backup and newest verified backup times; never the snapshot list)."""
    out: dict = {"gc": None, "prune": [], "verify": []}
    for kind in ("gc", "prune", "verify"):
        if isinstance(jobs.get(kind), str):
            out.setdefault("errors", []).append(f"{kind} jobs: {jobs[kind]}")
            continue
        mine = [pbs_job(j) for j in jobs.get(kind) or [] if j.get("store") == store]
        if kind == "gc":
            out["gc"] = mine[0] if mine else None
        else:
            out[kind] = sorted(mine, key=lambda j: j.get("id") or "")
    try:
        snaps = pbs.get(f"/admin/datastore/{urllib.parse.quote(store, safe='')}/snapshots", **({"ns": ns} if ns else {}))
    except PbsError as e:
        out.setdefault("errors", []).append(f"snapshots: {e}")
        return out
    state = [((s.get("verification") or {}).get("state"), s.get("backup-time")) for s in snaps or []]
    out["snapshots"] = {"count": len(state), "verified": sum(1 for v, _ in state if v == "ok"),
                        "failed": sum(1 for v, _ in state if v == "failed"),
                        "newest": iso(max((t for _, t in state if isinstance(t, int)), default=None)),
                        "newest_verified": iso(max((t for v, t in state if v == "ok" and isinstance(t, int)),
                                                   default=None)),
                        # not verified yet (neither ok nor failed): how far verification lags behind the backups
                        "oldest_unverified": iso(min((t for v, t in state if v not in ("ok", "failed")
                                                      and isinstance(t, int)), default=None))}
    return out


def pbs_health(stores: dict, opener) -> tuple[list[dict], str]:
    """Read every PBS datastore the site's `pbs` storages use. stores: {(server, port, datastore, namespace):
    {storages, fingerprint}}; opener(server, port, fingerprint) → (PBS | None, why not)."""
    out, missing, failed, clients = [], set(), [], {}
    for (server, port, store, ns), info in sorted(stores.items()):
        rec = {"server": server, "datastore": store, **({"namespace": ns} if ns else {}),
               "storages": sorted(info["storages"])}
        key = (server, port)
        if key not in clients:
            pbs, why = opener(server, port, info["fingerprint"]) if opener else (None, "")
            jobs: dict = {}
            if pbs:
                for kind, path in (("gc", "/admin/gc"), ("prune", "/admin/prune"), ("verify", "/admin/verify")):
                    try:
                        jobs[kind] = pbs.get(path) or []
                    except PbsError as e:
                        if e.code in (401, 403) or e.code is None:
                            pbs, why = None, str(e)
                            break
                        jobs[kind] = str(e)   # an older PBS without the job list
            clients[key] = (pbs, why, jobs)
        pbs, why, jobs = clients[key]
        if pbs is None:
            if why:
                rec["error"] = why
                failed.append(f"{server}: {why}")
            else:
                missing.add(server)
            out.append(rec)
            continue
        rec.update(pbs_datastore(pbs, store, ns, jobs))
        out.append(rec)
    notes = []
    if missing:
        notes.append(f"no token for {', '.join(sorted(missing))} (pbs: in homelab.yaml, docs/proxmox-tokens.md)")
    notes += sorted(set(failed))
    read = sum(1 for r in out if "error" not in r and r["server"] not in missing)
    return out, ("ok" if not notes else "; ".join(notes)) + f" ({read} of {len(out)} datastores read)"


def collect(pve: PVE, details: bool, jobs: int = 8, pbs=None) -> dict:
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

    errors: list[str] = []   # calls that failed: the snapshot is partial, the rest is still read

    def get(path: str, what: str, default):
        try:
            return pve.get(path) or default
        except PveError as e:
            errors.append(f"{what}: {e}")
            return default

    networks = {}
    notes: dict[str, list[str]] = {}   # storage health reads that failed (GitHub issue #152), one line each

    def read_node(n: dict):
        nets = get(f"/nodes/{n['node']}/network", f"node {n['node']} network", [])
        # GitHub issue #97: the node's own Proxmox VE version and running kernel (Sys.Audit, PVEAuditor)
        ns = get(f"/nodes/{n['node']}/status", f"node {n['node']} status", {})
        n["pveversion"] = clean(ns.get("pveversion"))
        n["kernel"] = clean((ns.get("current-kernel") or {}).get("release") or ns.get("kversion"))
        sub = subscription(pve, n["node"])
        if sub:
            n["subscription"] = sub
        cert = web_certificate(pve, n["node"])
        if cert:
            n["certificate"] = cert
        for key, read in (("zfs", node_zfs), ("disks", node_disks)):   # GitHub issue #152
            got = read(pve, n["node"], notes)
            if got is not None:
                n[key] = got
        networks[n["node"]] = [{"iface": clean(x.get("iface")), "type": x.get("type"), "cidr": x.get("cidr"),
                                "gateway": x.get("gateway"), "bridge_ports": clean(x.get("bridge_ports")),
                                "vlan_aware": bool(x.get("bridge_vlan_aware")), "active": bool(x.get("active"))}
                               for x in nets]

    # nodes and guests are read in parallel: a hung guest agent or a slow node no longer holds up the others
    with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        list(ex.map(read_node, [n for n in nodes if n["status"] == "online"]))

    # where each network storage lives (GitHub issue #89): an NFS/CIFS/PBS server is a dependency
    servers = {s.get("storage"): s for s in get("/storage", "storage configuration", [])}
    for s in storage:
        conf = servers.get(s["storage"]) or {}
        for key in ("server", "export", "datastore", "share"):
            if conf.get(key):
                s[key] = clean(conf[key])

    # GitHub issue #152: replication, and Ceph where a storage uses this cluster's own Ceph (no monhost)
    repl = replication(pve, nodes, notes)
    hyper = any(c.get("type") in ("rbd", "cephfs") and not c.get("monhost") and not c.get("disable")
                for c in servers.values())
    ceph = ceph_status(pve, notes) if hyper else None
    health = {k: ("ok" if k not in notes else "not read: " + "; ".join(sorted(notes[k])))
              for k in ("zfs", "disks", "replication")}
    if hyper:
        health["ceph"] = "ok" if ceph else "not read: " + "; ".join(notes.get("ceph") or ["no answer"])
    # GitHub issue #151: the PBS datastores behind `pbs` storages, read with a PBS token (pbs: in homelab.yaml)
    stores: dict = {}
    for sid, c in servers.items():
        if c.get("type") == "pbs" and c.get("server") and c.get("datastore") and not c.get("disable"):
            k = (clean(c["server"]), int(c.get("port") or 8007), clean(c["datastore"]), clean(c.get("namespace")) or "")
            e = stores.setdefault(k, {"storages": set(), "fingerprint": str(c.get("fingerprint") or "")})
            e["storages"].add(clean(sid))
    pbs_ds = None
    if stores:
        pbs_ds, health["pbs"] = pbs_health(stores, pbs)

    try:  # scheduled vzdump jobs (PVEAuditor can read them); None = could not read
        backup_jobs = [{"id": clean(j.get("id")), "enabled": j.get("enabled", 1) not in (0, "0"),
                        "schedule": clean(j.get("schedule")), "storage": clean(j.get("storage")),
                        "all": bool(j.get("all")), "vmid": id_list(j.get("vmid")), "exclude": id_list(j.get("exclude")),
                        "pool": clean(j.get("pool")), "node": clean(j.get("node")),
                        "comment": clean(j.get("comment"))}
                       for j in (pve.get("/cluster/backup") or [])]
    except PveError as e:
        errors.append(f"backup jobs: {e}")
        backup_jobs = None

    ip_sources = {"agent": "not queried", "lxc": "not queried"}
    if details:  # per-guest config: network, disks, cloud-init, agent — still read-only
        def read_guest(g: dict):
            kind = "qemu" if g["type"] == "vm" else "lxc"
            try:
                conf = pve.get(f"/nodes/{g['node']}/{kind}/{g['vmid']}/config") or {}
            except PveError as e:
                errors.append(f"guest {g['vmid']} config: {e}")
                return
            g["config"] = guest_config(conf)
            if g["status"] == "running":
                g["ips"] = guest_ips(pve, g, kind, conf, ip_sources)
        with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
            list(ex.map(read_guest, guests))
        backups, how = last_backups(pve, nodes, guests)
        ip_sources["backups"] = how
        for g in guests:
            g.update(backups.get(g["vmid"]) or {})

    warnings = [w for w in [None if guests else no_guests_hint(pve)] if w]
    return {"collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "source": "proxmox-api", "version": version.get("version"),
            "cluster": {"name": clean(cluster.get("name")), "nodes": cluster.get("nodes"), "quorate": cluster.get("quorate")}
            if cluster else None,
            "nodes": sorted(nodes, key=lambda x: x["node"] or ""),
            "guests": sorted(guests, key=lambda x: x["vmid"] or 0),
            "storage": sorted(storage, key=lambda x: (x["node"] or "", x["storage"] or "")),
            # sorted: nodes answer in any order, and Proxmox lists interfaces in a varying order
            "networks": {k: sorted(v, key=lambda x: x["iface"] or "") for k, v in sorted(networks.items())},
            "backup_jobs": backup_jobs,
            "replication": repl, **({"ceph": ceph} if ceph else {}),
            **({"pbs_datastores": pbs_ds} if pbs_ds is not None else {}), "storage_health": health,
            **({"guest_ip_sources": ip_sources, "config_version": CONFIG_VERSION} if details else {}),
            **({"warnings": warnings} if warnings else {}),
            **({"errors": sorted(errors)} if errors else {})}


def keep_details(old: dict | None, new: dict) -> dict:
    """A run without --details keeps each guest's config, reported addresses (ips) and backup results from the
    previous snapshot
    (same VMID and type) and stamps when they were read (details_at), so a plain refresh doesn't strip what
    pve_node_plan.py, drift_report.py and overview.py need (addresses: GitHub issue #97)."""
    if not old or any("config" in g for g in new.get("guests") or []):
        return new
    prev = {(g.get("vmid"), g.get("type")): g for g in old.get("guests") or [] if "config" in g}
    if not prev:
        return new
    kept = 0
    for g in new.get("guests") or []:
        o = prev.get((g.get("vmid"), g.get("type")))
        if o is not None:
            g["config"] = o["config"]
            for k in ("ips", "last_backup", "backup_error"):
                if k in o:
                    g[k] = o[k]
            kept += 1
    if kept:
        new["details_at"] = old.get("details_at") or old.get("collected_at")
        if old.get("config_version"):
            new["config_version"] = old["config_version"]
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


def health_summary(inv: dict) -> list[str]:
    """Storage health facts (GitHub issues #151, #152), not judged: overview.py applies the thresholds."""
    out = []
    pools = [(n["node"], p) for n in inv.get("nodes") or [] for p in n.get("zfs") or []]
    if pools:
        out.append("ZFS: " + ", ".join(f"{n}/{p['pool']} {p.get('state')}"
                                       + (f" (scrub {p['scrub_at']}, {p.get('scrub_errors')} errors)"
                                          if p.get("scrub_at") else "") for n, p in pools))
    disks = [d for n in inv.get("nodes") or [] for d in n.get("disks") or []]
    if disks:
        worn = max((d.get("wear_pct") for d in disks if isinstance(d.get("wear_pct"), int)), default=None)
        bad = sum(1 for d in disks if str(d.get("health") or "").upper() not in ("PASSED", "OK", "UNKNOWN", ""))
        out.append(f"Disks: {len(disks)}, SMART not passed: {bad}" + (f", most worn {worn}%" if worn is not None else ""))
    repl = inv.get("replication") or []
    if repl:
        out.append(f"Replication: {len(repl)} job(s), failing: {sum(1 for j in repl if j.get('fail_count'))}")
    if inv.get("ceph"):
        out.append(f"Ceph: {inv['ceph'].get('health')}")
    for ds in inv.get("pbs_datastores") or []:
        sn = ds.get("snapshots") or {}
        if not sn:
            continue   # not read: the note below says why, once per server
        out.append(f"PBS {ds['server']} {ds['datastore']}: {sn.get('verified', 0)}/{sn.get('count', 0)} snapshots "
                   f"verified, newest verified {sn.get('newest_verified') or 'none'}")
    out += [f"{k} not read — {v}" for k, v in sorted((inv.get("storage_health") or {}).items())
            if not v.startswith("ok")]
    return (["\nStorage health:"] + [f"  {x}" for x in out]) if out else []


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
    backups = (inv.get("guest_ip_sources") or {}).get("backups", "")
    if backups.startswith("not read"):
        lines.append(f"\nLast backups {backups} — the read-only token needs Sys.Audit on / (PVEAuditor).")
    if inv.get("details_at"):
        lines.append(f"\nGuest config kept from the --details run of {inv['details_at']} (refresh with --details).")
    lines += health_summary(inv)
    for w in inv.get("warnings") or []:
        lines.append(f"\nWarning: {w}.")
    if inv.get("errors"):
        lines.append(f"\nNot read ({len(inv['errors'])} API call(s) failed; the rest of the snapshot is complete):")
        lines += [f"  - {e}" for e in inv["errors"]]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", help="secret name (default: proxmox.tokens.read_only)")
    ap.add_argument("--out", help="write the snapshot alone to this file (default: its site in discovery/proxmox.json)")
    ap.add_argument("--details", action="store_true", help="also fetch each guest's config")
    ap.add_argument("--jobs", type=int, default=8, help="API calls in parallel (nodes, guests; default 8)")
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


def pbs_opener(cfg: dict):
    """(server, port, fingerprint) → (PBS | None, why not) from pbs: in homelab.yaml (GitHub issue #151): None and ''
    when no entry names that server (the token is optional)."""
    def open_pbs(server: str, port: int, fingerprint: str):
        try:
            e = hmlib.pbs_server(cfg, server)
            if not e:
                return None, ""
            token = hmlib.read_secret(cfg, str(e["token"]))
            pin = "" if e.get("ca_cert") or e.get("verify_tls") is False else str(e.get("fingerprint") or fingerprint)
            ctx = hmlib.proxmox_ssl_context(cfg, e)
        except hmlib.ConfigError as err:
            return None, str(err)
        return PBS(server, int(e.get("port") or port), token, ctx, pin), ""
    return open_pbs


def inventory_site(cfg: dict, px: dict, a) -> None:
    """Read one site's Proxmox and write its snapshot."""
    s = hmlib.site(cfg, px["_site"])
    ctx = hmlib.proxmox_ssl_context(cfg, px)
    token = hmlib.read_secret(cfg, a.secret or hmlib.proxmox_token_name(px, "read_only"))
    inv = collect(PVE(hmlib.pick_endpoint(px), token, ctx), a.details, a.jobs, pbs_opener(cfg))
    if s["name"]:
        inv = {"site": s["name"], **inv}
    if not a.summary:
        if a.out:
            out = Path(a.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            hmlib.atomic_write(out, json.dumps(inv, indent=2) + "\n")
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
