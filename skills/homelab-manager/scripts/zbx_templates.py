"""Zabbix templates: what the managed hosts use, newer official versions, fetching and importing (GitHub #168).

    zabbix_api.py templates [--upstream] [--branch release/8.0]   # in use; --upstream: newer official versions
    zabbix_api.py template-fetch <template name…> [--branch …]     # official YAML → zabbix/templates/
    zabbix_api.py template-import <file.yaml> --compare            # what an import would change (rw token)
    zabbix_api.py template-import <file.yaml>                      # export first (rollback), then import (rw token)

Official templates come only from the zabbix/zabbix repository on GitHub, branch release/<server major.minor>:
--upstream and template-fetch are downloads, so the guard asks first. A downloaded file is data: it is read with
yq, never run. Import is refused for a template or template group outside zabbix.managed_scope.template_groups.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import hmlib
import zbxlib

API = "https://api.github.com/repos/zabbix/zabbix"
RAW = "https://raw.githubusercontent.com/zabbix/zabbix"
ALLOWED_HOSTS = {"api.github.com", "raw.githubusercontent.com"}
CACHE = Path("discovery") / "zabbix-upstream"
TEMPLATES_DIR = Path("zabbix") / "templates"
STOP_WORDS = {"by", "zabbix", "agent", "active", "and", "the", "template", "http", "snmp", "for", "of"}
MAX_CANDIDATES = 6


def fetch(url: str, timeout: int = 60) -> bytes:
    """GET from the official repository only (pinned hosts, https)."""
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS or not (
            u.path.startswith("/repos/zabbix/zabbix/") or u.path.startswith("/zabbix/zabbix/")):
        raise hmlib.ConfigError(f"refusing to download from {url}: only the official zabbix/zabbix repository")
    req = urllib.request.Request(url, headers={"User-Agent": "homelab-manager", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise zbxlib.ZabbixError(f"GitHub HTTP {e.code} for {url}") from None
    except (urllib.error.URLError, OSError) as e:
        raise zbxlib.ZabbixError(f"GitHub not reachable ({getattr(e, 'reason', e)})") from None


def branch_for(version: str, given: str | None) -> str:
    if given:
        if not re.fullmatch(r"release/\d+\.\d+", given):
            raise hmlib.ConfigError("--branch must look like release/8.0")
        return given
    major, minor = zbxlib.version_tuple(version)
    return f"release/{major}.{minor}"


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or "")))


class Upstream:
    """The template YAML files of one release branch, fetched on demand and cached in discovery/zabbix-upstream/."""

    def __init__(self, root: Path, branch: str, get=fetch):
        self.root, self.branch, self.get = Path(root), branch, get
        self.cache = self.root / CACHE / branch.replace("/", "-")
        self._paths: list[str] | None = None
        self._parsed: dict[str, list[dict]] = {}

    def paths(self) -> list[str]:
        if self._paths is None:
            listing = self.cache / "tree.json"
            if listing.is_file() and time.time() - listing.stat().st_mtime < 7 * 86400:
                self._paths = json.loads(listing.read_text())
            else:
                ref = urllib.parse.quote(self.branch, safe="")
                top = json.loads(self.get(f"{API}/contents/?ref={ref}"))
                sha = next((e["sha"] for e in top if e.get("name") == "templates" and e.get("type") == "dir"), None)
                if not sha:
                    raise zbxlib.ZabbixError(f"no templates directory on {self.branch}")
                tree = json.loads(self.get(f"{API}/git/trees/{sha}?recursive=1"))
                self._paths = sorted("templates/" + e["path"] for e in tree.get("tree") or []
                                     if e.get("type") == "blob" and e["path"].endswith(".yaml"))
                self.cache.mkdir(parents=True, exist_ok=True)
                hmlib.atomic_write(listing, json.dumps(self._paths) + "\n")
        return self._paths

    def file(self, path: str) -> Path:
        local = self.cache / path
        if not local.is_file():
            data = self.get(f"{RAW}/{urllib.parse.quote(self.branch)}/{urllib.parse.quote(path)}")
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
        return local

    def templates_in(self, path: str) -> list[dict]:
        if path not in self._parsed:
            data = zbxlib.load_yaml(self.file(path)) or {}
            self._parsed[path] = [{"template": t.get("template"), "name": t.get("name"),
                                   "vendor_version": str((t.get("vendor") or {}).get("version") or "")}
                                  for t in (data.get("zabbix_export") or {}).get("templates") or []]
        return self._parsed[path]

    def candidates(self, name: str) -> list[str]:
        words = {w for w in re.findall(r"[a-z0-9]+", name.lower()) if w not in STOP_WORDS}
        scored = []
        for p in self.paths():
            tokens = set(re.findall(r"[a-z0-9]+", p.lower()))
            hit = len(words & tokens)
            if hit:
                scored.append((-hit, len(tokens), p))
        return [p for _, _, p in sorted(scored)[:MAX_CANDIDATES]]

    def find(self, name: str) -> tuple[str, dict] | None:
        for p in self.candidates(name):
            for t in self.templates_in(p):
                if name in (t["template"], t["name"]):
                    return p, t
        return None


def in_use(c: zbxlib.Client, cfg: dict) -> tuple[dict, dict[str, int]]:
    """({template name: template}, {template name: managed hosts using it, directly or through another})."""
    import zbx_reports
    s = zbx_reports.scope_ids(c, cfg)
    count: dict[str, int] = {}
    for zh in s["managed"].values():
        used = set()
        for t in zh.get("parentTemplates") or []:
            zbx_reports.closure(t["host"], s["templates"], used)
        for t in used:
            count[t] = count.get(t, 0) + 1
    return s["templates"], count


def cmd_templates(a, cfg) -> int:
    c = zbxlib.connect(cfg, "ro")
    templates, count = in_use(c, cfg)
    up = Upstream(Path(cfg["_root"]), branch_for(c.version(), a.branch)) if a.upstream else None
    newer = 0
    for name in sorted(count, key=lambda n: (-count[n], n)):
        t = templates.get(name) or {}
        vendor = f"{t.get('vendor_name')} {t.get('vendor_version')}".strip() if t.get("vendor_name") else "own"
        managed = any(x.get("tag") == zbxlib.MANAGED_TAG for x in t.get("tags") or [])
        line = f"  {hmlib.clean(name, 70):<60} {count[name]:>3} host(s)  {vendor}" + ("  (wrapper)" if managed else "")
        if up and t.get("vendor_name") == "Zabbix":
            found = up.find(name)
            if found is None:
                line += f"  — not found on {up.branch}"
            elif version_key(found[1]["vendor_version"]) > version_key(t.get("vendor_version")):
                newer += 1
                line += f"  → {found[1]['vendor_version']} on {up.branch} ({found[0]})"
        print(line)
    print(f"{len(count)} template(s) in use by managed hosts"
          + (f"; {newer} with a newer official version: template-fetch, then template-import --compare" if up else ""))
    return 0


def cmd_template_fetch(a, cfg) -> int:
    c = zbxlib.connect(cfg, "ro")
    root = Path(cfg["_root"])
    up = Upstream(root, branch_for(c.version(), a.branch))
    for name in a.names:
        found = up.find(name)
        if found is None:
            print(f"  {name}: not found on {up.branch}")
            continue
        path, t = found
        dest = root / TEMPLATES_DIR / Path(path).name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(up.file(path).read_bytes())
        print(f"  {name}: {t['vendor_version']} from {up.branch}/{path} → {dest.relative_to(root)}")
    print("Next: `zabbix_api.py template-import <file> --compare` shows what an import changes.")
    return 0


IMPORT_RULES_DELETE = ("items", "triggers", "discoveryRules", "graphs", "httptests", "valueMaps",
                       "templateDashboards")


def import_rules(delete_missing: bool) -> dict:
    rules = {"template_groups": {"createMissing": True, "updateExisting": True},
             "templates": {"createMissing": True, "updateExisting": True},
             "templateLinkage": {"createMissing": True, "deleteMissing": False}}
    for k in IMPORT_RULES_DELETE:
        rules[k] = {"createMissing": True, "updateExisting": True, "deleteMissing": delete_missing}
    return rules


def file_scope(data: dict, scope: zbxlib.Scope) -> tuple[list[str], list[str]]:
    """(template names in the file, problems: templates or groups outside the managed template groups)."""
    ex = (data or {}).get("zabbix_export") or {}
    bad = [f"template group {g.get('name')}" for g in ex.get("template_groups") or []
           if not scope.template_group(str(g.get("name")))]
    names = []
    for t in ex.get("templates") or []:
        names.append(str(t.get("template")))
        groups = [str(g.get("name")) for g in t.get("groups") or []]
        if not groups or not all(scope.template_group(g) for g in groups):
            bad.append(f"template {t.get('template')} (groups {', '.join(groups) or 'none'})")
    if ex.get("hosts") or ex.get("host_groups"):
        bad.append("hosts or host groups (only templates are imported here)")
    return names, bad


def summarize(diff, path="") -> list[str]:
    """importcompare's nested result as `templates/X/items: 2 added, 1 removed, 3 updated` lines."""
    out = []
    if isinstance(diff, dict):
        counts = {k: len(diff[k]) for k in ("added", "removed", "updated") if isinstance(diff.get(k), list) and diff[k]}
        if counts:
            out.append(f"{path or '/'}: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
        for k, v in diff.items():
            if k in ("added", "removed"):
                continue
            if k == "updated" and isinstance(v, list):
                for u in v:
                    after = (u or {}).get("after") or {}
                    label = after.get("template") or after.get("name") or after.get("key") or "?"
                    out += summarize({kk: vv for kk, vv in (u or {}).items() if kk not in ("before", "after")},
                                     f"{path}/{hmlib.clean(label, 60)}")
            else:
                out += summarize(v, f"{path}/{k}")
    return out


def cmd_template_import(a, cfg) -> int:
    root = Path(cfg["_root"])
    f = Path(a.file)
    f = f if f.is_absolute() else Path.cwd() / f
    data = zbxlib.load_yaml(f)
    if data is None:
        raise hmlib.ConfigError(f"{a.file} not found")
    names, bad = file_scope(data, zbxlib.Scope(zbxlib.settings(cfg)))
    if bad:
        raise hmlib.ConfigError("outside zabbix.managed_scope.template_groups, not imported: " + "; ".join(bad))
    if not names:
        raise hmlib.ConfigError(f"{a.file} has no templates")
    c = zbxlib.connect(cfg, "rw")
    text = f.read_text()
    rules = import_rules(not a.keep_missing)
    lines = summarize(c.call("configuration.importcompare", {"format": "yaml", "rules": rules, "source": text}))
    print(f"{a.file}: {len(names)} template(s): {', '.join(names)}")
    print("\n".join("  " + x for x in lines) if lines else "  no changes")
    if a.compare or not lines:
        return 0
    existing = [t["templateid"] for t in c.call("template.get", {"output": ["templateid"],
                                                                  "filter": {"host": names}}) or []]
    if existing:
        backup = root / "zabbix" / "export" / f"rollback-{time.strftime('%Y%m%d-%H%M%S')}.yaml"
        backup.parent.mkdir(parents=True, exist_ok=True)
        hmlib.atomic_write(backup, c.call("configuration.export", {"format": "yaml",
                                                                     "options": {"templates": existing}}))
        print(f"  saved the current version to {backup.relative_to(root)} (import it to roll back)")
    c.call("configuration.import", {"format": "yaml", "rules": rules, "source": text})
    print(f"Imported {len(names)} template(s).")
    return 0


def add_parsers(sub):
    p = sub.add_parser("templates")
    p.add_argument("--upstream", action="store_true")
    p.add_argument("--branch")
    p = sub.add_parser("template-fetch")
    p.add_argument("names", nargs="+")
    p.add_argument("--branch")
    p = sub.add_parser("template-import")
    p.add_argument("file")
    p.add_argument("--compare", action="store_true")
    p.add_argument("--keep-missing", action="store_true",
                   help="keep items, triggers… the new version no longer has (default: remove them, as Zabbix advises)")


HANDLERS = {"templates": cmd_templates, "template-fetch": cmd_template_fetch, "template-import": cmd_template_import}
