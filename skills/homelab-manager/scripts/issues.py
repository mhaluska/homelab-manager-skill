#!/usr/bin/env python3
"""Problems with the homelab-manager skill itself: kept in ISSUES.md, reported to the plugin's GitHub repository.

    issues.py add --title T --kind script|guard|instructions|setup|template|other
                  [--body-file F | --body TEXT] [--key K]
    issues.py list [--status open|reported|resolved|all]
    issues.py show SKILL-002
    issues.py report [--dry-run] [--match SKILL-002=42] [--new SKILL-003] [IDS…]
                                              # send new/changed issues to the plugin repository: comment on
                                              # the same/similar GitHub issue or create one, then set the
                                              # "reported through" marker so they aren't sent again
    issues.py resolve SKILL-002 [--note TEXT]
    issues.py reopen SKILL-002
    issues.py template                        # the sections every issue body follows
    issues.py migrate [--dry-run]             # repos set up before 0.6.0: move homelab entries to
                                              # docs/issues-archive.md (init_repo.py --sync-managed runs it)

What belongs here: a bundled script crashed or gave wrong results, the guard hook blocked a
legitimate command or let a dangerous one through, a template failed to validate, the skill's
instructions were wrong, missing or outdated, the setup misbehaved, or the user says the skill
did something wrong. Problems in the homelab (drift, audit findings, failed patch runs) are NOT
tracked here: they are reported in chat and in discovery/drift.md or docs/security-audit-<date>.md.

The plugin repository is public. `report` sanitises everything it sends (IP and MAC addresses, the
site domain, host and guest names from the inventory and discovery snapshots, the user name and
home path, tokens, keys and passwords); `--dry-run` prints exactly what would be sent.
Each body gets an Environment section (plugin, macOS, Python and tool versions, enabled components).
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

KINDS = ("script", "guard", "instructions", "setup", "template", "other")
STATUSES = ("open", "reported", "resolved")
META_RE = re.compile(r"^<!-- issue (\{.*\}) -->$")
MARK_RE = re.compile(r"^<!-- reported-through: (\S+) -->$")
KEY_RE = re.compile(r"<!-- hm-key: (\S+) -->")
HEADING_RE = re.compile(r"^## (ISSUE|SKILL)-\d+ ")
TEMPLATE = Path(__file__).resolve().parent.parent / "assets" / "issue-template.md"
PLUGIN_JSON = hmlib.PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
SECTIONS = ["Summary", "Steps to reproduce", "Expected", "Actual", "Evidence", "Environment", "Proposed fix"]
OPTIONAL = {"Proposed fix"}
TRIAGE = {"ADMIN", "MAINTAIN", "WRITE", "TRIAGE"}
GH = os.environ.get("HM_GH", "gh")  # overridable for tests
MATCH_THRESHOLD = 0.5
ARCHIVE = "docs/issues-archive.md"
OLD_HEADER_MARK = "Problems found while managing this homelab"
HEADER = """# Issues with the homelab-manager skill

Problems with the **skill itself** — a script that crashed or gave wrong results, the safety hook
blocking something legitimate (or letting something dangerous through), a template that doesn't
validate, instructions that were wrong or missing, a setup step that misbehaved. They can be sent
to the plugin's GitHub repository so they get fixed.

Problems in the homelab (drift, audit findings, failed runs) are not tracked here: Claude reports
them in chat and in `discovery/drift.md` / `docs/security-audit-<date>.md`.

- Note one: *"the skill got X wrong, write it down"* — Claude adds it with `issues.py`.
- Send new/changed ones: *"report skill issues"* — sanitised (no IPs, host names, user names,
  secrets), checked against existing GitHub issues first, shown to you before anything is sent.
- Managed by `issues.py`; edit the text under an issue freely, keep the `<!-- issue … -->` lines.

"""


def today():
    return dt.date.today().isoformat()


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def ts(v: str) -> dt.datetime:
    return dt.datetime.fromisoformat(v)


def seen_at(i: dict) -> str:
    return i.get("seen_at") or f"{i.get('last_seen') or i['found']}T00:00:00+00:00"


def plugin_info() -> dict:
    try:
        return json.loads(PLUGIN_JSON.read_text())
    except (OSError, ValueError):
        return {}


def plugin_repo() -> str:
    if os.environ.get("HM_ISSUES_REPO"):
        return os.environ["HM_ISSUES_REPO"]
    url = plugin_info().get("repository") or ""
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$", url)
    if not m:
        raise SystemExit("plugin.json has no GitHub repository URL — can't tell where to report.")
    return m.group(1)


def read_marker(path: Path) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        m = MARK_RE.match(line.strip())
        if m:
            return m.group(1)
    return None


def issues_path(cfg) -> Path:
    return Path(cfg["_root"]) / (hmlib.get(cfg, "issues.file") or "ISSUES.md")


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    items, cur = [], None
    for line in path.read_text().splitlines():
        m = META_RE.match(line.strip())
        if m:
            cur = json.loads(m.group(1))
            cur["body"] = []
            items.append(cur)
        elif line.startswith("<!-- /issue -->"):
            cur = None
        elif cur is not None and not HEADING_RE.match(line):
            cur["body"].append(line)
    for it in items:
        it["body"] = "\n".join(it["body"]).strip("\n")
        it["body"] = re.sub(r"^- \*\*(Kind|Severity):\*\*.*\n?", "", it["body"]).strip("\n")
        if it["body"] == "_No details._":
            it["body"] = ""
    return items


def render(items: list[dict], marker: str | None = None) -> str:
    out = [HEADER]
    if marker:
        out += [f"<!-- reported-through: {marker} -->",
                f"_Last reported: {marker.replace('T', ' ')[:16]} UTC — only issues added or changed "
                "after this are sent next time._", ""]
    order = {"open": 0, "reported": 1, "resolved": 2}
    rows = sorted(items, key=lambda i: (order.get(i["status"], 9), i["id"]))
    out += ["| ID | Kind | Title | Status | GitHub |", "|---|---|---|---|---|"]
    for i in rows:
        gh = f"[#{i['github_number']}]({i['github_url']})" if i.get("github_url") else "—"
        out.append(f"| {i['id']} | {i['kind']} | {i['title'].replace('|', '/')} | {i['status']} | {gh} |")
    if not items:
        out.append("| — | | No issues recorded yet. | | |")
    out.append("")
    for i in sorted(items, key=lambda i: i["id"]):
        meta = {k: v for k, v in i.items() if k != "body"}
        out.append(f"## {i['id']} — {i['title']}")
        out.append(f"<!-- issue {json.dumps(meta, ensure_ascii=False)} -->")
        line = (f"- **Kind:** {i['kind']} · **Found:** {i['found']}"
                + (f" (plugin {i['plugin_version']})" if i.get("plugin_version") else "")
                + (f" · **Last seen:** {i['last_seen']}" if i.get("last_seen") and i["last_seen"] != i["found"] else "")
                + f" · **Status:** {i['status']}"
                + (f" ([GitHub #{i['github_number']}]({i['github_url']}))" if i.get("github_url") else "")
                + (f" · **Resolved:** {i['resolved']}" if i.get("resolved") else ""))
        out += [line, "", i["body"].strip() or "_No details._", "<!-- /issue -->", ""]
    return "\n".join(out).rstrip() + "\n"


def save(path: Path, items, marker: str | None = None):
    path.write_text(render(items, marker or read_marker(path)))


def find(items, ident: str) -> dict:
    ident = ident.upper()
    if re.fullmatch(r"\d+", ident):
        ident = f"SKILL-{int(ident):03d}"
    for i in items:
        if i["id"] == ident:
            return i
    raise SystemExit(f"{ident} not found in ISSUES.md")


def sections(body: str) -> dict[str, str]:
    """Split a body into its `### Heading` sections (text before the first heading → "")."""
    out, cur = {"": []}, ""
    for line in body.splitlines():
        m = re.match(r"^#{2,3}\s+(.+?)\s*$", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
        else:
            out[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in out.items()}


def structure(body: str, env: str | None = None) -> tuple[str, list[str]]:
    """Return the body in template order plus the required sections that had to be marked unknown."""
    sec = {k: ("" if v == "_No response_" else v) for k, v in sections(body).items()}
    if sec.get("") and "Summary" not in sec:
        sec["Summary"] = sec.pop("")
    if env is not None:
        sec["Environment"] = env
    lead = sec.pop("", "")
    blank = [n for n in SECTIONS if n not in OPTIONAL and (not sec.get(n) or sec[n] == "_unknown_")]
    parts = [lead] if lead else []
    for n in SECTIONS + [k for k in sec if k not in SECTIONS]:
        parts.append(f"### {n}\n{sec.get(n) or ('_none_' if n in OPTIONAL else '_unknown_')}")
    return "\n\n".join(parts), blank


# ---- environment and sanitising ----

TOOLS = [("tofu", ["tofu", "version"]), ("packer", ["packer", "version"]), ("ansible", ["ansible", "--version"]),
         ("nmap", ["nmap", "--version"]), ("yq", ["yq", "--version"]), ("gh", ["gh", "--version"])]


def first_line(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    line = ((r.stdout or r.stderr).strip().splitlines() or [""])[0]
    return hmlib.clean(line, 80) or None


def environment(cfg) -> str:
    lines = [f"- homelab-manager {plugin_info().get('version', '?')}"]
    mac = first_line(["sw_vers", "-productVersion"])
    lines.append(f"- macOS {mac}" if mac else f"- {platform.system()} {platform.release()}")
    lines.append(f"- Python {platform.python_version()}")
    for name, cmd in TOOLS:
        v = first_line(cmd)
        if v:
            lines.append(f"- {name}: {v}")
    comps = [k for k, v in (cfg.get("components") or {}).items() if v is True]
    lines.append(f"- components: {', '.join(comps) or 'none recorded'}")
    backend = hmlib.get(cfg, "opentofu.state_backend")
    if backend:
        lines.append(f"- OpenTofu state: {backend}")
    return "\n".join(lines)


SECRET_RES = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), "<private-key>"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "<token>"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "<token>"),
    (re.compile(r"PVEAPIToken=\S+"), "PVEAPIToken=<token>"),
    (re.compile(r"\b[\w.-]+@[\w.-]+![\w.-]+[=:][0-9a-fA-F-]{36}\b"), "<proxmox-token>"),
    (re.compile(r"(?i)\b(authorization:\s*)(bearer\s+|token\s+|basic\s+)?\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)(\s*[:=]\s*)(?!<)\S+"), r"\1\2<redacted>"),
]
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])")
MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
GENERIC = {"homelab", "localhost", "local", "proxmox", "pve", "main", "default", "all", "ungrouped", "linux",
           "windows", "appliances", "kubernetes", "template", "templates", "none", "null", "true", "false", "root",
           "admin", "user", "users", "staff", "runner", "ubuntu", "debian", "rocky"}


def _names_in(obj, out: set):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("name", "hostname", "node", "fqdn", "cluster") and isinstance(v, str):
                out.add(v)
            else:
                _names_in(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _names_in(v, out)


def site_terms(cfg) -> tuple[list[str], list[str]]:
    """(domains, host names) of this site, from homelab.yaml, discovery snapshots and the Ansible inventory."""
    root = Path(cfg["_root"])
    domains = {d for d in [hmlib.get(cfg, "site.domain")] if d}
    hosts = set()
    ep = hmlib.get(cfg, "proxmox.endpoint") or ""
    m = re.match(r"^\w+://([^/:]+)", ep)
    if m:
        hosts.add(m.group(1))
    name = hmlib.get(cfg, "site.name")
    if name:
        hosts.add(name)
    for f in ("discovery/proxmox.json", "discovery/network.json"):
        try:
            _names_in(json.loads((root / f).read_text()), hosts)
        except (OSError, ValueError):
            pass
    inv = sorted(glob.glob(str(root / "ansible" / "inventory" / "**" / "*.y*ml"), recursive=True))
    if inv and shutil.which("yq"):
        r = subprocess.run(["yq", "-o=json", "eval-all",
                            '[.. | select(tag == "!!map" and has("hosts")) | .hosts | select(tag == "!!map") | keys] | flatten',
                            *inv], capture_output=True, text=True, timeout=20)
        try:
            hosts.update(h for h in json.loads(r.stdout or "[]") if isinstance(h, str))
        except ValueError:
            pass
    for h in list(hosts):
        if "." in h and not IPV4.fullmatch(h):
            hosts.add(h.split(".")[0])
            domains.add(h.split(".", 1)[1])
    keep = lambda t: len(t) >= 3 and t.lower() not in GENERIC and not IPV4.fullmatch(t)
    return (sorted(filter(keep, domains), key=len, reverse=True),
            sorted(filter(keep, hosts), key=len, reverse=True))


def sanitize(text: str, cfg) -> str:
    for rx, rep in SECRET_RES:
        text = rx.sub(rep, text)
    home = str(Path.home())
    text = text.replace(home, "~")
    text = re.sub(r"/(Users|home)/[^/\s]+", r"/\1/<user>", text)
    user = getpass.getuser()
    domains, hosts = site_terms(cfg)
    for d in domains:
        text = re.sub(rf"(?i)(?<![\w-]){re.escape(d)}(?![\w-])", "<domain>", text)
    for h in hosts:
        text = re.sub(rf"(?i)(?<![\w-]){re.escape(h)}(?![\w-])", "<host>", text)
    if len(user) >= 3 and user.lower() not in GENERIC:
        text = re.sub(rf"(?<![\w-]){re.escape(user)}(?![\w-])", "<user>", text)
    text = EMAIL.sub("<email>", text)
    text = MAC.sub("<mac>", text)
    text = IPV4.sub(lambda m: m.group(0) if m.group(0) in ("127.0.0.1", "0.0.0.0") else "<ip>", text)
    text = IPV6.sub(lambda m: "<ip6>" if ("::" in m.group(0) or re.search(r"(?i)[a-f]", m.group(0)))
                    and m.group(0).count(":") >= 2 else m.group(0), text)
    return text


# ---- commands ----

def cmd_template(a, cfg=None):
    print(TEMPLATE.read_text().rstrip())
    return 0


def cmd_add(a, cfg):
    path = issues_path(cfg)
    items = load(path)
    body = Path(a.body_file).read_text() if a.body_file else (a.body or "")
    body = "\n".join(hmlib.clean(l, 500) for l in body.splitlines())
    body, blank = structure(body, environment(cfg))
    if blank:
        print(f"note: no {', '.join(blank)} yet — fill {'it' if len(blank) == 1 else 'them'} in "
              "(issues.py template shows what goes where)", file=sys.stderr)
    if a.key:
        for i in items:
            if i.get("key") == a.key and i["status"] != "resolved":
                i["last_seen"] = today()
                if body != i["body"]:
                    i["seen_at"] = now_iso()  # changed → report again
                    i["body"] = body
                save(path, items)
                print(f"{i['id']} already tracked (key {a.key}); last seen updated.")
                return 0
    nums = [int(m.group(1)) for i in items if (m := re.match(r"SKILL-(\d+)$", i["id"]))]
    item = {"id": f"SKILL-{max(nums + [0]) + 1:03d}", "title": hmlib.clean(a.title, 120), "kind": a.kind,
            "status": "open", "found": today(), "seen_at": now_iso(), "key": a.key or "",
            "plugin_version": plugin_info().get("version", ""), "body": body}
    items.append(item)
    save(path, items)
    print(f"Added {item['id']}: {item['title']}")
    return 0


def cmd_list(a, cfg):
    items = load(issues_path(cfg))
    sel = [i for i in items if a.status == "all" or i["status"] == a.status]
    if not sel:
        print("No issues." if a.status == "all" else f"No {a.status} issues.")
    for i in sel:
        print(f"{i['id']}  {i.get('kind', '?'):<12} {i['status']:<8} {i['title']}"
              + (f"  {i['github_url']}" if i.get("github_url") else ""))
    return 0


def cmd_show(a, cfg):
    i = find(load(issues_path(cfg)), a.id)
    print(json.dumps({k: v for k, v in i.items() if k != "body"}, indent=2))
    print("\n" + (i["body"] or "(no details)"))
    return 0


def issue_title(i, cfg) -> str:
    return sanitize(f"[{i['kind']}] {i['title']}", cfg)


def issue_body(i, cfg) -> str:
    return (sanitize(i["body"] or "_No details._", cfg) + "\n\n---\n"
            f"_Reported with `issues.py` of homelab-manager {i.get('plugin_version') or '?'} "
            f"(local {i['id']}); host-specific details were redacted._"
            + (f"\n<!-- hm-key: {i['key']} -->" if i.get("key") else ""))


def update_note(i, cfg) -> str:
    return (f"**Seen again {seen_at(i)[:10]}** with homelab-manager {plugin_info().get('version', '?')}\n\n"
            + sanitize(i["body"] or "_No new details._", cfg))


def gh(args, cfg, **kw):
    return subprocess.run([GH, *args], cwd=cfg["_root"], capture_output=True, text=True, **kw)


def labels_to_use(i, repo, cfg) -> list[str]:
    """Only people with triage rights can label issues; others get the maintainer's triage instead."""
    r = gh(["repo", "view", repo, "--json", "viewerPermission", "-q", ".viewerPermission"], cfg)
    if r.returncode != 0 or r.stdout.strip() not in TRIAGE:
        return []
    r = gh(["label", "list", "--repo", repo, "--limit", "1000", "--json", "name"], cfg)
    try:
        have = {l["name"] for l in json.loads(r.stdout or "[]")} if r.returncode == 0 else set()
    except ValueError:
        have = set()
    return [l for l in ("skill-report", f"kind:{i['kind']}") if l in have]


def create_issue(i, repo, cfg) -> str | None:
    """gh issue create; on success record the URL on the item and return None, else an error."""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(issue_body(i, cfg))
    labels = labels_to_use(i, repo, cfg)
    try:
        r = gh(["issue", "create", "--repo", repo, "--title", issue_title(i, cfg), "--body-file", f.name]
               + (["--label", ",".join(labels)] if labels else []), cfg)
    finally:
        Path(f.name).unlink()
    if r.returncode != 0:
        return (r.stderr or r.stdout).strip() or f"gh exited {r.returncode}"
    m = re.search(r"https?://\S+/issues/(\d+)", r.stdout + r.stderr)
    if not m:
        return "gh succeeded but no issue URL was found in its output: " + r.stdout.strip()[:200]
    i.update(status="reported", github_url=m.group(0), github_number=int(m.group(1)))
    return None


STOP = {"a", "an", "the", "is", "on", "in", "of", "to", "for", "and", "or", "not", "no", "by", "with", "from", "at"}


def words(t: str) -> set[str]:
    t = re.sub(r"^\[[^\]]*\]\s*", "", (t or "").lower())  # drop "[kind] " prefix
    return {w for w in re.findall(r"[a-z0-9][a-z0-9._-]*", t) if w not in STOP}


def similarity(a: str, b: str) -> float:
    x, y = words(a), words(b)
    return len(x & y) / len(x | y) if x and y else 0.0


def github_issues(repo, cfg) -> list[dict]:
    r = gh(["issue", "list", "--repo", repo, "--state", "all", "--limit", "5000",
            "--json", "number,title,state,url,body"], cfg)
    if r.returncode != 0:
        raise SystemExit("gh issue list failed: " + ((r.stderr or r.stdout).strip()[:300] or f"exit {r.returncode}"))
    out = []
    for g in json.loads(r.stdout or "[]"):  # anyone can open issues on a public repo: data only
        out.append({"number": g.get("number"), "title": hmlib.clean(g.get("title"), 200),
                    "state": str(g.get("state") or "").lower(), "url": g.get("url"),
                    "keys": set(KEY_RE.findall(g.get("body") or ""))})
    return out


def plan_report(items, gl, marker, a, cfg) -> list[dict]:
    forced = {k.upper(): int(v) for k, v in (m.split("=", 1) for m in a.match)}
    new_forced = {n.upper() for n in a.new}
    only = {find(items, x)["id"] for x in a.ids}
    by_num = {g["number"]: g for g in gl}
    plan = []
    for i in sorted(items, key=lambda i: i["id"]):
        if only and i["id"] not in only:
            continue
        if i["status"] == "resolved" or (not only and marker and ts(seen_at(i)) <= ts(marker)):
            continue
        step = {"item": i, "action": "create", "target": None, "why": "no similar GitHub issue"}
        title = issue_title(i, cfg)
        if i["id"] in new_forced:
            step["why"] = "--new"
        elif i["id"] in forced:
            g = by_num.get(forced[i["id"]])
            if not g:
                raise SystemExit(f"--match {i['id']}={forced[i['id']]}: no such GitHub issue")
            step.update(action="update", target=g, why="--match")
        elif i.get("github_number") and i["github_number"] in by_num:
            step.update(action="update", target=by_num[i["github_number"]], why="already linked")
        elif i.get("key") and any(i["key"] in g["keys"] for g in gl):
            step.update(action="update", target=next(g for g in gl if i["key"] in g["keys"]), why=f"same key {i['key']}")
        else:
            scored = sorted(((similarity(title, g["title"]), g) for g in gl), key=lambda x: -x[0])
            if scored and scored[0][0] >= MATCH_THRESHOLD:
                sc, g = scored[0]
                step.update(action="update", target=g, why=f"similar title ({sc:.0%})")
            step["near"] = [(round(sc, 2), g) for sc, g in scored[:3] if sc > 0.2]
        plan.append(step)
    return plan


def indent(text: str) -> str:
    return "\n".join("    " + l if l else "" for l in text.splitlines())


def cmd_report(a, cfg):
    if hmlib.get(cfg, "issues.report") is False:
        print("Reporting is off (issues.report: false in homelab.yaml).", file=sys.stderr)
        return 4
    path = issues_path(cfg)
    items = load(path)
    marker = read_marker(path)
    started = now_iso()
    repo = plugin_repo()
    try:
        gl = github_issues(repo, cfg)
    except SystemExit as e:
        if not a.dry_run:
            raise
        print(f"warning: {e} — existing issues not checked (gh auth status?)", file=sys.stderr)
        gl = []
    plan = plan_report(items, gl, marker, a, cfg)
    print(f"Target: {repo} (public) — reported through: {marker or 'never'} — "
          f"{len(plan)} issue(s) to report, {len(gl)} GitHub issue(s) checked")
    for st in plan:
        i, g = st["item"], st["target"]
        if st["action"] == "update":
            print(f"\n{i['id']}  UPDATE #{g['number']} ({g['state']}) \"{g['title']}\"  — {st['why']}"
                  + ("  [closed on GitHub: comment only, not reopened]" if g["state"] == "closed" else ""))
            if a.dry_run:
                print("  comment:\n" + indent(update_note(i, cfg)))
        else:
            print(f"\n{i['id']}  CREATE \"{issue_title(i, cfg)}\"  — {st['why']}")
            for sc, n in st.get("near", []):
                print(f"    near: #{n['number']} ({sc:.0%}) \"{n['title']}\"")
            if a.dry_run:
                print("  body:\n" + indent(issue_body(i, cfg)))
    if a.dry_run:
        print("\nDry run — nothing sent. Read the text above: anything still site-specific? Edit the issue in "
              "ISSUES.md and re-run. Override matches with --match ID=NUMBER or --new ID.")
        return 0
    failed = []
    for st in plan:
        i, g = st["item"], st["target"]
        if st["action"] == "update":
            r = gh(["issue", "comment", str(g["number"]), "--repo", repo, "--body-file", "-"], cfg, input=update_note(i, cfg))
            if r.returncode != 0:
                failed.append(f"{i['id']}: {(r.stderr or r.stdout).strip()[:200]}")
                continue
            if not i.get("github_url"):
                i.update(status="reported", github_url=g["url"], github_number=g["number"])
            print(f"{i['id']} → commented on #{g['number']} {g['url']}")
        else:
            err = create_issue(i, repo, cfg)
            if err:
                failed.append(f"{i['id']}: {err[:200]}")
                continue
            print(f"{i['id']} → created {i['github_url']}")
    if failed:
        save(path, items)  # keep links that did succeed; marker unchanged so failures are retried
        print("Failed (marker not moved, re-run to retry):\n  " + "\n  ".join(failed), file=sys.stderr)
        return 1
    save(path, items, started)
    print(f"Marker set: reported through {started}")
    return 0


def cmd_status(a, cfg, status):
    path = issues_path(cfg)
    items = load(path)
    i = find(items, a.id)
    i["status"] = status if status != "open" or not i.get("github_url") else "reported"
    if status == "resolved":
        i["resolved"] = today()
        if a.note:
            i["body"] = (i["body"] + f"\n\n**Resolution ({today()}):** {a.note}").strip()
    else:
        i.pop("resolved", None)
    save(path, items)
    print(f"{i['id']} → {i['status']}")
    return 0


# ---- migration from the homelab-issue tracker (before 0.6.0) ----

def render_archived(i: dict) -> str:
    gh_link = f" · [GitHub #{i['github_number']}]({i['github_url']})" if i.get("github_url") else ""
    return (f"## {i['id']} — {i['title']}\n"
            f"- Severity: {i.get('severity', '?')} · Area: {i.get('area', '?')} · Found: {i.get('found', '?')}"
            f" · Status: {i.get('status', '?')}{gh_link}\n\n{i['body'].strip() or '_No details._'}\n")


def migrate(root: Path, dry_run: bool) -> list[str]:
    """Homelab problems are no longer tracked: move old entries to docs/issues-archive.md, reset the header."""
    try:
        cfg = hmlib.load_config(root)
        path = issues_path(cfg)
    except hmlib.ConfigError:
        path = Path(root) / "ISSUES.md"
    if not path.exists():
        return []
    items = load(path)
    old = [i for i in items if "kind" not in i]
    if not old and OLD_HEADER_MARK not in path.read_text():
        return []
    rel = path.relative_to(root).as_posix()
    msgs = ([f"move {len(old)} homelab issue(s) from {rel} to {ARCHIVE} (homelab problems aren't tracked any more)"]
            if old else []) + [f"{rel}: new header — it now tracks problems with the skill itself"]
    if dry_run:
        return msgs
    if old:
        archive = Path(root) / ARCHIVE
        archive.parent.mkdir(parents=True, exist_ok=True)
        head = "" if archive.exists() else (
            "# Archived homelab issues\n\nTracked in ISSUES.md until homelab-manager 0.6.0. Homelab problems are now "
            "reported in chat and in `discovery/drift.md` / `docs/security-audit-<date>.md` instead; this file is "
            "kept for reference only.\n\n")
        with archive.open("a") as f:
            f.write(head + f"_Archived {today()}._\n\n" + "\n".join(render_archived(i) for i in old) + "\n")
    path.write_text(render([i for i in items if "kind" in i], None))
    return msgs


def cmd_migrate(a, cfg):
    msgs = migrate(Path(cfg["_root"]), a.dry_run)
    print("\n".join(("would " if a.dry_run else "") + m for m in msgs) or "ISSUES.md is already in the current format.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("add")
    p.add_argument("--title", required=True)
    p.add_argument("--kind", choices=KINDS, required=True,
                   help="script: a bundled script failed · guard: hook blocked/allowed wrongly · instructions: "
                        "SKILL.md/references wrong or missing · setup · template: scaffolded files don't work")
    p.add_argument("--key", help="stable dedupe key, e.g. script:drift_report:keyerror-backup_jobs")
    p.add_argument("--body")
    p.add_argument("--body-file")
    p = sp.add_parser("list")
    p.add_argument("--status", choices=STATUSES + ("all",), default="all")
    sp.add_parser("template")
    p = sp.add_parser("migrate")
    p.add_argument("--dry-run", action="store_true")
    p = sp.add_parser("report")
    p.add_argument("ids", nargs="*", help="limit to these issues (ignores the marker)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--match", action="append", default=[], metavar="ID=NUMBER",
                   help="comment on this GitHub issue instead of the automatic choice")
    p.add_argument("--new", action="append", default=[], metavar="ID", help="create even if a similar one exists")
    for name in ("show", "resolve", "reopen"):
        p = sp.add_parser(name)
        p.add_argument("id")
        if name == "resolve":
            p.add_argument("--note")
    a = ap.parse_args()
    if a.cmd == "template":
        return cmd_template(a)
    try:
        cfg = hmlib.load_config()
    except hmlib.ConfigError as e:
        print(f"issues: {e}", file=sys.stderr)
        return 3
    return {"add": cmd_add, "list": cmd_list, "show": cmd_show, "report": cmd_report, "migrate": cmd_migrate,
            "resolve": lambda a, c: cmd_status(a, c, "resolved"),
            "reopen": lambda a, c: cmd_status(a, c, "open")}[a.cmd](a, cfg)


if __name__ == "__main__":
    sys.exit(main())
