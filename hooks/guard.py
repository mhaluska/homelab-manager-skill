#!/usr/bin/env python3
"""PreToolUse guard for Bash commands — the enforced part of homelab-manager's safety rules.

The skill text tells Claude how to behave; this hook makes the important rules hold
even if Claude gets it wrong. It returns one of:
  deny  — never allowed (scan outside authorized ranges, -auto-approve, printing secrets)
  ask   — the user must approve in the Claude app (destroy, replace, reboot, patching, …)
  (no output) — normal Claude Code permission handling

It also scans the contents of scripts that a command executes, so wrapping a
dangerous command in a generated script does not bypass approval.
Fails closed: if the hook itself errors on a command that looks infrastructure
related, it asks.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "skills" / "homelab-manager" / "scripts"))
import hmlib  # noqa: E402

DENY, ASK = "deny", "ask"

# (regex, decision, reason). Applied to the command text and to executed script contents.
RULES: list[tuple[re.Pattern, str, str]] = [
    # --- never ---------------------------------------------------------------------
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\s--?auto-approve\b"), DENY,
     "-auto-approve skips plan review. Run `tofu plan -out=<file>`, show the plan to the user, then `tofu apply <file>`."),
    (re.compile(r"\bsecurity\s+find-(generic|internet)-password\b[^\n;&|]*\s-[wg]\b"), DENY,
     "This would print a keychain secret. Use scripts/with_secrets.py, which injects it into the command's environment without printing it."),
    (re.compile(r"\bsecurity\s+(dump-keychain|export)\b"), DENY, "Dumping or exporting the keychain is not allowed."),
    (re.compile(r"\b(cat|less|more|head|tail|bat|cp|mv|scp|rsync|base64|xxd|od|strings|openssl|pbcopy|grep|awk|sed)\b"
                r"[^\n;&|]*\.ssh/id_[A-Za-z0-9_-]+(?![A-Za-z0-9_.-])"), DENY,
     "Private SSH keys must not be read, copied or printed. Use the SSH agent (ssh-add -L lists public keys)."),
    (re.compile(r"\bnmap\b[^\n;&|]*\s-iR\b"), DENY, "Random-target scanning (-iR) is never allowed."),
    (re.compile(r"\bnmap\b[^\n;&|]*\s-D\s"), DENY, "Decoy scanning (-D) is not allowed."),
    # --- OpenTofu state / destructive -----------------------------------------------
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\s(destroy|taint|untaint|force-unlock)\b"), ASK,
     "Destroys resources or overrides state/locks."),
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\sstate\s+(rm|mv|push|replace-provider)\b"), ASK,
     "Edits OpenTofu state directly."),
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\simport\b"), ASK, "Imports an existing resource into OpenTofu state."),
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\s-replace="), ASK, "Forces replacement (destroy + recreate) of a resource."),
    # --- Proxmox CLI / API -------------------------------------------------------------
    (re.compile(r"\b(qm|pct)\s+(destroy|stop|shutdown|reboot|reset|suspend|migrate|remote-migrate|resize|set|create|clone|"
                r"restore|importdisk|import|disk|move[-_]disk|move[-_]volume|rollback|delsnapshot|template|unlock|mount)\b"), ASK,
     "Changes a Proxmox VM/container directly (outside OpenTofu)."),
    (re.compile(r"\bpvesh\s+(create|set|delete)\b"), ASK, "Writes to the Proxmox API."),
    (re.compile(r"\bpvecm\s+(add|addnode|delnode|expected|create|updatecerts)\b"), ASK, "Changes Proxmox cluster membership/quorum."),
    (re.compile(r"\bha-manager\s+(add|remove|set|migrate|relocate|crm-command)\b"), ASK, "Changes Proxmox HA configuration."),
    (re.compile(r"\bpvesm\s+(add|remove|set|free|alloc)\b"), ASK, "Changes Proxmox storage."),
    (re.compile(r"\b(zfs\s+(destroy|rollback)|zpool\s+(destroy|remove|detach|offline|labelclear))\b"), ASK, "Destructive ZFS operation."),
    (re.compile(r"\b(curl|wget|http|xh)\b[^\n;&|]*api2[^\n;&|]*(-X\s*(POST|PUT|DELETE)|--request\s+(POST|PUT|DELETE)|\s-d\s|--data)"
                r"|\b(curl|wget|http|xh)\b[^\n;&|]*(-X\s*(POST|PUT|DELETE)|--request\s+(POST|PUT|DELETE)|\s-d\s|--data)[^\n;&|]*api2"), ASK,
     "Writes to the Proxmox API directly."),
    # --- reboots / patching -----------------------------------------------------------
    (re.compile(r"\b(ssh|ansible)(?![\w-])[^\n]*\b(reboot|shutdown|poweroff|halt|init\s+[06])\b"), ASK, "Reboots or shuts down remote systems."),
    (re.compile(r"\bsystemctl\s+(reboot|poweroff|halt|kexec)\b"), ASK, "Reboots or shuts down a system."),
    (re.compile(r"\bansible\b[^\n]*-m\s+(ansible\.(builtin|windows)\.)?(win_)?reboot\b"), ASK, "Reboots remote systems."),
    (re.compile(r"\bRestart-Computer\b|\bStop-Computer\b"), ASK, "Reboots or shuts down Windows systems."),
    # --- GitHub (gh) / issue tracker --------------------------------------------------
    (re.compile(r"\bgh\s+auth\s+token\b|\bgh\s+auth\s+status\b[^\n;&|]*(--show-token|\s-t\b)"), DENY,
     "This would print the GitHub token."),
    (re.compile(r"\bgh\s+issue\s+(create|close|delete|edit|comment|reopen|transfer|lock|unlock|pin|unpin)\b"), ASK,
     "Creates or changes a GitHub issue (public on a public repository)."),
    (re.compile(r"\bgh\s+(label\s+(create|edit|delete|clone)|release\s+(create|delete|edit|upload)"
                r"|repo\s+(delete|archive|rename|edit)|secret\s+(set|delete)|variable\s+(set|delete)"
                r"|pr\s+merge|workflow\s+run)\b"), ASK, "Changes the GitHub repository or its settings."),
    (re.compile(r"\bgh\s+api\b(?![^\n;&|]*(-X|--method)\s*GET)[^\n;&|]*((-X|--method)\s*(POST|PUT|PATCH|DELETE)"
                r"|\s(-f|-F|--field|--raw-field|--input)\b)"), ASK, "Writes to the GitHub API."),
    (re.compile(r"issues\.py\b[^\n;&|]*\s(open|report)\b(?![^\n;&|]*--dry-run)"), ASK,
     "Sends skill issues from skill_issues.md to the plugin's public GitHub repository (gh issue create / comment)."),
    # --- templates / git / misc -------------------------------------------------------
    (re.compile(r"\bpacker\s+build\b[^\n;&|]*\s-force\b"), ASK, "packer build -force overwrites an existing template."),
    (re.compile(r"\bgit\s+push\b[^\n;&|]*\s(--force|--force-with-lease|-f)\b"), ASK, "Force-push rewrites Git history."),
    (re.compile(r"\brm\b[^\n;&|]*(\.tfstate|\.terraform\b)"), ASK, "Deletes OpenTofu state or the provider directory."),
    (re.compile(r"(\bcurl\b|\bwget\b|base64\s+(-d|--decode|-D))[^\n;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"), ASK,
     "Pipes downloaded or decoded content into a shell."),
    (re.compile(r"\bsudo\s+nmap\b"), ASK, "Runs nmap as root (OS detection). Root nmap can do anything on this Mac."),
    (re.compile(r"\bnmap\b[^\n;&|]*\s(--script(?=[\s=]|$)|-sC\b|-A\b)"), ASK, "NSE scripts are intrusive."),
    (re.compile(r"nmap_scan\.py\b[^\n;&|]*--profile[ =]os\b"), ASK, "OS detection needs `sudo nmap -O`."),
    (re.compile(r"(config_set\.py|\byq\b[^\n;&|]*\s-i\b)[^\n;&|]*authorized_ranges\s*\+?=(?!=)"), ASK,
     "Widens the scan scope (network.authorized_ranges): only for ranges the user owns, with their yes."),
]

# ansible-playbook runs that change systems in high-impact ways
HIGH_IMPACT_PLAYBOOK = re.compile(r"(patch|upgrade|reboot|remove|destroy|decommission|rolling|drain|uninstall)", re.I)

# nmap options whose next argument is a value, not a target
NMAP_VALUE_OPTS = {"-p", "-oX", "-oN", "-oG", "-oA", "-oS", "-oM", "-iL", "--exclude", "--excludefile", "-e", "-S", "-D",
                   "--top-ports", "--script", "--script-args", "--max-retries", "--host-timeout", "--source-port", "-g",
                   "--data-length", "--min-rate", "--max-rate", "--min-parallelism", "--max-parallelism",
                   "--scan-delay", "--max-scan-delay", "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout",
                   "--version-intensity", "--ttl", "--dns-servers", "--stylesheet", "--datadir", "--resume", "-M",
                   "--port-ratio", "--exclude-ports", "--proxies", "--spoof-mac", "--mtu", "-iR",
                   "--stats-every", "--min-hostgroup", "--max-hostgroup", "--max-os-tries", "--script-timeout",
                   "--script-args-file", "--script-help", "--scanflags", "--servicedb", "--versiondb", "--data",
                   "--data-string", "--ip-options"}
# nmap_scan.py options whose next argument is a value, not a target
NMAP_SCAN_VALUE_OPTS = {"--profile", "--ports", "--top-ports", "--out", "--interface", "-e"}

SCRIPT_RUNNERS = {"bash", "sh", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node", "source", "."}
INFRA_HINT = re.compile(r"\b(tofu|terraform|packer|ansible|ansible-playbook|nmap|qm|pct|pvesh|ssh|security)\b")


HEREDOC_RUNNERS = SCRIPT_RUNNERS | {"ssh", "eval", "xargs", "osascript"}
SHELL_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"}


class Shell:
    """Split a command into simple commands the way the shell would: separators inside quotes don't
    split, $(…) and `…` are commands of their own, comments are dropped, and heredoc bodies are
    data unless a command on their line runs them (bash <<EOF, cat <<EOF | sh, ssh host <<EOF).

    segments   — simple commands, in order
    code       — heredoc bodies that a shell/interpreter executes (checked like commands)
    rule_text  — the command without data heredoc bodies (for the RULES regexes)
    """

    def __init__(self, command: str):
        self.s = command
        self.segments: list[str] = []
        self.code: list[str] = []
        self.data_spans: list[tuple[int, int]] = []
        end = self.parse(0, None)
        while end < len(self.s):  # stray `)` or backtick at top level: keep going
            end = self.parse(end + 1, None)
        text, last = [], 0
        for a, b in self.data_spans:
            text.append(self.s[last:a])
            last = b
        self.rule_text = "".join(text) + self.s[last:]

    def flush(self, buf: list[str]):
        t = "".join(buf).strip()
        if t:
            self.segments.append(t)
        buf.clear()

    def squote(self, i: int, buf: list[str]) -> int:
        j = self.s.find("'", i + 1)
        j = len(self.s) - 1 if j < 0 else j
        buf.append(self.s[i:j + 1])
        return j + 1

    def dquote(self, i: int, buf: list[str]) -> int:
        s, n = self.s, len(self.s)
        buf.append('"')
        i += 1
        while i < n:
            c = s[i]
            if c == "\\" and i + 1 < n:
                buf.append(s[i:i + 2])
                i += 2
            elif c == '"':
                buf.append('"')
                return i + 1
            elif s.startswith("$(", i) and not s.startswith("$((", i):
                i = self.parse(i + 2, ")")
                buf.append("$(…)")
            elif c == "`":
                i = self.parse(i + 1, "`")
                buf.append("`…`")
            else:
                buf.append(c)
                i += 1
        return n

    def heredoc_start(self, i: int, buf: list[str], pending: list) -> int:
        """At `<<`: read the delimiter word, remember the heredoc, return the index after the word."""
        s, n = self.s, len(self.s)
        j = i + 2
        strip = j < n and s[j] == "-"
        j += strip
        while j < n and s[j] in " \t":
            j += 1
        k, word = j, []
        while k < n and s[k] not in " \t\n;&|<>()":
            if s[k] in "'\"":
                q = s.find(s[k], k + 1)
                q = n if q < 0 else q
                word.append(s[k + 1:q])
                k = q + 1
            else:
                word.append(s[k].lstrip("\\"))
                k += 1
        if word:
            pending.append(("".join(word), strip))
        buf.append(s[i:k])
        return k

    def heredoc_bodies(self, i: int, pending: list, line_start: int) -> int:
        """At the newline after `<<WORD`: consume the bodies, classify each as code or data."""
        s, n = self.s, len(self.s)
        runs = False
        for seg in self.segments[line_start:]:
            tok = strip_prefix(tokens(seg))
            runs |= bool(tok) and Path(tok[0]).name in HEREDOC_RUNNERS
        for word, strip in pending:
            start = i
            while i < n:
                nl = s.find("\n", i)
                line_end = n if nl < 0 else nl
                line = s[i:line_end]
                i = line_end + 1 if nl >= 0 else n
                if (line.lstrip("\t") if strip else line) == word:
                    body_end = line_end
                    break
            else:
                body_end = n
            if runs:
                self.code.append(s[start:body_end])
            else:
                self.data_spans.append((start, body_end))
        pending.clear()
        return i

    def parse(self, i: int, stop: str | None) -> int:
        s, n = self.s, len(self.s)
        buf: list[str] = []
        pending: list = []
        line_start = len(self.segments)
        depth = 0
        while i < n:
            c = s[i]
            if stop == "`" and c == "`" or stop == ")" and c == ")" and depth == 0:
                self.flush(buf)
                return i + 1
            if c == "\\" and i + 1 < n:
                if s[i + 1] != "\n":
                    buf.append(s[i:i + 2])
                i += 2
            elif c == "'":
                i = self.squote(i, buf)
            elif c == '"':
                i = self.dquote(i, buf)
            elif s.startswith("$(", i) and not s.startswith("$((", i):
                i = self.parse(i + 2, ")")
                buf.append("$(…)")
            elif c == "`":
                i = self.parse(i + 1, "`")
                buf.append("`…`")
            elif c == "#" and (not buf or buf[-1][-1:] in (" ", "\t")):
                nl = s.find("\n", i)
                i = n if nl < 0 else nl
            elif s.startswith("<<", i) and not s.startswith("<<<", i):
                i = self.heredoc_start(i, buf, pending)
            elif c == "\n":
                self.flush(buf)
                i += 1
                if pending:
                    i = self.heredoc_bodies(i, pending, line_start)
                line_start = len(self.segments)
            elif c in ";|" or c == "&" and s[i - 1:i] not in (">", "<") and s[i + 1:i + 2] != ">":
                self.flush(buf)
                i += 1
            elif c in "()":
                depth += 1 if c == "(" else -1 if depth else 0
                self.flush(buf)
                i += 1
            else:
                buf.append(c)
                i += 1
        self.flush(buf)
        return n


def tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, comments=True)
    except ValueError:
        return segment.split()


def strip_prefix(tok: list[str]) -> list[str]:
    """Drop env assignments, sudo/env/time/exec wrappers, and with_secrets.py wrappers."""
    out = list(tok)
    while out:
        t = out[0]
        if t in SHELL_KEYWORDS:
            out = out[1:]
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) or t in ("sudo", "env", "time", "exec", "nohup", "command"):
            out = out[1:]
            while out and out[0].startswith("-") and out[0] != "--":  # sudo -n, env -i, …
                out = out[1:]
            continue
        if t.endswith("with_secrets.py") or (t in ("python3", "python") and len(out) > 1 and out[1].endswith("with_secrets.py")):
            idx = out.index("--") if "--" in out else len(out)
            out = out[idx + 1:]
            continue
        break
    return out


# --------------------------------------------------------------------------- checks

def check_text(text: str) -> list[tuple[str, str]]:
    hits = []
    for rx, decision, reason in RULES:
        if rx.search(text):
            hits.append((decision, reason))
    return hits


def nmap_targets(args: list[str], cwd: str) -> tuple[list[str], list[str]]:
    """Return (targets, problems) for an nmap argv (without the leading 'nmap')."""
    targets, problems = [], []
    i = 0
    while i < len(args):
        a = args[i]
        if a in NMAP_VALUE_OPTS:
            if a == "-iL" and i + 1 < len(args):
                p = Path(cwd, args[i + 1])
                try:
                    targets += [x for x in p.read_text().split() if x and not x.startswith("#")]
                except OSError:
                    problems.append(f"cannot read target list {args[i + 1]}")
            i += 2
            continue
        if a.startswith("-") or re.match(r"^\d*(>>?|<)", a):
            i += 1 + (re.fullmatch(r"\d*(>>?|<)", a) is not None)  # `> file`: skip the file too
            continue
        targets.append(a)
        i += 1
    return targets, problems


def check_nmap(argv: list[str], cwd: str, label: str = "nmap") -> list[tuple[str, str]]:
    targets, problems = nmap_targets(argv, cwd)
    root = hmlib.find_repo_root(cwd)
    if not root:
        return [(ASK, f"{label} outside a homelab-infrastructure repo: no homelab.yaml, so no authorized ranges to check against.")]
    try:
        cfg = hmlib.load_config(root)
        problems += hmlib.check_targets(targets, cfg) if targets else ["no scan targets found"]
    except hmlib.ConfigError as e:
        problems.append(str(e))
    return [(DENY, f"Scan refused: {p}") for p in problems]


def check_tofu_apply(tok: list[str], cwd: str) -> list[tuple[str, str]]:
    """`tofu apply` is fine only with a saved plan that deletes/replaces nothing."""
    if "apply" not in tok:
        return []
    chdir = next((t.split("=", 1)[1] for t in tok if t.startswith("-chdir=")), None)
    after = tok[tok.index("apply") + 1:]
    plan = next((t for t in after if not t.startswith("-")), None)
    if not plan:
        return [(ASK, "`tofu apply` without a saved, reviewed plan file.")]
    workdir = Path(cwd, chdir) if chdir else Path(cwd)
    try:
        res = subprocess.run([tok[0], "show", "-json", plan], cwd=workdir, capture_output=True, text=True, timeout=60)
        data = json.loads(res.stdout)
    except Exception:
        return [(ASK, f"Could not inspect plan {plan} — approve only if you have reviewed it.")]
    risky = []
    for rc in data.get("resource_changes", []):
        actions = rc.get("change", {}).get("actions", [])
        if "delete" in actions:
            risky.append(f"{rc.get('address')} ({'replace' if 'create' in actions else 'delete'})")
    if risky:
        return [(ASK, "Plan deletes or replaces: " + ", ".join(risky[:15]) + (" …" if len(risky) > 15 else ""))]
    return []


def check_ansible_playbook(tok: list[str]) -> list[tuple[str, str]]:
    if "--check" in tok or "-C" in tok or "--syntax-check" in tok or "--list-hosts" in tok or "--list-tasks" in tok:
        return []
    text = " ".join(tok)
    playbooks = " ".join(Path(t).name for t in tok if t.endswith((".yml", ".yaml")))
    if HIGH_IMPACT_PLAYBOOK.search(playbooks) or re.search(r"reboot\w*\s*[=:]\s*(true|yes|1)", text, re.I):
        return [(ASK, "High-impact playbook run (patching/reboot/removal) — not in --check mode.")]
    return []


def script_path(tok: list[str], cwd: str) -> Path | None:
    if not tok:
        return None
    first = tok[0]
    cand = None
    if Path(first).name in SCRIPT_RUNNERS and len(tok) > 1 and not tok[1].startswith("-"):
        cand = tok[1]
    elif "/" in first:
        cand = first
    if not cand:
        return None
    p = Path(os.path.expanduser(cand))
    p = p if p.is_absolute() else Path(cwd) / p
    return p if p.is_file() else None


SSH_VALUE_OPTS = set("bcDEeFIiJLlmOoPpQRSWw")


def inner_command(tok: list[str]) -> str | None:
    """The command string that `bash -c STR`, `eval STR…` or `ssh [opts] host CMD…` runs."""
    name = Path(tok[0]).name
    if name in ("bash", "sh", "zsh", "dash", "ksh") and "-c" in tok[1:-1]:
        return tok[tok.index("-c") + 1]
    if name == "eval":
        return " ".join(tok[1:])
    if name == "ssh":
        i = 1
        while i < len(tok) and tok[i].startswith("-"):
            i += 2 if tok[i][-1] in SSH_VALUE_OPTS and len(tok[i]) == 2 else 1
        return " ".join(tok[i + 1:]) or None
    return None


def evaluate(command: str, cwd: str, depth: int = 0) -> list[tuple[str, str]]:
    sh = Shell(command)
    findings = check_text(sh.rule_text)
    if depth < 3:
        for body in sh.code:  # heredoc a shell or interpreter runs: same checks as a command
            findings += evaluate(body, cwd, depth + 1)
    for seg in sh.segments:
        tok = strip_prefix(tokens(seg))
        if not tok:
            continue
        name = Path(tok[0]).name
        inner = inner_command(tok)
        if inner and depth < 3:
            findings += evaluate(inner, cwd, depth + 1)
        if name == "nmap":
            findings += check_nmap(tok[1:], cwd)
        elif name in ("tofu", "terraform"):
            findings += check_tofu_apply(tok, cwd)
        elif name == "ansible-playbook":
            findings += check_ansible_playbook(tok)
        script = script_path(tok, cwd)
        if script and script.name == "nmap_scan.py":
            args = tok[tok.index(next(t for t in tok if t.endswith("nmap_scan.py"))) + 1:]
            targets = [a for i, a in enumerate(args) if not a.startswith("-")
                       and (i == 0 or args[i - 1] not in NMAP_SCAN_VALUE_OPTS)]
            findings += check_nmap(targets, cwd, label="nmap_scan.py")
        elif script and depth < 2:
            try:
                plugin_owned = script.resolve().is_relative_to(PLUGIN_ROOT)
            except OSError:
                plugin_owned = False
            if not plugin_owned:
                try:
                    content = script.read_text(errors="replace")[:500_000]
                except OSError:
                    content = ""
                for decision, reason in evaluate(content, str(script.parent), depth + 1):
                    findings.append((decision, f"script {script.name}: {reason}"))
                if re.search(r"\bnmap\b", content):
                    findings.append((ASK, f"script {script.name} runs nmap with targets this hook cannot verify."))
    return findings


def decide(findings: list[tuple[str, str]]) -> dict | None:
    if not findings:
        return None
    decision = DENY if any(d == DENY for d, _ in findings) else ASK
    reasons = list(dict.fromkeys(r for d, r in findings if d == decision))
    if decision == DENY:
        reasons.append("If the user confirms this command is legitimate and the guard is wrong, note it as a skill "
                       "issue (issues.py add --kind guard) in this turn; never work around the guard.")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": "homelab-manager guard: " + " | ".join(reasons)}}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command", "")
    cwd = payload.get("cwd") or os.getcwd()
    try:
        out = decide(evaluate(command, cwd))
    except Exception as e:  # fail closed for anything infra-shaped
        out = decide([(ASK, f"guard error ({type(e).__name__}); review this command manually.")]) if INFRA_HINT.search(command) else None
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
