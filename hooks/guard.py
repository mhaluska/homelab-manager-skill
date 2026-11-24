#!/usr/bin/env python3
"""PreToolUse guard for Bash commands — the enforced part of homelab-manager's safety rules.

The skill text tells Claude how to behave; this hook makes the important rules hold
even if Claude gets it wrong. It returns one of:
  deny  — never allowed (scan outside authorized ranges, -auto-approve, printing secrets,
          non-English issues or pull requests on the plugin's own GitHub repository)
  ask   — the user must approve in the Claude app (destroy, replace, reboot, patching, …)
  (no output) — normal Claude Code permission handling

It also scans the contents of scripts that a command executes, so wrapping a
dangerous command in a generated script does not bypass approval.
Fails closed: if the hook itself errors (a broken install, unreadable input, a bug, its time budget used up),
it asks.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "skills" / "homelab-manager" / "scripts"))
try:
    import hmlib  # noqa: E402
except Exception as _e:  # noqa: BLE001 — a broken install must not let commands run unguarded: main() asks
    hmlib = None
    HMLIB_ERROR: Exception | None = _e
else:
    HMLIB_ERROR = None

DENY, ASK = "deny", "ask"
# One time budget for everything a single hook run starts (yq, tofu show, git): hooks.json kills the hook at
# 90 s and Claude Code then runs the command unguarded, so the hook must answer well before that.
BUDGET_S = 45
_deadline: float | None = None   # set by main(); None (tests, imports) = no budget


class OutOfTime(Exception):
    """The hook's time budget is used up: main() asks."""


def time_left(cap: float) -> float:
    """Timeout for the next subprocess: at most cap, and never past the hook's budget."""
    if _deadline is None:
        return cap
    left = _deadline - time.monotonic()
    if left < 2:
        raise OutOfTime()
    return min(cap, left)


_configs: dict[str, dict] = {}


def load_config(root) -> dict:
    """hmlib.load_config once per repository and hook run (each call starts yq)."""
    key = str(root)
    if key not in _configs:
        time_left(20)
        _configs[key] = hmlib.load_config(root)
    return _configs[key]
ISSUES_SEND = "Sends skill issues from skill_issues.md to the plugin's public GitHub repository (gh issue create / comment)."

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
    (re.compile(r"\bgit\b[^\n;&|]*\scredential(-[\w-]+)?\s+(fill|get)\b|\bgit-credential-[\w-]+\s+get\b"
                r"|\bgh\s+auth\s+git-credential\b"), DENY, "This would print a stored Git or GitHub credential."),
    # --- OpenTofu state / destructive -----------------------------------------------
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\s(destroy|taint|untaint|force-unlock)\b"), ASK,
     "Destroys resources or overrides state/locks."),
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\s(plan\b[^\n;&|]*\s--?destroy|apply\b[^\n;&|]*\s--?(destroy|refresh-only))\b"),
     ASK, "Plans or applies destroying every resource (-destroy), or applies a refresh-only run that rewrites state."),
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\sstate\s+(rm|mv|push|replace-provider)\b"), ASK,
     "Edits OpenTofu state directly."),
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\simport\b"), ASK, "Imports an existing resource into OpenTofu state."),
    (re.compile(r"\b(tofu|terraform)\b[^\n;&|]*\s-replace="), ASK, "Forces replacement (destroy + recreate) of a resource."),
    # --- Proxmox CLI / API -------------------------------------------------------------
    (re.compile(r"\b(qm|pct)\s+(destroy|stop|shutdown|reboot|reset|suspend|migrate|remote-migrate|resize|set|create|clone|"
                r"restore|importdisk|import|disk|move[-_]disk|move[-_]volume|rollback|delsnapshot|template|unlock|mount)\b"), ASK,
     "Changes a Proxmox VM/container directly (outside OpenTofu)."),
    (re.compile(r"\bpvesh\s+(create|set|delete)\b"), ASK, "Writes to the Proxmox API."),
    (re.compile(r"pve_snapshot\.py\b[^\n;&|]*\s(delete|rollback)\b"), ASK,
     "Deletes a guest snapshot or rolls a guest back to one (its changes since are lost)."),
    # --- LXD / Incus (containers on a NAS or an LXD/Incus host) -------------------------
    (re.compile(r"lxd_snapshot\.py\b[^\n;&|]*\s(delete|restore)\b"), ASK,
     "Deletes an LXD/Incus snapshot or restores an instance to one (its changes since are lost)."),
    (re.compile(r"\b(lxc|incus)\s+((snapshot\s+)?(delete|rm|restore)\b|query\b[^\n;&|]*(-X\s*|--request[ =])(PUT|PATCH|DELETE)\b)"), ASK,
     "Deletes or restores an LXD/Incus instance or snapshot, or changes it through the API."),
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
    (re.compile(r"\bredfish_command\b|\bipmitool\b[^\n;&|]*\s(power|chassis\s+power|mc\s+reset|raw)\b"), ASK,
     "BMC power or reset action (Redfish/IPMI): powers off or reboots a server."),
    (re.compile(r"\b(set-inform|syswrapper\.sh|upgrade\s+https?://)|\bmca-cli-op\s+(?!info\b)\S"
                # write requests to the Integration API or to the classic API's command/configuration paths
                # (/api/s/<site>/cmd|rest|set|upd|group, GitHub #77); /api/login and the stat/ reads pass
                r"|\b(curl|wget|http|xh)\b[^\n;&|]*(integration/v1|/api/s/[^/\s]+/(cmd|rest|set|upd|group)\b)[^\n;&|]*"
                r"(-X\s*(POST|PUT|PATCH|DELETE)|--request\s+(POST|PUT|PATCH|DELETE)|\s-d\s|--data)"
                r"|\b(curl|wget|http|xh)\b[^\n;&|]*(-X\s*(POST|PUT|PATCH|DELETE)|--request\s+(POST|PUT|PATCH|DELETE)|\s-d\s|--data)"
                r"[^\n;&|]*(integration/v1|/api/s/[^/\s]+/(cmd|rest|set|upd|group)\b)"), ASK,
     "Changes a UniFi device or the UniFi controller (adoption, reset, firmware, configuration)."),
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
    (re.compile(r"issues\.py\b[^\n;&|]*\s(open|report)\b(?![^\n;&|]*--dry-run)"), ASK, ISSUES_SEND),
    (re.compile(r"(config_set\.py|\byq\b[^\n;&|]*\s-i\b)[^\n;&|]*issues\.auto_send\s*=(?!=)"), ASK,
     "Lets skill issues be sent to the public plugin repository without asking (issues.auto_send): only on the "
     "user's own request."),
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
    (re.compile(r"config_set\.py\b[^\n;&|]*\s['\"]?(network\s*=|network\.excluded_hosts\s*-?=(?!=)"
                r"|[\w.\[\]-]*verify_tls\s*=\s*['\"]?(false|no|off|0)\b)"), ASK,
     "Narrows the scan exclusions, replaces the network settings or turns off TLS certificate checks: only with the "
     "user's yes."),
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
NMAP_SCAN_VALUE_OPTS = {"--profile", "--ports", "--top-ports", "--out", "--interface", "-e", "--site",
                        "--forget-missing"}
# ssh_probe.py options whose next argument is a value, not a target
SSH_PROBE_VALUE_OPTS = {"--user", "--port", "--timeout", "--jobs", "--site"}

SCRIPT_RUNNERS = {"bash", "sh", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node", "source", "."}
PYTHON_RE = re.compile(r"^python[0-9.]*$")
# a token whose value a Python script only knows at run time (a variable, an f-string field)
UNKNOWN = "__hm_runtime_value__"
# Python calls that run a program: subprocess.*, os.system/popen/exec*/spawn*, asyncio subprocesses
PY_EXEC_CALLS = re.compile(r"^(run|call|check_call|check_output|Popen|getoutput|getstatusoutput|system|popen"
                           r"|exec[lv]p?e?|spawn[lv]p?e?|create_subprocess_exec|create_subprocess_shell)$")


HEREDOC_RUNNERS = SCRIPT_RUNNERS | {"ssh", "eval", "xargs", "osascript"}
SHELL_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"}


class Shell:
    """Split a command into simple commands the way the shell would: separators inside quotes don't
    split, $(…) and `…` are commands of their own, comments are dropped, and heredoc bodies are
    data unless a command on their line runs them (bash <<EOF, cat <<EOF | sh, ssh host <<EOF).

    segments   — simple commands, in order
    code       — (language, body) of heredocs that a shell/interpreter executes (checked like commands);
                 language is "python" for a Python interpreter reading its program from stdin, else "shell"
    rule_text  — the command without data heredoc bodies (for the RULES regexes)
    writes     — (target, body) of data heredocs written to a file (`cat > x.sh <<EOF`, `cat <<EOF | tee x.sh`), so
                 a later `bash x.sh` in the same command is checked by that body
    An unquoted heredoc delimiter makes the shell run $(…) and `…` inside the body even when the body is data:
    those are commands of their own.
    """

    def __init__(self, command: str):
        self.s = command
        self.segments: list[str] = []
        self.code: list[tuple[str, str]] = []
        self.data_spans: list[tuple[int, int]] = []
        self.writes: list[tuple[str, str]] = []
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
        k, word, quoted = j, [], False
        while k < n and s[k] not in " \t\n;&|<>()":
            quoted = quoted or s[k] in "'\"\\"
            if s[k] in "'\"":
                q = s.find(s[k], k + 1)
                q = n if q < 0 else q
                word.append(s[k + 1:q])
                k = q + 1
            else:
                word.append(s[k].lstrip("\\"))
                k += 1
        if word:
            pending.append(("".join(word), strip, quoted))
        buf.append(s[i:k])
        return k

    def heredoc_bodies(self, i: int, pending: list, line_start: int) -> int:
        """At the newline after `<<WORD`: consume the bodies, classify each as code or data."""
        s, n = self.s, len(self.s)
        runs = None
        for seg in self.segments[line_start:]:
            lang = stdin_language(strip_prefix(tokens(seg)))
            runs = runs or lang
        targets = [t for seg in self.segments[line_start:] for t in write_targets(tokens(seg))]
        for word, strip, quoted in pending:
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
                self.code.append((runs, s[start:body_end]))
            else:
                self.data_spans.append((start, body_end))
                self.writes += [(t, s[start:body_end]) for t in targets]
            if not quoted and runs != "shell":   # the shell expands the body: $(…) and `…` run
                self.substitutions(start, body_end)
        pending.clear()
        return i

    def substitutions(self, i: int, end: int):
        s = self.s
        while i < end:
            if s[i] == "\\":
                i += 2
            elif s.startswith("$(", i) and not s.startswith("$((", i):
                i = self.parse(i + 2, ")")
            elif s[i] == "`":
                i = self.parse(i + 1, "`")
            else:
                i += 1

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


STDOUT_REDIRECT_RE = re.compile(r"^(?:1|&)?(?:>>?|>\|)(.*)$")


def write_targets(tok: list[str]) -> list[str]:
    """Files a simple command writes its output to: `> f`, `>> f`, `>f`, `&> f`, `tee [-a] f…`, `cp/mv … f`."""
    out = []
    for i, t in enumerate(tok):
        m = STDOUT_REDIRECT_RE.match(t)
        if m:
            target = m.group(1) or (tok[i + 1] if i + 1 < len(tok) else "")
            if target and not target.startswith("&"):
                out.append(target)
    name = Path(tok[0]).name if tok else ""
    if name == "tee":
        out += [t for t in tok[1:] if not t.startswith("-") and not STDOUT_REDIRECT_RE.match(t)]
    elif name in ("cp", "mv", "install", "ln") and len(tok) > 2 and not tok[-1].startswith("-"):
        out.append(tok[-1])
    elif name in ("curl", "wget"):   # curl -o FILE / --output FILE, wget -O FILE
        opts = ("-o", "--output") if name == "curl" else ("-O", "--output-document")
        out += [tok[i + 1] for i, t in enumerate(tok[:-1]) if t in opts]
        out += [t.split("=", 1)[1] for t in tok if t.startswith(tuple(o + "=" for o in opts if o.startswith("--")))]
    return out


ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# programs that run the command given after their own options
WRAPPERS = {"sudo", "doas", "env", "time", "exec", "nohup", "command", "builtin", "timeout", "gtimeout", "nice",
            "caffeinate", "stdbuf", "arch", "xargs", "parallel"}
# wrapper options whose next argument is a value, not the command (`sudo -u root nmap …`)
_TIMEOUT_OPTS = {"-s", "-k", "--signal", "--kill-after"}
WRAPPER_VALUE_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "-R"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-P", "--unset", "--chdir"},
    "exec": {"-a"},
    "nice": {"-n", "--adjustment"},
    "timeout": _TIMEOUT_OPTS, "gtimeout": _TIMEOUT_OPTS,
    "stdbuf": {"-i", "-o", "-e"},
    "caffeinate": {"-t", "-w"},
    "arch": {"-arch"},
    "xargs": {"-I", "-J", "-L", "-n", "-P", "-s", "-E", "-d", "-a", "-R", "-S", "--max-args", "--max-procs",
              "--delimiter", "--arg-file", "--max-lines", "--max-chars", "--eof", "--replace"},
    "parallel": {"-j", "-S", "-a", "-I", "-d", "-n", "-N", "--jobs", "--sshlogin", "--arg-file", "--colsep",
                 "--delimiter", "--max-args", "--max-replace-args"},
}
WRAPPER_POSITIONAL = {"timeout": 1, "gtimeout": 1}   # timeout DURATION command …
STDIN_ARG_WRAPPERS = {"xargs", "parallel"}           # add arguments read from stdin to the command
ROOT_WRAPPERS = {"sudo", "doas"}


def unwrap(tok: list[str]) -> tuple[list[str], dict]:
    """The command a segment runs: drop shell keywords, env assignments, wrappers with their options (sudo, env,
    timeout, xargs, …) and with_secrets.py. Flags: "stdin_args" (xargs/parallel add arguments from stdin), "root"
    (sudo/doas), "secrets" (the argv each with_secrets.py starts, outermost first)."""
    out, flags = list(tok), {}
    while out:
        t = out[0]
        name = Path(t).name
        if t in SHELL_KEYWORDS or ASSIGNMENT_RE.match(t):
            out = out[1:]
            continue
        if name in WRAPPERS and (name == t or "/" in t):
            if name == "command" and len(out) > 1 and out[1] in ("-v", "-V"):
                return [], flags   # `command -v nmap` looks a program up, it does not run it
            values = WRAPPER_VALUE_OPTS.get(name, set())
            out = out[1:]
            while out and out[0].startswith("-") and out[0] != "-":
                opt = out[0]
                if opt == "--":
                    out = out[1:]
                    break
                if name == "env" and opt in ("-S", "--split-string") and len(out) > 1:
                    out = tokens(out[1]) + out[2:]   # env -S 'cmd args': the string is the command
                    break
                out = out[2:] if opt in values and len(out) > 1 else out[1:]
            out = out[WRAPPER_POSITIONAL.get(name, 0):]
            if name in STDIN_ARG_WRAPPERS:
                flags["stdin_args"] = True
            if name in ROOT_WRAPPERS:
                flags["root"] = True
            continue
        if t.endswith("with_secrets.py") or (PYTHON_RE.match(name) and len(out) > 1 and out[1].endswith("with_secrets.py")):
            idx = out.index("--") if "--" in out else len(out)
            out = out[idx + 1:]
            flags.setdefault("secrets", []).append(list(out))
            continue
        break
    return out, flags


def strip_prefix(tok: list[str]) -> list[str]:
    """The command a segment runs, without wrappers (see unwrap)."""
    return unwrap(tok)[0]


VAR_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def expand(word: str, assigned: dict[str, str]) -> str:
    """`~` and $VAR / ${VAR} the way the shell would see them: variables set earlier in the same command, then
    the environment. $HM is this skill's base directory (SKILL.md) unless the command sets it. What stays
    unknown is left as is, so a `$` in the result means "only known at run time"."""
    def sub(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        if name in assigned:
            return assigned[name]
        if name in os.environ:
            return os.environ[name]
        if name == "HM":
            return str(PLUGIN_ROOT / "skills" / "homelab-manager")
        if name == "CLAUDE_PLUGIN_ROOT":
            return str(PLUGIN_ROOT)
        return m.group(0)
    return VAR_RE.sub(sub, os.path.expanduser(word) if word.startswith("~") else word)


def computed(word: str) -> bool:
    """Only known at run time: an unexpanded variable, $(…), `…`."""
    return "$" in word or "`" in word or "…" in word


def stdin_language(tok: list[str]) -> str | None:
    """"python"/"shell" when this command runs a heredoc on its stdin as code, else None.

    `bash <<EOF` and `python3 - <<EOF` run the body; `python3 issues.py add <<EOF` or `bash x.sh <<EOF` only
    feed it to a script as data (GitHub issue #60). ssh, eval, xargs and osascript always count as running it.
    """
    if not tok:
        return None
    name = Path(tok[0]).name
    if name not in HEREDOC_RUNNERS:
        return None
    lang = "python" if PYTHON_RE.match(name) else "shell"
    if name not in SCRIPT_RUNNERS or name in ("source", "."):
        return lang
    operands, skip = [], False
    for t in tok[1:]:
        if skip:
            skip = False
        elif re.match(r"^\d*(<<?|>>?|&>|<>)", t):  # a redirection; `> file`: the file too
            skip = re.fullmatch(r"\d*(<|>>?|&>|<>)", t) is not None
        elif not t.startswith("-") or t == "-":
            operands.append(t)
    if not operands or operands[0] == "-" or (lang == "shell" and "-s" in tok[1:]):
        return lang
    return None


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
    if any(UNKNOWN in t for t in targets):
        return [(ASK, f"{label} gets scan targets computed at run time; this hook cannot verify them.")]
    root = hmlib.find_repo_root(cwd)
    if not root:
        return [(ASK, f"{label} outside a homelab-infrastructure repo: no homelab.yaml, so no authorized ranges to check against.")]
    try:
        cfg = load_config(root)
        problems += (hmlib.check_targets(targets, cfg) if targets else
                     ["no scan targets found" + (": give them, or --site NAME to scan that site's authorized ranges"
                                                 if label == "nmap_scan.py" else "")])
    except hmlib.ConfigError as e:
        problems.append(str(e))
    return [(DENY, f"Scan refused: {p}") for p in problems]


def option_value(args: list[str], name: str) -> str | None:
    """The value of option name (`--site x` or `--site=x`) in args, None when absent."""
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None


def check_site_scan(site: str, cwd: str) -> list[tuple[str, str]]:
    """`nmap_scan.py --site N` without targets scans the site's ranges inside network.authorized_ranges: allowed
    when the site exists and some of its ranges are authorized, the same computation the script makes."""
    if UNKNOWN in site:
        return [(ASK, "nmap_scan.py gets its site at run time; this hook cannot verify the scan targets.")]
    root = hmlib.find_repo_root(cwd)
    if not root:
        return [(ASK, "nmap_scan.py outside a homelab-infrastructure repo: no homelab.yaml, so no authorized ranges "
                      "to check against.")]
    try:
        targets, _ = hmlib.site_scan_ranges(load_config(root), site)
    except hmlib.ConfigError as e:
        return [(DENY, f"Scan refused: {e}")]
    return [] if targets else [(DENY, f"Scan refused: no range of site {site} is inside network.authorized_ranges"
                                      " (or it is empty).")]


def plan_outputs(tok: list[str]) -> list[str]:
    """Plan files `tofu|terraform … plan -out=FILE` writes."""
    if not tok or Path(tok[0]).name not in ("tofu", "terraform") or "plan" not in tok:
        return []
    out = []
    for i, t in enumerate(tok):
        if t.startswith(("-out=", "--out=")):
            out.append(t.split("=", 1)[1])
        elif t in ("-out", "--out") and i + 1 < len(tok):
            out.append(tok[i + 1])
    return out


def trusted_binary(word: str, cwd: str) -> str | None:
    """The installed tofu/terraform this hook may run to read a plan: never the command's own `./tofu` (the hook
    would run it before the user is asked). None when the command names another binary than the installed one."""
    name = Path(word).name
    found = shutil.which(name) or next((p for p in (f"/opt/homebrew/bin/{name}", f"/usr/local/bin/{name}")
                                        if os.access(p, os.X_OK)), None)
    if not found:
        return None
    if "/" in word:
        try:
            if Path(cwd, os.path.expanduser(word)).resolve() != Path(found).resolve():
                return None
        except OSError:
            return None
    return found


def check_tofu_apply(tok: list[str], cwd: str, produced: set[str] = frozenset()) -> list[tuple[str, str]]:
    """`tofu apply` is fine only with a saved plan, made before this command, that deletes/replaces nothing."""
    if "apply" not in tok:
        return []
    chdir = next((t.split("=", 1)[1] for t in tok if t.startswith("-chdir=")), None)
    after = tok[tok.index("apply") + 1:]
    plan = next((t for t in after if not t.startswith("-")), None)
    if not plan:
        return [(ASK, "`tofu apply` without a saved, reviewed plan file.")]
    if Path(plan).name in produced:
        return [(ASK, f"`tofu apply {plan}`: the plan file is written by this same command, so nobody has reviewed "
                      f"it. Make the plan, show it to the user, then apply it in a separate command.")]
    workdir = Path(cwd, chdir) if chdir else Path(cwd)
    binary = trusted_binary(tok[0], cwd)
    if not binary:
        return [(ASK, f"`{tok[0]}` is not the installed {Path(tok[0]).name}; this hook does not run it to read plan "
                      f"{plan}. Approve only if you have reviewed the plan.")]
    try:
        res = subprocess.run([binary, "show", "-json", plan], cwd=workdir, capture_output=True, text=True,
                             timeout=time_left(60))
        data = json.loads(res.stdout)
    except OutOfTime:
        raise
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
    if HIGH_IMPACT_PLAYBOOK.search(playbooks) or re.search(r"reboot\w*\s*[=:]\s*(true|yes|1|always|if_required)\b", text, re.I):
        return [(ASK, "High-impact playbook run (patching/reboot/removal) — not in --check mode.")]
    if re.search(r"homelab_read_only\W*[=:]\W*(false|no|0)\b", text, re.I):   # GitHub #79
        return [(ASK, "Lets a playbook change appliances (homelab_read_only=false) — not in --check mode.")]
    return []


GH_REPO_RE = re.compile(r"github\.com[:/]([^/\s]+/[^/\s]+?)(?:\.git)?/?$")
GH_TEXT_OPTS = {"-t": "title", "--title": "title", "-b": "body", "--body": "body", "-F": "file", "--body-file": "file"}


def plugin_repo() -> str | None:
    """owner/name of the plugin's GitHub repository (plugin.json `repository`)."""
    try:
        url = json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text()).get("repository", "")
    except (OSError, ValueError):
        return None
    m = GH_REPO_RE.search(url or "")
    return m.group(1).lower() if m else None


def check_gh_language(tok: list[str], cwd: str) -> list[tuple[str, str]]:
    """gh issue/pr create, comment, edit, review aimed at the plugin's repository must be in English."""
    if len(tok) < 3 or tok[1] not in ("issue", "pr") or tok[2] not in ("create", "comment", "edit", "review"):
        return []
    repo, texts, i = None, [], 3
    while i < len(tok):
        t, val = tok[i], None
        if "=" in t and t.startswith("--"):
            t, val = t.split("=", 1)
        elif i + 1 < len(tok) and (t in GH_TEXT_OPTS or t in ("-R", "--repo")):
            val = tok[i + 1]
            i += 1
        i += 1
        if val is None:
            continue
        if t in ("-R", "--repo"):
            repo = val
        elif GH_TEXT_OPTS.get(t) == "file":
            f = Path(os.path.expanduser(val))
            f = f if f.is_absolute() else Path(cwd) / f
            if val != "-" and f.is_file():
                texts.append(f.read_text(errors="replace")[:200_000])
        elif t in GH_TEXT_OPTS:
            texts.append(val)
    if repo is None:
        try:
            r = subprocess.run(["git", "-C", cwd, "remote", "get-url", "origin"], capture_output=True, text=True,
                               timeout=time_left(5))
            m = GH_REPO_RE.search(r.stdout.strip())
            repo = m.group(1) if m else None
        except (OSError, subprocess.TimeoutExpired):
            repo = None
    target = plugin_repo()
    if not repo or not target or repo.removeprefix("https://github.com/").lower() != target:
        return []
    problems = [p for text in texts for p in hmlib.english_problems(text)]
    if not problems:
        return []
    return [(DENY, f"{target} is English-only: write the {tok[1]} text in English, translating the user's words "
                   f"(not English: {'; '.join(problems)}).")]


def is_python(script: Path, tok: list[str], content: str) -> bool:
    """Run by a Python interpreter: python3 x.py, a .py file, or a python shebang."""
    if PYTHON_RE.match(Path(tok[0]).name):
        return True
    if Path(tok[0]).name in SCRIPT_RUNNERS:
        return False
    first = content.split("\n", 1)[0]
    return script.suffix == ".py" if not first.startswith("#!") else "python" in first


SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
# per interpreter: (options with a value, options whose value is the program text, options after which no script
# file follows: a module or stdin)
RUNNER_OPTS = {
    "python": ({"-W", "-X", "-Q"}, {"-c"}, {"-m"}),
    "shell": ({"-o", "-O", "+o", "+O", "--rcfile", "--init-file"}, {"-c"}, {"-s", "-i"}),
    "perl": ({"-I", "-M", "-m"}, {"-e", "-E"}, set()),
    "ruby": ({"-I", "-r", "-C", "-E"}, {"-e"}, set()),
    "node": ({"-r", "--require", "--import", "--loader", "--input-type"}, {"-e", "--eval", "-p", "--print"}, set()),
}
REDIRECT_RE = re.compile(r"^\d*(<<?|>>?|&>|<>)")


def runner_kind(name: str) -> str | None:
    if PYTHON_RE.match(name):
        return "python"
    if name in SHELLS:
        return "shell"
    return {"perl": "perl", "ruby": "ruby", "node": "node"}.get(name)


def runner_parse(tok: list[str]) -> tuple[str, str]:
    """What an interpreter command runs: ("code", text) for -c/-e, ("script", operand), ("stdin", "") or
    ("none", "") (a module, interactive). Interpreter options and their values are skipped, so
    `bash -x x.sh` and `python3 -u x.py` find the script."""
    name = Path(tok[0]).name
    if name in ("source", "."):
        return ("script", tok[1]) if len(tok) > 1 else ("none", "")
    value_opts, code_opts, end_opts = RUNNER_OPTS[runner_kind(name)]
    i = 1
    while i < len(tok):
        t = tok[i]
        if t == "--":
            i += 1
            break
        if t == "-":
            return "stdin", ""
        if REDIRECT_RE.match(t):
            i += 1 + (REDIRECT_RE.fullmatch(t) is not None)   # `> file`: the file too
            continue
        if not t.startswith(("-", "+")):
            break
        if t.startswith("--"):
            opt, eq, val = t.partition("=")
            if opt in code_opts:
                return "code", val if eq else (tok[i + 1] if i + 1 < len(tok) else "")
            if opt in end_opts:
                return ("stdin", "") if opt == "-s" else ("none", "")
            i += 1 + (opt in value_opts and not eq)
            continue
        i += 1
        for j in range(1, len(t)):   # a cluster of short options: -xc, -Ilib, -cCODE
            o = t[0] + t[j]
            if o in code_opts:
                rest = t[j + 1:]
                return "code", rest if rest else (tok[i] if i < len(tok) else "")
            if o in end_opts:
                return ("stdin", "") if o == "-s" else ("none", "")
            if o in value_opts:
                i += (j + 1 == len(t))   # the value is the next word unless it is attached
                break
    if i < len(tok):
        return "script", tok[i]
    return "stdin", ""


SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/opt/homebrew/", "/System/", "/Library/", "/Applications/", "/nix/")


def is_text_file(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return b"\0" not in f.read(4096)
    except OSError:
        return False


def script_target(tok: list[str], cwd: str | None, assigned: dict[str, str]) -> tuple[str | None, Path | str | None]:
    """The script file a command runs, and its state:
      ("file", path)        — exists: its content is checked
      ("missing", path)     — does not exist (yet): created by this same command, or a typo
      ("computed", word)    — its path is only known at run time ($VAR, $(…), a `cd` to such a directory)
      (None, None)          — runs no script file (a binary, -c code, a module, stdin)
    Interpreter options are skipped; a bare command name found in PATH outside the system directories is a script
    too when it is a text file (a generated ~/bin/helper)."""
    if not tok:
        return None, None
    first, name = tok[0], Path(tok[0]).name
    if runner_kind(name) or name in ("source", "."):
        kind, cand = runner_parse(tok)
        if kind != "script":
            return None, None
    elif "/" in first:
        cand = first
    else:
        found = shutil.which(expand(first, assigned))
        if not found or found.startswith(SYSTEM_DIRS) or not is_text_file(Path(found)):
            return None, None
        return "file", Path(found)
    word = expand(cand, assigned)
    if computed(word):
        return "computed", word
    p = Path(word)
    if not p.is_absolute():
        if cwd is None:
            return "computed", word
        p = Path(cwd) / p
    if p.is_file():
        return "file", p
    return (None, None) if p.exists() else ("missing", p)


def interpreter_code(tok: list[str]) -> tuple[str, str] | None:
    """(kind, program text) for `python3 -c CODE`, `bash -lc CODE`, `perl -e CODE`, …"""
    kind = runner_kind(Path(tok[0]).name)
    if not kind:
        return None
    what, text = runner_parse(tok)
    return (kind, text) if what == "code" else None


SSH_VALUE_OPTS = set("bcDEeFIiJLlmOoPpQRSWw")


def inner_command(tok: list[str]) -> str | None:
    """The command string that `bash -c STR`, `eval STR…` or `ssh [opts] host CMD…` runs."""
    name = Path(tok[0]).name
    if name in SHELLS:
        code = interpreter_code(tok)
        return code[1] if code else None
    if name == "eval":
        return " ".join(tok[1:])
    if name == "ssh":
        i = 1
        while i < len(tok) and tok[i].startswith("-"):
            i += 2 if tok[i][-1] in SSH_VALUE_OPTS and len(tok[i]) == 2 else 1
        return " ".join(tok[i + 1:]) or None
    return None


def py_words(node: ast.AST) -> list[str] | None:
    """Words of a string expression ('a b', f'a {x}'), UNKNOWN for what is only known at run time."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return ["".join(v.value if isinstance(v, ast.Constant) else UNKNOWN for v in node.values)]
    return None


def py_argv(node: ast.AST) -> list[str] | None:
    """An argv list/tuple literal; elements not known before run time become UNKNOWN."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    out = []
    for e in node.elts:
        w = py_words(e)
        out.append(w[0] if w else UNKNOWN)
    return out


def py_call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


PY_FILE_CALLS = {"open", "Path", "PurePath", "expanduser", "read_text", "read_bytes", "copy", "copyfile", "copy2",
                 "copytree", "make_archive"}
SCAN_SCRIPT_RE = re.compile(r"(^|/)(nmap_scan|ssh_probe)\.py$")


def evaluate_python(content: str, cwd: str, depth: int) -> list[tuple[str, str]]:
    """A Python program: the RULES regexes over its text, and the commands it starts (subprocess, os.system,
    exec*), checked like shell commands. The word nmap in strings, comments or column labels is no scan
    (GitHub issue #60); an nmap argv whose targets are only known at run time asks."""
    findings = check_text(content)
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        m = re.search(r"""^.*['"](\S*/)?nmap(_scan\.py)?\b.*$""", content, re.M)
        if m:
            line = content.count("\n", 0, m.start()) + 1
            findings.append((ASK, f"line {line} may run nmap and the program could not be parsed: "
                                  f"{m.group(0).strip()[:120]}"))
        return findings
    commands: list[tuple[int, list[str], bool]] = []  # (line, argv or ["__shell__", cmd], started by a call)
    in_calls: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args and py_call_name(node) in PY_FILE_CALLS:
            w = py_words(node.args[0])
            if w and any(private_ssh_path(m.group(1)) for m in SSH_PATH_RE.finditer(w[0])):
                findings.append((DENY, f"line {node.lineno}: {SSH_KEY_REASON}"))
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) else [])
            if any((n or "").split(".")[0] == "nmap" for n in names):
                findings.append((ASK, f"line {node.lineno} imports python-nmap: scan targets this hook cannot verify."))
        if not isinstance(node, ast.Call) or not node.args or not PY_EXEC_CALLS.match(py_call_name(node)):
            continue
        first = node.args[0]
        argv = py_argv(first)
        if argv is not None:
            in_calls.add(id(first))
        elif len(node.args) > 1 and py_call_name(node) not in ("system", "popen", "getoutput", "getstatusoutput"):
            argv = [(py_words(a) or [UNKNOWN])[0] for a in node.args]  # os.execlp / create_subprocess_exec style
            argv = argv[1:] if py_call_name(node).startswith(("exec", "spawn")) and len(argv) > 1 \
                and argv[0] == argv[1] else argv
        else:
            words = py_words(first)
            if words is None:
                continue  # a variable: list literals that start with nmap are found below
            commands.append((node.lineno, ["__shell__", words[0]], True))
            continue
        commands.append((node.lineno, argv, True))
    for node in ast.walk(tree):  # argv lists built before the call: cmd = ["nmap", "-sn", net]
        if isinstance(node, (ast.List, ast.Tuple)) and id(node) not in in_calls:
            argv = py_argv(node)
            # an argv shape (nmap plus an option), not a list of labels such as ["nmap", "ssh"]
            if argv and Path(argv[0]).name in ("nmap", "sudo") and "nmap" in [Path(a).name for a in argv[:2]] \
                    and any(a.startswith("-") for a in argv[1:]):
                commands.append((node.lineno, argv, False))
    for line, argv, _ in commands:
        text = argv[1] if argv[0] == "__shell__" else shlex.join(argv)
        sub = evaluate(text, cwd, depth + 1)
        if not sub and UNKNOWN in text and any(SCAN_SCRIPT_RE.search(t) for t in tokens(text)):
            sub.append((ASK, "starts a scan script whose path or targets are computed at run time; "
                             "this hook cannot verify them."))
        findings += [(d, f"line {line}: {r}") for d, r in sub]
    return findings


# programs that run a command given in their arguments (`find -exec nmap`, `watch nmap`, `docker exec c nmap`)
CMD_RUNNERS = {"find", "watch", "script", "unbuffer", "proxychains", "proxychains4", "flock", "sg", "chroot",
               "ionice", "taskset", "numactl", "sshpass", "docker", "podman", "nerdctl", "kubectl", "limactl", "orb"}
SCAN_SCRIPTS = ("nmap_scan.py", "ssh_probe.py")
# this plugin's own scripts: `python3 issues.py …` in the wrong directory only fails, so a missing one does not ask
# unless something earlier in the same command writes a file of that name
PLUGIN_SCRIPT_NAMES = {f.name for d in (PLUGIN_ROOT / "skills" / "homelab-manager" / "scripts", PLUGIN_ROOT / "hooks")
                       if d.is_dir() for f in d.iterdir() if f.suffix == ".py"}


# --- with_secrets.py -------------------------------------------------------------------
# programs that get keychain secrets in their environment without asking (and this plugin's scripts)
SECRET_PROGRAMS = {"tofu", "terraform", "packer", "ansible", "ansible-playbook", "ansible-inventory"}
SECRET_VARS_RE = re.compile(r"\b(PROXMOX_(VE_API_TOKEN|TOKEN|PASSWORD)|AWS_SECRET_ACCESS_KEY"
                            r"|[A-Z][A-Z0-9_]*_(PASSWORD|API_KEY|SECRET|TOKEN))\b")
# the plugin itself, and its other installed versions (…/plugins/cache/<marketplace>/homelab-manager/<version>)
PLUGIN_HOMES = [PLUGIN_ROOT] + ([PLUGIN_ROOT.parent] if PLUGIN_ROOT.parent.name == "homelab-manager" else [])
PLUGINS_DIR = Path.home() / ".claude" / "plugins"


def in_plugin(p: Path) -> bool:
    try:
        r = Path(os.path.abspath(p)).resolve()
    except OSError:
        return False
    return any(r.is_relative_to(h) for h in PLUGIN_HOMES)


def secret_env_names(cwd: str) -> set[str]:
    """Environment variables with_secrets.py fills from the keychain, by homelab.yaml `secrets:` (kind env and
    user_password; the proxmox_token and s3_credentials names are in SECRET_VARS_RE)."""
    try:
        root = hmlib.find_repo_root(cwd)
        secrets = (load_config(root).get("secrets") or {}) if root else {}
    except OutOfTime:
        raise
    except Exception:   # noqa: BLE001 — no names known: the generic pattern still applies
        return set()
    names = set()
    for spec in secrets.values() if isinstance(secrets, dict) else []:
        env = spec.get("env") if isinstance(spec, dict) else None
        if isinstance(env, str) and env:
            names |= {env, f"{env}_PASSWORD"} if spec.get("kind") == "user_password" else {env}
    return names


def check_secrets(wrapped: list[list[str]], segment: str, cwd: str, assigned: dict[str, str]) -> list[tuple[str, str]]:
    """with_secrets.py puts keychain secrets into the environment of the command it starts. Only the tools that need
    them (OpenTofu, Packer, Ansible) and this plugin's scripts get them without asking; naming a secret's variable
    on the command line asks too (its value could be printed, encoded or sent somewhere)."""
    findings = []
    for argv in wrapped:
        if not argv:
            continue
        first = Path(argv[0]).name
        if argv[0].endswith("with_secrets.py") or (PYTHON_RE.match(first) and len(argv) > 1
                                                   and argv[1].endswith("with_secrets.py")):
            continue   # nested: the inner with_secrets.py's command is checked
        ok = first in SECRET_PROGRAMS
        if not ok and runner_kind(first) == "python":
            state, script = script_target([expand(t, assigned) for t in argv], cwd, assigned)
            ok = (state == "file" and in_plugin(script)) or (state == "missing" and script.name in PLUGIN_SCRIPT_NAMES)
        if not ok:
            findings.append((ASK, f"runs `{shlex.join(argv)[:80]}` with keychain secrets in its environment: only "
                                  "OpenTofu, Packer, Ansible and this plugin's scripts get them without asking."))
    names = secret_env_names(cwd)
    if SECRET_VARS_RE.search(segment) or any(re.search(rf"\b{re.escape(n)}\b", segment) for n in names):
        findings.append((ASK, "names a secret's environment variable in a command run by with_secrets.py: its "
                              "value could be printed or sent somewhere."))
    return findings


# --- credentials: SSH keys, keychain, Git, state ----------------------------------------
SSH_PATH_RE = re.compile(r"\.ssh/([^\s'\"(),;|&<>]*)")
SSH_PUBLIC_NAMES = ("config", "known_hosts", "authorized_keys", "environment", "rc")
SSH_METADATA_PROGRAMS = {"ls", "stat", "test", "[", "[[", "chmod", "chown", "mkdir", "file"}
SSH_KEY_USERS = {"ssh", "scp", "sftp", "rsync", "ssh-add", "ssh-keygen", "ssh-copy-id", "autossh", "mosh", "sshpass",
                 "ansible", "ansible-playbook", "ansible-inventory", "git"}
SSH_KEY_OPTION_RE = re.compile(r"(^|\s)(-i|-oIdentityFile=|IdentityFile=|--private-key=)\s*\S*$")
ARCHIVERS = {"tar", "zip", "cp", "rsync", "scp", "ditto", "cpio", "7z", "pax"}
SSH_KEY_REASON = "Private SSH keys must not be read, copied or printed. Use the SSH agent (ssh-add -L lists public keys)."


def private_ssh_path(rest: str) -> bool:
    """rest = what follows `.ssh/` in a path: a private key (or a glob that may match one)?"""
    first = rest.split("/")[0]
    if not first:
        return False
    if any(c in first for c in "*?[") and not first.endswith(".pub"):
        return True
    return not (first.endswith(".pub") or first.startswith(SSH_PUBLIC_NAMES))


def check_ssh_keys(tok: list[str]) -> list[tuple[str, str]]:
    """Any program naming a private key under .ssh/ is denied, except listing it and SSH tools taking it as their
    identity (`ssh -i ~/.ssh/key`, `ssh-add ~/.ssh/key`); archivers of the whole .ssh directory too."""
    prog = Path(tok[0]).name
    if prog in SSH_METADATA_PROGRAMS or prog in ("echo", "printf", "gh") or (prog == "git" and len(tok) > 1
                                                                          and tok[1] in ("commit", "tag")):
        return []   # these only show or record a path as text
    for i, t in enumerate(tok):
        if prog in ARCHIVERS and re.search(r"(^|/)\.ssh/?$", t):
            return [(DENY, SSH_KEY_REASON)]
        for m in SSH_PATH_RE.finditer(t):
            if not private_ssh_path(m.group(1)):
                continue
            if prog in SSH_KEY_USERS and (prog == "ssh-add" or (i and tok[i - 1] in ("-i", "-f", "--private-key", "--key-file"))
                                          or SSH_KEY_OPTION_RE.search(t[:m.start()])):
                continue
            return [(DENY, SSH_KEY_REASON)]
    return []


SECURITY_SECRET_SUBCOMMANDS = {"find-generic-password", "find-internet-password"}


def check_security(tok: list[str]) -> list[tuple[str, str]]:
    """macOS `security`: printing a keychain secret (-w, -g, also in a cluster such as -gw), dumping or exporting the
    keychain, and the interactive mode (-i, -p) that reads such commands from stdin are denied."""
    i = 1
    while i < len(tok) and tok[i].startswith("-"):
        if tok[i] in ("-i", "-p") or (not tok[i].startswith("--") and "i" in tok[i][1:]):
            return [(DENY, "`security -i` runs keychain commands from input this hook cannot see.")]
        i += 1
    if i >= len(tok):
        return []
    sub, args = tok[i], tok[i + 1:]
    if sub in ("dump-keychain", "export", "export-items"):
        return [(DENY, "Dumping or exporting the keychain is not allowed.")]
    if sub in SECURITY_SECRET_SUBCOMMANDS and any(
            a.startswith("-") and not a.startswith("--") and set(a[1:]) <= set("acCDGjlsgw") and set(a[1:]) & set("wg")
            for a in args):
        return [(DENY, "This would print a keychain secret. Use scripts/with_secrets.py, which injects it into the "
                       "command's environment without printing it.")]
    return []


TFSTATE_RE = re.compile(r"\.tfstate(\.|$)")
TFSTATE_OK = {"ls", "stat", "test", "[", "rm", "tofu", "terraform", "git", "find", "du", "mkdir", "touch", "chmod", "file"}


def check_state_read(tok: list[str]) -> list[tuple[str, str]]:
    name = Path(tok[0]).name
    if name in ("tofu", "terraform"):
        rest = [t for t in tok[1:] if not t.startswith("-")]
        if rest[:2] == ["state", "pull"] or (rest[:1] == ["show"] and len(rest) == 1 and "-json" in tok):
            return [(ASK, "Prints the whole OpenTofu state, which can hold secrets (passwords, keys, tokens) in clear.")]
        return []
    if name not in TFSTATE_OK and any(TFSTATE_RE.search(t) for t in tok[1:]):
        return [(ASK, "Reads OpenTofu state, which can hold secrets (passwords, keys, tokens) in clear.")]
    return []


# --- files that guard the guard ----------------------------------------------------------
IN_PLACE_EDITORS = {"sed", "gsed", "perl", "ruby", "yq", "awk", "gawk"}
REMOVERS = {"rm", "unlink", "truncate", "shred"}


def edit_targets(tok: list[str]) -> list[str]:
    """Files a command changes in place or removes (sed -i, perl -pi, yq -i, awk -i inplace, rm, truncate, dd of=)."""
    name = Path(tok[0]).name
    out = [t[3:] for t in tok if t.startswith("of=")] if name == "dd" else []
    in_place = any(t == "--in-place" or t.startswith("--in-place=")
                   or (t.startswith("-") and not t.startswith("--") and "i" in t[1:]) for t in tok[1:])
    if (name in IN_PLACE_EDITORS and in_place) or name in REMOVERS:
        out += [t for t in tok[1:] if not t.startswith("-")]
    return out


def protected_target(target: str, cwd: str) -> str | None:
    """Why writing this file needs the user's yes, or None."""
    p = Path(os.path.expanduser(target))
    p = p if p.is_absolute() else Path(cwd) / p
    if p.name == "homelab.yaml":
        return ("Changes homelab.yaml outside config_set.py (it holds the scan scope, TLS checks and the guard's own "
                "settings).")
    try:
        r = Path(os.path.abspath(p)).resolve()
    except OSError:
        r = p
    if in_plugin(r) or r.is_relative_to(PLUGINS_DIR.resolve()):
        return "Changes the installed plugin (its guard hook and scripts)."
    if r.name in ("settings.json", "settings.local.json") and r.parent.name == ".claude":
        return "Changes Claude Code permission settings (.claude/settings*.json)."
    return None


def check_protected_writes(tok: list[str], cwd: str) -> list[tuple[str, str]]:
    reasons = {protected_target(t, cwd) for t in write_targets(tok) + edit_targets(tok) if t and not computed(t)}
    return [(ASK, r) for r in sorted(reasons - {None})]


def runner_nmap_at(tok: list[str]) -> int | None:
    """Index of nmap run by a command runner: the program after find -exec/-execdir/-ok, else nmap anywhere."""
    for i, t in enumerate(tok[1:], 1):
        if Path(t).name == "nmap" and (Path(tok[0]).name != "find"
                                       or tok[i - 1] in ("-exec", "-execdir", "-ok", "-okdir")):
            return i
    return None


def check_scan_script(script_name: str, tok: list[str], cwd: str) -> list[tuple[str, str]]:
    """nmap_scan.py / ssh_probe.py: their targets must be inside the authorized ranges."""
    value_opts = NMAP_SCAN_VALUE_OPTS if script_name == "nmap_scan.py" else SSH_PROBE_VALUE_OPTS
    args = tok[tok.index(next(t for t in tok if t.endswith(script_name))) + 1:]
    targets = [a for i, a in enumerate(args) if not a.startswith("-")
               and (i == 0 or args[i - 1] not in value_opts)]
    site = option_value(args, "--site")
    if not targets and script_name == "nmap_scan.py" and option_value(args, "--forget-missing") is not None:
        return []   # edits network.json, scans nothing; the script refuses targets with it (GitHub issue #127)
    if not targets and site is not None and script_name == "nmap_scan.py":
        return check_site_scan(site, cwd)  # the site's authorized ranges (GitHub issue #118)
    if targets or script_name == "nmap_scan.py":  # ssh_probe.py without targets: hosts from network.json
        return check_nmap(targets, cwd, label=script_name)
    return []


def check_script_content(script: Path, content: str, tok: list[str], depth: int) -> list[tuple[str, str]]:
    if is_python(script, tok, content):
        sub = evaluate_python(content, str(script.parent), depth + 1)
    else:
        sub = evaluate(content, str(script.parent), depth + 1)
        if re.search(r"\bnmap\b", content):
            sub.append((ASK, "runs nmap with targets this hook cannot verify."))
    return [(d, f"script {script.name}: {r}") for d, r in sub]


def same_file(a: str, b: Path, cwd: str) -> bool:
    return os.path.normpath(os.path.join(cwd, os.path.expanduser(a))) == os.path.normpath(str(b))


def evaluate(command: str, cwd: str, depth: int = 0) -> list[tuple[str, str]]:
    if depth == 0:
        _configs.clear()   # a new command: homelab.yaml may have changed since the last one
    sh = Shell(command)
    findings = check_text(sh.rule_text)
    if depth < 3:
        for lang, body in sh.code:  # heredoc a shell or interpreter runs: same checks as a command
            findings += evaluate_python(body, cwd, depth + 1) if lang == "python" else evaluate(body, cwd, depth + 1)
    cur: str | None = cwd          # follows `cd` in this command; None once it goes somewhere only known at run time
    assigned: dict[str, str] = {}  # VAR=value set earlier in this command
    produced: set[str] = set()     # names of files written earlier in this command (tofu plan -out, >, cp, tee)
    for seg in sh.segments:
        raw = tokens(seg)
        if raw and raw[0] in ("export", "local", "declare", "readonly", "typeset"):
            raw = raw[1:]
        if raw and all(ASSIGNMENT_RE.match(t) for t in raw):
            for t in raw:
                k, v = t.split("=", 1)
                assigned[k] = expand(v, assigned)
            continue
        tok, flags = unwrap(raw)
        here = cur or cwd
        if "secrets" in flags:   # before an empty command is skipped: `with_secrets.py x -- env` prints them all
            findings += check_secrets(flags["secrets"], seg, here, assigned)
        if not tok:
            continue
        tok = [expand(t, assigned) for t in tok]
        if tok[0] in ("cd", "pushd", "popd"):
            dest = next((t for t in tok[1:] if not t.startswith("-")), os.path.expanduser("~"))
            unknown = computed(dest) or cur is None or tok[0] == "popd" or "-" in tok[1:]
            cur = None if unknown else os.path.normpath(os.path.join(cur, dest))
            continue
        name = Path(tok[0]).name
        if computed(tok[0]):
            findings.append((ASK, f"the program to run is computed at run time ({tok[0][:60]}); this hook cannot "
                                  f"check what it does."))
        findings += check_text(" ".join(tok))   # the command as the shell sees it: no quotes or backslashes
        findings += check_ssh_keys(tok) + check_state_read(tok) + check_protected_writes(tok, here)
        inner = inner_command(tok)
        if inner and depth < 3:
            findings += evaluate(inner, here, depth + 1)
        code = interpreter_code(tok)
        if code and code[0] == "python" and depth < 3:
            findings += [(d, f"python3 -c: {r}") for d, r in evaluate_python(code[1], here, depth + 1)]
        elif code and code[0] in ("perl", "ruby", "node"):
            findings += check_text(code[1])
            if re.search(r"\b(nmap|security|qm|pct|pvesh|tofu|terraform)\b", code[1]):
                findings.append((ASK, f"{name} code runs commands this hook cannot check."))
        if name == "nmap":
            if "stdin_args" not in flags or nmap_targets(tok[1:], here)[0]:   # xargs: targets may all come from stdin
                findings += check_nmap(tok[1:], here)
            if "stdin_args" in flags:
                findings.append((ASK, "nmap gets further targets from input this hook cannot see (xargs/parallel)."))
            if "root" in flags:
                findings.append((ASK, "Runs nmap as root (OS detection). Root nmap can do anything on this Mac."))
        elif name in CMD_RUNNERS and (at := runner_nmap_at(tok)):
            findings += [f for f in check_nmap([t for t in tok[at + 1:] if t not in ("{}", ";", "+")], here)
                         if f[0] == DENY]
            findings.append((ASK, f"runs nmap through {name}; this hook cannot verify its targets."))
        elif name in ("tofu", "terraform"):
            findings += check_tofu_apply(tok, here, produced)
        elif name == "ansible-playbook":
            findings += check_ansible_playbook(tok)
        elif name == "gh":
            findings += check_gh_language(tok, here)
        elif name == "security":
            findings += check_security(tok)
        state, script = script_target(tok, cur, assigned)
        script_name = Path(str(script)).name if script else ""
        if script_name in SCAN_SCRIPTS:
            findings += check_scan_script(script_name, tok, here)
        if state == "computed" and script_name not in SCAN_SCRIPTS:
            findings.append((ASK, f"runs a script whose path is only known at run time ({str(script)[:80]}); "
                                  f"this hook cannot check it."))
        elif state == "missing":
            written = [body for target, body in sh.writes if same_file(expand(target, assigned), script, cwd)
                       or (cur and same_file(expand(target, assigned), script, cur))]
            if written and depth < 2:
                for body in written:
                    findings += check_script_content(script, body, tok, depth)
            elif not written and script_name not in SCAN_SCRIPTS and (script_name not in PLUGIN_SCRIPT_NAMES
                                                                      or script_name in produced):
                findings.append((ASK, f"runs {script_name}, which does not exist yet (written by this same command?) "
                                      f"or not at {script}; this hook cannot check it."))
        elif state == "file" and script_name not in SCAN_SCRIPTS and depth < 2:
            try:
                plugin_owned = script.resolve().is_relative_to(PLUGIN_ROOT)
            except OSError:
                plugin_owned = False
            if not plugin_owned:
                try:
                    content = script.read_text(errors="replace")[:500_000]
                except OSError:
                    content = ""
                findings += check_script_content(script, content, tok, depth)
        produced.update(Path(t).name for t in write_targets(tok) + plan_outputs(tok))
    return findings


def auto_send(cwd: str) -> bool:
    """issues.auto_send: true in the repository's homelab.yaml (GitHub issue #114): the user opted in to sending skill
    issues without this hook asking; raw `gh issue` writes still ask."""
    try:
        root = hmlib.find_repo_root(cwd)
        return bool(root) and hmlib.get(load_config(root), "issues.auto_send") is True
    except Exception:   # noqa: BLE001 — unreadable config: keep asking
        return False


def opted_in(findings: list[tuple[str, str]], cwd: str) -> list[tuple[str, str]]:
    """Drop the issues.py send question when the repository opted in to issues.auto_send."""
    if any(r.endswith(ISSUES_SEND) for _, r in findings) and auto_send(cwd):
        return [(d, r) for d, r in findings if not r.endswith(ISSUES_SEND)]
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


def check_payload(payload) -> dict | None:
    if not isinstance(payload, dict):
        raise ValueError("hook input is not a JSON object")
    if payload.get("tool_name") != "Bash":
        return None
    if HMLIB_ERROR is not None:
        raise HMLIB_ERROR
    command = (payload.get("tool_input") or {}).get("command", "")
    if not isinstance(command, str):
        raise ValueError("command is not a string")
    cwd = payload.get("cwd") or os.getcwd()
    return decide(opted_in(evaluate(command, cwd), cwd))


def main() -> int:
    """Fails closed: any error, including a plugin install that cannot import hmlib, unreadable input or a used-up
    time budget, asks the user instead of letting the command run unchecked."""
    global _deadline
    _deadline = time.monotonic() + BUDGET_S
    try:
        out = check_payload(json.load(sys.stdin))
    except OutOfTime:
        out = decide([(ASK, "the guard ran out of time checking this command; review it manually.")])
    except Exception as e:  # noqa: BLE001
        out = decide([(ASK, f"guard error ({type(e).__name__}: {str(e)[:120]}); review this command manually.")])
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
