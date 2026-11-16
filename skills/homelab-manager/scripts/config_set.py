#!/usr/bin/env python3
"""Change values in homelab.yaml without disturbing the rest of the file.

    config_set.py 'site.domain=home.arpa' 'proxmox.verify_tls=false'
    config_set.py 'network.authorized_ranges+=10.0.10.0/24'    # append to a list (skipped if present)
    config_set.py 'network.excluded_hosts-=10.0.10.1'          # remove from a list
    config_set.py 'defaults.ssh_public_keys=["ssh-ed25519 AAAA… me@mac"]'
    config_set.py --delete discovery.ignore_unmanaged
    config_set.py --dry-run …                                  # print the diff, write nothing

`yq -i` re-serialises the whole document: it drops blank lines and comment alignment, and turns
`key: []  # comment` into a block list whose comment lands on a later key. This edits only the
lines of the keys it changes (an inline comment stays on its key) and checks the result with yq
(the whole document must equal the old one plus exactly these changes) before writing; on any
mismatch it writes nothing and exits 1 — then note a skill issue (SKILL.md §6).

Values: JSON if they parse as JSON (`true`, `3`, `["a", "b"]`, `"3"`), otherwise a plain string.
Missing keys (and parent mappings) are added at the end of their parent block.
"""
from __future__ import annotations

import argparse
import copy
import difflib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hmlib  # noqa: E402

_KEY = re.compile(r"""^(\s*)("[^"]*"|'[^']*'|[^\s#'"{\[][^:#]*?)\s*:(?=\s|$)""")
_PLAIN = re.compile(r"^[A-Za-z0-9_/][A-Za-z0-9_./@+~=-]*$")
_YAML_WORDS = {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~"}


class EditError(Exception):
    pass


# --------------------------------------------------------------------------- rendering

def plain_ok(s: str) -> bool:
    if not _PLAIN.match(s) or s.lower() in _YAML_WORDS:
        return False
    try:
        json.loads(s)
        return False          # a number
    except ValueError:
        return True


def render(v, quote_strings: bool = False) -> str:
    """One-line (flow) YAML for a value."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, str):
        return v if (plain_ok(v) and not quote_strings) else json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(render(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k if plain_ok(str(k)) else json.dumps(str(k))}: {render(x)}"
                               for k, x in v.items()) + "}"
    raise EditError(f"unsupported value type {type(v).__name__}")


def parse_value(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


# --------------------------------------------------------------------------- locating keys

def _significant(line: str) -> bool:
    s = line.strip()
    return bool(s) and not s.startswith("#")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_comment(rest: str) -> tuple[str, str]:
    """Split the text after `key:` into (value, ' # comment' with its leading spaces)."""
    q = None
    for i, c in enumerate(rest):
        if q:
            if c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == "#" and (i == 0 or rest[i - 1] in " \t"):
            j = i
            while j > 0 and rest[j - 1] in " \t":
                j -= 1
            return rest[:j], rest[j:]
    return rest.rstrip(), ""


def _key_name(raw: str) -> str:
    raw = raw.strip()
    return raw[1:-1] if raw[:1] in "\"'" and raw[-1:] == raw[:1] else raw


def _block_end(lines: list[str], i: int) -> int:
    """Index after the last child line of the key on line i (comments after it are not children)."""
    ind, end = _indent(lines[i]), i + 1
    for j in range(i + 1, len(lines)):
        if not _significant(lines[j]):
            continue
        if _indent(lines[j]) <= ind and not (lines[j].lstrip().startswith("- ") and _indent(lines[j]) == ind):
            break
        end = j + 1
    return end


def _find(lines: list[str], key: str, start: int, end: int) -> int | None:
    child = None
    for j in range(start, end):
        if not _significant(lines[j]):
            continue
        if child is None:
            child = _indent(lines[j])
        m = _KEY.match(lines[j])
        if m and _indent(lines[j]) == child and _key_name(m.group(2)) == key:
            return j
    return None


def _child_indent(lines: list[str], start: int, end: int, parent_indent: int) -> int:
    for j in range(start, end):
        if _significant(lines[j]):
            return _indent(lines[j])
    return parent_indent + 2


def _get(doc, path):
    for p in path:
        doc = doc[p]
    return doc


# --------------------------------------------------------------------------- editing

def _replace_value(lines, i, value, comment=None, keep_quotes=True):
    line = lines[i].rstrip("\n")
    m = _KEY.match(line)
    head = line[:m.end()]
    old_val, old_comment = _split_comment(line[m.end():])
    end = _block_end(lines, i)
    old_block = lines[i + 1:end]
    if isinstance(value, list) and old_block and old_block[-1].lstrip().startswith("- ") and value:
        # block list stays a block list
        ind = " " * _indent(next(x for x in old_block if x.lstrip().startswith("- ")))
        new = [head + old_val.rstrip() + (old_comment if comment is None else f"  # {comment}" if comment else "") + "\n"]
        new += [f"{ind}- {render(v)}\n" for v in value]
        lines[i:end] = new
        return
    quoted = keep_quotes and old_val.strip()[:1] in "\"'" and isinstance(value, str)
    lead = old_val[:len(old_val) - len(old_val.lstrip())] or " "
    new_val = lead + render(value, quote_strings=quoted)
    text = old_comment.lstrip() if comment is None else (f"# {comment}" if comment else "")
    if text and old_comment:
        # keep the comment's column when the value still fits before it
        col = len(head) + len(old_val) + (len(old_comment) - len(old_comment.lstrip()))
        tail = " " * max(1, col - len(head) - len(new_val)) + text
    else:
        tail = ("  " + text) if text else ""
    lines[i:end] = [head + new_val + tail + "\n"]


def apply_ops(text: str, doc: dict, ops: list[tuple]) -> tuple[str, dict]:
    """ops: ("set", path, value[, comment]) | ("add"|"remove", path, item) | ("delete", path).

    Returns (new text, expected document). Raises EditError when it can't edit safely.
    """
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    want = copy.deepcopy(doc)
    for op in ops:
        kind, path = op[0], op[1].split(".")
        # expected document
        parent = want
        for p in path[:-1]:
            if not isinstance(parent, dict):
                raise EditError(f"{'.'.join(path)}: {p} is not a mapping")
            if kind == "delete":
                parent = parent.get(p) or {}
                continue
            if parent.get(p) is None:
                parent[p] = {}
            parent = parent[p]
        if not isinstance(parent, dict):
            raise EditError(f"{'.'.join(path)}: parent is not a mapping")
        leaf = path[-1]
        comment = None
        if kind == "set":
            parent[leaf] = op[2]
            comment = op[3] if len(op) > 3 else None
        elif kind in ("add", "remove"):
            cur = parent.get(leaf)
            cur = [] if cur is None else cur
            if not isinstance(cur, list):
                raise EditError(f"{'.'.join(path)} is not a list")
            if kind == "add" and op[2] not in cur:
                cur = cur + [op[2]]
            elif kind == "remove":
                cur = [x for x in cur if x != op[2]]
            parent[leaf] = cur
        elif kind == "delete":
            if leaf not in parent:
                continue
            del parent[leaf]
        else:
            raise EditError(f"unknown operation {kind}")

        # text: deepest existing block key on the path
        start, end, line_no, depth, base_indent = 0, len(lines), None, 0, -2
        for d, p in enumerate(path):
            j = _find(lines, p, start, end)
            if j is None:
                break
            line_no, depth = j, d + 1
            start, end = j + 1, _block_end(lines, j)
            base_indent = _indent(lines[j])
        if depth == len(path):
            if kind == "delete":
                del lines[line_no:_block_end(lines, line_no)]
            else:
                _replace_value(lines, line_no, _get(want, path), comment)
            continue
        if line_no is not None:
            line = lines[line_no].rstrip("\n")
            m = _KEY.match(line)
            val, cmt = _split_comment(line[m.end():])
            val = val.strip()
            if val.startswith("{"):               # inline mapping: re-render it whole
                _replace_value(lines, line_no, _get(want, path[:depth]), None)
                continue
            if val in ("~", "null"):              # empty value becomes a block mapping
                lines[line_no] = line[:m.end()] + cmt + "\n"
                start = end = line_no + 1
            elif val:
                raise EditError(f"{'.'.join(path[:depth])} is not a mapping")
        if kind == "delete":
            continue
        # insert the missing chain at the end of the deepest existing block
        ind = _child_indent(lines, start, end, base_indent) if line_no is not None else 0
        at = end if line_no is not None else len(lines)
        new, rest = [], path[depth:]
        for k, p in enumerate(rest):
            pad = " " * (ind + 2 * k)
            if k < len(rest) - 1:
                new.append(f"{pad}{p}:\n")
            else:
                body = f"{pad}{p}: {render(_get(want, path))}"
                c = ""
                if comment:   # line the comment up with the sibling above, if it has one
                    prev = lines[at - 1] if at else ""
                    col = prev.find(" #") + 1 if _KEY.match(prev) and " #" in prev else 0
                    c = " " * max(2, col - len(body)) + f"# {comment}"
                new.append(f"{body}{c}\n")
        lines[at:at] = new
    return "".join(lines), want


def yq_json(text: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
    try:
        r = subprocess.run(["yq", "-o=json", ".", f.name], capture_output=True, text=True, timeout=20)
    finally:
        Path(f.name).unlink()
    if r.returncode != 0:
        raise EditError(f"result is not valid YAML: {r.stderr.strip()}")
    return json.loads(r.stdout or "{}") or {}


def _norm(v):
    """A mapping whose last key was deleted reads back as null: treat {} and null alike."""
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()} or None
    if isinstance(v, list):
        return [_norm(x) for x in v]
    return v


def edit_file(path: Path, ops: list[tuple], dry_run: bool = False) -> str:
    """Apply ops to a YAML file; verify with yq; return a unified diff ('' = no change)."""
    old = path.read_text()
    new, want = apply_ops(old, yq_json(old), ops)
    got = yq_json(new)
    if _norm(got) != _norm(want):
        raise EditError("the edited file doesn't match the intended change; nothing was written. "
                        "Edit by hand and note a skill issue (script:config_set).")
    diff = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        f"a/{path.name}", f"b/{path.name}"))
    if diff and not dry_run:
        path.write_text(new)
    return diff


def parse_op(arg: str) -> tuple:
    m = re.match(r"^([A-Za-z0-9_.-]+?)(\+=|-=|=)(.*)$", arg, re.S)
    if not m:
        raise EditError(f"can't parse {arg!r}: expected path=value, path+=item or path-=item")
    path, sign, value = m.groups()
    kind = {"=": "set", "+=": "add", "-=": "remove"}[sign]
    return (kind, path, parse_value(value))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ops", nargs="*", help="path=value | path+=item | path-=item")
    ap.add_argument("--delete", action="append", default=[], metavar="PATH")
    ap.add_argument("--file", help="default: homelab.yaml of this repo")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.file:
        target = Path(a.file)
    else:
        root = hmlib.find_repo_root()
        if not root:
            print(f"No {hmlib.CONFIG_NAME} found in this directory or its parents.", file=sys.stderr)
            return 2
        target = root / hmlib.CONFIG_NAME
    try:
        ops = [parse_op(x) for x in a.ops] + [("delete", p) for p in a.delete]
        if not ops:
            ap.error("nothing to change")
        diff = edit_file(target, ops, a.dry_run)
    except EditError as e:
        print(f"config_set: {e}", file=sys.stderr)
        return 1
    print(diff or "no change", end="" if diff else "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
