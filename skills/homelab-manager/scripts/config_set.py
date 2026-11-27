#!/usr/bin/env python3
"""Change values in homelab.yaml without disturbing the rest of the file.

    config_set.py 'site.domain=home.arpa' 'proxmox.verify_tls=false'
    config_set.py 'network.authorized_ranges+=10.0.10.0/24'    # append to a list (skipped if present)
    config_set.py 'sites+={name: offsite, label: Rented server, proxmox: {endpoint: https://…:8006}}'
    config_set.py 'network.excluded_hosts-=10.0.10.1'          # remove from a list
    config_set.py 'defaults.ssh_public_keys=["ssh-ed25519 AAAA… me@mac"]'
    config_set.py 'sites[offsite].proxmox.ca_cert=~/.config/homelab/ca.pem'   # a list entry by name (or id)
    config_set.py 'network.vlans[20].gw=10.0.20.1'
    config_set.py --delete discovery.ignore_unmanaged
    config_set.py --dry-run …                                  # print the diff, write nothing

`yq -i` re-serialises the whole document: it drops blank lines and comment alignment, and turns
`key: []  # comment` into a block list whose comment lands on a later key. This edits only the
lines of the keys it changes (an inline comment stays on its key) and checks the result with yq
(the whole document must equal the old one plus exactly these changes) before writing; on any
mismatch it writes nothing and exits 1 — then note a skill issue (SKILL.md §6).

Values: JSON if they parse as JSON (`true`, `3`, `["a", "b"]`, `"3"`), YAML flow syntax for a mapping or list
(`network.vlans+={id: 20, name: DMZ, cidr: 10.0.20.0/24}`), otherwise a plain string.
Missing keys (and parent mappings) are added at the end of their parent block. A mapping (or a list of mappings) set
on a new or empty key is written in block style; a value that is flow already stays flow.
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


def blocky(v) -> bool:
    """A value written in block style when it is new: a mapping, or a list holding one (GitHub issue #176)."""
    return (isinstance(v, dict) and bool(v)) or (isinstance(v, list) and any(isinstance(x, dict) and x for x in v))


def render_block(v, ind: int) -> list[str]:
    """Block-style YAML lines for a mapping or list, its keys at indent ind; scalars and empty values in flow."""
    pad, out = " " * ind, []
    if isinstance(v, dict):
        for k, x in v.items():
            key = k if plain_ok(str(k)) else json.dumps(str(k))
            if isinstance(x, (dict, list)) and x and (isinstance(x, dict) or blocky(x)):
                out += [f"{pad}{key}:\n"] + render_block(x, ind + 2)
            else:
                out.append(f"{pad}{key}: {render(x)}\n")
        return out
    for x in v:
        if isinstance(x, dict) and x:
            sub = render_block(x, ind + 2)
            out += [f"{pad}- {sub[0][ind + 2:]}"] + sub[1:]
        else:
            out.append(f"{pad}- {render(x)}\n")
    return out


def parse_value(text: str):
    try:
        return json.loads(text)
    except ValueError:
        pass
    if text.strip()[:1] in ("{", "["):  # YAML flow syntax: {id: 20, name: DMZ}; else a string ({vlan}{octet:03d})
        r = subprocess.run([hmlib.yq_bin(), "-o=json", "-p=yaml", "."], input=text, capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            v = json.loads(r.stdout or "null")
            if isinstance(v, (dict, list)):
                return v
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
    if blocky(value) and old_val.strip() in ("", "{}", "[]", "~", "null", '""', "''") and not any(
            x.lstrip().startswith("- ") for x in old_block if _significant(x)):
        # an empty value or a block mapping becomes a block (GitHub issue #176); a flow value stays flow
        text = old_comment.lstrip() if comment is None else (f"# {comment}" if comment else "")
        gap = len(old_val) + len(old_comment) - len(old_comment.lstrip())     # keep the comment's column
        tail = (" " * max(2, gap) + text) if text and old_comment else (("  " + text) if text else "")
        lines[i:end] = [head + tail + "\n"] + render_block(value, _indent(line) + 2)
        return
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


_SEG = re.compile(r"([A-Za-z0-9_-]+)(?:\[([^\]]*)\])?(?:\.|$)")
_PATH = r"[A-Za-z0-9_-]+?(?:\[[^\]=]*\])?(?:\.[A-Za-z0-9_-]+?(?:\[[^\]=]*\])?)*?"


def segments(path: str) -> list[tuple[str, str | None]]:
    """'sites[offsite].proxmox.ca_cert' -> [('sites', 'offsite'), ('proxmox', None), ('ca_cert', None)]."""
    segs = [(m.group(1), m.group(2)) for m in _SEG.finditer(path)]
    if not segs or "".join(f"{k}[{s}]." if s is not None else f"{k}." for k, s in segs)[:-1] != path:
        raise EditError(f"can't parse path {path!r}")
    return segs


def select(items, sel: str, where: str) -> int:
    """Index of the one list entry a selector names (GitHub issue #99): its name, else its id, else the item itself
    for a list of scalars."""
    if not isinstance(items, list):
        raise EditError(f"{where} is not a list")
    for field in ("name", "id"):
        hits = [i for i, x in enumerate(items) if isinstance(x, dict) and field in x and str(x[field]) == sel]
        if hits:
            break
    else:
        hits = [i for i, x in enumerate(items) if not isinstance(x, (dict, list)) and str(x) == sel]
    if len(hits) != 1:
        names = [str(x.get("name", x.get("id"))) if isinstance(x, dict) else str(x) for x in items]
        raise EditError(f"{where}[{sel}]: {'no entry' if not hits else f'{len(hits)} entries'} with name or id "
                        f"{sel!r} (entries: {', '.join(names) or 'none'})")
    return hits[0]


def _expect(want: dict, kind: str, segs, value) -> list | None:
    """Apply one operation to the expected document; return the concrete path (keys and list indexes), or None
    when there is nothing to do (deleting a missing key)."""
    path, parent, where = [], want, ""
    for n, (key, sel) in enumerate(segs):
        last = n == len(segs) - 1
        where = f"{where}.{key}" if where else key
        if not isinstance(parent, dict):
            raise EditError(f"{where}: parent is not a mapping")
        if last and sel is None:
            path.append(key)
            break
        if sel is None:
            if kind == "delete" and not isinstance(parent.get(key), dict):
                return None
            if parent.get(key) is None:
                parent[key] = {}
            parent, path = parent[key], path + [key]
            continue
        idx = select(parent.get(key), sel, where)
        where += f"[{sel}]"
        path += [key, idx]
        if last:
            break
        parent = parent[key][idx]
    leaf = path[-1]
    container = _get(want, path[:-1])
    if kind == "set":
        container[leaf] = value
    elif kind in ("add", "remove"):
        cur = container[leaf] if isinstance(leaf, int) else container.get(leaf)
        cur = [] if cur is None else cur
        if not isinstance(cur, list):
            raise EditError(f"{where} is not a list")
        if kind == "add" and value not in cur:
            cur = cur + [value]
        elif kind == "remove":
            cur = [x for x in cur if x != value]
        container[leaf] = cur
    elif kind == "delete":
        if isinstance(leaf, int):
            del container[leaf]
        elif leaf in container:
            del container[leaf]
        else:
            return None
    else:
        raise EditError(f"unknown operation {kind}")
    return path


def _list_items(lines: list[str], start: int, end: int) -> list[int]:
    """Line numbers of the `- ` entries of the block list in lines[start:end]."""
    ind = _child_indent(lines, start, end, 0)
    return [k for k in range(start, end) if _significant(lines[k]) and _indent(lines[k]) == ind
            and (lines[k].lstrip().startswith("- ") or lines[k].strip() == "-")]


def _edit_text(lines: list[str], path: list, kind: str, root, comment, top: int = 0) -> None:
    """Change the text of lines to match the expected value at path (keys and list indexes) under root, the
    expected value these lines hold. top: indent of their keys when none is found (a list entry's body)."""
    start, end, line_no, depth, base_indent = 0, len(lines), None, 0, -2
    for d, p in enumerate(path):
        if isinstance(p, int):                    # an entry of the list whose key is on line_no
            line = lines[line_no].rstrip("\n")
            if _split_comment(line[_KEY.match(line).end():])[0].strip():   # flow list: re-render it whole
                _replace_value(lines, line_no, _get(root, path[:d]), None)
                return
            items = _list_items(lines, start, end)
            a = items[p]
            b = items[p + 1] if p + 1 < len(items) else end
            ind = " " * _indent(lines[a])
            rest, item = path[d + 1:], (None if kind == "delete" and d == len(path) - 1 else _get(root, path[:d + 1]))
            body = lines[a].lstrip()[1:].lstrip(" ")
            if not rest or not isinstance(item, dict) or body.startswith("{") or not _KEY.match(body):
                lines[a:b] = [] if item is None else [f"{ind}- {render(item)}\n"]
                return
            pad = ind + "  "
            sub = [pad + body] + lines[a + 1:b]
            _edit_text(sub, rest, kind, item, comment, len(pad))
            k = next((k for k, x in enumerate(sub) if _significant(x)), None)
            if k is None:
                sub = [f"{ind}- {{}}\n"]
            else:
                sub[k] = f"{ind}- {sub[k][len(pad):]}"
            lines[a:b] = sub
            return
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
            _replace_value(lines, line_no, _get(root, path), comment)
        return
    if line_no is not None:
        line = lines[line_no].rstrip("\n")
        m = _KEY.match(line)
        val, cmt = _split_comment(line[m.end():])
        val = val.strip()
        if val.startswith("{"):               # inline mapping: re-render it whole
            _replace_value(lines, line_no, _get(root, path[:depth]), None)
            return
        if val in ("~", "null"):              # empty value becomes a block mapping
            lines[line_no] = line[:m.end()] + cmt + "\n"
            start = end = line_no + 1
        elif val:
            raise EditError(f"{'.'.join(map(str, path[:depth]))} is not a mapping")
    if kind == "delete":
        return
    # insert the missing chain at the end of the deepest existing block
    ind = _child_indent(lines, start, end, base_indent) if line_no is not None else top
    at = end if line_no is not None else len(lines)
    new, rest = [], path[depth:]
    for k, p in enumerate(rest):
        pad = " " * (ind + 2 * k)
        if k < len(rest) - 1:
            new.append(f"{pad}{p}:\n")
        else:
            v = _get(root, path)
            body = f"{pad}{p}:" if blocky(v) else f"{pad}{p}: {render(v)}"
            c = ""
            if comment:   # line the comment up with the sibling above, if it has one
                prev = lines[at - 1] if at else ""
                col = prev.find(" #") + 1 if _KEY.match(prev) and " #" in prev else 0
                c = " " * max(2, col - len(body)) + f"# {comment}"
            new.append(f"{body}{c}\n")
            if blocky(v):
                new += render_block(v, ind + 2 * k + 2)
    lines[at:at] = new


def apply_ops(text: str, doc: dict, ops: list[tuple]) -> tuple[str, dict]:
    """ops: ("set", path, value[, comment]) | ("add"|"remove", path, item) | ("delete", path).
    A path segment may select a list entry by name or id: sites[offsite].proxmox.ca_cert (GitHub issue #99).

    Returns (new text, expected document). Raises EditError when it can't edit safely.
    """
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    want = copy.deepcopy(doc)
    for op in ops:
        kind = op[0]
        path = _expect(want, kind, segments(op[1]), op[2] if len(op) > 2 else None)
        if path is not None:
            _edit_text(lines, path, kind, want, op[3] if kind == "set" and len(op) > 3 else None)
    return "".join(lines), want


def yq_json(text: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
    try:
        r = subprocess.run([hmlib.yq_bin(), "-o=json", ".", f.name], capture_output=True, text=True, timeout=20)
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
    if any(segments(op[1])[0][0] in ("sites", "network", "opentofu", "discovery") for op in ops):
        try:   # site names become Ansible groups, VLAN sites must exist: refuse a bad edit before writing
            hmlib.sites(want)
        except hmlib.ConfigError as e:
            raise EditError(f"{e} Nothing was written.") from None
    if any(segments(op[1])[0][0] in ("templates", "sites") for op in ops):   # Packer refuses others (#158)
        bad = hmlib.template_build_errors(want)
        if bad:
            raise EditError(f"{' '.join(bad)} Nothing was written.")
    if any(segments(op[1])[0][0] == "pbs" for op in ops):
        try:   # GitHub issue #151: each Proxmox Backup Server needs a server and a token
            hmlib.pbs_servers(want)
        except hmlib.ConfigError as e:
            raise EditError(f"{e} Nothing was written.") from None
    lang = hmlib.get(want, "site.language")
    if lang is not None and any(segments(op[1])[0][0] == "site" for op in ops) and not hmlib.language_code(lang):
        raise EditError("site.language must be a language code such as sk or pt-BR (or one word naming the "
                        "language); nothing was written.")
    got = yq_json(new)
    if _norm(got) != _norm(want):
        raise EditError("the edited file doesn't match the intended change; nothing was written. "
                        "Edit by hand and note a skill issue (script:config_set).")
    diff = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        f"a/{path.name}", f"b/{path.name}"))
    if diff and not dry_run:
        hmlib.atomic_write(path, new)
    return diff


def site_defaults(ops: list[tuple], doc: dict) -> list[str]:
    """Sites (GitHub issue #65): a VLAN added without a site gets the only site's name (with several, a note asks
    for one); adding the first site points at init_repo.py --name-default-site. Changes ops in place."""
    raw = doc.get("sites") if isinstance(doc.get("sites"), list) else []
    names = [str(x.get("name")) for x in raw if isinstance(x, dict) and x.get("name")]
    notes = []
    for i, op in enumerate(ops):
        if op[0] == "add" and op[1] == "network.vlans" and isinstance(op[2], dict) and op[2].get("site") in (None, ""):
            if len(names) == 1:
                ops[i] = (op[0], op[1], {**op[2], "site": names[0]})
                notes.append(f"config_set: VLAN {op[2].get('id')} gets site: {names[0]} (the only site; "
                             f"site: {hmlib.EVERY_SITE} for one every site has)")
            elif len(names) > 1:
                notes.append(f"config_set: VLAN {op[2].get('id')} has no site, so it applies to every site — add "
                             f"site: <{'|'.join(names)}> (or {hmlib.EVERY_SITE})")
        if op[0] == "add" and op[1] == "sites" and not raw:
            notes.append("config_set: the first site is the default (the existing location). "
                         "init_repo.py --name-default-site <name> also gives it ranges, tags its VLANs and creates "
                         "site_<name>.")
    return notes


def parse_op(arg: str) -> tuple:
    m = re.match(rf"^({_PATH})(\+=|-=|=)(.*)$", arg, re.S)
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
        hmlib.yq_bin()   # a clean error, not a traceback, when yq is missing (GitHub issue #119)
    except hmlib.ConfigError as e:
        print(f"config_set: {e}", file=sys.stderr)
        return 2
    try:
        ops = [parse_op(x) for x in a.ops] + [("delete", p) for p in a.delete]
        if not ops:
            ap.error("nothing to change")
        notes = site_defaults(ops, yq_json(target.read_text()))
        diff = edit_file(target, ops, a.dry_run)
    except EditError as e:
        print(f"config_set: {e}", file=sys.stderr)
        return 1
    print(diff or "no change", end="" if diff else "\n")
    for n in notes:
        print(n, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
