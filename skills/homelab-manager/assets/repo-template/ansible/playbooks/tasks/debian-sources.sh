#!/bin/sh
# APT sources and pins for dist-upgrade-debian.yml (GitHub issue #84). POSIX sh and awk (mawk, BSD awk).
#
#   debian-sources.sh list    FROM [MIRRORS]     one line per active entry: <file> TAB <kind> TAB <suites> TAB <uris>
#   debian-sources.sh pins                       active pin files (/etc/apt/preferences, preferences.d/*)
#   debian-sources.sh rewrite FROM TO [MIRRORS]  Debian entries of release FROM move to TO
#   debian-sources.sh disable FROM [MIRRORS]     foreign entries and pins are switched off (reversible)
#
# kind: debian — a Debian archive (a URI containing debian.org, or starting with one of MIRRORS, space-separated
# URI prefixes of local mirrors or caches) with a suite of release FROM (FROM, FROM-updates, FROM-security,
# FROM/updates, FROM-backports, FROM-proposed-updates); foreign — anything else: third-party repositories, other
# releases (stable, testing, sid, …). Only debian entries are rewritten; a release upgrade with foreign entries
# active is refused unless they are disabled or kept on purpose.
# disable comments a one-line entry out with "#hm-disabled " and adds the lines "#hm-disabled" and "Enabled: no"
# to a deb822 stanza; pin files get the suffix .hm-disabled. Undo: remove those markers (references/patching.md).
# HM_APT_ROOT (default /etc/apt) lets tests run it on a copy.
set -eu
mode=${1:-}
root=${HM_APT_ROOT:-/etc/apt}
case $mode in
  list|disable) from=$2; to=; mirrors=${3:-} ;;
  rewrite) from=$2; to=$3; mirrors=${4:-} ;;
  pins) from=; to=; mirrors= ;;
  *) echo "usage: $0 list|pins|rewrite|disable …" >&2; exit 2 ;;
esac

if [ "$mode" = pins ] || [ "$mode" = disable ]; then
  for f in "$root/preferences" "$root"/preferences.d/*; do
    [ -f "$f" ] || continue
    case $f in *.hm-disabled|*.dpkg-*|*.ucf-*|*~) continue ;; esac
    grep -q '^[[:space:]]*Pin' "$f" || continue
    if [ "$mode" = pins ]; then echo "$f"; else mv "$f" "$f.hm-disabled"; fi
  done
  [ "$mode" = pins ] && exit 0
fi

# shared awk: is_debian(uris) and kind(uris, suites)
common='
function is_debian(uris,   n, i, j, u, m, k) {
  n = split(uris, u, " ")
  if (n == 0) return 0
  k = split(mirrors, m, " ")
  for (i = 1; i <= n; i++) {
    if (u[i] ~ /debian\.org/) continue
    ok = 0
    for (j = 1; j <= k; j++) if (index(u[i], m[j]) == 1) ok = 1
    if (!ok) return 0
  }
  return 1
}
function base(s) { sub(/[-\/].*$/, "", s); return s }
function kind(uris, suites,   n, i, s) {
  if (!is_debian(uris)) return "foreign"
  n = split(suites, s, " ")
  if (n == 0) return "foreign"
  for (i = 1; i <= n; i++) if (base(s[i]) != from) return "foreign"
  return "debian"
}
function newsuite(s,   rest) {
  rest = substr(s, length(from) + 1)
  if (from == "buster" && rest == "/updates") rest = "-security"   # the security suite was renamed in bullseye
  return to rest
}
'

# one-line format: deb [options] URI SUITE COMPONENTS…
list_awk="$common"'
{
  line = $0
  if (line !~ /^[ \t]*deb(-src)?[ \t]/) { print; next }
  l = line; sub(/\[[^]]*\]/, "", l); split(l, f, /[ \t]+/)
  if (f[1] == "") { uri = f[3]; suite = f[4] } else { uri = f[2]; suite = f[3] }
  k = kind(uri, suite)
  if (mode == "list") { printf "%s\t%s\t%s\t%s\n", FILENAME, k, suite, uri > "/dev/stderr"; print; next }
  if (mode == "disable" && k == "foreign") { print "#hm-disabled " line; next }
  if (mode == "rewrite" && k == "debian") {
    p = index(line, uri) + length(uri); head = substr(line, 1, p - 1); rest = substr(line, p)
    q = index(rest, suite)
    line = head substr(rest, 1, q - 1) newsuite(suite) substr(rest, q + length(suite))
    if (to == "bookworm" && line ~ /[ \t]non-free([ \t]|$)/ && line !~ /non-free-firmware/) line = line " non-free-firmware"
  }
  print line
}'

# deb822 format: stanzas separated by blank lines, fields Types/URIs/Suites/Components/Enabled
deb822_awk="$common"'
BEGIN { RS = ""; ORS = "\n\n" }
{
  n = split($0, L, "\n"); uris = ""; suites = ""; enabled = 1
  for (i = 1; i <= n; i++) {
    if (L[i] ~ /^URIs:/) { uris = L[i]; sub(/^URIs:[ \t]*/, "", uris) }
    if (L[i] ~ /^Suites:/) { suites = L[i]; sub(/^Suites:[ \t]*/, "", suites) }
    if (L[i] ~ /^Enabled:[ \t]*no/) enabled = 0
  }
  if (!enabled || uris == "") { print; next }
  k = kind(uris, suites)
  if (mode == "list") { printf "%s\t%s\t%s\t%s\n", FILENAME, k, suites, uris > "/dev/stderr"; print; next }
  if (mode == "disable" && k == "foreign") { print $0 "\n#hm-disabled\nEnabled: no"; next }
  if (mode == "rewrite" && k == "debian") {
    out = ""
    for (i = 1; i <= n; i++) {
      l = L[i]
      if (l ~ /^Suites:/) {
        m = split(suites, s, /[ \t]+/); l = "Suites:"
        for (j = 1; j <= m; j++) l = l " " newsuite(s[j])
      }
      if (to == "bookworm" && l ~ /^Components:/ && l ~ /[ \t]non-free([ \t]|$)/ && l !~ /non-free-firmware/) l = l " non-free-firmware"
      out = out (i > 1 ? "\n" : "") l
    }
    print out; next
  }
  print
}'

for f in "$root/sources.list" "$root"/sources.list.d/*.list "$root"/sources.list.d/*.sources; do
  [ -f "$f" ] || continue
  case $f in *.sources) prog=$deb822_awk ;; *) prog=$list_awk ;; esac
  tmp="$f.hm-new"
  if [ "$mode" = list ]; then
    awk -v mode=list -v from="$from" -v to="$to" -v mirrors="$mirrors" "$prog" "$f" 2>&1 >/dev/null
    continue
  fi
  awk -v mode="$mode" -v from="$from" -v to="$to" -v mirrors="$mirrors" "$prog" "$f" > "$tmp"
  case $f in *.sources) printf '%s\n' "$(cat "$tmp")" > "$tmp.2" && mv "$tmp.2" "$tmp" ;; esac   # one final newline
  if cmp -s "$f" "$tmp"; then rm -f "$tmp"; else cat "$tmp" > "$f"; rm -f "$tmp"; echo "changed $f"; fi
done
