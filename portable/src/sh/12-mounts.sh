# ============================================================== mount table and temp directory
# The mount table (network and autofs mounts are never touched) and the private temporary
# directory, which is never put on such a mount.

# es_proc_mounts FILE: a /proc mounts file as "device TAB mount TAB fstype TAB options" lines.
# Every octal escape \ooo (000-377) of the four fields becomes its byte (\040 space, \043 "#",
# \134 backslash, ...), except \011 tab and \012 newline: the table is tab and newline separated,
# so those stay as written and paths are compared in that spelling (es_mount_text). Anything else
# after a backslash stays as it is.
es_proc_mounts() {
  awk 'BEGIN { for (i = 0; i < 8; i++) OCT[i ""] = i }
    function dec(s,   r, k, o, v) {
      r = ""
      while ((k = index(s, "\\")) > 0) {
        o = substr(s, k + 1, 3)
        if (o !~ /^[0-3][0-7][0-7]$/ || o == "011" || o == "012") { r = r substr(s, 1, k); s = substr(s, k + 1); continue }
        v = OCT[substr(o, 1, 1)] * 64 + OCT[substr(o, 2, 1)] * 8 + OCT[substr(o, 3, 1)]
        r = r substr(s, 1, k - 1) sprintf("%c", v); s = substr(s, k + 4)
      }
      return r s
    }
    NF >= 4 { printf "%s\t%s\t%s\t%s\n", dec($1), dec($2), dec($3), dec($4) }' "$1"
}

# es_mounts_init: mount table as "device TAB mount TAB fstype TAB options" in $ES_TMP/mounts.tsv
es_mounts_init() {
  ES_MOUNT_SRC=
  es_net_fs_extend
  for es_mf in "$ES_ROOT/proc/self/mounts" "$ES_ROOT/proc/mounts"; do
    [ -r "$es_mf" ] || continue
    es_proc_mounts "$es_mf" >"$ES_TMP/mounts.tsv"
    if [ -s "$ES_TMP/mounts.tsv" ]; then
      ES_MOUNT_SRC="read ${es_mf#"$ES_ROOT"}"
      return 0
    fi
  done
  es_which mount || return 1
  es_mcmd=$ES_W; es_marg=
  case $ES_OS in sunos|hpux) es_marg=-p ;; esac
  es_exec "$ES_TIMEOUT" "$ES_TMP/mount.out" "$ES_TMP/mount.err" "$es_mcmd" $es_marg
  ES_MOUNT_SRC="run mount${es_marg:+ }$es_marg"
  awk -v os="$ES_OS" '
    function zfs_of(   i, t) {
      for (i = 1; i <= NF; i++) { t = toupper($i); sub(/[,;:]$/, "", t)
        if (t == "ZFS" || t == "HFS" || t == "TFS" || t == "NFS" || t == "AUTOMNT" || t == "DFS") return tolower(t) }
      return "unknown" }
    function zflush() { if (zmnt != "") printf "%s\t%s\t%s\t\n", zdev, zmnt, zfs; zmnt = "" }
    os == "zos" {
      if ($0 ~ /^[^ \t]+[ \t]+\(\/[^)]*\)/) {
        zflush(); zdev = $1; zmnt = $0; sub(/^[^(]*\(/, "", zmnt); sub(/\).*/, "", zmnt); zfs = zfs_of(); next }
      if (zmnt != "" && zfs == "unknown") zfs = zfs_of()
      next }
    os == "sunos" || os == "hpux" { if (NF >= 7 && $1 != "#") printf "%s\t%s\t%s\t%s\n", $1, $3, $4, $7; next }
    os == "aix" || os == "os400" {
      if ($0 ~ /^ *node|^ *-----/) next
      if ($1 ~ /^\//) printf "%s\t%s\t%s\t%s\n", $1, $2, $3, $NF
      else if (NF >= 7 && $3 ~ /^\//) printf "%s:%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $NF
      next }
    / on / {
      dev = $0; sub(/ on .*/, "", dev); rest = $0; sub(/^.* on /, "", rest)
      if (rest ~ / type /) { mnt = rest; sub(/ type .*/, "", mnt); fs = rest; sub(/^.* type /, "", fs); opt = fs; sub(/ .*/, "", fs); sub(/^[^(]*\(/, "", opt); sub(/\).*/, "", opt) }
      else { mnt = rest; sub(/ \(.*/, "", mnt); opt = rest; sub(/^[^(]*\(/, "", opt); sub(/\).*/, "", opt); fs = opt; sub(/,.*/, "", fs); sub(/^[^,]*,? */, "", opt); gsub(/, /, ",", opt) }
      printf "%s\t%s\t%s\t%s\n", dev, mnt, fs, opt }
    END { zflush() }' "$ES_TMP/mount.out" >"$ES_TMP/mounts.tsv"
  [ -s "$ES_TMP/mounts.tsv" ]
}

# es_netmnts_early -> ES_NETMNTS from /proc/self/mounts (Linux, Cygwin) before the temporary
# directory exists, so that es_mktemp never puts it on a network or autofs mount (TMPDIR or HOME
# there). Elsewhere the mount table needs mount(8) with a timeout and a temp file: es_tmp_check
# reports such a temp directory afterwards.
es_netmnts_early() {
  ES_NETMNTS=
  for es_mf in "$ES_ROOT/proc/self/mounts" "$ES_ROOT/proc/mounts"; do
    [ -r "$es_mf" ] || continue
    ES_NETMNTS=$(es_proc_mounts "$es_mf" | awk -F '\t' -v net="$ES_NET_FS" -v npre="$ES_NET_FS_PREFIXES" -v lfuse="$ES_LOCAL_FUSE" "$ES_AWK_NETFS"' $2 != "/" && es_isnet($3) { print $2 }')
    [ -n "$ES_NETMNTS" ] && ES_NETMNTS="$ES_NETMNTS$ES_NL"
    break
  done
  es_win_netmnts
  # IBM i: /QNTC and /QFileSvr.400 are network roots before any mount table is read, so that a
  # TMPDIR on them is refused before the temporary directory is made (ES_OS is not known yet)
  es_en_os=${ES_OS:-}; [ -n "$es_en_os" ] || es_en_os=$(uname -s 2>/dev/null)
  case $es_en_os in os400|OS400) ES_NETMNTS="${ES_NETMNTS:-}/QNTC$ES_NL/QFileSvr.400$ES_NL" ;; esac
  return 0
}

es_mktemp() {
  es_netmnts_early
  for es_base in "${TMPDIR:-}" /tmp /var/tmp "$HOME"; do
    [ -n "$es_base" ] && es_local_path "$es_base" || continue
    [ -d "$es_base" ] && [ -w "$es_base" ] || continue
    es_try=0
    while [ $es_try -lt 20 ]; do
      ES_TMP="${es_base%/}/envscan.$$.$es_try"
      if mkdir "$ES_TMP" 2>/dev/null; then return 0; fi
      es_try=$((es_try + 1))
    done
  done
  ES_TMP=
  es_fatal "cannot create a private temporary directory (TMPDIR, /tmp, /var/tmp, HOME)"
}

# es_tmp_check: the log says so when the temporary directory is on a network or autofs mount
# (a system without /proc/self/mounts and a TMPDIR there)
es_tmp_check() {
  es_local_path "$ES_TMP" || es_log "warning: the temporary directory $ES_TMP is on a network or autofs mount (TMPDIR); raw data is written there until the scan ends"
  return 0
}
