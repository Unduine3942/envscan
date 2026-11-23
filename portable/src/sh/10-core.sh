# ============================================================== core helpers
# Conventions: functions are es_* (core) or probe_<area>_<name>; there is no
# "local", so helpers prefix their variables with a short tag of their own name.
# Probes run in background subshells with ES_P_DIR set; events go to fd 5.

ES_IMPL='posix-sh'
ES_NL='
'
ES_TAB=$(printf '\t')
ES_CR=$(printf '\r')
ES_PROBE_CAP=240
ES_LONG_PROBE_CAP=600
ES_RAW_CAP=65536
ES_XN=0
ES_PSEUDO_FS=' proc sysfs devpts cgroup cgroup2 mqueue tracefs securityfs debugfs pstore bpf configfs fusectl hugetlbfs binfmt_misc rpc_pipefs nsfs selinuxfs efivarfs autofs devtmpfs ramfs fuse.gvfsd-fuse fuse.portal overlay squashfs '

# ---------------------------------------------------------------- time

es_time_init() {
  ES_NS_DATE=0
  es_ti=$(date +%s%N 2>/dev/null) # lint-allow: date-epoch
  case $es_ti in
    ''|*[!0-9]*) ;;
    *) [ ${#es_ti} -gt 15 ] && ES_NS_DATE=1 ;;
  esac
}

es_now_ms() {
  if [ "$ES_NS_DATE" = 1 ]; then
    ES_MS=$(date +%s%N 2>/dev/null) # lint-allow: date-epoch
    ES_MS=${ES_MS%??????}
  else
    ES_MS=$(awk 'BEGIN { srand(); s = srand(); printf "%d000\n", s }')
  fi
}

es_epoch_s() {
  es_now_ms
  ES_SEC=$((ES_MS / 1000))
}

es_utc() {
  ES_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)
}

# es_iso_epoch SECONDS -> ES_ISO (UTC, computed in awk: no GNU date needed)
es_iso_epoch() {
  ES_ISO=$(awk -v t="$1" 'BEGIN {
    if (t !~ /^[0-9]+$/) exit
    d = int(t / 86400); s = t - d * 86400
    z = d + 719468; era = int(z / 146097); doe = z - era * 146097
    yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
    y = yoe + era * 400; doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
    mp = int((5 * doy + 2) / 153); dd = doy - int((153 * mp + 2) / 5) + 1
    mm = mp < 10 ? mp + 3 : mp - 9; if (mm <= 2) y++
    printf "%04d-%02d-%02dT%02d:%02d:%02dZ\n", y, mm, dd, int(s / 3600), int((s % 3600) / 60), s % 60
  }')
}

# ---------------------------------------------------------------- logging

es_log() {
  [ -n "$ES_TMP" ] && printf '%s\n' "$*" >>"$ES_TMP/log"
}

es_say() {
  printf '%s\n' "$*" >&4
  es_log "$*"
}

es_fatal() {
  printf 'envscan: %s\n' "$*" >&4
  es_cleanup
  exit 2
}

# ---------------------------------------------------------------- strings

# es_q VALUE -> ES_Q: the value single-quoted for eval
es_q() {
  es_qr=$1; es_qo=
  while :; do
    case $es_qr in
      *\'*) es_qo="$es_qo${es_qr%%\'*}'\\''"; es_qr=${es_qr#*\'} ;;
      *) break ;;
    esac
  done
  ES_Q="'$es_qo$es_qr'"
}

# es_trim VALUE -> ES_T (leading/trailing blanks and CR removed)
es_trim() {
  ES_T=$1
  ES_T=${ES_T%"$ES_CR"}
  while :; do
    case $ES_T in
      [" $ES_TAB"]*) ES_T=${ES_T#?} ;;
      *[" $ES_TAB"]) ES_T=${ES_T%?} ;;
      *) break ;;
    esac
  done
}

# es_unquote VALUE -> ES_T without one pair of surrounding quotes
es_unquote() {
  es_trim "$1"
  case $ES_T in
    \"*\") ES_T=${ES_T#\"}; ES_T=${ES_T%\"} ;;
    \'*\') ES_T=${ES_T#\'}; ES_T=${ES_T%\'} ;;
  esac
}

# es_first_line TEXT -> ES_T
es_first_line() {
  ES_T=${1%%"$ES_NL"*}
  ES_T=${ES_T%"$ES_CR"}
}

# es_read1 FILE -> ES_L (first line, CR stripped); fails when unreadable or empty
es_read1() {
  ES_L=
  [ -f "$1" ] && [ -r "$1" ] || return 1
  IFS= read -r ES_L <"$1" || [ -n "$ES_L" ] || return 1
  ES_L=${ES_L%"$ES_CR"}
  return 0
}

# es_is_num VALUE: true for an unsigned integer
es_is_num() {
  case $1 in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

# es_lower VALUE -> ES_T
es_lower() {
  ES_T=$(printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
}

# es_detect_ebcdic -> ES_EBCDIC (1 when this shell and its tools run in an EBCDIC code page, as on
# z/OS UNIX: the letter A is the byte c1), ES_EBCDIC_1047 (1 when the code page is IBM-1047: the
# character [ is the byte ad; IBM-037 and others agree on the letters but not there) and
# ES_EBCDIC_ARG (the IBM-1047 table json.awk needs, only for IBM-1047)
es_detect_ebcdic() {
  ES_EBCDIC=0; ES_EBCDIC_1047=0; ES_EBCDIC_ARG=
  case $(printf A | od -An -tx1 2>/dev/null) in
    *c1*) ES_EBCDIC=1 ;;
  esac
  [ "$ES_EBCDIC" = 1 ] || return 0
  case $(printf '[' | od -An -tx1 2>/dev/null) in
    *ad*) ES_EBCDIC_1047=1; ES_EBCDIC_ARG=$ES_EBCDIC_TAB ;;
  esac
  return 0
}

# es_version_of TEXT -> ES_T: first dotted version number (or bare number) in the text
es_version_of() {
  ES_T=$(printf '%s\n' "$1" | awk '{ if (match($0, /[0-9]+(\.[0-9]+)+/) || match($0, /[0-9]+/)) { print substr($0, RSTART, RLENGTH); exit } }')
}

# es_vercmp A B: prints -1, 0 or 1 comparing dotted versions numerically
es_vercmp() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, A, /[^0-9]+/); nb = split(b, B, /[^0-9]+/); n = na > nb ? na : nb
    for (i = 1; i <= n; i++) { x = A[i] + 0; y = B[i] + 0; if (x < y) { print -1; exit } if (x > y) { print 1; exit } }
    print 0 }'
}

es_norm_arch() {
  case $1 in
    x86_64|amd64|AMD64|x64|X86_64) ES_A=x86_64 ;;
    i[3-6]86|x86|i86pc|i86|X86) ES_A=x86 ;;
    aarch64|arm64|ARM64|aarch64_be|arm64e) ES_A=arm64 ;;
    arm*|ARM*) ES_A=arm ;;
    ppc64le|powerpc64le) ES_A=ppc64le ;;
    ppc64|powerpc64) ES_A=ppc64 ;;
    ppc|powerpc) ES_A=ppc ;;
    s390x) ES_A=s390x ;;
    riscv64) ES_A=riscv64 ;;
    sparc64|sun4u|sun4v|sparcv9) ES_A=sparc64 ;;
    sparc) ES_A=sparc ;;
    ia64) ES_A=ia64 ;;
    mips*) ES_A=mips ;;
    *) ES_A=other ;;
  esac
}

# ---------------------------------------------------------------- PATH and globs

# es_ltest OP PATH: test OP (-d -e -f -r -s -w -x) on PATH, a path that comes from the
# environment, HOME or a glob, only when PATH, resolved (es_resolve: links, ".", "..", repeated
# "/"), is not on a network or autofs mount and is not a credential store (es_cred_path on the
# resolved path, so ~/.config//gcloud/x is refused like ~/.config/gcloud/x); otherwise false
# without touching it (es_skip)
es_ltest() {
  if ! es_local_path "$2"; then es_skip "$2"; return 1; fi
  test "$1" "$2"
}

# es_skip PATH: PATH failed es_local_path; it goes to ES_CREDSKIP (a link into a credential
# store, ES_CREDLINK) or ES_NETSKIP (on a network or autofs mount), for the probe's notes
es_skip() {
  if [ -n "${ES_CREDLINK:-}" ]; then ES_CREDSKIP="${ES_CREDSKIP:-}$1$ES_NL"
  else ES_NETSKIP="${ES_NETSKIP:-}$1$ES_NL"
  fi
}

# es_exec_file PATH: PATH is an executable file. A link is followed only when its target is not
# on a network or autofs mount (/usr/local/bin/java -> /nfs/jdk/bin/java is never stat'ed);
# the directory itself was vetted by the caller (ES_PATH_SKIP, es_glob)
es_exec_file() {
  if [ -h "$1" ] && ! es_local_path "$1"; then es_skip "$1"; return 1; fi
  [ -f "$1" ] && [ -x "$1" ]
}

# es_which NAME -> ES_W: first executable on PATH (relative and empty entries skipped)
es_which() {
  ES_W=
  case $1 in
    */*) es_local_path "$1" && [ -f "$1" ] && [ -x "$1" ] && ES_W=$1; [ -n "$ES_W" ]; return ;;
  esac
  es_wifs=$IFS; IFS=:
  set -f
  for es_wd in $PATH; do
    case $es_wd in /*) ;; *) continue ;; esac
    case "$ES_NL${ES_PATH_SKIP:-}" in *"$ES_NL$es_wd$ES_NL"*) continue ;; esac
    if es_exec_file "$es_wd/$1"; then ES_W="$es_wd/$1"; break; fi
  done
  set +f
  IFS=$es_wifs
  [ -n "$ES_W" ]
}

# es_which_all NAME -> ES_WA: every match on PATH, newline separated, de-duplicated
es_which_all() {
  ES_WA=
  es_wifs=$IFS; IFS=:
  set -f
  for es_wd in $PATH; do
    case $es_wd in /*) ;; *) continue ;; esac
    case "$ES_NL${ES_PATH_SKIP:-}" in *"$ES_NL$es_wd$ES_NL"*) continue ;; esac
    if es_exec_file "$es_wd/$1"; then
      case "$ES_NL$ES_WA" in *"$ES_NL$es_wd/$1$ES_NL"*) ;; *) ES_WA="$ES_WA$es_wd/$1$ES_NL" ;; esac
    fi
  done
  set +f
  IFS=$es_wifs
  [ -n "$ES_WA" ]
}

# es_expand PATTERN -> ES_X: existing paths (newline separated) for a spec path pattern:
#   ~ = HOME, {env:NAME} = variable (skipped when unset), * = glob, /abs gets ENVSCAN_ROOT
es_expand() {
  ES_X=; es_ep=$1
  case $es_ep in
    '~'|'~/'*)
      [ -n "$HOME" ] || return 1
      es_ep=$HOME${es_ep#\~} ;;
    '{env:'*)
      es_en=${es_ep#\{env:}; es_en=${es_en%%\}*}
      case $es_en in ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_]*) return 1 ;; esac
      eval "es_ev=\${$es_en-}"
      [ -n "$es_ev" ] || return 1
      es_ep=$es_ev${es_ep#*\}} ;;
    /*) es_ep=$ES_ROOT$es_ep ;;
    *) return 1 ;;
  esac
  es_glob "$es_ep"
}

# es_glob PATTERN -> ES_X: the existing paths (newline separated) an absolute PATTERN (* ? [
# globs) names. A pattern that names a credential store (es_cred_path) is never expanded, so a
# credential directory is never listed. Nothing on a network or autofs mount is touched: a glob
# is skipped when its base directory is on one or has one below it. The pattern is expanded one
# globbed component at a time (~/.p*/pip.conf: ~/.p* first), and every directory and result is
# checked (es_local_path) before it is used, so a link into a credential store is never entered
# (es_skip collects what was left out, for the probe's notes).
es_glob() {
  ES_X=; es_ep=$1
  es_cred_path "$es_ep" && return 1
  if [ -n "${ES_NETMNTS:-}" ]; then
    es_eb=${es_ep%%[*?[]*}
    if [ "$es_eb" != "$es_ep" ]; then
      es_eb=${es_eb%/*}; [ -n "$es_eb" ] || es_eb=/
      if ! es_local_path "$es_eb" || es_netmnt_under "$es_eb"; then
        es_skip "$es_ep"
        return 1
      fi
    fi
  fi
  es_eifs=$IFS; IFS=$ES_NL
  es_etodo=$es_ep$ES_NL
  while [ -n "$es_etodo" ]; do
    es_eq=${es_etodo%%"$ES_NL"*}; es_etodo=${es_etodo#*"$ES_NL"}
    es_eh=${es_eq%%[*?[]*}
    if [ "$es_eh" = "$es_eq" ]; then es_glob_take "$es_eq"; continue; fi
    # the first globbed component: expanded in a directory that was already checked
    es_ed=${es_eh%/*}; es_ec=${es_eq#"$es_ed"/}; es_er=
    case $es_ec in */*) es_er=${es_ec#*/}; es_ec=${es_ec%%/*} ;; esac
    if [ -n "$es_ed" ] && ! es_local_path "$es_ed"; then es_skip "$es_ed"; continue; fi
    for es_ef in $es_ed/$es_ec; do
      if [ -z "$es_er" ]; then es_glob_take "$es_ef"; continue; fi
      es_cred_path "$es_ef" && continue
      if ! es_local_path "$es_ef"; then es_skip "$es_ef"; continue; fi
      [ -d "$es_ef" ] && es_etodo="$es_etodo$es_ef/$es_er$ES_NL"
    done
  done
  IFS=$es_eifs
  [ -n "$ES_X" ]
}

# es_glob_take PATH: es_glob keeps PATH when it exists and is no credential store, no link into
# one and not on a network or autofs mount ({env:PIP_CONFIG_FILE}=~/.netrc is never tested)
es_glob_take() {
  es_cred_path "$1" && return 0
  if ! es_local_path "$1"; then es_skip "$1"; return 0; fi
  if [ -e "$1" ] || [ -h "$1" ]; then ES_X="$ES_X$1$ES_NL"; fi
  return 0
}

# es_resolve PATH -> ES_RPATH: PATH with every symbolic link (in any component), ".", ".." and
# repeated "/" resolved; links are read with ls (no readlink -f, no cd). A component is touched
# only while the path so far is outside network and autofs mounts: on reaching one, es_resolve
# stops and fails with ES_RPATH = the resolved part plus the unresolved rest. A path whose links
# lead into a credential store (es_cred_path on the resolved path) fails with ES_CREDLINK=1:
# ~/.pip -> ~/.aws must not read ~/.aws/pip.conf. The store itself is never tested.
es_resolve() {
  ES_CREDLINK=
  # a UNC path (//server/share, \\server\share: Cygwin/MSYS) is a network path
  case $1 in //[!/]*|"\\\\"*) ES_RPATH=$1; return 1 ;; esac
  case $1 in /*) ;; *) ES_RPATH=$1; return 0 ;; esac
  es_rs_rest=$1; es_rs_cur=; es_rs_n=0
  while :; do
    while :; do case $es_rs_rest in /*) es_rs_rest=${es_rs_rest#/} ;; *) break ;; esac; done
    [ -n "$es_rs_rest" ] || break
    es_rs_c=${es_rs_rest%%/*}
    case $es_rs_rest in */*) es_rs_rest=${es_rs_rest#*/} ;; *) es_rs_rest= ;; esac
    case $es_rs_c in
      .) continue ;;
      ..) es_rs_cur=${es_rs_cur%/*}; continue ;;
    esac
    es_rs_cur="$es_rs_cur/$es_rs_c"
    if es_on_netfs "$es_rs_cur"; then ES_RPATH="$es_rs_cur${es_rs_rest:+/$es_rs_rest}"; return 1; fi
    # a credential store is never tested, not even for being a link (es_cred_path)
    es_cred_path "$es_rs_cur" && continue
    [ -h "$es_rs_cur" ] || continue
    es_rs_n=$((es_rs_n + 1))
    [ "$es_rs_n" -le 32 ] || break
    es_rs_ls=$(ls -ld "$es_rs_cur" 2>/dev/null)
    case $es_rs_ls in *' -> '*) es_rs_t=${es_rs_ls#*' -> '} ;; *) continue ;; esac
    case $es_rs_t in //[!/]*|"\\\\"*) ES_RPATH="$es_rs_t${es_rs_rest:+/$es_rs_rest}"; return 1 ;; esac
    case $es_rs_t in /*) es_rs_cur= ;; *) es_rs_cur=${es_rs_cur%/*} ;; esac
    es_rs_rest="$es_rs_t${es_rs_rest:+/$es_rs_rest}"
  done
  ES_RPATH="${es_rs_cur:-/}${es_rs_rest:+/$es_rs_rest}"
  # the resolved path is a credential store (also when no link was involved: ~/.config//gcloud/x)
  if es_cred_path "$ES_RPATH"; then ES_CREDLINK=1; return 1; fi
  return 0
}

# es_realpath PATH -> ES_RP: PATH fully resolved (es_resolve)
es_realpath() { es_resolve "$1"; ES_RP=$ES_RPATH; return 0; }

# es_local_path PATH: PATH, with its links resolved, is not on a network or autofs mount and
# does not lead into a credential store (ES_CREDLINK=1 tells the two apart)
es_local_path() { es_resolve "$1"; }

# es_netskip_note: a note listing what the probe left out because it is on a network or autofs
# mount (collected in ES_NETSKIP by es_expand), and one note per link into a credential store
# (ES_CREDSKIP), which makes the probe partial
es_netskip_note() {
  if [ -n "${ES_CREDSKIP:-}" ]; then
    printf '%s' "$ES_CREDSKIP" | awk 'NF && !s[$0]++' >"$ES_P_DIR/credskip.txt"
    while IFS= read -r es_ns_p; do es_partial "$es_ns_p not read: link to a credential store"; done <"$ES_P_DIR/credskip.txt"
    rm -f "$ES_P_DIR/credskip.txt"
  fi
  [ -n "${ES_NETSKIP:-}" ] || return 0
  es_ns_l=$(printf '%s' "$ES_NETSKIP" | awk 'NF && !s[$0]++ { n++; if (n <= 5) l = l (n > 1 ? ", " : "") $0 }
    END { if (n > 5) l = l " and " (n - 5) " more"; print l }')
  [ -n "$es_ns_l" ] && es_note "not read because they are on network or autofs mounts (nothing there is touched): $es_ns_l"
  return 0
}

# es_path_init -> ES_PATH_SKIP: PATH entries on network or autofs mounts (newline-terminated);
# es_which and es_which_all never look into them
es_path_init() {
  ES_PATH_SKIP=
  [ -n "${ES_NETMNTS:-}" ] || return 0
  es_pi_ifs=$IFS; IFS=:
  set -f
  for es_pi_d in $PATH; do
    case $es_pi_d in /*) es_local_path "$es_pi_d" || ES_PATH_SKIP="$ES_PATH_SKIP$es_pi_d$ES_NL" ;; esac
  done
  set +f
  IFS=$es_pi_ifs
  return 0
}

# es_winpath WINDOWS-PATH -> ES_T: C:\x\y as /cygdrive/c/x/y (Cygwin) or /c/x/y (MSYS); fails
# when the value is not a drive path or the drive is not mounted
es_winpath() {
  case $1 in [ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]:|[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]:[/\\]*) ;; *) ES_T=; return 1 ;; esac
  es_bs='\'; es_wr=${1#?:}
  while :; do
    case $es_wr in *"$es_bs"*) es_wr="${es_wr%%"$es_bs"*}/${es_wr#*"$es_bs"}" ;; *) break ;; esac
  done
  es_lower "${1%%:*}"; es_wd=$ES_T
  if [ -d "/cygdrive/$es_wd" ]; then ES_T="/cygdrive/$es_wd$es_wr"
  elif [ -d "/$es_wd" ]; then ES_T="/$es_wd$es_wr"
  else ES_T=; return 1
  fi
  ES_T=${ES_T%/}
}

# ---------------------------------------------------------------- processes

# es_killtree PID SIGNAL: signal the process and all its descendants
es_killtree() {
  es_kt=$(ps -e -o pid= -o ppid= 2>/dev/null)
  # fallback: the PID and PPID columns are found by their header names (ps -ef layouts differ)
  if [ -z "$es_kt" ]; then
    es_kt=$(ps -ef 2>/dev/null | awk 'NR == 1 { for (i = 1; i <= NF; i++) { if ($i == "PID") p = i; if ($i == "PPID") q = i }; next }
      p && q { print $p, $q }')
  fi
  es_kids=$(printf '%s\n' "$es_kt" | awk -v root="$1" '
    NF >= 2 { pp[$1] = $2 }
    END { for (p in pp) { q = p; for (i = 0; i < 64; i++) { q = pp[q]; if (q == "" || q == 0) break; if (q == root) { print p; break } } } }')
  kill -s "$2" $es_kids "$1" 2>/dev/null
}

# es_pid_init: how a subshell learns its own pid (ES_OWNPID=bash uses $BASHPID, checked to
# really change per subshell; otherwise "$ES_SH -c 'echo $$'" is exec'd in front of the command)
es_pid_init() {
  ES_SH=/bin/sh
  if [ ! -x "$ES_SH" ] && es_which sh; then ES_SH=$ES_W; fi
  ES_OWNPID=
  es_b1=$(printf '%s' "${BASHPID:-}"); es_b2=$(printf '%s' "${BASHPID:-}")
  if es_is_num "$es_b1" && es_is_num "$es_b2" && [ "$es_b1" != "$es_b2" ] && [ "$es_b1" != "$$" ]; then
    ES_OWNPID=bash
  fi
  es_env_bin_init
}

# es_watch TARGET SECONDS FLAGFILE [ENDFILE NUDGEPID]: a watchdog that, after SECONDS, creates
# FLAGFILE and kills the process tree of TARGET (a pid, or a file the child writes its pid to).
# It polls FLAGFILE.done once a second instead of being signalled and never holds the caller's
# descriptors, so an orphaned watchdog cannot keep a pipe open. FLAGFILE must be unique and must
# not be deleted while the watchdog may still run (a reused pid must never be killed).
# With ENDFILE: once the child has created ENDFILE but the caller has not noticed (the "wait"
# builtin can miss a child's exit on Cygwin/MSYS), NUDGEPID gets USR1 once a second so that its
# "wait" returns; the child is never killed after it created ENDFILE.
es_watch() {
  ES_WDONE="$3.done"
  (
    exec 3<&- 4>&- 5>&-
    es_wdir=${3%/*}; es_wn=0; es_we=0
    while :; do
      sleep 1
      if [ -f "$3.done" ] || [ ! -d "$es_wdir" ]; then exit 0; fi
      es_wn=$((es_wn + 1))
      if [ -n "$4" ] && [ -f "$4" ]; then
        es_we=$((es_we + 1))
        [ "$es_we" -ge 2 ] && kill -s USR1 "$5" 2>/dev/null
        [ "$es_we" -ge 60 ] && exit 0
        continue
      fi
      [ "$es_wn" -ge "$2" ] && break
    done
    es_wp=$1
    if ! es_is_num "$es_wp"; then
      es_wn=0
      while ! es_read1 "$1" && [ "$es_wn" -lt 5 ]; do sleep 1; es_wn=$((es_wn + 1)); done
      es_wp=$ES_L
    fi
    if [ -f "$3.done" ] || [ ! -d "$es_wdir" ]; then exit 0; fi
    : >"$3"
    es_is_num "$es_wp" || exit 0
    es_killtree "$es_wp" TERM
    sleep 2
    if [ -f "$3.done" ] || [ ! -d "$es_wdir" ]; then exit 0; fi
    es_killtree "$es_wp" KILL
  ) </dev/null >/dev/null 2>&1 &
}

es_unwatch() { : >"$ES_WDONE"; }

# es_child, es_restore_locale and the child environment: 13-child.sh

# es_exec SECONDS OUTFILE ERRFILE CMD ARGS... -> ES_RC, ES_TIMED_OUT
# The child runs in the foreground (the shell then blocks in waitpid; the "wait" builtin can miss
# a child's exit on Cygwin/MSYS), from /, stdin /dev/null, with the child environment applied.
# ERRFILE "-" appends stderr to OUTFILE.
es_exec() {
  es_xt=$1; es_xo=$2; es_xe=$3; shift 3
  ES_XN=$((ES_XN + 1))
  es_xf="${ES_P_DIR:-$ES_TMP}/wd.$ES_XN"
  while [ -e "$es_xf" ] || [ -e "$es_xf.done" ]; do ES_XN=$((ES_XN + 1)); es_xf="${ES_P_DIR:-$ES_TMP}/wd.$ES_XN"; done
  es_watch "$es_xf.pid" "$es_xt" "$es_xf"
  if [ "$es_xe" = - ]; then
    ( es_child "$es_xf.pid" "$@" ) </dev/null >"$es_xo" 2>&1
  else
    ( es_child "$es_xf.pid" "$@" ) </dev/null >"$es_xo" 2>"$es_xe"
  fi
  ES_RC=$?
  es_unwatch
  ES_TIMED_OUT=0
  [ -f "$es_xf" ] && ES_TIMED_OUT=1
  return $ES_RC
}

# ---------------------------------------------------------------- probe context

es_src() { printf '%s\n' "$*" >>"$ES_P_DIR/sources"; }

es_note() { printf '%s\n' "$*" >>"$ES_P_DIR/notes"; }

# ES_RAW_FILES: unredacted intermediates a probe directory can hold (configuration lines, git
# configuration, proxy settings). Each probe removes them right after their last use;
# es_raw_drop DIR removes what a stopped probe left (es_run_one).
ES_RAW_FILES='cfg.cur config_lines.txt env_lines.txt git_lines.txt git_urls.txt git-incl.txt tls_off.txt sys.tsv proxy_urls.tsv sys.in'
es_raw_drop() {
  for es_rf in $ES_RAW_FILES; do rm -f "$1/$es_rf"; done
  return 0
}

# ---------------------------------------------------------------- UTF-16 and binary files
# Redaction matches text, and UTF-16 (a NUL after every letter) or other binary content never
# matches it. A file that is not plain text is therefore decoded or not read at all: fail closed.

# es_bin_file FILE: succeeds when FILE holds a NUL byte or starts with a UTF-16 byte order mark.
# Any failure of the check counts as binary.
es_bin_file() {
  [ -s "$1" ] || return 1
  es_bfh=$(dd if="$1" bs=2 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
  case $es_bfh in fffe|feff) return 0 ;; esac
  tr -d '\000' <"$1" 2>/dev/null | cmp -s - "$1" && return 1
  return 0
}

# es_utf16_ascii LE|BE FILE: succeeds when FILE (after the 2-byte mark) is UTF-16 of ASCII only:
# every pair is the character byte (below 0x80) and a 00 byte, in the order the mark gave
es_utf16_ascii() {
  dd if="$2" bs=2 skip=1 2>/dev/null | od -An -v -tx1 | awk -v le="$1" '
    { for (i = 1; i <= NF; i++) T[++n] = $i }
    END {
      if (n % 2) exit 1
      for (i = 1; i <= n; i += 2) {
        if (le == "LE") { c = T[i]; z = T[i + 1] } else { z = T[i]; c = T[i + 1] }
        if (z != "00" || c !~ /^[0-7]/) exit 1
      }
      exit 0
    }'
}

# es_text_prep FILE: ES_TXT = the file to read: FILE itself when it is plain text, else a decoded
# copy ($ES_TMP/dec.N: the F event reads it when the report is rendered, so it lives as long as
# the other probe events, until es_cleanup). Returns 1 when FILE is UTF-16 or binary and cannot
# be decoded to NUL-free text: the caller must not emit its content.
es_text_prep() {
  ES_TXT=$1
  es_bin_file "$1" || return 0
  es_tpm=$(dd if="$1" bs=2 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
  case $es_tpm in fffe) es_tpe=LE ;; feff) es_tpe=BE ;; *) return 1 ;; esac
  # a name that does not exist yet: a call in a subshell does not keep the counter
  es_tpn=${es_tpn:-0}
  while :; do es_tpn=$((es_tpn + 1)); es_tpo=$ES_TMP/dec.${ES_P_ID:-x}.$es_tpn; [ -e "$es_tpo" ] || break; done
  if iconv -f UTF-16 -t UTF-8 <"$1" >"$es_tpo" 2>/dev/null && [ -s "$es_tpo" ] && ! es_bin_file "$es_tpo"; then
    ES_TXT=$es_tpo; return 0
  fi
  if es_utf16_ascii "$es_tpe" "$1"; then
    if dd if="$1" bs=2 skip=1 2>/dev/null | tr -d '\000' >"$es_tpo" && ! es_bin_file "$es_tpo"; then
      ES_TXT=$es_tpo; return 0
    fi
  fi
  rm -f "$es_tpo"
  return 1
}

# es_text_ok FILE: succeeds with ES_TXT = the text to read (FILE, or its decoded copy). Otherwise
# the probe becomes partial ("<file> not read: UTF-16 or binary content"); skip the file.
es_text_ok() {
  es_text_prep "$1" && return 0
  es_partial "${1#"$ES_ROOT"} not read: UTF-16 or binary content"
  return 1
}

es_status() { printf '%s\n' "$1" >"$ES_P_DIR/status"; }

# es_partial NOTE: downgrade ok to partial and record why
es_partial() {
  es_ps=ok
  [ -s "$ES_P_DIR/status" ] && IFS= read -r es_ps <"$ES_P_DIR/status"
  [ "$es_ps" = ok ] && es_status partial
  [ -n "$1" ] && es_note "$1"
  return 0
}

es_error() { printf '%s\n' "$*" >"$ES_P_DIR/error"; }

es_truncated() { : >"$ES_P_DIR/truncated"; }

# es_raw LABEL FILE: include FILE (redacted, capped) under raw.LABEL
es_raw() {
  [ -s "$2" ] && printf '%s\t%s\n' "$1" "$2" >>"$ES_P_DIR/raw"
  return 0
}

# es_fact KEY VALUE: shared with later probes, findings and the brief as ES_F_<KEY>
# es_dedup_last FILE: one "key TAB value" line per key (first position, last value), so that a
# setting repeated in a file does not become a duplicate JSON key
es_dedup_last() {
  [ -s "$1" ] || return 0
  awk -F '\t' '{ if (!($1 in v)) o[++n] = $1; v[$1] = $0 } END { for (i = 1; i <= n; i++) print v[o[i]] }' "$1" >"$1.dedup" &&
    mv "$1.dedup" "$1"
}

es_fact() {
  es_q "$2"
  printf 'ES_F_%s=%s\n' "$1" "$ES_Q" >>"$ES_P_DIR/facts"
  eval "ES_F_$1=\$2"
}

# es_cmd CMD ARGS...: run with the default timeout; output in ES_OUT_F / ES_ERR_F
es_cmd() {
  ES_CN=$((ES_CN + 1))
  ES_OUT_F="$ES_P_DIR/c$ES_CN.out"; ES_ERR_F="$ES_P_DIR/c$ES_CN.err"
  es_src "run $*"
  es_exec "$ES_TIMEOUT" "$ES_OUT_F" "$ES_ERR_F" "$@"
  if [ "$ES_TIMED_OUT" = 1 ]; then es_partial "timed out after ${ES_TIMEOUT}s: $*"; fi
  return $ES_RC
}

# es_cmd_merged CMD ARGS...: like es_cmd with stderr appended to the output file
es_cmd_merged() {
  es_cmd "$@"
  es_cmrc=$ES_RC
  cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
  return $es_cmrc
}

# es_tool NAME ARGS...: find NAME on PATH and run it unless forbidden; 127 when absent
es_tool() {
  ES_RC=127; ES_TIMED_OUT=0
  es_which "$1" || return 127
  es_tn=$1; shift
  if ! es_runnable "$ES_W" "$es_tn"; then
    es_note "$ES_W: $ES_WHY"
    ES_RC=126
    return 126
  fi
  es_cmd "$ES_W" "$@"
}

# es_need NAME ARGS...: es_tool for a command whose output the probe needs. When the tool is
# present but exits non-zero or prints nothing, the probe becomes partial with a note.
es_need() {
  es_tool "$@"
  es_nrc=$ES_RC
  case $es_nrc in 126|127) return "$es_nrc" ;; esac
  if [ "$es_nrc" != 0 ] || [ ! -s "$ES_OUT_F" ]; then
    if [ "$ES_TIMED_OUT" != 1 ]; then
      if [ "$es_nrc" = 0 ]; then es_partial "$* printed nothing"; else es_partial "$* failed (exit status $es_nrc)"; fi
    fi
    ES_RC=$es_nrc
    [ "$es_nrc" = 0 ] && return 1
    return "$es_nrc"
  fi
  return 0
}

# ---------------------------------------------------------------- events (fd 5)

# es_ev TYPE KEY VALUE: values with line breaks are escaped (s->S, e->E) or flattened
es_ev() {
  case $3 in
    *"$ES_NL"*|*"$ES_CR"*)
      case $1 in
        s|e)
          es_vv=$(printf '%s' "$3" | awk '{ s = $0; r = ""; for (i = 1; i <= length(s); i++) { c = substr(s, i, 1); if (c == "\\") c = "\\\\"; else if (c == "\t") c = "\\t"; else if (c == "\r") c = "\\r"; r = r c } printf "%s%s", (NR > 1 ? "\\n" : ""), r }')
          if [ "$1" = s ]; then set -- S "$2" "$es_vv"; else set -- E "$2" "$es_vv"; fi ;;
        *)
          es_vv=$(printf '%s' "$3" | tr '\r\n' '  ')
          set -- "$1" "$2" "$es_vv" ;;
      esac ;;
  esac
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >&5
}

es_o() { printf '{\t%s\n' "$1" >&5; }
es_oe() { printf '}\n' >&5; }
es_a() { printf '[\t%s\n' "$1" >&5; }
es_ae() { printf ']\n' >&5; }
es_s() { es_ev s "$1" "$2"; }
es_e() { es_ev e "$1" "$2"; }
es_l() { es_ev l "$1" "$2"; }
es_c() { es_ev c "$1" "$2"; }
es_z() { printf 'z\t%s\n' "$1" >&5; }
es_f() { printf 'f\t%s\t%s\t%s\n' "$1" "$2" "${3:-65536}" >&5; }

# es_v KEY NAME VALUE: string redacted when NAME is a secret name
es_v() {
  case $3 in
    *"$ES_NL"*|*"$ES_CR"*) es_vv=$(printf '%s' "$3" | tr '\r\n' '  ') ;;
    *) es_vv=$3 ;;
  esac
  printf 'v\t%s\t%s\t%s\n' "$1" "$2" "$es_vv" >&5
}

# es_sn KEY VALUE: string, or null when empty
es_sn() { if [ -n "$2" ]; then es_ev s "$1" "$2"; else es_z "$1"; fi; }

# es_n KEY VALUE: number (non-numeric text is kept as a string), null when empty
es_n() { if [ -n "$2" ]; then printf 'n\t%s\t%s\n' "$1" "$2" >&5; else es_z "$1"; fi; }

# es_b KEY VALUE: true/false, anything else null
es_b() {
  case $2 in
    true|false) printf 'b\t%s\t%s\n' "$1" "$2" >&5 ;;
    *) es_z "$1" ;;
  esac
}

# es_list KEY TEXT [TYPE]: array of the non-empty lines of TEXT (TYPE s, l, c or n)
es_list() {
  es_a "$1"
  es_lifs=$IFS; IFS=$ES_NL
  set -f
  for es_li in $2; do
    [ -n "$es_li" ] && es_ev "${3:-s}" - "$es_li"
  done
  set +f
  IFS=$es_lifs
  es_ae
}

# es_list_file KEY FILE [TYPE] [MAX]: array of the non-empty lines of a small FILE (no fork)
es_list_file() {
  es_a "$1"
  if [ -r "$2" ]; then
    es_lfn=0
    while IFS= read -r es_lfl || [ -n "$es_lfl" ]; do
      es_lfl=${es_lfl%"$ES_CR"}
      [ -n "$es_lfl" ] || continue
      es_lfn=$((es_lfn + 1))
      if [ "${4:-0}" -gt 0 ] && [ "$es_lfn" -gt "${4:-0}" ]; then break; fi
      printf '%s\t-\t%s\n' "${3:-s}" "$es_lfl" >&5
    done <"$2"
  fi
  es_ae
}

# es_list_lines KEY FILE [TYPE] [MAX]: like es_list_file for large files (one awk)
es_list_lines() {
  es_a "$1"
  if [ -r "$2" ] && es_text_ok "$2"; then
    awk -v t="${3:-s}" -v max="${4:-0}" '
      { sub(/\r$/, "") }
      $0 == "" { next }
      { n++; if (max > 0 && n > max) exit; printf "%s\t-\t%s\n", t, $0 }' "$ES_TXT" >&5
  fi
  es_ae
}

# es_count_lines FILE -> ES_T
es_count_lines() {
  ES_T=0
  [ -r "$1" ] && ES_T=$(awk 'END { print NR }' "$1")
}
