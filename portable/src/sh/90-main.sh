# ============================================================== main

es_usage() {
  cat <<'ES_USAGE'
usage: sh envscan.sh [options]
  --deep          enable tier "deep" (commands that may raise security alerts)
  --net           enable tier "net" (reachability of proxies and mirrors from local config)
  --out DIR       parent directory for the output folder
  --only IDS      comma-separated probe ids or area wildcards (net.*); others are skipped
  --skip IDS      comma-separated probe ids or area wildcards to skip
  --timeout SEC   per external command (default 15)
  --budget SEC    whole scan (default 600); remaining probes become skipped
  --no-redact     write secrets unredacted
  --list-probes   print every probe with tier, title and footprint, then exit
  --version       print the version and exit
  --help          this help
Writes envscan-<host>-<UTC time>/ (envscan.json, envscan.md, AGENT_BRIEF.md, envscan.log)
and prints its path on stdout. Read-only; the default tier makes no network traffic.
ES_USAGE
}

es_usage_error() {
  printf 'envscan: %s\n' "$1" >&2
  es_usage >&2
  exit 2
}

es_parse_args() {
  ES_DEEP=0; ES_NET=0; ES_OPT_OUT=; ES_ONLY=; ES_SKIP=; ES_ONLY_SET=; ES_SKIP_SET=; ES_TIMEOUT=15; ES_BUDGET=600
  ES_REDACT=1; ES_ACTION=scan; ES_FLAGS=
  while [ $# -gt 0 ]; do
    es_arg=$1; es_val=; es_has_val=0
    case $es_arg in
      -?*=*) es_val=${es_arg#*=}; es_arg=${es_arg%%=*}; es_has_val=1 ;;
    esac
    case $es_arg in
      --*) ;;
      -?*) es_arg="-$es_arg" ;;
    esac
    ES_FLAGS="$ES_FLAGS$1$ES_NL"
    # a value on a flag is an error, never ignored (--net=false must not enable --net)
    case $es_arg in
      --deep|--net|--no-redact|--list-probes|--version|--help|--h)
        [ "$es_has_val" = 0 ] || es_usage_error "option $es_arg takes no value" ;;
    esac
    case $es_arg in
      --deep) ES_DEEP=1 ;;
      --net) ES_NET=1 ;;
      --no-redact) ES_REDACT=0 ;;
      --list-probes) ES_ACTION=list ;;
      --version) ES_ACTION=version ;;
      --help|--h) ES_ACTION=help ;;
      --out|--only|--skip|--timeout|--budget)
        if [ $es_has_val = 0 ]; then
          [ $# -ge 2 ] || es_usage_error "$1 needs a value"
          es_val=$2; shift
          ES_FLAGS="$ES_FLAGS$es_val$ES_NL"
        fi
        case $es_arg in
          --out) [ -n "$es_val" ] || es_usage_error "--out needs a directory"; ES_OPT_OUT=$es_val ;;
          --only) ES_ONLY=$es_val; ES_ONLY_SET=1 ;;
          --skip) ES_SKIP=$es_val; ES_SKIP_SET=1 ;;
          --timeout)
            if es_is_num "$es_val" && [ "$es_val" -gt 0 ]; then ES_TIMEOUT=$es_val; else es_usage_error "--timeout needs a positive number of seconds"; fi ;;
          --budget)
            if es_is_num "$es_val" && [ "$es_val" -gt 0 ]; then ES_BUDGET=$es_val; else es_usage_error "--budget needs a positive number of seconds"; fi ;;
        esac ;;
      *) es_usage_error "unknown argument: $1" ;;
    esac
    shift
  done
}

es_list_probes() {
  es_spec_probes | while IFS=$ES_TAB read -r es_lid es_ltitle es_ltier es_lscope es_lfoot; do
    printf '%s  [%s]  %s\n' "$es_lid" "$es_ltier" "$es_ltitle"
    [ "$es_lfoot" = - ] && continue
    set -f; es_lifs=$IFS; IFS='|'
    for es_lf in $es_lfoot; do printf '    - %s\n' "$es_lf"; done
    IFS=$es_lifs; set +f
  done
}

# es_in_list ID LIST: LIST is comma-separated ids or shell patterns (net.*)
es_in_list() {
  es_mifs=$IFS; IFS=,; set -f
  for es_mp in $2; do
    es_trim "$es_mp"
    [ -n "$ES_T" ] || continue
    case $1 in $ES_T) IFS=$es_mifs; set +f; return 0 ;; esac
  done
  IFS=$es_mifs; set +f
  return 1
}

# es_check_selection LIST OPTION GIVEN -> ES_SEL: LIST (--only or --skip) with its empty
# entries dropped. Before anything is created, every pattern must consist of letters, digits,
# . _ - * and match at least one probe id, and a given option (GIVEN = 1) must name at least one
# (--only "" or --only=, would otherwise select every probe); otherwise usage error, exit 2.
es_check_selection() {
  ES_SEL=; es_cerr=
  if [ -z "$1" ]; then
    [ -z "${3:-}" ] || es_usage_error "$2 needs probe ids"
    return 0
  fi
  es_cids=$(es_spec_probes | awk -F '\t' '{ print $1 }')
  es_cifs=$IFS; IFS=,; set -f
  for es_cp in $1; do
    es_trim "$es_cp"; es_cpat=$ES_T
    [ -n "$es_cpat" ] || continue
    case $es_cpat in *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9._*-]*) es_cerr="$2: invalid pattern '$es_cpat' (allowed: letters, digits, . _ - *)"; break ;; esac
    es_cfound=0; IFS=$ES_NL
    for es_cid in $es_cids; do case $es_cid in $es_cpat) es_cfound=1; break ;; esac; done
    IFS=,
    [ "$es_cfound" = 1 ] || { es_cerr="$2: pattern '$es_cpat' matches no probe"; break; }
    ES_SEL="$ES_SEL${ES_SEL:+,}$es_cpat"
  done
  IFS=$es_cifs; set +f
  [ -n "$es_cerr" ] || [ -n "$ES_SEL" ] || es_cerr="$2 needs probe ids"
  [ -z "$es_cerr" ] || es_usage_error "$es_cerr"
  return 0
}

es_cleanup() {
  set +f
  if [ -n "$ES_CUR_PID" ]; then es_killtree "$ES_CUR_PID" KILL; ES_CUR_PID=; fi
  if [ -n "$ES_TMP" ] && [ -d "$ES_TMP/p" ]; then
    for es_cf in "$ES_TMP"/p/*/cleanup.list; do [ -f "$es_cf" ] && es_clean_list "$es_cf"; done
  fi
  case $ES_TMP in */envscan.[0-9]*) rm -rf "$ES_TMP" ;; esac
  case $ES_CRLF_DIR in */envscan-crlf.[0-9]*) rm -rf "$ES_CRLF_DIR" ;; esac
  ES_TMP=
}

es_on_signal() {
  trap '' INT TERM HUP QUIT PIPE
  printf '%s\n' "envscan: interrupted" >&4
  es_cleanup
  exit 2
}

es_detect_os() {
  ES_UNAME_S=$(uname -s 2>/dev/null); ES_UNAME_N=$(uname -n 2>/dev/null)
  ES_UNAME_R=$(uname -r 2>/dev/null); ES_UNAME_M=$(uname -m 2>/dev/null)
  case $ES_UNAME_S in
    Linux) ES_OS=linux ;;
    Darwin) ES_OS=darwin ;;
    FreeBSD) ES_OS=freebsd ;;
    OpenBSD) ES_OS=openbsd ;;
    NetBSD) ES_OS=netbsd ;;
    AIX) ES_OS=aix ;;
    SunOS) ES_OS=sunos ;;
    HP-UX) ES_OS=hpux ;;
    OS/390) ES_OS=zos ;;
    OS400) ES_OS=os400 ;;
    CYGWIN*|MINGW*|MSYS*) ES_OS=cygwin ;;
    *) ES_OS=other ;;
  esac
  es_norm_arch "$ES_UNAME_M"; ES_ARCH=$ES_A
  case $ES_OS in
    aix) ES_ARCH=ppc64 ;;
    zos) ES_ARCH=s390x ;;
    os400) ES_ARCH=ppc64 ;;
    sunos)
      if [ "$ES_UNAME_M" = i86pc ]; then
        ES_ARCH=x86
        es_which isainfo && case $(isainfo -k 2>/dev/null) in amd64) ES_ARCH=x86_64 ;; esac
      fi ;;
    hpux) case $ES_UNAME_M in ia64) ES_ARCH=ia64 ;; *) ES_ARCH=other ;; esac ;;
  esac
  ES_HOST=${ES_UNAME_N:-unknown}
  ES_F_wsl=false
  case $ES_UNAME_R in *[Mm]icrosoft*) [ "$ES_OS" = linux ] && ES_F_wsl=true ;; esac
}

es_shell_version() {
  if [ -n "${BASH_VERSION:-}" ]; then ES_SHELL="bash $BASH_VERSION"
  elif [ -n "${ZSH_VERSION:-}" ]; then ES_SHELL="zsh $ZSH_VERSION"
  elif [ -n "${KSH_VERSION:-}" ]; then ES_SHELL="ksh $KSH_VERSION"
  elif [ -n "${YASH_VERSION:-}" ]; then ES_SHELL="yash $YASH_VERSION"
  else
    ES_SHELL=sh
    if [ -h "/proc/$$/exe" ]; then
      es_realpath "/proc/$$/exe"
      ES_SHELL=${ES_RP##*/}; ES_SHELL=${ES_SHELL%.exe}
    fi
  fi
}

es_pick_out() {
  es_oparent=
  if [ -n "$ES_OPT_OUT" ]; then
    es_oarg=$ES_OPT_OUT
    # Cygwin/MSYS: a Windows drive path (C:\x or C:/x) from a Windows caller is absolute
    if [ "$ES_OS" = cygwin ] && es_winpath "$es_oarg"; then es_oarg=$ES_T; fi
    case $es_oarg in /*) es_oparent=$es_oarg ;; *) es_oparent="$ES_CWD/$es_oarg" ;; esac
    if [ ! -d "$es_oparent" ]; then mkdir -p "$es_oparent" 2>/dev/null || es_fatal "cannot create --out directory: $ES_OPT_OUT"; fi
    [ -w "$es_oparent" ] || es_fatal "--out directory is not writable: $ES_OPT_OUT"
  else
    # the first writable candidate that is not on a network/autofs mount and not a Desktop,
    # Documents or synchronised folder (an explicit --out is used as given)
    es_xdg_dirs
    for es_oc in "$ES_CWD" "${HOME:-}" "${TMPDIR:-}" /tmp /var/tmp; do
      [ -n "$es_oc" ] || continue
      es_local_path "$es_oc" || continue
      es_unsafe_dir "$es_oc" || continue
      if [ -d "$es_oc" ] && [ -w "$es_oc" ]; then es_oparent=$es_oc; break; fi
    done
    [ -n "$es_oparent" ] || es_fatal "no writable local output directory (current directory, HOME, temp; Desktop, Documents, synchronised folders and network mounts are never used); pass --out DIR"
  fi
  es_ohost=$(printf '%s' "$ES_HOST" | tr -c 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9._-' '_')
  es_ostamp=$(date -u '+%Y%m%dT%H%M%SZ')
  ES_OUT="${es_oparent%/}/envscan-$es_ohost-$es_ostamp"
  es_on=1
  while ! mkdir "$ES_OUT" 2>/dev/null; do
    es_on=$((es_on + 1))
    [ $es_on -le 20 ] || es_fatal "cannot create the output folder under $es_oparent"
    ES_OUT="${es_oparent%/}/envscan-$es_ohost-$es_ostamp-$es_on"
  done
}

es_init() {
  # the environment first (before the scanner changes LC_ALL, CDPATH or PWD); it stays in memory
  ES_ORIG_LC_ALL_SET=${LC_ALL+x}; ES_ORIG_LC_ALL=${LC_ALL-}
  LC_ALL=C; export LC_ALL
  es_env_capture
  es_child_keep_init
  IFS=" $ES_TAB$ES_NL"
  unset CDPATH
  ES_CWD=$(pwd 2>/dev/null)
  ES_TTY_IN=0; ES_TTY_OUT=0; ES_TTY_ERR=0
  [ -t 0 ] && ES_TTY_IN=1
  [ -t 1 ] && ES_TTY_OUT=1
  [ -t 2 ] && ES_TTY_ERR=1
  exec </dev/null 4>&2
  ES_ROOT=${ENVSCAN_ROOT:-}; ES_ROOT=${ES_ROOT%/}
  es_time_init
  es_now_ms; ES_T0=$ES_MS
  ES_DEADLINE=$((ES_T0 + ES_BUDGET * 1000))
  es_utc; ES_STARTED=$ES_UTC
  trap : USR1
  es_mktemp
  exec 2>>"$ES_TMP/shell.err"
  es_pid_init
  es_detect_os
  es_detect_ebcdic
  if [ "$ES_OS" = cygwin ] && es_winpath "$ES_ROOT"; then ES_ROOT=$ES_T; fi
  es_shell_version
  es_mounts_init
  es_netmnts_init
  es_tmp_check
  es_path_init
  es_child_vet_init
  es_awk_program >"$ES_TMP/json.awk"
  es_awk_proxy >"$ES_TMP/proxy.awk"
  es_spec_probes >"$ES_TMP/probes.tsv"
  es_spec_tools >"$ES_TMP/tools.spec"
  es_spec_findings >"$ES_TMP/findings.spec"
  es_shim_init
  ES_CLT=1; ES_MAC_JAVA=1
  if [ "$ES_OS" = darwin ]; then
    ES_CLT=0; ES_MAC_JAVA=0
    if es_which xcode-select; then
      es_exec "$ES_TIMEOUT" "$ES_TMP/xcs.out" "$ES_TMP/xcs.err" "$ES_W" -p && [ -s "$ES_TMP/xcs.out" ] && ES_CLT=1
    fi
    if [ -x "$ES_ROOT/usr/libexec/java_home" ]; then
      es_exec "$ES_TIMEOUT" "$ES_TMP/jh.out" "$ES_TMP/jh.err" "$ES_ROOT/usr/libexec/java_home" && [ -s "$ES_TMP/jh.out" ] && ES_MAC_JAVA=1
    fi
  fi
}

es_progress() {
  es_pd=' '; es_pi=${#2}
  while [ "$es_pi" -lt 33 ]; do es_pd="$es_pd."; es_pi=$((es_pi + 1)); done
  printf '[%2d/%d] %s%s %-9s %6s ms\n' "$1" "$ES_TOTAL" "$2" "$es_pd" "$3" "$4" >&4
  printf '[%2d/%d] %s%s %-9s %6s ms\n' "$1" "$ES_TOTAL" "$2" "$es_pd" "$3" "$4" >>"$ES_TMP/log"
}

es_run_one() {
  es_rn=$1; es_rid=$2; es_rtier=$4
  es_rdir="$ES_TMP/p/$es_rn"
  [ -d "$es_rdir" ] || mkdir -p "$es_rdir"
  : >"$es_rdir/data.ev"
  printf '%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" >"$es_rdir/meta"
  es_rwhy=; es_rkind=-; es_rdur=0; es_rleft=0
  if [ "$es_rtier" = deep ] && [ "$ES_DEEP" != 1 ]; then es_rwhy='tier deep is not enabled (use --deep)'; es_rkind=tier
  elif [ "$es_rtier" = net ] && [ "$ES_NET" != 1 ]; then es_rwhy='tier net is not enabled (use --net)'; es_rkind=tier
  elif [ -n "$ES_ONLY" ] && ! es_in_list "$es_rid" "$ES_ONLY"; then es_rwhy='not selected by --only'; es_rkind=select
  elif [ -n "$ES_SKIP" ] && es_in_list "$es_rid" "$ES_SKIP"; then es_rwhy='excluded by --skip'; es_rkind=select
  else
    es_now_ms
    es_rleft=$(( (ES_DEADLINE - ES_MS) / 1000 ))
    if [ "$es_rleft" -lt 1 ]; then es_rwhy="scan budget of ${ES_BUDGET}s exhausted"; es_rkind=budget; fi
  fi
  if [ -n "$es_rwhy" ]; then
    printf 'skipped\n' >"$es_rdir/status"
    printf '%s\n' "$es_rwhy" >"$es_rdir/notes"
  else
    es_rcap=$ES_PROBE_CAP
    [ "$es_rid" = tools.inventory ] && es_rcap=$ES_LONG_PROBE_CAP
    [ "$es_rleft" -lt "$es_rcap" ] && es_rcap=$es_rleft
    es_rfn="probe_${es_rid%%.*}_${es_rid#*.}"
    es_rt0=$ES_MS
    (
      ES_P_DIR=$es_rdir; ES_P_ID=$es_rid; ES_CN=0; ES_NETSKIP=; ES_CREDSKIP=
      exec 3<&- 5>>"$es_rdir/data.ev"
      cd / 2>/dev/null
      if type "$es_rfn" >/dev/null 2>&1; then
        "$es_rfn"
        [ -n "$ES_NETSKIP$ES_CREDSKIP" ] && es_netskip_note
        [ -s "$ES_P_DIR/status" ] || printf 'ok\n' >"$ES_P_DIR/status"
      else
        printf 'error\n' >"$ES_P_DIR/status"
        printf 'probe function %s is missing\n' "$es_rfn" >"$ES_P_DIR/error"
      fi
      : >"$ES_P_DIR/end"
    ) </dev/null >"$es_rdir/stdout" 2>"$es_rdir/stderr" &
    ES_CUR_PID=$!
    es_watch "$ES_CUR_PID" "$es_rcap" "$es_rdir/killed" "$es_rdir/end" "$$"
    # "wait" returns >128 when the watchdog's USR1 nudge (or a signal) interrupts it
    while :; do
      wait "$ES_CUR_PID"
      es_rrc=$?
      if [ "$es_rrc" -gt 128 ] && [ ! -f "$es_rdir/killed" ] && kill -s 0 "$ES_CUR_PID" 2>/dev/null; then continue; fi
      break
    done
    es_unwatch
    ES_CUR_PID=
    es_clean_list "$es_rdir/cleanup.list"
    # raw intermediates a stopped probe (timeout, error) could not remove itself
    es_raw_drop "$es_rdir"
    es_now_ms
    es_rdur=$((ES_MS - es_rt0))
    [ "$es_rdur" -ge 0 ] || es_rdur=0
    if [ -f "$es_rdir/killed" ]; then
      printf 'timeout\n' >"$es_rdir/status"
      printf '%s\n' "probe stopped after ${es_rcap}s (per-probe time cap or scan budget)" >>"$es_rdir/notes"
    elif [ ! -s "$es_rdir/status" ]; then
      printf 'error\n' >"$es_rdir/status"
      printf 'probe ended unexpectedly (exit status %s)\n' "$es_rrc" >"$es_rdir/error"
    fi
    es_ev_check "$es_rdir"
    if [ -s "$es_rdir/facts" ]; then . "$es_rdir/facts"; fi
    if [ -s "$es_rdir/stderr" ]; then
      { printf '%s\n' "--- $es_rid stderr:"; awk 'NR <= 50' "$es_rdir/stderr"; } >>"$ES_TMP/log"
    fi
  fi
  IFS= read -r es_rst <"$es_rdir/status"
  printf '%s\t%s\t%s\t%s\t%s\n' "$es_rn" "$es_rid" "$es_rst" "$es_rdur" "$es_rkind" >>"$ES_TMP/results.tsv"
  es_progress "$es_rn" "$es_rid" "$es_rst" "$es_rdur"
}

es_run_all() {
  ES_TOTAL=$(awk 'END { print NR }' "$ES_TMP/probes.tsv")
  : >"$ES_TMP/results.tsv"
  mkdir "$ES_TMP/p"
  es_dirs=; es_i=1
  while [ "$es_i" -le "$ES_TOTAL" ]; do es_dirs="$es_dirs $es_i"; es_i=$((es_i + 1)); done
  (cd "$ES_TMP/p" && mkdir $es_dirs) 2>/dev/null
  es_tiers=default
  [ "$ES_DEEP" = 1 ] && es_tiers="$es_tiers, deep"
  [ "$ES_NET" = 1 ] && es_tiers="$es_tiers, net"
  es_say "$ES_NAME $ES_VERSION ($ES_IMPL): $ES_TOTAL probes, tiers $es_tiers -> $ES_OUT"
  es_n=0
  while IFS=$ES_TAB read -r es_id es_title es_tier es_scope es_foot <&3; do
    es_n=$((es_n + 1))
    es_run_one "$es_n" "$es_id" "$es_title" "$es_tier" "$es_scope"
    # the unredacted copy of the environment is only for env.vars: later probes do not get it
    if [ "$es_id" = env.vars ]; then ES_ENV_ORIG=; fi
  done 3<"$ES_TMP/probes.tsv"
  # raw data shared between probes (left when net.proxy did not run or a probe was stopped)
  rm -f "$ES_TMP/pkg_proxy.tsv" "$ES_TMP/pkg_tools.tsv" "$ES_TMP/gitconfig.txt"
}

es_main() {
  # cleanup on every exit path, also before the scan starts: the CRLF self-repair copy (and,
  # once it exists, the private temp directory) is removed after --version, --help, a usage
  # error or a signal
  exec 4>&2
  ES_TMP=; ES_CUR_PID=
  trap es_cleanup EXIT
  trap es_on_signal INT TERM HUP QUIT PIPE
  es_parse_args "$@"
  case $ES_ACTION in
    version) printf '%s %s (%s)\n' "$ES_NAME" "$ES_VERSION" "$ES_IMPL"; exit 0 ;;
    help) es_usage; exit 0 ;;
    list) es_list_probes; exit 0 ;;
  esac
  es_check_selection "$ES_ONLY" --only "$ES_ONLY_SET"; ES_ONLY=$ES_SEL
  es_check_selection "$ES_SKIP" --skip "$ES_SKIP_SET"; ES_SKIP=$ES_SEL
  es_init
  es_pick_out
  es_run_all
  es_findings
  es_render
  es_cleanup
  printf '%s\n' "$ES_OUT"
  exit "$ES_EXIT"
}

es_main "$@"
