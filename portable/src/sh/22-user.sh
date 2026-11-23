# ============================================================== probes: user.*, env.*, shell.*, session.*

probe_user_identity() {
  es_uid=; es_user=; es_gid=; es_group=
  : >"$ES_P_DIR/groups.tsv"
  if es_need id; then
    awk -v gf="$ES_P_DIR/groups.tsv" '{
        s = $0
        if (match(s, /uid=[0-9]+(\([^)]*\))?/)) { v = substr(s, RSTART + 4, RLENGTH - 4); n = v; sub(/\(.*/, "", n); u = ""; if (match(v, /\(.*\)/)) u = substr(v, RSTART + 1, RLENGTH - 2); print "uid\t" n; print "user\t" u }
        if (match(s, /gid=[0-9]+(\([^)]*\))?/)) { v = substr(s, RSTART + 4, RLENGTH - 4); n = v; sub(/\(.*/, "", n); g = n; if (match(v, /\(.*\)/)) g = substr(v, RSTART + 1, RLENGTH - 2); print "gid\t" n; print "group\t" g }
        if (match(s, /groups=.*/)) {
          v = substr(s, RSTART + 7); sub(/ context=.*/, "", v); m = split(v, G, ",")
          for (j = 1; j <= m; j++) { n = G[j]; sub(/\(.*/, "", n); g = n; if (match(G[j], /\(.*\)/)) g = substr(G[j], RSTART + 1, RLENGTH - 2); print n "\t" g > gf }
        } }' "$ES_OUT_F" >"$ES_P_DIR/id.tsv"
    while IFS=$ES_TAB read -r es_k es_v; do
      case $es_k in uid) es_uid=$es_v ;; user) es_user=$es_v ;; gid) es_gid=$es_v ;; group) es_group=$es_v ;; esac
    done <"$ES_P_DIR/id.tsv"
  fi
  [ -n "$es_user" ] || es_user=${USER:-${LOGNAME:-}}
  es_src "environment HOME, SHELL, USER, LOGNAME"
  es_pw=; es_pwhome=; es_pwshell=; es_pwsrc=
  if [ -n "$es_uid" ]; then
    if es_tool getent passwd "$es_uid"; then
      es_read1 "$ES_OUT_F" && es_pw=$ES_L
      es_pwsrc=getent
    elif [ "$ES_RC" = 2 ] && [ "$ES_TIMED_OUT" = 0 ]; then
      es_pwsrc=getent
    elif [ -r "$ES_ROOT/etc/passwd" ]; then
      es_src "read /etc/passwd (own uid only)"
      es_pw=$(awk -F ':' -v u="$es_uid" '$3 == u { print; exit }' "$ES_ROOT/etc/passwd")
      es_pwsrc=/etc/passwd
    fi
  fi
  es_pwe=
  if [ -n "$es_pw" ]; then
    es_pwe=true
    es_pwhome=$(printf '%s\n' "$es_pw" | awk -F ':' '{ print $6 }')
    es_pwshell=$(printf '%s\n' "$es_pw" | awk -F ':' '{ print $7 }')
  elif [ -n "$es_pwsrc" ] && [ "$ES_OS" != darwin ] && [ "$ES_OS" != cygwin ] && [ "$ES_OS" != zos ] && [ "$ES_OS" != os400 ]; then
    es_pwe=false
  else
    es_note "the passwd database could not be checked on this system"
  fi
  es_admin=
  if [ -n "$es_uid" ]; then es_admin=false; [ "$es_uid" = 0 ] && es_admin=true; fi
  [ "$ES_OS" = os400 ] && es_note "IBM i: user profiles are not all in the PASE /etc/passwd, so a missing entry is not reported as absent"
  [ "$ES_OS" = zos ] && es_note "z/OS: users and groups live in RACF (or another security product), not in /etc/passwd; uid 0 is the only superuser test here (BPX.SUPERUSER is not checked)"
  es_adm_groups=; es_elev=
  while IFS=$ES_TAB read -r es_gn es_gname; do
    case $es_gname in
      sudo|wheel|admin|root|adm|staff|docker|lxd|libvirt|Administrators) es_adm_groups="$es_adm_groups$es_gname$ES_NL" ;;
    esac
  done <"$ES_P_DIR/groups.tsv"
  case "$ES_NL$es_adm_groups" in
    *"${ES_NL}sudo$ES_NL"*|*"${ES_NL}wheel$ES_NL"*|*"${ES_NL}admin$ES_NL"*) es_which sudo && es_elev=sudo ;;
  esac
  [ -z "$es_elev" ] && es_which doas && es_elev='doas (present)'
  es_dom=
  case $es_user in *@*) es_dom=${es_user#*@} ;; esac
  es_s name "$es_user"
  es_sn domain "$es_dom"
  es_n uid "$es_uid"
  es_n gid "$es_gid"
  es_sn primary_group "$es_group"
  es_a groups
  while IFS=$ES_TAB read -r es_gn es_gname; do es_s - "$es_gname"; done <"$ES_P_DIR/groups.tsv"
  es_ae
  es_list privileged_groups "$es_adm_groups"
  es_z sid
  es_b is_admin "$es_admin"
  es_sn elevation_method "$es_elev"
  es_z integrity
  es_sn home "${HOME:-}"
  es_sn passwd_home "$es_pwhome"
  es_sn shell "${SHELL:-}"
  es_sn passwd_shell "$es_pwshell"
  es_b passwd_entry "$es_pwe"
  [ -n "$es_uid" ] || es_partial "id did not run"
  es_fact user "$es_user"
  es_fact uid "$es_uid"
  es_fact is_admin "$es_admin"
  es_fact passwd_entry "$es_pwe"
  es_fact admin_groups "$es_adm_groups"
}

probe_user_profile() {
  es_src "environment HOME, XDG_*"
  es_h=${HOME:-}
  es_ex=; es_wr=; es_fs=; es_net=; es_ptype=
  if [ -n "$es_h" ]; then
    if es_mount_of "$es_h"; then
      es_src "$ES_MOUNT_SRC (file system of HOME, at scan start)"
      es_fs=$ES_MFS; es_net=false
      es_is_netfs "$es_fs" && es_net=true
    fi
    # a HOME on a network or autofs mount (also through a link) is not tested: exists and
    # writable stay unknown
    if [ "$es_net" != true ] && es_local_path "$es_h"; then
      es_ex=false; [ -d "$es_h" ] && es_ex=true
      es_wr=false; [ -w "$es_h" ] && es_wr=true
    else
      es_net=true
      es_note "HOME is on a network or autofs mount: it is not tested (exists and writable unknown)"
    fi
    case $es_net in true) es_ptype=network ;; false) es_ptype=local ;; esac
  else
    es_partial "HOME is not set"
  fi
  es_sn home "$es_h"
  es_b home_exists "$es_ex"
  es_b home_writable "$es_wr"
  es_sn home_fstype "$es_fs"
  es_b home_network "$es_net"
  es_sn profile_type "$es_ptype"
  es_o xdg
  for es_v in XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME XDG_STATE_HOME XDG_RUNTIME_DIR XDG_DATA_DIRS XDG_CONFIG_DIRS; do
    eval "es_vv=\${$es_v-}"
    [ -n "$es_vv" ] && es_s "$es_v" "$es_vv"
  done
  es_oe
  es_ud="${XDG_CONFIG_HOME:-$es_h/.config}/user-dirs.dirs"
  if [ -n "$es_h" ] && es_ltest -r "$es_ud"; then
    es_src "read ~/.config/user-dirs.dirs"
    es_o redirected_folders
    : >"$ES_P_DIR/xdg.tsv"
    while IFS= read -r es_line || [ -n "$es_line" ]; do
      case $es_line in
        XDG_*_DIR=*) es_unquote "${es_line#*=}"; printf '%s\t%s\n' "${es_line%%=*}" "$ES_T" >>"$ES_P_DIR/xdg.tsv" ;;
      esac
    done <"$es_ud"
    es_dedup_last "$ES_P_DIR/xdg.tsv"
    while IFS=$ES_TAB read -r es_k es_v; do es_s "$es_k" "$es_v"; done <"$ES_P_DIR/xdg.tsv"
    es_oe
  else
    es_z redirected_folders
  fi
  es_z onedrive; es_z fslogix
  es_fact home_network "$es_net"
  es_fact home_fstype "$es_fs"
}

# es_ibmi_sysvals -> ES_SV_NAMES, raw.ibmi_system_values: IBM i system values through the PASE
# "system" command (DSPSYSVAL only displays; --deep tier). The display text is kept as raw output,
# not parsed (tier 2, unverified: its layout is from IBM's documentation, not from a system).
es_ibmi_sysvals() {
  ES_SV_NAMES=; : >"$ES_P_DIR/sysvals.txt"
  for es_svn in QSECURITY QCCSID QTIMZON QLANGID; do
    if es_tool system "DSPSYSVAL SYSVAL($es_svn)" && [ -s "$ES_OUT_F" ]; then
      { printf '%s\n' "== $es_svn"; cat "$ES_OUT_F"; } >>"$ES_P_DIR/sysvals.txt"
      ES_SV_NAMES="$ES_SV_NAMES$es_svn$ES_NL"
    fi
  done
  es_raw ibmi_system_values "$ES_P_DIR/sysvals.txt"
  [ -n "$ES_SV_NAMES" ]
}

probe_user_privileges() {
  es_svok=0
  if [ "$ES_OS" = os400 ]; then
    if es_ibmi_sysvals; then es_svok=1; es_list ibmi_system_values "$ES_SV_NAMES"
    else es_note "IBM i: no system value could be read with the system command (DSPSYSVAL)"; fi
  fi
  if ! es_which sudo; then
    [ "$es_svok" = 1 ] || es_status not_found
    es_note "sudo is not installed"
    es_z sudo_rules
    return 0
  fi
  es_tool sudo -n -l
  es_rc=$ES_RC
  cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
  es_raw sudo_n_l "$ES_OUT_F"
  es_pwreq=false
  if grep -i -E 'password is required|a terminal is required|askpass' "$ES_OUT_F" >/dev/null 2>&1; then es_pwreq=true; fi
  awk 'f && NF { sub(/^[ \t]+/, ""); print } /may run the following commands/ { f = 1 }' "$ES_OUT_F" >"$ES_P_DIR/rules.txt"
  es_n exit_code "$es_rc"
  es_b password_required "$es_pwreq"
  es_list_file sudo_rules "$ES_P_DIR/rules.txt" l 100
  es_nopw=false
  grep 'NOPASSWD' "$ES_P_DIR/rules.txt" >/dev/null 2>&1 && es_nopw=true
  es_b nopasswd_rules "$es_nopw"
  es_note "sudo -n -l may be logged by the system (auth log)"
}

# es_env_capture -> ES_ENV_ORIG: the environment as "NAME TAB value" lines, sorted by name, the
# value escaped like S events (\\ \n \t \r). Names come from awk's ENVIRON, so a line of a
# multi-line value (a PEM key) can never be taken for a variable. Runs at scan start after
# LC_ALL=C was set; the original LC_ALL (or its absence) is put back. The capture stays in
# memory: env.vars redacts it before anything is written.
es_env_capture() {
  # z/OS: the preamble changed _CEE_RUNOPTS and _BPXK_AUTOCVT; the user's own values are reported
  ES_ENV_ORIG=$(ENVSCAN_LC_ORIG=$ES_ORIG_LC_ALL ENVSCAN_PRE_CEE=${ES_PRE_CEE:-} ENVSCAN_PRE_CVT=${ES_PRE_CVT:-} awk -v lcset="$ES_ORIG_LC_ALL_SET" \
      -v prezos="${ES_PRE_ZOS:-}" -v ceeset="${ES_PRE_CEE_SET:-}" -v cvtset="${ES_PRE_CVT_SET:-}" 'BEGIN {
      for (k in ENVIRON) {
        if (k == "" || k == "ENVSCAN_LC_ORIG" || k == "ENVSCAN_PRE_CEE" || k == "ENVSCAN_PRE_CVT" || k ~ /[\t\r\n]/) continue
        if (k == "LC_ALL") { if (lcset == "") continue; V[k] = ENVIRON["ENVSCAN_LC_ORIG"] }
        else if (prezos != "" && k == "_CEE_RUNOPTS") { if (ceeset == "") continue; V[k] = ENVIRON["ENVSCAN_PRE_CEE"] }
        else if (prezos != "" && k == "_BPXK_AUTOCVT") { if (cvtset == "") continue; V[k] = ENVIRON["ENVSCAN_PRE_CVT"] }
        else V[k] = ENVIRON[k]
        K[++n] = k
      }
      for (i = 2; i <= n; i++) { t = K[i]; for (j = i - 1; j > 0 && K[j] > t; j--) K[j + 1] = K[j]; K[j + 1] = t }
      for (i = 1; i <= n; i++) {
        v = V[K[i]]; e = ""
        if (v ~ /[\\\t\r\n]/) {
          for (p = 1; p <= length(v); p++) {
            c = substr(v, p, 1)
            if (c == "\\") c = "\\\\"; else if (c == "\n") c = "\\n"; else if (c == "\t") c = "\\t"; else if (c == "\r") c = "\\r"
            e = e c
          }
          v = e
        }
        printf "%s\t%s\n", K[i], v
      } }')
}

probe_env_vars() {
  es_src "process environment (awk ENVIRON, captured in memory at scan start; redacted before it is written)"
  es_o process
  printf '%s\n' "$ES_ENV_ORIG" | es_awk envev >&5
  es_z machine
  es_z user
  [ -n "$ES_ENV_ORIG" ] || es_partial "the environment could not be captured at scan start"
  [ -n "$ES_PATH_PREPENDED" ] && es_note "the scanner prepended $ES_PATH_PREPENDED to PATH before capturing the environment"
  [ -n "${ES_PRE_ZOS:-}" ] && es_note "z/OS: the scanner set _BPXK_AUTOCVT=ON and appended FILETAG(AUTOCVT,AUTOTAG) POSIX(ON) to _CEE_RUNOPTS for the commands it starts; _CEE_RUNOPTS and _BPXK_AUTOCVT above are your original values (absent when you had none)"
  return 0
}

probe_env_path() {
  es_src "process PATH"
  es_src "test each PATH entry (local file systems only)"
  es_s separator ":"
  es_a entries
  es_seen=; es_nmiss=0; es_nrel=0; es_nwr=0
  es_pifs=$IFS; IFS=:; set -f
  set -- $PATH
  IFS=$es_pifs; set +f
  case $PATH in *:) set -- "$@" "" ;; esac
  for es_e in "$@"; do
    es_rel=false; es_dup=false; es_net=; es_ex=; es_wr=
    case $es_e in /*) ;; *) es_rel=true; es_nrel=$((es_nrel + 1)) ;; esac
    case "$ES_NL$es_seen" in *"$ES_NL$es_e$ES_NL"*) es_dup=true ;; esac
    es_seen="$es_seen$es_e$ES_NL"
    if [ "$es_rel" = false ] && es_mount_of "$es_e"; then
      es_net=false; es_is_netfs "$ES_MFS" && es_net=true
    fi
    # an entry on a network or autofs mount, also through a link (es_path_init), is not tested
    if [ "$es_rel" = false ]; then
      case "$ES_NL${ES_PATH_SKIP:-}" in *"$ES_NL$es_e$ES_NL"*) es_net=true ;; esac
    fi
    if [ "$es_net" != true ]; then
      es_ex=false; es_wr=false
      [ -d "${es_e:-.}" ] && es_ex=true
      [ "$es_ex" = true ] && [ -w "${es_e:-.}" ] && es_wr=true
      [ "$es_ex" = false ] && es_nmiss=$((es_nmiss + 1))
      [ "$es_wr" = true ] && es_nwr=$((es_nwr + 1))
    fi
    es_o -
    es_s path "$es_e"; es_s scope process
    es_b exists "$es_ex"; es_b writable "$es_wr"; es_b network "$es_net"
    es_b duplicate "$es_dup"; es_b relative "$es_rel"
    es_oe
  done
  es_ae
  es_n missing_count "$es_nmiss"
  es_n relative_count "$es_nrel"
  es_n writable_count "$es_nwr"
  es_fact path_relative "$es_nrel"
  es_fact path_missing "$es_nmiss"
}

probe_shell_info() {
  es_src "environment SHELL"
  es_sht=
  if [ -e "$ES_ROOT/bin/sh" ]; then
    es_src "list /bin/sh link target"
    es_realpath "$ES_ROOT/bin/sh"
    es_sht=${ES_RP##*/}; es_sht=${es_sht%.exe}
  fi
  es_shells=
  if [ -r "$ES_ROOT/etc/shells" ]; then
    es_src "read /etc/shells"
    es_shells=$(awk '/^\// { print }' "$ES_ROOT/etc/shells")
  fi
  es_bv=; es_zv=
  if es_need bash --version; then es_read1 "$ES_OUT_F" && es_bv=$ES_L; fi
  if es_need zsh --version; then es_read1 "$ES_OUT_F" && es_zv=$ES_L; fi
  es_pw=
  if es_which_all pwsh; then es_pw=$ES_WA; fi
  es_s current_shell "$ES_SHELL"
  es_s shell_version "$ES_SHELL"
  es_sn login_shell "${SHELL:-}"
  es_sn sh_target "$es_sht"
  es_sn bash_version "$es_bv"
  es_sn zsh_version "$es_zv"
  es_list shells "$es_shells"
  es_s umask "$ES_ORIG_UMASK"
  es_list powershell_installed "$es_pw"
  es_z language_mode; es_z execution_policy; es_z effective_policy
  es_z cmd_autorun; es_z cmd_disabled; es_z wsh_enabled
  es_fact sh_target "$es_sht"
  es_version_of "$es_bv"; es_fact bash_version "$ES_T"
  es_fact login_shell "${SHELL:-}"
}

# es_flavor TOOL-OUTPUT-FILE RC PATH -> ES_T: gnu | bsd | busybox | other
es_flavor() {
  ES_T=other
  if grep -E 'BusyBox|busybox|not GNU' "$1" >/dev/null 2>&1; then ES_T=busybox
  elif grep -E 'BSD|bsdtar|libarchive|awk version 20' "$1" >/dev/null 2>&1; then ES_T=bsd
  elif grep 'uutils' "$1" >/dev/null 2>&1; then ES_T=other
  elif grep 'GNU' "$1" >/dev/null 2>&1; then ES_T=gnu
  else
    es_realpath "$3"
    case $ES_RP in
      */busybox*) ES_T=busybox ;;
      *) case $ES_OS in darwin|freebsd|openbsd|netbsd) [ "$2" != 0 ] && ES_T=bsd ;; esac ;;
    esac
  fi
}

probe_shell_userland() {
  if [ -e "$ES_ROOT/bin/busybox" ]; then es_src "list /bin/busybox link targets"; fi
  es_o details
  es_summary=
  for es_t in sed awk grep tar date find; do
    if ! es_which "$es_t"; then eval "es_fl_$es_t=; es_ln_$es_t="; continue; fi
    es_p=$ES_W
    es_tool "$es_t" --version
    es_rc=$ES_RC
    cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
    if [ "$es_t" = awk ] && ! grep -E 'GNU|BusyBox|awk version' "$ES_OUT_F" >/dev/null 2>&1; then
      es_tool awk -W version
      cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
      if grep 'mawk' "$ES_OUT_F" >/dev/null 2>&1; then es_rc=mawk; fi
    fi
    es_flavor "$ES_OUT_F" "$es_rc" "$es_p"
    es_fl=$ES_T
    [ "$es_rc" = mawk ] && es_fl=other
    es_read1 "$ES_OUT_F"; es_ln=$ES_L
    [ "$es_rc" = mawk ] && es_ln=$(grep 'mawk' "$ES_OUT_F" | awk 'NR == 1')
    eval "es_fl_$es_t=\$es_fl"
    es_o "$es_t"; es_s path "$es_p"; es_s flavor "$es_fl"; es_sn version_line "$es_ln"; es_oe
    es_summary="$es_summary $es_t=$es_fl"
  done
  es_oe
  es_sn sed "$es_fl_sed"; es_sn awk "$es_fl_awk"; es_sn grep "$es_fl_grep"
  es_sn tar "$es_fl_tar"; es_sn date "$es_fl_date"; es_sn find "$es_fl_find"
  es_pl=; es_which perl && es_pl=$ES_W
  es_sn perl "$es_pl"
  es_fact userland "${es_summary# }"
}

probe_session_context() {
  es_src "environment SSH_CONNECTION, SSH_TTY, DISPLAY, WAYLAND_DISPLAY, XDG_SESSION_TYPE, XDG_CURRENT_DESKTOP, TERM"
  es_src "test whether stdin, stdout and stderr are terminals (at scan start)"
  es_type=unknown
  if [ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ]; then es_type=ssh
  elif [ "$ES_TTY_IN" = 1 ] || [ "$ES_TTY_OUT" = 1 ]; then es_type=console
  elif [ -n "${INVOCATION_ID:-}${JOURNAL_STREAM:-}" ]; then es_type=service
  fi
  es_disp=${DISPLAY:-}
  [ -n "$es_disp" ] || es_disp=${WAYLAND_DISPLAY:-}
  es_hasd=false; [ -n "$es_disp" ] && es_hasd=true
  es_inter=false; [ "$ES_TTY_IN" = 1 ] && es_inter=true
  es_s type "$es_type"
  es_b interactive "$es_inter"
  es_sn display "$es_disp"
  es_b display_available "$es_hasd"
  es_sn terminal "${TERM:-}"
  es_b tty "$([ "$ES_TTY_IN" = 1 ] && printf true || printf false)"
  es_o terminals
  es_b stdin "$([ "$ES_TTY_IN" = 1 ] && printf true || printf false)"
  es_b stdout "$([ "$ES_TTY_OUT" = 1 ] && printf true || printf false)"
  es_b stderr "$([ "$ES_TTY_ERR" = 1 ] && printf true || printf false)"
  es_oe
  es_sn session_id "${XDG_SESSION_ID:-}"
  es_sn xdg_session_type "${XDG_SESSION_TYPE:-}"
  es_sn desktop "${XDG_CURRENT_DESKTOP:-}"
  es_sn ssh_connection "${SSH_CONNECTION:-}"
  es_fact session_type "$es_type"
  es_fact display "$es_hasd"
}
