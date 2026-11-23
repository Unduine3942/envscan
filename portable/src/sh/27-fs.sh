# ============================================================== probes: fs.*, proc.list, svc.list, sched.tasks, virt.*

# es_flags_of OPTIONS -> ES_NOEXEC ES_NOSUID ES_RO (true/false)
es_flags_of() {
  ES_NOEXEC=false; ES_NOSUID=false; ES_RO=false
  es_fo=$(printf '%s' "$1" | tr -d ' ')
  case ",$es_fo," in *,noexec,*) ES_NOEXEC=true ;; esac
  case ",$es_fo," in *,nosuid,*) ES_NOSUID=true ;; esac
  case ",$es_fo," in *,ro,*|*,read-only,*) ES_RO=true ;; esac
}

probe_fs_mounts() {
  if [ ! -s "$ES_TMP/mounts.tsv" ]; then
    es_partial "no mount table (no /proc/self/mounts and mount failed)"
    case ${ES_OS:-} in zos|os400) es_note "network file systems could not be identified without a mount table; only /QNTC and /QFileSvr.400 (IBM i) are known network roots, so paths here were vetted less strictly than on other systems" ;; esac
    es_a mounts; es_ae; es_o key_paths; es_oe
    return 0
  fi
  es_src "$ES_MOUNT_SRC (at scan start)"
  es_a mounts
  es_nm=0
  while IFS=$ES_TAB read -r es_dev es_mnt es_fs es_opt; do
    es_nm=$((es_nm + 1))
    [ "$es_nm" -le 300 ] || continue
    es_o -; es_s device "$es_dev"; es_s mount "$es_mnt"; es_s fstype "$es_fs"
    es_a options
    es_r=$es_opt
    while [ -n "$es_r" ]; do es_trim "${es_r%%,*}"; [ -n "$ES_T" ] && es_s - "$ES_T"; case $es_r in *,*) es_r=${es_r#*,} ;; *) es_r= ;; esac; done
    es_ae
    es_oe
  done <"$ES_TMP/mounts.tsv"
  es_ae
  [ "$es_nm" -gt 300 ] && { es_truncated; es_note "mount list capped at 300 of $es_nm entries"; }
  es_o key_paths
  es_nx=; es_rro=; es_done=
  for es_p in / /tmp /var/tmp /dev/shm "${HOME:-}" "${TMPDIR:-}" "$ES_CWD"; do
    [ -n "$es_p" ] || continue
    case "$ES_NL$es_done" in *"$ES_NL$es_p$ES_NL"*) continue ;; esac
    es_done="$es_done$es_p$ES_NL"
    es_mount_of "$es_p" || continue
    es_flags_of "$ES_MOPT"
    es_o "$es_p"; es_s mount "$ES_MNT"; es_s fstype "$ES_MFS"; es_b noexec "$ES_NOEXEC"; es_b nosuid "$ES_NOSUID"; es_b ro "$ES_RO"; es_oe
    case $es_p in /tmp|/var/tmp|/dev/shm|"${TMPDIR:-/tmp}") [ "$ES_NOEXEC" = true ] && es_nx="$es_nx$es_p$ES_NL" ;; esac
    [ "$es_p" = / ] && es_rro=$ES_RO
  done
  es_oe
  es_n count "$es_nm"
  es_fact noexec_temp "$es_nx"
  es_fact root_ro "$es_rro"
}

# es_free_mb DIR -> ES_T (free MB from df -P -k, "" when unknown)
es_free_mb() {
  ES_T=
  es_cmd df -P -k "$1" || return 1
  ES_T=$(awk 'NR > 1 { for (i = NF; i >= 4; i--) if ($i ~ /^[0-9]+%$/) { print int($(i - 1) / 1024); exit } }' "$ES_OUT_F")
}

# es_xdg_dirs -> ES_XDG_DESKTOP, ES_XDG_DOCUMENTS from the environment or ~/.config/user-dirs.dirs
es_xdg_dirs() {
  ES_XDG_DESKTOP=${XDG_DESKTOP_DIR:-}; ES_XDG_DOCUMENTS=${XDG_DOCUMENTS_DIR:-}
  es_ud="${XDG_CONFIG_HOME:-${HOME:-/nonexistent}/.config}/user-dirs.dirs"
  if [ -n "${HOME:-}" ] && es_local_path "$es_ud" && [ -r "$es_ud" ]; then
    while IFS= read -r es_line || [ -n "$es_line" ]; do
      case $es_line in
        XDG_DESKTOP_DIR=*|XDG_DOCUMENTS_DIR=*)
          es_unquote "${es_line#*=}"
          case $ES_T in '$HOME'*) ES_T="$HOME${ES_T#'$HOME'}" ;; esac
          case $es_line in
            XDG_DESKTOP_DIR=*) [ -n "$ES_XDG_DESKTOP" ] || ES_XDG_DESKTOP=$ES_T ;;
            *) [ -n "$ES_XDG_DOCUMENTS" ] || ES_XDG_DOCUMENTS=$ES_T ;;
          esac ;;
      esac
    done <"$es_ud"
  fi
  es_xdg_enabled "$ES_XDG_DESKTOP"; ES_XDG_DESKTOP=$ES_T
  es_xdg_enabled "$ES_XDG_DOCUMENTS"; ES_XDG_DOCUMENTS=$ES_T
}

# es_xdg_enabled DIR -> ES_T: DIR normalised ("//" and a trailing "/" removed), or "" when it
# is HOME or an ancestor of HOME ("$HOME/" or "/" is how a user disables an XDG directory)
es_xdg_enabled() {
  es_normdir "$1"; es_xe=$ES_ND
  es_normdir "${HOME:-/nonexistent}"
  case "$ES_ND/" in "${es_xe%/}/"*) ES_T= ;; *) ES_T=$es_xe ;; esac
}

# es_unsafe_dir PATH -> fails with ES_WHY when the scanner must never write there: Desktop,
# Documents (also the XDG user directories) and folders that a sync client uploads
es_unsafe_dir() {
  ES_WHY=
  es_lower "$1"; es_ul="$ES_T/"
  case $es_ul in
    */desktop/*|*/documents/*) ES_WHY='Desktop and Documents are never written to' ;;
    */onedrive*|*/dropbox*|*/google\ drive*|*/googledrive*|*/my\ drive/*|*/library/mobile\ documents/*|\
    */library/cloudstorage/*|*/icloud\ drive*|*/iclouddrive*|*/box/*|*/box\ sync/*|*/nextcloud*|*/owncloud*|\
    */seafile*|*/pcloud*|*/mega/*|*/synologydrive*)
      ES_WHY='synchronised (cloud) folders are never written to' ;;
  esac
  if [ -z "$ES_WHY" ]; then
    es_normdir "$1"; es_up=$ES_ND
    for es_xd in "${ES_XDG_DESKTOP:-}" "${ES_XDG_DOCUMENTS:-}"; do
      [ -n "$es_xd" ] || continue
      case "$es_up/" in "$es_xd/"*) ES_WHY='the XDG Desktop and Documents directories are never written to' ;; esac
    done
  fi
  [ -z "$ES_WHY" ]
}

# es_mkdir_test PARENT TAG -> ES_T: a new directory PARENT/.envscan-TAG.<pid>.<n>, created with
# mkdir so that an existing file, directory or symbolic link is never followed or reused. The
# path is listed in the probe's cleanup.list first, so the main shell removes it even when the
# probe is killed.
es_mkdir_test() {
  ES_T=; es_mn=0
  while [ "$es_mn" -lt 5 ]; do
    es_mn=$((es_mn + 1))
    es_md="$1/.envscan-$2.$$.$es_mn"
    if [ -e "$es_md" ] || [ -h "$es_md" ]; then continue; fi
    printf '%s\n' "$es_md" >>"$ES_P_DIR/cleanup.list"
    if mkdir "$es_md" 2>/dev/null; then ES_T=$es_md; return 0; fi
    return 1
  done
  return 1
}

# es_clean_list FILE: remove the test directories a probe listed (main shell, after each probe)
es_clean_list() {
  [ -s "$1" ] || return 0
  while IFS= read -r es_cl; do
    case $es_cl in
      */.envscan-[wx].[0-9]*.[0-9]*) [ -d "$es_cl" ] && [ ! -h "$es_cl" ] && rm -rf "$es_cl" 2>/dev/null ;;
    esac
  done <"$1"
  : >"$1"
}

# es_loc_candidates: "id TAB path" lines of the candidate write locations
es_loc_candidates() {
  es_sd=${ES_SCRIPT%/*}; [ "$es_sd" = "$ES_SCRIPT" ] && es_sd=.
  case $es_sd in /*) ;; *) es_sd="$ES_CWD/$es_sd" ;; esac
  printf 'tmpdir\t%s\n' "${TMPDIR:-}"
  printf 'tmp\t/tmp\nvar_tmp\t/var/tmp\ndev_shm\t/dev/shm\n'
  printf 'home\t%s\n' "${HOME:-}"
  printf 'home_local\t%s\n' "${HOME:+$HOME/.local}"
  printf 'home_bin\t%s\n' "${HOME:+$HOME/bin}"
  printf 'opt\t/opt\nusr_local\t/usr/local\n'
  printf 'cwd\t%s\n' "$ES_CWD"
  printf 'script_dir\t%s\n' "$es_sd"
}

# es_loc_test PATH -> es_ex, es_wr, es_free, es_fs, es_nx, es_net, es_skip and ES_LS, the state:
# writable, not_writable, absent, skipped (never touched) or unknown (inconclusive test)
es_loc_test() {
  es_ex=; es_wr=; es_free=; es_fs=; es_nx=; es_net=; es_skip=
  if es_mount_of "$1"; then
    es_fs=$ES_MFS; es_flags_of "$ES_MOPT"; es_nx=$ES_NOEXEC
    es_net=false; es_is_netfs "$es_fs" && es_net=true
  fi
  # nothing on a network or autofs mount is touched (no existence check, no mkdir test)
  if [ "$es_net" = true ] || ! es_local_path "$1"; then
    if [ "$es_net" != true ] && [ -n "$ES_CREDLINK" ]; then es_skip='link to a credential store'; ES_LS=skipped; return 0; fi
    es_net=true; es_skip="on a network or autofs mount${es_fs:+ ($es_fs)}"; ES_LS=skipped; return 0
  fi
  es_ex=false; [ -d "$1" ] && es_ex=true
  if ! es_unsafe_dir "$1"; then es_skip=$ES_WHY; ES_LS=skipped; return 0; fi
  if [ "$es_ex" != true ]; then ES_LS=absent; return 0; fi
  if es_mkdir_test "$1" w; then
    es_wr=true; ES_LS=writable; rmdir "$ES_T" 2>/dev/null
  elif [ -n "$es_md" ] && { [ -e "$es_md" ] || [ -h "$es_md" ]; }; then
    ES_LS=unknown
  else
    es_wr=false; ES_LS=not_writable
  fi
  es_free_mb "$1" || es_nfail=$((es_nfail + 1)); es_free=$ES_T
  return 0
}

# es_install_verdict LOC-FILE -> ES_T: true when an install candidate (HOME, ~/.local, ~/bin,
# /opt, /usr/local, the current directory) is writable; false only when every candidate was
# tested or is absent; "" (unknown) when one was skipped or its test was inconclusive
es_install_verdict() {
  ES_T=$(awk -F '\t' '$1 ~ /^(home|home_local|home_bin|opt|usr_local|cwd)$/ {
      if ($6 == "writable") w = 1; else if ($6 != "not_writable" && $6 != "absent") u = 1 }
    END { print (w ? "true" : (u ? "" : "false")) }' "$1")
}

probe_fs_locations() {
  es_src "create and remove one test directory (mkdir, never an existing name) in each candidate directory"
  es_xdg_dirs
  es_loc_candidates >"$ES_P_DIR/cands.tsv"
  : >"$ES_P_DIR/loc.tsv"
  es_a locations
  es_wids=; es_fhome=; es_ftmp=; es_nfail=0
  while IFS=$ES_TAB read -r es_id es_p; do
    [ -n "$es_p" ] || continue
    es_loc_test "$es_p"
    es_o -
    es_s id "$es_id"; es_s path "$es_p"; es_b exists "$es_ex"; es_b writable "$es_wr"; es_n free_mb "$es_free"
    es_sn fstype "$es_fs"; es_b noexec "$es_nx"; es_b network "$es_net"
    [ -n "$es_skip" ] && es_s note "not tested: $es_skip"
    es_oe
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$es_id" "$es_p" "${es_wr:--}" "${es_free:--}" "${es_nx:--}" "$ES_LS" >>"$ES_P_DIR/loc.tsv"
    [ "$es_wr" = true ] && es_wids="$es_wids$es_id$ES_TAB$es_p$ES_NL"
    case $es_id in home) es_fhome=$es_free ;; tmpdir) es_ftmp=$es_free ;; tmp) [ -n "$es_ftmp" ] || es_ftmp=$es_free ;; esac
  done <"$ES_P_DIR/cands.tsv"
  es_ae
  es_clean_list "$ES_P_DIR/cleanup.list"
  [ "$es_nfail" -gt 0 ] && es_partial "df failed for $es_nfail location(s); free space unknown there"
  es_install_verdict "$ES_P_DIR/loc.tsv"
  [ -z "$ES_T" ] && es_note "no install location was found writable and at least one was not tested, so whether one is writable is unknown"
  es_fact install_writable "$ES_T"
  es_fact writable_paths "$es_wids"
  es_fact free_home_mb "$es_fhome"
  es_fact free_tmp_mb "$es_ftmp"
  es_fact locations "$(cat "$ES_P_DIR/loc.tsv")"
}

probe_fs_semantics() {
  es_d="$ES_TMP/fs-semantics.$$"
  es_src "create and remove test files in a new private directory under the scanner temp directory ($ES_TMP)"
  es_cs=; es_sl=; es_hl=; es_slnote=
  if mkdir "$es_d" 2>/dev/null && (set -C; : >"$es_d/CaseTest") 2>/dev/null; then
    es_cs=true; [ -e "$es_d/casetest" ] && es_cs=false
    es_cmd ln -s CaseTest "$es_d/symlink-test"
    if [ "$ES_RC" = 0 ] && [ -h "$es_d/symlink-test" ]; then es_sl=ok
    elif [ "$ES_RC" = 0 ]; then es_sl=error; es_slnote="ln -s created a copy, not a symbolic link (Cygwin/MSYS emulation)"
    elif grep -i -E 'permission|not permitted|privilege' "$ES_ERR_F" >/dev/null 2>&1; then es_sl=denied
    else es_sl=error; es_read1 "$ES_ERR_F" && es_slnote=$ES_L
    fi
    es_cmd ln "$es_d/CaseTest" "$es_d/hardlink-test"
    if [ "$ES_RC" = 0 ]; then es_hl=true; else es_hl=false; fi
  else
    es_partial "could not create a test directory in the scanner's temp directory"
  fi
  rm -rf "$es_d" 2>/dev/null
  es_nmax=; es_pmax=
  if es_tool getconf NAME_MAX "$ES_TMP" && es_read1 "$ES_OUT_F" && es_is_num "$ES_L"; then es_nmax=$ES_L; fi
  if es_tool getconf PATH_MAX "$ES_TMP" && es_read1 "$ES_OUT_F" && es_is_num "$ES_L"; then es_pmax=$ES_L; fi
  [ -n "$es_nmax" ] || es_note "getconf NAME_MAX gave no value"
  es_b case_sensitive "$es_cs"
  es_sn symlink "$es_sl"
  [ -n "$es_slnote" ] && es_s symlink_detail "$es_slnote"
  es_b hardlink "$es_hl"
  es_z junction; es_z long_paths_enabled; es_z short_names
  es_n name_max "$es_nmax"
  es_n path_max "$es_pmax"
  es_s tested_in "$ES_TMP"
  es_fact case_sensitive "$es_cs"
  es_fact symlink "$es_sl"
  es_fact symlink_detail "$es_slnote"
}

# fs.exec_test runs only in per-user places: a new private directory in the scanner's temp
# directory (the temp file system), and new directories under HOME, ~/.local and ~/bin
# es_exec_try DIR -> es_out (ok, blocked or error), es_det: write a #!/bin/sh script into a new
# test directory in DIR and run it
es_exec_try() {
  es_out=error; es_det=
  if ! es_mkdir_test "$1" x; then es_det='could not create a new test directory'; return 0; fi
  es_f="$ES_T/envscan-exec.sh"
  if ! { (set -C; printf '#!/bin/sh\nprintf "envscan-exec-ok\\n"\n' >"$es_f") 2>/dev/null && chmod 700 "$es_f" 2>/dev/null; }; then
    es_det='could not write the test script'; return 0
  fi
  es_cmd "$es_f"
  if [ "$ES_RC" = 0 ] && grep 'envscan-exec-ok' "$ES_OUT_F" >/dev/null 2>&1; then es_out=ok
  elif [ "$ES_RC" = 126 ] || grep -i -E 'permission denied|not permitted|operation not permitted' "$ES_ERR_F" >/dev/null 2>&1; then
    es_out=blocked
  fi
  es_read1 "$ES_ERR_F" && es_det=$ES_L
  [ -n "$es_det" ] || es_det="exit status $ES_RC"
  return 0
}

probe_fs_exec_test() {
  es_src "create a new private directory in the scanner temp directory and under HOME, ~/.local, ~/bin; write a #!/bin/sh script there, chmod 700, run it, remove the directory"
  es_xdg_dirs
  es_a results
  es_blocked=; es_n=0
  {
    printf 'temp\t%s\n' "$ES_TMP"
    printf 'home\t%s\n' "${HOME:-}"
    printf 'home_local\t%s\n' "${HOME:+$HOME/.local}"
    printf 'home_bin\t%s\n' "${HOME:+$HOME/bin}"
  } >"$ES_P_DIR/xcands.tsv"
  while IFS=$ES_TAB read -r es_id es_p; do
    [ -n "$es_p" ] || continue
    # nothing on a network or autofs mount is touched (no existence check, no script)
    es_xfs=; ES_CREDLINK=; es_mount_of "$es_p" && es_xfs=$ES_MFS
    if { [ -n "$es_xfs" ] && es_is_netfs "$es_xfs"; } || ! es_local_path "$es_p"; then
      es_xw="on a network or autofs mount${es_xfs:+ ($es_xfs)}"
      [ -n "$ES_CREDLINK" ] && es_xw='link to a credential store'
      es_o -; es_s id "$es_id"; es_s path "$es_p"; es_s kind sh-script; es_s outcome skipped
      es_s detail "$es_xw"; es_oe
      continue
    fi
    [ -d "$es_p" ] && [ -w "$es_p" ] || continue
    if ! es_unsafe_dir "$es_p"; then
      es_o -; es_s id "$es_id"; es_s path "$es_p"; es_s kind sh-script; es_s outcome skipped; es_s detail "$ES_WHY"; es_oe
      continue
    fi
    es_exec_try "$es_p"
    [ "$es_out" = blocked ] && es_blocked="$es_blocked$es_id "
    es_o -; es_s id "$es_id"; es_s path "$es_p"; es_s kind sh-script; es_s outcome "$es_out"; es_s detail "$es_det"; es_oe
    es_n=$((es_n + 1))
  done <"$ES_P_DIR/xcands.tsv"
  es_ae
  es_clean_list "$ES_P_DIR/cleanup.list"
  [ "$es_n" -gt 0 ] || es_partial "no writable per-user directory to test"
  es_fact exec_blocked "$es_blocked"
}

# es_nss_local: user-name lookups stay on this machine. The passwd line of /etc/nsswitch.conf
# lists only local sources (no ldap, sss, nis, winbind, ...); without nsswitch.conf the C
# library reads /etc/passwd. Never on Cygwin/MSYS, where names come from Windows (and possibly
# a domain controller).
es_nss_local() {
  [ "$ES_OS" = cygwin ] && return 1
  [ -r "$ES_ROOT/etc/nsswitch.conf" ] || return 0
  es_nsrc=$(awk '$1 == "passwd:" { $1 = ""; print; exit }' "$ES_ROOT/etc/nsswitch.conf")
  set -f
  for es_ns in $es_nsrc; do
    case $es_ns in files|compat|systemd|cache|db|extrausers|altfiles|usrfiles|'['*|*']') ;; *) set +f; return 1 ;; esac
  done
  set +f
  return 0
}

probe_proc_list() {
  # numeric uids (ps -o uid=) mapped to names from /etc/passwd only: ps -o user= would resolve
  # every uid through NSS, which can mean LDAP/SSSD queries
  es_fmt=
  if es_tool ps -A -o pid= -o ppid= -o uid= -o comm= -o args= && [ -s "$ES_OUT_F" ]; then es_fmt=uid
  elif es_nss_local && es_tool ps -A -o pid= -o ppid= -o user= -o comm= -o args= && [ -s "$ES_OUT_F" ]; then es_fmt=user
  elif es_nss_local && es_tool ps -ef && [ -s "$ES_OUT_F" ]; then es_fmt=ef
  else
    if es_nss_local; then es_partial "ps did not run"
    elif [ "$ES_OS" = cygwin ]; then es_status not_applicable; es_note "Cygwin/MSYS: ps would look up Windows account names; Windows processes are reported by envscan.ps1"
    else es_partial "ps -o uid= is not supported here and user names would need a directory (NSS) lookup; processes were not listed"
    fi
    es_n count ""; es_a processes; es_ae; es_b truncated false
    return 0
  fi
  es_pwf=
  if [ "$es_fmt" = uid ] && [ -r "$ES_ROOT/etc/passwd" ]; then
    es_pwf="$ES_ROOT/etc/passwd"; es_src "read /etc/passwd (names for the numeric uids; no directory lookups)"
  fi
  awk -v fmt="$es_fmt" -v me="${ES_F_user:-}" -v myuid="${ES_F_uid:-}" -v endf="$ES_P_DIR/procs.end" -v pwf="$es_pwf" '
    BEGIN { if (pwf != "") while ((getline l < pwf) > 0) { split(l, P, ":"); if (P[3] != "" && !(P[3] in U)) U[P[3]] = P[1] } }
    fmt == "ef" && NR == 1 { next }
    {
      if (fmt == "uid") { pid = $1; ppid = $2; uid = $3; user = (uid in U) ? U[uid] : uid; comm = $4; a = 5 }
      else if (fmt == "user") { pid = $1; ppid = $2; uid = ""; user = $3; comm = $4; a = 5 }
      else {
        user = $1; pid = $2; ppid = $3; uid = ""; a = ($4 ~ /^[0-9]+$/) ? 8 : 6; comm = $NF
        # STIME is one token ("10:15", "Nov03") or two ("Nov 03" on AIX/Solaris for older
        # processes): CMD follows the TIME column, found after the C column
        if ($4 ~ /^[0-9]+$/) for (i = 6; i <= 9 && i < NF; i++)
          if ($i ~ /^([0-9]+-)?[0-9]+:[0-9][0-9](:[0-9][0-9])?$/) { a = i + 1; break }
      }
      args = ""; for (i = a; i <= NF; i++) args = args (i > a ? " " : "") $i
      if (fmt == "ef") { comm = $a; sub(/.*\//, "", comm) }
      own = (uid != "" && myuid != "") ? (uid == myuid) : (user == me)
      n++
      if (n > 500) next
      printf "{\t-\nn\tpid\t%s\nn\tppid\t%s\ns\tname\t%s\ns\tuser\t%s\n", pid, ppid, comm, user
      p = args; sub(/ .*/, "", p)
      if (own && p ~ /^\//) printf "s\tpath\t%s\n", p; else print "z\tpath"
      if (own) printf "c\tcmdline\t%s\n", args; else print "z\tcmdline"
      print "}"
    }
    END { printf "n\tcount\t%d\nb\ttruncated\t%s\n", n, (n > 500 ? "true" : "false") > endf }' "$ES_OUT_F" >"$ES_P_DIR/procs.ev"
  es_a processes
  printf '@\t%s\n' "$ES_P_DIR/procs.ev" >&5
  es_ae
  printf '@\t%s\n' "$ES_P_DIR/procs.end" >&5
  es_note "command lines are shown only for this user's own processes"
  es_pc=$(awk -F '\t' '$2 == "count" { print $3 }' "$ES_P_DIR/procs.end")
  if [ "${es_pc:-0}" -gt 500 ]; then es_truncated; fi
  es_fact proc_count "$es_pc"
}

probe_svc_list() {
  es_mgr=; : >"$ES_P_DIR/svc.tsv"
  if es_which systemctl && es_tool systemctl list-units --type=service --all --no-legend --no-pager && [ "$ES_RC" = 0 ] && [ -s "$ES_OUT_F" ]; then
    es_mgr=systemd
    cp "$ES_OUT_F" "$ES_P_DIR/units.txt"
    es_tool systemctl list-unit-files --type=service --no-legend --no-pager
    awk -v uf="$ES_OUT_F" '
      BEGIN { while ((getline l < uf) > 0) { split(l, F, " "); M[F[1]] = F[2] } }
      { i = 1; if ($1 !~ /\.service$/) i = 2; u = $i; st = $(i + 2) "/" $(i + 3); d = ""; for (k = i + 4; k <= NF; k++) d = d (d == "" ? "" : " ") $k
        print u "\t" d "\t" st "\t" ((u in M) ? M[u] : "-") }' "$ES_P_DIR/units.txt" >"$ES_P_DIR/svc.tsv"
  elif [ "$ES_OS" = darwin ] && es_tool launchctl list; then
    es_mgr=launchd
    awk 'NR > 1 { print $3 "\t-\t" ($1 == "-" ? "stopped" : "running") "\t-" }' "$ES_OUT_F" >"$ES_P_DIR/svc.tsv"
    es_note "launchctl list shows this user's launchd domain only"
  elif [ "$ES_OS" = aix ] && es_tool lssrc -a; then
    es_mgr=src
    awk 'NR > 1 { print $1 "\t" ($2 ~ /^[0-9]+$/ ? "-" : $2) "\t" $NF "\t-" }' "$ES_OUT_F" >"$ES_P_DIR/svc.tsv"
  elif [ "$ES_OS" = sunos ] && es_tool svcs -a; then
    es_mgr=smf
    awk 'NR > 1 { print $3 "\t-\t" $1 "\t-" }' "$ES_OUT_F" >"$ES_P_DIR/svc.tsv"
  elif [ -d "$ES_ROOT/etc/init.d" ]; then
    es_mgr=sysvinit
    es_src "list /etc/init.d"
    for es_f in "$ES_ROOT"/etc/init.d/*; do [ -f "$es_f" ] && printf '%s\t-\t-\t-\n' "${es_f##*/}" >>"$ES_P_DIR/svc.tsv"; done
  fi
  es_sn manager "$es_mgr"
  es_total=$(awk 'END { print NR }' "$ES_P_DIR/svc.tsv")
  es_n count "$es_total"
  es_a services
  awk -F '\t' 'NR <= 400 { printf "{\t-\ns\tname\t%s\n", $1
      if ($2 != "-" && $2 != "") printf "s\tdisplay\t%s\n", $2; else print "z\tdisplay"
      if ($3 != "-") printf "s\tstate\t%s\n", $3; else print "z\tstate"
      if ($4 != "-") printf "s\tstart_mode\t%s\n", $4; else print "z\tstart_mode"
      print "z\taccount\nz\tpath\n}" }' "$ES_P_DIR/svc.tsv" >&5
  es_ae
  es_tr=false; [ "$es_total" -gt 400 ] && { es_tr=true; es_truncated; }
  es_b truncated "$es_tr"
  if [ -z "$es_mgr" ] && [ "$ES_OS" = cygwin ]; then
    es_status not_applicable; es_note "Cygwin/MSYS: Windows services are reported by envscan.ps1"
  elif [ -z "$es_mgr" ] && [ "$ES_OS" = zos ]; then es_status not_applicable; es_note "z/OS: services are started tasks and address spaces under MVS; no UNIX command lists them quietly (tier 2, unverified)"
  elif [ -z "$es_mgr" ] && [ "$ES_OS" = os400 ]; then es_status not_applicable; es_note "IBM i: services are subsystems and jobs (WRKACTJOB), outside PASE; not listed (tier 2, unverified)"
  elif [ -z "$es_mgr" ]; then es_status not_found; es_note "no service manager was found (typical inside containers)"; fi
  es_fact svc_manager "$es_mgr"
}

probe_sched_tasks() {
  es_ct=
  : >"$ES_P_DIR/cron.txt"
  if es_tool crontab -l; then
    awk '{ sub(/\r$/, "") } /^[ \t]*(#|$)/ { next } { print }' "$ES_OUT_F" >"$ES_P_DIR/cron.txt"
  fi
  es_list_file user_crontab "$ES_P_DIR/cron.txt" c 200
  es_a tasks
  es_nt=0
  for es_d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /Library/LaunchAgents /Library/LaunchDaemons "${HOME:+$HOME/Library/LaunchAgents}"; do
    [ -n "$es_d" ] || continue
    es_dd="$ES_ROOT$es_d"
    if [ -n "${HOME:-}" ]; then case $es_d in "$HOME"/*) es_dd=$es_d ;; esac; fi
    es_ltest -d "$es_dd" || continue
    es_src "list $es_d"
    es_glob "$es_dd/*" || continue
    es_tr=$ES_X
    while [ -n "$es_tr" ]; do
      es_f=${es_tr%%"$ES_NL"*}; es_tr=${es_tr#*"$ES_NL"}
      [ -f "$es_f" ] || continue
      es_o -; es_s name "${es_f##*/}"; es_s path "$es_d"; es_s state present; es_oe
      es_nt=$((es_nt + 1))
    done
  done
  es_ae
  es_tm=
  if es_which systemctl && es_tool systemctl list-timers --all --no-pager --no-legend && [ "$ES_RC" = 0 ]; then
    es_tm=$(awk 'NF { gsub(/[ \t]+/, " "); print }' "$ES_OUT_F")
  fi
  es_list timers "$es_tm"
  es_lg=
  if es_which loginctl && [ -n "${ES_F_user:-}" ] && es_tool loginctl show-user "$ES_F_user" -p Linger; then
    case $(awk 'NR == 1' "$ES_OUT_F") in Linger=yes) es_lg=true ;; Linger=no) es_lg=false ;; esac
  fi
  es_b linger "$es_lg"
  es_count_lines "$ES_P_DIR/cron.txt"
  es_n count $((es_nt + ES_T))
}

probe_virt_platform() {
  es_ctr=false; es_eng=; es_k8s=false; es_hyp=; es_vend=; es_model=; es_sdv=; es_kvm=; es_vmflag=false
  es_src "read /.dockerenv, /run/.containerenv, /proc/1/cgroup, /proc/self/mountinfo"
  [ -e "$ES_ROOT/.dockerenv" ] && { es_ctr=true; es_eng=docker; }
  [ -e "$ES_ROOT/run/.containerenv" ] && { es_ctr=true; es_eng=podman; }
  if [ -r "$ES_ROOT/proc/1/cgroup" ]; then
    es_cg=$(awk '/kubepods/ { print "kubernetes"; exit } /libpod/ { print "podman"; exit } /docker/ { print "docker"; exit } /containerd/ { print "containerd"; exit } /lxc/ { print "lxc"; exit }' "$ES_ROOT/proc/1/cgroup")
    if [ -n "$es_cg" ]; then es_ctr=true; [ -n "$es_eng" ] || es_eng=$es_cg; [ "$es_cg" = kubernetes ] && es_k8s=true; fi
  fi
  if [ -r "$ES_ROOT/proc/self/mountinfo" ] && awk '$5 == "/" && $0 ~ / - overlay / { f = 1 } END { exit !f }' "$ES_ROOT/proc/self/mountinfo"; then
    es_ctr=true; [ -n "$es_eng" ] || es_eng=unknown
  fi
  es_src "environment KUBERNETES_SERVICE_HOST, container, WSL_DISTRO_NAME"
  [ -n "${KUBERNETES_SERVICE_HOST:-}" ] && { es_k8s=true; es_ctr=true; [ -n "$es_eng" ] || es_eng=kubernetes; }
  if [ -n "${container:-}" ]; then es_ctr=true; [ -n "$es_eng" ] || es_eng=$container; fi
  if es_read1 "$ES_ROOT/sys/class/dmi/id/sys_vendor"; then es_src "read /sys/class/dmi/id/sys_vendor, product_name"; es_vend=$ES_L; fi
  es_read1 "$ES_ROOT/sys/class/dmi/id/product_name" && es_model=$ES_L
  case "$es_vend $es_model" in
    *QEMU*|*KVM*) es_hyp=kvm ;;
    *VMware*) es_hyp=vmware ;;
    *Microsoft*Virtual*) es_hyp=hyperv ;;
    *innotek*|*VirtualBox*) es_hyp=virtualbox ;;
    *Xen*) es_hyp=xen ;;
    *Amazon*EC2*|*Amazon*) es_hyp=aws ;;
    *Google*) es_hyp=gce ;;
    *OpenStack*) es_hyp=openstack ;;
    *Parallels*) es_hyp=parallels ;;
    *Nutanix*) es_hyp=nutanix ;;
  esac
  if [ -r "$ES_ROOT/proc/cpuinfo" ] && grep '^flags.* hypervisor' "$ES_ROOT/proc/cpuinfo" >/dev/null 2>&1; then
    es_src "read /proc/cpuinfo (hypervisor flag)"; es_vmflag=true
  fi
  if es_tool systemd-detect-virt && es_read1 "$ES_OUT_F"; then es_sdv=$ES_L; fi
  if [ -z "$es_sdv" ] && [ "$ES_RC" = 1 ] && es_read1 "$ES_OUT_F"; then es_sdv=$ES_L; fi
  es_hvok=0
  if [ "$ES_OS" = darwin ] && es_tool sysctl -n kern.hv_vmm_present && es_read1 "$ES_OUT_F"; then
    es_hvok=1; [ "$ES_L" = 1 ] && es_vmflag=true
  fi
  es_src "test /dev/kvm, /var/run/docker.sock, \$XDG_RUNTIME_DIR/podman/podman.sock"
  if [ -e "$ES_ROOT/dev/kvm" ]; then es_kvm=false; [ -r "$ES_ROOT/dev/kvm" ] && [ -w "$ES_ROOT/dev/kvm" ] && es_kvm=true; fi
  es_v=none
  if [ "$es_ctr" = true ]; then es_v=container
  elif [ "${ES_F_wsl:-false}" = true ]; then es_v=wsl
  elif [ "$ES_OS" = cygwin ] && [ -z "$es_hyp" ]; then
    es_v=unknown
    if [ "$es_vmflag" = true ]; then es_note "the hypervisor CPU flag is also set on Windows hosts that use Hyper-V or virtualization-based security; envscan.ps1 identifies the platform"
    else es_note "Cygwin/MSYS: envscan.ps1 identifies the platform"; fi
  elif [ -n "$es_hyp" ] || [ "$es_vmflag" = true ]; then es_v=vm
  else
    # "none" only from a source that can tell: systemd-detect-virt, macOS kern.hv_vmm_present,
    # or the x86 hypervisor CPU flag being absent from a readable /proc/cpuinfo
    case $es_sdv in
      none) es_v=none ;;
      '')
        es_v=unknown
        [ "$es_hvok" = 1 ] && es_v=none
        case $ES_ARCH in x86_64|amd64|i?86|i86pc|x86) [ -r "$ES_ROOT/proc/cpuinfo" ] && es_v=none ;; esac
        [ "$es_v" = unknown ] && es_note "no source here can tell a virtual machine from bare metal (no systemd-detect-virt; the cpuinfo hypervisor flag is only reliable on x86)" ;;
      *) es_v=vm ;;
    esac
  fi
  [ -z "$es_hyp" ] && case $es_sdv in none|''|docker|podman|lxc|wsl|container-other|systemd-nspawn) ;; *) es_hyp=$es_sdv ;; esac
  es_s virtualization "$es_v"
  es_sn hypervisor "$es_hyp"
  es_sn vendor "$es_vend"
  es_sn model "$es_model"
  es_sn systemd_detect_virt "$es_sdv"
  es_o container; es_b detected "$es_ctr"; es_sn engine "$es_eng"; es_b kubernetes "$es_k8s"; es_oe
  es_z wsl_distros
  es_o docker_socket
  if [ -e "$ES_ROOT/var/run/docker.sock" ]; then
    es_s path /var/run/docker.sock
    es_acc=false; [ -r "$ES_ROOT/var/run/docker.sock" ] && [ -w "$ES_ROOT/var/run/docker.sock" ] && es_acc=true
    es_b accessible "$es_acc"
  else es_z path; es_z accessible; fi
  es_oe
  es_ps=
  [ -n "${XDG_RUNTIME_DIR:-}" ] && es_ltest -e "$XDG_RUNTIME_DIR/podman/podman.sock" && es_ps=$XDG_RUNTIME_DIR/podman/podman.sock
  es_sn podman_socket "$es_ps"
  es_b kvm "$es_kvm"
  es_fact virtualization "$es_v"
  es_fact container "$es_ctr"
  es_fact container_engine "$es_eng"
  es_fact kubernetes "$es_k8s"
}

probe_virt_engine() {
  es_any=0
  if es_which docker; then
    if es_runnable "$ES_W" docker; then
      es_tool docker --context default info
      cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
      es_raw docker_info "$ES_OUT_F"
      es_o docker
      es_n exit_code "$ES_RC"
      awk '/^ *(Server Version|Storage Driver|Cgroup Driver|Cgroup Version|Docker Root Dir|Operating System|Kernel Version|HTTP Proxy|HTTPS Proxy|No Proxy|Security Options|Rootless):/ {
          k = $0; sub(/:.*/, "", k); sub(/^ +/, "", k); v = $0; sub(/^[^:]*: */, "", v); gsub(/ /, "_", k); print "s\t" tolower(k) "\t" v }' "$ES_OUT_F" >&5
      es_mir=$(awk '/^ *Registry Mirrors:/ { f = 1; next } f && /^ +[abcdefghijklmnopqrstuvwxyz]+:\/\// { sub(/^ +/, ""); print; next } { f = 0 }' "$ES_OUT_F")
      es_ins=$(awk '/^ *Insecure Registries:/ { f = 1; next } f && /^ +[^ ]/ && !/:$/ { sub(/^ +/, ""); print; next } { f = 0 }' "$ES_OUT_F")
      es_list registry_mirrors "$es_mir"
      es_list insecure_registries "$es_ins"
      es_oe
      es_any=1
    else
      es_note "docker: $ES_WHY"
    fi
  fi
  if es_which podman; then
    es_o podman; es_s path "$ES_W"; es_s detail "podman info is not run; the version is in tools.inventory"; es_oe
    es_any=1
  fi
  if [ "$es_any" = 0 ]; then es_status not_found; es_note "no runnable docker CLI and no podman"; fi
  return 0
}
