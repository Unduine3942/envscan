# ============================================================== child environment: path vetting
# Kept variables (13-child.sh) that hold paths are vetted like every other path before a child
# sees them (spec/child_env.toml, docs/DEVELOPING.md rule 6). "Refused" is the existing vetting
# (es_local_path: a network or autofs mount, a UNC path, a mapped network drive, a credential
# store, also through a link), which never touches a refused path:
#   ES_CHILD_HOME_PATHS  a refused value is replaced by an empty folder in the scanner's temp
#                        folder (TMPDIR, TMP, TEMP: by the temp folder itself)
#   ES_CHILD_PATH_LISTS  refused entries of the ":" list are dropped; a list left empty is removed
#   any other variable   an absolute path ("/...", "C:\...", "C:/...", "\\...") that is refused is
#                        removed
# The verdict is kept per variable with the value it was made for (ES_CVI_<NAME>, ES_CVD_<NAME>,
# ES_CVO_<NAME>); es_child_vet_init fills it at the scan start, and a value a probe changed later
# is vetted again in the child.

# es_child_vet_init: the verdicts for every kept variable (es_init, after the mount table)
es_child_vet_init() {
  set -f
  for es_cvn in ${ES_CHILD_KEEP:-}; do
    es_shell_name "$es_cvn" || continue
    eval "es_cvs=\${$es_cvn+x}"
    [ -n "$es_cvs" ] && es_child_vet "$es_cvn"
  done
  set +f
  return 0
}

# es_child_vet NAME -> ES_CVA: k (pass as it is), r (pass the vetted value ES_CVO_<NAME>) or d
# (leave out); NAME is a valid shell name that is set
es_child_vet() {
  eval "es_cv_v=\$$1; es_cv_d=\${ES_CVD_$1-}; es_cv_i=\${ES_CVI_$1-}"
  if [ -n "$es_cv_d" ] && [ "$es_cv_i" = "$es_cv_v" ]; then ES_CVA=$es_cv_d; return 0; fi
  ES_CVA=k; es_cv_o=
  case $ES_CHILD_HOME_PATHS in
    *" $1 "*) if es_cv_refused "$es_cv_v"; then es_cv_home "$1"; fi ;;
    *) case $ES_CHILD_PATH_LISTS in
         *" $1 "*) es_cv_list "$es_cv_v" ;;
         *) es_cv_refused "$es_cv_v" && ES_CVA=d ;;
       esac ;;
  esac
  eval "ES_CVD_$1=\$ES_CVA; ES_CVI_$1=\$es_cv_v; ES_CVO_$1=\$es_cv_o"
}

# es_cv_home NAME -> ES_CVA r with es_cv_o = the replacement folder (d when there is none)
es_cv_home() {
  ES_CVA=d
  [ -n "${ES_TMP:-}" ] && [ -d "$ES_TMP" ] || return 0
  case $1 in
    TMPDIR|TMP|TEMP) es_cv_o=$ES_TMP ;;
    *) es_cv_o="$ES_TMP/childhome.$1"; mkdir "$es_cv_o" 2>/dev/null; [ -d "$es_cv_o" ] || return 0 ;;
  esac
  ES_CVA=r
}

# es_cv_list LIST -> ES_CVA (k unchanged, r es_cv_o = LIST without its refused entries, d nothing
# left); relative and empty entries stay as they are
es_cv_list() {
  es_cl_r=$1:; es_cl_o=; es_cl_n=0; es_cl_drop=0
  while [ -n "$es_cl_r" ]; do
    es_cl_e=${es_cl_r%%:*}; es_cl_r=${es_cl_r#*:}
    if es_cv_refused "$es_cl_e"; then es_cl_drop=1; continue; fi
    if [ "$es_cl_n" = 0 ]; then es_cl_o=$es_cl_e; else es_cl_o="$es_cl_o:$es_cl_e"; fi
    es_cl_n=$((es_cl_n + 1))
  done
  [ "$es_cl_drop" = 1 ] || { ES_CVA=k; return 0; }
  if [ "$es_cl_n" = 0 ]; then ES_CVA=d; else ES_CVA=r; es_cv_o=$es_cl_o; fi
}

# es_cv_refused VALUE: VALUE is an absolute path that the vetting refuses (relative values and
# anything else never are)
es_cv_refused() {
  case $1 in
    /*|"\\\\"*) ! es_local_path "$1" ;;
    [ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]:[/\\]*) es_cv_winabs "$1" ;;
    *) return 1 ;;
  esac
}

# es_cv_winabs VALUE: a Windows drive path (Cygwin/MSYS) is refused on a mapped network drive
# (ES_NETMNTS, checked before the drive is touched) or when its local form is refused; elsewhere
# such a value is no path of this system
es_cv_winabs() {
  es_cw_l=${1%%:*}
  if es_on_netfs "/$es_cw_l" || es_on_netfs "/cygdrive/$es_cw_l"; then return 0; fi
  [ "${ES_OS:-}" = cygwin ] || return 1
  es_cw_t=${ES_T-}
  if es_winpath "$1"; then es_cw_p=$ES_T; ES_T=$es_cw_t; ! es_local_path "$es_cw_p"; return; fi
  ES_T=$es_cw_t
  return 1
}
