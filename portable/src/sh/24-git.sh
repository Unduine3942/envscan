# ============================================================== pkg.sources: git configuration
# git config --list never follows include.path itself (--no-includes): an include can name a
# file on an NFS, SMB or autofs mount. The scanner reads each unconditional include one level
# deep, only from a local path, and notes the others:
#   "git include not read (<reason>): <path>", reason one of
#   network path      the resolved file is on a network or autofs mount (never touched); partial
#   credential store  the file, or the file a link leads to, is a credential store (es_cred_path:
#                     ~/.ssh, .git-credentials, .netrc, ...), never opened or tested; partial
#   not a local path  ~user/, %(prefix)/, a Windows drive or UNC path, or relative to an origin
#                     that is not an absolute file name (command line, blob, quoted); partial
#   unreadable        not a regular file (never opened), or git config --file failed; partial
#   nested include    an include.path inside an included file (path as written); partial
#   condition <cond>  includeIf.<cond>.path (path as written); a note only
# <path> is the resolved path when resolution worked, else the value as written. A missing local
# include file is skipped, as git skips it; a file is read once. Notes pass the value redaction
# rules like any data string (a hasconfig:remote.*.url: condition can hold a credentialed URL).

# es_git_env -> ES_CHILD_EXTRA for the git children: git reads its global and system
# configuration through HOME, XDG_CONFIG_HOME, GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM; one on a
# network or autofs mount is replaced, for the git children only ("NAME=es_gr_NAME", 13-child.sh),
# by an empty local directory (a missing file for GIT_CONFIG_*), so git reads nothing there. The
# scanner's own variables stay as they are.
es_git_env() {
  ES_CHILD_EXTRA='GIT_CEILING_DIRECTORIES=es_gceil'
  for es_gv in HOME XDG_CONFIG_HOME GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM; do
    eval "es_gx=\${$es_gv:-}"
    [ -n "$es_gx" ] || continue
    es_local_path "$es_gx" && continue
    mkdir -p "$ES_P_DIR/githome" 2>/dev/null
    case $es_gv in GIT_CONFIG_*) es_gn="$ES_P_DIR/githome/none" ;; *) es_gn="$ES_P_DIR/githome" ;; esac
    eval "es_gr_$es_gv=\$es_gn"
    ES_CHILD_EXTRA="$ES_CHILD_EXTRA $es_gv=es_gr_$es_gv"
    case $es_gv in HOME) es_gl='git home folder' ;; *) es_gl=$es_gv ;; esac
    case $es_gv in GIT_CONFIG_SYSTEM) es_gw=system ;; *) es_gw=global ;; esac
    es_partial "$es_gl $es_gx is on a network path: $es_gw git configuration from there is not read"
  done
  return 0
}

# es_git_optfail: the last git command failed because it does not know one of its options
es_git_optfail() { grep -i -E 'unknown (option|switch)|usage:' "$ES_ERR_F" >/dev/null 2>&1; }

# es_git_list -> $ES_TMP/gitconfig.txt ("origin TAB key=value"; origin "unknown" from a git
# before 2.8, which has no --show-origin) and ES_GIT_NOINC (--no-includes, or "" for a git
# before 1.7.10, which has neither option and no includes); fails when git gave nothing
es_git_list() {
  ES_GIT_NOINC=--no-includes
  if es_tool git config --list --show-origin --no-includes; then
    awk 'NF' "$ES_OUT_F" >"$ES_TMP/gitconfig.txt"; return 0
  fi
  case $ES_RC in 126|127) return 1 ;; esac
  if ! es_git_optfail; then es_partial "git config --list failed (exit status $ES_RC)"; return 1; fi
  if ! es_tool git config --list --no-includes; then
    if ! es_git_optfail; then es_partial "git config --list failed (exit status $ES_RC)"; return 1; fi
    ES_GIT_NOINC=
    if ! es_tool git config --list; then es_partial "git config --list failed (exit status $ES_RC)"; return 1; fi
  fi
  awk 'NF { print "unknown\t" $0 }' "$ES_OUT_F" >"$ES_TMP/gitconfig.txt"
  return 0
}

# es_git_noread REASON PATH: an unconditional include that is not read (the probe is partial)
es_git_noread() { es_partial "git include not read ($1): $2"; }

# es_git_cond KEY VALUE: includeIf.<cond>.path is never read; a note only
es_git_cond() {
  es_gc=${1#*.}; es_gc=${es_gc%.*}
  es_note "git include not read (condition $es_gc): $2"
}

# es_git_incpath ORIGIN VALUE -> ES_T: the file an include.path VALUE names (~/ with the user's
# HOME, es_ghome, also when git runs with a replacement HOME; a relative path from the directory
# of the origin file); fails with ES_T = VALUE when that is not a local path: ~user/, %(prefix)/,
# a Windows drive or UNC path, or relative to an origin that is not a plain absolute file name
# (command line, blob, unknown, or a name git printed in quotes)
es_git_incpath() {
  ES_T=$2
  case $2 in
    '~/'*) [ -n "$es_ghome" ] || return 1; ES_T="${es_ghome%/}/${2#'~/'}" ;;
    /*) ;;
    '~'*|'%('*|''|[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]:*|\\*) return 1 ;;
    *) case $1 in file:/*) es_gd=${1#file:}; ES_T="${es_gd%/*}/$2" ;; *) return 1 ;; esac ;;
  esac
  return 0
}

# es_git_nested FILE: the include directives of an included file (key=value lines) are not followed
es_git_nested() {
  while IFS= read -r es_gl; do
    es_gk=${es_gl%%=*}
    case $es_gk in
      [Ii][Nn][Cc][Ll][Uu][Dd][Ee].[Pp][Aa][Tt][Hh]) es_git_noread 'nested include' "${es_gl#*=}" ;;
      [Ii][Nn][Cc][Ll][Uu][Dd][Ee][Ii][Ff].*.[Pp][Aa][Tt][Hh]) es_git_cond "$es_gk" "${es_gl#*=}" ;;
    esac
  done <"$1"
}

# es_git_include ORIGIN VALUE: read one unconditional include, one level deep
es_git_include() {
  if ! es_git_incpath "$1" "$2"; then es_git_noread 'not a local path' "$ES_T"; return 0; fi
  es_gi=$ES_T
  # a credential store is never opened or tested, also when a link leads to one
  if es_cred_path "$es_gi"; then es_git_noread 'credential store' "$es_gi"; return 0; fi
  if ! es_resolve "$es_gi"; then
    if [ -n "$ES_CREDLINK" ]; then es_git_noread 'credential store' "$es_gi"; else es_git_noread 'network path' "$es_gi"; fi
    return 0
  fi
  if es_cred_path "$ES_RPATH"; then es_git_noread 'credential store' "$es_gi"; return 0; fi
  case "$ES_NL$es_gseen" in *"$ES_NL$es_gi$ES_NL"*) return 0 ;; esac
  es_gseen="$es_gseen$es_gi$ES_NL"
  # a missing file (or a dangling link) is skipped, as git skips it; anything but a regular file
  # (a FIFO, a device) is never opened
  [ -e "$es_gi" ] || return 0
  if [ ! -f "$es_gi" ] || ! es_tool git config --list $ES_GIT_NOINC --file "$es_gi"; then
    es_git_noread unreadable "$es_gi"; return 0
  fi
  awk -v o="file:$es_gi" 'NF { print o "\t" $0 }' "$ES_OUT_F" >>"$ES_P_DIR/git-incl.txt"
  es_git_nested "$ES_OUT_F"
}

# es_git_includes: follow the unconditional include.path entries of $ES_TMP/gitconfig.txt (git
# before 1.7.10 has no includes); conditional ones are only noted
es_git_includes() {
  [ -n "$ES_GIT_NOINC" ] || return 0
  : >"$ES_P_DIR/git-incl.txt"; es_gseen=
  while IFS=$ES_TAB read -r es_go es_gkv; do
    es_gk=${es_gkv%%=*}
    case $es_gk in
      [Ii][Nn][Cc][Ll][Uu][Dd][Ee].[Pp][Aa][Tt][Hh]) es_git_include "$es_go" "${es_gkv#*=}" ;;
      [Ii][Nn][Cc][Ll][Uu][Dd][Ee][Ii][Ff].*.[Pp][Aa][Tt][Hh]) es_git_cond "$es_gk" "${es_gkv#*=}" ;;
    esac
  done <"$ES_TMP/gitconfig.txt"
  cat "$ES_P_DIR/git-incl.txt" >>"$ES_TMP/gitconfig.txt"
}

# es_git_config: git's configuration as the git_config list (origin, key, redacted value) and
# $ES_TMP/gitconfig.txt, git_lines.txt and git_urls.txt (raw) for the endpoint, proxy and TLS
# checks. git runs in a new empty directory below the scanner temp directory, with discovery
# stopped at its parent and GIT_DIR/GIT_WORK_TREE unset, so that no repository configuration is read.
es_git_config() {
  : >"$ES_TMP/gitconfig.txt"
  es_gcwd="$ES_P_DIR/git-cwd"
  if mkdir "$es_gcwd" 2>/dev/null; then
    ES_CHILD_CWD=$es_gcwd
    # per-call extras of the git children (13-child.sh, es_git_env); GIT_DIR, GIT_WORK_TREE and the
    # other repository variables are not on the child allowlist, so git never sees them
    es_gceil=$ES_P_DIR
    es_ghome=${HOME:-}
    es_git_env
    es_git_list && es_git_includes
    ES_CHILD_CWD=; ES_CHILD_EXTRA=
  else
    es_partial "could not create an empty directory for git config"
  fi
  es_a git_config
  while IFS=$ES_TAB read -r es_go es_gkv; do
    [ -n "$es_gkv" ] || continue
    es_o -; es_s origin "$es_go"; es_s key "${es_gkv%%=*}"; es_v value "${es_gkv%%=*}" "${es_gkv#*=}"; es_oe
  done <"$ES_TMP/gitconfig.txt"
  es_ae
  awk -F '\t' '{ print "git:" $1 "\t" $2 }' "$ES_TMP/gitconfig.txt" >"$ES_P_DIR/git_lines.txt" 2>/dev/null
  # endpoints in git config: the URL subsection of url.<base>.insteadOf, http.<url>.*, lfs.<url>.*
  # and URL values; credential.<url>.* only says where the user signs in and is not a package source
  awk -F '\t' '{
      k = $2; sub(/=.*/, "", k); v = substr($2, length(k) + 2)
      sec = tolower(k); sub(/\..*/, "", sec)
      if (sec == "credential") next
      rest = substr(k, length(sec) + 2); sb = ""
      if (index(rest, ".") > 0) { sb = rest; sub(/\.[^.]*$/, "", sb) }
      print "git:" $1 "\t" sb " " v
    }' "$ES_TMP/gitconfig.txt" >"$ES_P_DIR/git_urls.txt" 2>/dev/null
}
