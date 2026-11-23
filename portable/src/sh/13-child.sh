# ============================================================== child environment
# Every external command run through es_exec gets ONLY (spec/child_env.toml):
#   1. the per-call extras of the probe (ES_CHILD_EXTRA: "NAME" passes the variable NAME, and
#      "NAME=SRC" passes NAME with the value of the scanner variable SRC, so a probe never changes
#      its own environment for a child: git's GIT_CEILING_DIRECTORIES and replacement HOME,
#      fc-list's XDG_CACHE_HOME), then
#   2. LC_ALL (C, or the user's own for ES_CHILD_LOCALE=user) and DOCKER_CONTEXT=default, then
#   3. the [child_env] overrides (generated es_child_env, names in ES_CHILD_SET), then
#   4. the scan-start variables of the [child_env_keep] allowlist (ES_CHILD_KEEP, es_child_keep_init),
#      each with its current value, vetted when it holds a path (es_child_vet, 13-childvet.sh).
# Everything else (proxy settings with user:password, tokens, LD_PRELOAD, NODE_OPTIONS, BASH_ENV,
# ENV, DOCKER_HOST, ...) stays out. The command is started through "env -i NAME=value ... CMD":
# values are passed as arguments, never evaluated, so quotes and line breaks in them are harmless.
# Known exposure: those arguments, the allowlisted values included (PATH, HOME, ...; never a
# token, which the allowlist keeps out), are visible in env's command line (ps) for the moment
# before env replaces itself with the command. Without $BASHPID the pid wrapper "$ES_SH -c" runs
# AFTER env -i, so it starts with the child environment too. Without an env command the child
# subshell unsets every other exported variable first. The scanner's own environment is never
# changed (all of this happens in the subshell that es_exec starts), and env.vars still reports
# the full, redacted environment.

# es_child_keep_init -> ES_CHILD_KEEP: the names of the current environment (awk ENVIRON) that
# children may see: valid shell names in ES_CHILD_KEEP_NAMES or starting with an
# ES_CHILD_KEEP_PREFIXES entry; LC_ALL is set per child. es_init runs it at the scan start.
# Test hook: with ENVSCAN_TEST_STUBS=1 the settings of the test stubs (ES_STUB_*) reach them too.
es_child_keep_init() {
  ES_CHILD_KEEP=$(awk -v names="$ES_CHILD_KEEP_NAMES" -v pre="$ES_CHILD_KEEP_PREFIXES" -v stubs="${ENVSCAN_TEST_STUBS:-}" 'BEGIN {
      np = split(pre, P, " ")
      for (k in ENVIRON) {
        if (k == "LC_ALL" || k !~ /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_]*$/) continue
        ok = index(names, " " k " ") > 0
        for (i = 1; !ok && i <= np; i++) if (index(k, P[i]) == 1) ok = 1
        if (stubs == "1" && index(k, "ES_STUB_") == 1) ok = 1
        if (ok) printf "%s ", k
      }
    }')
  ES_CHILD_KEEP_DONE=1
}

# es_env_bin_init -> ES_ENV_BIN: the env command (a system location first, then PATH); "" when
# there is none (es_child then unsets the other variables itself)
es_env_bin_init() {
  ES_ENV_BIN=
  for es_eb in /usr/bin/env /bin/env /QOpenSys/usr/bin/env; do
    if [ -f "$es_eb" ] && [ -x "$es_eb" ]; then ES_ENV_BIN=$es_eb; return 0; fi
  done
  es_which env && ES_ENV_BIN=$ES_W
  return 0
}

# es_shell_name NAME: NAME is a valid shell variable name ([A-Za-z_][A-Za-z0-9_]*)
es_shell_name() {
  case $1 in
    ''|[0123456789]*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_]*) return 1 ;;
  esac
  return 0
}

# es_child_ref NAME SRC: the child gets NAME with the value of SRC, when SRC is set and NAME was
# not given yet (the first entry wins) -> ES_CE_REFS, ES_CE_SEEN, ES_CE_MAP (" NAME=SRC ...")
es_child_ref() {
  es_shell_name "$1" && es_shell_name "$2" || return 0
  case $ES_CE_SEEN in *" $1 "*) return 0 ;; esac
  eval "es_cr_set=\${$2+x}"
  [ -n "$es_cr_set" ] || return 0
  ES_CE_SEEN="$ES_CE_SEEN$1 "; ES_CE_MAP="$ES_CE_MAP $1=$2"
  ES_CE_REFS="$ES_CE_REFS \"$1=\$$2\""
}

# es_child_refs -> ES_CE_REFS ( "NAME=$SRC" ...: references, evaluated by es_child; no value is
# ever part of the text), ES_CE_SEEN (" NAME ... "): every variable a child gets, in the order of
# the list at the top. Kept variables go through es_child_vet: unchanged, replaced (the reference
# names the vetted value ES_CVO_<NAME>) or left out.
es_child_refs() {
  ES_CE_REFS=; ES_CE_SEEN=' '; ES_CE_MAP=
  set -f
  for es_cr_n in ${ES_CHILD_EXTRA:-} LC_ALL DOCKER_CONTEXT $ES_CHILD_SET; do
    case $es_cr_n in *=*) es_child_ref "${es_cr_n%%=*}" "${es_cr_n#*=}" ;; *) es_child_ref "$es_cr_n" "$es_cr_n" ;; esac
  done
  for es_cr_n in ${ES_CHILD_KEEP:-}; do
    es_shell_name "$es_cr_n" || continue
    case $ES_CE_SEEN in *" $es_cr_n "*) continue ;; esac
    eval "es_cr_set=\${$es_cr_n+x}"
    [ -n "$es_cr_set" ] || continue
    es_child_vet "$es_cr_n"
    case $ES_CVA in
      k) es_child_ref "$es_cr_n" "$es_cr_n" ;;
      r) es_child_ref "$es_cr_n" "ES_CVO_$es_cr_n" ;;
    esac
  done
  set +f
}

# es_child_unset: without an env command, every exported variable not in ES_CE_SEEN is unset in
# the child subshell ("command" keeps a read-only variable from ending the subshell), and every
# variable in it gets the value its reference names. A name that is not a valid shell name cannot
# be removed this way.
es_child_unset() {
  for es_cu_a in $ES_CE_MAP; do eval "es_cu_v_${es_cu_a%%=*}=\${${es_cu_a#*=}}"; done
  es_cu_l=$(awk 'BEGIN { for (k in ENVIRON) if (k ~ /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_]*$/) print k }')
  set -f
  for es_cu_n in $es_cu_l; do
    case $ES_CE_SEEN in *" $es_cu_n "*) continue ;; esac
    command unset "$es_cu_n" 2>/dev/null
  done
  set +f
  for es_cu_n in $ES_CE_SEEN; do eval "$es_cu_n=\$es_cu_v_$es_cu_n"; export "$es_cu_n"; done
}

es_restore_locale() {
  if [ -n "$ES_ORIG_LC_ALL_SET" ]; then LC_ALL=$ES_ORIG_LC_ALL; export LC_ALL; else unset LC_ALL; fi
}

# es_child_settings: the child's own settings, in the child subshell: [child_env] overrides,
# DOCKER_CONTEXT (a docker context from config.json could point at a remote engine) and LC_ALL.
# Children run under LC_ALL=C, because their output is parsed (a German id prints "Gruppen="); a
# probe that reports the user's locale itself sets ES_CHILD_LOCALE=user.
es_child_settings() {
  es_child_env
  DOCKER_CONTEXT=default; export DOCKER_CONTEXT
  if [ "${ES_CHILD_LOCALE:-}" = user ]; then es_restore_locale; else LC_ALL=C; export LC_ALL; fi
  [ -n "${ES_CHILD_KEEP_DONE:-}" ] || es_child_keep_init
  [ -n "${ES_ENV_BIN+x}" ] || es_env_bin_init
  es_child_refs
}

# es_child PIDFILE CMD ARGS...: body of every external command (always run in a subshell that
# it replaces); the pid of the command is written to PIDFILE for the watchdog. The command gets
# the child environment described at the top of this module; the pid wrapper "$ES_SH -c" (no
# $BASHPID) starts after env -i or after es_child_unset, never with the scanner's environment.
es_child() {
  exec 3<&- 4>&- 5>&-
  IFS=" $ES_TAB$ES_NL"
  if [ -n "${ES_CHILD_CWD:-}" ] && [ -d "$ES_CHILD_CWD" ]; then cd "$ES_CHILD_CWD" 2>/dev/null || cd / 2>/dev/null
  else cd / 2>/dev/null
  fi
  es_cpf=$1; shift
  es_child_settings
  if [ "$ES_OWNPID" != bash ]; then
    set -- "$ES_SH" -c 'echo "$$" >"$1"; shift; exec "$@"' sh "$es_cpf" "$@"
  else
    printf '%s\n' "$BASHPID" >"$es_cpf"
  fi
  # a command whose name holds "=" would be read by env as one more variable
  case $1 in
    *=*) es_child_unset ;;
    *) if [ -n "$ES_ENV_BIN" ]; then eval "set -- \"\$ES_ENV_BIN\" -i $ES_CE_REFS \"\$@\""; else es_child_unset; fi ;;
  esac
  exec "$@"
}
