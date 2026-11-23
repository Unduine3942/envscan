# ============================================================== execution policy
# What the scanner may execute: never version-manager shims, aliases, network-mount binaries,
# remote container engines or binaries in world-writable directories.

# es_normdir PATH -> ES_ND: PATH with repeated "/" collapsed and trailing "/" removed (text
# only). Like the rest of the execution policy it leaves ES_T alone: es_tool and es_runnable
# run between a helper that returns ES_T and the use of that value.
es_normdir() {
  ES_ND=$1
  while :; do case $ES_ND in *//*) ES_ND="${ES_ND%%//*}/${ES_ND#*//}" ;; *) break ;; esac; done
  while :; do case $ES_ND in ?*/) ES_ND=${ES_ND%/} ;; *) break ;; esac; done
}

# es_shim_of DIR -> ES_SHIM (manager id, "" when none), ES_SD (DIR normalised): DIR is a shim
# directory when its lower-cased path contains a marker of a version manager (spec/tools.toml)
# and, when the manager names a required executable, that executable is in DIR (the rule of the
# ps1's Get-EsShimManager). Decided by the directory alone, however a file in it was found;
# results are remembered per directory.
es_shim_of() {
  es_normdir "$1"; ES_SD=$ES_ND; ES_SHIM=
  case "$ES_NL${ES_SHIM_SEEN:-}" in
    *"$ES_NL$ES_SD$ES_TAB"*)
      es_sx="$ES_NL$ES_SHIM_SEEN"; es_sx=${es_sx#*"$ES_NL$ES_SD$ES_TAB"}; ES_SHIM=${es_sx%%"$ES_NL"*}
      return 0 ;;
  esac
  es_slc=$ES_SD
  case $es_slc in *[ABCDEFGHIJKLMNOPQRSTUVWXYZ]*) es_slc=$(printf '%s' "$es_slc" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz') ;; esac
  es_sr=${ES_VM_MARKERS:-}
  while [ -n "$es_sr" ]; do
    es_sm=${es_sr%%"$ES_NL"*}; es_sr=${es_sr#*"$ES_NL"}
    es_sk=${es_sm%%"$ES_TAB"*}
    case $es_slc in *"$es_sk"*) ;; *) continue ;; esac
    es_sm=${es_sm#*"$ES_TAB"}; es_sq=${es_sm#*"$ES_TAB"}
    if [ "$es_sq" != - ] && ! es_ltest -x "$ES_SD/$es_sq" && ! es_ltest -x "$ES_SD/$es_sq.exe"; then continue; fi
    ES_SHIM=${es_sm%%"$ES_TAB"*}; break
  done
  ES_SHIM_SEEN="${ES_SHIM_SEEN:-}$ES_SD$ES_TAB$ES_SHIM$ES_NL"
  return 0
}

# es_runnable PATH [TOOL-ID] -> fails with ES_WHY when the scanner must not execute PATH
es_runnable() {
  ES_WHY=
  if ! es_local_path "$1"; then
    ES_WHY='on a network or autofs mount (not executed)'
    [ -n "$ES_CREDLINK" ] && ES_WHY='link to a credential store (not executed)'
    return 1
  fi
  es_shim_of "${1%/*}"
  if [ -n "$ES_SHIM" ]; then ES_WHY="version-manager shim ($ES_SHIM, not executed)"; return 1; fi
  case $1 in
    /mnt/[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]/*) [ "$ES_F_wsl" = true ] && { ES_WHY='Windows binary under /mnt (WSL interop, not executed)'; return 1; } ;;
    *.ps1) ES_WHY='PowerShell shim (not executed)'; return 1 ;;
    */[Mm]icrosoft/[Ww]indows[Aa]pps/*) ES_WHY='Windows app execution alias (not executed; may open the Microsoft Store)'; return 1 ;;
  esac
  if [ -h "$1" ]; then
    es_realpath "$1"
    case $ES_RP in */corepack/*) ES_WHY='corepack shim (may download, not executed)'; return 1 ;; esac
    es_shim_of "${ES_RP%/*}"
    if [ -n "$ES_SHIM" ]; then ES_WHY="link to a version-manager shim ($ES_SHIM, not executed)"; return 1; fi
  fi
  es_runnable_os "$1" "${2:-${1##*/}}" || return 1
  es_runnable_dir "$1"
}

# es_runnable_os PATH TOOL-ID: macOS developer and Java stubs, remote container engines
es_runnable_os() {
  if [ "$ES_OS" = darwin ]; then
    case $1 in
      "$ES_ROOT"/usr/bin/*)
        es_rb=${1##*/}
        case " $ES_MAC_DEV_SHIMS " in
          *" $es_rb "*) [ "$ES_CLT" = 1 ] || { ES_WHY='macOS developer-tools shim without developer tools (not executed)'; return 1; } ;;
        esac
        case " $ES_MAC_JAVA_SHIMS " in
          *" $es_rb "*) [ "$ES_MAC_JAVA" = 1 ] || { ES_WHY='macOS Java stub without a JDK (not executed)'; return 1; } ;;
        esac ;;
    esac
  fi
  case $2 in
    docker|docker.exe|docker-compose)
      case ${DOCKER_HOST:-} in
        tcp://*|ssh://*|http://*|https://*) ES_WHY='DOCKER_HOST points to a remote engine (not executed)'; return 1 ;;
      esac
      if [ -n "${DOCKER_CONTEXT:-}" ]; then ES_WHY='DOCKER_CONTEXT is set and may name a remote engine (not executed)'; return 1; fi ;;
    podman|podman.exe|podman-remote)
      if [ -n "${CONTAINER_HOST:-}${CONTAINER_CONNECTION:-}" ]; then
        ES_WHY='CONTAINER_HOST or CONTAINER_CONNECTION selects a remote podman engine (not executed)'; return 1
      fi ;;
  esac
  return 0
}

# es_runnable_dir PATH: a binary in a world-writable directory without the sticky bit could have
# been planted by anyone: inventory only (one ls per directory, remembered)
es_runnable_dir() {
  es_ww_d=${1%/*}
  case "$ES_NL${ES_WW_OK:-}" in *"$ES_NL$es_ww_d$ES_NL"*) return 0 ;; esac
  case "$ES_NL${ES_WW_BAD:-}" in
    *"$ES_NL$es_ww_d$ES_NL"*) ES_WHY='in a world-writable directory without the sticky bit (not executed)'; return 1 ;;
  esac
  es_ww_m=$(ls -ld "$es_ww_d" 2>/dev/null); es_ww_m=${es_ww_m%% *}
  case $es_ww_m in
    ????????w[!tT]*)
      ES_WW_BAD="${ES_WW_BAD:-}$es_ww_d$ES_NL"
      ES_WHY='in a world-writable directory without the sticky bit (not executed)'; return 1 ;;
  esac
  ES_WW_OK="${ES_WW_OK:-}$es_ww_d$ES_NL"
  return 0
}

ES_MAC_DEV_SHIMS='git make gcc g++ cc c++ cpp clang clang++ python3 pip3 swift swiftc lldb ld as ar nm strip ranlib lipo otool svn bison flex m4 gm4 gnumake gperf indent ctags xcrun xcodebuild llvm-gcc llvm-g++ unifdef'
ES_MAC_JAVA_SHIMS='java javac jar keytool javadoc jshell jarsigner'

# es_shim_init -> ES_VM_MARKERS ("marker TAB id TAB requires" lines, markers lower-case, from
# spec/tools.toml) for es_shim_of, and ES_SHIM_DIRS: the PATH entries that are version-manager
# shim directories ("dir TAB id" lines, normalised; for runtime.version_managers). PATH entries
# on network or autofs mounts are left out without being touched.
es_shim_init() {
  es_spec_vmanagers >"$ES_TMP/vmanagers.tsv"
  ES_VM_MARKERS=$(awk -F '\t' -v OFS='\t' '$3 != "-" { m = split($3, M, "|")
      for (j = 1; j <= m; j++) if (M[j] != "") print tolower(M[j]), $1, ($4 == "" ? "-" : $4) }' "$ES_TMP/vmanagers.tsv")
  [ -n "$ES_VM_MARKERS" ] && ES_VM_MARKERS="$ES_VM_MARKERS$ES_NL"
  ES_SHIM_SEEN=; ES_SHIM_DIRS=
  es_si_ifs=$IFS; IFS=:; set -f
  for es_si_d in $PATH; do
    case $es_si_d in /*) ;; *) continue ;; esac
    case "$ES_NL${ES_PATH_SKIP:-}" in *"$ES_NL$es_si_d$ES_NL"*) continue ;; esac
    es_shim_of "$es_si_d"
    [ -n "$ES_SHIM" ] || continue
    case "$ES_NL$ES_SHIM_DIRS" in *"$ES_NL$ES_SD$ES_TAB"*) continue ;; esac
    ES_SHIM_DIRS="$ES_SHIM_DIRS$ES_SD$ES_TAB$ES_SHIM$ES_NL"
  done
  IFS=$es_si_ifs; set +f
  return 0
}

# ============================================================== read policy
# es_cred_path PATH: PATH (a path or a glob pattern) names a credential store, which the
# scanner never opens, lists or tests for existence (docs/DEVELOPING.md rule 4): the folders,
# files, history suffixes and key extensions of spec/policy.toml, plus the CA exemption below.
# Text only. The generated matchers (es_cred_folder_hit, es_cred_file_hit, es_cred_key_ext) ignore
# case themselves, because macOS disks do (~/.SSH is ~/.ssh). A path with a trailing dot or space
# on a component is also tried with those removed, for parity with Windows (".ssh." opens .ssh);
# awk runs only for such a path (no process per path on macOS /Users).
# The path is also tried in its normalised spelling (es_cred_norm: repeated "/", "." and ".."
# folded, trailing "/" removed), so ~/.config//gcloud/x, ~/.config/./gcloud/x and "id_rsa/" are
# stores too; a glob pattern is tried as written and normalised.
# Under Cygwin/MSYS (ES_OS=cygwin) a path with a component that holds "~<digit>" (an 8.3 short
# name such as GIT-CR~1) or ":" (an NTFS stream such as .ssh::$DATA; a leading drive letter "C:"
# is fine) is refused as a store: such a spelling can reach a store whose name we cannot match.
# Mirrored by Test-EsCredentialPath in src/ps/11-exec.ps1, from the same spec data.
es_cred_path() {
  if [ "${ES_OS:-}" = cygwin ] && es_cred_winrisk "$1"; then return 0; fi
  es_cred_match "$1" && return 0
  es_cpn=$1
  case $1 in
    *//*|*/./*|*/.|*/../*|*/..|*/|./*|../*|*"\\"*) es_cred_norm "$1"; es_cpn=$ES_CN2; es_cred_match "$es_cpn" && return 0 ;;
  esac
  case $es_cpn in *[.\ ]/*|*[.\ ]) ;; *) return 1 ;; esac
  es_crp=$(printf '%s\n' "$es_cpn" | awk '{ n = split($0, C, "/"); s = ""
    for (i = 1; i <= n; i++) { c = C[i]; if (c !~ /^[.]+$/) sub(/[. ]+$/, "", c); s = s (i > 1 ? "/" : "") c }
    print s }')
  es_cred_match "$es_crp"
}

# es_cred_norm PATH -> ES_CN2: PATH without empty and "." components, ".." folded into the
# component before it (dropped at the root), no trailing "/"; "\" is a separator under
# Cygwin/MSYS. Text only, no file system access, no fork.
es_cred_norm() {
  es_cn_sep=/; [ "${ES_OS:-}" = cygwin ] && es_cn_sep='/\'
  es_cn_abs=; es_cn_out=
  case $1 in /*) es_cn_abs=/ ;; \\*) [ "$es_cn_sep" = / ] || es_cn_abs=/ ;; esac
  es_cn_ifs=$IFS; IFS=$es_cn_sep; set -f
  for es_cn_c in $1; do
    case $es_cn_c in
      ''|.) ;;
      ..) case $es_cn_out in
            '') [ -n "$es_cn_abs" ] || es_cn_out=.. ;;
            ..|*/..) es_cn_out=$es_cn_out/.. ;;
            */*) es_cn_out=${es_cn_out%/*} ;;
            *) es_cn_out= ;;
          esac ;;
      *) es_cn_out=${es_cn_out:+$es_cn_out/}$es_cn_c ;;
    esac
  done
  set +f; IFS=$es_cn_ifs
  ES_CN2=$es_cn_abs$es_cn_out
  [ -n "$ES_CN2" ] || ES_CN2=${es_cn_abs:-.}
}

# es_cred_winrisk PATH: (Cygwin/MSYS) a component with "~<digit>" or ":" (not a leading drive letter)
es_cred_winrisk() {
  es_wr_first=1
  es_wr_ifs=$IFS; IFS='/\'; set -f
  for es_wr_c in $1; do
    if [ -n "$es_wr_first" ]; then
      es_wr_first=
      case $es_wr_c in ?:) continue ;; esac
    fi
    case $es_wr_c in
      *~[0-9]*|*:*) set +f; IFS=$es_wr_ifs; return 0 ;;
    esac
  done
  set +f; IFS=$es_wr_ifs
  return 1
}

# es_cred_match PATH: the policy tests on one spelling of the path
es_cred_match() {
  es_cred_folder_hit "$1" && return 0
  es_cred_file_hit "$1" && return 0
  es_cred_key_ext "$1" && { es_ca_path "$1" || return 0; }
  return 1
}

# es_ca_path PATH: PATH is a CA bundle (ES_CA_BUNDLES, also below a fake root), a file in an
# anchor directory (ES_CA_ANCHOR_DIRS) or a system CA store, or a Java cacerts file: the
# certificates tls.trust and tls.java_cacerts read on purpose (no private keys there)
# Narrow on purpose: a private-key name (key, priv, secret in the file name) is never exempt, and
# only the exact trust-store leaf names of spec policy.toml (es_trust_store_leaf, such as cert.pem)
# or certificate files in the system CA directories are. cacerts.p12, cacerts.key and the like
# are stores.
es_ca_path() {
  es_cal=${1##*/}
  case $es_cal in *[Kk][Ee][Yy]*|*[Pp][Rr][Ii][Vv]*|*[Ss][Ee][Cc][Rr][Ee][Tt]*) return 1 ;; esac
  es_trust_store_leaf "$es_cal" && return 0
  case /$1 in
    *.pem)
      case /$1 in */ssl/certs/*|*/tls/certs/*|*/ca-certificates/*|*/ca-trust/*|*/trust-source/*|*/pki/trust/*) return 0 ;; esac
      # the lists are space separated; callers may have IFS set to a newline (es_glob)
      es_cab=" ${ES_CA_BUNDLES:-} "
      while :; do
        es_cab=${es_cab#" "}; [ -n "$es_cab" ] || break
        es_caw=${es_cab%% *}
        [ -n "$es_caw" ] && case /$1 in *"$es_caw") return 0 ;; esac
        es_cab=${es_cab#* }
      done
      es_cab=" ${ES_CA_ANCHOR_DIRS:-} "
      while :; do
        es_cab=${es_cab#" "}; [ -n "$es_cab" ] || break
        es_caw=${es_cab%% *}
        [ -n "$es_caw" ] && case /$1 in *"$es_caw"/*) return 0 ;; esac
        es_cab=${es_cab#* }
      done ;;
  esac
  return 1
}
