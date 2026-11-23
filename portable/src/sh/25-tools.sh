# ============================================================== probes: tools.inventory, runtime.*, native.deps

# es_binarch: read "# TAB path" headers followed by od -An -tx1 output; print "path TAB arch"
es_binarch() {
  awk 'BEGIN { for (i = 0; i < 256; i++) H[sprintf("%02x", i)] = i }
    $1 == "#" || $0 == "#END" {
      if (cur != "") {
        a = "unknown"
        if (nb >= 20 && B[0] == "7f" && B[1] == "45" && B[2] == "4c" && B[3] == "46") {
          le = (B[5] == "01"); m = le ? H[B[18]] + 256 * H[B[19]] : 256 * H[B[18]] + H[B[19]]
          if (m == 62) a = "x86_64"; else if (m == 3) a = "x86"; else if (m == 183) a = "arm64"; else if (m == 40) a = "arm"
          else if (m == 21) a = (le ? "ppc64le" : "ppc64"); else if (m == 20) a = "ppc"; else if (m == 22) a = "s390x"
          else if (m == 243) a = (B[4] == "02" ? "riscv64" : "riscv32"); else if (m == 43) a = "sparc64"; else if (m == 2) a = "sparc"
          else if (m == 50) a = "ia64"; else if (m == 8) a = "mips"; else a = "elf-" m
        } else if (nb >= 8 && (B[0] == "cf" || B[0] == "ce") && B[1] == "fa" && B[2] == "ed" && B[3] == "fe") {
          c = H[B[4]] + 256 * H[B[5]] + 65536 * H[B[6]] + 16777216 * H[B[7]]
          if (c == 16777223) a = "x86_64"; else if (c == 16777228) a = "arm64"; else if (c == 7) a = "x86"; else if (c == 12) a = "arm"; else a = "macho-" c
        } else if (nb >= 8 && B[0] == "ca" && B[1] == "fe" && B[2] == "ba" && B[3] == "be") {
          nf = 16777216 * H[B[4]] + 65536 * H[B[5]] + 256 * H[B[6]] + H[B[7]]
          if (nf > 0 && nf < 8) {
            l = ""
            for (k = 0; k < nf; k++) {
              o = 8 + 20 * k; if (o + 3 >= nb) break
              c = 16777216 * H[B[o]] + 65536 * H[B[o + 1]] + 256 * H[B[o + 2]] + H[B[o + 3]]
              t = (c == 16777223) ? "x86_64" : (c == 16777228) ? "arm64" : (c == 7) ? "x86" : (c == 12) ? "arm" : "other"
              l = l (l == "" ? "" : ",") t
            }
            a = "universal(" l ")"
          } else a = "java-class"
        } else if (nb >= 64 && B[0] == "4d" && B[1] == "5a") {
          e = H[B[60]] + 256 * H[B[61]] + 65536 * H[B[62]]
          if (e + 6 < nb && B[e] == "50" && B[e + 1] == "45" && B[e + 2] == "00" && B[e + 3] == "00") {
            m = H[B[e + 4]] + 256 * H[B[e + 5]]
            if (m == 34404) a = "x86_64"; else if (m == 332) a = "x86"; else if (m == 43620) a = "arm64"; else if (m == 452) a = "arm"; else a = "pe-" m
          } else a = "pe"
        } else if (nb >= 2 && B[0] == "23" && B[1] == "21") a = "script"
        print cur "\t" a
      }
      cur = substr($0, 3); nb = 0; next
    }
    { for (i = 1; i <= NF; i++) B[nb++] = $i }'
}

# es_versions FILE...: "file TAB version TAB line TAB status" for command outputs. The JVM's
# "Picked up JAVA_TOOL_OPTIONS: ..." banners are skipped (their option values are not versions).
# Status "loader" marks a program that could not start (dynamic loader error, wrong binary
# format): its version is "-" and the line is the error; otherwise the status is "-".
es_versions() {
  awk '
    { sub(/\r$/, ""); gsub(/\t/, " ") }
    /^(NOTE: )?Picked up [ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_]+:/ { next }
    !(FILENAME in E) && FNR <= 10 {
      l = tolower($0)
      if (index(l, "error while loading shared libraries") || (index(l, "version `") && index(l, "not found")) ||
          index(l, "not found (required by") || index(l, "error loading shared library") || index(l, "error relocating") ||
          index(l, "library not loaded") || index(l, "exec format error") || index(l, "cannot execute binary file")) E[FILENAME] = $0
    }
    !(FILENAME in L) && NF { L[FILENAME] = $0 }
    !(FILENAME in V) && FNR <= 10 && match($0, /[0-9]+(\.[0-9]+)+/) { V[FILENAME] = substr($0, RSTART, RLENGTH); VL[FILENAME] = $0 }
    END {
      for (f in L) {
        if (f in E) print f "\t-\t" E[f] "\tloader"
        else print f "\t" ((f in V) ? V[f] : "-") "\t" ((f in VL) ? VL[f] : L[f]) "\t-"
      } }' "$@" 2>/dev/null
}

# es_os_tool_dirs -> ES_OS_TOOL_DIRS: install directories of this OS, searched for every tool in
# addition to its spec dirs (| separated patterns). Tier 2, unverified: the locations are from
# IBM's and the zopen community's documentation.
es_os_tool_dirs() {
  case $ES_OS in
    zos) ES_OS_TOOL_DIRS='/usr/lpp/java/*/bin|/usr/lpp/IBM/cyp/*/bin|/usr/lpp/IBM/cnj/*/bin|/usr/lpp/IBM/zoautil/bin|/usr/local/zopen/*/bin|/usr/local/zopen/usr/local/bin|/usr/local/bin' ;;
    os400) ES_OS_TOOL_DIRS='/QOpenSys/pkgs/bin|/QOpenSys/usr/bin|/QOpenSys/QIBM/ProdData/JavaVM/*/*/bin|/QOpenSys/QIBM/ProdData/JavaVM/*/*/jre/bin|/QOpenSys/pkgs/lib/jvm/*/bin' ;;
    *) ES_OS_TOOL_DIRS= ;;
  esac
}

probe_tools_inventory() {
  es_os_tool_dirs
  es_src "test PATH directories and the known install directories in spec/tools.toml"
  es_src "read the first 512 bytes of each found executable (ELF/Mach-O/PE machine type)"
  mkdir -p "$ES_P_DIR/t"
  : >"$ES_P_DIR/inv.tsv"
  es_ti=0; es_tmo=
  while IFS=$ES_TAB read -r es_id es_name es_cat es_mode es_tos es_exe es_args es_dirs; do
    case $es_tos in
      all|unix) ;;
      linux|darwin) [ "$ES_OS" = "$es_tos" ] || continue ;;
      *) continue ;;
    esac
    es_paths=; es_onp=false
    es_r1=$es_exe
    while [ -n "$es_r1" ]; do
      es_x=${es_r1%%|*}; case $es_r1 in *'|'*) es_r1=${es_r1#*|} ;; *) es_r1= ;; esac
      if es_which_all "$es_x"; then es_paths="$es_paths$ES_WA"; es_onp=true; fi
    done
    if [ -n "$ES_OS_TOOL_DIRS" ]; then
      if [ "$es_dirs" = - ]; then es_dirs=$ES_OS_TOOL_DIRS; else es_dirs="$es_dirs|$ES_OS_TOOL_DIRS"; fi
    fi
    if [ "$es_dirs" != - ]; then
      es_r2=$es_dirs
      while [ -n "$es_r2" ]; do
        es_dp=${es_r2%%|*}; case $es_r2 in *'|'*) es_r2=${es_r2#*|} ;; *) es_r2= ;; esac
        es_expand "$es_dp" || continue
        es_r3=$ES_X
        while [ -n "$es_r3" ]; do
          es_d=${es_r3%%"$ES_NL"*}; es_r3=${es_r3#*"$ES_NL"}
          es_r1=$es_exe
          while [ -n "$es_r1" ]; do
            es_x=${es_r1%%|*}; case $es_r1 in *'|'*) es_r1=${es_r1#*|} ;; *) es_r1= ;; esac
            if es_exec_file "$es_d/$es_x"; then
              case "$ES_NL$es_paths" in *"$ES_NL$es_d/$es_x$ES_NL"*) ;; *) es_paths="$es_paths$es_d/$es_x$ES_NL" ;; esac
            fi
          done
        done
      done
    fi
    if [ -z "$es_paths" ]; then
      printf '%s\t%s\t%s\tfalse\t-\t-\tfalse\tfalse\t-\t-\t-\n' "$es_id" "$es_name" "$es_cat" >>"$ES_P_DIR/inv.tsv"
      continue
    fi
    es_path=${es_paths%%"$ES_NL"*}
    es_plist=; es_r3=$es_paths
    while [ -n "$es_r3" ]; do es_plist="$es_plist${es_plist:+|}${es_r3%%"$ES_NL"*}"; es_r3=${es_r3#*"$ES_NL"}; done
    es_realpath "$es_path"; es_real=$ES_RP
    es_ran=false; es_why=-; es_outf=-
    if [ "$es_mode" = presence ]; then
      es_why='presence only (not executed)'
    elif ! es_runnable "$es_path" "$es_id"; then
      es_why=$ES_WHY
    else
      es_ti=$((es_ti + 1)); es_outf="$ES_P_DIR/t/$es_ti.out"
      if [ "$es_args" = - ]; then set --; else set -f; set -- $es_args; set +f; fi
      es_src "run $es_path $*"
      es_exec "$ES_TIMEOUT" "$es_outf" - "$es_path" "$@"
      es_ran=true
      if [ "$ES_TIMED_OUT" = 1 ]; then es_why="timed out after ${ES_TIMEOUT}s"; es_tmo="$es_tmo $es_id"; fi
    fi
    printf '%s\t%s\t%s\ttrue\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$es_id" "$es_name" "$es_cat" "$es_path" "$es_plist" \
      "$es_onp" "$es_ran" "$es_why" "$es_outf" "$es_real" >>"$ES_P_DIR/inv.tsv"
  done <"$ES_TMP/tools.spec"
  es_versions "$ES_P_DIR"/t/*.out >"$ES_P_DIR/versions.tsv"
  {
    while IFS=$ES_TAB read -r es_id es_n es_c es_found es_path es_pl es_onp es_ran es_why es_outf es_real; do
      [ "$es_found" = true ] || continue
      printf '#\t%s\n' "$es_path"
      od -v -An -tx1 -N 512 "$es_real" 2>/dev/null
    done <"$ES_P_DIR/inv.tsv"
    printf '#END\n'
  } | es_binarch >"$ES_P_DIR/arch.tsv"
  awk -F '\t' -v vf="$ES_P_DIR/versions.tsv" -v af="$ES_P_DIR/arch.tsv" -v tf="$ES_TMP/tools.tsv" '
    BEGIN {
      while ((getline l < vf) > 0) { split(l, A, "\t"); V[A[1]] = A[2]; VL[A[1]] = A[3]; if (A[4] == "loader") LD[A[1]] = 1 }
      while ((getline l < af) > 0) { k = index(l, "\t"); AR[substr(l, 1, k - 1)] = substr(l, k + 1) }
      print "{\ttools"; printf "" > tf
    }
    {
      printf "{\t%s\ns\tname\t%s\ns\tcat\t%s\nb\tfound\t%s\n", $1, $2, $3, $4
      if ($4 == "true") {
        printf "s\tpath\t%s\n[\tpaths\n", $5
        n = split($6, P, "|"); for (i = 1; i <= n; i++) if (P[i] != "") printf "s\t-\t%s\n", P[i]
        printf "]\nb\ton_path\t%s\n", $7
        v = ($10 in V) ? V[$10] : "-"; vl = ($10 in VL) ? VL[$10] : ""
        # a loader error (missing library, GLIBCXX version) is reported as such, never as a version
        why = ($10 in LD) ? "fails to run: the program could not start (see version_line)" : $9
        if (v != "-") printf "s\tversion\t%s\n", v; else print "z\tversion"
        if (vl != "") printf "s\tversion_line\t%s\n", substr(vl, 1, 200); else print "z\tversion_line"
        printf "b\texecuted\t%s\n", $8
        if (why != "-") printf "s\treason\t%s\n", why; else print "z\treason"
        a = ($5 in AR) ? AR[$5] : ""
        if (a != "") printf "s\tbinary_arch\t%s\n", a; else print "z\tbinary_arch"
        print $1 "\t" $2 "\t" $3 "\t" (v == "-" ? "" : v) "\t" $5 "\t" $8 "\t" (why == "-" ? "" : why) "\t" a > tf
        found++
      } else print "z\tpath\n[\tpaths\n]\nb\ton_path\tfalse\nz\tversion\nz\tversion_line\nb\texecuted\tfalse\nz\treason\nz\tbinary_arch"
      print "}"
    }
    END { print "}"; printf "n\tfound_count\t%d\n", found }' "$ES_P_DIR/inv.tsv" >&5
  [ -n "$es_tmo" ] && es_partial "version command timed out:$es_tmo"
  es_fact tools_found "$(awk -F '\t' 'END { print NR }' "$ES_TMP/tools.tsv")"
  es_fact shims_skipped "$(awk -F '\t' '$7 ~ /shim/ { n++ } END { print n + 0 }' "$ES_TMP/tools.tsv")"
  es_fact arch_mismatch "$(awk -F '\t' -v os="${ES_F_os_arch:-$ES_ARCH}" '
    $3 == "runtime" && $8 ~ /^(x86_64|x86|arm64|arm|ppc64le|ppc64|s390x|riscv64)$/ && $8 != os { printf "%s%s=%s", (n++ ? ", " : ""), $1, $8 }' "$ES_TMP/tools.tsv")"
}

# es_tail_components PATTERN PATH -> ES_T: the last N components of PATH, N = components of PATTERN with *
es_tail_components() {
  es_tn=0; es_tr=$1
  while [ -n "$es_tr" ]; do
    es_tc=${es_tr%%/*}; case $es_tr in */*) es_tr=${es_tr#*/} ;; *) es_tr= ;; esac
    case $es_tc in *'*'*) es_tn=$((es_tn + 1)) ;; esac
  done
  [ "$es_tn" -gt 0 ] || es_tn=1
  ES_T=; es_tp=${2%/}
  while [ "$es_tn" -gt 0 ]; do
    ES_T=${es_tp##*/}${ES_T:+/}$ES_T; es_tp=${es_tp%/*}; es_tn=$((es_tn - 1))
  done
}

probe_runtime_version_managers() {
  es_src "list the version directories in spec/tools.toml (no shim is executed)"
  es_src "PATH entries matching version-manager shim directories"
  es_a managers
  es_nm=0
  while IFS=$ES_TAB read -r es_vid es_vname es_vmark es_vreq es_vver; do
    es_shims=; es_r=$ES_SHIM_DIRS
    while [ -n "$es_r" ]; do
      es_l=${es_r%%"$ES_NL"*}; es_r=${es_r#*"$ES_NL"}
      [ "${es_l#*"$ES_TAB"}" = "$es_vid" ] && es_shims="$es_shims${es_l%%"$ES_TAB"*}$ES_NL"
    done
    es_vers=; es_r2=$es_vver
    while [ -n "$es_r2" ]; do
      es_vp=${es_r2%%|*}; case $es_r2 in *'|'*) es_r2=${es_r2#*|} ;; *) es_r2= ;; esac
      es_expand "$es_vp" || continue
      es_r3=$ES_X
      while [ -n "$es_r3" ]; do
        es_d=${es_r3%%"$ES_NL"*}; es_r3=${es_r3#*"$ES_NL"}
        [ -d "$es_d" ] || continue
        es_tail_components "$es_vp" "$es_d"
        case "$ES_NL$es_vers" in *"$ES_NL$ES_T$ES_NL"*) ;; *) es_vers="$es_vers$ES_T$ES_NL" ;; esac
      done
    done
    [ -n "$es_shims$es_vers" ] || continue
    es_o -; es_s id "$es_vid"; es_s name "$es_vname"; es_list shim_dirs "$es_shims"; es_list versions "$es_vers"; es_oe
    es_nm=$((es_nm + 1))
  done <"$ES_TMP/vmanagers.tsv"
  es_ae
  [ "$es_nm" -gt 0 ] || es_status not_found
  es_fact vmanagers "$es_nm"
}

# es_jdk_add HOME SOURCE: record a Java home once (by real path). HOME comes from JAVA_HOME,
# PATH, a glob or java_home: nothing on a network or autofs mount is tested (es_ltest)
es_jdk_add() {
  es_ltest -d "$1" || return 0
  es_ltest -x "$1/bin/java" || es_ltest -f "$1/release" || return 0
  es_realpath "$1"
  case "$ES_NL$es_jreal" in *"$ES_NL$ES_RP$ES_NL"*) return 0 ;; esac
  es_jreal="$es_jreal$ES_RP$ES_NL"
  printf '%s\t%s\n' "$1" "$2" >>"$ES_P_DIR/jdks.tsv"
}

# es_jdk_dirs: es_jdk_add for every directory in ES_X (es_expand, es_glob)
es_jdk_dirs() {
  es_jr=$ES_X
  while [ -n "$es_jr" ]; do
    es_g=${es_jr%%"$ES_NL"*}; es_jr=${es_jr#*"$ES_NL"}
    [ -d "$es_g" ] && es_jdk_add "$es_g" directory
  done
  return 0
}

# es_os_jdk_dirs -> ES_OS_JDK_DIRS: JDK directory patterns of this OS (| separated) (tier 2, unverified)
es_os_jdk_dirs() {
  case $ES_OS in
    zos) ES_OS_JDK_DIRS='/usr/lpp/java/*' ;;
    os400) ES_OS_JDK_DIRS='/QOpenSys/QIBM/ProdData/JavaVM/*/*bit|/QOpenSys/pkgs/lib/jvm/*' ;;
    *) ES_OS_JDK_DIRS= ;;
  esac
}

probe_runtime_java() {
  : >"$ES_P_DIR/jdks.tsv"
  es_jreal=
  es_jh=${JAVA_HOME:-}
  if [ -n "$es_jh" ]; then
    es_jhp=$es_jh
    [ "$ES_OS" = cygwin ] && es_winpath "$es_jh" && es_jhp=$ES_T
    es_jdk_add "$es_jhp" JAVA_HOME
  fi
  if es_which java && es_runnable "$ES_W" java; then
    es_jw=$ES_W
    es_realpath "$es_jw"
    es_jp=${ES_RP%/bin/java.exe}; es_jp=${es_jp%/bin/java}; es_jp=${es_jp%/jre}
    if [ "$es_jp" != "$ES_RP" ] && { es_ltest -f "$es_jp/release" || es_ltest -d "$es_jp/lib"; }; then
      es_jdk_add "$es_jp" PATH
    elif es_cmd_merged "$es_jw" -XshowSettings:properties -version; then
      # a launcher stub (Windows javapath, wrapper script): the JVM reports its own home
      es_jp=$(awk '/^[ \t]*java\.home = / { sub(/^[^=]*= /, ""); sub(/\r$/, ""); print; exit }' "$ES_OUT_F")
      es_winpath "$es_jp" && es_jp=$ES_T
      es_jp=${es_jp%/jre}
      [ -n "$es_jp" ] && es_jdk_add "$es_jp" PATH
    fi
  fi
  es_src "read <jdk>/release for JAVA_HOME, PATH java and the known JDK directories"
  es_pf=
  if [ "$ES_OS" = cygwin ] && es_winpath "${ProgramW6432:-${PROGRAMFILES:-C:\\Program Files}}"; then es_pf=$ES_T; fi
  # the known JDK directories through es_expand/es_glob: no glob below or into a network or
  # autofs mount, every result vetted before it is tested
  es_os_jdk_dirs
  es_jq=$ES_OS_JDK_DIRS
  while [ -n "$es_jq" ]; do
    es_jpat=${es_jq%%|*}; case $es_jq in *'|'*) es_jq=${es_jq#*|} ;; *) es_jq= ;; esac
    es_expand "$es_jpat" && es_jdk_dirs
  done
  for es_jpat in '/usr/lib/jvm/*' '/usr/java/*' '/opt/*jdk*' '/opt/java/*' \
      '/Library/Java/JavaVirtualMachines/*/Contents/Home' '~/Library/Java/JavaVirtualMachines/*/Contents/Home' \
      '~/.sdkman/candidates/java/*' '~/.jdks/*'; do
    es_expand "$es_jpat" && es_jdk_dirs
  done
  if [ -n "$es_pf" ]; then
    for es_jpat in 'Java/*' 'Eclipse Adoptium/*' 'Microsoft/jdk-*' 'Zulu/*' 'Amazon Corretto/*' 'BellSoft/*' \
        'Semeru/*' 'RedHat/*'; do
      es_glob "$es_pf/$es_jpat" && es_jdk_dirs
    done
  fi
  if [ "$ES_OS" = darwin ] && [ -x "$ES_ROOT/usr/libexec/java_home" ]; then
    es_cmd "$ES_ROOT/usr/libexec/java_home" -V
    cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
    es_raw java_home "$ES_OUT_F"
    awk '/\/.*Home/ { s = $0; sub(/^[^\/]*\//, "/", s); print s }' "$ES_OUT_F" >"$ES_P_DIR/jh.txt"
    while IFS= read -r es_g; do es_jdk_add "$es_g" java_home; done <"$ES_P_DIR/jh.txt"
  fi
  es_sn java_home "$es_jh"
  es_a jdks
  es_nj=0; es_vers=
  while IFS=$ES_TAB read -r es_g es_how; do
    es_ver=; es_vend=; es_arch=; es_rt=
    if es_ltest -r "$es_g/release"; then
      while IFS= read -r es_line || [ -n "$es_line" ]; do
        case $es_line in
          JAVA_VERSION=*) es_unquote "${es_line#*=}"; es_ver=$ES_T ;;
          IMPLEMENTOR=*) es_unquote "${es_line#*=}"; es_vend=$ES_T ;;
          OS_ARCH=*) es_unquote "${es_line#*=}"; es_arch=$ES_T ;;
          JAVA_RUNTIME_VERSION=*) es_unquote "${es_line#*=}"; es_rt=$ES_T ;;
        esac
      done <"$es_g/release"
    fi
    es_kind=jre; es_ltest -x "$es_g/bin/javac" && es_kind=jdk
    [ -n "$es_arch" ] && { es_norm_arch "$es_arch"; es_arch=$ES_A; }
    es_o -; es_s path "$es_g"; es_sn version "$es_ver"; es_sn runtime_version "$es_rt"; es_sn vendor "$es_vend"
    es_sn arch "$es_arch"; es_s kind "$es_kind"; es_s source "$es_how"; es_oe
    es_nj=$((es_nj + 1)); es_vers="$es_vers${es_ver:-unknown} ($es_kind)$ES_NL"
  done <"$ES_P_DIR/jdks.tsv"
  es_ae
  [ "$es_nj" -gt 0 ] || es_status not_found
  es_fact jdk_count "$es_nj"
  es_fact java_versions "$es_vers"
}

probe_runtime_dotnet() {
  es_dn=
  if es_which dotnet; then es_dn=$ES_W
  else
    for es_d in "${DOTNET_ROOT:-}" "$ES_ROOT/usr/share/dotnet" "$ES_ROOT/usr/lib/dotnet" "$ES_ROOT/usr/local/share/dotnet" "${HOME:+$HOME/.dotnet}" "$ES_ROOT/opt/dotnet"; do
      if [ -n "$es_d" ] && es_ltest -x "$es_d/dotnet"; then es_dn=$es_d/dotnet; break; fi
    done
  fi
  es_z framework
  if [ -z "$es_dn" ]; then
    es_list sdks ""; es_list runtimes ""
    es_status not_found
    return 0
  fi
  es_s dotnet "$es_dn"
  es_sdks=; es_rts=
  if es_runnable "$es_dn" dotnet; then
    if es_cmd "$es_dn" --list-sdks; then es_sdks=$(awk '{ print $1 }' "$ES_OUT_F"); fi
    if es_cmd "$es_dn" --list-runtimes; then es_rts=$(awk '{ print $1 " " $2 }' "$ES_OUT_F"); fi
  else
    es_note "$es_dn: $ES_WHY; versions read from the install directory"
    es_realpath "$es_dn"; es_root=${ES_RP%/*}
    es_src "list $es_root/sdk, $es_root/shared"
    if es_glob "$es_root/sdk/*"; then
      es_dr=$ES_X
      while [ -n "$es_dr" ]; do
        es_d=${es_dr%%"$ES_NL"*}; es_dr=${es_dr#*"$ES_NL"}
        [ -d "$es_d" ] && es_sdks="$es_sdks${es_d##*/}$ES_NL"
      done
    fi
    if es_glob "$es_root/shared/*/*"; then
      es_dr=$ES_X
      while [ -n "$es_dr" ]; do
        es_d=${es_dr%%"$ES_NL"*}; es_dr=${es_dr#*"$ES_NL"}
        [ -d "$es_d" ] && { es_p=${es_d%/*}; es_rts="$es_rts${es_p##*/} ${es_d##*/}$ES_NL"; }
      done
    fi
  fi
  es_list sdks "$es_sdks"
  es_list runtimes "$es_rts"
  es_fact dotnet_sdks "$es_sdks"
}

# es_python_cands -> ES_T: python3, python, python2 and python3.N in PATH, then the fixed
# locations, one per line. PATH entries and locations on network or autofs mounts are not
# listed (no glob, no existence check there), as in es_which.
es_python_cands() {
  es_pc=
  for es_n in python3 python python2; do
    es_which_all "$es_n" && es_pc="$es_pc$ES_WA"
  done
  es_pifs=$IFS; IFS=:; set -f
  set -- $PATH
  IFS=$es_pifs; set +f
  for es_d in "$@"; do
    case $es_d in /*) ;; *) continue ;; esac
    case "$ES_NL${ES_PATH_SKIP:-}" in *"$ES_NL$es_d$ES_NL"*) continue ;; esac
    for es_f in "$es_d"/python3.[0-9] "$es_d"/python3.[0-9][0-9]; do
      es_exec_file "$es_f" && es_pc="$es_pc$es_f$ES_NL"
    done
  done
  for es_f in "$ES_ROOT/usr/libexec/platform-python" "$ES_ROOT/usr/bin/python3" "$ES_ROOT/usr/local/bin/python3" "$ES_ROOT/opt/homebrew/bin/python3"; do
    es_local_path "$es_f" && [ -f "$es_f" ] && [ -x "$es_f" ] && es_pc="$es_pc$es_f$ES_NL"
  done
  ES_T=$es_pc
}

probe_runtime_python() {
  es_src "test PATH and known locations for python3/python"
  es_python_cands; es_cands=$ES_T
  es_a interpreters
  es_np=0; es_seen=; es_vers=
  es_r=$es_cands
  while [ -n "$es_r" ]; do
    es_p=${es_r%%"$ES_NL"*}; es_r=${es_r#*"$ES_NL"}
    es_realpath "$es_p"
    case "$ES_NL$es_seen" in *"$ES_NL$ES_RP$ES_NL"*) continue ;; esac
    es_seen="$es_seen$ES_RP$ES_NL"
    es_ver=; es_why=; es_store=false; es_preal=$ES_RP
    case $es_p in */[Mm]icrosoft/[Ww]indows[Aa]pps/*) es_store=true ;; esac
    if es_runnable "$es_p" python; then
      es_cmd_merged "$es_p" --version && es_read1 "$ES_OUT_F" && { es_version_of "$ES_L"; es_ver=$ES_T; }
    else
      es_why=$ES_WHY
    fi
    es_o -; es_s path "$es_p"; es_sn real_path "$es_preal"; es_sn version "$es_ver"; es_b store_alias "$es_store"; es_sn not_run_reason "$es_why"; es_oe
    es_np=$((es_np + 1)); es_vers="$es_vers${es_ver:-unknown}${es_why:+ (not run)}$ES_NL"
  done
  es_ae
  es_list launcher ""
  if [ "$es_np" = 0 ]; then
    es_status not_found
    es_fact python_found false
  else
    es_fact python_found true
  fi
  es_fact python_versions "$es_vers"
}

# es_font_count -> ES_FONTS: the number of fonts fc-list lists ("" when it failed); fc-list gets its
# cache folder in the scanner temp folder (XDG_CACHE_HOME, for that child only)
es_font_count() {
  ES_FONTS=
  es_fcache="$ES_TMP/fc-cache"
  ES_CHILD_EXTRA='XDG_CACHE_HOME=es_fcache'
  if es_tool fc-list; then ES_FONTS=$(awk 'END { print NR }' "$ES_OUT_F"); fi
  ES_CHILD_EXTRA=
}

probe_native_deps() {
  es_kind=; es_ver=
  if es_tool getconf GNU_LIBC_VERSION && es_read1 "$ES_OUT_F"; then
    set -f; set -- $ES_L; set +f
    es_kind=glibc; es_ver=${2:-}
  fi
  if [ -z "$es_kind" ]; then
    for es_f in "$ES_ROOT"/lib/ld-musl-*; do
      if [ -e "$es_f" ]; then es_src "list /lib/ld-musl-*"; es_kind=musl; break; fi
    done
  fi
  if [ "$es_kind" != glibc ] && es_which ldd && es_runnable "$ES_W" ldd; then
    es_cmd_merged "$ES_W" --version
    if grep -i musl "$ES_OUT_F" >/dev/null 2>&1; then
      es_kind=musl
      es_ver=$(awk '/^Version/ { print $2; exit }' "$ES_OUT_F")
    elif [ -z "$es_kind" ] && grep -i -E 'glibc|gnu libc' "$ES_OUT_F" >/dev/null 2>&1; then
      es_kind=glibc; es_read1 "$ES_OUT_F"; es_ver=${ES_L##* }
    fi
  fi
  case $ES_OS in
    darwin) es_kind=libSystem; es_ver=${ES_F_os_version:-} ;;
    aix) es_kind=aix-libc; es_ver=${ES_F_os_version:-} ;;
    sunos) es_kind=solaris-libc; es_ver=${ES_F_os_version:-} ;;
    zos) es_kind=zos-le; es_ver=${ES_F_os_version:-} ;;
    os400) es_kind=pase-libc; es_ver=${ES_F_os_version:-} ;;
    freebsd|openbsd|netbsd) es_kind=bsd-libc; es_ver=$ES_UNAME_R ;;
    cygwin) es_kind=cygwin; es_ver=${ES_UNAME_R%%\(*} ;;
  esac
  es_ldc=
  if es_which ldconfig; then es_ldc=$ES_W
  else
    for es_f in "$ES_ROOT/sbin/ldconfig" "$ES_ROOT/usr/sbin/ldconfig"; do [ -x "$es_f" ] && { es_ldc=$es_f; break; }; done
  fi
  : >"$ES_P_DIR/ldcache.txt"
  if [ -n "$es_ldc" ] && [ "$ES_OS" = linux ] && es_cmd "$es_ldc" -p; then cp "$ES_OUT_F" "$ES_P_DIR/ldcache.txt"; fi
  es_ssl=$(awk '$1 ~ /^libssl\.so/ { print $1 }' "$ES_P_DIR/ldcache.txt" | sort -u)
  es_cxx=$(awk '$1 == "libstdc++.so.6" { print $NF; exit }' "$ES_P_DIR/ldcache.txt")
  if [ -z "$es_ssl$es_cxx" ]; then
    es_src "list /lib*, /usr/lib*, /usr/local/lib for libssl and libstdc++"
    for es_f in "$ES_ROOT"/lib*/libssl.so.* "$ES_ROOT"/usr/lib*/libssl.so.* "$ES_ROOT"/usr/lib/*/libssl.so.* "$ES_ROOT"/usr/local/lib*/libssl.so.* \
        "$ES_ROOT"/lib*/libssl*.dylib "$ES_ROOT"/usr/local/opt/openssl*/lib/libssl*.dylib "$ES_ROOT"/opt/homebrew/opt/openssl*/lib/libssl*.dylib; do
      [ -e "$es_f" ] && es_ssl="$es_ssl${es_f##*/}$ES_NL"
    done
    for es_f in "$ES_ROOT"/usr/lib*/libstdc++.so.6 "$ES_ROOT"/usr/lib/*/libstdc++.so.6 "$ES_ROOT"/lib*/libstdc++.so.6 "$ES_ROOT"/lib/*/libstdc++.so.6; do
      if [ -e "$es_f" ]; then es_cxx=$es_f; break; fi
    done
  fi
  es_gx=
  if [ -n "$es_cxx" ] && [ -r "$es_cxx" ]; then
    es_src "read libstdc++.so.6 (GLIBCXX version strings)"
    es_gx=$(tr -c 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.' '\n' <"$es_cxx" 2>/dev/null | grep '^GLIBCXX_[0-9]' | sort -u | awk '
      { v = $0; sub(/^GLIBCXX_/, "", v); for (i = 1; i <= 4; i++) A[i] = 0; split(v, A, "."); better = 0
        for (i = 1; i <= 4; i++) { if (A[i] + 0 > B[i] + 0) { better = 1; break } if (A[i] + 0 < B[i] + 0) break }
        if (better || best == "") { best = v; for (i = 1; i <= 4; i++) B[i] = A[i] + 0 } }
      END { print best }')
  fi
  es_odbc=
  if [ -r "$ES_ROOT/etc/odbcinst.ini" ]; then
    es_src "read /etc/odbcinst.ini"
    es_odbc=$(awk '/^\[.*\]/ { s = $0; sub(/^\[/, "", s); sub(/\].*$/, "", s); if (s != "ODBC") print s }' "$ES_ROOT/etc/odbcinst.ini")
  fi
  es_font_count; es_fonts=$ES_FONTS
  es_o libc; es_sn kind "$es_kind"; es_sn version "$es_ver"; es_oe
  es_sn glibcxx_max "$es_gx"
  es_sn libstdcxx_path "$es_cxx"
  es_list libssl "$es_ssl"
  es_z vcredist; es_z ucrt; es_z webview2
  es_list odbc_drivers "$es_odbc"
  es_n fonts_count "$es_fonts"
  [ -n "$es_kind" ] || es_partial "C library could not be identified"
  es_fact libc_kind "$es_kind"
  es_fact libc_version "$es_ver"
  es_fact glibcxx_max "$es_gx"
}
