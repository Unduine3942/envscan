# ============================================================== probes: os.*, hw.*

probe_os_identity() {
  es_src "run uname -s -n -r -m (at scan start)"
  es_uv=; es_up=
  es_tool uname -v && es_read1 "$ES_OUT_F" && es_uv=$ES_L
  if [ "${ES_EBCDIC:-0}" = 1 ] && [ "${ES_EBCDIC_1047:-0}" != 1 ]; then
    es_note "this EBCDIC code page is not IBM-1047: characters outside printable ASCII show as U+FFFD in envscan.json and ? in envscan.md, and the report files are not converted (host code page)"
  fi
  [ "$ES_OS" = zos ] || { es_tool uname -p && es_read1 "$ES_OUT_F" && es_up=$ES_L; }
  [ "$es_up" = unknown ] && es_up=
  es_name=; es_pretty=; es_vid=; es_ver=; es_did=; es_like=; es_build=; es_variant=
  es_osr=
  for es_f in "$ES_ROOT/etc/os-release" "$ES_ROOT/usr/lib/os-release"; do
    if [ -r "$es_f" ]; then es_osr=$es_f; break; fi
  done
  if [ -n "$es_osr" ]; then
    es_src "read ${es_osr#"$ES_ROOT"}"
    while IFS= read -r es_line || [ -n "$es_line" ]; do
      case $es_line in
        NAME=*) es_unquote "${es_line#NAME=}"; es_name=$ES_T ;;
        PRETTY_NAME=*) es_unquote "${es_line#PRETTY_NAME=}"; es_pretty=$ES_T ;;
        VERSION_ID=*) es_unquote "${es_line#VERSION_ID=}"; es_vid=$ES_T ;;
        VERSION=*) es_unquote "${es_line#VERSION=}"; es_ver=$ES_T ;;
        ID=*) es_unquote "${es_line#ID=}"; es_did=$ES_T ;;
        ID_LIKE=*) es_unquote "${es_line#ID_LIKE=}"; es_like=$ES_T ;;
        BUILD_ID=*) es_unquote "${es_line#BUILD_ID=}"; es_build=$ES_T ;;
        VARIANT_ID=*) es_unquote "${es_line#VARIANT_ID=}"; es_variant=$ES_T ;;
      esac
    done <"$es_osr"
  fi
  if [ -z "$es_pretty" ] && [ -r "$ES_ROOT/etc/lsb-release" ]; then
    es_src "read /etc/lsb-release"
    while IFS= read -r es_line || [ -n "$es_line" ]; do
      case $es_line in
        DISTRIB_ID=*) es_unquote "${es_line#DISTRIB_ID=}"; [ -n "$es_did" ] || es_lower "$ES_T"; [ -n "$es_did" ] || es_did=$ES_T ;;
        DISTRIB_RELEASE=*) es_unquote "${es_line#DISTRIB_RELEASE=}"; [ -n "$es_vid" ] || es_vid=$ES_T ;;
        DISTRIB_DESCRIPTION=*) es_unquote "${es_line#DISTRIB_DESCRIPTION=}"; es_pretty=$ES_T ;;
      esac
    done <"$ES_ROOT/etc/lsb-release"
  fi
  es_rh=; es_deb=; es_alp=
  if es_read1 "$ES_ROOT/etc/redhat-release"; then
    es_src "read /etc/redhat-release"; es_rh=$ES_L
    [ -n "$es_pretty" ] || es_pretty=$es_rh
    if [ -z "$es_vid" ]; then es_version_of "$es_rh"; es_vid=$ES_T; fi
  fi
  if es_read1 "$ES_ROOT/etc/debian_version"; then es_src "read /etc/debian_version"; es_deb=$ES_L; fi
  if es_read1 "$ES_ROOT/etc/alpine-release"; then es_src "read /etc/alpine-release"; es_alp=$ES_L; fi
  es_pv=; es_kr=$ES_UNAME_R
  if es_read1 "$ES_ROOT/proc/version"; then es_src "read /proc/version"; es_pv=$ES_L; fi
  if es_read1 "$ES_ROOT/proc/sys/kernel/osrelease"; then es_src "read /proc/sys/kernel/osrelease"; es_kr=$ES_L; fi
  es_wsl=false; es_wslv=
  if [ "$ES_OS" = linux ]; then
    case "$es_kr $es_pv" in
      *WSL2*|*microsoft-standard*) es_wsl=true; es_wslv=2 ;;
      *Microsoft*|*microsoft*) es_wsl=true; es_wslv=1 ;;
    esac
  fi
  case $ES_OS in
    darwin)
      if es_tool sw_vers; then
        es_raw sw_vers "$ES_OUT_F"
        while IFS= read -r es_line; do
          es_k=${es_line%%:*}; es_trim "${es_line#*:}"
          case $es_k in
            ProductName) es_name=$ES_T ;;
            ProductVersion) es_vid=$ES_T ;;
            BuildVersion) es_build=$ES_T ;;
          esac
        done <"$ES_OUT_F"
        es_did=macos; es_pretty="${es_name:-macOS} $es_vid"
      else
        es_partial "sw_vers did not run"
      fi ;;
    aix)
      es_vid="$es_uv.$ES_UNAME_R"; es_pretty="AIX $es_vid"; es_did=aix
      if es_tool oslevel -s && es_read1 "$ES_OUT_F"; then es_build=$ES_L; fi ;;
    sunos)
      if es_read1 "$ES_ROOT/etc/release"; then es_src "read /etc/release"; es_trim "$ES_L"; es_pretty=$ES_T; fi
      es_vid=$ES_UNAME_R; es_did=solaris ;;
    zos)
      # z/OS UNIX: plain uname -s/-r/-v give the OS/390-compatible identity (for example "OS/390 12.00
      # 03"); the z/OS name, release and version come with -I: "uname -Ia" prints sysname, node,
      # release, version, machine ("z/OS ZOS1 05.00 02 8561" is z/OS 2.5). Tier 2, unverified: the
      # layout is from IBM's uname documentation, not from a system.
      es_zok=0
      if es_tool uname -Ia && es_read1 "$ES_OUT_F"; then
        es_raw uname_Ia "$ES_OUT_F"
        set -f; set -- $ES_L; set +f
        es_zr=${3:-}; es_zr=${es_zr%%.*}; es_zv=${4:-}
        while :; do case $es_zv in 0?*) es_zv=${es_zv#0} ;; *) break ;; esac; done
        while :; do case $es_zr in 0?*) es_zr=${es_zr#0} ;; *) break ;; esac; done
        if [ "${1:-}" = z/OS ] && es_is_num "$es_zv" && es_is_num "$es_zr"; then
          es_vid="$es_zv.$es_zr"; es_pretty="z/OS $es_vid"; es_zok=1
        fi
      fi
      if [ "$es_zok" = 0 ]; then
        es_vid=$ES_UNAME_R; es_pretty="z/OS (release unknown)"
        es_partial "uname -I did not report the z/OS release and version; plain uname gives only the OS/390-compatible identity ($ES_UNAME_S $ES_UNAME_R $es_uv)"
      fi
      es_did=zos ;;
    os400)
      # IBM i PASE: uname -v is the version and -r the release (7 and 5 are IBM i 7.5).
      # Tier 2, unverified.
      if es_is_num "$es_uv" && es_is_num "$ES_UNAME_R"; then es_vid="$es_uv.$ES_UNAME_R"; es_pretty="IBM i $es_vid"
      else es_vid=$ES_UNAME_R; es_pretty="IBM i $ES_UNAME_R"; es_partial "uname -v/-r did not give a version and release: $es_uv $ES_UNAME_R"
      fi
      es_did=ibmi ;;
  esac
  [ -n "$es_pretty" ] || { [ -n "$es_name" ] && es_pretty="$es_name ${es_ver:-$es_vid}"; }
  [ -n "$es_pretty" ] || es_pretty="$ES_UNAME_S $ES_UNAME_R"
  es_trim "$es_pretty"; es_pretty=$ES_T
  [ -n "$es_vid" ] || es_vid=$ES_UNAME_R
  es_bits=
  if es_tool getconf LONG_BIT && es_read1 "$ES_OUT_F"; then es_bits=$ES_L; fi
  es_ros=
  es_osarch=$ES_ARCH; es_parch=$ES_ARCH
  if [ "$ES_OS" = darwin ]; then
    if es_tool sysctl -n sysctl.proc_translated && es_read1 "$ES_OUT_F"; then
      case $ES_L in 1) es_ros=true; es_osarch=arm64; es_parch=x86_64 ;; 0) es_ros=false ;; esac
    fi
  fi
  if [ "$es_bits" = 32 ]; then
    case $es_osarch in x86_64) es_parch=x86 ;; arm64) es_parch=arm ;; ppc64) es_parch=ppc ;; sparc64) es_parch=sparc ;; esac
  fi
  es_fqdn=; es_dom=
  case $ES_HOST in *.*) es_fqdn=$ES_HOST ;; esac
  if [ -z "$es_fqdn" ] && [ -r "$ES_ROOT/etc/hosts" ]; then
    es_src "read /etc/hosts (own host name)"
    es_fqdn=$(awk -v h="$ES_HOST" '
      { sub(/#.*/, "") }
      { hit = 0; for (i = 2; i <= NF; i++) if ($i == h) hit = 1
        if (hit) for (i = 2; i <= NF; i++) if (index($i, h ".") == 1) { print $i; exit } }' "$ES_ROOT/etc/hosts")
  fi
  [ -n "$es_fqdn" ] && es_dom=${es_fqdn#*.}
  if [ -z "$es_dom" ] && [ -r "$ES_ROOT/etc/resolv.conf" ]; then
    es_dom=$(awk '$1 == "domain" && NF >= 2 { print $2; exit }' "$ES_ROOT/etc/resolv.conf")
  fi
  es_krb=false; es_sssd=false; es_joined=
  if [ -e "$ES_ROOT/etc/krb5.conf" ]; then es_krb=true; fi
  if [ -e "$ES_ROOT/etc/sssd/sssd.conf" ]; then es_sssd=true; fi
  es_src "test /etc/krb5.conf, /etc/sssd/sssd.conf (presence only)"
  if [ $es_sssd = true ]; then es_joined=true
  elif [ $es_krb = false ] && [ "$ES_OS" = linux ]; then es_joined=false
  fi
  es_s family "$ES_OS"
  es_s name "$es_pretty"
  es_sn version "$es_vid"
  es_sn build "$es_build"
  es_sn edition "$es_variant"
  es_sn kernel "$es_kr"
  es_sn kernel_version "$es_uv"
  es_sn kernel_banner "$es_pv"
  es_s arch "$es_osarch"
  es_sn machine "$ES_UNAME_M"
  es_sn processor "$es_up"
  es_s process_arch "$es_parch"
  es_n userland_bits "$es_bits"
  es_s hostname "$ES_HOST"
  es_sn fqdn "$es_fqdn"
  es_sn domain "$es_dom"
  es_b domain_joined "$es_joined"
  es_b directory_joined "$es_joined"
  es_b kerberos_config "$es_krb"
  es_b sssd_config "$es_sssd"
  es_z install_type
  es_sn distro_id "$es_did"
  es_sn distro_like "$es_like"
  es_sn distro_version "$es_ver"
  es_sn redhat_release "$es_rh"
  es_sn debian_version "$es_deb"
  es_sn alpine_version "$es_alp"
  if [ "$ES_OS" = linux ]; then es_b wsl "$es_wsl"; es_n wsl_version "$es_wslv"; else es_z wsl; es_z wsl_version; fi
  es_b rosetta "$es_ros"
  if [ "$ES_OS" = linux ] && [ -z "$es_osr" ] && [ -z "$es_rh" ] && [ -z "$es_alp" ]; then
    es_partial "no os-release, lsb-release or distribution release file was readable"
  fi
  es_fact os_name "$es_pretty"
  es_fact os_version "$es_vid"
  es_fact os_arch "$es_osarch"
  es_fact process_arch "$es_parch"
  es_fact distro_id "$es_did"
  es_fact os_kernel "$es_kr"
  es_fact wsl "$es_wsl"
  es_fact rosetta "$es_ros"
  es_fact userland_bits "$es_bits"
}

probe_os_time_locale() {
  es_src "environment TZ, LANG, LC_*"
  es_tz=${TZ:-}
  if [ -z "$es_tz" ] && es_read1 "$ES_ROOT/etc/timezone"; then es_src "read /etc/timezone"; es_tz=$ES_L; fi
  if [ -z "$es_tz" ] && [ -h "$ES_ROOT/etc/localtime" ]; then
    es_src "read /etc/localtime link target"
    es_realpath "$ES_ROOT/etc/localtime"
    case $ES_RP in */zoneinfo/*) es_tz=${ES_RP##*/zoneinfo/} ;; esac
  fi
  es_cpa=; es_cpo=
  if [ "$ES_OS" = cygwin ]; then
    # Cygwin/MSYS expose the Windows registry read-only under /proc/registry
    es_reg="$ES_ROOT/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control"
    if [ -z "$es_tz" ] && es_read1 "$es_reg/TimeZoneInformation/TimeZoneKeyName"; then
      es_src "read /proc/registry/.../TimeZoneInformation/TimeZoneKeyName (Windows time zone)"; es_tz=$ES_L
    fi
    if es_read1 "$es_reg/Nls/CodePage/ACP"; then es_src "read /proc/registry/.../Nls/CodePage/ACP, OEMCP"; es_cpa=$ES_L; fi
    es_read1 "$es_reg/Nls/CodePage/OEMCP" && es_cpo=$ES_L
  fi
  es_off=$(date '+%z' 2>/dev/null)
  case $es_off in [+-][0-9][0-9][0-9][0-9]) ;; *) es_off= ;; esac
  es_loc=$ES_ORIG_LC_ALL
  [ -n "$es_loc" ] || es_loc=${LC_CTYPE:-}
  [ -n "$es_loc" ] || es_loc=${LANG:-}
  es_locsrc=default; [ -n "$es_loc" ] && es_locsrc=environment
  [ -n "$es_loc" ] || es_loc=C
  es_enc=; es_dec=; es_dfmt=; es_u8=
  # the locale commands report the user's locale: they run with the original LC_ALL (every
  # other child runs under LC_ALL=C)
  ES_CHILD_LOCALE=user
  if es_tool locale; then
    es_raw locale "$ES_OUT_F"
    if [ "$es_locsrc" = default ]; then
      while IFS= read -r es_line; do
        case $es_line in
          LC_CTYPE=*) es_unquote "${es_line#LC_CTYPE=}"; [ -n "$ES_T" ] && { es_loc=$ES_T; es_locsrc='locale command (LC_CTYPE)'; } ;;
        esac
      done <"$ES_OUT_F"
    fi
    if es_tool locale charmap && es_read1 "$ES_OUT_F"; then es_enc=$ES_L; fi
    if es_tool locale -k decimal_point d_fmt; then
      while IFS= read -r es_line; do
        case $es_line in
          decimal_point=*) es_unquote "${es_line#decimal_point=}"; es_dec=$ES_T ;;
          d_fmt=*) es_unquote "${es_line#d_fmt=}"; es_dfmt=$ES_T ;;
        esac
      done <"$ES_OUT_F"
    fi
    if es_tool locale -a; then
      es_u8=false
      if grep -i 'utf-*8' "$ES_OUT_F" >/dev/null 2>&1; then es_u8=true; fi
    fi
  else
    es_partial "the locale command is not available; encoding derived from the locale name"
  fi
  ES_CHILD_LOCALE=
  if [ -z "$es_enc" ]; then
    case $es_loc in
      *.*) es_enc=${es_loc#*.}; es_enc=${es_enc%%@*} ;;
      C|POSIX) es_enc=ANSI_X3.4-1968 ;;
    esac
  fi
  es_isu8=false
  case $es_enc in [Uu][Tt][Ff]-8|[Uu][Tt][Ff]8) es_isu8=true ;; esac
  es_sn timezone "$es_tz"
  es_sn utc_offset "$es_off"
  es_s locale "$es_loc"
  es_s locale_source "$es_locsrc"
  es_o locale_env
  for es_v in LANG LANGUAGE LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES; do
    eval "es_vv=\${$es_v-}"
    [ -n "$es_vv" ] && es_s "$es_v" "$es_vv"
  done
  [ -n "$ES_ORIG_LC_ALL" ] && es_s LC_ALL "$ES_ORIG_LC_ALL"
  es_oe
  es_sn encoding "$es_enc"
  es_b encoding_is_utf8 "$es_isu8"
  es_b utf8_available "$es_u8"
  es_sn decimal_separator "$es_dec"
  es_sn date_format "$es_dfmt"
  es_n codepage_ansi "$es_cpa"; es_n codepage_oem "$es_cpo"; es_z codepage_console
  es_fact utc_offset "$es_off"
  es_fact encoding "$es_enc"
  es_fact encoding_utf8 "$es_isu8"
  es_fact decimal_sep "$es_dec"
  es_fact locale_name "$es_loc"
  es_fact timezone "$es_tz"
}

probe_os_health() {
  es_up=; es_boot=; es_l1=; es_l5=; es_l15=
  if es_read1 "$ES_ROOT/proc/uptime"; then
    es_src "read /proc/uptime"
    es_up=${ES_L%%[. ]*}
  fi
  if es_read1 "$ES_ROOT/proc/loadavg"; then
    es_src "read /proc/loadavg"
    set -- $ES_L
    es_l1=$1; es_l5=$2; es_l15=$3
  fi
  if [ -z "$es_up" ]; then
    case $ES_OS in
      darwin|freebsd|openbsd|netbsd)
        if es_tool sysctl -n kern.boottime && es_read1 "$ES_OUT_F"; then
          es_bs=$(printf '%s\n' "$ES_L" | awk '{ if (match($0, /sec = [0-9]+/)) print substr($0, RSTART + 6, RLENGTH - 6) }')
          if es_is_num "$es_bs"; then es_epoch_s; es_up=$((ES_SEC - es_bs)); fi
        fi
        if es_tool sysctl -n vm.loadavg && es_read1 "$ES_OUT_F"; then
          set -- $(printf '%s\n' "$ES_L" | tr -d '{}')
          es_l1=$1; es_l5=$2; es_l15=$3
        fi ;;
      *)
        if es_tool uptime && es_read1 "$ES_OUT_F"; then
          es_raw uptime "$ES_OUT_F"
          es_up=$(awk '{
            s = $0; sub(/^.* up +/, "", s); sub(/, +[0-9]+ users?.*$/, "", s); t = 0
            if (match(s, /[0-9]+ +days?/)) t += substr(s, RSTART, RLENGTH) * 86400
            if (match(s, /[0-9]+:[0-9]+/)) { hm = substr(s, RSTART, RLENGTH); split(hm, H, ":"); t += H[1] * 3600 + H[2] * 60 }
            else if (match(s, /[0-9]+ +min/)) t += substr(s, RSTART, RLENGTH) * 60
            else if (match(s, /[0-9]+ +hrs?/)) t += substr(s, RSTART, RLENGTH) * 3600
            print t; exit }' "$ES_OUT_F")
          set -- $(awk '{ s = $0; if (sub(/^.*load averages?: */, "", s)) { gsub(/,/, " ", s); print s } }' "$ES_OUT_F")
          es_l1=${1:-}; es_l5=${2:-}; es_l15=${3:-}
        fi ;;
    esac
  fi
  if es_is_num "$es_up"; then
    es_epoch_s
    es_iso_epoch $((ES_SEC - es_up)); es_boot=$ES_ISO
  else
    es_up=; es_partial "uptime could not be determined"
  fi
  es_pr=; es_reasons=
  if [ -e "$ES_ROOT/var/run/reboot-required" ] || [ -e "$ES_ROOT/run/reboot-required" ]; then
    es_pr=true; es_reasons="reboot-required flag file present$ES_NL"
    for es_f in "$ES_ROOT/var/run/reboot-required.pkgs" "$ES_ROOT/run/reboot-required.pkgs"; do
      if [ -r "$es_f" ]; then es_reasons="${es_reasons}packages: $(awk '{ printf "%s%s", (NR > 1 ? " " : ""), $0 }' "$es_f")$ES_NL"; break; fi
    done
  fi
  es_src "read /var/run/reboot-required"
  if [ "$ES_OS" = linux ] && [ -d "$ES_ROOT/lib/modules" ]; then
    es_src "list /lib/modules (installed kernels)"
    es_newest=
    for es_k in "$ES_ROOT"/lib/modules/*; do
      [ -d "$es_k" ] || continue
      es_k=${es_k##*/}
      if [ -z "$es_newest" ] || [ "$(es_vercmp "$es_k" "$es_newest")" = 1 ]; then es_newest=$es_k; fi
    done
    if [ -n "$es_newest" ]; then
      [ -n "$es_pr" ] || es_pr=false
      if [ ! -d "$ES_ROOT/lib/modules/$ES_UNAME_R" ]; then
        es_pr=true; es_reasons="${es_reasons}modules of the running kernel $ES_UNAME_R are no longer installed$ES_NL"
      elif [ "$es_newest" != "$ES_UNAME_R" ] && [ "$(es_vercmp "$es_newest" "$ES_UNAME_R")" = 1 ]; then
        es_pr=true; es_reasons="${es_reasons}newer kernel installed: $es_newest (running $ES_UNAME_R)$ES_NL"
      fi
    fi
  fi
  es_n uptime_seconds "$es_up"
  es_sn last_boot_utc "$es_boot"
  if [ -n "$es_l1" ]; then es_a load; es_n - "$es_l1"; es_n - "$es_l5"; es_n - "$es_l15"; es_ae; else es_z load; fi
  es_b pending_reboot "$es_pr"
  es_list pending_reasons "$es_reasons"
  es_fact pending_reboot "$es_pr"
  es_fact pending_reasons "$es_reasons"
  es_fact uptime_s "$es_up"
}

probe_hw_cpu() {
  es_model=; es_vendor=; es_logical=; es_sockets=; es_cores=; es_flags=
  if [ -r "$ES_ROOT/proc/cpuinfo" ]; then
    es_src "read /proc/cpuinfo"
    es_ci=$(awk -F ':' '
      { k = $1; sub(/[ \t]+$/, "", k); v = $0; sub(/^[^:]*:[ \t]*/, "", v) }
      k == "processor" && v ~ /^[0-9]+$/ { n++ }
      k == "model name" && m == "" { m = v }
      (k == "Hardware" || k == "Model" || k == "cpu model" || k == "cpu" || k == "uarch") && alt == "" { alt = v }
      k == "vendor_id" && vd == "" { vd = v }
      k == "CPU implementer" && vd == "" { vd = "arm implementer " v }
      k == "physical id" { sock[v] = 1 }
      k == "cpu cores" && cc == "" { cc = v }
      (k == "flags" || k == "Features" || k == "features") && fl == "" { fl = v }
      END {
        ns = 0; for (s in sock) ns++
        if (m == "") m = alt
        printf "%s\t%s\t%s\t%s\t%s\t%s\n", (m == "" ? "-" : m), (vd == "" ? "-" : vd), n + 0, ns, (cc == "" ? "-" : cc), (fl == "" ? "-" : fl) }' "$ES_ROOT/proc/cpuinfo")
    IFS=$ES_TAB read -r es_model es_vendor es_logical es_sockets es_cpc es_flags <<ES_CPU
$es_ci
ES_CPU
    [ "$es_model" = - ] && es_model=
    [ "$es_vendor" = - ] && es_vendor=
    [ "$es_flags" = - ] && es_flags=
    [ "$es_logical" = 0 ] && es_logical=
    if [ "$es_sockets" != 0 ] && es_is_num "$es_cpc"; then es_cores=$((es_sockets * es_cpc)); fi
    [ "$es_sockets" = 0 ] && es_sockets=
  fi
  if [ "$ES_OS" = darwin ] || { [ -z "$es_model" ] && [ "$ES_OS" != linux ] && [ "$ES_OS" != cygwin ]; }; then
    case $ES_OS in
      darwin) es_sargs='machdep.cpu.brand_string machdep.cpu.vendor machdep.cpu.features machdep.cpu.leaf7_features hw.ncpu hw.physicalcpu hw.packages hw.optional.neon hw.optional.arm.FEAT_AES' ;;
      *) es_sargs='hw.model hw.ncpu hw.machine_arch' ;;
    esac
    es_tool sysctl $es_sargs
    if [ -s "$ES_OUT_F" ]; then
      while IFS= read -r es_line; do
        es_k=${es_line%%:*}; es_trim "${es_line#*:}"
        case $es_k in
          machdep.cpu.brand_string|hw.model) es_model=$ES_T ;;
          machdep.cpu.vendor) es_vendor=$ES_T ;;
          machdep.cpu.features|machdep.cpu.leaf7_features) es_flags="$es_flags $ES_T" ;;
          hw.ncpu) es_logical=$ES_T ;;
          hw.physicalcpu) es_cores=$ES_T ;;
          hw.packages) es_sockets=$ES_T ;;
          hw.optional.neon) [ "$ES_T" = 1 ] && es_flags="$es_flags neon" ;;
          hw.optional.arm.FEAT_AES) [ "$ES_T" = 1 ] && es_flags="$es_flags aes" ;;
        esac
      done <"$ES_OUT_F"
    fi
  fi
  case $ES_OS in
    zos) [ -n "$es_model" ] || { es_model="IBM Z (machine type ${ES_UNAME_M:-unknown})"; es_vendor=IBM; } ;;
    os400) [ -n "$es_model" ] || { es_model="IBM Power (PASE, uname -m ${ES_UNAME_M:-unknown})"; es_vendor=IBM; } ;;
  esac
  if [ -z "$es_logical" ]; then
    if es_tool getconf _NPROCESSORS_ONLN && es_read1 "$ES_OUT_F" && es_is_num "$ES_L"; then es_logical=$ES_L; fi
  fi
  [ -n "$es_cores" ] || es_cores=$es_logical
  es_lflags=" $(printf '%s' "$es_flags" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz') "
  es_s model "${es_model:-unknown}"
  es_sn vendor "$es_vendor"
  es_n cores "$es_cores"
  es_n logical "$es_logical"
  es_n sockets "$es_sockets"
  es_o features
  es_avx2=
  if [ -n "$es_flags" ] || [ "$ES_ARCH" = arm64 ]; then
    case $ES_ARCH in
      x86_64|x86)
        es_cpu_tf sse4_2 sse4.2; es_b sse4_2 "$ES_TF"
        es_cpu_tf avx avx1.0; es_b avx "$ES_TF"
        es_cpu_tf avx2; es_b avx2 "$ES_TF"; es_avx2=$ES_TF
        es_cpu_tf avx512f; es_b avx512f "$ES_TF"
        es_cpu_tf aes; es_b aes "$ES_TF"
        es_b neon false ;;
      arm64|arm)
        es_b sse4_2 false; es_b avx false; es_b avx2 false; es_b avx512f false; es_avx2=false
        es_cpu_tf aes; es_b aes "$ES_TF"
        es_cpu_tf neon asimd; [ "$ES_ARCH" = arm64 ] && ES_TF=true
        es_b neon "$ES_TF" ;;
      *) es_z sse4_2; es_z avx; es_z avx2; es_z avx512f; es_z aes; es_z neon ;;
    esac
  else
    es_z sse4_2; es_z avx; es_z avx2; es_z avx512f; es_z aes; es_z neon
  fi
  es_oe
  set -f; es_fl=$(printf '%s\n' $es_lflags); set +f
  es_list flags "$es_fl"
  [ -n "$es_model" ] || es_partial "CPU model not found"
  es_fact cpu_logical "$es_logical"
  es_fact cpu_model "$es_model"
  es_fact cpu_avx2 "$es_avx2"
}

# es_cpu_tf FLAG...: ES_TF=true when any FLAG is in $es_lflags
es_cpu_tf() {
  ES_TF=false
  for es_hf in "$@"; do
    case $es_lflags in *" $es_hf "*) ES_TF=true; return 0 ;; esac
  done
  return 0
}

probe_hw_memory() {
  es_tot=; es_av=; es_st=; es_sf=
  if [ -r "$ES_ROOT/proc/meminfo" ]; then
    es_src "read /proc/meminfo"
    es_mi=$(awk '
      { v = $2 + 0 }
      $1 == "MemTotal:" { t = v } $1 == "MemAvailable:" { a = v; ha = 1 } $1 == "MemFree:" { f = v }
      $1 == "Buffers:" { b = v } $1 == "Cached:" { c = v } $1 == "SwapTotal:" { st = v; hs = 1 } $1 == "SwapFree:" { sf = v }
      END { if (!ha) a = f + b + c
        printf "%s %s %s %s\n", (t ? int(t / 1024) : "-"), (t ? int(a / 1024) : "-"), (hs ? int(st / 1024) : "-"), (hs ? int(sf / 1024) : "-") }' "$ES_ROOT/proc/meminfo")
    set -- $es_mi
    es_tot=$1; es_av=$2; es_st=$3; es_sf=$4
    [ "$es_tot" = - ] && es_tot=; [ "$es_av" = - ] && es_av=; [ "$es_st" = - ] && es_st=; [ "$es_sf" = - ] && es_sf=
  fi
  if [ -z "$es_tot" ]; then
    case $ES_OS in
      darwin)
        if es_tool sysctl -n hw.memsize && es_read1 "$ES_OUT_F" && es_is_num "$ES_L"; then es_tot=$((ES_L / 1048576)); fi
        if es_tool sysctl -n vm.swapusage && es_read1 "$ES_OUT_F"; then
          set -- $(printf '%s\n' "$ES_L" | awk '{ for (i = 1; i <= NF; i++) { if ($i == "total") t = $(i + 2); if ($i == "free") f = $(i + 2) } sub(/M$/, "", t); sub(/M$/, "", f); printf "%d %d\n", t, f }')
          es_st=${1:-}; es_sf=${2:-}
        fi
        if es_tool vm_stat; then
          es_av=$(awk '
            /page size of/ { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) ps = $i }
            /^Pages (free|inactive|speculative):/ { v = $NF; sub(/\.$/, "", v); p += v }
            END { if (ps) printf "%d\n", p * ps / 1048576 }' "$ES_OUT_F")
        fi ;;
      freebsd|openbsd|netbsd)
        if es_tool sysctl -n hw.physmem && es_read1 "$ES_OUT_F" && es_is_num "$ES_L"; then es_tot=$((ES_L / 1048576)); fi ;;
      aix)
        if es_tool lsattr -El sys0 -a realmem && es_read1 "$ES_OUT_F"; then
          set -- $ES_L; es_is_num "${2:-}" && es_tot=$(($2 / 1024))
        fi ;;
      sunos)
        if es_tool prtconf; then
          es_tot=$(awk '/^Memory size:/ { v = $3; if ($4 ~ /^G/) v *= 1024; print v; exit }' "$ES_OUT_F")
        fi ;;
    esac
  fi
  if [ -z "$es_tot" ]; then
    if es_tool getconf _PHYS_PAGES && es_read1 "$ES_OUT_F" && es_is_num "$ES_L"; then
      es_pp=$ES_L
      if es_tool getconf PAGESIZE && es_read1 "$ES_OUT_F" && es_is_num "$ES_L"; then
        es_tot=$(awk -v p="$es_pp" -v s="$ES_L" 'BEGIN { printf "%d\n", p * s / 1048576 }')
      fi
    fi
  fi
  es_n total_mb "$es_tot"
  es_n available_mb "$es_av"
  es_n swap_total_mb "$es_st"
  es_n swap_free_mb "$es_sf"
  [ -n "$es_tot" ] || es_partial "total memory could not be determined"
  [ -n "$es_av" ] || es_note "available memory is not reported on this system"
  es_fact mem_total_mb "$es_tot"
  es_fact mem_avail_mb "$es_av"
}

# es_block_base DEVICE -> ES_T: /dev/sda1 -> sda, /dev/nvme0n1p2 -> nvme0n1 (empty when unknown)
es_block_base() {
  ES_T=${1#/dev/}
  case $ES_T in
    */*|'') ES_T= ;;
    nvme*p[0-9]*|mmcblk*p[0-9]*) ES_T=${ES_T%p*} ;;
    sd*|vd*|xvd*|hd*)
      while :; do case $ES_T in *[0-9]) ES_T=${ES_T%?} ;; *) break ;; esac; done ;;
    *) ES_T= ;;
  esac
}

probe_hw_storage() {
  es_dfargs=
  es_dfknown=0; es_dfok=0
  if [ "$ES_OS" = zos ]; then
    # z/OS: a plain df also asks NFS servers, so only mount points whose file system type the
    # mount table shows as local are queried (tier 2, unverified)
    es_dfknown=1
    es_note "z/OS: df -kP runs only on mount points with a known local file system type (zfs, hfs, tfs); network and unknown types are never queried"
  elif es_tool df -P -k -l && [ -s "$ES_OUT_F" ]; then
    es_dfok=1
  else
    es_note "df -l failed; using the local mounts from the mount table"
  fi
  if [ "$es_dfok" = 1 ]; then
    es_dfout=$ES_OUT_F
  else
    if [ -s "$ES_TMP/mounts.tsv" ]; then
      es_dfargs=$(awk -F '\t' -v net="$ES_NET_FS" -v npre="$ES_NET_FS_PREFIXES" -v lfuse="$ES_LOCAL_FUSE" -v ps="$ES_PSEUDO_FS" -v known="$es_dfknown" "$ES_AWK_NETFS"' !es_isnet($3) && index(ps, " " $3 " ") == 0 && !(known && $3 == "unknown") { print $2 }' "$ES_TMP/mounts.tsv")
    fi
    es_dfkeep=
    while IFS= read -r es_dfm; do
      [ -n "$es_dfm" ] || continue
      es_on_netfs "$es_dfm" || es_dfkeep="$es_dfkeep$es_dfm$ES_NL"
    done <<ES_DFEOF
$es_dfargs
ES_DFEOF
    es_dfargs=${es_dfkeep%"$ES_NL"}
    es_dfout=
    if [ -n "$es_dfargs" ]; then
      es_sifs=$IFS; IFS=$ES_NL; set -f
      set -- $es_dfargs
      IFS=$es_sifs; set +f
      es_tool df -P -k "$@"
      es_dfout=$ES_OUT_F
    fi
  fi
  [ -n "$ES_MOUNT_SRC" ] && es_src "$ES_MOUNT_SRC (file system types, at scan start)"
  es_a volumes
  es_nvol=0
  if [ -n "$es_dfout" ] && [ -s "$es_dfout" ]; then
    awk 'NR > 1 {
        c = 0; for (i = NF; i >= 5; i--) if ($i ~ /^[0-9]+%$/ || $i == "-") { c = i; break }
        if (!c) next
        dev = $1; for (i = 2; i <= c - 4; i++) dev = dev " " $i
        mnt = $(c + 1); for (i = c + 2; i <= NF; i++) mnt = mnt " " $i
        printf "%s\t%s\t%s\t%s\n", dev, mnt, $(c - 3), $(c - 1) }' "$es_dfout" >"$ES_P_DIR/df.tsv"
    while IFS=$ES_TAB read -r es_dev es_mnt es_tot es_av; do
      es_fs=
      if es_mount_of "$es_mnt" && [ "$ES_MNT" = "$es_mnt" ]; then es_fs=$ES_MFS; fi
      # a volume missing from the mount table has no fstype (null): kept, never "pseudo"
      if [ -n "$es_fs" ]; then
        case " $ES_PSEUDO_FS " in *" $es_fs "*) [ "$es_fs" = overlay ] || continue ;; esac
      fi
      case $es_mnt in /snap/*|/var/lib/snapd/*) continue ;; esac
      es_netv=false; [ -n "$es_fs" ] && es_is_netfs "$es_fs" && es_netv=true
      es_rem=
      es_block_base "$es_dev"
      if [ -n "$ES_T" ] && es_read1 "$ES_ROOT/sys/block/$ES_T/removable"; then
        case $ES_L in 1) es_rem=true ;; 0) es_rem=false ;; esac
      fi
      es_o -
      es_s mount "$es_mnt"; es_s device "$es_dev"; es_sn fstype "$es_fs"
      if es_is_num "$es_tot"; then es_n total_mb $((es_tot / 1024)); else es_z total_mb; fi
      if es_is_num "$es_av"; then es_n free_mb $((es_av / 1024)); else es_z free_mb; fi
      es_b network "$es_netv"; es_b removable "$es_rem"
      es_oe
      es_nvol=$((es_nvol + 1))
    done <"$ES_P_DIR/df.tsv"
    es_src "read /sys/block/*/removable (per volume)"
  fi
  es_ae
  es_note "network file systems are not queried (df -l); see fs.mounts for every mount"
  if [ "$es_nvol" = 0 ]; then es_partial "no volume information (df failed)"; fi
}

probe_hw_gpu() {
  es_a gpus
  es_ng=0; es_tools=0; es_tried=0
  if es_need nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader; then
    es_tools=1
    while IFS=, read -r es_gn es_gd es_gm; do
      es_trim "$es_gn"; es_gn=$ES_T
      [ -n "$es_gn" ] || continue
      es_trim "$es_gd"; es_gd=$ES_T
      es_trim "$es_gm"; es_gm=${ES_T%% *}
      es_o -; es_s name "$es_gn"; es_sn driver_version "$es_gd"; es_n vram_mb "$es_gm"; es_s source nvidia-smi; es_oe
      es_ng=$((es_ng + 1))
    done <"$ES_OUT_F"
  else
    case $? in 126|127) ;; *) es_tried=1 ;; esac
  fi
  if [ "$ES_OS" = darwin ]; then
    if es_need system_profiler SPDisplaysDataType; then
      es_tools=1
      awk '
        /Chipset Model:/ { if (n != "") print n "\t" v; n = $0; sub(/^.*Chipset Model: */, "", n); v = "" }
        /VRAM \(.*\):/ { v = $0; sub(/^.*: */, "", v); sub(/ .*/, "", v) }
        END { if (n != "") print n "\t" v }' "$ES_OUT_F" >"$ES_P_DIR/gpus.tsv"
      while IFS=$ES_TAB read -r es_gn es_gm; do
        es_o -; es_s name "$es_gn"; es_z driver_version; es_n vram_mb "$es_gm"; es_s source system_profiler; es_oe
        es_ng=$((es_ng + 1))
      done <"$ES_P_DIR/gpus.tsv"
    else
      case $? in 126|127) ;; *) es_tried=1 ;; esac
    fi
  elif es_need lspci; then
    es_tools=1
    awk '/VGA compatible controller|3D controller|Display controller/ { s = $0; sub(/^[^:]*:[^:]*: */, "", s); print s }' "$ES_OUT_F" >"$ES_P_DIR/gpus.txt"
    while IFS= read -r es_gn; do
      [ -n "$es_gn" ] || continue
      es_o -; es_s name "$es_gn"; es_z driver_version; es_z vram_mb; es_s source lspci; es_oe
      es_ng=$((es_ng + 1))
    done <"$ES_P_DIR/gpus.txt"
  else
    case $? in 126|127) ;; *) es_tried=1 ;; esac
  fi
  es_ae
  es_dri=
  if [ -d "$ES_ROOT/dev/dri" ]; then
    es_src "list /dev/dri"
    for es_f in "$ES_ROOT"/dev/dri/*; do [ -e "$es_f" ] && es_dri="$es_dri${es_f##*/}$ES_NL"; done
  fi
  es_list dri_nodes "$es_dri"
  if [ "$es_ng" = 0 ]; then
    if [ "$es_tools" = 1 ] || [ -n "$es_dri" ]; then
      [ -n "$es_dri" ] && es_note "render nodes exist in /dev/dri but no adapter details were available"
      [ -z "$es_dri" ] && [ "$es_tried" = 0 ] && es_status not_found
    elif [ "$es_tried" = 0 ]; then
      es_partial "no GPU query tool (nvidia-smi, lspci) is available"
    fi
  fi
  es_fact gpu_count "$es_ng"
}
