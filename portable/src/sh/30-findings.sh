# ============================================================== findings
# Rules read the facts (ES_F_*) that probes published and the probe results.
# Severity, title and recommendation come from spec/findings.toml; a rule only decides
# whether the finding applies and writes a one-line detail. Facts of probes that did not
# run are empty, so a rule never fires on missing data.

# es_find ID DETAIL EVIDENCE: EVIDENCE is a |-separated list of probe ids
es_find() {
  es_fd=$(printf '%s' "$2" | tr '\t\r\n' '   ')
  printf '%s\t%s\t%s\n' "$1" "$es_fd" "$3" >>"$ES_TMP/findings.raw"
}

# es_pstatus ID -> ES_T: status of a probe ("" when it is not in the results)
es_pstatus() {
  ES_T=
  while IFS=$ES_TAB read -r es_pn es_pid es_pst es_pdur es_pkind; do
    if [ "$es_pid" = "$1" ]; then ES_T=$es_pst; return 0; fi
  done <"$ES_TMP/results.tsv"
  return 1
}

# es_ran ID: the probe ran (any status except skipped)
es_ran() { es_pstatus "$1" && [ "$ES_T" != skipped ]; }

# es_done ID: the probe completed (ok, not_found or not_applicable); only then may a rule or
# the brief conclude that something is absent
es_done() { es_pstatus "$1" || return 1; case $ES_T in ok|not_found|not_applicable) return 0 ;; esac; return 1; }

# es_has_facts ID: the probe ran and looked (ok or not_found). A not_applicable probe publishes
# no facts, so a rule that concludes from a missing value stays silent.
es_has_facts() { es_pstatus "$1" || return 1; case $ES_T in ok|not_found) return 0 ;; esac; return 1; }

es_lt() { es_is_num "$1" && es_is_num "$2" && [ "$1" -lt "$2" ]; }

# es_flt A B: true when decimal A < decimal B
es_flt() {
  [ -n "$1" ] && [ -n "$2" ] || return 1
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 < b + 0) }'
}

# es_join TEXT [MAX] -> ES_T: non-empty lines joined with ", " (at most MAX items, default 5)
es_join() {
  ES_T=$(printf '%s\n' "$1" | awk -v max="${2:-5}" 'NF { n++; if (n <= max) s = s (s == "" ? "" : ", ") $0 } END { if (n > max) s = s ", ... (" n " in total)"; print s }')
}

es_findings() {
  es_counts
  : >"$ES_TMP/findings.raw"
  es_rules_exec
  es_rules_tls_pkg
  es_rules_net
  es_rules_platform
  es_rules_limits
  es_rules_fs_user
  es_rules_scan
  # order: blockers, warnings, info; spec order inside a severity
  awk -F '\t' '
    FNR == NR { n++; id[n] = $1; sv[n] = $2; ti[n] = $3; re[n] = $4; next }
    !($1 in D) { D[$1] = $2; E[$1] = $3 }
    END {
      printf "" > tsv
      split("blocker warning info", S, " ")
      for (k = 1; k <= 3; k++) for (i = 1; i <= n; i++) if (sv[i] == S[k] && (id[i] in D)) {
        f = id[i]; m = split(E[f], EV, "|"); ev = ""
        for (j = 1; j <= m; j++) if (EV[j] != "") ev = ev (ev == "" ? "" : ", ") EV[j]
        printf "%s\t%s\t%s\t%s\t%s\t%s\n", f, sv[i], ti[i], D[f], re[i], ev > tsv
        printf "{\t-\ns\tid\t%s\ns\tseverity\t%s\ns\ttitle\t%s\ns\tdetail\t%s\ns\trecommendation\t%s\n[\tevidence\n", f, sv[i], ti[i], D[f], re[i]
        for (j = 1; j <= m; j++) if (EV[j] != "") printf "s\t-\t%s\n", EV[j]
        printf "]\n}\n"
      }
    }' tsv="$ES_TMP/findings.tsv" "$ES_TMP/findings.spec" "$ES_TMP/findings.raw" >"$ES_TMP/findings.ev"
  [ -f "$ES_TMP/findings.tsv" ] || : >"$ES_TMP/findings.tsv"
}

es_rules_exec() {
  if [ -n "${ES_F_noexec_temp:-}" ]; then
    es_join "$ES_F_noexec_temp"; es_find exec.noexec_temp "mounted noexec: $ES_T" "fs.mounts"
  fi
  es_mac=
  [ "${ES_F_selinux:-}" = enforcing ] && es_mac="SELinux enforcing"
  if [ "${ES_F_apparmor:-}" = enabled ] && [ -n "${ES_F_aa_profile:-}" ]; then
    case $ES_F_aa_profile in unconfined*) ;; *) es_mac="${es_mac:+$es_mac; }AppArmor profile $ES_F_aa_profile" ;; esac
  fi
  [ "${ES_F_fapolicyd:-}" = active ] && es_mac="${es_mac:+$es_mac; }fapolicyd active"
  [ -n "$es_mac" ] && es_find exec.mac_enforcing "$es_mac" "sec.app_control"
  es_ac=; es_ev=
  [ "${ES_F_fapolicyd:-}" = active ] && { es_ac="fapolicyd is active (only trusted executables may run)"; es_ev=sec.app_control; }
  if [ -n "${ES_F_exec_blocked:-}" ]; then
    es_ac="${es_ac:+$es_ac; }execution test blocked in: $ES_F_exec_blocked"; es_ev="${es_ev:+$es_ev|}fs.exec_test"
  fi
  [ -n "$es_ac" ] && es_find exec.app_control "$es_ac" "$es_ev"
  return 0
}

es_rules_tls_pkg() {
  if es_is_num "${ES_F_ca_custom:-}" && [ "$ES_F_ca_custom" -gt 0 ]; then
    es_join "$ES_F_ca_subjects" 3; es_find tls.enterprise_ca "$ES_F_ca_custom locally added CA certificate(s): $ES_T" "tls.trust"
  elif [ "$ES_OS" = darwin ] && [ -n "${ES_F_ca_subjects:-}" ]; then
    es_join "$ES_F_ca_subjects" 3; es_find tls.enterprise_ca "certificates in the System keychain: $ES_T" "tls.trust"
  fi
  if [ "${ES_F_default_route:-}" = false ] && es_has_facts net.routes; then
    es_find tls.offline_pki "no default route: online revocation checks (CRL/OCSP) and root updates cannot be reached" "net.routes|tls.trust"
  fi
  es_tv=
  [ -n "${ES_F_tls_disabled_env:-}" ] && { es_join "$ES_F_tls_disabled_env"; es_tv="environment: $ES_T"; }
  [ -n "${ES_F_tls_disabled_cfg:-}" ] && { es_join "$ES_F_tls_disabled_cfg" 3; es_tv="${es_tv:+$es_tv; }config: $ES_T"; }
  [ -n "$es_tv" ] && es_find tls.verification_disabled "$es_tv" "tls.trust|pkg.sources"
  if [ -n "${ES_F_endpoints_internal:-}" ]; then
    es_join "$ES_F_endpoints_internal"; es_find pkg.mirror "configured endpoints: $ES_T" "pkg.sources"
  fi
  if [ -n "${ES_F_caches:-}" ]; then
    es_join "$ES_F_caches" 8; es_find pkg.offline_cache "caches: $ES_T" "pkg.caches"
  fi
  if es_done pkg.sources && es_done pkg.caches && es_done net.proxy; then
    if [ -z "${ES_F_endpoints_internal:-}" ] && [ "${ES_F_proxy:-}" != true ] && [ -z "${ES_F_caches:-}" ]; then
      es_d="no internal registry or mirror in $ES_F_pkg_config_count package config file(s), no proxy, no local dependency cache"
      [ -n "${ES_F_endpoints_public:-}" ] && { es_join "$ES_F_endpoints_public" 3; es_d="$es_d; only public endpoints: $ES_T"; }
      es_find pkg.no_source "$es_d" "pkg.sources|pkg.caches|net.proxy"
    fi
  fi
  return 0
}

es_rules_net() {
  if [ "${ES_F_proxy:-}" = true ]; then
    es_join "${ES_F_proxy_hosts:-}"; es_find net.proxy_configured "proxy: ${ES_T:-configured (see net.proxy)}" "net.proxy"
  fi
  [ "${ES_F_default_route:-}" = false ] && es_has_facts net.routes && es_find net.no_route "no default gateway in the routing table" "net.routes"
  if [ -n "${ES_F_listen_ports:-}" ]; then
    es_used=
    for es_p in $ES_T_COMMON_PORTS; do
      case " $ES_F_listen_ports " in *" $es_p "*) es_used="$es_used $es_p" ;; esac
    done
    [ -n "$es_used" ] && es_find net.ports_in_use "already listening:$es_used" "net.listening"
  fi
  return 0
}

# es_legacy -> ES_T: reason when the OS or shell is past end of support ("" otherwise).
# The thresholds reflect vendor support dates as of envscan 1.0.0 (late 2026).
es_legacy() {
  ES_T=; es_v=${ES_F_os_version:-}; es_maj=${es_v%%.*}
  es_is_num "$es_maj" || es_maj=
  case ${ES_F_distro_id:-} in
    rhel|ol|rocky|almalinux|scientific) es_lt "$es_maj" 8 && ES_T="$ES_F_os_name (end of maintenance support)" ;;
    centos) case ${ES_F_os_name:-} in *Stream*) es_lt "$es_maj" 9 && ES_T="$ES_F_os_name (end of life)" ;; *) ES_T="$ES_F_os_name (CentOS Linux is end of life)" ;; esac ;;
    ubuntu) es_lt "$es_maj" 22 && ES_T="$ES_F_os_name (end of standard support)" ;;
    debian) es_lt "$es_maj" 12 && ES_T="$ES_F_os_name (end of support)" ;;
    sles|sled) es_lt "$es_maj" 15 && ES_T="$ES_F_os_name (end of general support)" ;;
    alpine) [ "$(es_vercmp "$es_v" 3.21)" = -1 ] && ES_T="$ES_F_os_name (branch no longer maintained)" ;;
    macos) es_lt "$es_maj" 15 && ES_T="${ES_F_os_name:-macOS} (no longer receives security updates)" ;;
    aix) [ "$(es_vercmp "$es_v" 7.2)" = -1 ] && ES_T="AIX $es_v (end of support)" ;;
    solaris) [ "$(es_vercmp "${ES_UNAME_R:-0}" 5.11)" = -1 ] && ES_T="Solaris $ES_UNAME_R (end of support)" ;;
  esac
  if [ -z "$ES_T" ] && [ "$ES_OS" = linux ] && [ -n "${ES_F_os_kernel:-}" ] && [ "$(es_vercmp "$ES_F_os_kernel" 3.10)" = -1 ]; then
    ES_T="Linux kernel $ES_F_os_kernel"
  fi
  if [ -z "$ES_T" ] && [ -n "${ES_F_bash_version:-}" ] && [ "$(es_vercmp "$ES_F_bash_version" 4.0)" = -1 ]; then
    ES_T="bash $ES_F_bash_version is the default bash (bash 4+ features such as associative arrays are missing)"
  fi
}

es_rules_platform() {
  if [ "$ES_OS" = linux ] && [ -n "${ES_F_libc_kind:-}" ]; then
    es_d="$ES_F_libc_kind ${ES_F_libc_version:-}"
    [ -n "${ES_F_glibcxx_max:-}" ] && es_d="$es_d; libstdc++ up to GLIBCXX_$ES_F_glibcxx_max"
    es_find native.libc "$es_d" "native.deps"
  fi
  es_am=
  [ "${ES_F_rosetta:-}" = true ] && es_am="the scanner shell runs under Rosetta 2 (x86_64 on arm64)"
  if [ "${ES_F_userland_bits:-}" = 32 ]; then
    case ${ES_F_os_arch:-$ES_ARCH} in x86_64|arm64|ppc64|ppc64le|s390x|sparc64) es_am="${es_am:+$es_am; }32-bit userland on a 64-bit kernel" ;; esac
  fi
  [ -n "${ES_F_arch_mismatch:-}" ] && es_am="${es_am:+$es_am; }runtime binaries: $ES_F_arch_mismatch (OS ${ES_F_os_arch:-$ES_ARCH})"
  [ -n "$es_am" ] && es_find arch.mismatch "$es_am" "os.identity|tools.inventory"
  [ "${ES_F_fips:-}" = true ] && es_find crypto.fips "FIPS mode enabled (kernel fips_enabled=1${ES_F_crypto_policy:+, crypto policy $ES_F_crypto_policy})" "sec.crypto"
  if [ "${ES_F_pending_reboot:-}" = true ]; then
    es_join "${ES_F_pending_reasons:-}" 3; es_find os.pending_reboot "${ES_T:-reboot pending}" "os.health"
  fi
  es_legacy
  [ -n "$ES_T" ] && es_find os.legacy "$ES_T" "os.identity|shell.info"
  if [ "${ES_F_container:-}" = true ]; then
    es_d="engine: ${ES_F_container_engine:-unknown}"
    [ "${ES_F_kubernetes:-}" = true ] && es_d="$es_d, Kubernetes"
    es_find container.detected "$es_d" "virt.platform"
  fi
  [ "${ES_F_root_ro:-}" = true ] && es_find container.readonly_root "/ is mounted read-only" "fs.mounts|sec.app_control"
  if [ "${ES_F_display:-}" = false ]; then
    case $ES_OS in darwin|cygwin) ;; *) es_find session.headless "DISPLAY and WAYLAND_DISPLAY are not set (session: ${ES_F_session_type:-unknown})" "session.context" ;; esac
  fi
  [ "${ES_F_python_found:-}" = false ] && es_find runtime.python_absent "no python3, python or python2 on PATH or in the known locations" "runtime.python"
  if es_is_num "${ES_F_shims_skipped:-}" && [ "$ES_F_shims_skipped" -gt 0 ]; then
    es_find runtime.shims_not_run "$ES_F_shims_skipped tool(s) resolve to shims that were not executed" "tools.inventory|runtime.version_managers"
  fi
  return 0
}

es_rules_limits() {
  if es_lt "${ES_F_nofile_soft:-}" "$ES_T_NOFILE_SOFT_MIN"; then
    es_find limits.nofile_low "soft limit $ES_F_nofile_soft (hard ${ES_F_nofile_hard:-unknown}); recommended at least $ES_T_NOFILE_SOFT_MIN" "limits.process"
  fi
  es_il=
  es_lt "${ES_F_inotify_watches:-}" "$ES_T_INOTIFY_WATCHES_MIN" && es_il="max_user_watches $ES_F_inotify_watches (< $ES_T_INOTIFY_WATCHES_MIN)"
  es_lt "${ES_F_inotify_instances:-}" "$ES_T_INOTIFY_INSTANCES_MIN" && es_il="${es_il:+$es_il; }max_user_instances $ES_F_inotify_instances (< $ES_T_INOTIFY_INSTANCES_MIN)"
  [ -n "$es_il" ] && es_find limits.inotify_low "$es_il" "limits.kernel"
  if es_lt "${ES_F_max_map_count:-}" "$ES_T_MAX_MAP_COUNT_MIN"; then
    es_find limits.max_map_count_low "vm.max_map_count $ES_F_max_map_count (< $ES_T_MAX_MAP_COUNT_MIN)" "limits.kernel"
  fi
  es_cl=
  if es_is_num "${ES_F_cg_mem:-}" && es_is_num "${ES_F_mem_total_mb:-}"; then
    es_cgmb=$((ES_F_cg_mem / 1048576))
    [ "$es_cgmb" -lt "$ES_F_mem_total_mb" ] && es_cl="memory limit $es_cgmb MB (host $ES_F_mem_total_mb MB)"
  fi
  if [ -n "${ES_F_cg_cpu:-}" ] && [ "$ES_F_cg_cpu" != max ] && es_is_num "${ES_F_cpu_logical:-}"; then
    es_lim=$(awk -v l="$ES_F_cpu_logical" -v f="$ES_T_CGROUP_CPU_FRACTION_WARN" 'BEGIN { print l * f }')
    es_flt "$ES_F_cg_cpu" "$es_lim" && es_cl="${es_cl:+$es_cl; }CPU quota $ES_F_cg_cpu cores (host $ES_F_cpu_logical logical CPUs)"
  fi
  [ -n "$es_cl" ] && es_find limits.cgroup "$es_cl" "limits.cgroup|hw.memory|hw.cpu"
  if es_lt "${ES_F_mem_avail_mb:-}" "$ES_T_MEMORY_MIN_MB"; then
    es_find limits.memory_low "$ES_F_mem_avail_mb MB available of ${ES_F_mem_total_mb:-unknown} MB" "hw.memory"
  elif [ -z "${ES_F_mem_avail_mb:-}" ] && es_lt "${ES_F_mem_total_mb:-}" "$ES_T_MEMORY_MIN_MB"; then
    es_find limits.memory_low "$ES_F_mem_total_mb MB total memory" "hw.memory"
  fi
  return 0
}

es_rules_fs_user() {
  es_ld=
  es_lt "${ES_F_free_home_mb:-}" "$ES_T_DISK_FREE_MIN_MB" && es_ld="home: $ES_F_free_home_mb MB free (< $ES_T_DISK_FREE_MIN_MB)"
  es_lt "${ES_F_free_tmp_mb:-}" "$ES_T_TEMP_FREE_MIN_MB" && es_ld="${es_ld:+$es_ld; }temp: $ES_F_free_tmp_mb MB free (< $ES_T_TEMP_FREE_MIN_MB)"
  [ -n "$es_ld" ] && es_find fs.low_disk "$es_ld" "fs.locations"
  case ${ES_F_symlink:-} in
    denied|error) es_find fs.symlinks_unavailable "ln -s in the temp directory: $ES_F_symlink${ES_F_symlink_detail:+ ($ES_F_symlink_detail)}" "fs.semantics" ;;
  esac
  [ "${ES_F_case_sensitive:-}" = false ] && es_find fs.case_insensitive "the temp directory's file system ignores case" "fs.semantics"
  [ "${ES_F_install_writable:-}" = false ] && es_has_facts fs.locations && es_find fs.no_writable_install_dir "none of HOME, ~/.local, ~/bin, /opt, /usr/local or the current directory is writable" "fs.locations"
  [ "${ES_F_is_admin:-}" = true ] && es_find user.is_admin "uid 0 (root)" "user.identity"
  [ "${ES_F_passwd_entry:-}" = false ] && es_find user.no_passwd_entry "uid ${ES_F_uid:-unknown} has no passwd entry" "user.identity"
  [ "${ES_F_home_network:-}" = true ] && es_find user.home_network "HOME is on ${ES_F_home_fstype:-a network file system}" "user.profile"
  if [ "${ES_F_encoding_utf8:-}" = false ] && [ -n "${ES_F_encoding:-}" ]; then
    es_find locale.non_utf8 "encoding $ES_F_encoding (locale ${ES_F_locale_name:-unknown})" "os.time_locale"
  fi
  [ "${ES_F_decimal_sep:-}" = , ] && es_find locale.decimal_comma "locale ${ES_F_locale_name:-unknown} uses ',' as decimal separator" "os.time_locale"
  return 0
}

es_rules_scan() {
  es_bad=$(awk -F '\t' '$3 ~ /^(partial|denied|timeout|error)$/ || $5 == "budget" { printf "%s%s", (n++ ? "|" : ""), $2 }' "$ES_TMP/results.tsv")
  if [ -n "$es_bad" ]; then
    es_find scan.partial "$(printf '%s' "$es_bad" | awk -F '|' '{ s = ""; for (i = 1; i <= NF; i++) s = s (i > 1 ? ", " : "") $i; printf "%d probe(s) not fully checked: %s", NF, s }')" "$es_bad"
  fi
}
