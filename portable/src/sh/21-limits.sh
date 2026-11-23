# ============================================================== probes: limits.*, net.ports

# es_ulimit FLAG... -> ES_T: first flag the shell's ulimit accepts ("" when none)
es_ulimit() {
  ES_T=
  for es_uf in "$@"; do
    ES_T=$(ulimit "$es_uf" 2>/dev/null) && [ -n "$ES_T" ] && return 0
    ES_T=
  done
  return 1
}

probe_limits_process() {
  es_ns=; es_nh=; es_ps=; es_ph=; es_stk=; es_core=; es_ml=; es_as=
  if [ -r "$ES_ROOT/proc/self/limits" ]; then
    es_src "read /proc/self/limits"
    es_lim=$(awk '
      NR == 1 { next }
      { name = substr($0, 1, 26); sub(/ +$/, "", name); soft = substr($0, 27, 21); hard = substr($0, 48, 21)
        gsub(/ /, "", soft); gsub(/ /, "", hard)
        if (name == "Max open files") { ns = soft; nh = hard }
        if (name == "Max processes") { ps = soft; ph = hard }
        if (name == "Max stack size") stk = soft
        if (name == "Max core file size") core = soft
        if (name == "Max locked memory") ml = soft
        if (name == "Max address space") as = soft }
      END { printf "%s %s %s %s %s %s %s %s\n", (ns == "" ? "-" : ns), (nh == "" ? "-" : nh), (ps == "" ? "-" : ps),
              (ph == "" ? "-" : ph), (stk == "" ? "-" : stk), (core == "" ? "-" : core), (ml == "" ? "-" : ml), (as == "" ? "-" : as) }' "$ES_ROOT/proc/self/limits")
    set -f; set -- $es_lim; set +f
    es_ns=${1:--}; es_nh=${2:--}; es_ps=${3:--}; es_ph=${4:--}; es_stk=${5:--}; es_core=${6:--}; es_ml=${7:--}; es_as=${8:--}
    [ "$es_ns" = - ] && es_ns=; [ "$es_nh" = - ] && es_nh=; [ "$es_ps" = - ] && es_ps=; [ "$es_ph" = - ] && es_ph=
    [ "$es_stk" = - ] && es_stk=; [ "$es_core" = - ] && es_core=; [ "$es_ml" = - ] && es_ml=; [ "$es_as" = - ] && es_as=
    es_is_num "$es_stk" && es_stk=$((es_stk / 1024))
    es_is_num "$es_ml" && es_ml=$((es_ml / 1024))
  fi
  es_src "shell builtin ulimit -a, -Sn, -Hn, -Su, -Hu"
  es_ua=$(ulimit -a 2>/dev/null)
  if [ -n "$es_ua" ]; then printf '%s\n' "$es_ua" >"$ES_P_DIR/ulimit.txt"; es_raw ulimit "$ES_P_DIR/ulimit.txt"; fi
  if [ -z "$es_ns" ]; then
    es_ulimit -Sn && es_ns=$ES_T
    es_ulimit -Hn && es_nh=$ES_T
    es_ulimit -Su -Sp && es_ps=$ES_T
    es_ulimit -Hu -Hp && es_ph=$ES_T
    es_ulimit -Ss && es_stk=$ES_T
    es_ulimit -Sc && { es_core=$ES_T; es_is_num "$es_core" && es_core=$((es_core * 512)); }
    es_ulimit -Sl && es_ml=$ES_T
    es_ulimit -Sv && { es_as=$ES_T; es_is_num "$es_as" && es_as=$((es_as * 1024)); }
  fi
  es_n nofile_soft "$es_ns"
  es_n nofile_hard "$es_nh"
  es_n nproc_soft "$es_ps"
  es_n nproc_hard "$es_ph"
  es_n stack_kb_soft "$es_stk"
  es_n core_soft "$es_core"
  es_n memlock_kb_soft "$es_ml"
  es_n address_space_soft "$es_as"
  es_s units "core_soft and address_space_soft in bytes; unlimited is the string unlimited"
  [ -n "$es_ns" ] || es_partial "open-file limit could not be read"
  es_fact nofile_soft "$es_ns"
  es_fact nofile_hard "$es_nh"
  es_fact nproc_soft "$es_ps"
}

probe_limits_kernel() {
  if [ ! -d "$ES_ROOT/proc/sys" ]; then
    if [ "$ES_OS" = darwin ] || [ "$ES_OS" = freebsd ]; then
      es_tool sysctl kern.maxfiles kern.maxfilesperproc kern.maxproc kern.maxprocperuid kern.ipc.somaxconn
      if [ -s "$ES_OUT_F" ]; then
        while IFS= read -r es_line; do
          es_k=${es_line%%:*}; es_trim "${es_line#*:}"
          case $es_k in
            kern.*) es_n "$es_k" "$ES_T"; [ "$es_k" = kern.ipc.somaxconn ] && es_fact somaxconn "$ES_T" ;;
          esac
        done <"$ES_OUT_F"
        return 0
      fi
    fi
    es_status not_applicable
    case $ES_OS in
      zos) es_note "no /proc/sys on z/OS UNIX; its kernel limits are BPXPRMxx parmlib settings (not read, needs operator commands)" ;;
      os400) es_note "no /proc/sys in IBM i PASE; process limits are in limits.process, system values are read with --deep" ;;
      *) es_note "no /proc/sys on this system" ;;
    esac
    return 0
  fi
  es_src "read /proc/sys/{fs,vm,kernel,user,net/core} tunables"
  for es_kv in fs.file-max:fs/file-max fs.file-nr:fs/file-nr \
      fs.inotify.max_user_watches:fs/inotify/max_user_watches fs.inotify.max_user_instances:fs/inotify/max_user_instances \
      vm.max_map_count:vm/max_map_count vm.overcommit_memory:vm/overcommit_memory vm.swappiness:vm/swappiness \
      kernel.pid_max:kernel/pid_max kernel.threads-max:kernel/threads-max kernel.yama.ptrace_scope:kernel/yama/ptrace_scope \
      kernel.unprivileged_userns_clone:kernel/unprivileged_userns_clone kernel.perf_event_paranoid:kernel/perf_event_paranoid \
      user.max_user_namespaces:user/max_user_namespaces net.core.somaxconn:net/core/somaxconn; do
    es_k=${es_kv%%:*}
    if es_read1 "$ES_ROOT/proc/sys/${es_kv#*:}"; then
      es_v=$(printf '%s' "$ES_L" | tr '\t' ' ')
      if es_is_num "$es_v"; then es_n "$es_k" "$es_v"; else es_s "$es_k" "$es_v"; fi
      case $es_k in
        fs.inotify.max_user_watches) es_fact inotify_watches "$es_v" ;;
        fs.inotify.max_user_instances) es_fact inotify_instances "$es_v" ;;
        vm.max_map_count) es_fact max_map_count "$es_v" ;;
        net.core.somaxconn) es_fact somaxconn "$es_v" ;;
      esac
    else
      es_z "$es_k"
    fi
  done
  if es_read1 "$ES_ROOT/sys/kernel/mm/transparent_hugepage/enabled"; then
    es_src "read /sys/kernel/mm/transparent_hugepage/enabled"
    es_thp=${ES_L#*\[}; es_thp=${es_thp%%\]*}
    es_s transparent_hugepage "$es_thp"
  else
    es_z transparent_hugepage
  fi
  : >"$ES_P_DIR/limits.txt"
  for es_f in "$ES_ROOT/etc/security/limits.conf" "$ES_ROOT"/etc/security/limits.d/*.conf; do
    [ -r "$es_f" ] || continue
    es_src "read ${es_f#"$ES_ROOT"}"
    es_text_ok "$es_f" || continue
    awk -v f="${es_f#"$ES_ROOT"}" '{ sub(/\r$/, "") } /^[ \t]*(#|$)/ { next } { gsub(/[ \t]+/, " "); print f ": " $0 }' "$ES_TXT" >>"$ES_P_DIR/limits.txt"
  done
  es_list_file limits_conf "$ES_P_DIR/limits.txt" l 200
  es_o systemd_default_limits
  : >"$ES_P_DIR/sysd.tsv"
  for es_f in "$ES_ROOT/etc/systemd/system.conf" "$ES_ROOT/etc/systemd/user.conf"; do
    [ -r "$es_f" ] || continue
    es_src "read ${es_f#"$ES_ROOT"} (DefaultLimit*)"
    es_scope=${es_f##*/}; es_scope=${es_scope%.conf}
    while IFS= read -r es_line || [ -n "$es_line" ]; do
      case $es_line in
        DefaultLimit*=*) es_trim "${es_line#*=}"; printf '%s\t%s\n' "$es_scope.${es_line%%=*}" "$ES_T" >>"$ES_P_DIR/sysd.tsv" ;;
      esac
    done <"$es_f"
  done
  # a setting repeated in the file: the last line wins (as in systemd), one JSON key each
  es_dedup_last "$ES_P_DIR/sysd.tsv"
  while IFS=$ES_TAB read -r es_k es_v; do es_s "$es_k" "$es_v"; done <"$ES_P_DIR/sysd.tsv"
  es_oe
}

# es_cg_min CURRENT NEW -> ES_T: smaller of two limits ("max" = unlimited)
es_cg_min() {
  ES_T=$1
  es_is_num "$2" || return 0
  if ! es_is_num "$1" || [ "$2" -lt "$1" ]; then ES_T=$2; fi
}

probe_limits_cgroup() {
  if [ ! -r "$ES_ROOT/proc/self/cgroup" ]; then
    es_status not_applicable
    es_note "no /proc/self/cgroup (not Linux)"
    return 0
  fi
  es_src "read /proc/self/cgroup"
  es_cgv=; es_path=; es_mem=; es_cpu=; es_pids=
  es_base="$ES_ROOT/sys/fs/cgroup"
  if [ -e "$es_base/cgroup.controllers" ]; then es_cgv=2
  elif [ -d "$es_base/memory" ] || [ -d "$es_base/cpu" ] || [ -d "$es_base/cpu,cpuacct" ]; then es_cgv=1
  fi
  if [ "$es_cgv" = 2 ]; then
    es_path=$(awk -F ':' '$1 == "0" && $2 == "" { print $3; exit }' "$ES_ROOT/proc/self/cgroup")
    [ -n "$es_path" ] || es_path=/
    es_src "read cgroup v2 memory.max, cpu.max, pids.max (own cgroup and parents)"
    es_p=$es_path; es_mem=max; es_cpu=max; es_pids=max
    while :; do
      es_d="$es_base${es_p%/}"
      [ "$es_p" = / ] && es_d=$es_base
      if [ -d "$es_d" ]; then
        if es_read1 "$es_d/memory.max"; then es_cg_min "$es_mem" "$ES_L"; es_mem=$ES_T; fi
        if es_read1 "$es_d/pids.max"; then es_cg_min "$es_pids" "$ES_L"; es_pids=$ES_T; fi
        if es_read1 "$es_d/cpu.max"; then
          set -- $ES_L
          if es_is_num "${1:-}" && es_is_num "${2:-}" && [ "$2" -gt 0 ]; then
            es_c=$(awk -v q="$1" -v p="$2" 'BEGIN { printf "%.2f\n", q / p }')
            if [ "$es_cpu" = max ] || [ "$(awk -v a="$es_c" -v b="$es_cpu" 'BEGIN { print (a < b) ? 1 : 0 }')" = 1 ]; then es_cpu=$es_c; fi
          fi
        fi
      fi
      [ "$es_p" = / ] && break
      es_p=${es_p%/*}; [ -n "$es_p" ] || es_p=/
    done
  elif [ "$es_cgv" = 1 ]; then
    es_src "read cgroup v1 memory.limit_in_bytes, cpu.cfs_quota_us, cpu.cfs_period_us, pids.max"
    es_mp=$(awk -F ':' '$2 ~ /(^|,)memory(,|$)/ { print $3; exit }' "$ES_ROOT/proc/self/cgroup")
    es_cp=$(awk -F ':' '$2 ~ /(^|,)cpu(,|$)/ { print $2 ":" $3; exit }' "$ES_ROOT/proc/self/cgroup")
    es_pp=$(awk -F ':' '$2 ~ /(^|,)pids(,|$)/ { print $3; exit }' "$ES_ROOT/proc/self/cgroup")
    es_path=$es_mp
    for es_d in "$es_base/memory$es_mp" "$es_base/memory"; do
      if es_read1 "$es_d/memory.limit_in_bytes"; then
        es_mem=$ES_L
        case $es_mem in 9223372036854[0-9]*) es_mem=max ;; esac
        break
      fi
    done
    es_cctl=${es_cp%%:*}; es_cpath=${es_cp#*:}
    for es_d in "$es_base/$es_cctl$es_cpath" "$es_base/$es_cctl" "$es_base/cpu$es_cpath" "$es_base/cpu"; do
      if es_read1 "$es_d/cpu.cfs_quota_us"; then
        es_q=$ES_L; es_per=100000
        es_read1 "$es_d/cpu.cfs_period_us" && es_per=$ES_L
        if [ "$es_q" = -1 ]; then es_cpu=max
        elif es_is_num "$es_q" && es_is_num "$es_per" && [ "$es_per" -gt 0 ]; then
          es_cpu=$(awk -v q="$es_q" -v p="$es_per" 'BEGIN { printf "%.2f\n", q / p }')
        fi
        break
      fi
    done
    for es_d in "$es_base/pids$es_pp" "$es_base/pids"; do
      if es_read1 "$es_d/pids.max"; then es_pids=$ES_L; break; fi
    done
  fi
  es_raw cgroup "$ES_ROOT/proc/self/cgroup"
  es_n version "$es_cgv"
  es_sn path "$es_path"
  case $es_mem in max) es_s memory_max_bytes unlimited ;; *) es_n memory_max_bytes "$es_mem" ;; esac
  case $es_cpu in max) es_s cpu_quota_cores unlimited ;; *) es_n cpu_quota_cores "$es_cpu" ;; esac
  case $es_pids in max) es_s pids_max unlimited ;; *) es_n pids_max "$es_pids" ;; esac
  [ -n "$es_cgv" ] || es_partial "cgroup file system not found under /sys/fs/cgroup"
  es_fact cg_version "$es_cgv"
  es_fact cg_mem "$es_mem"
  es_fact cg_cpu "$es_cpu"
  es_fact cg_pids "$es_pids"
}

probe_net_ports() {
  es_es=; es_ee=; es_ups=
  if es_read1 "$ES_ROOT/proc/sys/net/ipv4/ip_local_port_range"; then
    es_src "read /proc/sys/net/ipv4/ip_local_port_range"
    set -- $ES_L; es_es=${1:-}; es_ee=${2:-}
  fi
  if es_read1 "$ES_ROOT/proc/sys/net/ipv4/ip_unprivileged_port_start"; then
    es_src "read /proc/sys/net/ipv4/ip_unprivileged_port_start"; es_ups=$ES_L
  fi
  es_res=
  if es_read1 "$ES_ROOT/proc/sys/net/ipv4/ip_local_reserved_ports"; then
    es_src "read /proc/sys/net/ipv4/ip_local_reserved_ports"; es_res=$ES_L
  fi
  if [ -z "$es_es" ]; then
    case $ES_OS in
      darwin|freebsd)
        es_tool sysctl -n net.inet.ip.portrange.first net.inet.ip.portrange.last
        if [ -s "$ES_OUT_F" ]; then
          { IFS= read -r es_es; IFS= read -r es_ee; } <"$ES_OUT_F"
        fi ;;
    esac
  fi
  es_o ephemeral
  es_n start "$es_es"; es_n end "$es_ee"
  es_oe
  es_a excluded_tcp
  if [ -n "$es_res" ]; then
    es_sifs=$IFS; IFS=,
    for es_r in $es_res; do
      es_o -; es_n start "${es_r%-*}"; es_n end "${es_r#*-}"; es_oe
    done
    IFS=$es_sifs
  fi
  es_ae
  es_n unprivileged_port_start "$es_ups"
  es_z urlacl_count
  [ -n "$es_es" ] || es_partial "ephemeral port range not found"
  es_fact eph_start "$es_es"
  es_fact eph_end "$es_ee"
  es_fact reserved_ports "$es_res"
}
