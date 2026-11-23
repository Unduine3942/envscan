# ============================================================== probes: net.*

# awk functions for /proc/net/route, tcp and tcp6, which print each 32-bit address word in the
# host's byte order (run with -v be=$ES_PROC_BE): net32(x) puts such a word of 8 hex digits into
# network order, ip4(x) decodes it as a dotted IPv4 address
ES_AWK_PROCNET='function net32(x) { x = toupper(x); return be ? x : substr(x, 7, 2) substr(x, 5, 2) substr(x, 3, 2) substr(x, 1, 2) }
function ip4(x,   n) { n = net32(x); return H[substr(n, 1, 2)] "." H[substr(n, 3, 2)] "." H[substr(n, 5, 2)] "." H[substr(n, 7, 2)] }
BEGIN { for (i = 0; i < 256; i++) H[sprintf("%02X", i)] = i }
'

# es_proc_be -> ES_PROC_BE: 1 on a big-endian host (s390x, ppc64, sparc, mips), else 0; read
# from the ELF header of /proc/self/exe (the reading process), else from the machine name
es_proc_be() {
  ES_PROC_BE=0
  es_ei=$(od -An -tx1 -N6 "$ES_ROOT/proc/self/exe" 2>/dev/null | tr -d ' \t\n')
  case $es_ei in
    7f454c46??01) return 0 ;;
    7f454c46??02) ES_PROC_BE=1; return 0 ;;
  esac
  case ${ES_UNAME_M:-} in
    s390*|ppc|ppc64|powerpc|powerpc64|sparc*|mips|mips64|m68k|parisc*|hppa*|aarch64_be|armeb|armv*b|or1k) ES_PROC_BE=1 ;;
  esac
  return 0
}

# es_proc_gateways -> ES_T: "gateway TAB interface" lines for default routes in /proc/net/route
# (0.0.0.0/0, and the 0.0.0.0/1 + 128.0.0.0/1 pair of full-tunnel VPNs)
es_proc_gateways() {
  ES_T=
  [ -r "$ES_ROOT/proc/net/route" ] || return 1
  es_proc_be
  ES_T=$(awk -v be="$ES_PROC_BE" "$ES_AWK_PROCNET"'
    NR > 1 && NF >= 8 {
      d = ip4($2); m = ip4($8)
      if (!((d == "0.0.0.0" && (m == "0.0.0.0" || m == "128.0.0.0")) || (d == "128.0.0.0" && m == "128.0.0.0"))) next
      if (toupper($3) == "00000000") { printf "(on-link)\t%s\n", $1; next }
      printf "%s\t%s\n", ip4($3), $1 }' "$ES_ROOT/proc/net/route" | awk '!s[$0]++')
  return 0
}

probe_net_interfaces() {
  : >"$ES_P_DIR/ifaces.tsv"
  es_how=
  if es_tool ip -o link && [ -s "$ES_OUT_F" ]; then
    es_how=ip
    cp "$ES_OUT_F" "$ES_P_DIR/link.txt"
    es_need ip -o addr || :
    awk -v lf="$ES_P_DIR/link.txt" '
      BEGIN { while ((getline l < lf) > 0) { n = split(l, F, " "); nm = F[2]; sub(/:$/, "", nm); sub(/@.*/, "", nm)
                ord[++cnt] = nm; st[nm] = "-"; mac[nm] = "-"; mtu[nm] = "-"
                for (i = 3; i <= n; i++) { if (F[i] == "mtu") mtu[nm] = F[i + 1]; if (F[i] == "state") st[nm] = F[i + 1]; if (F[i] ~ /^link\//) mac[nm] = F[i + 1] } } }
      { nm = $2; sub(/:$/, "", nm); sub(/@.*/, "", nm); if ($3 == "inet" || $3 == "inet6") addr[nm] = addr[nm] (addr[nm] == "" ? "" : ",") $4 }
      END { for (i = 1; i <= cnt; i++) { nm = ord[i]; print nm "\t" mtu[nm] "\t" mac[nm] "\t" st[nm] "\t" (addr[nm] == "" ? "-" : addr[nm]) } }' "$ES_OUT_F" >"$ES_P_DIR/ifaces.tsv"
  elif es_tool ifconfig -a && [ -s "$ES_OUT_F" ]; then
    es_how=ifconfig
    awk '
      /^[^ \t]/ { nm = $1; sub(/:$/, "", nm); ord[++cnt] = nm; mtu[nm] = "-"; mac[nm] = "-"; st[nm] = ($0 ~ /[<,]UP[,>]|[ \t]UP[ \t]/) ? "UP" : "DOWN" }
      { for (i = 1; i <= NF; i++) {
          if ($i == "mtu") mtu[nm] = $(i + 1); else if ($i ~ /^MTU:/) { v = $i; sub(/^MTU:/, "", v); mtu[nm] = v }
          if ($i == "ether" || $i == "HWaddr" || $i == "lladdr") mac[nm] = $(i + 1)
          if ($i == "inet" || $i == "inet6") { a = $(i + 1); if (a == "addr:") a = $(i + 2); sub(/^addr:/, "", a); if (a != "") addr[nm] = addr[nm] (addr[nm] == "" ? "" : ",") a }
        } }
      END { for (i = 1; i <= cnt; i++) { nm = ord[i]; print nm "\t" mtu[nm] "\t" mac[nm] "\t" st[nm] "\t" (addr[nm] == "" ? "-" : addr[nm]) } }' "$ES_OUT_F" >"$ES_P_DIR/ifaces.tsv"
  elif [ -r "$ES_ROOT/proc/net/dev" ]; then
    es_how=proc
    es_src "read /proc/net/dev"
    awk -F ':' 'NR > 2 { n = $1; gsub(/ /, "", n); print n "\t-\t-\t-\t-" }' "$ES_ROOT/proc/net/dev" >"$ES_P_DIR/ifaces.tsv"
  fi
  es_gws=
  if es_proc_gateways; then es_src "read /proc/net/route (default gateways)"; es_gws=$ES_T; fi
  es_a interfaces
  while IFS=$ES_TAB read -r es_nm es_mtu es_mac es_st es_addr; do
    es_o -
    es_s name "$es_nm"; es_z description
    es_a addresses
    if [ "$es_addr" != - ]; then
      es_r=$es_addr
      while [ -n "$es_r" ]; do es_s - "${es_r%%,*}"; case $es_r in *,*) es_r=${es_r#*,} ;; *) es_r= ;; esac; done
    fi
    es_ae
    [ "$es_mac" = - ] && es_mac=; [ "$es_mtu" = - ] && es_mtu=; [ "$es_st" = - ] && es_st=
    es_sn mac "$es_mac"; es_n mtu "$es_mtu"; es_sn state "$es_st"
    es_a gateways
    es_r=$es_gws
    while [ -n "$es_r" ]; do
      es_l=${es_r%%"$ES_NL"*}; case $es_r in *"$ES_NL"*) es_r=${es_r#*"$ES_NL"} ;; *) es_r= ;; esac
      [ "${es_l#*"$ES_TAB"}" = "$es_nm" ] && es_s - "${es_l%%"$ES_TAB"*}"
    done
    es_ae
    es_a dns; es_ae
    es_z dhcp
    es_oe
  done <"$ES_P_DIR/ifaces.tsv"
  es_ae
  if [ -z "$es_how" ] && [ "$ES_OS" = zos ] && es_tool onetstat -h && [ -s "$ES_OUT_F" ]; then
    es_raw onetstat_h "$ES_OUT_F"
    es_partial "z/OS: the home addresses are in raw.onetstat_h; interfaces are not parsed (tier 2, unverified)"
  elif [ -z "$es_how" ]; then
    if [ "$ES_OS" = cygwin ]; then es_partial "no ip or ifconfig under Cygwin/MSYS; envscan.ps1 reports Windows interfaces"
    else es_partial "no ip, ifconfig or /proc/net/dev available"; fi
  fi
  es_note "per-interface DNS servers are not tracked on Unix; see net.dns"
}

# es_ip_defaults FILE: "gateway dev iface" lines for the default routes in ip route output,
# including a full tunnel's /1 halves and the nexthop lines of a multipath default
es_ip_defaults() {
  awk 'function gw(   i, g, d) {
        g = ""; d = ""
        for (i = 1; i <= NF; i++) {
          if ($i == "via") { g = $(i + 1); if (g == "inet" || g == "inet6") g = $(i + 2) }
          if ($i == "dev") d = $(i + 1)
        }
        if (g == "" && d == "") return ""
        return (g == "" ? "(on-link)" : g) (d == "" ? "" : " dev " d)
      }
      $1 == "default" || $1 == "0.0.0.0/1" || $1 == "128.0.0.0/1" || $1 == "::/1" || $1 == "8000::/1" {
        r = gw(); mp = (r == ""); if (r != "") print r; next }
      mp && $1 == "nexthop" { r = gw(); if (r != "") print r; next }
      { mp = 0 }' "$1" | awk '!s[$0]++'
}

# es_route_get_default FILE: the default route from BSD/macOS "route -n get" output
es_route_get_default() {
  awk '/gateway:/ { g = $2 } /interface:/ { d = $2 } END { if (g != "" || d != "") print (g == "" ? "(on-link)" : g) (d == "" ? "" : " dev " d) }' "$1"
}

# es_route_get [-inet6]: "route -n get [-inet6] default" -> ES_T, the default route ("" when the
# routing table has none: "not in table"); fails when the family could not be checked (no route
# command, another error, a timeout), which is unknown, not "no default route"
es_route_get() {
  es_tool route -n get "$@" default
  ES_T=
  case $ES_RC in
    0) ES_T=$(es_route_get_default "$ES_OUT_F"); return 0 ;;
    126|127) return 1 ;;
  esac
  [ "$ES_TIMED_OUT" != 1 ] && grep -i 'not in table' "$ES_OUT_F" "$ES_ERR_F" >/dev/null 2>&1
}

# es_proc_routes -> ES_T: /proc/net/route decoded like ip route ("default via 10.0.0.1 dev eth0
# metric 100", "10.0.0.0/16 dev eth0"); Destination, Gateway and Mask are hex words in host byte
# order (es_proc_be runs first, in es_proc_gateways), the prefix length is the mask's bit count
es_proc_routes() {
  ES_T=$(awk -v be="$ES_PROC_BE" "$ES_AWK_PROCNET"'
    BEGIN { for (i = 0; i < 256; i++) { b = 0; v = i; while (v > 0) { b += v % 2; v = int(v / 2) }; B[sprintf("%02X", i)] = b } }
    NR > 1 && NF >= 8 && length($2) == 8 && length($3) == 8 && length($8) == 8 {
      m = toupper($8); p = B[substr(m, 1, 2)] + B[substr(m, 3, 2)] + B[substr(m, 5, 2)] + B[substr(m, 7, 2)]
      d = ip4($2)
      r = (d == "0.0.0.0" && p == 0) ? "default" : d "/" p
      if (toupper($3) != "00000000") r = r " via " ip4($3)
      print r " dev " $1 (($7 + 0) > 0 ? " metric " ($7 + 0) : "") }' "$ES_ROOT/proc/net/route")
}

probe_net_routes() {
  es_gw=; es_routes=; es_how=; es_how6=
  if es_tool ip route && [ "$ES_RC" = 0 ]; then
    es_how=ip
    es_routes=$(awk 'NF' "$ES_OUT_F")
    es_gw=$(es_ip_defaults "$ES_OUT_F")
    if es_tool ip -6 route && [ "$ES_RC" = 0 ]; then
      es_how6=ip
      es_r6=$(awk 'NF' "$ES_OUT_F"); es_g6=$(es_ip_defaults "$ES_OUT_F")
      es_routes="$es_routes${es_r6:+$ES_NL$es_r6}"
      es_gw="$es_gw${es_g6:+$ES_NL$es_g6}"
    fi
  elif es_proc_gateways; then
    es_how=proc
    es_src "read /proc/net/route"
    es_gw=$(printf '%s\n' "$ES_T" | awk -F '\t' 'NF { print $1 " dev " $2 }')
    es_proc_routes; es_routes=$ES_T
  else
    case $ES_OS in
      darwin|freebsd|openbsd|netbsd|sunos|aix|os400)
        if es_route_get; then es_how=route; es_gw=$ES_T; es_raw route "$ES_OUT_F"; fi
        if es_route_get -inet6; then es_how6=route; es_gw="$es_gw${ES_T:+${es_gw:+$ES_NL}$ES_T}"; fi ;;
    esac
  fi
  # IPv6 from /proc when ip -6 route did not run: default routes (::/0) other than the reject
  # route on lo; the next hop as eight groups (leading zeros dropped, no :: compression)
  if [ -z "$es_how6" ] && [ -r "$ES_ROOT/proc/net/ipv6_route" ]; then
    es_how6=proc
    es_src "read /proc/net/ipv6_route"
    es_g6=$(awk '$1 == "00000000000000000000000000000000" && $2 == "00" && $10 != "lo" && NF >= 10 {
        g = $5
        if (g == "00000000000000000000000000000000") { print "(on-link) dev " $10; next }
        r = ""; for (i = 0; i < 8; i++) { h = substr(g, i * 4 + 1, 4); sub(/^0+/, "", h); if (h == "") h = "0"; r = r (i ? ":" : "") h }
        print r " dev " $10 }' "$ES_ROOT/proc/net/ipv6_route" | awk '!s[$0]++')
    es_gw="$es_gw${es_g6:+${es_gw:+$ES_NL}$es_g6}"
  fi
  es_list default_gateways "$es_gw"
  es_list routes "$es_routes"
  es_a families_checked
  [ -n "$es_how" ] && es_s - ipv4
  [ -n "$es_how6" ] && es_s - ipv6
  es_ae
  # no default route is concluded only when both address families were checked
  es_dr=
  if [ -n "$es_gw" ]; then es_dr=true
  elif [ -n "$es_how" ] && [ -n "$es_how6" ]; then es_dr=false
  elif [ -n "$es_how" ]; then es_note "no IPv4 default route; IPv6 routes could not be checked"
  fi
  es_b default_route "$es_dr"
  if [ -z "$es_how" ]; then
    es_partial "no quiet routing source (ip, /proc/net/route, route get); netstat is only used with --deep"
  fi
  es_fact default_route "$es_dr"
  es_fact gateways "$es_gw"
}

probe_net_dns() {
  es_sv=; es_se=; es_opt=; es_order=
  if [ -r "$ES_ROOT/etc/resolv.conf" ]; then
    es_src "read /etc/resolv.conf"
    es_sv=$(awk '$1 == "nameserver" { print $2 }' "$ES_ROOT/etc/resolv.conf")
    es_se=$(awk '$1 == "search" || $1 == "domain" { for (i = 2; i <= NF; i++) print $i }' "$ES_ROOT/etc/resolv.conf")
    es_opt=$(awk '$1 == "options" { for (i = 2; i <= NF; i++) print $i }' "$ES_ROOT/etc/resolv.conf")
  fi
  es_stub=false
  case "$ES_NL$es_sv$ES_NL" in *"${ES_NL}127.0.0.53$ES_NL"*|*"${ES_NL}127.0.0.54$ES_NL"*) es_stub=true ;; esac
  es_up=
  if [ "$es_stub" = true ] && [ -r "$ES_ROOT/run/systemd/resolve/resolv.conf" ]; then
    es_src "read /run/systemd/resolve/resolv.conf (systemd-resolved upstream servers)"
    es_up=$(awk '$1 == "nameserver" { print $2 }' "$ES_ROOT/run/systemd/resolve/resolv.conf")
  fi
  if [ "$ES_OS" = darwin ] && es_tool scutil --dns; then
    es_raw scutil_dns "$ES_OUT_F"
    es_sv=$(awk -F ' : ' '/nameserver\[[0-9]+\]/ { print $2 }' "$ES_OUT_F" | awk '!s[$0]++')
    es_se=$(awk -F ' : ' '/search domain\[[0-9]+\]/ { print $2 }' "$ES_OUT_F" | awk '!s[$0]++')
  fi
  if [ -r "$ES_ROOT/etc/nsswitch.conf" ]; then
    es_src "read /etc/nsswitch.conf"
    es_order=$(awk '$1 == "hosts:" { $1 = ""; sub(/^ +/, ""); print; exit }' "$ES_ROOT/etc/nsswitch.conf")
  fi
  : >"$ES_P_DIR/hosts.txt"
  if [ -r "$ES_ROOT/etc/hosts" ]; then
    es_src "read /etc/hosts"
    if es_text_ok "$ES_ROOT/etc/hosts"; then
    awk '{ sub(/\r$/, ""); sub(/#.*/, ""); gsub(/[ \t]+/, " "); sub(/^ /, ""); sub(/ $/, "") } NF' "$ES_TXT" >"$ES_P_DIR/hosts.txt"
    fi
  fi
  es_list servers "$es_sv"
  es_list upstream_servers "$es_up"
  es_b systemd_resolved_stub "$es_stub"
  es_list search "$es_se"
  es_list options "$es_opt"
  es_list_lines hosts_entries "$ES_P_DIR/hosts.txt" s 200
  es_sn resolver_order "$es_order"
  [ -n "$es_sv" ] || es_partial "no DNS servers found"
  es_fact dns_servers "${es_up:-$es_sv}"
  es_fact dns_search "$es_se"
}

# es_hostport TEXT -> ES_T: "host:port" for a proxy URL or host:port value ("" when none)
es_hostport() {
  ES_T=$(printf '%s\n' "$1" | awk '{
    s = $0; gsub(/["'"'"']/, "", s); sub(/^[^=\/:]*=[ \t]*/, "", s); sub(/;$/, "", s)
    if (match(s, /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9+.-]*:\/\/[^\/ \t]+/)) {
      u = substr(s, RSTART, RLENGTH); sch = tolower(u); sub(/:\/\/.*/, "", sch); hp = u; sub(/^[^:]*:\/\//, "", hp); sub(/^.*@/, "", hp)
      if (hp !~ /:[0-9]+$/) hp = hp ":" (sch == "https" ? 443 : (sch ~ /^socks/ ? 1080 : 80))
      print hp; exit }
    if (match(s, /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9.-]+:[0-9]+$/)) { print s; exit } }')
}

# es_proxy_settings [FILE...]: the proxy settings in "source TAB text" lines, found by the name of
# the setting (proxy.awk): "source TAB kind TAB endpoint TAB key TAB value TAB text"
es_proxy_settings() { awk -f "$ES_TMP/proxy.awk" "$@" 2>/dev/null; }

# es_proxy_found KIND ENDPOINT: count a proxy setting (kind "proxy") and its endpoint
es_proxy_found() {
  [ "$1" = proxy ] || return 0
  es_any=true
  [ "$2" != - ] && es_hosts="$es_hosts$2$ES_NL"
  return 0
}

# es_proxy_macos: the system proxy of macOS (scutil --proxy) as the "macos" object; counts it
es_proxy_macos() {
  es_tool scutil --proxy || return 0
  es_raw scutil_proxy "$ES_OUT_F"
  es_o macos
  while IFS= read -r es_line; do
    es_k=${es_line%% :*}; es_trim "$es_k"; es_k=$ES_T
    es_trim "${es_line#* : }"; es_v=$ES_T
    case $es_k in
      HTTPEnable|HTTPSEnable|ProxyAutoConfigEnable|SOCKSEnable) es_n "$es_k" "$es_v" ;;
      HTTPProxy|HTTPSProxy|SOCKSProxy|ProxyAutoConfigURLString) es_s "$es_k" "$es_v"; es_any=true ;;
      HTTPPort|HTTPSPort|SOCKSPort) es_n "$es_k" "$es_v" ;;
    esac
  done <"$ES_OUT_F"
  es_oe
  es_mh=$(awk '/HTTPSProxy :|HTTPProxy :/ { h = $3 } /HTTPSPort :|HTTPPort :/ { p = $3 } END { if (h != "") print h ":" (p == "" ? 80 : p) }' "$ES_OUT_F")
  [ -n "$es_mh" ] && es_hosts="$es_hosts$es_mh$ES_NL"
  return 0
}

probe_net_proxy() {
  es_src "environment proxy variables"
  es_hosts=; es_any=false
  es_o env
  for es_v in $ES_PROXY_ENV; do
    eval "es_vv=\${$es_v-}"
    [ -n "$es_vv" ] || continue
    es_e "$es_v" "$es_vv"
    case $es_v in no_proxy|NO_PROXY) ;; *) es_any=true; es_hostport "$es_vv"; [ -n "$ES_T" ] && es_hosts="$es_hosts$ES_T$ES_NL" ;; esac
  done
  es_oe
  : >"$ES_P_DIR/sys.in"
  for es_f in "$ES_ROOT/etc/environment" "$ES_ROOT/etc/apt/apt.conf" "$ES_ROOT"/etc/apt/apt.conf.d/* "$ES_ROOT/etc/yum.conf" "$ES_ROOT/etc/dnf/dnf.conf"; do
    [ -f "$es_f" ] && [ -r "$es_f" ] || continue
    es_src "read ${es_f#"$ES_ROOT"} (proxy settings)"
    es_text_ok "$es_f" || continue
    awk -v f="${es_f#"$ES_ROOT"}" '{ print f "\t" $0 }' "$ES_TXT" >>"$ES_P_DIR/sys.in"
  done
  # no pipeline: es_text_prep must run in this shell (decoded copies, probe status)
  es_proxy_settings <"$ES_P_DIR/sys.in" >"$ES_P_DIR/sys.tsv"
  rm -f "$ES_P_DIR/sys.in"
  es_o system
  es_a files
  while IFS=$ES_TAB read -r es_f es_kd es_ep es_k es_vl es_line; do
    es_o -; es_s file "$es_f"; es_l line "$es_line"; es_oe
    es_proxy_found "$es_kd" "$es_ep"
  done <"$ES_P_DIR/sys.tsv"
  es_ae
  [ "$ES_OS" = darwin ] && es_proxy_macos
  es_oe
  es_a package_managers
  if [ -s "$ES_TMP/pkg_proxy.tsv" ]; then
    es_src "package-manager proxy settings found by pkg.sources"
    while IFS=$ES_TAB read -r es_f es_kd es_ep es_k es_vl es_line; do
      [ "$es_vl" = - ] && es_vl=
      # the package manager (pkg.sources' configs spec), as envscan.ps1 writes it
      es_tl=$(awk -F '\t' -v f="$es_f" '$1 == f { print $2; exit }' "$ES_TMP/pkg_tools.tsv" 2>/dev/null)
      case $es_f in git:*) es_tl=git ;; esac
      [ -n "$es_tl" ] || es_tl=${es_f##*/}
      es_o -; es_s tool "$es_tl"; es_s setting "$es_k"; es_v value "$es_k" "$es_vl"; es_s file "$es_f"; es_oe
      es_proxy_found "$es_kd" "$es_ep"
    done <"$ES_TMP/pkg_proxy.tsv"
  fi
  es_ae
  es_z winhttp; es_z wininet
  # the raw proxy settings (system files and pkg.sources) are not needed any more
  rm -f "$ES_P_DIR/sys.tsv" "$ES_TMP/pkg_proxy.tsv" "$ES_TMP/pkg_tools.tsv"
  es_hosts=$(printf '%s' "$es_hosts" | awk 'NF && !s[$0]++')
  es_list proxy_endpoints "$es_hosts"
  es_b proxy_configured "$es_any"
  es_fact proxy "$es_any"
  es_fact proxy_hosts "$es_hosts"
}

probe_net_listening() {
  if [ ! -r "$ES_ROOT/proc/net/tcp" ] && [ ! -r "$ES_ROOT/proc/net/tcp6" ]; then
    es_status not_applicable
    es_note "no quiet source of listening sockets on this system (no /proc/net/tcp); run with --deep for netstat"
    es_a tcp; es_ae
    return 0
  fi
  : >"$ES_P_DIR/listen.tsv"
  es_proc_be
  for es_f in "$ES_ROOT/proc/net/tcp" "$ES_ROOT/proc/net/tcp6"; do
    [ -r "$es_f" ] || continue
    es_src "read ${es_f#"$ES_ROOT"} (LISTEN state)"
    # the port is printed in network order, each 32-bit word of the address in host order
    awk -v be="$ES_PROC_BE" "$ES_AWK_PROCNET"'
      NR > 1 && $4 == "0A" {
        split($2, A, ":"); a = toupper(A[1]); p = toupper(A[2]); port = H[substr(p, 1, 2)] * 256 + H[substr(p, 3, 2)]
        if (length(a) == 8) ip = ip4(a)
        else {
          n = net32(substr(a, 1, 8)) net32(substr(a, 9, 8)) net32(substr(a, 17, 8)) net32(substr(a, 25, 8))
          ip = ""; for (w = 0; w < 8; w++) ip = ip (w ? ":" : "") tolower(substr(n, w * 4 + 1, 4))
          if (ip == "0000:0000:0000:0000:0000:0000:0000:0000") ip = "::"
          else if (ip == "0000:0000:0000:0000:0000:0000:0000:0001") ip = "::1"
          else if (substr(ip, 1, 30) == "0000:0000:0000:0000:0000:ffff:") ip = "::ffff:" H[substr(n, 25, 2)] "." H[substr(n, 27, 2)] "." H[substr(n, 29, 2)] "." H[substr(n, 31, 2)]
        }
        k = ip " " port; if (!(k in s)) { s[k] = 1; print ip "\t" port }
      }' "$es_f" >>"$ES_P_DIR/listen.tsv"
  done
  es_a tcp
  es_ports=
  while IFS=$ES_TAB read -r es_ip es_port; do
    es_o -; es_s address "$es_ip"; es_n port "$es_port"; es_z pid; es_z process; es_oe
    es_ports="$es_ports $es_port"
  done <"$ES_P_DIR/listen.tsv"
  es_ae
  es_note "process names need root or a socket-to-process sweep; pid and process are null"
  es_fact listen_ports "$es_ports"
}

probe_net_netstat() {
  if es_tool netstat -an; then :
  elif es_tool ss -an; then :
  else
    es_status not_found
    es_note "neither netstat nor ss is available"
    return 0
  fi
  es_raw socket_table "$ES_OUT_F"
  awk '/LISTEN/ { l = ""; for (i = 1; i <= NF; i++) if ($i ~ /[.:][0-9]+$/) { l = $i; break } if (l != "") print $1 "\t" l }' "$ES_OUT_F" | awk '!s[$0]++' >"$ES_P_DIR/ns.tsv"
  es_a listening
  while IFS=$ES_TAB read -r es_p es_l; do es_o -; es_s proto "$es_p"; es_s local "$es_l"; es_oe; done <"$ES_P_DIR/ns.tsv"
  es_ae
}

probe_net_firewall() {
  es_ufw=; es_fw=; es_nft=; es_ipt=; es_alf=
  if [ -r "$ES_ROOT/etc/ufw/ufw.conf" ]; then
    es_src "read /etc/ufw/ufw.conf"
    es_ufw=$(awk -F '=' '$1 == "ENABLED" { v = tolower($2); gsub(/[" \t]/, "", v); print (v == "yes" ? "enabled" : "disabled"); exit }' "$ES_ROOT/etc/ufw/ufw.conf")
  fi
  if es_tool systemctl is-active firewalld nftables iptables; then :; fi
  if [ -s "$ES_OUT_F" ] && [ "$ES_RC" != 127 ] && [ "$ES_RC" != 126 ]; then
    { IFS= read -r es_fw; IFS= read -r es_nft; IFS= read -r es_ipt; } <"$ES_OUT_F"
    case $es_fw in active|inactive|failed|unknown|activating) ;; *) es_fw=; es_nft=; es_ipt= ;; esac
  fi
  if [ "$ES_OS" = darwin ] && [ -x "$ES_ROOT/usr/libexec/ApplicationFirewall/socketfilterfw" ]; then
    es_cmd "$ES_ROOT/usr/libexec/ApplicationFirewall/socketfilterfw" --getglobalstate
    if es_read1 "$ES_OUT_F"; then
      case $ES_L in *enabled*) es_alf=enabled ;; *disabled*) es_alf=disabled ;; *) es_alf=$ES_L ;; esac
    fi
  fi
  es_sn ufw "$es_ufw"
  es_sn firewalld "$es_fw"
  es_sn nftables "$es_nft"
  es_sn iptables "$es_ipt"
  es_sn macos_alf "$es_alf"
  es_z profiles
  es_note "firewall rules need root; only configuration files and service states were read"
  case $ES_OS in
    zos) es_note "z/OS: IP filtering and Communications Server policy are not read" ;;
    os400) es_note "IBM i: IP packet rules and NAT are not read" ;;
  esac
  if [ -z "$es_ufw$es_fw$es_alf" ] && [ "$ES_OS" != cygwin ]; then es_partial "no firewall service state could be read"; fi
  [ "$ES_OS" = cygwin ] && es_note "Windows Firewall is reported by envscan.ps1"
  return 0
}
