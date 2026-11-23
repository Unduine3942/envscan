# ============================================================== probes: net.reachability (--net)
# Only proxies and internal mirrors found in local configuration (net.proxy, pkg.sources) are
# checked. Public registries (ES_PUBLIC_HOSTS) are never looked up; cloud metadata and
# link-local hosts (ES_NET_NEVER) are never looked up or contacted, also when a configured name
# resolves to one (DNS rebinding): the TCP check connects to the vetted address, never to the
# name, so nothing resolves the name a second time. An IPv6 address is contacted only in the
# global unicast and unique-local ranges (es_ip6_ok), an IPv4 address only in the private and
# shared ranges (es_ip4_ok). A target that could not be checked (no resolver, a failed lookup)
# makes the probe partial. A host name is looked up only in its absolute form (es_lookup_name: one
# trailing dot added), so no DNS search list, ndots or suffix devolution applies; a single-label
# name ("proxy", "localhost") is never looked up at all, nor is a malformed name (empty once one
# trailing dot is removed, starting with "." or holding ".."). IP literals are never handed to a
# resolver: they are vetted and contacted as they are.

ES_MAX_REACH=20
ES_V6_WHY='IPv6 address outside the global and unique-local ranges; never contacted'
ES_V4_WHY='public IPv4 address; never contacted'
ES_LABEL_WHY='single-label name; DNS search domains could expand it, so it is not looked up'
ES_MALFORMED_WHY='malformed host name; not looked up'

# es_malformed_name HOST: HOST (not an IPv6 literal) is empty once one trailing "." is removed,
# starts with "." or holds ".." anywhere as written
es_malformed_name() {
  [ -n "${1%.}" ] || return 0
  case $1 in .*|*..*) return 0 ;; esac
  return 1
}

# es_single_label HOST: HOST (a name, not an IP literal) has no "." once one trailing "." is removed
es_single_label() {
  case ${1%.} in *.*) return 1 ;; esac
  return 0
}

# es_lookup_name HOST -> ES_T: what the resolver is asked for a host NAME (IP literals never reach
# a resolver): its absolute form (one trailing "." removed, then one added: "proxy.corp" and
# "proxy.corp." both become "proxy.corp."). getent (glibc, musl, BSD) and dscacheutil accept it.
es_lookup_name() { ES_T="${1%.}."; }

# es_ip4_quad ADDRESS: a dotted-quad IPv4 address (four decimal octets 0-255, no leading zeros)
# -> es_4o1 .. es_4o4
es_ip4_quad() {
  case $1 in *[!0-9.]*|.*|*.|*..*|'') return 1 ;; esac
  es_4r=$1.; es_4n=0
  while [ -n "$es_4r" ]; do
    es_4o=${es_4r%%.*}; es_4r=${es_4r#*.}
    case $es_4o in 0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;; *) return 1 ;; esac
    [ "$es_4o" -le 255 ] || return 1
    es_4n=$((es_4n + 1))
    [ "$es_4n" -le 4 ] || return 1
    eval "es_4o$es_4n=\$es_4o"
  done
  [ "$es_4n" = 4 ]
}

# es_ip4_ok ADDRESS: a dotted-quad IPv4 address in 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or
# 100.64.0.0/10 may be contacted
es_ip4_ok() {
  es_ip4_quad "$1" || return 1
  case $es_4o1 in
    10) return 0 ;;
    172) [ "$es_4o2" -ge 16 ] && [ "$es_4o2" -le 31 ] ;;
    192) [ "$es_4o2" = 168 ] ;;
    100) [ "$es_4o2" -ge 64 ] && [ "$es_4o2" -le 127 ] ;;
    *) return 1 ;;
  esac
}

# es_ip6_ok ADDRESS: an IPv6 address (lower-cased) may be contacted: its first hextet (the text
# before the first ":", 0 for "::...") is 2000-3fff (global unicast) or fc00-fdff (unique local),
# it is not in fd00:ec2::/32 (second hextet ec2 with leading zeros stripped; "fd00::..." has 0)
# and it has no zone id (%...). fe80::/10, ::ffff: mapped, 64:ff9b:: NAT64, loopback, multicast
# and uncompressed forms of those all fail.
es_ip6_ok() {
  es_lower "$1"; es_6=$ES_T
  case $es_6 in *%*|'') return 1 ;; esac
  es_6h=${es_6%%:*}
  case $es_6h in ''|*[!0-9a-f]*|?????*) return 1 ;; esac
  es_6v=$((0x$es_6h))
  if [ "$es_6v" -ge 8192 ] && [ "$es_6v" -le 16383 ]; then return 0; fi
  [ "$es_6v" -ge 64512 ] && [ "$es_6v" -le 65023 ] || return 1
  if [ "$es_6v" = 64768 ]; then
    es_6s=${es_6#*:}; es_6s=${es_6s%%:*}
    while :; do case $es_6s in 0?*) es_6s=${es_6s#0} ;; *) break ;; esac; done
    [ "$es_6s" = ec2 ] && return 1
  fi
  return 0
}

# es_net_never HOST: succeeds when HOST (a name or an address, any case, IPv6 brackets allowed)
# must never be resolved or contacted: an ES_NET_NEVER entry ending in "." or ":" is an
# address prefix, any other entry must equal the whole host
es_net_never() {
  es_lower "$1"; es_nn=${ES_T#\[}; es_nn=${es_nn%\]}; es_nn=${es_nn%.}
  [ -n "$es_nn" ] || return 1
  set -f
  for es_ne in $ES_NET_NEVER; do
    case $es_ne in
      *.|*:) case $es_nn in "$es_ne"*) set +f; return 0 ;; esac ;;
      *) if [ "$es_nn" = "$es_ne" ]; then set +f; return 0; fi ;;
    esac
  done
  set +f
  return 1
}

# es_public_host HOST: succeeds when lower-case HOST (one trailing "." ignored) is (under) a
# public registry host
es_public_host() {
  es_phn=${1%.}
  set -f
  for es_ph in $ES_PUBLIC_HOSTS; do
    case $es_phn in "$es_ph"|*".$es_ph") set +f; return 0 ;; esac
  done
  set +f
  return 1
}

# es_ip_literal HOST: succeeds when HOST is a dotted-quad IPv4 address (no leading zeros) or
# an IPv6 address (es_ip6_literal); other numeric forms ("2852039166") are names that only a
# resolver may vet
es_ip_literal() {
  case $1 in *:*) es_ip6_literal "$1"; return ;; esac
  es_ip4_quad "$1"
}

# es_ip6_literal ADDRESS: a syntactically valid IPv6 address (zone ids are not): 8 groups of 1-4
# hex digits, or fewer around one "::"; the last two groups may be a dotted quad ("::ffff:1.2.3.4")
es_ip6_literal() {
  es_6a=$1
  case $es_6a in *[!0-9a-fA-F:.]*|*:::*|*::*::*) return 1 ;; esac
  case $es_6a in
    *.*) es_ip4_quad "${es_6a##*:}" || return 1; es_6a="${es_6a%:*}:0:0" ;;
  esac
  case $es_6a in
    *::*) es_6l=${es_6a%%::*}; es_6r=${es_6a#*::}
      es_ip6_groups "$es_6l" 1 || return 1; es_6n=$ES_6G
      es_ip6_groups "$es_6r" 1 || return 1
      [ $((es_6n + ES_6G)) -le 7 ] ;;
    *) es_ip6_groups "$es_6a" 0 && [ "$ES_6G" = 8 ] ;;
  esac
}

# es_ip6_groups TEXT EMPTY-OK -> ES_6G: TEXT is ":"-separated groups of 1-4 hex digits (TEXT may be
# empty when EMPTY-OK is 1); ES_6G = the number of groups
es_ip6_groups() {
  ES_6G=0
  if [ -z "$1" ]; then [ "$2" = 1 ]; return; fi
  es_6t=$1:
  while [ -n "$es_6t" ]; do
    es_6g=${es_6t%%:*}; es_6t=${es_6t#*:}
    case $es_6g in ''|*[!0-9a-fA-F]*|?????*) return 1 ;; esac
    ES_6G=$((ES_6G + 1))
  done
  return 0
}

# es_reach_targets -> ES_T: "host:port TAB source" lines (proxies first, de-duplicated)
es_reach_targets() {
  es_t=
  es_r=${ES_F_proxy_hosts:-}
  while [ -n "$es_r" ]; do
    es_l=${es_r%%"$ES_NL"*}; case $es_r in *"$ES_NL"*) es_r=${es_r#*"$ES_NL"} ;; *) es_r= ;; esac
    [ -n "$es_l" ] && es_t="$es_t$es_l${ES_TAB}proxy$ES_NL"
  done
  es_r=${ES_F_endpoints_internal:-}
  while [ -n "$es_r" ]; do
    es_l=${es_r%%"$ES_NL"*}; case $es_r in *"$ES_NL"*) es_r=${es_r#*"$ES_NL"} ;; *) es_r= ;; esac
    [ -n "$es_l" ] || continue
    es_hostport "$es_l"
    [ -n "$ES_T" ] && es_t="$es_t$ES_T${ES_TAB}package source$ES_NL"
  done
  ES_T=$(printf '%s' "$es_t" | awk -F '\t' 'NF { k = tolower($1); if (!s[k]++) print }')
}

# es_resolve_host HOST -> ES_T: the addresses HOST resolves to, one per line; returns 0 with
# the addresses, or with ES_T "" when the answer is a definitive "no address" (getent exit status
# 2, an empty answer); 1 when no resolver tool (getent, or dscacheutil on macOS) could be asked;
# 2 when the lookup failed (a timeout, an error, a crash), with es_lerr saying how
es_resolve_host() {
  ES_T=; es_lerr=
  [ -n "$es_ge$es_dsc" ] || return 1
  es_rts=$ES_TIMEOUT; [ "$ES_TIMEOUT" -gt 5 ] && ES_TIMEOUT=5
  if [ -n "$es_ge" ]; then
    es_cmd "$es_ge" ahosts "$1"
    # a getent without the ahosts database (exit status 1) is asked for hosts
    [ "$ES_RC" = 1 ] && es_cmd "$es_ge" hosts "$1"
    es_rq='{ print $1 }'; es_rnf=2
  else
    es_cmd "$es_dsc" -q host -a name "$1"
    es_rq='$1 == "ip_address:" || $1 == "ipv6_address:" { print $2 }'; es_rnf=-
  fi
  es_rrc=$ES_RC
  ES_TIMEOUT=$es_rts
  [ "$es_rrc" = "$es_rnf" ] && return 0
  if [ "$es_rrc" != 0 ]; then
    if [ "$ES_TIMED_OUT" = 1 ]; then es_lerr="name lookup timed out"
    else es_lerr="name lookup failed (exit status $es_rrc)"; fi
    return 2
  fi
  # addresses only (an IPv6 zone id is kept: es_ip6_ok refuses it)
  ES_T=$(awk "$es_rq" "$ES_OUT_F" | awk '/^[0-9A-Fa-f:.]+(%[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.-]+)?$/ && !s[$0]++')
  return 0
}

# es_tcp_check ADDRESS PORT -> es_tcp (ok, refused, timeout, error; "" without a TCP client), es_ms
es_tcp_check() {
  es_tcp=error; es_ms=
  case $1 in *:*) es_ta="[$1]" ;; *) es_ta=$1 ;; esac
  if [ -n "$es_curl" ]; then
    es_cmd "$es_curl" -q -sS -o /dev/null --noproxy '*' --connect-timeout 3 -m 4 -w '%{time_connect}' "telnet://$es_ta:$2"
    es_rc=$ES_RC
    es_tc=; es_read1 "$ES_OUT_F" && es_tc=$ES_L
    es_ms=$(awk -v t="$es_tc" 'BEGIN { if (t + 0 > 0) printf "%d\n", t * 1000 }')
    case $es_rc in
      0) es_tcp=ok ;;
      7) es_tcp=refused ;;
      28) if [ -n "$es_ms" ]; then es_tcp=ok; else es_tcp=timeout; fi ;;
      *) es_tcp=error ;;
    esac
  elif [ -n "$es_nc" ]; then
    if es_cmd "$es_nc" -z -w 3 "$1" "$2"; then es_tcp=ok; else es_tcp=error; fi
  else
    es_tcp=; es_err='no TCP client (curl, nc)'; return 0
  fi
  if [ "$es_tcp" != ok ]; then
    es_read1 "$ES_ERR_F" && es_err=$ES_L
    [ -n "$es_err" ] || es_err="exit status $ES_RC"
  fi
  return 0
}

# es_reach_one HOST PORT -> es_res (the addresses), es_tcp, es_ms, es_err and es_why (why HOST
# was not contacted). Every address is vetted before the connection, which goes to an address
# (IPv4 first), never to the name.
es_reach_one() {
  es_res=; es_tcp=; es_ms=; es_err=; es_why=
  es_rv=0
  if es_ip_literal "$1"; then es_res=$1
  else
    es_lookup_name "$1"
    es_resolve_host "$ES_T"; es_rv=$?
    es_res=$ES_T
  fi
  if [ "$es_rv" = 0 ]; then :
  elif [ "$es_rv" = 1 ]; then
    es_tcp=skipped; es_why='no resolver available; names are not contacted'; es_nores=1; return 0
  else
    es_tcp=error; es_err=$es_lerr; es_lfail=$((es_lfail + 1)); return 0
  fi
  if [ -z "$es_res" ]; then es_tcp=unresolved; es_err='the name has no address'; return 0; fi
  es_a4=; es_a6=; es_v4=; es_rr=$es_res$ES_NL
  while [ -n "$es_rr" ]; do
    es_ra=${es_rr%%"$ES_NL"*}; es_rr=${es_rr#*"$ES_NL"}
    [ -n "$es_ra" ] || continue
    if es_net_never "$es_ra"; then
      es_tcp=skipped; es_why='resolves to a cloud metadata or link-local address; never contacted'; return 0
    fi
    case $es_ra in
      *:*) es_ip6_ok "$es_ra" && [ -z "$es_a6" ] && es_a6=$es_ra ;;
      *) es_v4=1; [ -z "$es_a4" ] && es_ip4_ok "$es_ra" && es_a4=$es_ra ;;
    esac
  done
  if [ -z "$es_a4$es_a6" ]; then
    es_tcp=skipped; es_why=$ES_V6_WHY; [ -n "$es_v4" ] && es_why=$ES_V4_WHY
    return 0
  fi
  es_tcp_check "${es_a4:-$es_a6}" "$2"
}

# es_reach_tools -> es_curl, es_nc (TCP clients), es_ge, es_dsc (resolvers)
es_reach_tools() {
  es_curl=; es_nc=; es_ge=; es_dsc=
  es_which curl && es_runnable "$ES_W" curl && es_curl=$ES_W
  [ -z "$es_curl" ] && es_which nc && es_runnable "$ES_W" nc && es_nc=$ES_W
  if es_which getent && es_runnable "$ES_W" getent; then es_ge=$ES_W
  elif [ "$ES_OS" = darwin ] && es_which dscacheutil && es_runnable "$ES_W" dscacheutil; then es_dsc=$ES_W
  fi
  return 0
}

# es_reach_item: one target. A skipped target has tcp "skipped" and a reason, and no resolved,
# ms or error (the shared contract); each skip is also a probe note, and leaves the status alone.
es_reach_item() {
  es_o -; es_s host "$es_h"; es_n port "$es_p"; es_s source "$es_srcx"
  if [ "$es_tcp" = skipped ]; then
    es_s tcp skipped; es_s reason "$es_why"
    es_note "skipped $es_h:$es_p: $es_why"
  else
    es_list resolved "$es_res"; es_sn tcp "$es_tcp"; es_n ms "$es_ms"; es_sn error "$es_err"; es_z reason
  fi
  es_oe
}

probe_net_reachability() {
  es_src "DNS lookup and TCP connect (3 s) to proxy and internal mirror hosts found in net.proxy and pkg.sources only; public registries and cloud metadata or link-local addresses are never looked up or contacted"
  es_reach_targets
  es_a targets
  if [ -z "$ES_T" ]; then
    es_ae; es_status not_found
    es_note "no proxy or internal mirror was found in local configuration (run together with net.proxy and pkg.sources)"
    return 0
  fi
  printf '%s\n' "$ES_T" >"$ES_P_DIR/targets.tsv"
  es_reach_tools
  es_looked=0; es_over=0; es_nores=; es_lfail=0
  while IFS=$ES_TAB read -r es_hp es_srcx; do
    es_p=${es_hp##*:}; es_lower "${es_hp%:*}"; es_h=${ES_T#\[}; es_h=${es_h%\]}
    es_is_num "$es_p" || continue
    case $es_h in
      *:*) es_ip6_literal "$es_h" || { es_note "not checked (not a plain host name): $es_h"; continue; } ;;
      *) if es_malformed_name "$es_h"; then
           es_res=; es_tcp=skipped; es_ms=; es_err=; es_why=$ES_MALFORMED_WHY; es_reach_item; continue
         fi ;;
    esac
    case $es_h in
      *:*) ;;
      [abcdefghijklmnopqrstuvwxyz0-9]*) case $es_h in *[!abcdefghijklmnopqrstuvwxyz0-9._-]*) es_note "not checked (not a plain host name): $es_h"; continue ;; esac ;;
      *) es_note "not checked (not a plain host name): $es_h"; continue ;;
    esac
    es_res=; es_tcp=skipped; es_ms=; es_err=; es_why=
    if es_net_never "$es_h"; then es_why='cloud metadata or link-local address; never contacted'
    elif es_public_host "$es_h"; then es_why='public registry; only internal mirrors and proxies are checked'
    elif case $es_h in *:*) ! es_ip6_ok "$es_h" ;; *) false ;; esac; then es_why=$ES_V6_WHY
    elif case $es_h in [0-9]*.[0-9]*.[0-9]*.[0-9]*) ! es_ip4_ok "$es_h" ;; *) false ;; esac; then es_why=$ES_V4_WHY
    elif case $es_h in *:*) false ;; *) es_single_label "$es_h" ;; esac; then es_why=$ES_LABEL_WHY
    elif [ "$es_looked" -ge "$ES_MAX_REACH" ]; then es_over=$((es_over + 1)); continue
    else
      # every host costs up to ~10 s (5 s name lookup, 4 s connect): stop before the scan budget ends
      es_now_ms
      if [ $(( (ES_DEADLINE - ES_MS) / 1000 )) -lt 10 ]; then es_partial "the scan budget ran out; the remaining hosts were not checked"; break; fi
      es_looked=$((es_looked + 1))
      es_reach_one "$es_h" "$es_p"
    fi
    es_reach_item
  done <"$ES_P_DIR/targets.tsv"
  es_ae
  [ "$es_over" -gt 0 ] && es_note "$es_over more endpoint(s) not checked (at most $ES_MAX_REACH looked up)"
  if [ "$es_looked" -gt 0 ] && [ -z "$es_curl$es_nc" ]; then es_partial "no TCP client (curl, nc) is available; only DNS was checked"; fi
  [ -n "$es_nores" ] && es_partial "no resolver (getent, dscacheutil) is available: host names were not looked up or contacted"
  [ "$es_lfail" -gt 0 ] && es_partial "the name lookup failed for $es_lfail host(s); they were not contacted"
  return 0
}
