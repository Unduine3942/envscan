# ============================================================== probes: pkg.*

# ES_PUBLIC_HOSTS (generated from spec/configs.toml public_hosts): host suffixes of well-known
# public registries, mirrors and code hosts. Anything else that a configuration points at is
# treated as an internal or custom endpoint.

# es_endpoints FILE...: "class TAB scheme://host[:port]" for every URL in the files (userinfo removed).
# Input lines are "source TAB text". Only URL schemes used by package managers, VCS and proxies
# count, and the scheme must start a word ("credential.https://x" in a git key is not a URL).
# Comment lines, XML comments, xmlns/schemaLocation attributes, w3.org and the Maven POM/XSD
# schema URLs name documents, not servers, and are ignored. Loopback hosts and the cloud
# metadata and link-local hosts of ES_NET_NEVER are not endpoints (the shared contract).
es_endpoints() {
  awk -v pub="$ES_PUBLIC_HOSTS" -v never="$ES_NET_NEVER" '
    function dropped(h,   i, e) {
      if (h == "localhost" || h ~ /\.localhost$/ || h ~ /^127\./ || h == "::1") return 1
      for (i = 1; i <= nn; i++) {
        e = NV[i]
        if (e ~ /[.:]$/) { if (substr(h, 1, length(e)) == e) return 1 }
        else if (h == e) return 1
      }
      return 0
    }
    BEGIN { n = split(pub, P, " "); nn = split(tolower(never), NV, " ") }
    {
      src = $0; sub(/\t.*/, "", src); lc = $0; sub(/^[^\t]*\t/, "", lc); lc = tolower(lc)
      if (src != prev) { incom = 0; prev = src }
      if (incom) { k = index(lc, "-->"); if (k == 0) next; lc = substr(lc, k + 3); incom = 0 }
      while ((k = index(lc, "<!--")) > 0) {
        e = index(substr(lc, k + 4), "-->")
        if (e == 0) { lc = substr(lc, 1, k - 1); incom = 1; break }
        lc = substr(lc, 1, k - 1) " " substr(lc, k + e + 6)
      }
      if (lc ~ /^[ \t]*(#|;|\/\/|!)/) next
      gsub(/[abcdefghijklmnopqrstuvwxyz0-9_.:-]*schemalocation[ \t]*=[ \t]*"[^"]*"/, " ", lc)
      gsub(/xmlns(:[abcdefghijklmnopqrstuvwxyz0-9_.-]+)?[ \t]*=[ \t]*"[^"]*"/, " ", lc)
      while (match(lc, /(https?|ftps?|sftp|ssh|git|git\+ssh|svn|svn\+ssh|socks[45]?h?|rsync|s3|gs|oci|ldaps?|wss?):\/\/[^\/ \t"'"'"'<>,;)]+/)) {
        st = RSTART; ln = RLENGTH; pre = (st > 1) ? substr(lc, st - 1, 1) : ""
        u = substr(lc, st, ln); lc = substr(lc, st + ln)
        pth = lc; sub(/[ \t"'"'"'<>,;)].*/, "", pth)
        if (pre ~ /[abcdefghijklmnopqrstuvwxyz0-9.-]/) continue
        k = index(u, "://"); sch = substr(u, 1, k - 1); hp = substr(u, k + 3)
        at = 0; for (j = length(hp); j > 0; j--) if (substr(hp, j, 1) == "@") { at = j; break }
        if (at) hp = substr(hp, at + 1)
        if (match(hp, /^\[[0-9a-f:.%]+](:[0-9]+)?/) || match(hp, /^[abcdefghijklmnopqrstuvwxyz0-9._~%-]+(:[0-9]+)?/)) hp = substr(hp, 1, RLENGTH); else continue
        h = hp; sub(/:[0-9]*$/, "", h); sub(/^\[/, "", h); sub(/]$/, "", h); sub(/\.$/, "", h)
        if (h == "" || h == "w3.org" || h ~ /\.w3\.org$/) continue
        if (h == "maven.apache.org" && pth ~ /^\/(pom|xsd|settings|maven-v)/) continue
        if (dropped(h)) continue
        c = "custom"
        if (h ~ /^10\./ || h ~ /^192\.168\./ || h ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ || h !~ /\./ || h ~ /\.(local|corp|internal|intranet|lan|home\.arpa|localdomain)$/) c = "internal"
        else for (i = 1; i <= n; i++) if (P[i] != "" && (h == P[i] || (length(h) > length(P[i]) && substr(h, length(h) - length(P[i])) == "." P[i]))) { c = "public"; break }
        key = sch "://" hp
        if (!(key in seen)) { seen[key] = 1; print c "\t" key }
      }
    }' "$@" 2>/dev/null
}

# es_config_raw FILE MODE MAX MATCH: the kept lines of one config file, unredacted, appended to
# config_lines.txt for the endpoint, proxy and TLS checks (internal only: the report gets an F
# event, which redacts the whole file before the same filter). The byte cap and the
# case-insensitive line matching are those of config_lines in json.awk, so both keep the same lines.
es_config_raw() {
  # UTF-16 or binary content is decoded or not read (es_text_prep), as for the F event
  es_cr=${5:-}
  if [ -z "$es_cr" ]; then
    es_text_prep "$1" && es_cr=$ES_TXT || { : >"$ES_P_DIR/cfg.cur"; return 0; }
  fi
  awk -v mode="$2" -v max="$3" -v match_list="$4" -v fname="$1" '
    BEGIN { nm = (match_list == "" || match_list == "-") ? 0 : split(tolower(match_list), M, "|")
            max += 0; if (max <= 0) max = 65536 }
    { sub(/\r$/, ""); add = length($0) + (NR > 1 ? 1 : 0); if (total + add > max) exit; total += add }
    /^[ \t]*$/ { next }
    mode != "lines" && /^[ \t]*[#;]/ { next }
    mode == "lines" { keep = 0; lc = tolower($0); for (i = 1; i <= nm; i++) if (index(lc, M[i]) > 0) { keep = 1; break } if (!keep) next }
    { print fname "\t" $0 }' "$es_cr" >"$ES_P_DIR/cfg.cur"
  cat "$ES_P_DIR/cfg.cur" >>"$ES_P_DIR/config_lines.txt"
}

# es_proxy_urls: proxy.awk lines in, "source TAB url" out for each proxy setting: the URL as
# scheme://host[:port] in lower case, never userinfo or a path ("http://" for a bare host:port)
es_proxy_urls() {
  awk -F '\t' '$2 == "proxy" {
      u = ""
      if (match($5, /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9+.-]*:\/\/[^\/ \t"'"'"'<>,;?#]+/)) {
        u = substr($5, RSTART, RLENGTH); k = index(u, "://"); sch = substr(u, 1, k - 1); hp = substr(u, k + 3)
        for (j = length(hp); j > 0; j--) if (substr(hp, j, 1) == "@") { hp = substr(hp, j + 1); break }
        if (match(hp, /^(\[[0-9A-Fa-f:.%]+]|[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9._-]+)(:[0-9]+)?/)) u = sch "://" substr(hp, 1, RLENGTH); else u = ""
      } else if ($3 != "-") u = "http://" $3
      if (u == "") next
      k = $1 "\t" tolower(u); if (!s[k]++) print k }'
}

# es_pkg_config_item ID TOOL OS-PATH SCOPE MODE MAX MATCH: one file of the configs list: its
# redacted lines (F event), and the urls (endpoint bases) and proxy_urls found in its raw lines
es_pkg_config_item() {
  es_o -
  es_s id "$1"; es_s tool "$2"; es_s path "${3#"$ES_ROOT"}"; es_s scope "$4"; es_s mode "$5"
  if es_text_prep "$3"; then
    printf 'F\tlines\t%s\t%s\t%s\t%s\n' "$ES_TXT" "$6" "$5" "$7" >&5
    es_config_raw "$3" "$5" "$6" "$7" "$ES_TXT"
  else
    # UTF-16 or binary: the F event prints only the "not read" line, and nothing else is read
    printf 'F\tlines\t%s\t%s\t%s\t%s\n' "$3" "$6" "$5" "$7" >&5
    : >"$ES_P_DIR/cfg.cur"
    es_partial "${3#"$ES_ROOT"} not read: UTF-16 or binary content"
  fi
  es_list urls "$(es_endpoints "$ES_P_DIR/cfg.cur" | awk -F '\t' '{ print $2 }')"
  es_list proxy_urls "$(es_proxy_settings "$ES_P_DIR/cfg.cur" | es_proxy_urls | awk -F '\t' '{ print $2 }')"
  es_oe
  printf '%s\t%s\t%s\n' "$3" "$2" "${3#"$ES_ROOT"}" >>"$ES_P_DIR/config_tools.tsv"
}

# es_pkg_proxy_list: the proxy_urls list ({tool, url, source}) from the raw proxy settings of
# the configuration files and of git ($ES_TMP/pkg_proxy.tsv, which net.proxy reads too)
es_pkg_proxy_list() {
  es_a proxy_urls
  es_proxy_urls <"$ES_TMP/pkg_proxy.tsv" | awk -F '\t' -v tf="$ES_P_DIR/config_tools.tsv" '
    BEGIN { while ((getline l < tf) > 0) { split(l, A, "\t"); T[A[1]] = A[2]; P[A[1]] = A[3] } }
    { if ($1 ~ /^git:/) { t = "git"; s = substr($1, 5) } else { t = ($1 in T) ? T[$1] : "-"; s = ($1 in P) ? P[$1] : $1 }
      print t "\t" $2 "\t" s }' >"$ES_P_DIR/proxy_urls.tsv"
  while IFS=$ES_TAB read -r es_pt es_pu es_ps; do
    es_o -; es_s tool "$es_pt"; es_s url "$es_pu"; es_s source "$es_ps"; es_oe
  done <"$ES_P_DIR/proxy_urls.tsv"
  es_ae
}

# es_pkg_configs: the configs list (files of spec/configs.toml) -> es_nf, es_cids
es_pkg_configs() {
  es_spec_configs >"$ES_P_DIR/configs.spec"
  es_nf=0; es_cids=
  es_a configs
  while IFS=$ES_TAB read -r es_cid es_ctool es_cos es_cscope es_cmode es_cmax es_cmatch es_cpaths; do
    case $es_cos in
      all|unix) ;;
      linux) [ "$ES_OS" = linux ] || continue ;;
      darwin) [ "$ES_OS" = darwin ] || continue ;;
      *) continue ;;
    esac
    es_cifs=$IFS; IFS='|'; set -f
    set -- $es_cpaths
    IFS=$es_cifs; set +f
    es_seen=
    for es_pat in "$@"; do
      es_expand "$es_pat" || continue
      es_xifs=$IFS; IFS=$ES_NL; set -f
      for es_f in $ES_X; do
        IFS=$es_xifs
        [ -f "$es_f" ] && [ -r "$es_f" ] || continue
        case "$ES_NL$es_seen" in *"$ES_NL$es_f$ES_NL"*) continue ;; esac
        case $es_f in *"$ES_TAB"*|*"$ES_NL"*) es_note "skipped a config file whose name contains a tab or line break"; continue ;; esac
        es_seen="$es_seen$es_f$ES_NL"
        es_pkg_config_item "$es_cid" "$es_ctool" "$es_f" "$es_cscope" "$es_cmode" "$es_cmax" "$es_cmatch"
        es_nf=$((es_nf + 1))
        case " $es_cids " in *" $es_cid "*) ;; *) es_cids="$es_cids $es_cid" ;; esac
      done
      IFS=$es_xifs; set +f
    done
  done <"$ES_P_DIR/configs.spec"
  es_ae
}

probe_pkg_sources() {
  es_src "read package-manager and repository config files from spec/configs.toml (redacted)"
  : >"$ES_P_DIR/config_lines.txt"; : >"$ES_P_DIR/config_tools.tsv"
  es_pkg_configs
  es_src "environment package variables"
  : >"$ES_P_DIR/env_lines.txt"
  es_o env
  for es_v in $ES_PACKAGE_ENV; do
    eval "es_vv=\${$es_v-}"
    [ -n "$es_vv" ] || continue
    es_e "$es_v" "$es_vv"
    printf 'env:%s\t%s=%s\n' "$es_v" "$es_v" "$es_vv" >>"$ES_P_DIR/env_lines.txt"
  done
  es_oe
  es_git_config
  es_endpoints "$ES_P_DIR/config_lines.txt" "$ES_P_DIR/env_lines.txt" "$ES_P_DIR/git_urls.txt" >"$ES_TMP/endpoints.tsv"
  es_a endpoints
  es_int=; es_pub=
  while IFS=$ES_TAB read -r es_ec es_eu; do
    es_s - "$es_eu"
    case $es_ec in public) es_pub="$es_pub$es_eu$ES_NL" ;; *) es_int="$es_int$es_eu$ES_NL" ;; esac
  done <"$ES_TMP/endpoints.tsv"
  es_ae
  es_list internal_endpoints "$es_int"
  es_list public_endpoints "$es_pub"
  awk -F '\t' '{
      l = tolower($2); gsub(/[ \t"'"'"']/, "", l)
      if (l ~ /strict-ssl[=:]?false|enablestrictssl:?false|sslverify[=:]?(false|0|no)|ssl_verify:?(false|0)|verify-peer(false|0)|verify-host(false|0)|trusted-host|disable-tls[=:]?true|secure-http[=:]?false|ssl_verify_mode:?0|wagon\.http\.ssl\.insecure=true|ssl\.insecure=true/) print $1 ": " $2
    }' "$ES_P_DIR/config_lines.txt" "$ES_P_DIR/env_lines.txt" "$ES_P_DIR/git_lines.txt" >"$ES_P_DIR/tls_off.txt" 2>/dev/null
  es_list_file tls_verification_disabled "$ES_P_DIR/tls_off.txt" l 50
  # proxies by setting name, not by a value that happens to contain "proxy" (a Nexus npm-proxy URL)
  es_proxy_settings "$ES_P_DIR/config_lines.txt" "$ES_P_DIR/git_lines.txt" >"$ES_TMP/pkg_proxy.tsv"
  es_pkg_proxy_list
  es_n config_count "$es_nf"
  es_fact endpoints_internal "$es_int"
  es_fact endpoints_public "$es_pub"
  es_fact pkg_config_count "$es_nf"
  es_fact tls_disabled_cfg "$(awk 'NR <= 5' "$ES_P_DIR/tls_off.txt")"
  es_cids=${es_cids# }
  es_fact pkg_config_ids "$(printf '%s' "$es_cids" | awk '{ for (i = 1; i <= NF; i++) printf "%s%s", (i > 1 ? ", " : ""), $i }')"
  # the raw configuration lines, git configuration and command outputs go now; only
  # $ES_TMP/pkg_proxy.tsv stays, for net.proxy (which removes it)
  # the tool of each configuration file, for net.proxy (package_managers[].tool)
  cp "$ES_P_DIR/config_tools.tsv" "$ES_TMP/pkg_tools.tsv" 2>/dev/null
  es_raw_drop "$ES_P_DIR"
  rm -f "$ES_TMP/gitconfig.txt" "$ES_P_DIR"/c*.out "$ES_P_DIR"/c*.err
}

ES_CACHE_CAP=10000

# es_count_entries DIR -> ES_T: the number of entries in DIR (dot files included), counted up to
# ES_CACHE_CAP + 1 (more than the cap: truncated). One directory listing (ls -A, which every ls
# has), not a stat per entry.
es_count_entries() {
  ES_T=$(ls -A "$1" 2>/dev/null | awk -v cap="$ES_CACHE_CAP" '$0 != "." && $0 != ".." { n++; if (n > cap) exit } END { print n + 0 }')
}

probe_pkg_caches() {
  es_src "list cache directories from spec/configs.toml (top-level entry counts, at most $ES_CACHE_CAP per directory)"
  es_spec_caches >"$ES_P_DIR/caches.spec"
  es_a caches
  es_found=; es_ntr=0
  while IFS=$ES_TAB read -r es_cid es_ctool es_cpaths; do
    es_cifs=$IFS; IFS='|'; set -f
    set -- $es_cpaths
    IFS=$es_cifs; set +f
    for es_pat in "$@"; do
      es_expand "$es_pat" || continue
      es_xifs=$IFS; IFS=$ES_NL; set -f
      for es_d in $ES_X; do
        IFS=$es_xifs
        [ -d "$es_d" ] || continue
        es_count_entries "$es_d"; es_cnt=$ES_T; es_tr=false
        [ "$es_cnt" -gt 0 ] || continue
        if [ "$es_cnt" -gt "$ES_CACHE_CAP" ]; then es_cnt=$ES_CACHE_CAP; es_tr=true; es_ntr=$((es_ntr + 1)); fi
        es_o -; es_s id "$es_cid"; es_s tool "$es_ctool"; es_s path "$es_d"; es_n entries "$es_cnt"; es_b truncated "$es_tr"; es_oe
        es_found="$es_found$es_cid$ES_NL"
      done
      IFS=$es_xifs; set +f
    done
  done <"$ES_P_DIR/caches.spec"
  es_ae
  if [ "$es_ntr" -gt 0 ]; then
    es_truncated; es_note "entries are counted up to $ES_CACHE_CAP per directory; $es_ntr cache directories hold more (truncated)"
  fi
  [ -n "$es_found" ] || es_status not_found
  es_fact caches "$es_found"
}

# es_pkg_list MANAGER FORMAT: append "manager TAB name TAB version" lines from $ES_OUT_F
es_pkg_list() {
  awk -v m="$1" -v f="$2" '
    { sub(/\r$/, "") }
    f == "tab" { if (NF) { split($0, A, "\t"); print m "\t" A[1] "\t" A[2] } next }
    f == "space" { if (NF) print m "\t" $1 "\t" $2; next }
    f == "apk" || f == "pkgng" {
      s = $1; if (match(s, /-[0-9][^-]*(-r[0-9]+)?(_[0-9]+)?(,[0-9]+)?$/)) print m "\t" substr(s, 1, RSTART - 1) "\t" substr(s, RSTART + 1); else if (s != "") print m "\t" s "\t"
      next }
    f == "name" { if (NF) print m "\t" $1 "\t"; next }
    f == "lslpp" { if ($0 ~ /^#/ || $0 == "") next; split($0, A, ":"); print m "\t" A[2] "\t" A[3]; next }
    f == "ips" { if (NF >= 2) print m "\t" $1 "\t" $2; next }' "$ES_OUT_F" >>"$ES_P_DIR/pkgs.tsv"
}

probe_pkg_installed() {
  : >"$ES_P_DIR/pkgs.tsv"
  es_mgrs=
  if es_need dpkg-query -W -f='${Package}\t${Version}\n'; then es_pkg_list dpkg tab; es_mgrs="$es_mgrs dpkg"; fi
  if es_need rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'; then es_pkg_list rpm tab; es_mgrs="$es_mgrs rpm"; fi
  if es_need apk info -v; then es_pkg_list apk apk; es_mgrs="$es_mgrs apk"; fi
  if es_need pacman -Q; then es_pkg_list pacman space; es_mgrs="$es_mgrs pacman"; fi
  if [ "$ES_OS" = darwin ] && es_need pkgutil --pkgs; then es_pkg_list pkgutil name; es_mgrs="$es_mgrs pkgutil"; fi
  if es_need brew list --versions; then es_pkg_list brew space; es_mgrs="$es_mgrs brew"; fi
  if [ "$ES_OS" = freebsd ] && es_need pkg info; then es_pkg_list pkg pkgng; es_mgrs="$es_mgrs pkg"; fi
  if [ "$ES_OS" = aix ] && es_need lslpp -Lc; then es_pkg_list lslpp lslpp; es_mgrs="$es_mgrs lslpp"; fi
  if [ "$ES_OS" = sunos ] && es_need pkg list -H; then es_pkg_list ips ips; es_mgrs="$es_mgrs ips"; fi
  es_a managers
  for es_m in $es_mgrs; do
    es_c=$(awk -F '\t' -v m="$es_m" '$1 == m { n++ } END { print n + 0 }' "$ES_P_DIR/pkgs.tsv")
    es_o -; es_s name "$es_m"; es_n count "$es_c"; es_oe
  done
  es_ae
  es_total=$(awk 'END { print NR }' "$ES_P_DIR/pkgs.tsv")
  es_a packages
  sort -t "$ES_TAB" -k 2,2 "$ES_P_DIR/pkgs.tsv" 2>/dev/null | awk -F '\t' '
    NR <= 500 { printf "{\t-\ns\tname\t%s\ns\tversion\t%s\ns\tsource\t%s\n}\n", $2, $3, $1 }' >&5
  es_ae
  es_trunc=false; [ "$es_total" -gt 500 ] && es_trunc=true
  es_n total "$es_total"
  es_b truncated "$es_trunc"
  [ "$es_trunc" = true ] && es_truncated
  if [ "$ES_OS" = darwin ] && [ -d "$ES_ROOT/Applications" ]; then
    es_src "list /Applications"
    es_apps=
    for es_f in "$ES_ROOT"/Applications/*.app; do [ -e "$es_f" ] && es_apps="$es_apps${es_f##*/}$ES_NL"; done
    es_list applications "$es_apps"
  fi
  if [ -z "$es_mgrs" ]; then es_status not_found; es_note "no supported package manager was found"; fi
  es_fact pkg_managers "${es_mgrs# }"
  es_fact pkg_total "$es_total"
}
