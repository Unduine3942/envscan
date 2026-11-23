# ============================================================== probes: sec.*, tls.*

probe_sec_app_control() {
  es_se=; es_secfg=; es_aa=; es_aaprof=; es_ctx=; es_fa=; es_fainst=false
  es_sc=; es_nnp=; es_cap=; es_lock=; es_rro=; es_sip=; es_gk=; es_mdm=
  if es_read1 "$ES_ROOT/sys/fs/selinux/enforce"; then
    es_src "read /sys/fs/selinux/enforce"
    case $ES_L in 1) es_se=enforcing ;; 0) es_se=permissive ;; esac
  fi
  if [ -r "$ES_ROOT/etc/selinux/config" ]; then
    es_src "read /etc/selinux/config"
    es_secfg=$(awk -F '=' '$1 == "SELINUX" { print $2; exit }' "$ES_ROOT/etc/selinux/config")
    [ -n "$es_se" ] || { [ "$ES_OS" = linux ] && es_se=disabled; }
  fi
  if es_read1 "$ES_ROOT/sys/module/apparmor/parameters/enabled"; then
    es_src "read /sys/module/apparmor/parameters/enabled"
    case $ES_L in Y*) es_aa=enabled ;; N*) es_aa=disabled ;; esac
  fi
  for es_f in "$ES_ROOT/proc/self/attr/apparmor/current" "$ES_ROOT/proc/self/attr/current"; do
    if es_read1 "$es_f"; then
      es_src "read ${es_f#"$ES_ROOT"}"
      es_v=$(printf '%s' "$ES_L" | tr -d '\000')
      if [ "$es_aa" = enabled ]; then es_aaprof=$es_v; else es_ctx=$es_v; fi
      break
    fi
  done
  if [ -d "$ES_ROOT/etc/fapolicyd" ]; then
    es_src "list /etc/fapolicyd"
    es_fainst=true
  fi
  if es_which systemctl && { [ "$es_fainst" = true ] || es_which fapolicyd; }; then
    es_tool systemctl is-active fapolicyd
    es_read1 "$ES_OUT_F" && es_fa=$ES_L
  fi
  if [ -r "$ES_ROOT/proc/self/status" ]; then
    es_src "read /proc/self/status (Seccomp, NoNewPrivs, CapEff)"
    while IFS= read -r es_line; do
      es_trim "${es_line#*:}"
      case $es_line in
        Seccomp:*) case $ES_T in 0) es_sc=disabled ;; 1) es_sc=strict ;; 2) es_sc=filter ;; *) es_sc=$ES_T ;; esac ;;
        NoNewPrivs:*) case $ES_T in 1) es_nnp=true ;; 0) es_nnp=false ;; esac ;;
        CapEff:*) es_cap=$ES_T ;;
      esac
    done <"$ES_ROOT/proc/self/status"
  fi
  if es_read1 "$ES_ROOT/sys/kernel/security/lockdown"; then
    es_src "read /sys/kernel/security/lockdown"
    es_lock=${ES_L#*\[}; es_lock=${es_lock%%\]*}
  fi
  if es_mount_of /; then
    es_src "$ES_MOUNT_SRC (root read-only, at scan start)"
    es_rro=false
    case ",$ES_MOPT," in *,ro,*) es_rro=true ;; esac
  fi
  if [ "$ES_OS" = darwin ]; then
    if es_tool csrutil status && es_read1 "$ES_OUT_F"; then
      case $ES_L in *enabled*) es_sip=enabled ;; *disabled*) es_sip=disabled ;; *) es_sip=$ES_L ;; esac
    fi
    es_tool spctl --status
    cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
    if es_read1 "$ES_OUT_F"; then
      case $ES_L in *enabled*) es_gk=enabled ;; *disabled*) es_gk=disabled ;; *) es_gk=$ES_L ;; esac
    fi
    if es_tool profiles status -type enrollment; then
      if grep -i 'MDM enrollment: Yes' "$ES_OUT_F" >/dev/null 2>&1; then es_mdm=true
      elif grep -i 'MDM enrollment: No' "$ES_OUT_F" >/dev/null 2>&1; then es_mdm=false
      fi
      es_raw profiles "$ES_OUT_F"
    fi
  fi
  es_z applocker; es_z srp; es_z wdac; es_z smart_app_control; es_z exploit_protection
  es_sn selinux "$es_se"
  es_sn selinux_config "$es_secfg"
  es_sn selinux_context "$es_ctx"
  es_sn apparmor "$es_aa"
  es_sn apparmor_profile "$es_aaprof"
  es_o fapolicyd; es_b installed "$es_fainst"; es_sn state "$es_fa"; es_oe
  es_sn seccomp "$es_sc"
  es_b no_new_privs "$es_nnp"
  es_sn cap_eff "$es_cap"
  es_sn lockdown "$es_lock"
  es_b root_readonly "$es_rro"
  es_sn sip "$es_sip"
  es_sn gatekeeper "$es_gk"
  es_b mdm_enrolled "$es_mdm"
  es_fact selinux "$es_se"
  es_fact apparmor "$es_aa"
  es_fact aa_profile "$es_aaprof"
  es_fact fapolicyd "$es_fa"
  es_fact root_ro "$es_rro"
  es_fact cap_eff "$es_cap"
}

probe_sec_crypto() {
  es_fips=; es_pol=; es_ov=; es_od=
  if es_read1 "$ES_ROOT/proc/sys/crypto/fips_enabled"; then
    es_src "read /proc/sys/crypto/fips_enabled"
    case $ES_L in 1) es_fips=true ;; 0) es_fips=false ;; esac
  elif [ "$ES_OS" = linux ]; then
    es_fips=false
    es_note "/proc/sys/crypto/fips_enabled is absent (kernel without FIPS support)"
  fi
  if [ -r "$ES_ROOT/etc/crypto-policies/config" ]; then
    es_src "read /etc/crypto-policies/config"
    es_pol=$(awk '{ sub(/\r$/, "") } /^[ \t]*(#|$)/ { next } { print; exit }' "$ES_ROOT/etc/crypto-policies/config")
  fi
  if es_need openssl version -a; then
    es_raw openssl "$ES_OUT_F"
    es_read1 "$ES_OUT_F" && es_ov=$ES_L
    es_od=$(awk -F ': ' '/^OPENSSLDIR/ { v = $2; gsub(/"/, "", v); print v; exit }' "$ES_OUT_F")
  fi
  es_src "environment OPENSSL_CONF"
  es_b fips "$es_fips"
  es_sn crypto_policy "$es_pol"
  es_sn openssl_version "$es_ov"
  es_sn openssl_dir "$es_od"
  es_sn openssl_conf "${OPENSSL_CONF:-}"
  es_z schannel; es_z dotnet_strong_crypto
  es_fact fips "$es_fips"
  es_fact crypto_policy "$es_pol"
  es_fact openssl_version "$es_ov"
}

probe_tls_trust() {
  es_a bundles
  es_first=; es_rootc=
  es_src "read CA bundles listed in spec/configs.toml (certificate count)"
  for es_b0 in $ES_CA_BUNDLES; do
    es_bp="$ES_ROOT$es_b0"
    es_ltest -r "$es_bp" || continue
    es_nc=$(grep -c 'BEGIN CERTIFICATE' "$es_bp" 2>/dev/null)
    es_o -; es_s path "$es_b0"; es_n certs "$es_nc"; es_oe
    if [ -z "$es_first" ]; then es_first=$es_b0; es_rootc=$es_nc; fi
  done
  es_ae
  es_anchors=
  es_src "list custom anchor directories from spec/configs.toml"
  for es_d0 in $ES_CA_ANCHOR_DIRS; do
    es_d="$ES_ROOT$es_d0"
    es_ltest -d "$es_d" || continue
    for es_apat in "$es_d/*" "$es_d/*/*"; do
      es_glob "$es_apat" || continue
      es_ar=$ES_X
      while [ -n "$es_ar" ]; do
        es_f=${es_ar%%"$ES_NL"*}; es_ar=${es_ar#*"$ES_NL"}
        [ -f "$es_f" ] && es_anchors="$es_anchors${es_f#"$ES_ROOT"}$ES_NL"
      done
    done
  done
  es_ossl=; es_which openssl && es_runnable "$ES_W" openssl && es_ossl=$ES_W
  es_subjects=; es_na=0
  es_a roots
  es_aifs=$IFS; IFS=$ES_NL; set -f
  for es_af in $es_anchors; do
    IFS=$es_aifs
    es_na=$((es_na + 1))
    es_subj=; es_until=
    if [ -n "$es_ossl" ] && [ "$es_na" -le 25 ]; then
      if es_cmd "$es_ossl" x509 -noout -subject -enddate -in "$ES_ROOT$es_af"; then
        while IFS= read -r es_line; do
          case $es_line in
            subject=*) es_trim "${es_line#subject=}"; es_subj=$ES_T ;;
            notAfter=*) es_until=${es_line#notAfter=} ;;
          esac
        done <"$ES_OUT_F"
      fi
    fi
    es_o -
    es_s subject "${es_subj:-${es_af##*/}}"; es_z thumbprint; es_sn not_after "$es_until"
    es_s store anchors; es_s origin "$es_af"
    es_oe
    es_subjects="$es_subjects${es_subj:-${es_af##*/}}$ES_NL"
  done
  IFS=$es_aifs; set +f
  es_ae
  if [ "$ES_OS" = darwin ]; then
    # admin-domain trust settings: the certificates an administrator (or MDM) added as trusted.
    # The System keychain itself is not opened.
    if es_tool security dump-trust-settings -d; then
      es_lbl=$(awk '/^Cert [0-9]+: / { sub(/^Cert [0-9]+: /, ""); print }' "$ES_OUT_F")
      es_subjects="$es_subjects$es_lbl${es_lbl:+$ES_NL}"
      es_list admin_trust_settings "$es_lbl"
    else
      es_list admin_trust_settings ""
    fi
  fi
  es_list enterprise_roots "$es_subjects"
  es_list custom_anchors "$es_anchors"
  es_n root_count "$es_rootc"
  es_z authroot_count
  es_z root_auto_update
  es_sn default_bundle "$es_first"
  es_src "environment TLS variables"
  es_o runtime_trust
  es_dis=
  for es_v in $ES_TLS_ENV; do
    eval "es_vv=\${$es_v-}"
    [ -n "$es_vv" ] || continue
    es_e "$es_v" "$es_vv"
    case "$es_v=$es_vv" in
      NODE_TLS_REJECT_UNAUTHORIZED=0) es_dis="${es_dis}NODE_TLS_REJECT_UNAUTHORIZED=0$ES_NL" ;;
      PYTHONHTTPSVERIFY=0) es_dis="${es_dis}PYTHONHTTPSVERIFY=0$ES_NL" ;;
      GIT_SSL_NO_VERIFY=0|GIT_SSL_NO_VERIFY=false) ;;
      GIT_SSL_NO_VERIFY=*) es_dis="${es_dis}GIT_SSL_NO_VERIFY=$es_vv$ES_NL" ;;
      NODE_OPTIONS=*--use-openssl-ca*|NODE_OPTIONS=*--use-system-ca*) ;;
    esac
  done
  es_oe
  es_jh=${JAVA_HOME:-}
  es_jc=
  if [ -n "$es_jh" ]; then
    for es_f in "$es_jh/lib/security/cacerts" "$es_jh/jre/lib/security/cacerts"; do
      if es_ltest -f "$es_f"; then es_jc=$es_f; break; fi
    done
  fi
  if [ -n "$es_jc" ]; then
    es_src "read \$JAVA_HOME/lib/security/cacerts (size and date)"
    es_ls=$(ls -ldL "$es_jc" 2>/dev/null)
    es_o java_cacerts
    es_s path "$es_jc"
    set -f; set -- $es_ls; set +f
    es_n size_bytes "${5:-}"
    es_s modified "${6:-} ${7:-} ${8:-}"
    es_oe
  else
    es_z java_cacerts
  fi
  case $ES_OS in
    zos) es_note "z/OS: system certificates are in RACF key rings and gskkyman key databases (not read); only file bundles and Java cacerts are checked" ;;
    os400) es_note "IBM i: system certificates are in the Digital Certificate Manager stores (not read); only PASE file bundles and Java cacerts are checked" ;;
  esac
  [ -n "$es_first" ] || [ -n "$es_anchors" ] || [ "$ES_OS" = darwin ] || es_partial "no CA bundle found in the known locations"
  es_fact ca_custom "$es_na"
  es_fact ca_subjects "$es_subjects"
  es_fact tls_disabled_env "$es_dis"
  es_fact ca_bundle "$es_first"
}

probe_tls_java_cacerts() {
  es_kt=
  if [ -n "${JAVA_HOME:-}" ] && es_ltest -x "$JAVA_HOME/bin/keytool"; then es_kt=$JAVA_HOME/bin/keytool
  elif es_which keytool; then es_kt=$ES_W
  fi
  if [ -z "$es_kt" ]; then
    es_status not_found
    es_note "keytool was not found (JAVA_HOME/bin, PATH)"
    return 0
  fi
  if ! es_runnable "$es_kt" keytool; then
    es_status skipped
    es_note "$es_kt: $ES_WHY"
    return 0
  fi
  es_cmd "$es_kt" -list -v -cacerts -storepass changeit
  if [ "$ES_RC" != 0 ] && grep -i -E 'illegal option|unknown option' "$ES_OUT_F" "$ES_ERR_F" >/dev/null 2>&1; then
    es_ks=
    es_kh=${es_kt%/bin/keytool}
    for es_f in "$es_kh/lib/security/cacerts" "$es_kh/jre/lib/security/cacerts"; do
      if es_ltest -f "$es_f"; then es_ks=$es_f; break; fi
    done
    [ -n "$es_ks" ] && es_cmd "$es_kt" -list -v -keystore "$es_ks" -storepass changeit
  fi
  if [ "$ES_RC" != 0 ]; then
    cat "$ES_ERR_F" >>"$ES_OUT_F" 2>/dev/null
    es_raw keytool "$ES_OUT_F"
    es_status error
    es_error "keytool failed (exit $ES_RC)"
    return 0
  fi
  es_cnt=$(awk '/Your keystore contains/ { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) { print $i; exit } }' "$ES_OUT_F")
  awk '/^Owner: / { sub(/^Owner: /, ""); print }' "$ES_OUT_F" >"$ES_P_DIR/owners.txt"
  es_s keytool "$es_kt"
  es_n entries "$es_cnt"
  es_list_lines owners "$ES_P_DIR/owners.txt" s 400
  es_missing=
  es_aifs=$IFS; IFS=$ES_NL; set -f
  for es_subj in $ES_F_ca_subjects; do
    IFS=$es_aifs
    es_cn=$(printf '%s\n' "$es_subj" | awk '{ if (match($0, /CN ?= ?[^,\/]+/)) { s = substr($0, RSTART, RLENGTH); sub(/^CN ?= ?/, "", s); print s } else print $0 }')
    [ -n "$es_cn" ] || continue
    grep -F "$es_cn" "$ES_P_DIR/owners.txt" >/dev/null 2>&1 || es_missing="$es_missing$es_cn$ES_NL"
  done
  IFS=$es_aifs; set +f
  es_list enterprise_roots_missing "$es_missing"
  es_fact java_missing_roots "$es_missing"
}
