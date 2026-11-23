# ============================================================== rendering

# es_awk_program: the event writer as one awk program (redaction rules, then the writer); the
# scanner writes it to $ES_TMP/json.awk at scan start
es_awk_program() { es_awk_redact; es_awk_redact_xml; es_awk_redact_text; es_awk_json; }

# es_awk MODE FILE...: run the event writer with the redaction rules
es_awk() {
  es_am=$1; shift
  awk -v mode="$es_am" -v redact="$ES_REDACT" -v placeholder="$ES_REDACT_PLACEHOLDER" \
    -v segs="$ES_REDACT_SEGMENTS" -v contains="$ES_REDACT_CONTAINS" -v namesfx="$ES_REDACT_NAME_SUFFIXES" \
    -v excepts="$ES_REDACT_EXCEPTIONS" -v sfxexc="$ES_REDACT_SUFFIX_EXCEPTIONS" \
    -v prefixes="$ES_REDACT_PREFIXES" -v minlen="$ES_REDACT_MINLEN" -v pairkeys="$ES_REDACT_PAIR_KEYS" \
    -v optwords="$ES_REDACT_OPTION_WORDS" -v hdrwords="$ES_REDACT_HEADER_WORDS" -v toolopts="$ES_REDACT_TOOL_OPTIONS" \
    -v xmlel="$ES_REDACT_XML_ELEMENTS" -v xmlat="$ES_REDACT_XML_ATTRS" -v pkmarker="$ES_REDACT_PKMARKER" \
    -v ebcdic="${ES_EBCDIC:-0}" -v ebcdic_tab="${ES_EBCDIC_ARG:-}" \
    -f "$ES_TMP/json.awk" "$@"
}

# es_ev_check DIR: make the event file of a stopped probe well-formed before it is rendered.
# A probe killed while an awk wrote to fd 5 (block-buffered) leaves a last line without a line
# break: that line is dropped (a cut-off value is not data, and a closer glued onto it would
# put every later probe inside this one). Structures left open are closed; broken data is
# discarded.
es_ev_check() {
  [ -s "$1/data.ev" ] || return 0
  es_cnl=$(wc -l <"$1/data.ev" | tr -d ' ')
  es_cl=$(awk -v nl="${es_cnl:-0}" '
    NR > nl + 0 { cut = 1; exit }
    /^[{[]/ { st[++d] = substr($0, 1, 1); next }
    /^[]}]/ { if (d == 0) { bad = 1; exit } d--; next }
    END { if (bad) { print "BAD"; exit } if (cut) print "CUT"; for (i = d; i > 0; i--) print (st[i] == "{" ? "}" : "]") }' "$1/data.ev")
  case $es_cl in
    BAD)
      mv "$1/data.ev" "$1/data.bad"; : >"$1/data.ev"
      printf '%s\n' "probe data was malformed and has been discarded" >>"$1/notes"
      return 0 ;;
    CUT*)
      awk -v nl="${es_cnl:-0}" 'NR <= nl + 0' "$1/data.ev" >"$1/data.cut" && mv "$1/data.cut" "$1/data.ev"
      es_cl=${es_cl#CUT}; es_cl=${es_cl#"$ES_NL"}
      printf '%s\n' "the probe was stopped while writing: its last, incomplete data line was dropped" >>"$1/notes" ;;
  esac
  [ -n "$es_cl" ] || return 0
  printf '%s\n' "$es_cl" >>"$1/data.ev"
  printf '%s\n' "probe data is incomplete (the probe was stopped)" >>"$1/notes"
}

# es_counts -> ES_C_<status>, ES_C_TOTAL, ES_C_GOOD, ES_EXIT
es_counts() {
  ES_C_ok=0; ES_C_partial=0; ES_C_not_found=0; ES_C_not_applicable=0
  ES_C_denied=0; ES_C_timeout=0; ES_C_error=0; ES_C_skipped=0; ES_C_TOTAL=0; ES_EXIT=0
  while IFS=$ES_TAB read -r es_cn es_cid es_cst es_cdur es_ckind; do
    ES_C_TOTAL=$((ES_C_TOTAL + 1))
    case $es_cst in
      ok|partial|not_found|not_applicable|denied|timeout|error|skipped) eval "ES_C_$es_cst=\$((ES_C_$es_cst + 1))" ;;
    esac
    case $es_cst in partial|denied|timeout|error) ES_EXIT=1 ;; esac
    [ "$es_ckind" = budget ] && ES_EXIT=1
  done <"$ES_TMP/results.tsv"
  ES_C_GOOD=$((ES_C_ok + ES_C_not_found + ES_C_not_applicable))
}

# es_envelope N ID STATUS DURATION: one probes.<id> object (fd 5)
es_envelope() {
  es_edir="$ES_TMP/p/$1"
  IFS=$ES_TAB read -r es_eid es_etitle es_etier es_escope <"$es_edir/meta"
  es_o "$2"
  es_s status "$3"
  es_s tier "$es_etier"
  es_s scope "$es_escope"
  es_s title "$es_etitle"
  es_list_file sources "$es_edir/sources"
  es_n duration_ms "$4"
  es_o data
  [ "${ES_SAFE:-0}" != 1 ] && [ -s "$es_edir/data.ev" ] && printf '@\t%s\n' "$es_edir/data.ev" >&5
  es_oe
  es_etrunc=false
  [ -f "$es_edir/truncated" ] && es_etrunc=true
  if [ "${ES_SAFE:-0}" != 1 ] && [ -s "$es_edir/raw" ]; then
    es_o raw
    es_etotal=0
    while IFS=$ES_TAB read -r es_elabel es_efile; do
      [ -r "$es_efile" ] || continue
      es_esize=$(wc -c <"$es_efile" | tr -d ' ')
      es_is_num "$es_esize" || es_esize=0
      es_eleft=$((ES_RAW_CAP - es_etotal))
      if [ "$es_eleft" -le 0 ]; then es_etrunc=true; break; fi
      if [ "$es_esize" -gt "$es_eleft" ]; then es_etrunc=true; es_esize=$es_eleft; fi
      es_f "$es_elabel" "$es_efile" "$es_esize"
      es_etotal=$((es_etotal + es_esize))
    done <"$es_edir/raw"
    es_oe
  fi
  es_b truncated "$es_etrunc"
  if [ "${ES_SAFE:-0}" = 1 ]; then es_s error "the report was written without probe data because rendering it failed"
  elif es_read1 "$es_edir/error"; then es_s error "$ES_L"; else es_z error; fi
  [ -s "$es_edir/notes" ] && es_list_file notes "$es_edir/notes"
  es_oe
}

# es_render_json: the report must always be written. When rendering fails (an awk error on
# some probe's data), it is written again with every probe's data and raw output left out.
es_render_json() {
  ES_SAFE=0
  es_render_json_once
  if ! es_json_ok "$ES_OUT/envscan.json"; then
    es_say "envscan: rendering envscan.json failed; writing it again without probe data"
    ES_SAFE=1
    es_render_json_once
  fi
}

es_json_ok() { [ -s "$1" ] && [ "$(awk 'END { print $0 }' "$1")" = "}" ]; }

es_render_json_once() {
  exec 5>"$ES_TMP/report.ev"
  es_o -
  es_s schema "$ES_SCHEMA"
  es_o scanner
  es_s name "$ES_NAME"; es_s version "$ES_VERSION"; es_s impl "$ES_IMPL"; es_s shell_version "$ES_SHELL"
  es_oe
  es_o run
  es_s started_utc "$ES_STARTED"; es_s finished_utc "$ES_FINISHED"
  es_n duration_ms "$((ES_T1 - ES_T0))"
  es_a tiers; es_s - default
  [ "$ES_DEEP" = 1 ] && es_s - deep
  [ "$ES_NET" = 1 ] && es_s - net
  es_ae
  es_list flags "$ES_FLAGS"
  es_s cwd "$ES_CWD"; es_s out_dir "$ES_OUT"
  es_n exit_code "$ES_EXIT"
  if [ "$ES_REDACT" = 1 ]; then es_b redaction true; else es_b redaction false; fi
  es_o counts
  for es_st in ok partial not_found not_applicable denied timeout error skipped; do
    eval "es_n $es_st \"\$ES_C_$es_st\""
  done
  es_oe
  [ -n "$ES_ROOT" ] && es_s test_root "$ES_ROOT"
  es_oe
  es_o host
  es_s os_family "$ES_OS"
  es_s os_name "${ES_F_os_name:-$ES_UNAME_S}"
  es_s os_version "${ES_F_os_version:-$ES_UNAME_R}"
  es_s arch "$ES_ARCH"
  es_s hostname "$ES_HOST"
  es_oe
  es_a findings
  [ -s "$ES_TMP/findings.ev" ] && printf '@\t%s\n' "$ES_TMP/findings.ev" >&5
  es_ae
  es_o probes
  while IFS=$ES_TAB read -r es_rn es_rid es_rst es_rdur es_rkind; do
    es_envelope "$es_rn" "$es_rid" "$es_rst" "$es_rdur"
  done <"$ES_TMP/results.tsv"
  es_oe
  es_oe
  exec 5>&-
  es_awk json "$ES_TMP/report.ev" >"$ES_OUT/envscan.json" || es_say "envscan: error writing envscan.json"
}

es_h() { es_ev h - "$1"; }

es_render_md() {
  exec 5>"$ES_TMP/md.ev"
  es_h "# envscan report: $ES_HOST"
  es_h ""
  es_h "- $ES_NAME $ES_VERSION ($ES_IMPL, $ES_SHELL), started $ES_STARTED, finished $ES_FINISHED"
  es_h "- tiers: $es_tiers; redaction: $([ "$ES_REDACT" = 1 ] && printf on || printf off); exit code $ES_EXIT"
  es_h "- probes: $ES_C_TOTAL ($ES_C_ok ok, $ES_C_partial partial, $ES_C_not_found not_found, $ES_C_not_applicable not_applicable, $ES_C_denied denied, $ES_C_timeout timeout, $ES_C_error error, $ES_C_skipped skipped)"
  [ -n "$ES_ROOT" ] && es_h "- test root (ENVSCAN_ROOT): $ES_ROOT"
  es_h ""
  es_h "## Findings"
  es_h ""
  if [ -s "$ES_TMP/findings.tsv" ]; then
    while IFS=$ES_TAB read -r es_fid es_fsev es_ftitle es_fdetail es_frec es_fev; do
      es_h "- **[$es_fsev] $es_ftitle** ($es_fid): $es_fdetail"
      es_h "  - recommendation: $es_frec"
      es_h "  - evidence: $es_fev"
    done <"$ES_TMP/findings.tsv"
  else
    es_h "- none"
  fi
  while IFS=$ES_TAB read -r es_rn es_rid es_rst es_rdur es_rkind; do
    es_mdir="$ES_TMP/p/$es_rn"
    IFS=$ES_TAB read -r es_mid es_mtitle es_mtier es_mscope <"$es_mdir/meta"
    es_h ""
    es_h "## $es_rid - $es_mtitle"
    es_h ""
    es_h "- status: **$es_rst** - tier $es_mtier - scope $es_mscope - $es_rdur ms"
    if [ -s "$es_mdir/sources" ]; then
      es_msrc=
      while IFS= read -r es_ml; do es_msrc="$es_msrc${es_msrc:+; }$es_ml"; done <"$es_mdir/sources"
      es_h "- sources: $es_msrc"
    fi
    es_read1 "$es_mdir/error" && es_h "- error: $ES_L"
    if [ -s "$es_mdir/notes" ]; then
      while IFS= read -r es_mnote; do es_h "- note: $es_mnote"; done <"$es_mdir/notes"
    fi
    if [ -s "$es_mdir/data.ev" ]; then
      es_h ""
      es_o data; printf '@\t%s\n' "$es_mdir/data.ev" >&5; es_oe
    fi
    if [ -s "$es_mdir/raw" ]; then
      while IFS=$ES_TAB read -r es_mlabel es_mfile; do
        [ -r "$es_mfile" ] || continue
        es_h ""
        es_h "raw output \`$es_mlabel\`:"
        printf 'r\t%s\t%s\t%s\n' "$es_mlabel" "$es_mfile" 8192 >&5
      done <"$es_mdir/raw"
    fi
  done <"$ES_TMP/results.tsv"
  exec 5>&-
  es_awk md "$ES_TMP/md.ev" >"$ES_OUT/envscan.md" || es_say "envscan: error writing envscan.md"
}

es_render_log() {
  {
    printf '%s\n' "envscan $ES_VERSION ($ES_IMPL) on $ES_HOST, started $ES_STARTED, finished $ES_FINISHED"
    cat "$ES_TMP/log"
    if [ -s "$ES_TMP/shell.err" ]; then
      printf '%s\n' "--- shell messages:"
      awk 'NR <= 200' "$ES_TMP/shell.err"
    fi
    printf 'exit code %s\n' "$ES_EXIT"
  } >"$ES_TMP/log.full"
  es_awk log "$ES_TMP/log.full" >"$ES_OUT/envscan.log"
}

# es_conv_check FILE NAME: self-check of an iconv result. z/OS iconv may or may not turn NL (0x15)
# into LF, and standard CCSID 1047 maps NL to U+0085: the converted file must hold LF bytes, no
# C2 85 pair, and envscan.json must start with { (0x7b). Anything else fails.
es_conv_check() {
  es_cc=$(od -An -v -tx1 "$1" 2>/dev/null | awk -v want="$2" '
    { for (i = 1; i <= NF; i++) { n++; if (n == 1) first = $i; if ($i == "0a") lf = 1; if (prev == "c2" && $i == "85") bad = 1; prev = $i } }
    END { ok = (lf && !bad); if (want == "envscan.json" && first != "7b") ok = 0; print (ok ? "ok" : "bad") }')
  [ "$es_cc" = ok ]
}

# es_ebcdic_convert FILE...: z/OS only. The report files are written in the host code page; when
# that is IBM-1047 each is converted to UTF-8 (in a temporary file below $ES_TMP), checked
# (es_conv_check), moved into place and tagged with the numeric CCSID 1208 (UTF-8). Any failure
# leaves the file as written and is logged: the report is never lost. Another EBCDIC code page is
# not converted at all. The conversion runs without the scanner's auto-conversion settings, so
# iconv reads the bytes as they are and its output is not converted again.
es_ebcdic_convert() {
  [ "${ES_OS:-}" = zos ] && [ "${ES_EBCDIC:-0}" = 1 ] || return 0
  if [ "${ES_EBCDIC_1047:-0}" != 1 ]; then
    es_say "envscan: the host code page is not IBM-1047 (the character [ is not the byte ad); the report files stay in the host code page, unconverted"
    return 0
  fi
  for es_xc in "$@"; do
    [ -s "$es_xc" ] || continue
    es_xn=${es_xc##*/}; es_xt="$ES_TMP/$es_xn.conv"
    if ! ( _BPXK_AUTOCVT=OFF; export _BPXK_AUTOCVT; unset _CEE_RUNOPTS
           iconv -f IBM-1047 -t UTF-8 <"$es_xc" >"$es_xt" ) 2>/dev/null || [ ! -s "$es_xt" ]; then
      rm -f "$es_xt"
      es_say "envscan: iconv IBM-1047 to UTF-8 failed for $es_xn; it stays in IBM-1047"
    elif ! es_conv_check "$es_xt" "$es_xn"; then
      rm -f "$es_xt"
      es_say "envscan: the UTF-8 copy of $es_xn failed the self-check (no line feed, NL left as U+0085, or envscan.json not starting with a brace); it stays in IBM-1047"
    elif mv "$es_xt" "$es_xc" 2>/dev/null; then
      chtag -tc 1208 "$es_xc" 2>/dev/null || es_say "envscan: chtag failed for $es_xn; the file is UTF-8 but untagged"
    else
      rm -f "$es_xt"
      es_say "envscan: could not replace $es_xn with its UTF-8 copy; it stays in IBM-1047"
    fi
  done
  return 0
}

es_render() {
  es_now_ms; ES_T1=$ES_MS
  es_utc; ES_FINISHED=$ES_UTC
  es_render_json
  es_render_md
  es_brief >"$ES_TMP/brief.txt"
  es_awk text "$ES_TMP/brief.txt" >"$ES_OUT/AGENT_BRIEF.md"
  es_say "envscan: $ES_C_TOTAL probes, $ES_C_ok ok, $((ES_C_TOTAL - ES_C_GOOD - ES_C_skipped)) not fully checked, $ES_C_skipped skipped; exit $ES_EXIT"
  es_ebcdic_convert "$ES_OUT/envscan.json" "$ES_OUT/envscan.md" "$ES_OUT/AGENT_BRIEF.md"
  es_render_log
  es_ebcdic_convert "$ES_OUT/envscan.log"
}
