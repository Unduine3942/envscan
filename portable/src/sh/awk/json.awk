# envscan.sh event writer: turns probe event streams into JSON, Markdown or
# redacted text. POSIX awk only (gawk, mawk, nawk/BWK, busybox); run with LC_ALL=C.
# The scanner runs redact.awk (the redaction rules) and this file as one program.
#
# Event lines:  <type> TAB <key> [TAB <value> [TAB <extra>]]
#   {  [  begin object / array (key "-" inside arrays)    }  ]  end
#   s  string (value rules)               S  string with \\ \n \t \r escapes
#   e  environment value: named-value rules with <key> as the name
#   E  like e, value escaped like S
#   v  key TAB name TAB value: named-value rules with <name> as the name
#   l  configuration line (line rules)    c  command line (command-line rules)
#   x  string already redacted, escaped like S (written by this program only)
#   n  number (non-numeric values become strings)   b  true/false   z  null
#   f  key TAB path [TAB max-bytes]: file content, text rules
#   r  like f; Markdown prints it as a fenced block
#   F  key TAB path TAB max-bytes TAB mode TAB match-words: a configuration file as members
#      <key> (array of lines), truncated and line_count. Text rules run over the whole file
#      first; mode "lines" then keeps the lines that contain a match word (words split by |,
#      case-insensitive), other modes keep the lines that are not blank or comments
#   h  Markdown only: the value is printed as a line (headings, summaries)
#   @  TAB path: process the event lines of another file here (no nesting limit)
#
# Modes (-v mode=...):
#   json   events -> JSON (pure ASCII, \uXXXX escapes, invalid UTF-8 -> U+FFFD)
#   md     events -> nested Markdown bullet lists
#   text   every input line -> redacted line (line rules)
#   log    every input line -> redacted line (command-line rules)
#   envev  "NAME TAB value" lines (value escaped like S; es_env_capture) -> one x event per
#          variable, redacted here (named-value rules), then "}" and the count:
#          n TAB redacted TAB <number of values the redaction changed>
#
# Other -v variables: mdmax, and the redaction settings (see redact.awk)
#
# EBCDIC hosts (z/OS, IBM i QSH): the shell detects them once and passes -v ebcdic=1 and
# -v ebcdic_tab="<256 decimal code points>" (IBM-1047 to Unicode, spec/ebcdic.toml). The 95
# printable ASCII characters are recognised through a string literal of this file (so they are
# right in any EBCDIC code page); every other byte is mapped through the table to a \uXXXX
# escape, and UTF-8 validation is skipped. The JSON is then pure ASCII; its text is still
# EBCDIC, which the shell converts after writing (es_ebcdic_convert). The table is IBM-1047 only:
# in another EBCDIC code page the shell passes an empty ebcdic_tab, and every byte outside printable
# ASCII then shows as U+FFFD (JSON) or ? (Markdown) instead of a wrong character.

BEGIN {
    if (ebcdic + 0) ebcdic_setup()
    else for (i = 1; i < 256; i++) ORD[sprintf("%c", i)] = i
    redact_setup()
    if (mdmax == "") mdmax = 300
    depth = 0; nred = 0
    NULC = sprintf("%c", 0); BOM_LE = "\377\376"; BOM_BE = "\376\377"
    NOREAD = "[UTF-16 or binary content not read]"
}

# ------------------------------------------------------------------ values

function unesc(s,   r, i, n, c, d) {
    if (index(s, "\\") == 0) return s
    r = ""; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\\" && i < n) {
            d = substr(s, i + 1, 1); i++
            if (d == "n") c = "\n"; else if (d == "t") c = "\t"; else if (d == "r") c = "\r"; else c = d
        }
        r = r c
    }
    return r
}

# binary_line: a line that shows a file is UTF-16 (byte order mark on the first line) or holds a
# NUL byte (awks that cannot hold NUL, such as mawk, drop it; the shell checks those files).
# Such content is never emitted: the redaction rules cannot match NUL-interleaved text.
function binary_line(line, first) {
    if (first && (substr(line, 1, 2) == BOM_LE || substr(line, 1, 2) == BOM_BE)) return 1
    return (NULC != "" && index(line, NULC) > 0)
}

# read_file: a whole file (text rules); a private key anywhere replaces the whole content. max
# counts the line breaks between lines only, so a last line without one is not cut off.
function read_file(path, max,   line, r, n, total, pk, add, nl) {
    r = ""; n = 0; total = 0; pk = 0; text_reset()
    if (max == "" || max + 0 <= 0) max = 65536
    nl = 0
    while ((getline line < path) > 0) {
        if (binary_line(line, ++nl == 1)) { close(path); return NOREAD }
        sub(/\r$/, "", line)
        if (index(line, pkmarker) > 0) pk = 1
        add = length(line) + (n ? 1 : 0)
        if (total + add > max + 0) { r = r (n ? "\n" : "") "[... truncated]"; break }
        r = r (n ? "\n" : "") (redact ? text_line(line) : line); n++; total += add
    }
    close(path)
    if (pk && redact) return PKTEXT
    return r
}

function num_text(v,   neg) {
    if (v !~ /^-?[0-9]+(\.[0-9]+)?$/) return ""
    neg = ""
    if (substr(v, 1, 1) == "-") { neg = "-"; v = substr(v, 2) }
    while (length(v) > 1 && substr(v, 1, 1) == "0" && substr(v, 2, 1) != ".") v = substr(v, 2)
    if (neg == "-" && v == "0") neg = ""
    return neg v
}

# text_of sets KIND to str|num|bool|null and returns the (redacted) plain text
function text_of(t, key, val, extra,   k, name, x) {
    KIND = "str"
    if (t == "s") return redact ? redact_value(val) : val
    if (t == "S") { x = unesc(val); return redact ? redact_value(x) : x }
    if (t == "x") return unesc(val)
    if (t == "e" || t == "E") { x = (t == "E") ? unesc(val) : val; return redact_named(key, x) }
    if (t == "v") {
        k = index(val, "\t"); name = substr(val, 1, k - 1); x = substr(val, k + 1)
        if (k == 0) { name = ""; x = val }
        return redact_named(name, x)
    }
    if (t == "l") return redact_line(val)
    if (t == "c") return redact_cmdline(val)
    if (t == "f" || t == "r") return read_file(val, extra)
    if (t == "n") { x = num_text(val); if (x != "") { KIND = "num"; return x } return redact ? redact_value(val) : val }
    if (t == "b") { if (val == "true" || val == "false") { KIND = "bool"; return val } KIND = "null"; return "null" }
    KIND = "null"; return "null"
}

# config_lines KEY SPEC: the F event (see the header); SPEC = path TAB max TAB mode TAB words.
# The byte count and the case-insensitive match are the same as es_config_raw in 24-pkg.sh.
function config_lines(key, spec,   P, path, max, cmode, nm, M, line, total, trunc, pk, n, i, k, keep, red, cnt, add, nl, bin) {
    split(spec, P, "\t"); path = P[1]; max = P[2] + 0; cmode = P[3]
    if (max <= 0) max = 65536
    nm = (P[4] == "" || P[4] == "-") ? 0 : split(tolower(P[4]), M, "|")
    split("", RAW); n = 0; total = 0; trunc = 0; pk = 0; text_reset()
    nl = 0; bin = 0
    while ((getline line < path) > 0) {
        if (binary_line(line, ++nl == 1)) { bin = 1; break }
        sub(/\r$/, "", line)
        add = length(line) + (n ? 1 : 0)
        if (total + add > max) { trunc = 1; break }
        total += add
        RAW[++n] = line
        if (index(line, pkmarker) > 0) pk = 1
    }
    close(path)
    handle("[\t" key)
    cnt = 0
    if (bin) { handle("x\t-\t" NOREAD); cnt = 1 }
    else if (pk && redact) { handle("x\t-\t" PKTEXT); cnt = 1 }
    else for (i = 1; i <= n; i++) {
        line = RAW[i]
        red = redact ? text_line(line) : line
        if (line ~ /^[ \t]*$/) continue
        if (cmode == "lines") { keep = 0; for (k = 1; k <= nm; k++) if (index(tolower(line), M[k]) > 0) { keep = 1; break } if (!keep) continue }
        else if (line ~ /^[ \t]*[#;]/) continue
        handle("x\t-\t" env_escape(red)); cnt++
    }
    handle("]")
    handle("b\ttruncated\t" (trunc ? "true" : "false"))
    handle("n\tline_count\t" cnt)
}

# ------------------------------------------------------------------ EBCDIC

# ebcdic_setup: PRT[c] holds every printable ASCII character as this awk sees it; ECP[c] the
# Unicode code point of every other byte (IBM-1047); NONPRT matches a character that is not in PRT.
function ebcdic_setup(   a, i, c, n, E, lets) {
    a = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    n = length(a)
    for (i = 1; i <= n; i++) PRT[substr(a, i, 1)] = 1
    n = split(ebcdic_tab, E, " ")
    HAVE_TAB = (n > 255)
    for (i = 2; i <= n; i++) {
        c = sprintf("%c", i - 1)
        if (!(c in PRT)) ECP[c] = E[i] + 0
    }
    lets = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    NONPRT = "[^]" lets "0-9 !\"#$%&'()*+,./:;<=>?@_`{|}~^[\\\\-]"
}

# plain: no character outside printable ASCII
function plain(s) {
    if (ebcdic + 0) return !(s ~ NONPRT)
    return !(s ~ /[^ -~]/)
}

# ecp: Unicode code point of a byte that is not printable ASCII (U+FFFD when unknown)
function ecp(c) { return (c in ECP) ? ECP[c] : 65533 }

# e8clean: Markdown text on an EBCDIC host: controls become spaces, other characters stay
# (the shell converts the file to UTF-8 afterwards)
function e8clean(s,   r, p, i, n, c, o) {
    r = ""; p = ""; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c in PRT) p = p c
        else if (!HAVE_TAB) p = p "?"
        else { o = ecp(c); p = p ((o < 32 || (o >= 127 && o < 160)) ? " " : c) }
        if (length(p) > 400) { r = r p; p = "" }
    }
    return r p
}

# jslow_e: escape what jrep left, on an EBCDIC host
function jslow_e(s,   r, p, i, n, c, o) {
    r = ""; p = ""; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c in PRT) p = p c
        else { o = ecp(c); p = p ((o < 32 || o == 127) ? ctl(o) : ucode(o)) }
        if (length(p) > 400) { r = r p; p = "" }
    }
    return r p
}

# ------------------------------------------------------------------ UTF-8

# u8len: byte length of the valid UTF-8 sequence starting at s[i] (0 when invalid); sets U8CP
function u8len(s, i, n,   o, need, b2, b3, b4) {
    o = ORD[substr(s, i, 1)] + 0
    need = 0
    if (o >= 194 && o <= 223) need = 1
    else if (o >= 224 && o <= 239) need = 2
    else if (o >= 240 && o <= 244) need = 3
    if (need == 0 || i + need > n) return 0
    b2 = ORD[substr(s, i + 1, 1)] + 0
    if (b2 < 128 || b2 > 191) return 0
    if ((o == 224 && b2 < 160) || (o == 237 && b2 > 159) || (o == 240 && b2 < 144) || (o == 244 && b2 > 143)) return 0
    if (need >= 2) { b3 = ORD[substr(s, i + 2, 1)] + 0; if (b3 < 128 || b3 > 191) return 0 }
    if (need == 3) { b4 = ORD[substr(s, i + 3, 1)] + 0; if (b4 < 128 || b4 > 191) return 0 }
    if (need == 1) U8CP = (o - 192) * 64 + (b2 - 128)
    else if (need == 2) U8CP = (o - 224) * 4096 + (b2 - 128) * 64 + (b3 - 128)
    else U8CP = (o - 240) * 262144 + (b2 - 128) * 4096 + (b3 - 128) * 64 + (b4 - 128)
    return need + 1
}

# u8clean: valid UTF-8 kept, invalid bytes -> "?", control characters -> space
function u8clean(s,   r, p, i, n, c, o, k) {
    if (plain(s)) return s
    if (ebcdic + 0) return e8clean(s)
    r = ""; p = ""; n = length(s); i = 1
    while (i <= n) {
        c = substr(s, i, 1); o = ORD[c] + 0
        if (o >= 32 && o < 127) { p = p c; i++ }
        else if (o < 32 || o == 127) { p = p " "; i++ }
        else {
            k = u8len(s, i, n)
            if (k == 0) { p = p "?"; i++ } else { p = p substr(s, i, k); i += k }
        }
        if (length(p) > 400) { r = r p; p = "" }
    }
    return r p
}

# ------------------------------------------------------------------ JSON

function ctl(o) {
    if (o == 10) return "\\n"
    if (o == 13) return "\\r"
    if (o == 9) return "\\t"
    if (o == 8) return "\\b"
    if (o == 12) return "\\f"
    return sprintf("\\u%04x", o)
}

function ucode(cp,   hi, lo) {
    if (cp < 65536) return sprintf("\\u%04x", cp)
    cp -= 65536; hi = 55296 + int(cp / 1024); lo = 56320 + (cp % 1024)
    return sprintf("\\u%04x\\u%04x", hi, lo)
}

# jrep: replace every occurrence of the single character from (split is literal for one character)
function jrep(s, from, to,   n, i, r, P) {
    n = split(s, P, from)
    r = P[1]
    for (i = 2; i <= n; i++) r = r to P[i]
    return r
}

# jslow: escape what jrep left (other control characters, non-ASCII bytes)
function jslow(s,   r, p, i, n, c, o, k) {
    if (ebcdic + 0) return jslow_e(s)
    r = ""; p = ""; n = length(s); i = 1
    while (i <= n) {
        c = substr(s, i, 1); o = ORD[c] + 0
        if (o >= 32 && o < 127) { p = p c; i++ }
        else if (o < 32 || o == 127) { p = p ctl(o); i++ }
        else {
            k = u8len(s, i, n)
            if (k == 0) { p = p "\\ufffd"; i++ } else { p = p ucode(U8CP); i += k }
        }
        if (length(p) > 400) { r = r p; p = "" }
    }
    return r p
}

function jstr(s) {
    if (plain(s) && s !~ /["\\]/) return "\"" s "\""
    if (index(s, "\\") > 0) s = jrep(s, "\\", "\\\\")
    if (index(s, "\"") > 0) s = jrep(s, "\"", "\\\"")
    if (!plain(s)) {
        if (index(s, "\n") > 0) s = jrep(s, "\n", "\\n")
        if (index(s, "\t") > 0) s = jrep(s, "\t", "\\t")
        if (index(s, "\r") > 0) s = jrep(s, "\r", "\\r")
        if (!plain(s)) s = jslow(s)
    }
    return "\"" s "\""
}

function put(s) { printf "%s", s }

function ind(d,   s, i) { s = ""; for (i = 0; i < d; i++) s = s "  "; return s }

function begin_member(key) {
    if (depth == 0) return
    if (TYPE[depth] == "a" && PEND[depth]) flush_array(depth)
    if (CNT[depth]++) put(",")
    put("\n" ind(depth))
    if (TYPE[depth] == "o") put(jstr(key) ": ")
}

function flush_array(d,   i) {
    put("[")
    for (i = 1; i <= NI[d]; i++) put((i > 1 ? "," : "") "\n" ind(d) IT[d, i])
    CNT[d] = NI[d]; PEND[d] = 0
}

function json_event(t, key, val, extra,   v, s, i) {
    if (t == "h") return
    if (t == "{" || t == "[") {
        begin_member(key)
        depth++; TYPE[depth] = (t == "{") ? "o" : "a"; CNT[depth] = 0; NI[depth] = 0; IL[depth] = 0
        PEND[depth] = (t == "[")
        if (t == "{") put("{")
        return
    }
    if (t == "}" || t == "]") {
        if (depth == 0) return
        if (TYPE[depth] == "a" && PEND[depth]) {
            s = "["
            for (i = 1; i <= NI[depth]; i++) s = s (i > 1 ? ", " : "") IT[depth, i]
            put(s "]")
        } else if (CNT[depth] == 0) put(TYPE[depth] == "o" ? "}" : "]")
        else put("\n" ind(depth - 1) (TYPE[depth] == "o" ? "}" : "]"))
        depth--
        if (depth == 0) put("\n")
        return
    }
    v = text_of(t, key, val, extra)
    if (KIND == "str") v = jstr(v)
    if (depth > 0 && TYPE[depth] == "a" && PEND[depth]) {
        NI[depth]++; IT[depth, NI[depth]] = v; IL[depth] += length(v) + 2
        if (IL[depth] > 100 || NI[depth] > 16) flush_array(depth)
        return
    }
    begin_member(key); put(v)
}

# ------------------------------------------------------------------ Markdown

function md_clean(v) {
    gsub(/\r/, "", v); gsub(/\n/, " / ", v); gsub(/\t/, " ", v); gsub(/\|/, "/", v)
    v = u8clean(v)
    if (length(v) > mdmax + 0) v = substr(v, 1, mdmax) "..."
    return v
}

function md_label(d, key) { return (TYPE[d] == "a") ? "" : key ":" }

function md_line(d, label, v) { print ind(d) "- " (label == "" ? v : label " " v) }

function md_flush(d,   i, label) {
    label = md_label(d - 1, KEY[d])
    print ind(d - 2) "- " (label == "" ? "(list)" : label)
    for (i = 1; i <= NI[d]; i++) print ind(d - 1) "- " IT[d, i]
    PEND[d] = 0; NI[d] = 0
}

function md_event(t, key, val, extra,   v, s, i) {
    if (t == "h") { print u8clean(redact_value(val)); return }
    if (t == "{" || t == "[") {
        if (depth > 0 && TYPE[depth] == "a" && PEND[depth]) md_flush(depth)
        if (depth > 0) {
            CNT[depth]++
            if (t == "{" && TYPE[depth] == "a") print ind(depth - 1) "- (" CNT[depth] ")"
            else if (t == "{") print ind(depth - 1) "- " key ":"
        }
        depth++; TYPE[depth] = (t == "{") ? "o" : "a"; CNT[depth] = 0; NI[depth] = 0; IL[depth] = 0
        PEND[depth] = (t == "["); KEY[depth] = key
        return
    }
    if (t == "}" || t == "]") {
        if (depth == 0) return
        if (TYPE[depth] == "a" && PEND[depth]) {
            s = ""
            for (i = 1; i <= NI[depth]; i++) s = s (i > 1 ? ", " : "") IT[depth, i]
            if (NI[depth] == 0) s = "(none)"
            md_line(depth - 2, md_label(depth - 1, KEY[depth]), s)
        }
        depth--
        return
    }
    if (t == "r") {
        print ""
        print "```text"
        v = read_file(val, extra)
        gsub(/```/, "'''", v)
        print u8clean_lines(v)
        print "```"
        print ""
        return
    }
    v = md_clean(text_of(t, key, val, extra))
    if (v == "") v = "\"\""
    if (depth > 0 && TYPE[depth] == "a" && PEND[depth]) {
        NI[depth]++; IT[depth, NI[depth]] = v; IL[depth] += length(v) + 2
        if (IL[depth] > 160) md_flush(depth)
        return
    }
    CNT[depth]++
    md_line(depth - 1, md_label(depth, key), v)
}

function u8clean_lines(v,   n, i, P, r) {
    n = split(v, P, "\n"); r = ""
    for (i = 1; i <= n; i++) r = r (i > 1 ? "\n" : "") u8clean(P[i])
    return r
}

# ------------------------------------------------------------------ main

function env_escape(v,   r, i, n, c) {
    if (v !~ /[\\\t\r\n]/) return v
    r = ""; n = length(v)
    for (i = 1; i <= n; i++) {
        c = substr(v, i, 1)
        if (c == "\\") c = "\\\\"
        else if (c == "\n") c = "\\n"
        else if (c == "\t") c = "\\t"
        else if (c == "\r") c = "\\r"
        r = r c
    }
    return r
}

# env_var: one "NAME TAB value" line of es_env_capture -> x event (the value redacted here, so
# that no unredacted value is written to the scanner's temp directory)
function env_var(line,   k, name, v, x) {
    k = index(line, "\t")
    if (k < 2) return
    name = substr(line, 1, k - 1); v = unesc(substr(line, k + 1))
    x = redact_named(name, v)
    if (redact && x != v) nred++
    printf "x\t%s\t%s\n", name, env_escape(x)
}

# handle: one event line; "@ TAB path" includes the event lines of another file
function handle(line,   t, key, val, extra, rest, k, p, l) {
    t = substr(line, 1, 1)
    if (t == "@") {
        p = substr(line, 3)
        while ((getline l < p) > 0) handle(l)
        close(p)
        return
    }
    key = ""; val = ""; extra = ""
    if (length(line) > 2) {
        rest = substr(line, 3); k = index(rest, "\t")
        if (k == 0) key = rest
        else {
            key = substr(rest, 1, k - 1); val = substr(rest, k + 1)
            if (t == "f" || t == "r") { k = index(val, "\t"); if (k > 0) { extra = substr(val, k + 1); val = substr(val, 1, k - 1) } }
        }
    }
    if (t == "F") { config_lines(key, val); return }
    if (mode == "md") md_event(t, key, val, extra)
    else json_event(t, key, val, extra)
}

mode == "text" { print redact_line($0); next }

mode == "log" { print redact_cmdline($0); next }

mode == "envev" { env_var($0); next }

{ handle($0) }

END {
    if (mode == "envev") printf "}\nn\tredacted\t%d\n", nred
    while (mode == "json" && depth > 0) json_event("}", "", "", "")
}
