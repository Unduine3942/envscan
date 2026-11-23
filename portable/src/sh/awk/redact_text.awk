# redact_text.awk: the xml attribute and pair LINE RULES and the TEXT RULES of spec/redaction.toml,
# part of the redaction program (es_awk_program: redact.awk, redact_xml.awk, redact_text.awk and
# json.awk share one namespace). Secret XML elements and the XML states: redact_xml.awk.

# ------------------------------------------------------------------ LINE RULES (xml)

# xml: <element>content</ for xml_elements, attribute="..." for xml_attributes,
# key|name="..secret word.." value="...", <add key="<url>" value="...">
function redact_xml(l,   i) {
    if (NXE > 0) l = redact_xml_elems(l)
    for (i = 1; i <= NXA; i++) if (index(tolower(l), XA[i]) > 0) l = redact_xml_attr(l, XA[i])
    if (index(tolower(l), "value") > 0) l = redact_xml_pairs(l)
    return l
}

# redact_xml_attr(l, a): attribute a (lower case, not preceded by a word character) = "..." ->
# content replaced. Linear time: the text is split once on a (attribute names are plain letters)
# and once on the quote, and both lists are walked forward only (no copy of the rest per match).
function redact_xml_attr(l, a,   out, cur, n, A, nq, QP, qi, i, k, m, c, j, e) {
    if (a !~ /^[abcdefghijklmnopqrstuvwxyz]+$/) return l
    n = split(tolower(l), A, a); nq = xml_quote_list(l, QP)
    out = ""; cur = 1; k = 1 - length(a); m = length(a); qi = 1
    for (i = 1; i < n; i++) {
        k += length(A[i]) + m
        if (k < cur) continue
        c = (k > 1) ? substr(l, k - 1, 1) : ""
        if (is_word(c)) continue
        j = k + m
        while (is_ws(substr(l, j, 1))) j++
        if (substr(l, j, 1) != "=") continue
        j++
        while (is_ws(substr(l, j, 1))) j++
        if (substr(l, j, 1) != "\"") continue
        while (qi <= nq && QP[qi] <= j) qi++
        if (qi > nq) break
        e = QP[qi]
        out = out substr(l, cur, j - cur + 1) placeholder; cur = e
    }
    return out substr(l, cur)
}

# xml_quote_list(l, QP): the positions of the double quotes of l in QP[1..n] -> n
function xml_quote_list(l, QP,   n, P, i, pos) {
    n = split(l, P, "\""); pos = 0
    for (i = 1; i < n; i++) { pos += length(P[i]) + 1; QP[i] = pos }
    return n - 1
}

function redact_xml_pairs(l,   out, rest, lo, k, k1, k2, w, c, j, n, e, val, lval, hit, i, ve) {
    out = ""; rest = l
    while (1) {
        lo = tolower(rest)
        k1 = index(lo, "key"); k2 = index(lo, "name")
        if (k1 == 0 && k2 == 0) break
        if (k1 > 0 && (k2 == 0 || k1 < k2)) { k = k1; w = 3 } else { k = k2; w = 4 }
        c = (k > 1) ? substr(rest, k - 1, 1) : ""
        n = length(rest); j = k + w
        if (!is_word(c)) {
            while (j <= n && is_ws(substr(rest, j, 1))) j++
            if (substr(rest, j, 1) == "=") {
                j++
                while (j <= n && is_ws(substr(rest, j, 1))) j++
                if (substr(rest, j, 1) == "\"" && (e = index(substr(rest, j + 1), "\"")) > 0) {
                    val = substr(rest, j + 1, e - 1); lval = tolower(val); hit = 0
                    for (i = 1; i <= NXW && !hit; i++) if (index(lval, XW[i]) > 0) hit = 1
                    if (!hit && w == 3 && lval ~ /^[abcdefghijklmnopqrstuvwxyz][abcdefghijklmnopqrstuvwxyz0-9+.-]*:\/\// && tolower(out substr(rest, 1, k - 1)) ~ /<add[ \t]+$/) hit = 1
                    if (hit) {
                        j = j + e + 1
                        if (is_ws(substr(rest, j, 1))) {
                            while (j <= n && is_ws(substr(rest, j, 1))) j++
                            if (tolower(substr(rest, j, 5)) == "value") {
                                j += 5
                                while (j <= n && is_ws(substr(rest, j, 1))) j++
                                if (substr(rest, j, 1) == "=") {
                                    j++
                                    while (j <= n && is_ws(substr(rest, j, 1))) j++
                                    if (substr(rest, j, 1) == "\"" && (ve = index(substr(rest, j + 1), "\"")) > 0) {
                                        out = out substr(rest, 1, j) placeholder; rest = substr(rest, j + ve); continue
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        out = out substr(rest, 1, k + w - 1); rest = substr(rest, k + w)
    }
    return out rest
}

# ------------------------------------------------------------------ TEXT RULES (blocks)

# block_open: [indent] [- ] [quote] key [quote] (= or :) [ "{" | "[" | a YAML block scalar
# (| |- > >- |2 ...) ] with a secret key -> 1, BLK_IND
function block_open(line,   p, n, kstart, len, q) {
    match(line, /^[ \t]*/); BLK_IND = RLENGTH; p = RLENGTH + 1
    if (match(substr(line, p), /^-[ \t]+/)) p += RLENGTH
    q = substr(line, p, 1); if (q == "\"" || q == "'") p++
    kstart = p; n = length(line)
    while (p <= n && substr(line, p, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.:\/@$-]/) p++
    for (len = p - kstart; len > 0; len--)
        if (substr(line, kstart + len) ~ /^["']?[ \t]*[:=][ \t]*([\[{]|[|>][-+0-9]*)?[ \t]*$/) return secret_name(substr(line, kstart, len))
    return 0
}

# triple_open: [indent] [quote] key [quote] (= or :) """ (or ''') not closed on that line, with a
# secret key (a TOML multi-line string) -> 1, TU = the delimiter
function triple_open(line,   p, n, kstart, len, q, after, d) {
    match(line, /^[ \t]*/); p = RLENGTH + 1
    q = substr(line, p, 1); if (q == "\"" || q == "'") p++
    kstart = p; n = length(line)
    while (p <= n && substr(line, p, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.:\/@$-]/) p++
    for (len = p - kstart; len > 0; len--) {
        after = substr(line, kstart + len)
        if (!match(after, /^["']?[ \t]*[:=][ \t]*("""|''')/)) continue
        d = substr(after, RLENGTH - 2, 3)
        if (index(substr(after, RLENGTH + 1), d) > 0) continue
        if (!secret_name(substr(line, kstart, len))) return 0
        TU = d; return 1
    }
    return 0
}

# until_line: a line inside a triple-quoted string (TU): replaced up to the closing delimiter,
# which ends the value and stays (with what follows it)
function until_line(line,   ni, at, b) {
    match(line, /^[ \t]*/); ni = RLENGTH
    at = index(tolower(line), TU)
    if (at == 0) {
        if (line ~ /^[ \t\r]*$/) return line
        return substr(line, 1, ni) placeholder
    }
    TU = ""; b = substr(line, 1, at - 1)
    if (b ~ /[^ \t\r]/) b = substr(line, 1, ni) placeholder
    return b substr(line, at)
}

# text_line: one line of a whole file or raw output; TB is the open block's indent (-1: none),
# TU the delimiter that closes an open triple-quoted value, TX the closing name of an open XML
# element, STC a secret start tag whose ">" is still to come ("": none; text_reset clears all)
function text_line(line,   ni, t, out) {
    if (TU != "") return until_line(line)
    if (TX != "") return xml_until_line(line)
    if (STC != "") { out = st_line(line); if (!ST_PASS) return out }
    match(line, /^[ \t]*/); ni = RLENGTH
    if (TB >= 0) {
        t = substr(line, ni + 1)
        if (t == "" || t ~ /^[}\]]+[,;]?[ \t]*$/) return line
        if (ni > TB || (ni == TB && substr(t, 1, 2) == "- ")) return substr(line, 1, ni) placeholder
        TB = -1
    }
    out = redact_line(line)
    if (line ~ /[:=]/ && block_open(line)) TB = BLK_IND
    else if (line ~ /[:=]/ && triple_open(line)) ;
    else if (index(line, "<") > 0) xml_states(line)
    return out
}
