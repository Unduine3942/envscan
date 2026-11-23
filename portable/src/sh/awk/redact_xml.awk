# redact_xml.awk: the secret XML elements of the xml LINE RULE and the XML parts of the TEXT
# RULES (spec/redaction.toml), part of the redaction program (es_awk_program: redact.awk,
# redact_xml.awk, redact_text.awk, json.awk share one namespace).
#
# Linear time: a line is split once on "<" (pieces XP_P[2..XP_N] each start right after a "<");
# one forward pass lists the live closing tags (outside comments) and the secret start tags, one
# backward pass links each start tag to its first matching closing tag and each closing tag to the
# next one with the same name; the scan then moves forward only. The ">" of a start tag is
# searched character by character with a memo of searches that failed (XP_F), so no piece is
# scanned more than four times whatever the input. A line prepared twice in a row (the line rules,
# then the TEXT states) is prepared once. tolower is ASCII-only under LC_ALL=C (es_awk).

# xml_prep(l): pieces XP_P (as written), XP_L (lower case), XP_N; closing tags XC_I (piece),
# XC_S (position of the piece), XC_A/XC_B (keys, xml_close_keys), XC_N; secret start tags XT_I,
# XT_S, XT_E (offset after the name), XT_C (closing name), XT_O (first matching closing tag), XT_N
function xml_prep(l,   i, n, pos, incm, c) {
    if (XP_DONE && l == XP_LINE) return
    XP_LINE = l; XP_DONE = 1
    n = split(l, XP_P, "<"); split(tolower(l), XP_L, "<"); XP_N = n
    split("", XP_F); split("", XP_FE); XC_N = 0; XT_N = 0; pos = 1; incm = 0
    for (i = 2; i <= n; i++) {
        pos += length(XP_P[i - 1]) + 1
        if (incm) { if (index(XP_L[i], "-->") > 0) incm = 0; continue }
        c = substr(XP_L[i], 1, 1)
        if (c == "/") xml_close_keys(i, pos)
        else if (c == "!") { if (substr(XP_L[i], 2, 2) == "--") incm = index(substr(XP_L[i], 4), "-->") == 0 }
        else if (c != "" && NXE > 0 && index("abcdefghijklmnopqrstuvwxyz_", c) > 0) xml_start_name(i, pos)
    }
    xml_prep_back()
}

# xml_close_keys(i, pos): piece i is a live closing tag "</N": N matches a closing name C (C has
# at most one ":") when N is C or starts with C ":", so it answers XC_A = N up to its first ":"
# (when it has one) and XC_B = N up to its second ":" (or all of N); XC_B "-": "</" without a name
function xml_close_keys(i, pos,   nm, c, k) {
    k = ++XC_N; XC_I[k] = i; XC_S[k] = pos; XC_A[k] = ""
    match(XP_L[i], /^\/[abcdefghijklmnopqrstuvwxyz0-9_.:-]*/)
    nm = substr(XP_L[i], 2, RLENGTH - 1)
    if (nm == "") { XC_B[k] = "-"; return }
    c = index(nm, ":")
    if (c == 0) { XC_B[k] = nm; return }
    XC_A[k] = substr(nm, 1, c - 1)
    c = index(substr(nm, c + 1), ":") > 0 ? c + index(substr(nm, c + 1), ":") : 0
    XC_B[k] = (c > 0) ? substr(nm, 1, c - 1) : nm
}

# xml_elem_at(s, j): the end (position after it) of a secret element name (xml_elements) at j
# of the lower-case text s, not followed by a word character; 0 when there is none
function xml_elem_at(s, j,   i, m) {
    for (i = 1; i <= NXE; i++) {
        m = length(XE[i])
        if (substr(s, j, m) == XE[i] && !is_word(substr(s, j + m, 1))) return j + m
    }
    return 0
}

# xml_start_name(i, pos): piece i starts a secret start tag when an element name follows "<",
# after an optional prefix ([A-Za-z_][A-Za-z0-9_.-]* ":") that is taken as a prefix only when an
# element name follows it (<password:x> is "password", <token:password> "token:password")
function xml_start_name(i, pos,   s, e, c) {
    s = XP_L[i]; e = 0
    if (match(s, /^[abcdefghijklmnopqrstuvwxyz_][abcdefghijklmnopqrstuvwxyz0-9_.-]*:/)) e = xml_elem_at(s, RLENGTH + 1)
    if (e == 0) e = xml_elem_at(s, 1)
    if (e == 0) return
    c = ++XT_N; XT_I[c] = i; XT_S[c] = pos; XT_E[c] = e; XT_C[c] = substr(s, 1, e - 1)
}

# xml_prep_back: XT_O and the same-key chains XC_N1/XC_N2 (closing-tag indexes, 0: none), from
# the end of the line backwards; XP_LAST is emptied again entry by entry
function xml_prep_back(   k, t, a, b, r) {
    k = XC_N; r = XC_N + 1
    for (t = XT_N; t >= 1; t--) {
        for (; k >= 1 && XC_I[k] > XT_I[t]; k--) {
            r = k; a = XC_A[k]; b = XC_B[k]
            XC_N2[k] = (b in XP_LAST) ? XP_LAST[b] : 0; XP_LAST[b] = k
            if (a != "") { XC_N1[k] = (a in XP_LAST) ? XP_LAST[a] : 0; XP_LAST[a] = k }
        }
        XT_O[t] = ((XT_C[t]) in XP_LAST) ? XP_LAST[XT_C[t]] : 0
    }
    for (k = r; k <= XC_N; k++) {
        if (XC_B[k] in XP_LAST) delete XP_LAST[XC_B[k]]
        if (XC_A[k] != "" && (XC_A[k] in XP_LAST)) delete XP_LAST[XC_A[k]]
    }
}

# xml_next_close(j): the first live closing tag after piece j (an index of XC_*, 0: none); the
# cursor XC_CUR only moves forward during one scan
function xml_next_close(j) {
    while (XC_CUR <= XC_N && XC_I[XC_CUR] <= j) XC_CUR++
    return (XC_CUR <= XC_N) ? XC_CUR : 0
}

# xml_own_after(k, j, c): from the chain start k (a closing tag matching c, or 0), the first one
# after piece j
function xml_own_after(k, j, c) {
    while (k > 0 && XC_I[k] <= j) k = (XC_A[k] == c) ? XC_N1[k] : XC_N2[k]
    return k
}

# xml_own_scan(j, c): the first live closing tag after piece j that matches c (linear; used once
# per line, for an element or start tag that began on an earlier line)
function xml_own_scan(j, c,   k) {
    for (k = xml_next_close(j); k > 0 && k <= XC_N; k++)
        if (XC_A[k] == c || XC_B[k] == c) return k
    return 0
}

# xml_gt(i, off, q, pos): the position in the line of the ">" that ends a start tag, searched from
# offset off of piece i (at line position pos) in quote state q; ">" inside "..." and '...' does not
# count -> the position (XG_J = its piece), else 0 (XG_Q = the quote state at the line end). A
# search that fails marks the pieces it entered with its state (XP_F) and the quote state it ended
# in (XP_FE); a later search entering a piece in a state marked there fails at once, with that end
# state.
function xml_gt(i, off, q, pos,   m, s, n, c, x, ne, EM, EQ) {
    ne = 0
    for (m = i; m <= XP_N; m++) {
        if (m > i) pos += length(XP_P[m - 1]) + 1
        if (index(XP_F[m], "[" q "]") > 0) { q = XP_FE[m, q]; break }
        EM[++ne] = m; EQ[ne] = q
        s = XP_P[m]; n = length(s)
        for (x = (m == i) ? off : 1; x <= n; x++) {
            c = substr(s, x, 1)
            if (q == "") { if (c == ">") { XG_J = m; return pos + x - 1 }; if (c == "\"" || c == "'") q = c }
            else if (c == q) q = ""
        }
    }
    for (m = 1; m <= ne; m++) { XP_F[EM[m]] = XP_F[EM[m]] "[" EQ[m] "]"; XP_FE[EM[m], EQ[m]] = q }
    XG_Q = q
    return 0
}

# xml_piece_of(g): the piece that holds position g of the prepared line (linear, once per line)
function xml_piece_of(g,   i, pos) {
    pos = 1
    for (i = 2; i <= XP_N; i++) { pos += length(XP_P[i - 1]) + 1; if (pos > g) return i - 1 }
    return XP_N
}

# xml_content(l, g, j, own, first, c): the content of a start tag whose ">" is at g (in piece j),
# own = its first matching closing tag after j (0: none): it runs to that closing tag, else to the
# next live "</", else a non-blank rest of the line is replaced. Appends to XO_OUT from XO_CUR;
# returns the piece to go on with, 0 when the line is done. first: the start tag begins its line
# (TEXT mode: with no "</" after it, it opens the multi-line state, as a blank rest does).
function xml_content(l, g, j, own, first, c,   k, blank) {
    k = own
    if (k == 0) k = xml_next_close(j)
    if (k > 0) {
        XO_OUT = XO_OUT substr(l, XO_CUR, g - XO_CUR + 1) placeholder; XO_CUR = XC_S[k] - 1
        return XC_I[k] + 1
    }
    blank = substr(l, g + 1) !~ /[^ \t\r\n\f\v]/
    if (XS_SET && XS_TX == "" && XS_ST == "" && (first || blank)) XS_TX = c
    if (!blank) { XO_OUT = XO_OUT substr(l, XO_CUR, g - XO_CUR + 1) placeholder; XO_CUR = length(l) + 1 }
    return 0
}

# xml_scan(l, set, g0, c0): l with the content of every secret element replaced (the xml LINE
# RULE). set (TEXT mode): also XS_TX (the closing name of an element left open: multi-line state)
# and XS_ST/XS_STQ (a start tag without its ">" on the line: start-tag state, open quote).
# g0 > 0: the ">" at g0 ends a start tag (closing name c0) that began on an earlier line.
function xml_scan(l, set, g0, c0,   i, t, g, j, first) {
    XO_OUT = ""; XO_CUR = 1; XS_SET = set; XS_TX = ""; XS_ST = ""; XS_STQ = ""
    if (index(l, "<") == 0 && g0 == 0) return l
    xml_prep(l); XC_CUR = 1
    match(l, /^[ \t]*/); first = RLENGTH + 1
    i = 2
    if (g0 > 0) { j = xml_piece_of(g0); i = xml_content(l, g0, j, xml_own_scan(j, c0), 1, c0) }
    for (t = 1; i >= 2 && t <= XT_N; t++) {
        if (XT_I[t] < i) continue
        if ((g = xml_gt(XT_I[t], XT_E[t], "", XT_S[t])) == 0) {
            if (set && XS_ST == "" && XS_TX == "") { XS_ST = XT_C[t]; XS_STQ = XG_Q }
            continue
        }
        j = XG_J
        if (substr(l, g - 1, 1) == "/") { i = j + 1; continue }
        i = xml_content(l, g, j, xml_own_after(XT_O[t], j, XT_C[t]), XT_S[t] - 1 == first, XT_C[t])
    }
    return XO_OUT substr(l, XO_CUR)
}

# redact_xml_elems(l): the xml LINE RULE for secret elements (no state)
function redact_xml_elems(l) { return xml_scan(l, 0, 0, "") }

# ------------------------------------------------------------------ TEXT RULES (xml states)

# text_reset: no open block, multi-line value or start tag (the start of a whole text)
function text_reset() { TB = -1; TU = ""; TX = ""; STC = ""; STQ = "" }

# xml_states(line): after the line rules: the states a line of a whole text opens (TX: the
# closing name of an element left open; STC/STQ: a start tag whose ">" is on a later line)
function xml_states(line) {
    xml_scan(line, 1, 0, "")
    TX = XS_TX; STC = XS_ST; STQ = XS_STQ
}

# xml_until_line(line): a line inside an element left open (TX): replaced up to its live closing
# tag "</[prefix:]element"; what follows that tag goes through the line and text rules again
function xml_until_line(line,   ni, m, at, b) {
    match(line, /^[ \t]*/); ni = RLENGTH
    xml_prep(line); XC_CUR = 1
    m = xml_own_scan(1, TX)
    if (m == 0) {
        if (line ~ /^[ \t\r]*$/) return line
        return substr(line, 1, ni) placeholder
    }
    TX = ""; at = XC_S[m] - 1; b = substr(line, 1, at - 1)
    if (b ~ /[^ \t\r]/) b = substr(line, 1, ni) placeholder
    return b text_line(substr(line, at))
}

# st_gt(line): the first ">" of line outside quotes, the quote state carried in from STQ (0: none;
# STQ = the state at the line end)
function st_gt(line,   n, x, c, q) {
    q = STQ; n = length(line)
    for (x = 1; x <= n; x++) {
        c = substr(line, x, 1)
        if (q == "") { if (c == ">") return x; if (c == "\"" || c == "'") q = c }
        else if (c == q) q = ""
    }
    STQ = q
    return 0
}

# st_line(line): a line while a secret start tag is open (STC): a line starting with "<" ends the
# state without effect (ST_PASS = 1: the caller processes the line as usual); without the tag's
# ">" the line goes through the line rules; at the ">" what follows is content right after a start
# tag that begins its line (a self-closing "/>" ends the state without effect)
function st_line(line,   g, c, r) {
    ST_PASS = 0
    if (STQ == "" && line ~ /^[ \t]*</) { STC = ""; ST_PASS = 1; return line }
    if ((g = st_gt(line)) == 0) return redact_line(line)
    c = STC; STC = ""; STQ = ""
    if (g > 1 && substr(line, g - 1, 1) == "/") { ST_PASS = 1; return line }
    r = xml_scan(line, 0, g, c)
    xml_scan(line, 1, g, c)
    TX = XS_TX; STC = XS_ST; STQ = XS_STQ
    return redact_line(r)
}
