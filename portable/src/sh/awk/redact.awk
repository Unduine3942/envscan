# envscan.sh redaction rules: spec/redaction.toml (its header is the rule description).
# POSIX awk only (gawk, mawk, nawk/BWK, busybox); run with LC_ALL=C. POSIX awk has no
# look-around and no back-references, so every rule is a small scanner.
#
# The scanner runs this file and json.awk as one program; redact_setup() (called from the
# BEGIN block of json.awk) builds the tables from these -v variables:
#   redact=1|0, placeholder, segs, contains, namesfx, excepts, sfxexc, prefixes, minlen,
#   pairkeys, optwords, hdrwords, toolopts, xmlel, xmlat, pkmarker

function redact_setup(   i, n, tmp, to_n, to_l, to_p, to_t) {
    if (placeholder == "") placeholder = "<redacted>"
    PHL = length(placeholder)
    if (pkmarker == "") pkmarker = "PRIVATE KEY"
    if (minlen == "") minlen = 20
    minlen = minlen + 0
    if (redact == "") redact = 1
    redact = redact + 0
    PKTEXT = "<redacted: private key>"
    n = split(segs, tmp, " "); for (i = 1; i <= n; i++) SEG[tmp[i]] = 1
    NCONT = split(contains, CONT, " ")
    NNS = split(namesfx, NS, " ")
    n = split(excepts, tmp, " "); for (i = 1; i <= n; i++) EXC[tmp[i]] = 1
    NSX = split(sfxexc, SX, " ")
    NPRE = split(prefixes, PRE, " ")
    NPK = split(tolower(pairkeys), PK, " ")
    NOW = split(tolower(optwords), OW, " ")
    NHW = split(tolower(hdrwords), HW, " ")
    NXE = split(tolower(xmlel), XE, " ")
    NXA = split(tolower(xmlat), XA, " ")
    RUNSEP = ",;&#}])\"'<>|"
    # a value, line or command line longer than this is not scanned (spec "LENGTH CAP")
    MAXLEN = 131072; TOOLONG = "<redacted: too long>"
    # host[:port] of a scheme-less userinfo ends at the end of the token or at one of these
    UIEND = "/,;)]}><|&#?\\"
    # tool options: TNAME[1..NTN] lower-case tool names, TOPTS[tool] = " opt opt ..."
    NTN = 0
    to_n = split(toolopts, to_l, " ")
    for (i = 1; i <= to_n; i++) {
        to_p = index(to_l[i], ":")
        if (to_p < 2 || to_p == length(to_l[i])) continue
        to_t = tolower(substr(to_l[i], 1, to_p - 1))
        if (!(to_t in TOPTS)) TNAME[++NTN] = to_t
        TOPTS[to_t] = TOPTS[to_t] " " substr(to_l[i], to_p + 1)
    }
    NXW = 0
    for (i = 1; i <= NCONT; i++) XW[++NXW] = tolower(CONT[i])
    XW[++NXW] = "pwd"; XW[++NXW] = "pass"
    text_reset()
}

# ------------------------------------------------------------------ helpers

function is_ws(c) { return c == " " || c == "\t" || c == "\n" || c == "\r" || c == "\f" || c == "\v" }

function ends_with(s, t) { return length(s) >= length(t) && substr(s, length(s) - length(t) + 1) == t }

function is_word(c) { return c != "" && c ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_]/ }

# quote_end: position of the quote that closes the one at s[j], 0 when there is none. A quote
# preceded by an odd number of backslashes is escaped ("a\"b" is one value).
function quote_end(s, j,   q, k, off, b) {
    q = substr(s, j, 1); off = j
    while ((k = index(substr(s, off + 1), q)) > 0) {
        k += off; b = 0
        while (k - b - 1 > j && substr(s, k - b - 1, 1) == "\\") b++
        if (b % 2 == 0) {
            # shell idiom: 'a' then an escaped quote, then 'b c' reopened (one value)
            if (q == "'" && substr(s, k + 1, 3) == "\\''") { off = k + 3; continue }
            # PowerShell/SQL/YAML: two single quotes inside '...' are one literal quote
            if (q == "'" && k > j + 1 && substr(s, k + 1, 1) == "'") { off = k + 1; continue }
            return k
        }
        off = k
    }
    return 0
}

# esc_quote(s, j): s[j] is a backslash before a quote: \" or \' opens an escaped-quoted string
# inside a string (JSON in an environment value, a shell argument: {\"password\":\"x\"})
function esc_quote(s, j,   c) {
    if (substr(s, j, 1) != "\\") return 0
    c = substr(s, j + 1, 1)
    return c == "\"" || c == "'"
}

# esc_end(s, j): s[j] opens \" (or \'); the position of the backslash of the next \" (\') that
# closes it, 0 when the string is unterminated (it runs to the end of the text)
function esc_end(s, j,   k, off, t) {
    t = substr(s, j, 2); off = j + 1
    while ((k = index(substr(s, off + 1), t)) > 0) {
        k += off
        # \\\" (a run of backslashes before the quote) is a quote of the inner string, not the closer
        if (k > j + 2 && substr(s, k - 1, 1) == "\\") { off = k + 1; continue }
        return k
    }
    return 0
}

# ------------------------------------------------------------------ NAME RULES

# camelCase boundaries get "_": [a-z0-9][A-Z] and [A-Z]+[A-Z][a-z]
function camel_split(s,   r, i, n, c, p, q) {
    if (s !~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZ]/) return s
    r = substr(s, 1, 1); n = length(s)
    for (i = 2; i <= n; i++) {
        c = substr(s, i, 1)
        if (c ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZ]/) {
            p = substr(s, i - 1, 1); q = substr(s, i + 1, 1)
            if (p ~ /[abcdefghijklmnopqrstuvwxyz0-9]/ || (p ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZ]/ && q ~ /[abcdefghijklmnopqrstuvwxyz]/)) r = r "_"
        }
        r = r c
    }
    return r
}

function secret_name(name,   u, n, i, P, norm, joined, k, r) {
    if (name == "") return 0
    if (name in NAMEC) return NAMEC[name]
    r = 0
    u = toupper(name)
    if (!(u in EXC)) {
        n = split(toupper(camel_split(name)), P, "[^ABCDEFGHIJKLMNOPQRSTUVWXYZ0-9]+")
        norm = ""; joined = ""; k = 0
        for (i = 1; i <= n; i++) if (P[i] != "") { k++; norm = norm (k > 1 ? "_" : "") P[i]; joined = joined P[i] }
        if (k > 0) {
            r = -1
            for (i = 1; i <= NSX; i++) if (ends_with(norm, SX[i])) { r = 0; break }
            if (r < 0) for (i = 1; i <= n; i++) if (P[i] != "" && (P[i] in SEG)) { r = 1; break }
            if (r < 0) for (i = 1; i <= NCONT; i++) if (index(joined, CONT[i]) > 0) { r = 1; break }
            if (r < 0) for (i = 1; i <= NNS; i++) if (ends_with(joined, NS[i])) { r = 1; break }
            if (r < 0) r = 0
        }
    }
    NAMEC[name] = r
    return r
}

# ------------------------------------------------------------------ VALUE RULES

# url userinfo (password to the last "@" of the authority; long user-only tokens) and conda
# "/t/<token>/" path segments
function redact_url(v,   r, rest, k, j, n, c, auth, colon, at, fat, p, run, q, s2, seg, e) {
    r = ""; rest = v
    while ((k = index(rest, "://")) > 0) {
        c = (k > 1) ? substr(rest, k - 1, 1) : ""
        r = r substr(rest, 1, k + 2); rest = substr(rest, k + 3)
        if (c !~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9+.-]/) continue
        n = length(rest); j = 1
        while (j <= n) { c = substr(rest, j, 1); if (c == "/" || c == "?" || c == "#" || is_ws(c)) break; j++ }
        auth = substr(rest, 1, j - 1)
        at = 0; for (p = length(auth); p > 0; p--) if (substr(auth, p, 1) == "@") { at = p; break }
        if (at > 0) {
            colon = index(auth, ":")
            if (colon > 0 && colon < at) { r = r substr(auth, 1, colon) placeholder "@"; rest = substr(rest, at + 1) }
            else {
                fat = index(auth, "@")
                if (fat - 1 >= minlen && index(substr(auth, 1, fat - 1), ":") == 0) { r = r placeholder "@"; rest = substr(rest, fat + 1) }
            }
        }
        n = length(rest); j = 1
        while (j <= n && !is_ws(substr(rest, j, 1))) j++
        run = substr(rest, 1, j - 1)
        if (index(run, "/t/") > 0) {
            s2 = ""; q = run
            while ((p = index(q, "/t/")) > 0) {
                seg = substr(q, p + 3); e = index(seg, "/")
                if (e > 8) { s2 = s2 substr(q, 1, p + 2) placeholder; q = substr(seg, e); break }
                s2 = s2 substr(q, 1, p); q = substr(q, p + 1)
            }
            rest = s2 q substr(rest, j)
        }
    }
    return r rest
}

# scheme-less userinfo in every token (a run without whitespace or quotes): user:password@host
# [:port] -> user:<redacted>@host[:port] (spec/redaction.toml "bare userinfo"). A match starts at the
# token start or after one of = ; , ( |. The user runs to the first ":" (1-128 characters, no "/";
# "@" is allowed: john.doe@corp.com, and "\": DOMAIN\user), the password (1-256 characters, no "/"
# or "\") to an "@" followed by a host: [A-Za-z0-9._-]+ or [IPv6] with an optional port of 1-5
# digits, then the end of the token or one of UIEND (/ , ; ) ] } > < | & # ? \; after a port also
# . !). When the host does not end there, the password runs on to the next "@" (an unencoded "@"
# inside it). user@host:path (scp, git) and image:tag@sha256:<digest> never match.
# Linear: every start looks at windows of at most 270 characters; the tokens are cut with two
# split() calls (no copy of the rest of the text per token).
function redact_userinfo(v,   w, ns, T, S, i, r, t) {
    w = " " v
    split(w, T, /[ \t\r\n"']+/)
    ns = split(w, S, /[^ \t\r\n"']+/)
    r = S[1]
    for (i = 2; i <= ns; i++) {
        t = T[i]
        if (index(t, "@") > 0 && index(t, ":") > 0) t = ui_token(t)
        r = r t S[i]
    }
    return substr(r, 2)
}

# ui_token: the userinfo rule inside one token; after a match the token goes on after the host's
# end character (a list of proxies). Fallback, fail closed, when nothing matched: a token whose
# first ":" is followed by 257+ characters (no "/" or "\") and an "@" after them, or whose part
# before the first ":" is 129+ characters and is followed by a password and an "@", is one
# secret: the whole token becomes the placeholder (it holds no ":", so a second pass keeps it).
function ui_token(t,   n, P, SS, i, s, e, st, seg, c, ca, w, rp, off, k, a, h, r, last, fc, tail, rl) {
    n = split(t, P, /[=;,(|]/)
    s = 1
    for (i = 1; i <= n; i++) { SS[i] = s; s += length(P[i]) + 1 }
    r = ""; last = 1; st = 1; i = 1
    while (i <= n) {
        e = SS[i] + length(P[i])
        if (e < st) { i++; continue }
        seg = (st > SS[i]) ? substr(P[i], st - SS[i] + 1) : P[i]
        c = index(seg, ":"); h = 0
        if (c > 1 && c <= 129 && index(substr(seg, 1, c - 1), "/") == 0) {
            ca = st + c - 1
            w = substr(t, ca + 1, 257)
            rp = match(w, /[\/\\]/) ? RSTART : 0
            off = 0
            while ((k = index(substr(w, off + 1), "@")) > 0) {
                a = off + k
                if (a == 1 || (rp > 0 && a > rp)) break
                h = ui_host(substr(t, ca + a + 1, 270))
                if (h > 0) break
                off = a
            }
            if (h > 0) {
                r = r substr(t, last, ca - last + 1) placeholder "@" substr(t, ca + a + 1, h)
                last = ca + a + 1 + h
                st = last + 1
                continue
            }
        }
        st = e + 1; i++
    }
    if (last > 1) return r substr(t, last)
    fc = index(t, ":")
    if (fc > 0) {
        tail = substr(t, fc + 1)
        rl = match(tail, /[\/\\]/) ? RSTART - 1 : length(tail)
        if (fc > 129 && rl >= 2 && index(substr(tail, 2, rl - 1), "@") > 0) return placeholder
        if (rl >= 257 && index(substr(tail, 258, rl - 257), "@") > 0) return placeholder
    }
    return t
}

# ui_host: length of host[:port] at the start of s when the end of s or a UIEND character
# follows it, else 0
function ui_host(s,   n, c, pt) {
    if (match(s, /^\[[0-9A-Fa-f:.]+]/) || match(s, /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9._-]+/)) n = RLENGTH; else return 0
    pt = 0
    if (substr(s, n + 1, 1) == ":" && match(substr(s, n + 2), /^[0-9]+/) && RLENGTH <= 5) { n += 1 + RLENGTH; pt = 1 }
    c = substr(s, n + 1, 1)
    if (c == "" || index(UIEND, c) > 0) return n
    # after a port, the end of a sentence: "via user:pw@host:80."
    if (pt && (c == "." || c == "!")) return n
    return 0
}

# tokens: [A-Za-z0-9_.+/=-] runs that start with a known prefix, not preceded by a word character
function redact_tokens(v,   i, p, k, j, prev, r, rest, n, need) {
    if (length(v) < minlen) return v
    for (i = 1; i <= NPRE; i++) {
        p = PRE[i]
        if (index(v, p) == 0) continue
        need = length(p) + 4; if (need < minlen) need = minlen
        r = ""; rest = v
        while ((k = index(rest, p)) > 0) {
            prev = (k > 1) ? substr(rest, k - 1, 1) : ""
            j = k + length(p); n = length(rest)
            while (j <= n && substr(rest, j, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.+\/=-]/) j++
            if (prev !~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_-]/ && j - k >= need) { r = r substr(rest, 1, k - 1) placeholder; rest = substr(rest, j) }
            else { r = r substr(rest, 1, k + length(p) - 1); rest = substr(rest, k + length(p)) }
        }
        v = r rest
    }
    return v
}

# "Bearer <8+ chars>" and "Basic <8+ chars>" -> "Bearer <redacted>"
function redact_scheme_word(v,   r, rest, lrest, k, kb, kc, w, j, n, s, c) {
    r = ""; rest = v
    while (1) {
        lrest = tolower(rest)
        kb = index(lrest, "bearer"); kc = index(lrest, "basic")
        if (kb == 0 && kc == 0) break
        if (kb > 0 && (kc == 0 || kb < kc)) { k = kb; w = 6 } else { k = kc; w = 5 }
        c = (k > 1) ? substr(rest, k - 1, 1) : ""
        n = length(rest); j = k + w; s = j
        while (j <= n && is_ws(substr(rest, j, 1))) j++
        if (!is_word(c) && j > s) {
            s = j
            while (j <= n && substr(rest, j, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9._~+\/-]/) j++
            if (j - s >= 8) {
                while (j <= n && substr(rest, j, 1) == "=") j++
                r = r substr(rest, 1, k + w - 1) " " placeholder; rest = substr(rest, j)
                continue
            }
        }
        r = r substr(rest, 1, k + w - 1); rest = substr(rest, k + w)
    }
    return r rest
}

# skip_quote(s, j): j after a quote or an escaped quote (\" \') at s[j], else j
function skip_quote(s, j,   c) {
    c = substr(s, j, 1)
    if (c == "\"" || c == "'") return j + 1
    return esc_quote(s, j) ? j + 2 : j
}

# authz_end(s, j): the end of credentials starting at j: whitespace, a quote, "," ";" or a
# backslash before a quote
function authz_end(s, j,   n, c) {
    n = length(s)
    while (j <= n) {
        c = substr(s, j, 1)
        if (is_ws(c) || c == "\"" || c == "'" || c == "," || c == ";" || esc_quote(s, j)) break
        j++
    }
    return j
}

# <key ending in authorization> [quote] [:=] [quote] [scheme] <credentials>, a quote also
# escaped (\" \'): Authorization, Proxy-Authorization, HTTP_AUTHORIZATION, proxyAuthorization
# (key/value leaves these keys here)
function redact_authz(v,   r, rest, k, c, j, j0, n, s) {
    r = ""; rest = v
    while ((k = index(tolower(rest), "authorization")) > 0) {
        n = length(rest); j = skip_quote(rest, k + 13)
        while (j <= n && is_ws(substr(rest, j, 1))) j++
        c = substr(rest, j, 1)
        if (c != ":" && c != "=") { r = r substr(rest, 1, k + 12); rest = substr(rest, k + 13); continue }
        j++
        while (j <= n && is_ws(substr(rest, j, 1))) j++
        j = skip_quote(rest, j)
        j0 = j; s = j
        while (s <= n && substr(rest, s, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]/) s++
        if (s > j && s <= n && is_ws(substr(rest, s, 1))) { while (s <= n && is_ws(substr(rest, s, 1))) s++; j = s }
        s = authz_end(rest, j)
        if (s == j && j != j0) { j = j0; s = authz_end(rest, j) }
        if (s > j) { r = r substr(rest, 1, j - 1) placeholder; rest = substr(rest, s) }
        else { r = r substr(rest, 1, j - 1); rest = substr(rest, j) }
    }
    return r rest
}

# placeholder_end(s, j): s[j] starts the placeholder (redaction runs more than once over a
# text). Returns the end of what belongs to the value after it: j + PHL when the value is just
# the placeholder (kept as it is), else the end of the continuation ("<redacted>Rest0fSecret").
function placeholder_end(s, j) { return run_end(s, j + PHL) }

# pair keys: <key>=<value> anywhere (connection strings, query strings), key not preceded by a
# key character; a quoted value is replaced with its quotes, an escaped-quoted value (\"...\")
# keeps its delimiters. The occurrences of the keys (plain letters) are found once (split), in
# position order, the longest key first at one position; the text is never sliced per match.
function redact_pairkeys(v,   r, cur, n, OC, k, bk, c, j, q, e, pre) {
    n = length(v); pairkey_occurrences(tolower(v), OC)
    r = ""; cur = 1
    for (k = 1; k <= n; k++) {
        if (!(k in OC) || k < cur) continue
        bk = OC[k]; c = (k > 1) ? substr(v, k - 1, 1) : ""
        if (c ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.-]/) continue
        j = k + length(PK[bk]); e = 0
        while (j <= n && is_ws(substr(v, j, 1))) j++
        if (j > n || substr(v, j, 1) != "=") continue
        j++
        while (j <= n && is_ws(substr(v, j, 1))) j++
        q = substr(v, j, 1); pre = j - 1
        if (substr(v, j, PHL) == placeholder) { e = placeholder_end(v, j); if (e == j + PHL) e = 0 }
        else if (esc_quote(v, j)) { pre = j + 1; e = esc_end(v, j); if (e == 0) e = n + 1 }
        else if (q == "\"" || q == "'") { e = quote_end(v, j); e = (e > 0) ? e + 1 : n + 1 }
        else { e = run_end(v, j); if (e == j) e = 0 }
        if (e > 0) { r = r substr(v, cur, pre - cur + 1) placeholder; cur = e }
    }
    return r substr(v, cur)
}

# pairkey_occurrences(lv, OC): OC[position] = the pair key (index of PK) found at that position of
# the lower-case text lv, the longest one where several start at one position
function pairkey_occurrences(lv, OC,   i, m, A, t, p, L) {
    split("", OC)
    for (i = 1; i <= NPK; i++) {
        L = length(PK[i])
        if (PK[i] !~ /^[abcdefghijklmnopqrstuvwxyz]+$/) {
            # not a plain word (never in the spec today): searched without a regular expression
            for (p = 0; (t = index(substr(lv, p + 1), PK[i])) > 0; ) { p += t; if (!(p in OC) || L > length(PK[OC[p]])) OC[p] = i }
            continue
        }
        m = split(lv, A, PK[i]); p = 1 - L
        for (t = 1; t < m; t++) {
            p += length(A[t]) + L
            if (!(p in OC) || L > length(PK[OC[p]])) OC[p] = i
        }
    }
}

# unquoted run (spec "unquoted run"): value characters (anything except whitespace and the
# separators , ; & # } ] ) " ' < > |) from j, up to whitespace. A sequence of separators belongs
# to the value only when a value character follows it and that character does not start another
# key (key chars, optional quote, optional whitespace, = or :): "Pwd=a;b" and "Pwd=ab)cd" lose
# the whole value, "Pwd=abc;" keeps the ";", "Pwd=a;Database=x" keeps ";Database=x",
# "(token=abc)" keeps the ")". Returns the position after the run.
function run_end(s, j,   n, c, k) {
    n = length(s)
    while (j <= n) {
        c = substr(s, j, 1)
        if (is_ws(c)) break
        if (index(RUNSEP, c) > 0) {
            k = j
            while (k <= n && index(RUNSEP, substr(s, k, 1)) > 0) k++
            c = substr(s, k, 1)
            if (c == "" || is_ws(c)) break
            if (substr(s, k) ~ /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.-]+["']?[ \t\r\n\f\v]*[=:]/) break
            j = k
            continue
        }
        j++
    }
    return j
}

# pair_at(s, from): the first match of key-chars+ (\?["'])? [ \t\r\n]* [:=] [ \t\r\n]* in s at or
# after from -> 1 with RSTART and RLENGTH as match() sets them, else 0. Found from each separator
# backwards (never before from), so a long run of key characters that no separator follows costs
# linear, not quadratic, time (a regex match() retries every start position of the run).
function pair_at(s, from,   n, p, k, e, c) {
    n = length(s)
    if (from < 1) from = 1
    for (p = from; p <= n; p++) {
        c = substr(s, p, 1)
        if (c != ":" && c != "=") continue
        k = p - 1
        while (k >= from && index(" \t\r\n", substr(s, k, 1)) > 0) k--
        c = (k >= from) ? substr(s, k, 1) : ""
        if (c == "\"" || c == "'") { k--; if (k >= from && substr(s, k, 1) == "\\") k-- }
        e = k
        while (k >= from && substr(s, k, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.-]/) k--
        if (k == e) continue
        e = p + 1
        while (e <= n && index(" \t\r\n", substr(s, e, 1)) > 0) e++
        RSTART = k + 1; RLENGTH = e - RSTART
        return 1
    }
    return 0
}

# xml_qname(r, rest, k, key): the key at k of rest (r: the text before rest) is the first part of
# an XML qualified name, not a key: right after "<" or "</", followed directly by ":" and a secret
# element name (xml_elements, any case, not followed by a word character): <token:password>,
# </ns:clientSecret>. <password:x> and "<password: x" stay keys (over-redaction).
function xml_qname(r, rest, k, key,   b) {
    if (substr(rest, k + length(key), 1) != ":" || NXE == 0) return 0
    if (xml_elem_at(tolower(substr(rest, k + length(key) + 1, 64)), 1) == 0) return 0
    b = substr(r, length(r) - 1) substr(rest, (k > 2) ? k - 2 : 1, (k > 2) ? 2 : k - 1)
    b = substr(b, length(b) - 1)
    return substr(b, length(b), 1) == "<" || b == "</"
}

# key/value: every key[quote][space](= or :)[space]value whose key is a secret name (the quote
# may be escaped: {\"password\":\"x\"}); a quoted or escaped-quoted value keeps its quotes,
# "{" or "[" replaces the rest of the text, else an unquoted run
function redact_pairs(v,   r, cur, pos, k, m, key, j, n, q, e) {
    r = ""; cur = 1; pos = 1; n = length(v)
    while (pair_at(v, pos)) {
        k = RSTART; m = RLENGTH; j = k + m; pos = j
        key = substr(v, k, m); sub(/(\\?["'])?[ \t\r\n]*[:=][ \t\r\n]*$/, "", key)
        if (j > n || ends_with(toupper(key), "AUTHORIZATION") || xml_qname("", v, k, key) || !secret_name(key)) continue
        if (substr(v, j, PHL) == placeholder) {
            e = placeholder_end(v, j); pos = e
            if (e != j + PHL) { r = r substr(v, cur, j - cur) placeholder; cur = e }
            continue
        }
        if (esc_quote(v, j)) {
            e = esc_end(v, j)
            r = r substr(v, cur, j + 2 - cur) placeholder
            if (e == 0) { cur = n + 1; break }
            cur = e; pos = e; continue
        }
        q = substr(v, j, 1)
        if (q == "\"" || q == "'") {
            e = quote_end(v, j)
            r = r substr(v, cur, j + 1 - cur) placeholder
            if (e == 0) { cur = n + 1; break }
            cur = e; pos = e; continue
        }
        if (q == "{" || q == "[") {
            if (substr(v, j + 1) ~ /^[ \t\r\n]*$/) continue
            r = r substr(v, cur, j - cur) placeholder; cur = n + 1; break
        }
        e = run_end(v, j)
        if (e == j) continue
        r = r substr(v, cur, j - cur) placeholder; cur = e; pos = e
    }
    return r substr(v, cur)
}

function redact_value(v,   lv) {
    if (!redact || v == "") return v
    if (length(v) > MAXLEN) return TOOLONG
    if (index(v, pkmarker) > 0) return PKTEXT
    if (index(v, "://") > 0) v = redact_url(v)
    if (index(v, "@") > 1 && index(v, ":") > 0) v = redact_userinfo(v)
    v = redact_tokens(v)
    lv = tolower(v)
    if (index(lv, "bearer") > 0 || index(lv, "basic") > 0) v = redact_scheme_word(v)
    if (index(tolower(v), "authorization") > 0) v = redact_authz(v)
    if (v ~ /[:=]/) { v = redact_pairkeys(v); v = redact_pairs(v) }
    return v
}

# ------------------------------------------------------------------ LINE RULES

# line_key LINE SKIPKW: [indent] [- ] [export |set ] [quote] key [quote] (= or :) <non-blank rest>
# -> LK_KEY, LK_HEAD (the line through the separator); a rest of only "{" or "[" is no match
function line_key(line, skipkw,   p, n, lo, kstart, len, after, q) {
    match(line, /^[ \t]*/); p = RLENGTH + 1
    if (match(substr(line, p), /^-[ \t]+/)) p += RLENGTH
    if (skipkw) {
        lo = tolower(substr(line, p, 7))
        if (lo ~ /^export[ \t]/) p += 6
        else if (lo ~ /^set[ \t]/) p += 3
        else return 0
        while (substr(line, p, 1) == " " || substr(line, p, 1) == "\t") p++
    }
    q = substr(line, p, 1); if (q == "\"" || q == "'") p++
    kstart = p; n = length(line)
    while (p <= n && substr(line, p, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.:\/@$-]/) p++
    for (len = p - kstart; len > 0; len--) {
        after = substr(line, kstart + len)
        if (match(after, /^["']?[ \t]*[:=][ \t]*/) && RLENGTH < length(after)) {
            if (substr(after, RLENGTH + 1) ~ /^[\[{][ \t]*$/) return 0
            LK_KEY = substr(line, kstart, len); LK_HEAD = substr(line, 1, kstart + len - 1 + RLENGTH)
            return 1
        }
    }
    return 0
}

# space pairs: a secret key and a quoted value separated by whitespace only (Groovy, yarn
# classic): password "x", "//reg/:_authToken" "x". The key starts the text or follows
# whitespace, { ( ; or ","; it may be quoted. An unquoted value after whitespace is left alone.
function redact_spacepairs(l,   r, n, i, b, q, k, ks, ke, w, c, ve) {
    r = ""; n = length(l); i = 1
    while (i <= n) {
        b = (i > 1) ? substr(l, i - 1, 1) : ""
        if (b == "" || is_ws(b) || index("{(;,", b) > 0) {
            q = substr(l, i, 1); k = i
            if (q == "\"" || q == "'") k++; else q = ""
            ks = k
            while (k <= n && substr(l, k, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.:\/@$-]/) k++
            ke = k
            if (ke > ks && (q == "" || substr(l, k, 1) == q)) {
                if (q != "") k++
                w = k
                while (k <= n && (substr(l, k, 1) == " " || substr(l, k, 1) == "\t")) k++
                c = substr(l, k, 1); ve = 0
                if (k > w && (c == "\"" || c == "'")) ve = sp_qend(l, k, c)
                if (ve > 0) {
                    if (secret_name(substr(l, ks, ke - ks))) r = r substr(l, i, k - i + 1) placeholder c
                    else r = r substr(l, i, ve - i + 1)
                    i = ve + 1; continue
                }
            }
        }
        r = r substr(l, i, 1); i++
    }
    return r
}

# sp_qend(s, k, q): the closing quote of the string opened by q at k ("..." with backslash
# escapes, '...' without), 0 when there is none
function sp_qend(s, k, q,   n) {
    n = length(s); k++
    while (k <= n) {
        if (q == "\"" && substr(s, k, 1) == "\\") { k += 2; continue }
        if (substr(s, k, 1) == q) return k
        k++
    }
    return 0
}

function redact_line(line,   l) {
    if (!redact || line == "") return line
    if (length(line) > MAXLEN) return TOOLONG
    l = line
    if (index(l, "\"") > 0 || index(l, "'") > 0) l = redact_spacepairs(l)
    if (l !~ /[=:<]/) return redact_value(l)
    # bare userinfo first: in "svc:pw@proxy.corp:8080" the line-key rule would see a key "svc:pw@proxy.corp"
    if (index(l, "@") > 1 && index(l, ":") > 0) l = redact_userinfo(l)
    if ((line_key(l, 1) || line_key(l, 0)) && secret_name(LK_KEY)) l = LK_HEAD placeholder
    if (index(l, "<") > 0) l = redact_xml(l)
    return redact_value(l)
}

# TEXT RULES (blocks, multi-line values) and the xml LINE RULE: redact_text.awk

# ------------------------------------------------------------------ COMMAND LINES

# options: (-|--|/)<name containing an option word>(=|:|whitespace)<value>
function redact_options(s,   r, n, i, c, j, k, lnm, w, hit, q, e, v) {
    r = ""; n = length(s); i = 1
    while (i <= n) {
        c = substr(s, i, 1)
        if ((c == "-" || c == "/") && (i == 1 || is_ws(substr(s, i - 1, 1)))) {
            j = i + 1
            if (c == "-" && substr(s, j, 1) == "-") j++
            k = j
            while (k <= n && substr(s, k, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.-]/) k++
            lnm = tolower(substr(s, j, k - j)); hit = 0
            for (w = 1; w <= NOW && !hit; w++) if (index(lnm, OW[w]) > 0) hit = 1
            if (hit && k <= n) {
                q = substr(s, k, 1)
                if (q == "=" || q == ":" || is_ws(q)) {
                    e = k + 1
                    if (is_ws(q)) while (e <= n && is_ws(substr(s, e, 1))) e++
                    if (e <= n && esc_quote(s, e)) {
                        # an escaped-quoted value keeps its delimiters
                        v = esc_end(s, e); if (v == 0) v = n + 1
                        r = r substr(s, i, e + 2 - i) placeholder; i = v; continue
                    }
                    if (e <= n) {
                        q = substr(s, e, 1); v = 0
                        if (q == "\"" || q == "'") { v = quote_end(s, e); v = (v > 0) ? v + 1 : 0 }
                        if (v == 0) { v = e; while (v <= n && !is_ws(substr(s, v, 1))) v++ }
                        if (v > e) { r = r substr(s, i, e - i) placeholder; i = v; continue }
                    }
                }
            }
            if (k <= i) k = i + 1
            r = r substr(s, i, k - i); i = k; continue
        }
        r = r c; i++
    }
    return r
}

# user options: -u / --user / --proxy-user user:secret -> user:<redacted>
function redact_useropt(s,   r, n, i, lo, o, j, k, u, e, c, qa, v) {
    r = ""; n = length(s); i = 1
    while (i <= n) {
        if (substr(s, i, 1) == "-" && (i == 1 || is_ws(substr(s, i - 1, 1)))) {
            lo = tolower(substr(s, i, 12)); o = 0
            if (lo == "--proxy-user") o = 12
            else if (substr(lo, 1, 6) == "--user") o = 6
            else if (substr(lo, 1, 2) == "-u") o = 2
            if (o > 0) {
                j = i + o; k = j
                while (k <= n && (is_ws(substr(s, k, 1)) || substr(s, k, 1) == "=")) k++
                # -u may carry its value attached (curl -ubob:pw)
                c = substr(s, j, 1)
                if (k > j || (o == 2 && c != "" && c != "-")) {
                    c = substr(s, k, 1); qa = 0
                    if (c == "\"" || c == "'") { qa = k; k++ }
                    u = k
                    while (k <= n) { c = substr(s, k, 1); if (is_ws(c) || c == ":" || c == "\"" || c == "'") break; k++ }
                    if (k > u && substr(s, k, 1) == ":") {
                        # the value: to the quote that closes the whole argument ("bob:pa ss"), else a run
                        # of text and quoted pieces (bob:'pa ss'x), which ends at whitespace
                        e = k + 1
                        if (qa) { e = quote_end(s, qa); if (e == 0) e = n + 1 }
                        else while (e <= n) {
                            c = substr(s, e, 1)
                            if (c == "\"" || c == "'") { v = quote_end(s, e); e = (v > 0) ? v + 1 : n + 1; continue }
                            if (is_ws(c)) break
                            e++
                        }
                        if (e > k + 1) { r = r substr(s, i, k - i + 1) placeholder; i = e; continue }
                    }
                }
            }
        }
        r = r substr(s, i, 1); i++
    }
    return r
}

# headers: -H / --header "Name: value" where Name contains a header word -> value replaced
function redact_headers(s,   r, n, i, lo, o, j, k, h, hn, w, hit, e, c) {
    r = ""; n = length(s); i = 1
    while (i <= n) {
        if (substr(s, i, 1) == "-" && (i == 1 || is_ws(substr(s, i - 1, 1)))) {
            lo = tolower(substr(s, i, 8)); o = 0
            if (lo == "--header") o = 8
            else if (substr(lo, 1, 2) == "-h") o = 2
            if (o > 0) {
                j = i + o; k = j
                while (k <= n && (is_ws(substr(s, k, 1)) || substr(s, k, 1) == "=")) k++
                if (k > j) {
                    c = substr(s, k, 1); if (c == "\"" || c == "'") k++
                    h = k
                    while (k <= n && substr(s, k, 1) ~ /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9-]/) k++
                    hn = tolower(substr(s, h, k - h)); hit = 0
                    for (w = 1; w <= NHW && !hit; w++) if (index(hn, HW[w]) > 0) hit = 1
                    if (hit) {
                        while (k <= n && is_ws(substr(s, k, 1))) k++
                        if (substr(s, k, 1) == ":") {
                            k++
                            while (k <= n && is_ws(substr(s, k, 1))) k++
                            e = k
                            while (e <= n) { c = substr(s, e, 1); if (c == "\"" || c == "'" || c == "\r" || c == "\n") break; e++ }
                            if (e > k) { r = r substr(s, i, k - i) placeholder; i = e; continue }
                        }
                    }
                }
            }
        }
        r = r substr(s, i, 1); i++
    }
    return r
}

# tool_in(ls, t): the lower-cased line ls contains tool t as a program name: after the start,
# whitespace, a quote or / \ ; & | ( =, with an optional .exe, .cmd, .bat or .com, then
# whitespace, a quote or the end
function tool_in(ls, t,   off, rest, k, p, b, a, x) {
    off = 0; rest = ls
    while ((k = index(rest, t)) > 0) {
        p = off + k
        b = (p > 1) ? substr(ls, p - 1, 1) : ""
        if (b == "" || is_ws(b) || index("\"'/\\;&|(=", b) > 0) {
            a = substr(ls, p + length(t))
            x = substr(a, 1, 4)
            if (x == ".exe" || x == ".cmd" || x == ".bat" || x == ".com") a = substr(a, 5)
            a = substr(a, 1, 1)
            if (a == "" || is_ws(a) || a == "\"" || a == "'") return 1
        }
        off = p; rest = substr(ls, p + 1)
    }
    return 0
}

# value_end(s, e): end (exclusive) of the value at e: a quoted or escaped-quoted (\"..\")
# value is one value, otherwise a run up to whitespace
function value_end(s, e,   n, q, k) {
    n = length(s); q = substr(s, e, 1)
    if (esc_quote(s, e)) { k = esc_end(s, e); return (k > 0) ? k + 2 : n + 1 }
    if (q == "\"" || q == "'") { k = quote_end(s, e); return (k > 0) ? k + 1 : n + 1 }
    while (e <= n && !is_ws(substr(s, e, 1))) e++
    return e
}

# one tool option o after whitespace: o<value> -> o<redacted>, o<whitespace><value> ->
# o<whitespace><redacted>. Options starting with "-" are case-sensitive, "/" options are not.
function redact_toolopt(s, o,   r, rest, k, b, j, e, v, ci) {
    r = ""; rest = s; ci = (substr(o, 1, 1) == "/")
    if (ci) o = tolower(o)
    while ((k = index(ci ? tolower(rest) : rest, o)) > 0) {
        b = (k > 1) ? substr(rest, k - 1, 1) : substr(r, length(r), 1)
        j = k + length(o)
        if (!is_ws(b) || j > length(rest)) { r = r substr(rest, 1, k); rest = substr(rest, k + 1); continue }
        e = j
        if (is_ws(substr(rest, j, 1))) {
            while (e <= length(rest) && is_ws(substr(rest, e, 1))) e++
            if (e > length(rest)) { r = r substr(rest, 1, k); rest = substr(rest, k + 1); continue }
        }
        v = value_end(rest, e)
        if (v <= e) { r = r substr(rest, 1, k); rest = substr(rest, k + 1); continue }
        r = r substr(rest, 1, e - 1) placeholder; rest = substr(rest, v)
    }
    return r rest
}

# tool options (spec "tool options"): the password options of every tool in tool_options that
# appears in the line as a program name
function redact_toolopts(s,   ls, i, t, opts, m, O, j) {
    if (NTN == 0) return s
    ls = tolower(s); opts = ""
    for (i = 1; i <= NTN; i++) { t = TNAME[i]; if (index(ls, t) > 0 && tool_in(ls, t)) opts = opts TOPTS[t] }
    if (opts == "") return s
    m = split(opts, O, " ")
    for (j = 1; j <= m; j++) s = redact_toolopt(s, O[j])
    return s
}

function redact_cmdline(s) {
    if (!redact || s == "") return s
    if (length(s) > MAXLEN) return TOOLONG
    # tool options first: an attached value (7z -pSecretPw) would read as an option name
    s = redact_toolopts(s)
    s = redact_options(s)
    if (index(s, ":") > 0) s = redact_useropt(s)
    if (index(s, ":") > 0) s = redact_headers(s)
    return redact_value(s)
}

# named values (environment, registry style): a secret name loses its value; any other value
# gets the command-line and value rules
function redact_named(name, v) {
    if (!redact || v == "") return v
    if (secret_name(name)) return placeholder
    if (length(v) > MAXLEN) return TOOLONG
    return redact_cmdline(v)
}
