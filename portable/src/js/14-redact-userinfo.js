// ---------------------------------------------------------------------------
// 14-redact-userinfo: scheme-less user:password@host, its fail-closed fallback for values beyond
// its bounds, and <key ending in authorization> credentials (spec/redaction.toml "bare
// userinfo" and "auth schemes"). Scanners that give the matches of ES_BARE_USERINFO_RE,
// ES_LONG_USERINFO_RE and ES_AUTH_HEADER_RE of src/ps/14-redact.ps1.
// ---------------------------------------------------------------------------

// A match starts the text or follows whitespace or one of " ' ; , = ( |.
function jsRdUiStartCode(k) {
    return jsRdWsCode(k) || k === 34 || k === 39 || k === 59 || k === 44 || k === 61 || k === 40 || k === 124;
}

// User characters: anything but whitespace and " ' / : = ; , ( |.
function jsRdUiUserCode(k) {
    return k >= 0 && !jsRdWsCode(k) && k !== 34 && k !== 39 && k !== 47 && k !== 58 && k !== 61
        && k !== 59 && k !== 44 && k !== 40 && k !== 124;
}

// After the host[:port]: the end of the text, whitespace or one of " ' / , ; ) ] } > < | & # ? \ . !
function jsRdUiEndAt(s, i) {
    if (i >= s.length) { return true; }
    var k = s.charCodeAt(i);
    return jsRdWsCode(k) || "\"'/,;)]}><|&#?\\.!".indexOf(s.charAt(i)) >= 0;
}

function jsRdUiPort(s, e) {
    // :<1-5 digits> at e followed by an end: the end of the port, else -1.
    if (s.charAt(e) !== ":") { return -1; }
    var j = e + 1;
    while (j < s.length && j - e <= 6 && s.charCodeAt(j) >= 48 && s.charCodeAt(j) <= 57) { j++; }
    var digits = j - e - 1;
    return (digits >= 1 && digits <= 5 && jsRdUiEndAt(s, j)) ? j : -1;
}

function jsRdUiHost(s, q) {
    // ([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})? then an end, with the backtracking of
    // the ps1 expression (a shorter host ends before a "."): the end, or -1.
    var e = jsRdRunWith(/[A-Za-z0-9._\-]*/g, s, q);
    if (e > q) {
        var port = jsRdUiPort(s, e);
        if (port >= 0) { return port; }
        if (jsRdUiEndAt(s, e)) { return e; }
        var dot = s.substring(q, e).lastIndexOf(".");
        return dot > 0 ? q + dot : -1;
    }
    if (s.charAt(q) !== "[") { return -1; }
    var j = jsRdRunWith(/[0-9A-Fa-f:.]*/g, s, q + 1);
    if (j === q + 1 || s.charAt(j) !== "]") { return -1; }
    var withPort = jsRdUiPort(s, j + 1);
    if (withPort >= 0) { return withPort; }
    return jsRdUiEndAt(s, j + 1) ? j + 1 : -1;
}

function jsRdUiGoodAt(st, from) {
    // The first "@" at or after `from` that a valid host follows (cached: `from` only grows).
    if (st.goodAt >= from) { return st.goodAt; }
    if (st.goodAt === -1) { return -1; }
    var a = st.v.indexOf("@", from);
    while (a >= 0) {
        var end = jsRdUiHost(st.v, a + 1);
        if (end >= 0) { st.goodAt = a; st.goodEnd = end; return a; }
        a = st.v.indexOf("@", a + 1);
    }
    st.goodAt = -1;
    return -1;
}

function jsRdUiStop(st, from) {
    // The first whitespace, quote, / or \ at or after `from` (cached), or the text length.
    if (st.stop >= from) { return st.stop; }
    st.stopRe.lastIndex = from;
    var m = st.stopRe.exec(st.v);
    st.stop = m ? m.index : st.v.length;
    return st.stop;
}

function jsRdUiMatch(st, s) {
    // user (1-128) ":" password (1-256, lazy) "@" host at s: { colon, at, end } or null.
    var v = st.v, u = s;
    while (u - s <= 128 && jsRdUiUserCode(v.charCodeAt(u))) { u++; }
    if (u === s || u - s > 128 || v.charAt(u) !== ":") { return null; }
    var at = jsRdUiGoodAt(st, u + 2);
    if (at < 0 || at - u - 1 > 256 || jsRdUiStop(st, u + 1) < at) { return null; }
    return { colon: u, at: at, end: st.goodEnd };
}

function jsRdBareUserinfo(v) {
    // user:password@host[:port] -> user:<redacted>@host[:port] (ES_BARE_USERINFO_RE).
    var stopRe = new RegExp("[" + JS_RD_WS + "\"'/\\\\]", "g");
    var st = { v: v, goodAt: -2, goodEnd: -1, stop: -1, stopRe: stopRe };
    var out = [], pos = 0, s = 0, n = v.length;
    while (s < n) {
        var m = (s === 0 || jsRdUiStartCode(v.charCodeAt(s - 1))) ? jsRdUiMatch(st, s) : null;
        if (!m) { s++; continue; }
        out.push(v.substring(pos, m.colon + 1), ES_PLACEHOLDER);
        pos = m.at;
        s = m.end;
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

function jsRdLongToken(v, s, e) {
    // A token [s, e) beyond the userinfo bounds: user part (to the first ":") of 129+ characters
    // and a password and "@" after it, or a password of 257+ characters before an "@".
    var colon = jsRdIndexIn(v, ":", s, e);
    if (colon < 0) { return false; }
    var r = colon + 1;
    while (r < e && v.charAt(r) !== "/" && v.charAt(r) !== "\\") { r++; }
    var last = v.substring(colon + 1, r).lastIndexOf("@");
    if (last < 0) { return false; }
    if (last >= 257) { return true; }
    return colon - s >= 129 && last >= 1;
}

function jsRdLongUserinfo(v) {
    // ES_LONG_USERINFO_RE: such a token becomes the placeholder as a whole (fail closed).
    var out = [], pos = 0, s = 0, n = v.length;
    while (s < n) {
        var k = v.charCodeAt(s);
        if (jsRdWsCode(k) || jsRdQuoteCode(k)) { s++; continue; }
        var e = s;
        while (e < n && !jsRdWsCode(v.charCodeAt(e)) && !jsRdQuoteCode(v.charCodeAt(e))) { e++; }
        if (jsRdLongToken(v, s, e)) { out.push(v.substring(pos, s), ES_PLACEHOLDER); pos = e; }
        s = e;
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

function jsRdUserinfo(v) {
    // Both userinfo rules, in the order of Protect-EsValue and Protect-EsLine.
    return jsRdLongUserinfo(jsRdBareUserinfo(v));
}

// ------------------------------------------------------------------ authorization keys

function jsRdSkipQuote(v, j) {
    // After an optional quote or escaped quote at j.
    if (jsRdEscQuoteAt(v, j)) { return j + 2; }
    return jsRdQuoteCode(v.charCodeAt(j)) ? j + 1 : j;
}

function jsRdAuthzCredEnd(v, j) {
    // Credentials stop at whitespace, a quote, "," ";" or a backslash before a quote.
    var n = v.length;
    while (j < n) {
        var k = v.charCodeAt(j);
        if (jsRdWsCode(k) || jsRdQuoteCode(k) || k === 44 || k === 59 || jsRdEscQuoteAt(v, j)) { break; }
        j++;
    }
    return j;
}

function jsRdAuthzAt(v, e) {
    // After a key ending in "authorization" (at e): [credentials start, end] or null.
    var j = jsRdSkipWs(v, jsRdSkipQuote(v, e));
    if (v.charAt(j) !== ":" && v.charAt(j) !== "=") { return null; }
    var j0 = jsRdSkipQuote(v, jsRdSkipWs(v, j + 1));
    var s = j0;
    while (jsRdLetterCode(v.charCodeAt(s))) { s++; }
    if (s > j0 && jsRdWsAt(v, s)) {
        var t = jsRdSkipWs(v, s);
        var ce = jsRdAuthzCredEnd(v, t);
        if (ce > t) { return [t, ce]; }
    }
    var end = jsRdAuthzCredEnd(v, j0);
    return end > j0 ? [j0, end] : null;
}

function jsRdAuthorization(v) {
    // <key ending in authorization> [quote] (: or =) [quote] [scheme] <credentials> -> placeholder.
    var lower = v.toLowerCase();
    var out = [], pos = 0, from = 0, k;
    while ((k = lower.indexOf("authorization", from)) >= 0) {
        from = k + 1;
        if (jsRdKeyCode(v.charCodeAt(k + 13))) { continue; }
        var hit = jsRdAuthzAt(v, k + 13);
        if (!hit) { continue; }
        out.push(v.substring(pos, hit[0]), ES_PLACEHOLDER);
        pos = hit[1];
        from = hit[1];
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}
