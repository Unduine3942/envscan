// ---------------------------------------------------------------------------
// 14-redact-pairs: quoted strings, unquoted runs, pair keys, key/value pairs and the value rules
// (Protect-EsValue). Scanners that give the matches of ES_QUOTED_RE, the unquoted run,
// ES_PAIR_KEYS_ESC_RE, ES_PAIR_KEYS_RE, ES_KEY_HINT_RE and ES_PAIR_RE of src/ps/14-redact.ps1.
// ---------------------------------------------------------------------------

// ------------------------------------------------------------------ quoted strings

function jsRdSingleEnd(v, j) {
    // '...' with '' for a quote at j; unterminated runs to the end. The end (exclusive).
    var n = v.length, k = j + 1;
    while (k < n) {
        if (v.charCodeAt(k) !== 39) { k++; continue; }
        if (v.charCodeAt(k + 1) === 39) { k += 2; continue; }
        return k + 1;
    }
    return n;
}

function jsRdQuotedEnd(v, j) {
    // ES_QUOTED_RE at j: "..." with backslash escapes, or '...' ('' a quote) followed by any
    // \''...' (the shell idiom 'a'\''b'). The end (exclusive), or -1 when it does not match.
    var n = v.length, k;
    if (v.charCodeAt(j) === 34) {
        k = j + 1;
        while (k < n) {
            var c = v.charCodeAt(k);
            if (c === 34) { return k + 1; }
            if (c === 92) { if (k + 1 >= n) { return -1; } k += 2; continue; }
            k++;
        }
        return n;
    }
    if (v.charCodeAt(j) !== 39) { return -1; }
    k = jsRdSingleEnd(v, j);
    while (v.substring(k, k + 3) === "\\''") { k = jsRdSingleEnd(v, k + 2); }
    return k;
}

function jsRdEscEnd(v, j) {
    // v[j] is a backslash before a quote q (\" or \'): the index of the backslash of the \q that
    // closes it (one backslash, not a run of them), or -1 when it runs to the end.
    var close = "\\" + v.charAt(j + 1);
    var from = j + 2, at;
    while ((at = v.indexOf(close, from)) >= 0) {
        if (v.charCodeAt(at - 1) !== 92) { return at; }
        from = at + 1;
    }
    return -1;
}

// ------------------------------------------------------------------ unquoted runs and keys

// Separators , ; & # } ] ) " ' < > |: part of a value only before a value character.
function jsRdSepCode(k) {
    return k === 44 || k === 59 || k === 38 || k === 35 || k === 125 || k === 93 || k === 41 || k === 34
        || k === 39 || k === 60 || k === 62 || k === 124;
}

function jsRdKeyStartAt(v, k) {
    // [A-Za-z0-9_.-]+ ["']? \s* [:=] at k (the start of another key).
    var j = k;
    while (jsRdKeyCode(v.charCodeAt(j))) { j++; }
    if (j === k) { return false; }
    if (jsRdQuoteCode(v.charCodeAt(j))) { j++; }
    j = jsRdSkipWs(v, j);
    return v.charAt(j) === ":" || v.charAt(j) === "=";
}

function jsRdRunEnd(v, j) {
    // Unquoted run at j (spec "unquoted run"); the placeholder is one value character. The end.
    var n = v.length, ph = ES_PLACEHOLDER, i = j;
    while (i < n) {
        var c = v.charCodeAt(i);
        if (c === 60 && v.substring(i, i + ph.length) === ph) { i += ph.length; continue; }
        if (jsRdWsCode(c)) { break; }
        if (!jsRdSepCode(c)) { i++; continue; }
        var k = i;
        while (k < n && jsRdSepCode(v.charCodeAt(k))) { k++; }
        if (k >= n || jsRdWsAt(v, k) || jsRdKeyStartAt(v, k)) { break; }
        i = k;
    }
    return i;
}

function jsRdSepEnd(v, e, trailing) {
    // (\\?["'])? \s* [:=] (then \s* when trailing) at e: the end, or -1.
    var j = jsRdSkipWs(v, jsRdSkipQuote(v, e));
    if (v.charAt(j) !== ":" && v.charAt(j) !== "=") { return -1; }
    return trailing ? jsRdSkipWs(v, j + 1) : j + 1;
}

function jsRdNextKey(v, from, keyRe) {
    // The next key run starting at or after `from` that no key character precedes: [start, end].
    keyRe.lastIndex = from;
    var m;
    while ((m = keyRe.exec(v)) !== null) {
        var s = m.index, e = s + m[0].length;
        if (s === 0 || !jsRdKeyCode(v.charCodeAt(s - 1))) { return [s, e]; }
        keyRe.lastIndex = e;
    }
    return null;
}

function jsRdKeyHint(v) {
    // ES_KEY_HINT_RE: a key that holds a secret word, followed by (quote) : or =.
    var re = ES_REDACT_RULES.hintRe, keyRe = /[A-Za-z0-9_.\-]+/g, from = 0, key;
    while ((key = jsRdNextKey(v, from, keyRe)) !== null) {
        from = key[1];
        if (jsRdSepEnd(v, key[1], false) >= 0 && re.test(v.substring(key[0], key[1]))) { return true; }
    }
    return false;
}

// ------------------------------------------------------------------ pair keys

function jsRdPairKeyValue(v, s, lower) {
    // A pair key (password, pwd, ...) at s followed by \s*=\s*: the value start, or -1.
    var keys = ES_REDACT_RULES.pairKeys;
    for (var i = 0; i < keys.length; i++) {
        if (lower.substring(s, s + keys[i].length) !== keys[i]) { continue; }
        var j = jsRdSkipWs(v, s + keys[i].length);
        return v.charAt(j) === "=" ? jsRdSkipWs(v, j + 1) : -1;
    }
    return -1;
}

function jsRdPairKeyEscHit(v, j) {
    // An escaped-quoted value at j: [keep through, resume at] (the delimiters stay), or null.
    if (!jsRdEscQuoteAt(v, j)) { return null; }
    var d = jsRdEscEnd(v, j);
    return d < 0 ? [j + 2, v.length] : [j + 2, d];
}

function jsRdPairKeyPlainHit(v, j) {
    // A quoted string or an unquoted run at j (not an escaped quote): [start, end] or null.
    if (j >= v.length || jsRdEscQuoteAt(v, j)) { return null; }
    var end = jsRdQuotedEnd(v, j);
    if (end < 0) { end = jsRdRunEnd(v, j); }
    return end > j ? [j, end] : null;
}

function jsRdPairKeys(v, escaped) {
    // ES_PAIR_KEYS_ESC_RE (escaped) or ES_PAIR_KEYS_RE: the value of a pair key -> placeholder.
    var lower = v.toLowerCase(), keyRe = /[A-Za-z0-9_.\-]+/g;
    var out = [], pos = 0, from = 0, key;
    while ((key = jsRdNextKey(v, from, keyRe)) !== null) {
        from = key[0] + 1;
        var j = jsRdPairKeyValue(v, key[0], lower);
        var hit = j < 0 ? null : (escaped ? jsRdPairKeyEscHit(v, j) : jsRdPairKeyPlainHit(v, j));
        if (!hit) { from = key[1]; continue; }
        out.push(v.substring(pos, hit[0]), ES_PLACEHOLDER);
        pos = hit[1];
        from = escaped && hit[1] < v.length ? hit[1] + 2 : hit[1];
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

// ------------------------------------------------------------------ key/value pairs

function jsRdPairCut(v, start) {
    // Protect-EsPairs for one secret key whose value starts at `start`:
    // [keep through, resume at, stop] or null (nothing to replace).
    var n = v.length;
    if (jsRdEscQuoteAt(v, start)) {
        var d = jsRdEscEnd(v, start);
        return [start + 2, d < 0 ? n : d, false];
    }
    var c = v.charAt(start);
    if (c === "\"" || c === "'") {
        var end = jsRdQuotedEnd(v, start);
        var close = (end < 0 || end - start < 2 || v.charAt(end - 1) !== c) ? n : end - 1;
        return [start + 1, close, false];
    }
    if (c === "{" || c === "[") {
        return jsRdIsBlank(v.substring(start + 1)) ? null : [start, n, true];
    }
    var run = jsRdRunEnd(v, start);
    return run > start ? [start, run, false] : null;
}

function jsRdXmlQualifiedKey(v, s, e) {
    // spec VALUE RULES key/value: a key right after "<" or "</" followed directly by ":" and a
    // secret element name (xml_elements, any case, no word character after it) is the prefix of an
    // XML qualified name, not a key (<token:password>, </ns:clientSecret>). "<password:x>" and
    // "<password: x" stay key/value pairs.
    var lt = v.charCodeAt(s - 1) === 47 ? s - 2 : s - 1;
    if (lt < 0 || v.charCodeAt(lt) !== 60 || v.charCodeAt(e) !== 58) { return false; }
    return jsRdXmlElementAt(jsRdXmlLower(v.substr(e + 1, 64)), 0) > 0;
}

function jsRdPairs(v) {
    // Key/value rule: the value of every secret key (key run + (quote) : or =) in the text.
    var keyRe = /[A-Za-z0-9_.\-]+/g, n = v.length;
    var out = [], pos = 0, from = 0, key;
    while ((key = jsRdNextKey(v, from, keyRe)) !== null) {
        var sep = jsRdSepEnd(v, key[1], true);
        from = sep < 0 ? key[1] : sep;
        if (sep < 0 || key[0] < pos || sep >= n) { continue; }
        if (jsRdXmlQualifiedKey(v, key[0], key[1])) { continue; }
        var name = v.substring(key[0], key[1]);
        if (name.length >= 13 && name.toUpperCase().substring(name.length - 13) === "AUTHORIZATION") { continue; }
        if (!jsRdSecretCached(name)) { continue; }
        var cut = jsRdPairCut(v, sep);
        if (!cut) { continue; }
        out.push(v.substring(pos, cut[0]), ES_PLACEHOLDER);
        pos = cut[1];
        if (cut[2]) { break; }
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

// ------------------------------------------------------------------ the value rules

function jsRdAny(v) {
    // True for any value that one of the value rules could change (cheap pre-test, a superset
    // of ES_REDACT_ANY_RE).
    if (v.indexOf("://") >= 0 || v.indexOf(ES_PK_MARKER) >= 0) { return true; }
    var lower = v.toLowerCase();
    if (lower.indexOf("bearer") >= 0 || lower.indexOf("basic") >= 0 || lower.indexOf("authorization") >= 0) { return true; }
    if (v.indexOf("@") >= 0 && v.indexOf(":") >= 0) { return true; }
    var re = ES_REDACT_RULES.tokenRe;
    re.lastIndex = 0;
    if (re.test(v)) { return true; }
    return jsRdKeyHint(v);
}

function jsRdValueRules(text) {
    // The value rules in the order of Protect-EsValue (after the private key and length tests).
    var v = text;
    if (v.indexOf("://") >= 0) {
        v = jsRdUrlUser(jsRdUrlPass(v));
        if (v.indexOf("/t/") >= 0) { v = jsRdConda(v); }
    }
    if (v.indexOf("@") > 0) { v = jsRdUserinfo(v); }
    if (v.length >= ES_REDACT_RULES.min) { v = jsRdTokens(v); }
    var lower = v.toLowerCase();
    if (lower.indexOf("bearer") >= 0 || lower.indexOf("basic") >= 0) { v = jsRdBearer(v); }
    if (lower.indexOf("authorization") >= 0) { v = jsRdAuthorization(v); }
    if (jsRdKeyHint(v)) {
        v = jsRdPairKeys(jsRdPairKeys(v, true), false);
        v = jsRdPairs(v);
    }
    return v;
}

function protectEsValue(value) {
    if (value === null || value === undefined || !ES_OPT.redact) { return value; }
    jsRdReady();
    var v = String(value);
    if (v.length === 0 || !jsRdAny(v)) { return v; }
    if (v.indexOf(ES_PK_MARKER) >= 0) { return ES_PK_TEXT; }
    if (v.length > ES_MAX_LENGTH) { return ES_TOO_LONG; }
    return jsRdValueRules(v);
}
