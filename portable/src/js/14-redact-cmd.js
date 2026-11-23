// ---------------------------------------------------------------------------
// 14-redact-cmd: command lines (spec/redaction.toml "COMMAND LINES"), named values, tables and
// the probe data safety net. Scanners that give the matches of the ps1 tool option, option,
// user option and header expressions (ES_TOOL_*, ES_CLI_*); then the value rules.
// ---------------------------------------------------------------------------

// ------------------------------------------------------------------ tool options

function jsRdToolIn(lower, tool) {
    // The tool as a program name: after the start, whitespace, a quote or / \ ; & | ( =, with an
    // optional .exe .cmd .bat .com, then a quote, whitespace or the end.
    var from = 0, k;
    while ((k = lower.indexOf(tool, from)) >= 0) {
        from = k + 1;
        var b = lower.charCodeAt(k - 1);
        if (k > 0 && !jsRdWsCode(b) && "\"'/\\;&|(=".indexOf(lower.charAt(k - 1)) < 0) { continue; }
        var a = k + tool.length;
        if (/^\.(exe|cmd|bat|com)/.test(lower.substring(a, a + 4))) { a += 4; }
        if (a >= lower.length || jsRdWsAt(lower, a) || jsRdQuoteCode(lower.charCodeAt(a))) { return true; }
    }
    return false;
}

function jsRdToolValueEnd(t, p) {
    // ES_TOOL_VALUE at p: an escaped-quoted string, a quoted string or a word. The end.
    if (jsRdEscQuoteAt(t, p)) {
        var d = jsRdEscEnd(t, p);
        return d < 0 ? t.length : d + 2;
    }
    var end = jsRdQuotedEnd(t, p);
    if (end >= 0) { return end; }
    end = p;
    while (end < t.length && !jsRdWsAt(t, end)) { end++; }
    return end;
}

function jsRdToolOption(t, option, attached) {
    // (\s<option>)(?=\S)<value> (attached) or (\s<option>\s+)<value> -> ...<redacted>.
    // Options starting with "/" are case-insensitive.
    var ci = option.charAt(0) === "/";
    var hay = ci ? t.toLowerCase() : t, o = ci ? option.toLowerCase() : option;
    var out = [], pos = 0, from = 0, last = 0, k;
    while ((k = hay.indexOf(o, from)) >= 0) {
        from = k + 1;
        if (k - 1 < last || !jsRdWsAt(t, k - 1)) { continue; }
        var v = k + o.length;
        if (v >= t.length || (attached ? jsRdWsAt(t, v) : !jsRdWsAt(t, v))) { continue; }
        if (!attached) { v = jsRdSkipWs(t, v); if (v >= t.length) { continue; } }
        var end = jsRdToolValueEnd(t, v);
        out.push(t.substring(pos, v), ES_PLACEHOLDER);
        pos = end;
        last = end;
        from = end;
    }
    return out.length ? out.join("") + t.substring(pos) : t;
}

function protectEsToolOptions(text) {
    // tool_options: the password options of a known tool named in the line (mysql -pX,
    // sqlcmd -P X). "-" options are case-sensitive, Windows "/" options are not.
    var tools = ES_REDACT_RULES.tools;
    var t = String(text);
    for (var i = 0; i < tools.names.length; i++) {
        if (!jsRdToolIn(t.toLowerCase(), tools.names[i])) { continue; }
        var options = tools.opts["k" + tools.names[i]];
        for (var j = 0; j < options.length; j++) {
            t = jsRdToolOption(jsRdToolOption(t, options[j], true), options[j], false);
        }
    }
    return t;
}

// ------------------------------------------------------------------ options

function jsRdHeadAt(t, m) {
    // (?:^|\s) at m: the index after it (the head of an option), or -1.
    if (m === 0 && !jsRdWsAt(t, 0)) { return 0; }
    return jsRdWsAt(t, m) ? m + 1 : -1;
}

function jsRdOptionName(t, h) {
    // (--?|/) <name holding an option word> (=|:|\s+) at h: the value start, or -1.
    var c = t.charAt(h), j = h + 1;
    if (c === "-" && t.charAt(j) === "-") { j++; } else if (c !== "-" && c !== "/") { return -1; }
    var e = j;
    while (jsRdKeyCode(t.charCodeAt(e))) { e++; }
    if (e === j || !jsRdContainsAny(t.substring(j, e).toLowerCase(), ES_REDACT_RULES.optionWords)) { return -1; }
    if (t.charAt(e) === "=" || t.charAt(e) === ":") { return e + 1; }
    return jsRdWsAt(t, e) ? jsRdSkipWs(t, e) : -1;
}

function jsRdOptionValue(t, v, escaped) {
    // The value of an option at v: [keep through, resume at, match end] or null.
    if (v >= t.length) { return null; }
    if (escaped) {
        if (!jsRdEscQuoteAt(t, v)) { return null; }
        var d = jsRdEscEnd(t, v);
        return d < 0 ? [v + 2, t.length, t.length] : [v + 2, d, d + 2];
    }
    if (jsRdEscQuoteAt(t, v)) { return null; }
    var end = jsRdQuotedEnd(t, v);
    if (end < 0) { end = v; while (end < t.length && !jsRdWsAt(t, end)) { end++; } }
    return end > v ? [v, end, end] : null;
}

function jsRdCliOptions(t, escaped) {
    // ES_CLI_OPTION_ESC_RE (escaped: delimiters kept) or ES_CLI_OPTION_RE.
    var out = [], pos = 0, m = 0, n = t.length;
    while (m < n) {
        var h = jsRdHeadAt(t, m);
        var v = h < 0 ? -1 : jsRdOptionName(t, h);
        var hit = v < 0 ? null : jsRdOptionValue(t, v, escaped);
        if (!hit) { m++; continue; }
        out.push(t.substring(pos, hit[0]), ES_PLACEHOLDER);
        pos = hit[1];
        m = hit[2];
    }
    return out.length ? out.join("") + t.substring(pos) : t;
}

// ------------------------------------------------------------------ user options and headers

function jsRdUserHead(t, h) {
    // -u (attached: before a character other than whitespace, = or -) or -u / --user /
    // --proxy-user then [\s=]+, any case: the index after the head, or -1.
    var lower = t.substring(h, h + 12).toLowerCase();
    if (lower.substring(0, 2) !== "-u" && lower.substring(0, 6) !== "--user" && lower !== "--proxy-user") { return -1; }
    var c = t.charCodeAt(h + 2);
    if (lower.substring(0, 2) === "-u" && c >= 0 && !jsRdWsCode(c) && c !== 61 && c !== 45) { return h + 2; }
    var e = h + (lower.substring(0, 2) === "-u" ? 2 : (lower === "--proxy-user" ? 12 : 6));
    var j = e;
    while (j < t.length && (jsRdWsAt(t, j) || t.charAt(j) === "=")) { j++; }
    return j > e ? j : -1;
}

function jsRdUserName(t, j) {
    // [^\s:"']+ then ":" at j: the index of the ":", or -1.
    var k = j;
    while (k < t.length && !jsRdWsAt(t, k) && ":\"'".indexOf(t.charAt(k)) < 0) { k++; }
    return (k > j && t.charAt(k) === ":") ? k : -1;
}

function jsRdUserQuotedHit(t, h) {
    // ES_CLI_USER_QUOTED_RE: "user:secret" quoted as a whole -> "user:<redacted>".
    var j = jsRdUserHead(t, h);
    if (j < 0 || !jsRdQuoteCode(t.charCodeAt(j))) { return null; }
    var colon = jsRdUserName(t, j + 1);
    if (colon < 0) { return null; }
    var close = t.indexOf(t.charAt(j), colon + 1);
    return close < 0 ? [colon + 1, t.length, t.length] : [colon + 1, close, close + 1];
}

function jsRdUserPlainHit(t, h) {
    // ES_CLI_USER_RE: user:secret with a quoted or plain secret -> user:<redacted>.
    var j = jsRdUserHead(t, h);
    var colon = j < 0 ? -1 : jsRdUserName(t, j);
    if (colon < 0 || colon + 1 >= t.length) { return null; }
    var end = jsRdQuotedEnd(t, colon + 1);
    if (end < 0 && !jsRdQuoteCode(t.charCodeAt(colon + 1))) {
        end = colon + 1;
        while (end < t.length && !jsRdWsAt(t, end) && !jsRdQuoteCode(t.charCodeAt(end))) { end++; }
    }
    return end > colon + 1 ? [colon + 1, end, end] : null;
}

function jsRdHeaderHit(t, h) {
    // ES_CLI_HEADER_RE: -H / --header "<name with a header word>: value" -> value replaced.
    var lower = t.substring(h, h + 8).toLowerCase();
    var e = lower.substring(0, 2) === "-h" ? h + 2 : (lower === "--header" ? h + 8 : -1);
    var j = e;
    while (e >= 0 && j < t.length && (jsRdWsAt(t, j) || t.charAt(j) === "=")) { j++; }
    if (e < 0 || j === e) { return null; }
    if (jsRdQuoteCode(t.charCodeAt(j))) { j++; }
    var k = jsRdRunWith(/[A-Za-z0-9\-]*/g, t, j);
    if (k === j || !jsRdContainsAny(t.substring(j, k).toLowerCase(), ES_REDACT_RULES.headerWords)) { return null; }
    var colon = jsRdSkipWs(t, k);
    if (t.charAt(colon) !== ":") { return null; }
    for (var p = jsRdSkipWs(t, colon + 1); p > colon; p--) {
        var end = jsRdRunWith(/[^"'\r\n]*/g, t, p);
        if (end > p) { return [p, end, end]; }
    }
    return null;
}

function jsRdHeadRule(t, rule) {
    // Every match of a rule whose head is (?:^|\s): text through hit[0], placeholder, from hit[1].
    var out = [], pos = 0, m = 0, n = t.length;
    while (m < n) {
        var h = jsRdHeadAt(t, m);
        var hit = (h < 0 || h >= n) ? null : rule(t, h);
        if (!hit) { m++; continue; }
        out.push(t.substring(pos, hit[0]), ES_PLACEHOLDER);
        pos = hit[1];
        m = hit[2];
    }
    return out.length ? out.join("") + t.substring(pos) : t;
}

// ------------------------------------------------------------------ command lines, named values

function protectEsCommandLine(text) {
    // Command lines: options, tool options, user:secret options and headers, then the value rules.
    if (!text || !ES_OPT.redact) { return text; }
    jsRdReady();
    var s = String(text);
    if (s.length > ES_MAX_LENGTH) { return ES_TOO_LONG; }
    // Tool options first: an attached value (7z -pSecretPw) would read as an option name.
    var t = protectEsToolOptions(s);
    t = jsRdCliOptions(jsRdCliOptions(t, true), false);
    if (t.indexOf(":") >= 0) {
        t = jsRdHeadRule(t, jsRdUserQuotedHit);
        t = jsRdHeadRule(t, jsRdUserPlainHit);
        t = jsRdHeadRule(t, jsRdHeaderHit);
    }
    return protectEsValue(t);
}

function protectEsNamedValue(name, value) {
    // Environment and registry values: secret names lose their value; strings get the
    // command-line and value rules; other types (numbers, booleans) pass unchanged.
    if (value === null || value === undefined || !ES_OPT.redact) { return value; }
    if (testEsSecretName(name)) { return ES_PLACEHOLDER; }
    if (typeof value === "string") { return protectEsCommandLine(value); }
    if (esIsArray(value)) {
        var items = [];
        for (var i = 0; i < value.length; i++) {
            items.push(typeof value[i] === "string" ? protectEsCommandLine(value[i]) : value[i]);
        }
        return items;
    }
    return value;
}

function protectEsTable(table) {
    // Copy of a name -> value table; values whose (leaf) name looks secret are replaced.
    var out = {};
    if (table === null || table === undefined) { return out; }
    var keys = esKeys(table);
    for (var i = 0; i < keys.length; i++) {
        var leaf = keys[i];
        var slash = leaf.lastIndexOf("\\");
        if (slash >= 0) { leaf = leaf.substring(slash + 1); }
        out[keys[i]] = protectEsNamedValue(leaf, table[keys[i]]);
    }
    return out;
}

// ------------------------------------------------------------------ probe data (safety net)

function jsRdDataItem(item, depth) {
    if (typeof item === "string") { return protectEsValue(item); }
    if (esIsArray(item) || esIsTable(item)) { return protectEsData(item, depth + 1); }
    return item;
}

function protectEsData(value, depth) {
    // The value rules applied to every string in probe data (tables and arrays copied).
    if (value === null || value === undefined || !ES_OPT.redact) { return value; }
    var d = depth || 0;
    if (d > 30) { return ES_PLACEHOLDER; }
    if (typeof value === "string") { return protectEsValue(value); }
    var i, copy;
    if (esIsTable(value)) {
        copy = {};
        for (var key in value) {
            if (esHas(value, key)) { copy[key] = jsRdDataItem(value[key], d); }
        }
        return copy;
    }
    if (esIsArray(value)) {
        copy = [];
        for (i = 0; i < value.length; i++) { copy.push(jsRdDataItem(value[i], d)); }
        return copy;
    }
    return value;
}
