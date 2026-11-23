// ---------------------------------------------------------------------------
// 14-redact-text: configuration lines and whole texts (spec/redaction.toml "LINE RULES" and
// "TEXT RULES"). Port of Protect-EsLine, Protect-EsSpacePairs, Protect-EsText and its helpers.
// The line expressions need no lookbehind and run as JScript regular expressions; .NET "."
// (anything but \n) is written [^\n], and the ps1 -match is case-insensitive (flag i).
// ---------------------------------------------------------------------------

function jsRdRe(source, flags) {
    // A regular expression whose \s and \S (all outside classes) mean the .NET whitespace.
    var text = source.replace(/\\s/g, "[" + JS_RD_WS + "]").replace(/\\S/g, "[^" + JS_RD_WS + "]");
    return new RegExp(text, flags);
}

function jsRdLineRules(r) {
    var attributes = convertToEsAlternation(r.xml_attributes);
    var secretWords = convertToEsAlternation([].concat(r.name_contains, ["pwd", "pass"]));
    var key = "([A-Za-z0-9_.\\-:/@$]+)";
    return {
        lineKey: jsRdRe("^(\\s*(?:-\\s+)?(?:export\\s+|set\\s+)?[\"']?)" + key + "([\"']?\\s*[:=]\\s*)(\\S[^\\n]*)\\n?$", "i"),
        blockKey: jsRdRe("^(\\s*)(?:-\\s+)?[\"']?" + key + "[\"']?\\s*[:=]\\s*(?:[\\[{]|[|>][-+0-9]*)?\\s*$", "i"),
        tripleKey: jsRdRe("^\\s*[\"']?" + key + "[\"']?\\s*[:=]\\s*(\"\"\"|''')(?![^\\n]*\\2)", "i"),
        xmlElements: jsRdLowerList(r.xml_elements),
        xmlAttribute: jsRdRe("(\\b(?:" + attributes + ")\\s*=\\s*\")[^\"]*(\")", "gi"),
        xmlPair: jsRdRe("(\\b(?:key|name)\\s*=\\s*\"[^\"]*(?:" + secretWords + ")[^\"]*\"\\s+value\\s*=\\s*\")[^\"]*(\")", "gi"),
        xmlUrlKey: jsRdRe("(<add\\s+key\\s*=\\s*\"[a-z][a-z0-9+.\\-]*://[^\"]*\"\\s+value\\s*=\\s*\")[^\"]*(\")", "gi"),
        closers: jsRdRe("^\\s*[}\\]]+[,;]?\\s*$", ""),
        openOnly: jsRdRe("^[\\[{]\\s*$", "")
    };
}

function jsRdLowerList(list) {
    var out = [];
    for (var i = 0; i < list.length; i++) { out.push(String(list[i]).toLowerCase()); }
    return out;
}

function jsRdReplaceInner(text, re) {
    // re has two groups around the part to replace: $1 <placeholder> $2.
    re.lastIndex = 0;
    return text.replace(re, function (all, head, tail) { return head + ES_PLACEHOLDER + tail; });
}

function jsRdXml(line) {
    var rules = ES_REDACT_RULES.lines;
    var l = jsRdXmlScan(line).text;
    l = jsRdReplaceInner(l, rules.xmlAttribute);
    l = jsRdReplaceInner(l, rules.xmlPair);
    return jsRdReplaceInner(l, rules.xmlUrlKey);
}

// ------------------------------------------------------------------ lines

function protectEsLine(line) {
    if (line === null || line === undefined || !ES_OPT.redact) { return line; }
    jsRdReady();
    var l = String(line);
    if (l.length > ES_MAX_LENGTH) { return ES_TOO_LONG; }
    if (l.indexOf("\"") >= 0 || l.indexOf("'") >= 0) { l = protectEsSpacePairs(l); }
    if (!/[=:<]/.test(l)) { return protectEsValue(l); }
    // user:password@host first: the key rule would take user:password@host as the key.
    if (l.indexOf("@") > 0) { l = jsRdUserinfo(l); }
    var m = ES_REDACT_RULES.lines.lineKey.exec(l);
    if (m && !ES_REDACT_RULES.lines.openOnly.test(m[4]) && testEsSecretName(m[2])) { l = m[1] + m[2] + m[3] + ES_PLACEHOLDER; }
    if (l.indexOf("<") >= 0) { l = jsRdXml(l); }
    return protectEsValue(l);
}

function jsRdSpaceStartCode(k) {
    // Before a space pair key: the start, whitespace or one of { ( ; ,
    return !(k >= 0) || jsRdWsCode(k) || k === 123 || k === 40 || k === 59 || k === 44;
}

function jsRdSpaceKeyCode(k) {
    // [A-Za-z0-9_.\-:/@$]
    return jsRdKeyCode(k) || k === 58 || k === 47 || k === 64 || k === 36;
}

function jsRdSpaceValueEnd(v, j) {
    // "..." (backslash escapes, no line break after a backslash) or '...' at j, closed: end or -1.
    var q = v.charCodeAt(j), n = v.length, k = j + 1;
    while (k < n) {
        var c = v.charCodeAt(k);
        if (c === q) { return k + 1; }
        if (q === 34 && c === 92) { if (v.charCodeAt(k + 1) === 10) { return -1; } k += 2; continue; }
        k++;
    }
    return -1;
}

function jsRdSpacePairAt(v, s) {
    // ES_SPACE_PAIR_RE at s: { key, value: [start, end] } or null.
    var q = v.charCodeAt(s), k = jsRdQuoteCode(q) ? s + 1 : s;
    var ks = k;
    while (jsRdSpaceKeyCode(v.charCodeAt(k))) { k++; }
    if (k === ks) { return null; }
    var ke = k;
    if (jsRdQuoteCode(q)) { if (v.charCodeAt(k) !== q) { return null; } k++; }
    var w = k;
    while (v.charCodeAt(k) === 32 || v.charCodeAt(k) === 9) { k++; }
    if (k === w || !jsRdQuoteCode(v.charCodeAt(k))) { return null; }
    var end = jsRdSpaceValueEnd(v, k);
    return end < 0 ? null : { key: v.substring(ks, ke), value: [k, end] };
}

function protectEsSpacePairs(line) {
    // The quoted value of a secret key that only whitespace separates from it.
    var v = String(line), n = v.length;
    var out = [], pos = 0, s = 0;
    while (s < n) {
        var m = jsRdSpaceStartCode(v.charCodeAt(s - 1)) ? jsRdSpacePairAt(v, s) : null;
        if (!m) { s++; continue; }
        s = m.value[1];
        if (!testEsSecretName(m.key)) { continue; }
        var quote = v.charAt(m.value[0]);
        out.push(v.substring(pos, m.value[0]), quote, ES_PLACEHOLDER, quote);
        pos = m.value[1];
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

// ------------------------------------------------------------------ whole texts

function jsRdSplitLines(text) {
    // text -split "\r?\n" (a string separator keeps empty lines).
    var parts = text.split("\n");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
        var p = parts[i];
        out.push((i < parts.length - 1 && p.charAt(p.length - 1) === "\r") ? p.substring(0, p.length - 1) : p);
    }
    return out;
}

function protectEsText(text) {
    // Whole files and raw output: line rules plus multi-line values opened by a secret key.
    if (text === null || text === undefined || !ES_OPT.redact) { return text; }
    jsRdReady();
    var t = String(text);
    if (t.indexOf(ES_PK_MARKER) >= 0) { return ES_PK_TEXT; }
    var state = { block: -1, until: null, xml: false, tag: null };
    var lines = jsRdSplitLines(t);
    var out = [];
    for (var i = 0; i < lines.length; i++) { out.push(protectEsTextLine(lines[i], state)); }
    return out.join("\n");
}

function protectEsTextLine(line, state) {
    // One line of protectEsText; state carries an open value from line to line.
    if (state.tag) {
        var tagged = protectEsXmlTagLine(line, state);
        if (tagged !== null) { return tagged; }
    }
    if (state.until) { return state.xml ? protectEsXmlUntilLine(line, state) : protectEsUntilLine(line, state); }
    var indent = jsRdLeadingWs(line);
    if (state.block >= 0) {
        if (jsRdIsBlank(line) || ES_REDACT_RULES.lines.closers.test(line)) { return line; }
        if (indent > state.block || (indent === state.block && line.substring(indent, indent + 2) === "- ")) {
            return line.substring(0, indent) + ES_PLACEHOLDER;
        }
        state.block = -1;
    }
    var result = protectEsLine(line);
    startEsTextBlock(line, state);
    return result;
}

function startEsTextBlock(line, state) {
    // A value that goes on over the next lines: an indented block ({ [ or a YAML | >) or a
    // triple-quoted string after a secret key, or a secret XML element left open.
    var rules = ES_REDACT_RULES.lines, m;
    if (line.indexOf(":") >= 0 || line.indexOf("=") >= 0) {
        m = rules.blockKey.exec(line);
        if (m && testEsSecretName(m[2])) { state.block = m[1].length; return; }
        m = rules.tripleKey.exec(line);
        if (m && testEsSecretName(m[1])) { state.until = m[2]; return; }
    }
    if (line.indexOf("<") >= 0) { startEsXmlState(line, state); }
}

function protectEsUntilLine(line, state) {
    // A line inside a triple-quoted string: replaced up to the closing delimiter, which ends the
    // value and stays (with what follows it). XML elements: protectEsXmlUntilLine.
    var indent = jsRdLeadingWs(line);
    var at = line.toLowerCase().indexOf(state.until);
    if (at < 0) {
        return jsRdIsBlank(line) ? line : line.substring(0, indent) + ES_PLACEHOLDER;
    }
    state.until = null;
    var before = line.substring(0, at);
    if (!jsRdIsBlank(before)) { before = line.substring(0, indent) + ES_PLACEHOLDER; }
    return before + line.substring(at);
}
