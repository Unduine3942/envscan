// ---------------------------------------------------------------------------
// 14-redact: secret redaction, implementing the rules documented in spec/redaction.toml.
// Port of src/ps/14-redact.ps1. JScript regular expressions have no lookbehind, no atomic
// groups and no \G, so the rules whose ps1 regular expressions need them are small scanners
// (as in src/sh/awk/redact.awk) that give the matches the ps1 expressions give. Every scanner
// walks the text once from left to right and looks at bounded windows only: linear time.
// Files: 14-redact.js (setup, names, URL, userinfo, token and scheme rules),
// 14-redact-pairs.js (key/value rules, protectEsValue), 14-redact-text.js (lines, text) and
// 14-redact-cmd.js (command lines, named values, probe data).
// ---------------------------------------------------------------------------

var ES_REDACT_READY = false;
var ES_PK_MARKER = "PRIVATE KEY";
var ES_PK_TEXT = "<redacted: private key>";
// A line, command line or value longer than this is replaced whole instead of scanned.
var ES_MAX_LENGTH = 131072;
var ES_TOO_LONG = "<redacted: too long>";
// Rule tables built from ES_REDACT by initializeEsRedaction.
var ES_REDACT_RULES = null;
var ES_NAME_CACHE = {};
var ES_NAME_CACHE_COUNT = 0;
// Whitespace as .NET \s sees it (for regular expressions built at run time).
var JS_RD_WS = "\\t\\n\\u000b\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";

// ------------------------------------------------------------------ character classes

function jsRdWsCode(k) {
    // .NET \s: ASCII whitespace, NEL and the Unicode space separators.
    if (k === 32 || (k >= 9 && k <= 13)) { return true; }
    if (!(k >= 128)) { return false; }
    return k === 0x85 || k === 0xa0 || k === 0x1680 || (k >= 0x2000 && k <= 0x200a) || k === 0x2028
        || k === 0x2029 || k === 0x202f || k === 0x205f || k === 0x3000;
}

function jsRdWsAt(s, i) { return jsRdWsCode(s.charCodeAt(i)); }

function jsRdAlnumCode(k) { return (k >= 48 && k <= 57) || (k >= 65 && k <= 90) || (k >= 97 && k <= 122); }

function jsRdLetterCode(k) { return (k >= 65 && k <= 90) || (k >= 97 && k <= 122); }

// \w (ASCII): letters, digits, "_".
function jsRdWordCode(k) { return jsRdAlnumCode(k) || k === 95; }

// Key characters [A-Za-z0-9_.-].
function jsRdKeyCode(k) { return jsRdAlnumCode(k) || k === 95 || k === 46 || k === 45; }

function jsRdQuoteCode(k) { return k === 34 || k === 39; }

// A backslash followed by a quote at i (\" or \').
function jsRdEscQuoteAt(s, i) { return s.charCodeAt(i) === 92 && jsRdQuoteCode(s.charCodeAt(i + 1)); }

function jsRdSkipWs(s, i) {
    var n = s.length;
    while (i < n && jsRdWsCode(s.charCodeAt(i))) { i++; }
    return i;
}

function jsRdLeadingWs(s) { return jsRdSkipWs(s, 0); }

function jsRdIsBlank(s) { return jsRdSkipWs(s, 0) === s.length; }

function jsRdEscapeRe(text) { return String(text).replace(/[\\^$.*+?()[\]{}|\/\-]/g, "\\$&"); }

// The end (exclusive) of a run of characters that `re` (a global class*, e.g. /[a-z]*/g) takes at i.
function jsRdRunWith(re, s, i) {
    re.lastIndex = i;
    var m = re.exec(s);
    return (m && m.index === i) ? i + m[0].length : i;
}

// ------------------------------------------------------------------ setup

function convertToEsAlternation(words) {
    // Regular expression alternation of literal words, longest first.
    var list = jsRdWords(words, "");
    var out = [];
    for (var i = 0; i < list.length; i++) { out.push(jsRdEscapeRe(list[i])); }
    return out.join("|");
}

function jsRdWords(words, mode) {
    // Non-empty strings, upper- or lower-cased by mode, longest first.
    var list = [];
    var items = esIsArray(words) ? words : [words];
    for (var i = 0; i < items.length; i++) {
        if (items[i] === null || items[i] === undefined || String(items[i]) === "") { continue; }
        var w = String(items[i]);
        list.push(mode === "upper" ? w.toUpperCase() : (mode === "lower" ? w.toLowerCase() : w));
    }
    list.sort(function (a, b) { return b.length - a.length; });
    return list;
}

function jsRdSet(words) {
    var set = {};
    var list = jsRdWords(words, "upper");
    for (var i = 0; i < list.length; i++) { set["k" + list[i]] = true; }
    return set;
}

function jsRdTokenPrefixes(rules) {
    // Each prefix with the length its token needs: token_min_length, at least prefix + 4.
    var min = Number(rules.token_min_length);
    var list = jsRdWords(rules.token_prefixes, "");
    var out = [];
    for (var i = 0; i < list.length; i++) {
        var rest = min - list[i].length;
        out.push({ prefix: list[i], need: list[i].length + (rest < 4 ? 4 : rest) });
    }
    return out;
}

function jsRdToolTable(entries) {
    // tool_options "tool:option" -> { names: [tool...], opts: { "k"+tool: [option...] } }.
    var names = [];
    var opts = {};
    var list = esIsArray(entries) ? entries : [];
    for (var i = 0; i < list.length; i++) {
        var text = String(list[i]);
        var colon = text.indexOf(":");
        if (colon < 1) { continue; }
        var tool = text.substring(0, colon).toLowerCase();
        if (!esHas(opts, "k" + tool)) { opts["k" + tool] = []; names.push(tool); }
        opts["k" + tool].push(text.substring(colon + 1));
    }
    return { names: names, opts: opts };
}

function jsRdBuildRules(r) {
    var hint = [].concat(r.name_segments, r.name_contains, r.name_suffixes, r.pair_keys);
    var tokenAlt = [];
    var prefixes = jsRdTokenPrefixes(r);
    for (var i = 0; i < prefixes.length; i++) { tokenAlt.push(jsRdEscapeRe(prefixes[i].prefix)); }
    return {
        segments: jsRdSet(r.name_segments), exact: jsRdSet(r.exact_exceptions),
        suffixExcept: jsRdWords(r.suffix_exceptions, "upper"), contains: jsRdWords(r.name_contains, "upper"),
        suffixes: jsRdWords(r.name_suffixes, "upper"), min: Number(r.token_min_length),
        prefixes: prefixes, tokenRe: new RegExp(tokenAlt.join("|"), "g"),
        pairKeys: jsRdWords(r.pair_keys, "lower"), hintRe: new RegExp(convertToEsAlternation(hint), "i"),
        optionWords: jsRdWords(r.option_words, "lower"), headerWords: jsRdWords(r.header_words, "lower"),
        tools: jsRdToolTable(r.tool_options), lines: jsRdLineRules(r)
    };
}

function initializeEsRedaction() {
    var r = ES_REDACT;
    ES_PLACEHOLDER = String(r.placeholder);
    ES_PK_MARKER = String(r.private_key_marker);
    ES_REDACT_RULES = jsRdBuildRules(r);
    ES_NAME_CACHE = {};
    ES_NAME_CACHE_COUNT = 0;
    ES_REDACT_READY = true;
}

function jsRdReady() { if (!ES_REDACT_READY) { initializeEsRedaction(); } }

// ------------------------------------------------------------------ names

function jsRdSegments(upper) {
    // Runs of [A-Z0-9] (ps: -split '[^A-Z0-9]+', empty parts dropped).
    var out = [];
    var parts = upper.replace(/[^A-Z0-9]+/g, " ").split(" ");
    for (var i = 0; i < parts.length; i++) { if (parts[i] !== "") { out.push(parts[i]); } }
    return out;
}

function jsRdEndsWithAny(text, words) {
    for (var i = 0; i < words.length; i++) {
        var w = words[i];
        if (text.length >= w.length && text.substring(text.length - w.length) === w) { return true; }
    }
    return false;
}

function jsRdContainsAny(text, words) {
    for (var i = 0; i < words.length; i++) { if (text.indexOf(words[i]) >= 0) { return true; } }
    return false;
}

function testEsSecretName(name) {
    if (name === null || name === undefined || String(name) === "") { return false; }
    jsRdReady();
    var rules = ES_REDACT_RULES;
    var text = String(name);
    if (rules.exact["k" + text.toUpperCase()]) { return false; }
    // camelCase boundaries become separators: sessionKey -> session_Key, HTTPProxy -> HTTP_Proxy.
    var split = text.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2");
    var segments = jsRdSegments(split.toUpperCase());
    if (segments.length === 0) { return false; }
    if (jsRdEndsWithAny(segments.join("_"), rules.suffixExcept)) { return false; }
    for (var i = 0; i < segments.length; i++) { if (rules.segments["k" + segments[i]]) { return true; } }
    var joined = segments.join("");
    return jsRdContainsAny(joined, rules.contains) || jsRdEndsWithAny(joined, rules.suffixes);
}

function jsRdSecretCached(key) {
    // The name verdict, cached per key (Protect-EsPairs).
    var slot = "k" + key;
    if (esHas(ES_NAME_CACHE, slot)) { return ES_NAME_CACHE[slot]; }
    if (ES_NAME_CACHE_COUNT > 4096) { ES_NAME_CACHE = {}; ES_NAME_CACHE_COUNT = 0; }
    var secret = testEsSecretName(key);
    ES_NAME_CACHE[slot] = secret;
    ES_NAME_CACHE_COUNT++;
    return secret;
}

// ------------------------------------------------------------------ URL userinfo and conda tokens

function jsRdSchemeCode(k) { return jsRdAlnumCode(k) || k === 43 || k === 46 || k === 45; }

function jsRdHasScheme(s, k, floor) {
    // \b[a-z][a-z0-9+.-]* ending at k (the "://"), starting at or after floor.
    var i = k - 1;
    while (i >= floor && jsRdSchemeCode(s.charCodeAt(i))) { i--; }
    for (var p = i + 1; p < k; p++) {
        if (jsRdLetterCode(s.charCodeAt(p)) && !jsRdWordCode(s.charCodeAt(p - 1))) { return true; }
    }
    return false;
}

function jsRdAuthorityEnd(s, i, stops) {
    // First index at or after i holding whitespace or one of `stops` (char codes).
    var n = s.length;
    while (i < n) {
        var k = s.charCodeAt(i);
        if (jsRdWsCode(k) || stops.indexOf(String.fromCharCode(k)) >= 0) { break; }
        i++;
    }
    return i;
}

function jsRdIndexIn(s, ch, from, to) {
    for (var i = from; i < to; i++) { if (s.charAt(i) === ch) { return i; } }
    return -1;
}

function jsRdUrlPass(v) {
    // scheme://user:password@host -> scheme://user:<redacted>@host (password to the last "@").
    var out = [], pos = 0, from = 0, k;
    while ((k = v.indexOf("://", from)) >= 0) {
        from = k + 1;
        if (!jsRdHasScheme(v, k, pos)) { continue; }
        var end = jsRdAuthorityEnd(v, k + 3, "/?#");
        var colon = jsRdIndexIn(v, ":", k + 3, end);
        if (colon < 0) { continue; }
        var at = v.substring(colon, end).lastIndexOf("@");
        if (at <= 0) { continue; }
        out.push(v.substring(pos, colon + 1), ES_PLACEHOLDER);
        pos = colon + at;
        from = pos + 1;
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

function jsRdUrlUser(v) {
    // scheme://<token of token_min_length+ characters>@host -> scheme://<redacted>@host.
    var min = ES_REDACT_RULES.min;
    var out = [], pos = 0, from = 0, k;
    while ((k = v.indexOf("://", from)) >= 0) {
        from = k + 1;
        if (!jsRdHasScheme(v, k, pos)) { continue; }
        var end = jsRdAuthorityEnd(v, k + 3, "/?#:@");
        if (v.charAt(end) !== "@" || end - (k + 3) < min) { continue; }
        out.push(v.substring(pos, k + 3), ES_PLACEHOLDER);
        pos = end;
        from = end + 1;
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

function jsRdCondaAt(v, k) {
    // The first "/t/<8+ chars>/" in the run after "://" at k: [segment start, end], or null.
    var runEnd = jsRdAuthorityEnd(v, k + 3, "");
    var p = v.indexOf("/t/", k + 3);
    while (p >= 0 && p + 3 <= runEnd) {
        var segEnd = jsRdAuthorityEnd(v, p + 3, "/");
        if (segEnd - (p + 3) >= 8 && v.charAt(segEnd) === "/") { return [p + 3, segEnd]; }
        p = v.indexOf("/t/", p + 1);
    }
    return { skip: runEnd };
}

function jsRdConda(v) {
    // (://\S*?/t/)<8+ characters other than / and whitespace>(?=/) -> placeholder.
    var out = [], pos = 0, from = 0, k;
    while ((k = v.indexOf("://", from)) >= 0) {
        var hit = jsRdCondaAt(v, k);
        if (!esIsArray(hit)) { from = (hit.skip > k + 1) ? hit.skip : k + 1; continue; }
        out.push(v.substring(pos, hit[0]), ES_PLACEHOLDER);
        pos = hit[1];
        from = hit[1];
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

// ------------------------------------------------------------------ tokens, Bearer/Basic

function jsRdTokens(v) {
    // A run of [A-Za-z0-9_.+/=-] that starts with a token prefix (not after [A-Za-z0-9_-]) and
    // is long enough -> placeholder. Case-sensitive.
    var rules = ES_REDACT_RULES, re = rules.tokenRe, runRe = /[A-Za-z0-9_.+\/=\-]*/g;
    var out = [], pos = 0, m;
    re.lastIndex = 0;
    while ((m = re.exec(v)) !== null) {
        var k = m.index;
        var prev = v.charCodeAt(k - 1);
        re.lastIndex = k + 1;
        if (k > 0 && (jsRdAlnumCode(prev) || prev === 95 || prev === 45)) { continue; }
        var end = jsRdRunWith(runRe, v, k);
        if (!jsRdTokenFits(v, k, end - k)) { continue; }
        out.push(v.substring(pos, k), ES_PLACEHOLDER);
        pos = end;
        re.lastIndex = end;
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}

function jsRdTokenFits(v, k, length) {
    var list = ES_REDACT_RULES.prefixes;
    for (var i = 0; i < list.length; i++) {
        var p = list[i].prefix;
        if (length >= list[i].need && v.substring(k, k + p.length) === p) { return true; }
    }
    return false;
}

function jsRdCredCode(k) {
    // [A-Za-z0-9-._~+/]
    return jsRdAlnumCode(k) || k === 45 || k === 46 || k === 95 || k === 126 || k === 43 || k === 47;
}

function jsRdSchemeWordEnd(v, k, w) {
    // \b(bearer|basic)\s+<8+ credential characters>=* at k (word length w): the end, or -1.
    var n = v.length;
    if (k > 0 && jsRdWordCode(v.charCodeAt(k - 1))) { return -1; }
    var j = jsRdSkipWs(v, k + w);
    if (j === k + w) { return -1; }
    var s = j;
    while (j < n && jsRdCredCode(v.charCodeAt(j))) { j++; }
    if (j - s < 8) { return -1; }
    while (j < n && v.charCodeAt(j) === 61) { j++; }
    return j;
}

function jsRdBearer(v) {
    // "Bearer <8+ chars>" and "Basic <8+ chars>" (any case) -> "<word> <redacted>".
    var lower = v.toLowerCase();
    var out = [], pos = 0, from = 0, kb = -2, kc = -2;
    while (true) {
        if (kb !== -1 && kb < from) { kb = lower.indexOf("bearer", from); }
        if (kc !== -1 && kc < from) { kc = lower.indexOf("basic", from); }
        if (kb < 0 && kc < 0) { break; }
        var k = (kb >= 0 && (kc < 0 || kb < kc)) ? kb : kc;
        var w = (k === kb) ? 6 : 5;
        var end = jsRdSchemeWordEnd(v, k, w);
        if (end < 0) { from = k + 1; continue; }
        out.push(v.substring(pos, k + w), " ", ES_PLACEHOLDER);
        pos = end;
        from = end;
    }
    return out.length ? out.join("") + v.substring(pos) : v;
}
