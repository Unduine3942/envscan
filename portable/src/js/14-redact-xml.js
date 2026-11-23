// ---------------------------------------------------------------------------
// 14-redact-xml: secret XML elements (spec/redaction.toml LINE RULES "xml" and TEXT RULES
// "multi-line"). A hand-written scanner instead of a regular expression: JScript has no
// lookbehind, and every cursor only moves forward (linear time on hostile lines).
//   start tag  "<" [prefix ":"] element (xml_elements, ASCII case-insensitive, no word character
//              after it) attributes ">". The prefix counts only when an element follows the ":"
//              (<token:password> is password with prefix token, <password:x> is password). The
//              tag ends at the first ">" outside "..." and '...'; self-closing (left alone) only
//              with "/" right before that ">".
//   content    ">" to the element's own closing tag "</[prefix:]element" later on the line, else
//              to the next "</", else a non-blank rest of the line (fail closed); closing tags
//              inside <!-- ... --> do not count, an unterminated "<!--" hides the rest of the line.
//   text mode  the first start tag with no "</" after it opens the multi-line state when the rest
//              is blank or the tag begins its line; a secret start tag without its ">" opens the
//              start-tag state (attributes over several lines); after the multi-line closing tag
//              the rest of the line goes through the line and text rules again.
// Lower-casing and blank tests are ASCII only: JScript maps U+0130 to "i".
// ---------------------------------------------------------------------------

function jsRdXmlNameStart(k) {
    // [A-Za-z_]
    return (k >= 65 && k <= 90) || (k >= 97 && k <= 122) || k === 95;
}

function jsRdXmlNameCode(k) {
    // [A-Za-z0-9_.-]
    return jsRdXmlNameStart(k) || (k >= 48 && k <= 57) || k === 46 || k === 45;
}

function jsRdXmlWordCode(k) {
    // A word character ([A-Za-z0-9_]), as in a regular expression \b.
    return jsRdXmlNameStart(k) || (k >= 48 && k <= 57);
}

function jsRdXmlBlankCode(k) { return k === 32 || (k >= 9 && k <= 13); }

function jsRdXmlSkipBlank(s, i) {
    var k = i;
    while (k < s.length && jsRdXmlBlankCode(s.charCodeAt(k))) { k++; }
    return k;
}

function jsRdXmlIsBlank(s) { return jsRdXmlSkipBlank(s, 0) === s.length; }

function jsRdXmlLower(text) {
    // ASCII-only lower case: the length and every non-ASCII character stay.
    return text.replace(/[A-Z]+/g, function (run) { return run.toLowerCase(); });
}

function jsRdXmlElementAt(lower, at) {
    // The length of the secret element name at at (lower-case line), or 0.
    var names = ES_REDACT_RULES.lines.xmlElements;
    for (var i = 0; i < names.length; i++) {
        var name = names[i];
        if (lower.substr(at, name.length) === name && !jsRdXmlWordCode(lower.charCodeAt(at + name.length))) {
            return name.length;
        }
    }
    return 0;
}

function jsRdXmlQName(lower, start) {
    // "[prefix:]element" at start: {end, name (lower case)} or null. The prefix holds no ":", so
    // the only prefix candidate is the name run up to the first ":".
    if (!jsRdXmlNameStart(lower.charCodeAt(start))) { return null; }
    var k = start + 1, size;
    while (jsRdXmlNameCode(lower.charCodeAt(k))) { k++; }
    if (lower.charCodeAt(k) === 58) {
        size = jsRdXmlElementAt(lower, k + 1);
        if (size > 0) { return { end: k + 1 + size, name: lower.substring(start, k + 1 + size) }; }
    }
    size = jsRdXmlElementAt(lower, start);
    return size > 0 ? { end: start + size, name: lower.substring(start, start + size) } : null;
}

function jsRdXmlTagEnd(line, from, quote) {
    // The ">" that ends a start tag: the first one outside "..." and '...' from `from`, with
    // `quote` (a char code, 0 for none) still open. {gt (or -1), quote open at the line end}.
    var n = line.length, q = quote;
    for (var k = from; k < n; k++) {
        var ch = line.charCodeAt(k);
        if (q) { if (ch === q) { q = 0; } }
        else if (ch === 62) { return { gt: k, quote: 0 }; }
        else if (ch === 34 || ch === 39) { q = ch; }
    }
    return { gt: -1, quote: q };
}

// ------------------------------------------------------------------ closing tags of one line

function jsRdXmlCursor(line) {
    // Lazily built lists of the closing tags outside comments; pointers only move forward.
    return { line: line, lower: jsRdXmlLower(line), closes: null, byName: null, next: 0, at: {} };
}

function jsRdXmlCloseList(line) {
    // Every "</" outside <!-- ... -->, in order; an unterminated "<!--" hides the rest.
    var list = [], from = 0, cs = line.indexOf("<!--"), at;
    while ((at = line.indexOf("</", from)) >= 0) {
        if (cs >= 0 && cs < at) {
            var ce = line.indexOf("-->", cs + 4);
            if (ce < 0) { break; }
            from = ce + 3;
            cs = line.indexOf("<!--", from);
            continue;
        }
        list.push(at);
        from = at + 2;
    }
    return list;
}

function jsRdXmlIndexCloses(c) {
    // c.closes and c.byName ("k" + qualified element name -> its closing tag positions).
    c.closes = jsRdXmlCloseList(c.line);
    c.byName = {};
    for (var i = 0; i < c.closes.length; i++) {
        var q = jsRdXmlQName(c.lower, c.closes[i] + 2);
        if (!q) { continue; }
        var key = "k" + q.name;
        if (!esHas(c.byName, key)) { c.byName[key] = []; }
        c.byName[key].push(c.closes[i]);
    }
}

function jsRdXmlNextClose(c, from) {
    // The next "</" outside comments at or after from, or -1 (from never decreases).
    if (!c.closes) { jsRdXmlIndexCloses(c); }
    while (c.next < c.closes.length && c.closes[c.next] < from) { c.next++; }
    return c.next < c.closes.length ? c.closes[c.next] : -1;
}

function jsRdXmlOwnClose(c, name, from) {
    // The next "</name" (lower-case qualified name) outside comments at or after from, or -1.
    if (!c.closes) { jsRdXmlIndexCloses(c); }
    var key = "k" + name;
    if (!esHas(c.byName, key)) { return -1; }
    var list = c.byName[key], i = esHas(c.at, key) ? c.at[key] : 0;
    while (i < list.length && list[i] < from) { i++; }
    c.at[key] = i;
    return i < list.length ? list[i] : -1;
}

function jsRdXmlContentEnd(c, from, name) {
    // Where the content after a start tag ends: its own closing tag, else the next "</".
    var own = jsRdXmlOwnClose(c, name, from);
    return own >= 0 ? own : jsRdXmlNextClose(c, from);
}

// ------------------------------------------------------------------ one line

function jsRdXmlScan(line) {
    // {text, open, tag}: the line with secret element contents replaced; open = {until (lower
    // "[prefix:]element"), enter} for the first start tag with no "</" after it (enter: the rest
    // is blank or the tag begins its line); tag = {until, quote} for a secret start tag without
    // its ">" on the line (left alone, scanning stops there).
    var c = jsRdXmlCursor(line), out = [], pos = 0, lt = line.indexOf("<");
    while (lt >= 0) {
        var q = jsRdXmlQName(c.lower, lt + 1);
        if (!q) { lt = line.indexOf("<", lt + 1); continue; }
        var end = jsRdXmlTagEnd(line, q.end, 0);
        if (end.gt < 0) { return jsRdXmlResult(out, line, pos, null, { until: q.name, quote: end.quote }); }
        var gt = end.gt;
        if (gt > q.end && line.charCodeAt(gt - 1) === 47) { lt = line.indexOf("<", gt + 1); continue; }
        var close = jsRdXmlContentEnd(c, gt + 1, q.name);
        out.push(line.substring(pos, gt + 1));
        if (close >= 0) {
            out.push(ES_PLACEHOLDER);
            pos = close;
            lt = line.indexOf("<", close + 1);
            continue;
        }
        pos = gt + 1;
        var blankRest = jsRdXmlIsBlank(line.substring(gt + 1));
        if (!blankRest) { out.push(ES_PLACEHOLDER); pos = line.length; }
        var open = { until: q.name, enter: blankRest || jsRdXmlSkipBlank(line, 0) === lt };
        return jsRdXmlResult(out, line, pos, open, null);
    }
    return jsRdXmlResult(out, line, pos, null, null);
}

function jsRdXmlResult(out, line, pos, open, tag) {
    return { text: out.join("") + line.substring(pos), open: open, tag: tag };
}

// ------------------------------------------------------------------ whole texts (protectEsText)

function startEsXmlState(line, state) {
    // After the line rules of a text line: a secret element left open enters the multi-line
    // state, a start tag without its ">" the start-tag state.
    var scan = jsRdXmlScan(line);
    if (scan.open && scan.open.enter) { state.until = scan.open.until; state.xml = true; }
    else if (scan.tag) { state.tag = scan.tag; }
}

function jsRdXmlIndent(line) {
    return line.substring(0, jsRdXmlSkipBlank(line, 0));
}

function protectEsXmlUntilLine(line, state) {
    // A line inside a secret element: replaced up to its closing tag (outside comments); the rest
    // of the closing line goes through the line and text rules again.
    var at = jsRdXmlOwnClose(jsRdXmlCursor(line), state.until, 0);
    if (at < 0) { return jsRdXmlIsBlank(line) ? line : jsRdXmlIndent(line) + ES_PLACEHOLDER; }
    state.until = null;
    state.xml = false;
    var before = line.substring(0, at);
    if (!jsRdXmlIsBlank(before)) { before = jsRdXmlIndent(line) + ES_PLACEHOLDER; }
    return before + protectEsTextLine(line.substring(at), state);
}

function protectEsXmlTagLine(line, state) {
    // A line after a secret start tag without its ">": null when the state ends without effect
    // (the line starts with "<" outside a quote: the caller handles the line as usual), the line
    // rules while the ">" is missing, else the line rules up to the ">" and the content after it.
    var tag = state.tag;
    if (!tag.quote && line.charCodeAt(jsRdXmlSkipBlank(line, 0)) === 60) { state.tag = null; return null; }
    var end = jsRdXmlTagEnd(line, 0, tag.quote);
    if (end.gt < 0) {
        state.tag = { until: tag.until, quote: end.quote };
        return protectEsLine(line);
    }
    state.tag = null;
    var head = protectEsLine(line.substring(0, end.gt + 1));
    return head + jsRdXmlAfterTag(line, end.gt + 1, tag.until, state);
}

function jsRdXmlAfterTag(line, from, until, state) {
    // The content after the ">" of a start tag that begins its line: to its own closing tag or the
    // next "</" (the rest of the line then goes through the line and text rules again), else the
    // rest is replaced and the multi-line state begins.
    var close = jsRdXmlContentEnd(jsRdXmlCursor(line), from, until);
    if (close >= 0) { return ES_PLACEHOLDER + protectEsTextLine(line.substring(close), state); }
    state.until = until;
    state.xml = true;
    var rest = line.substring(from);
    return jsRdXmlIsBlank(rest) ? rest : ES_PLACEHOLDER;
}
