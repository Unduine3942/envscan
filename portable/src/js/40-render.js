// ---------------------------------------------------------------------------
// 40-render: envscan.md (full report, one section per probe); port of 40-render.ps1.
// AGENT_BRIEF.md lives in 41-brief.js. The text is returned; writeEsTextFile writes it
// as ASCII ("?" for any other character).
//
// Differences from ps1, all in ordering or number spelling only:
// - data keys follow getEsOrderedKeys (code-unit order; ps1 sorts with the culture's comparer);
// - raw labels and other sorted names use jsMd_sortI (case-insensitive, "-" ignored first),
//   an approximation of Sort-Object's culture order;
// - numbers print with String() (ps1 [string] gives 15 significant digits for doubles).
// ---------------------------------------------------------------------------

var ES_MD_MAX_ITEMS = 300;
var ES_MD_MAX_INLINE = 30;
// Strings that render as-is (no markdown-active characters, one line, short).
var ES_MD_PLAIN_RE = /^[^<>*_|`\[\]#\\\r\n]{0,300}$/;
var JSMD_ACTIVE_RE = /[<>*_|`\[\]#\\]/;

// ------------------------------------------------------------------ PowerShell value semantics

function jsMd_str(value) {
    // [string]$Value as PowerShell concatenation does it: null -> "", True/False for booleans.
    if (value === null || value === undefined) { return ""; }
    if (typeof value === "boolean") { return value ? "True" : "False"; }
    if (esIsDate(value)) { return formatEsUtc(value); }
    if (esIsArray(value)) { return jsMd_strArray(value); }
    return String(value);
}

function jsMd_strArray(list) {
    // [string]@(a, b) joins with a space.
    var parts = [];
    for (var i = 0; i < list.length; i++) { parts.push(jsMd_str(list[i])); }
    return parts.join(" ");
}

function jsMd_isScalar(value) {
    // Test-EsJsonScalar: anything that is not a list or a table.
    return !esIsArray(value) && !esIsTable(value);
}

function jsMd_truthy(value) {
    // PowerShell truthiness: an empty list is false, a one-item list is its item, a table is true.
    if (esIsArray(value)) { return value.length > 1 || (value.length === 1 && jsMd_truthy(value[0])); }
    if (esIsTable(value)) { return true; }
    return !!value;
}

function jsMd_psArray(value) {
    // @($x): null -> [null] (one item), a list -> itself, anything else -> [value].
    if (esIsArray(value)) { return value; }
    return [value === undefined ? null : value];
}

function jsMd_where(value) {
    // @($x | Where-Object { $_ }): the truthy items.
    var out = [];
    if (value === null || value === undefined) { return out; }
    var list = esIsArray(value) ? value : [value];
    for (var i = 0; i < list.length; i++) { if (jsMd_truthy(list[i])) { out.push(list[i]); } }
    return out;
}

function jsMd_count(table) {
    // $hashtable.Count (every key, "__order" included).
    var n = 0;
    for (var k in table) { if (esHas(table, k)) { n++; } }
    return n;
}

function jsMd_compareI(a, b) {
    var x = String(a).toLowerCase();
    var y = String(b).toLowerCase();
    var xs = x.replace(/-/g, "");
    var ys = y.replace(/-/g, "");
    if (xs !== ys) { return xs < ys ? -1 : 1; }
    if (x !== y) { return x < y ? -1 : 1; }
    return 0;
}

function jsMd_sortI(list) {
    // Sort-Object on strings (a copy): case-insensitive.
    var copy = jsMd_psArray(list).slice(0);
    copy.sort(jsMd_compareI);
    return copy;
}

function jsMd_sortUniqueI(list) {
    // Sort-Object -Unique: sorted, duplicates (ignoring case) dropped.
    var sorted = jsMd_sortI(list);
    var out = [];
    for (var i = 0; i < sorted.length; i++) {
        if (out.length === 0 || String(out[out.length - 1]).toLowerCase() !== String(sorted[i]).toLowerCase()) { out.push(sorted[i]); }
    }
    return out;
}

function jsMd_keys(table) {
    // $table.PSBase.Keys of a plain object, sorted as Sort-Object does.
    var keys = [];
    if (!esIsTable(table)) { return keys; }
    for (var k in table) { if (esHas(table, k)) { keys.push(k); } }
    return jsMd_sortI(keys);
}

// ------------------------------------------------------------------ formatting

function formatEsMdText(text) {
    // One line; strings with markdown-active characters become code spans.
    var t = jsMd_str(text).replace(/[\r\n]+/g, " ");
    if (t.length > 300) { t = t.substr(0, 300) + "..."; }
    if (JSMD_ACTIVE_RE.test(t)) {
        if (t.indexOf("`") >= 0) { return "`` " + t + " ``"; }
        return "`" + t + "`";
    }
    return t;
}

function formatEsMdScalar(value) {
    if (typeof value === "string" && ES_MD_PLAIN_RE.test(value)) { return value; }
    if (value === null || value === undefined) { return "null"; }
    if (typeof value === "boolean") { return value ? "true" : "false"; }
    if (esIsDate(value)) { return formatEsUtc(value); }
    return formatEsMdText(jsMd_str(value));
}

function jsMd_selectFirst(list, count) {
    // Select-Object -First count: the first count items that are not null (it skips nulls).
    var out = [];
    for (var i = 0; i < list.length && out.length < count; i++) {
        if (list[i] !== null && list[i] !== undefined) { out.push(list[i]); }
    }
    return out;
}

function jsMd_scalarList(list, max) {
    var items = jsMd_selectFirst(list, max);
    var parts = [];
    for (var i = 0; i < items.length; i++) { parts.push(formatEsMdScalar(items[i])); }
    return parts.join(", ");
}

function testEsFlatTable(value) {
    if (!esIsTable(value)) { return false; }
    for (var k in value) {
        if (!esHas(value, k)) { continue; }
        var item = value[k];
        if (esIsTable(item)) { return false; }
        if (esIsArray(item)) { for (var i = 0; i < item.length; i++) { if (!jsMd_isScalar(item[i])) { return false; } } }
    }
    return true;
}

function formatEsMdInline(table) {
    var parts = [];
    var keys = getEsOrderedKeys(table);
    for (var i = 0; i < keys.length; i++) {
        var value = table[keys[i]];
        if (typeof value === "string" && ES_MD_PLAIN_RE.test(value)) { parts.push(keys[i] + ": " + value); continue; }
        if (value === null || value === undefined || (esIsArray(value) && value.length === 0)) { continue; }
        if (esIsArray(value)) { parts.push(keys[i] + ": " + jsMd_scalarList(value, ES_MD_MAX_INLINE)); }
        else { parts.push(keys[i] + ": " + formatEsMdScalar(value)); }
    }
    return parts.join("; ");
}

function jsMd_allScalar(list) {
    for (var i = 0; i < list.length; i++) { if (!jsMd_isScalar(list[i])) { return false; } }
    return true;
}

function jsMd_tableLines(value, indent, out) {
    var keys = getEsOrderedKeys(value);
    for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var item = value[key];
        if (jsMd_isScalar(item)) { out.push(indent + "- " + key + ": " + formatEsMdScalar(item)); continue; }
        if ((esIsArray(item) && item.length === 0) || (esIsTable(item) && jsMd_count(item) === 0)) { out.push(indent + "- " + key + ": (none)"); continue; }
        if (esIsArray(item) && jsMd_allScalar(item)) {
            var text = jsMd_scalarList(item, ES_MD_MAX_INLINE);
            if (item.length > ES_MD_MAX_INLINE) { text += " (+" + (item.length - ES_MD_MAX_INLINE) + " more)"; }
            out.push(indent + "- " + key + ": " + text);
            continue;
        }
        out.push(indent + "- " + key + ":");
        jsMd_dataLines(item, indent + "  ", out);
    }
}

function jsMd_arrayLines(list, indent, out) {
    var items = jsMd_selectFirst(list, ES_MD_MAX_ITEMS);
    for (var i = 0; i < items.length; i++) {
        var item = items[i];
        if (jsMd_isScalar(item)) { out.push(indent + "- " + formatEsMdScalar(item)); }
        else if (testEsFlatTable(item)) { out.push(indent + "- " + formatEsMdInline(item)); }
        else { out.push(indent + "-"); jsMd_dataLines(item, indent + "  ", out); }
    }
    if (list.length > ES_MD_MAX_ITEMS) { out.push(indent + "- ... " + (list.length - ES_MD_MAX_ITEMS) + " more (see envscan.json)"); }
}

function jsMd_dataLines(value, indent, out) {
    if (esIsTable(value)) { jsMd_tableLines(value, indent, out); return; }
    if (esIsArray(value)) { jsMd_arrayLines(value, indent, out); return; }
    out.push(indent + "- " + formatEsMdScalar(value));
}

function formatEsMdData(value, indent) {
    // Markdown list lines for probe data (an array of lines; ps1 writes them to the pipeline).
    var out = [];
    jsMd_dataLines(value, indent || "", out);
    return out;
}

function formatEsMdFence(label, text) {
    var fence = "```";
    var body = jsMd_str(text);
    if (body.indexOf("```") >= 0) { fence = "~~~~"; }
    return ["**" + label + "**", "", fence + "text", body.replace(/\r/g, ""), fence, ""];
}

function jsMd_probeHead(id, envelope) {
    var out = ["## " + id + " - " + jsMd_str(envelope.title), "",
        "status **" + jsMd_str(envelope.status) + "** - tier " + jsMd_str(envelope.tier) + " - scope " + jsMd_str(envelope.scope) + " - " + jsMd_str(envelope.duration_ms) + " ms", ""];
    if (jsMd_truthy(envelope.error)) { out.push("> error: " + formatEsMdText(envelope.error)); out.push(""); }
    var notes = jsMd_psArray(envelope.notes);
    for (var i = 0; i < notes.length; i++) { if (jsMd_truthy(notes[i])) { out.push("> note: " + formatEsMdText(notes[i])); } }
    if (notes.length > 0) { out.push(""); }
    var sources = jsMd_psArray(envelope.sources);
    if (sources.length > 0) {
        var texts = [];
        for (var s = 0; s < sources.length; s++) { texts.push(formatEsMdText(sources[s])); }
        out.push("Sources: " + texts.join(", "));
        out.push("");
    }
    return out;
}

function formatEsMdProbe(id, envelope) {
    var out = jsMd_probeHead(id, envelope);
    if (esIsTable(envelope.data) && jsMd_count(envelope.data) > 0) { out = out.concat(formatEsMdData(envelope.data, "")); out.push(""); }
    if (jsMd_truthy(envelope.raw)) {
        var labels = jsMd_keys(envelope.raw);
        for (var i = 0; i < labels.length; i++) { out = out.concat(formatEsMdFence("raw: " + labels[i], envelope.raw[labels[i]])); }
    }
    if (jsMd_truthy(envelope.truncated)) { out.push("_raw output truncated_"); out.push(""); }
    return out;
}

function jsMd_reportHead(report) {
    var run = report.run;
    var hostBlock = report.host;
    var scanner = report.scanner;
    var counts = [];
    for (var i = 0; i < ES_STATUSES.length; i++) {
        var n = run.counts ? run.counts[ES_STATUSES[i]] : null;
        if (n > 0) { counts.push(ES_STATUSES[i] + " " + n); }
    }
    return ["# envscan report: " + jsMd_str(hostBlock.hostname), "",
        "- OS: " + jsMd_str(hostBlock.os_name) + " " + jsMd_str(hostBlock.os_version) + " (" + jsMd_str(hostBlock.arch) + ")",
        "- Scanner: " + jsMd_str(scanner.name) + " " + jsMd_str(scanner.version) + " (" + jsMd_str(scanner.impl) + ", " + jsMd_str(scanner.shell_version) + ")",
        "- Started: " + jsMd_str(run.started_utc) + ", duration " + jsMd_str(run.duration_ms) + " ms, tiers: " + jsMd_psArray(run.tiers).join(", ") + ", exit code " + jsMd_str(run.exit_code),
        "- Redaction: " + (jsMd_truthy(run.redaction) ? "on" : "OFF (--no-redact)"),
        "- Probe status counts: " + counts.join(", "), "", "## Findings", ""];
}

function jsMd_findingLines(findings) {
    var list = jsMd_psArray(findings);
    var out = [];
    if (findings === null || findings === undefined || (esIsArray(findings) && findings.length === 0)) { return ["No findings."]; }
    for (var i = 0; i < list.length; i++) {
        var f = list[i];
        out.push("- **" + jsMd_str(f.severity).toUpperCase() + "** " + jsMd_str(f.title) + " (" + jsMd_str(f.id) + "): " + formatEsMdText(f.detail));
        out.push("  - Recommendation: " + jsMd_str(f.recommendation));
        out.push("  - Evidence: " + jsMd_psArray(f.evidence).join(", "));
    }
    return out;
}

function convertToEsMarkdownReport(report) {
    var lines = jsMd_reportHead(report).concat(jsMd_findingLines(report.findings));
    lines.push("");
    var probes = report.probes || {};
    var order = jsMd_psArray(probes.__order);
    for (var i = 0; i < order.length; i++) {
        var id = order[i];
        if (id !== null && esHas(probes, id)) { lines = lines.concat(formatEsMdProbe(id, probes[id])); }
    }
    return lines.join("\n");
}
