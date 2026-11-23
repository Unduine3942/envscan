// ---------------------------------------------------------------------------
// 10-core: state, small utilities, time, environment, logging, JSON writer.
// Port of src/ps/10-core.ps1. JScript 5.8 (ES3): see the contract in docs and tools/target_js.py.
// ---------------------------------------------------------------------------

var ES_STATUSES = ["ok", "partial", "not_found", "not_applicable", "denied", "timeout", "error", "skipped"];
var ES_RAW_CAP = 65536;
var ES_OPT = {
    deep: false, net: false, out: null, only: [], skip: [],
    timeout: 15, budget: 600, redact: true, list: false, version: false, help: false
};
var ES_RESULTS = {};
var ES_LOG = [];
var ES_TMP = null;
var ES_EMPTY_IN = null;
var ES_CHILD_CWD = null;
var ES_CMD_SEQ = 0;
var ES_BUDGET_SKIPS = 0;
var ES_NETWORK_DRIVES = [];
var ES_NETWORK_DRIVE_TARGETS = {};
// The process environment before the scanner changed anything (Save-EsEnvSnapshot):
// ES_ENV_SNAPSHOT maps each variable name, as Windows spells it, to its value;
// ES_ENV_SNAPSHOT_NAMES maps the lower-case name to that spelling (names are case-insensitive:
// look up ES_ENV_SNAPSHOT[ES_ENV_SNAPSHOT_NAMES[name.toLowerCase()]]).
var ES_ENV_SNAPSHOT = {};
var ES_ENV_SNAPSHOT_NAMES = {};
var ES_CHILD_ENV_SAVED = [];
var ES_STARTED = new Date();
var ES_PLACEHOLDER = "<redacted>";
var ES_ARGS = [];
var ES_SCRIPT_PATH = null;
try { ES_SCRIPT_PATH = String(WScript.ScriptFullName); } catch (e) { ES_SCRIPT_PATH = null; }
// ps1 compatibility values: WSH has no PowerShell language mode.
var ES_LANGUAGE_MODE = "WSH";
var ES_FULL_LANGUAGE = true;
var ES_PROCESS_ENV = ES_SHELL.Environment("PROCESS");
var ES_START_CWD = String(ES_SHELL.CurrentDirectory);

// ------------------------------------------------------------------ utilities (JScript only)

function esIsArray(value) { return Object.prototype.toString.call(value) === "[object Array]"; }
function esIsDate(value) { return Object.prototype.toString.call(value) === "[object Date]"; }
function esIsTable(value) {
    // A plain data object (ps hashtable): not null, an array, a Date or a COM object.
    return value !== null && typeof value === "object" && !esIsArray(value) && !esIsDate(value)
        && Object.prototype.toString.call(value) === "[object Object]";
}

function esHas(obj, key) {
    // Own-key test that a data key named "hasOwnProperty" cannot shadow (never call
    // obj.hasOwnProperty directly: env variables, registry values and config keys are data).
    if (obj === null || obj === undefined) { return false; }
    return Object.prototype.hasOwnProperty.call(obj, key);
}

function esIndexOf(array, value) {
    if (!array) { return -1; }
    for (var i = 0; i < array.length; i++) { if (array[i] === value) { return i; } }
    return -1;
}

function esContains(array, value) { return esIndexOf(array, value) >= 0; }

function esContainsI(array, value) {
    // Case-insensitive -contains for strings (PowerShell semantics).
    if (!array || value === null || value === undefined) { return false; }
    var lower = String(value).toLowerCase();
    for (var i = 0; i < array.length; i++) {
        if (array[i] !== null && array[i] !== undefined && String(array[i]).toLowerCase() === lower) { return true; }
    }
    return false;
}

function esKeys(obj) {
    // Own keys, sorted by code unit ("__order" included when present).
    var keys = [];
    if (obj === null || typeof obj !== "object") { return keys; }
    for (var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) { keys.push(k); } }
    keys.sort();
    return keys;
}

function esTrim(s) {
    if (s === null || s === undefined) { return ""; }
    return String(s).replace(/^[\s\xa0\uFEFF]+/, "").replace(/[\s\xa0\uFEFF]+$/, "");
}

function esStartsWith(s, prefix) {
    if (s === null || s === undefined) { return false; }
    return String(s).substr(0, prefix.length) === prefix;
}

function esEndsWithI(s, suffix) {
    if (s === null || s === undefined) { return false; }
    var text = String(s).toLowerCase();
    var end = String(suffix).toLowerCase();
    return text.length >= end.length && text.substr(text.length - end.length) === end;
}

function esLower(s) {
    if (s === null || s === undefined) { return ""; }
    return String(s).toLowerCase();
}

function esRepeat(text, count) {
    var out = "";
    for (var i = 0; i < count; i++) { out += text; }
    return out;
}

function esPadLeft(text, width, ch) {
    var s = String(text);
    return s.length >= width ? s : esRepeat(ch || " ", width - s.length) + s;
}

function esPadRight(text, width, ch) {
    var s = String(text);
    return s.length >= width ? s : s + esRepeat(ch || " ", width - s.length);
}

function esPad2(n) { return esPadLeft(String(n), 2, "0"); }
function esPad4(n) { return esPadLeft(String(n), 4, "0"); }

function esJoinPath(a, b) {
    // Join-Path: one backslash between the parts.
    var left = String(a);
    var right = String(b).replace(/^[\\\/]+/, "");
    if (left === "") { return right; }
    if (left.charAt(left.length - 1) === "\\" || left.charAt(left.length - 1) === "/") { return left + right; }
    return left + "\\" + right;
}

// The path checks below look only at the path given: callers vet it first (testEsLocalPath,
// testEsCredentialPath, getEsPathLinkReason), as the ps1 does before Test-Path.
function esIsFile(p) {
    try { return !!p && ES_FSO.FileExists(String(p)); } catch (e) { return false; }
}

function esIsDir(p) {
    try { return !!p && ES_FSO.FolderExists(String(p)); } catch (e) { return false; }
}

function esPathExists(p) { return esIsFile(p) || esIsDir(p); }

function esErrorText(e) {
    // The message of a caught JScript or COM error.
    if (e === null || e === undefined) { return "unknown error"; }
    if (typeof e === "object") {
        var text = e.message || e.description || "";
        if (!text && typeof e.number === "number") { text = "error 0x" + ((e.number < 0 ? e.number + 4294967296 : e.number).toString(16)); }
        return String(text || "unknown error");
    }
    return String(e);
}

// ------------------------------------------------------------------ time

function getEsUtc() { return new Date(); }

function formatEsUtc(value) {
    // ISO 8601 UTC from the numeric fields (no locale formatting).
    if (value === null || value === undefined) { return null; }
    return esPad4(value.getUTCFullYear()) + "-" + esPad2(value.getUTCMonth() + 1) + "-" + esPad2(value.getUTCDate())
        + "T" + esPad2(value.getUTCHours()) + ":" + esPad2(value.getUTCMinutes()) + ":" + esPad2(value.getUTCSeconds()) + "Z";
}

function formatEsStamp(value) {
    // Compact UTC stamp for folder names: 20261110T164048Z.
    return esPad4(value.getUTCFullYear()) + esPad2(value.getUTCMonth() + 1) + esPad2(value.getUTCDate())
        + "T" + esPad2(value.getUTCHours()) + esPad2(value.getUTCMinutes()) + esPad2(value.getUTCSeconds()) + "Z";
}

function getEsElapsedMs(start) {
    var ms = new Date().getTime() - start.getTime();
    return ms < 0 ? 0 : ms;
}

function convertFromEsCimDate(value) {
    // A DMTF datetime (20261030023208.500000+540, local time and offset in minutes) as a Date.
    if (value === null || value === undefined) { return null; }
    if (esIsDate(value)) { return value; }
    // The fraction is kept to the millisecond (the process-tree stop compares creation times).
    var m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d+)([+-]\d+)$/.exec(String(value));
    if (!m) { return null; }
    var ms = parseInt((m[7] + "000").substr(0, 3), 10);
    var local = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms);
    if (isNaN(local)) { return null; }
    return new Date(local - parseInt(m[8], 10) * 60000);
}

// ------------------------------------------------------------------ environment

function getEsEnv(name) {
    // The current process value (case-insensitive name), or null when unset.
    if (!name) { return null; }
    var value = "";
    try { value = String(ES_PROCESS_ENV.Item(String(name))); } catch (e) { return null; }
    return value === "" ? null : value;
}

function setEsEnvValue(name, value) {
    // JScript only: sets (or with null/"" removes) a variable of this process and its children.
    try {
        if (value === null || value === undefined || value === "") { ES_PROCESS_ENV.Remove(String(name)); }
        else { ES_PROCESS_ENV.Item(String(name)) = String(value); }
    } catch (e) { /* removing an unset variable fails: nothing to do */ }
}

function saveEsEnvSnapshot() {
    var snapshot = {};
    var names = {};
    var items = new Enumerator(ES_PROCESS_ENV);
    for (; !items.atEnd(); items.moveNext()) {
        var entry = String(items.item());
        var eq = entry.indexOf("=", 1);
        if (eq <= 0) { continue; }
        var name = entry.substr(0, eq);
        snapshot[name] = entry.substr(eq + 1);
        names[name.toLowerCase()] = name;
    }
    ES_ENV_SNAPSHOT = snapshot;
    ES_ENV_SNAPSHOT_NAMES = names;
}

// ------------------------------------------------------------------ logging

function writeEsLog(message) {
    // Log lines carry commands, paths and error messages: redacted like command lines.
    var text = String(message);
    if (typeof ES_REDACT_READY !== "undefined" && ES_REDACT_READY && ES_OPT.redact) {
        try { text = protectEsCommandLine(text); } catch (e) { text = "[log line not redacted: dropped]"; }
    }
    ES_LOG.push(formatEsUtc(getEsUtc()) + " " + text);
}

function writeEsProgress(message) {
    // Never stdout: it carries only the output folder path.
    try { WScript.StdErr.WriteLine(esAsciiText(String(message))); } catch (e) { /* no stderr */ }
}

function writeEsFatal(lines) {
    var list = esIsArray(lines) ? lines : [lines];
    for (var i = 0; i < list.length; i++) { writeEsProgress(list[i]); }
}

function esAsciiText(text) {
    // Every character outside printable ASCII, tab, CR and LF becomes "?".
    return String(text).replace(/[^\t\n\r\x20-\x7e]/g, "?");
}

function writeEsTextFile(path, text) {
    // ASCII ("?" for any other character) with CRLF line ends and a final CRLF, like
    // Set-Content. The file must not exist yet (the output folder is new): never overwrites.
    var body = esAsciiText(String(text).replace(/\r\n/g, "\n")).replace(/\n/g, "\r\n") + "\r\n";
    var stream = ES_FSO.CreateTextFile(String(path), false, false);
    try { stream.Write(body); } finally { stream.Close(); }
}

// ------------------------------------------------------------------ JSON writer

var ES_JSON_PLAIN_RE = /^[ !#-\[\]-~]*$/;

function convertToEsJsonString(text) {
    if (text === null || text === undefined) { return "null"; }
    var s = String(text);
    if (ES_JSON_PLAIN_RE.test(s)) { return "\"" + s + "\""; }
    var parts = [];
    for (var i = 0; i < s.length; i++) {
        var code = s.charCodeAt(i);
        if (code === 34) { parts.push("\\\""); }
        else if (code === 92) { parts.push("\\\\"); }
        else if (code >= 32 && code <= 126) { parts.push(s.charAt(i)); }
        else if (code === 10) { parts.push("\\n"); }
        else if (code === 13) { parts.push("\\r"); }
        else if (code === 9) { parts.push("\\t"); }
        else { parts.push("\\u" + esPadLeft(code.toString(16), 4, "0")); }
    }
    return "\"" + parts.join("") + "\"";
}

function convertToEsJsonScalar(value) {
    if (value === null || value === undefined) { return "null"; }
    if (typeof value === "string") { return convertToEsJsonString(value); }
    if (typeof value === "boolean") { return value ? "true" : "false"; }
    if (esIsDate(value)) { return convertToEsJsonString(formatEsUtc(value)); }
    if (typeof value === "number") { return (isNaN(value) || !isFinite(value)) ? "null" : String(value); }
    return convertToEsJsonString(String(value));
}

function esIsContainer(value) { return esIsArray(value) || esIsTable(value); }

function getEsOrderedKeys(table) {
    // Keys listed in __order first, then the rest sorted by code unit.
    var order = [];
    var seen = {};
    var listed = esIsArray(table.__order) ? table.__order : [];
    for (var i = 0; i < listed.length; i++) {
        var key = String(listed[i]);
        if (key !== "__order" && Object.prototype.hasOwnProperty.call(table, key) && !seen["k" + key]) {
            order.push(key);
            seen["k" + key] = true;
        }
    }
    var all = esKeys(table);
    for (var j = 0; j < all.length; j++) {
        if (all[j] !== "__order" && !seen["k" + all[j]]) { order.push(all[j]); }
    }
    return order;
}

function esJsonTableParts(value, level, out) {
    var keys = getEsOrderedKeys(value);
    if (keys.length === 0) { out.push("{}"); return; }
    var pad = esRepeat("  ", level + 1);
    out.push("{\n");
    for (var i = 0; i < keys.length; i++) {
        var item = value[keys[i]];
        out.push(pad + convertToEsJsonString(keys[i]) + ": ");
        if (esIsContainer(item)) { esJsonParts(item, level + 1, out); }
        else { out.push(convertToEsJsonScalar(item)); }
        out.push(i < keys.length - 1 ? ",\n" : "\n");
    }
    out.push(esRepeat("  ", level) + "}");
}

function esJsonInlineArray(items) {
    // The one-line form of a short array of scalars, or null.
    if (items.length > 12) { return null; }
    var parts = [];
    for (var i = 0; i < items.length; i++) {
        if (esIsContainer(items[i])) { return null; }
        parts.push(convertToEsJsonScalar(items[i]));
    }
    var inline = "[" + parts.join(", ") + "]";
    return inline.length <= 100 ? inline : null;
}

function esJsonArrayParts(items, level, out) {
    if (items.length === 0) { out.push("[]"); return; }
    var inline = esJsonInlineArray(items);
    if (inline !== null) { out.push(inline); return; }
    var pad = esRepeat("  ", level + 1);
    out.push("[\n");
    for (var i = 0; i < items.length; i++) {
        out.push(pad);
        if (esIsContainer(items[i])) { esJsonParts(items[i], level + 1, out); }
        else { out.push(convertToEsJsonScalar(items[i])); }
        out.push(i < items.length - 1 ? ",\n" : "\n");
    }
    out.push(esRepeat("  ", level) + "]");
}

function esJsonParts(value, level, out) {
    if (esIsTable(value)) { esJsonTableParts(value, level, out); return; }
    if (esIsArray(value)) { esJsonArrayParts(value, level, out); return; }
    out.push(convertToEsJsonScalar(value));
}

function convertToEsJson(value) {
    var out = [];
    esJsonParts(value, 0, out);
    return out.join("");
}
