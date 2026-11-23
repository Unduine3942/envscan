// ---------------------------------------------------------------------------
// 11b-wmi: the WMI worker (CIM queries and the process-tree stop) and the CIM cache.
// Port of Get-EsCim / Get-EsCimSafe of src/ps/11-exec.ps1.
//
// Every WMI query runs in a separate cscript process with a //T limit, so a hung WMI provider
// cannot hang the scan:
//   cscript //nologo //E:jscript //T:<sec> envscan.js --es-wmi-worker <tmp>\wN.req <tmp>\wN.res
// Both files are UTF-16 (FSO Unicode mode), line based, created exclusively in the scanner's
// own temp folder; the worker accepts no other paths (testEsWorkerPaths). Request lines:
//   query / <namespace> / <WQL> / <comma-separated props>   |   tree-stop / <pid>   |   reg-check
// Reply lines (values escaped: \\ \t \n \r):
//   S<TAB>ok  or  S<TAB>error<TAB><message>       status, always the last line
//   I                                             a new item
//   P<TAB><prop><TAB><type><TAB><value>            type z null, s string, n number, b 0/1
//   P<TAB><prop><TAB>a<TAB><count> + count lines E<TAB><type><TAB><value>   an array
//   P<TAB><prop>.<sub><TAB>x<TAB>                 the embedded object <prop> is null
//   O<TAB><prop>.<sub><TAB><count> + count E lines  <sub> of each object of an embedded array
// Values arrive as WMI scripting gives them: 64-bit integers as decimal strings, datetimes as
// DMTF strings (convertFromEsCimDate). Embedded objects: request "Prop.Sub" props (one level);
// the item then holds Prop as a plain object {Sub: ...} (or an array of them, or null). A bare
// embedded object prop arrives as null.
// A worker never starts another worker (ES_WORKER_MARK in its environment): a library snippet
// that is started as a worker must hand over to invokeEsWmiWorker first (esInitForTests).
// ---------------------------------------------------------------------------

var ES_WORKER_SEQ = 0;
var ES_WORKER_SCRIPT = null;
var ES_WORKER_OPTION = "--es-wmi-worker";
var ES_WORKER_MARK = "__ES_WMI_WORKER";
var ES_CIM_CACHE = {};
var ES_WMI_NAME_RE = /^[A-Za-z0-9_]+$/;
var ES_WMI_PROP_RE = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)?$/;
var ES_WMI_NAMESPACE_RE = /^[A-Za-z0-9_]+([\\\/][A-Za-z0-9_]+)*$/;

// ------------------------------------------------------------------ text files and escaping

function esWriteUnicodeFile(path, text) {
    // UTF-16 text in a new file (fails when the file exists).
    var stream = ES_FSO.CreateTextFile(path, false, true);
    try { stream.Write(text); } finally { stream.Close(); }
}

function esReadUnicodeFile(path) {
    var stream = ES_FSO.OpenTextFile(path, 1, false, -1);
    try { return stream.AtEndOfStream ? "" : stream.ReadAll(); } finally { stream.Close(); }
}

function esWorkerEscape(text) {
    return String(text).replace(/\\/g, "\\\\").replace(/\t/g, "\\t").replace(/\n/g, "\\n").replace(/\r/g, "\\r");
}

function esWorkerUnescape(text) {
    return String(text).replace(/\\(.)/g, function (all, ch) {
        if (ch === "t") { return "\t"; }
        if (ch === "n") { return "\n"; }
        if (ch === "r") { return "\r"; }
        return ch;
    });
}

function esComErrorText(e) {
    // A COM error with its HRESULT, so getEsErrorStatus can classify WMI codes.
    var text = esErrorText(e);
    if (e && typeof e.number === "number" && e.number !== 0) {
        var code = (e.number < 0 ? e.number + 4294967296 : e.number).toString(16);
        text = esTrim(text) + " (0x" + esPadLeft(code, 8, "0") + ")";
    }
    return esTrim(text);
}

// ------------------------------------------------------------------ client side

function getEsWorkerHost() {
    // The running cscript.exe (same bitness; its path comes from the process, not the
    // environment) when it lies in a trusted local folder, else the System32 one; throws when
    // neither is trusted.
    var host = "";
    try { host = String(WScript.FullName); } catch (e) { host = ""; }
    if (/\\cscript\.exe$/i.test(host) && testEsSystemFolder(host.substr(0, host.lastIndexOf("\\")))) { return host; }
    var system = getEsSystemTool("cscript.exe");
    if (!system) { throw new Error("WMI worker: the Windows folder is not a trusted local path"); }
    return system;
}

function esWorkerCommand(request, reply, timeoutSec) {
    var script = ES_WORKER_SCRIPT || ES_SCRIPT_PATH;
    return "\"" + getEsWorkerHost() + "\" //nologo //E:jscript //T:" + timeoutSec + " \"" + script + "\" "
        + ES_WORKER_OPTION + " \"" + request + "\" \"" + reply + "\"";
}

function esStartWorker(request, reply, limit) {
    // The worker process, with ES_WORKER_MARK set for it only.
    var previous = getEsEnv(ES_WORKER_MARK);
    setEsEnvValue(ES_WORKER_MARK, "1");
    try {
        return withEsChildExtras([ES_WORKER_MARK], function () {
            return esStartChild(esWorkerCommand(request, reply, limit), ES_CHILD_CWD);
        });
    }
    finally { setEsEnvValue(ES_WORKER_MARK, previous); }
}

function invokeEsWorker(lines, timeoutSec, label) {
    // One worker run: {status: 'ok'|'error', error, items}. Throws when the worker gave no
    // reply ("WMI query timed out: ..." after the time limit).
    if (getEsEnv(ES_WORKER_MARK)) { throw new Error("WMI worker: a worker never starts another worker"); }
    if (!ES_TMP) { throw new Error("WMI worker: no temporary folder"); }
    var limit = timeoutSec > 0 ? timeoutSec : ES_OPT.timeout;
    ES_WORKER_SEQ++;
    var request = esJoinPath(ES_TMP, "w" + ES_WORKER_SEQ + ".req");
    var reply = esJoinPath(ES_TMP, "w" + ES_WORKER_SEQ + ".res");
    var start = getEsUtc();
    try {
        esWriteUnicodeFile(request, lines.join("\n"));
        var child = esStartWorker(request, reply, limit);
        if (!esWaitChild(child, (limit + 5) * 1000)) {
            try { child.Terminate(); } catch (e) { /* gone */ }
        }
        if (!ES_FSO.FileExists(reply)) {
            if (getEsElapsedMs(start) >= limit * 1000) { throw new Error("WMI query timed out: " + (label || lines[0])); }
            throw new Error("WMI worker failed (exit code " + child.ExitCode + ")");
        }
        return esParseWorkerReply(esReadUnicodeFile(reply));
    } finally {
        esDeleteFile(request);
        esDeleteFile(reply);
    }
}

function esParseWorkerValue(type, text) {
    if (type === "s") { return esWorkerUnescape(text); }
    if (type === "n") { return Number(text); }
    if (type === "b") { return text === "1"; }
    return null;
}

function esReadWorkerList(lines, at, count) {
    // count E lines after index at: [values, index of the last line read].
    var values = [];
    var i = at;
    for (var k = 0; k < count && i + 1 < lines.length; k++) {
        var e = lines[++i].split("\t");
        values.push(esParseWorkerValue(e[1], e.slice(2).join("\t")));
    }
    return [values, i];
}

function esSetWorkerProp(item, name, type, value) {
    // A reply value into the item; "Prop.Sub" fills the plain object item.Prop.
    var dot = name.indexOf(".");
    if (dot < 0) { item[name] = value; return; }
    var parent = name.substr(0, dot);
    if (type === "x") { if (!Object.prototype.hasOwnProperty.call(item, parent)) { item[parent] = null; } return; }
    if (!esIsTable(item[parent])) { item[parent] = {}; }
    item[parent][name.substr(dot + 1)] = value;
}

function esSetWorkerObjects(item, name, values) {
    // "Prop.Sub" of an embedded array: item.Prop[k].Sub = values[k].
    var dot = name.indexOf(".");
    var parent = name.substr(0, dot);
    var list = esIsArray(item[parent]) ? item[parent] : [];
    for (var k = 0; k < values.length; k++) {
        if (!esIsTable(list[k])) { list[k] = {}; }
        list[k][name.substr(dot + 1)] = values[k];
    }
    item[parent] = list;
}

function esParseWorkerReply(text) {
    var reply = { status: "error", error: "WMI worker: incomplete reply", items: [] };
    var lines = String(text).split("\n");
    var item = null;
    for (var i = 0; i < lines.length; i++) {
        var f = lines[i].split("\t");
        if (f[0] === "I") { item = {}; reply.items.push(item); }
        else if ((f[0] === "P" && f[2] === "a" || f[0] === "O") && item) {
            var read = esReadWorkerList(lines, i, parseInt(f[0] === "O" ? f[2] : f[3], 10) || 0);
            i = read[1];
            if (f[0] === "O") { esSetWorkerObjects(item, f[1], read[0]); } else { esSetWorkerProp(item, f[1], "a", read[0]); }
        }
        else if (f[0] === "P" && item) { esSetWorkerProp(item, f[1], f[2], esParseWorkerValue(f[2], f.slice(3).join("\t"))); }
        else if (f[0] === "S") {
            reply.status = f[1] === "ok" ? "ok" : "error";
            reply.error = f[1] === "ok" ? null : esWorkerUnescape(f.slice(2).join("\t"));
        }
    }
    return reply;
}

// ------------------------------------------------------------------ CIM

function esBuildWql(className, filter, props) {
    // SELECT of the top-level props ("Prop.Sub" selects Prop).
    if (!ES_WMI_NAME_RE.test(String(className))) { throw new Error("invalid class name: " + className); }
    var list = props || [];
    if (list.length === 0) { throw new Error(className + ": no props requested"); }
    var top = [];
    for (var i = 0; i < list.length; i++) {
        if (!ES_WMI_PROP_RE.test(String(list[i]))) { throw new Error(className + ": invalid prop name " + list[i]); }
        var name = String(list[i]).split(".")[0];
        if (!esContainsI(top, name)) { top.push(name); }
    }
    if (filter && /[\r\n]/.test(filter)) { throw new Error(className + ": invalid filter"); }
    return "SELECT " + top.join(",") + " FROM " + className + (filter ? " WHERE " + filter : "");
}

function getEsCim(className, namespace, filter, props, timeoutSec) {
    // Plain objects with the requested props (same spelling as requested); throws on failure.
    var ns = namespace || "root/cimv2";
    if (!ES_WMI_NAMESPACE_RE.test(ns)) { throw new Error("invalid namespace: " + ns); }
    var wql = esBuildWql(className, filter, props);
    var reply = invokeEsWorker(["query", ns, wql, props.join(",")], timeoutSec, className);
    if (reply.status !== "ok") { throw new Error(reply.error); }
    return reply.items;
}

function getEsCimSafe(className, namespace, filter, props, timeoutSec) {
    // Like getEsCim but returns {items, status, error}. Shared through the cache: callers must
    // not change the result.
    var ns = namespace || "root/cimv2";
    var key = ns + ":" + className + "|" + (filter || "") + "|" + (props || []).join(",");
    if (Object.prototype.hasOwnProperty.call(ES_CIM_CACHE, key)) { return ES_CIM_CACHE[key]; }
    var result;
    try {
        result = { items: getEsCim(className, ns, filter || "", props || [], timeoutSec), status: "ok", error: null };
    } catch (e) {
        var message = esErrorText(e);
        result = { items: [], status: getEsErrorStatus(message), error: className + ": " + message };
    }
    ES_CIM_CACHE[key] = result;
    return result;
}

// ------------------------------------------------------------------ worker side

function testEsWorkerPaths(request, reply) {
    // Both files directly inside one scanner temp folder (envscan-<n>-<n> under TEMP or the
    // profile), the request present and the reply not yet: nothing else is ever read or written.
    var req = String(request || "");
    var res = String(reply || "");
    var m = /^([A-Za-z]:\\.+)\\(w\d{1,9})\.req$/.exec(req);
    if (!m || res.toLowerCase() !== (m[1] + "\\" + m[2] + ".res").toLowerCase()) { return false; }
    if (/(^|\\)\.\.?(\\|$)/.test(m[1])) { return false; }
    var folder = m[1];
    var slash = folder.lastIndexOf("\\");
    if (!/^envscan-\d+-\d+$/.test(folder.substr(slash + 1))) { return false; }
    var parent = folder.substr(0, slash).toLowerCase();
    var base = esLower(getEsEnv("TEMP") || getEsEnv("USERPROFILE")).replace(/\\+$/, "");
    if (!base || parent !== base) { return false; }
    try {
        if ((ES_FSO.GetFolder(folder).Attributes & 1024) !== 0) { return false; }
        // stdin.empty: made by initializeEsTemp in every folder a scanner created.
        return ES_FSO.FileExists(folder + "\\stdin.empty") && ES_FSO.FileExists(req) && !ES_FSO.FileExists(res)
            && !ES_FSO.FolderExists(res);
    } catch (e) { return false; }
}

function esWorkerEncode(value) {
    // [type, text] for one scalar WMI value.
    if (value === null || value === undefined) { return ["z", ""]; }
    if (typeof value === "string") { return ["s", esWorkerEscape(value)]; }
    if (typeof value === "number") { return ["n", String(value)]; }
    if (typeof value === "boolean") { return ["b", value ? "1" : "0"]; }
    if (typeof value === "date") { return ["s", formatEsUtc(new Date(value))]; }
    return ["z", ""];
}

var ES_WMI_UNSIGNED_BITS = { uint8: 256, uint16: 65536, uint32: 4294967296 };

function esWorkerTypes(service, className) {
    // Lower-case prop name -> CIM type, from the MOF text of the class and its superclasses
    // (WMI scripting hands uint32 values of 2^31 and more as negative numbers, and 64-bit
    // integers as strings).
    var types = {};
    try {
        var cls = service.Get(className);
        var names = [className].concat(esVbList(cls.Derivation_));
        for (var i = 0; i < names.length; i++) {
            var lines = String(service.Get(names[i]).GetObjectText_()).split("\n");
            for (var k = 0; k < lines.length; k++) {
                var m = /\b([us]int(8|16|32|64))\s+([A-Za-z0-9_]+)(\[\])?\s*[;=]/.exec(lines[k]);
                if (m && !types[m[3].toLowerCase()]) { types[m[3].toLowerCase()] = m[1]; }
            }
        }
    } catch (e) { /* no types: values stay as given */ }
    return types;
}

function esWorkerNumber(value, type) {
    // Unsigned values back to unsigned; 64-bit strings to numbers when exact (up to 2^53).
    if (typeof value === "number" && value < 0 && ES_WMI_UNSIGNED_BITS[type]) { return value + ES_WMI_UNSIGNED_BITS[type]; }
    if (typeof value === "string" && (type === "uint64" || type === "sint64") && /^-?\d{1,16}$/.test(value)) {
        var number = Number(value);
        if (Math.abs(number) <= 9007199254740991) { return number; }
    }
    return value;
}

function esWorkerProp(out, name, value, type) {
    if (typeof value === "unknown") {
        var list = [];
        try { list = new VBArray(value).toArray(); } catch (e) { list = []; }
        out.push("P\t" + name + "\ta\t" + list.length);
        for (var i = 0; i < list.length; i++) { out.push("E\t" + esWorkerEncode(esWorkerNumber(list[i], type)).join("\t")); }
        return;
    }
    out.push("P\t" + name + "\t" + esWorkerEncode(esWorkerNumber(value, type)).join("\t"));
}

function esWorkerConnect(namespace) {
    var locator = new ActiveXObject("WbemScripting.SWbemLocator");
    return locator.ConnectServer(".", String(namespace).replace(/\//g, "\\"));
}

function esWorkerGet(obj, name) {
    try { return obj[name]; } catch (e) { return null; }
}

function esWorkerEmbedded(out, name, parent, sub) {
    // "Prop.Sub": Sub of the embedded object Prop, or of each object of an embedded array.
    if (parent === null || parent === undefined) { out.push("P\t" + name + "\tx\t"); return; }
    if (typeof parent === "unknown") {
        var list = [];
        try { list = new VBArray(parent).toArray(); } catch (e) { list = []; }
        out.push("O\t" + name + "\t" + list.length);
        for (var i = 0; i < list.length; i++) {
            var value = list[i] !== null && typeof list[i] === "object" ? esWorkerGet(list[i], sub) : null;
            out.push("E\t" + esWorkerEncode(typeof value === "unknown" ? null : value).join("\t"));
        }
        return;
    }
    esWorkerProp(out, name, typeof parent === "object" ? esWorkerGet(parent, sub) : null);
}

// The only WQL a worker runs: a plain SELECT of named props from one class (never ASSOCIATORS OF
// or REFERENCES OF, which walk to other objects), in a namespace like root/cimv2.
var ES_WORKER_QUERY_RE = /^SELECT [A-Za-z0-9_.,]+ FROM [A-Za-z0-9_]+( WHERE .*)?$/;

function testEsWorkerQuery(lines) {
    // Throws unless a query request is well formed (the request file is not trusted).
    if (!ES_WMI_NAMESPACE_RE.test(String(lines[1] || ""))) { throw new Error("invalid namespace: " + lines[1]); }
    if (!ES_WORKER_QUERY_RE.test(String(lines[2] || ""))) { throw new Error("invalid query: " + lines[2]); }
    var props = lines[3] ? lines[3].split(",") : [];
    for (var i = 0; i < props.length; i++) {
        if (!ES_WMI_PROP_RE.test(props[i])) { throw new Error("invalid prop name: " + props[i]); }
    }
    return props;
}

function esWorkerQuery(lines, out) {
    var props = testEsWorkerQuery(lines);
    var service = esWorkerConnect(lines[1]);
    var rows = new Enumerator(service.ExecQuery(lines[2], "WQL", 32));
    var types = null;
    for (; !rows.atEnd(); rows.moveNext()) {
        var item = rows.item();
        if (types === null) { types = esWorkerTypes(service, /\sFROM\s+([A-Za-z0-9_]+)/.exec(lines[2])[1]); }
        out.push("I");
        for (var i = 0; i < props.length; i++) {
            var parts = props[i].split(".");
            var value = esWorkerGet(item, parts[0]);
            if (parts.length > 1) { esWorkerEmbedded(out, props[i], value, parts[1]); }
            else { esWorkerProp(out, props[i], value, types[parts[0].toLowerCase()]); }
        }
    }
}

function esWorkerTreeWindow(lines) {
    // {pid, from, to} of a tree-stop request (numbers only), else throws.
    for (var i = 1; i <= 3; i++) {
        if (!/^\d{1,15}$/.test(String(lines[i] || ""))) { throw new Error("tree-stop: invalid request"); }
    }
    return { pid: parseInt(lines[1], 10), from: parseInt(lines[2], 10), to: parseInt(lines[3], 10) };
}

function testEsTreeRoot(snapshot, request) {
    // The snapshot's process request.pid was created inside [from, to]: the child we started,
    // not a later process that got its recycled PID.
    for (var i = 0; i < snapshot.length; i++) {
        if (Number(snapshot[i].ProcessId) !== request.pid) { continue; }
        var created = convertFromEsCimDate(snapshot[i].CreationDate);
        return created !== null && created.getTime() >= request.from && created.getTime() <= request.to;
    }
    return false;
}

function esWorkerTreeStop(lines, out) {
    // One Win32_Process snapshot; the process and its descendants are stopped (Terminate), only
    // when the process is the one the parent started (testEsTreeRoot).
    var request = esWorkerTreeWindow(lines);
    var rows = new Enumerator(esWorkerConnect("root/cimv2").ExecQuery(
        "SELECT Handle,ProcessId,ParentProcessId,CreationDate FROM Win32_Process", "WQL", 32));
    var snapshot = [];
    var objects = {};
    for (; !rows.atEnd(); rows.moveNext()) {
        var item = rows.item();
        snapshot.push({ ProcessId: item.ProcessId, ParentProcessId: item.ParentProcessId, CreationDate: item.CreationDate });
        objects["p" + item.ProcessId] = item;
    }
    if (!testEsTreeRoot(snapshot, request)) { throw new Error("tree-stop: process " + request.pid + " is not the started child (PID reused or gone)"); }
    var ids = selectEsDescendants(request.pid, snapshot);
    for (var i = 0; i < ids.length; i++) {
        try { if (objects["p" + ids[i]]) { objects["p" + ids[i]].Terminate(); } } catch (e) { /* already gone */ }
        out.push("I");
        out.push("P\tProcessId\tn\t" + ids[i]);
    }
}

function invokeEsWmiWorker(request, reply) {
    // The worker mode. Returns the exit code, or null when the paths are not acceptable.
    if (!testEsWorkerPaths(request, reply)) { return null; }
    var out = [];
    var status = "S\tok";
    try {
        var lines = esReadUnicodeFile(request).split("\n");
        if (lines[0] === "query") { esWorkerQuery(lines, out); }
        else if (lines[0] === "tree-stop") { esWorkerTreeStop(lines, out); }
        else if (lines[0] === "reg-check") { esRegCheck(); }
        else { throw new Error("unknown request " + lines[0]); }
    } catch (e) {
        out = [];
        status = "S\terror\t" + esWorkerEscape(esComErrorText(e));
    }
    out.push(status);
    esWriteUnicodeFile(reply, out.join("\n"));
    return 0;
}
