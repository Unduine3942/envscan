// ---------------------------------------------------------------------------
// 12-runner: arguments, probe results, probe runner, output and temp folders.
// Port of src/ps/12-runner.ps1.
// ---------------------------------------------------------------------------

var ES_USAGE = [
    "Usage: cscript //nologo envscan.js [options]   (normally started through envscan.cmd --wsh)",
    "",
    "  --deep          also run probes that security tooling may flag (whoami /all, gpresult, exec tests)",
    "  --net           also check reachability of proxies and mirrors found in local configuration",
    "  --out DIR       parent directory for the output folder",
    "  --only IDS      comma-separated probe ids or area wildcards (net.*) to run",
    "  --skip IDS      comma-separated probe ids or area wildcards to skip",
    "  --timeout SEC   timeout per external command (default 15)",
    "  --budget SEC    time budget for the whole scan (default 600)",
    "  --no-redact     write secret values unredacted",
    "  --list-probes   list every probe and exactly what it reads or runs, then exit",
    "  --version       print the version and exit",
    "  --help          this text"
];
var ES_FLAG_OPTIONS = ["deep", "net", "no-redact", "list-probes", "version", "help", "h"];
var ES_VALUE_OPTIONS = ["out", "only", "skip", "timeout", "budget"];

// ------------------------------------------------------------------ arguments

function splitEsIdList(value) {
    var parts = String(value === null || value === undefined ? "" : value).split(",");
    var ids = [];
    for (var i = 0; i < parts.length; i++) { var id = esTrim(parts[i]); if (id) { ids.push(id); } }
    return ids;
}

function testEsIdMatch(id, patterns) {
    for (var i = 0; i < (patterns || []).length; i++) { if (esLikeRegExp(patterns[i]).test(id)) { return true; } }
    return false;
}

function testEsIdPatterns(option, patterns) {
    // Error messages for --only / --skip (see the ps1 for the rules).
    if (!patterns || patterns.length === 0) { return ["--" + option + " needs probe ids"]; }
    var errors = [];
    for (var i = 0; i < patterns.length; i++) {
        var text = String(patterns[i]);
        if (!/^[A-Za-z0-9._*-]+$/.test(text)) {
            errors.push("--" + option + ": invalid pattern '" + text + "' (allowed: letters, digits, . _ - *)");
            continue;
        }
        var like = esLikeRegExp(text);
        var hit = false;
        for (var p = 0; p < ES_PROBES.length && !hit; p++) { hit = like.test(ES_PROBES[p].id); }
        if (!hit) { errors.push("--" + option + ": pattern '" + text + "' matches no probe"); }
    }
    return errors;
}

function readEsNumberOption(value, min, max) {
    if (!/^[0-9]{1,9}$/.test(String(value))) { return null; }
    var number = parseInt(String(value), 10);
    return number < min || number > max ? null : number;
}

function esCopyOptions(options) {
    var copy = {};
    for (var k in options) { if (Object.prototype.hasOwnProperty.call(options, k)) { copy[k] = options[k]; } }
    return copy;
}

function esApplyOption(opt, key, raw, value, errors) {
    // One parsed option into opt (a fresh copy owned by readEsArguments).
    var flags = { deep: "deep", net: "net", "list-probes": "list", version: "version", help: "help", h: "help" };
    if (Object.prototype.hasOwnProperty.call(flags, key)) { opt[flags[key]] = true; return; }
    if (key === "no-redact") { opt.redact = false; return; }
    if (key === "out") { opt.out = value; return; }
    if (key === "only" || key === "skip") {
        opt[key] = splitEsIdList(value);
        var problems = testEsIdPatterns(key, opt[key]);
        for (var i = 0; i < problems.length; i++) { errors.push(problems[i]); }
        return;
    }
    var limits = { timeout: [1, 3600, "--timeout must be 1-3600 seconds: "], budget: [10, 86400, "--budget must be 10-86400 seconds: "] };
    if (Object.prototype.hasOwnProperty.call(limits, key)) {
        var number = readEsNumberOption(value, limits[key][0], limits[key][1]);
        if (number !== null) { opt[key] = number; } else { errors.push(limits[key][2] + value); }
        return;
    }
    errors.push("unknown option: " + raw);
}

function readEsArguments(args) {
    // Parses the arguments into a new ES_OPT; returns the error messages.
    var errors = [];
    var opt = esCopyOptions(ES_OPT);
    var list = args || [];
    for (var i = 0; i < list.length; i++) {
        var raw = String(list[i]);
        var value = null;
        var name = raw;
        var m = /^(-{1,2}[A-Za-z-]+)=([\s\S]*)$/.exec(raw);
        if (m) { name = m[1]; value = m[2]; }
        if (!esStartsWith(name, "-")) { errors.push("unexpected argument: " + raw); continue; }
        var key = name.replace(/^-+/, "").toLowerCase();
        if (esContains(ES_FLAG_OPTIONS, key) && value !== null) { errors.push("option --" + key + " takes no value"); continue; }
        if (esContains(ES_VALUE_OPTIONS, key) && value === null) {
            i++;
            if (i >= list.length) { errors.push("missing value for " + raw); break; }
            value = String(list[i]);
        }
        esApplyOption(opt, key, raw, value, errors);
    }
    ES_OPT = opt;
    return errors;
}

// ------------------------------------------------------------------ probe results

function newEsResult(status) {
    return { status: status || "ok", data: {}, raw: {}, sources: [], notes: [], error: null, truncated: false };
}

function addEsNote(result, note, status) {
    var effective = status === undefined ? "partial" : status;
    result.notes.push(note);
    if (effective && result.status === "ok") { result.status = effective; }
}

function addEsCimItems(result, className, namespace, filter, props) {
    // Queries CIM through the worker, records the source, notes failures; returns the items.
    var ns = namespace || "root/cimv2";
    result.sources.push(ns === "root/cimv2" ? "CIM " + className : "CIM " + ns + ":" + className);
    var query = getEsCimSafe(className, ns, filter || "", props);
    if (query.status !== "ok") { addEsNote(result, query.error, "partial"); }
    return query.items;
}

function invokeEsTool(result, label, filePath, args, timeoutSec, encoding, allowFailure) {
    // Runs a tool for a probe: source and raw output recorded; partial when it timed out, could
    // not start, exited non-zero or printed nothing (allowFailure skips the last two checks).
    var run = invokeEsCommand(filePath, args || [], timeoutSec || 0, encoding || "Oem");
    result.sources.push("run " + run.command);
    var text = getEsCommandText(run);
    if (text) { result.raw[label] = text; }
    if (run.timed_out) { addEsNote(result, label + ": timed out", "partial"); }
    else if (run.error) { addEsNote(result, label + ": " + run.error, "partial"); }
    else if (!allowFailure) {
        if (run.exit_code !== null && run.exit_code !== 0) { addEsNote(result, label + ": exit code " + run.exit_code, "partial"); }
        else if (!text) { addEsNote(result, label + ": no output", "partial"); }
    }
    return run;
}

// The Windows folder as Windows reports it (FSO GetSpecialFolder(0), i.e. GetWindowsDirectory),
// never the SystemRoot/SystemDrive/windir variables: a SystemRoot of \\host\share would make every
// child command start that share's cmd.exe. Read once; tests may set it to a fake value.
var ES_WINDOWS_DIR = null;

function testEsSystemFolder(path) {
    // A plain local folder X:\name[\name...] (no device, UNC, mapped network drive, % or
    // wildcard) that is not, and is not below, a link or a credential store.
    var p = String(path || "");
    if (!/^[A-Za-z]:\\[^\\\/:*?"<>|%~]+(\\[^\\\/:*?"<>|%~]+)*$/.test(p)) { return false; }
    if (!testEsLocalPath(p)) { return false; }
    return !getEsPathLinkReason(p);
}

function getEsWindowsDir() {
    // The trusted Windows folder (see ES_WINDOWS_DIR), or null when it is not testEsSystemFolder.
    if (ES_WINDOWS_DIR === null) {
        try { ES_WINDOWS_DIR = String(ES_FSO.GetSpecialFolder(0).Path).replace(/\\+$/, ""); } catch (e) { ES_WINDOWS_DIR = ""; }
    }
    return testEsSystemFolder(ES_WINDOWS_DIR) ? ES_WINDOWS_DIR : null;
}

function getEsSystemTool(name) {
    // Absolute System32 path (never PATH, never the environment's SystemRoot); Sysnative from a
    // 32-bit process on 64-bit Windows. null when the Windows folder is not trusted.
    var root = getEsWindowsDir();
    if (!root) { return null; }
    if (getEsEnv("PROCESSOR_ARCHITEW6432")) {
        var native = esJoinPath(root, "Sysnative\\" + name);
        if (esIsFile(native)) { return native; }
    }
    return esJoinPath(root, "System32\\" + name);
}

// ------------------------------------------------------------------ runner

function getEsSkipReason(meta) {
    if (meta.tier === "deep" && !ES_OPT.deep) { return "requires --deep"; }
    if (meta.tier === "net" && !ES_OPT.net) { return "requires --net"; }
    if (ES_OPT.only.length > 0 && !testEsIdMatch(meta.id, ES_OPT.only)) { return "not selected by --only"; }
    if (testEsIdMatch(meta.id, ES_OPT.skip)) { return "excluded by --skip"; }
    if (getEsElapsedMs(ES_STARTED) / 1000 > ES_OPT.budget) {
        ES_BUDGET_SKIPS++;
        return "scan budget exhausted";
    }
    return null;
}

function limitEsRaw(raw) {
    // Redacts raw text and caps it at ES_RAW_CAP characters per probe.
    var out = {};
    var truncated = false;
    var left = ES_RAW_CAP;
    var labels = esKeys(raw);
    for (var i = 0; i < labels.length; i++) {
        var text = protectEsText(raw[labels[i]] === null || raw[labels[i]] === undefined ? "" : String(raw[labels[i]]));
        if (text === null || text === undefined || text.length === 0) { continue; }
        if (left <= 0) { truncated = true; continue; }
        if (text.length > left) { text = text.substr(0, left) + "\n[truncated]"; truncated = true; }
        left -= text.length;
        out[labels[i]] = text;
    }
    return { raw: out, truncated: truncated };
}

function esProtectedList(items, protect) {
    var out = [];
    for (var i = 0; i < (items || []).length; i++) { if (items[i]) { out.push(protect(String(items[i]))); } }
    return out;
}

function completeEsEnvelope(meta, result, durationMs) {
    var status = esContains(ES_STATUSES, result.status) ? result.status : "error";
    var limited = limitEsRaw(esIsTable(result.raw) ? result.raw : {});
    var envelope = {
        __order: ["status", "tier", "scope", "title", "sources", "duration_ms", "data", "raw", "truncated", "error", "notes"],
        status: status, tier: String(meta.tier), scope: String(meta.scope), title: String(meta.title),
        sources: esProtectedList(result.sources, protectEsCommandLine), duration_ms: durationMs,
        data: protectEsData(esIsTable(result.data) ? result.data : {}), truncated: !!result.truncated || limited.truncated,
        error: result.error ? protectEsValue(String(result.error)) : null
    };
    if (esKeys(limited.raw).length > 0) { envelope.raw = limited.raw; }
    var notes = esProtectedList(result.notes, protectEsValue);
    if (notes.length > 0) { envelope.notes = notes; }
    return envelope;
}

function esShownKeys(keys) {
    var shown = keys.slice(0, 5).join(", ");
    return keys.length > 5 ? shown + " (+" + (keys.length - 5) + " more)" : shown;
}

function addEsDeniedNote(result) {
    // Denied (or unlistable) registry keys make an ok or not_found result partial, with a note.
    var denied = ES_DENIED_READS;
    var unlisted = ES_REG_UNLISTED;
    ES_DENIED_READS = [];
    ES_REG_UNLISTED = [];
    if (denied.length === 0 && unlisted.length === 0) { return; }
    result.notes = esIsArray(result.notes) ? result.notes : [];
    if (denied.length > 0) { result.notes.push("access denied to " + denied.length + " registry key(s): " + esShownKeys(denied)); }
    if (unlisted.length > 0) {
        result.notes.push("registry listing unavailable (WMI StdRegProv did not answer): " + unlisted.length + " key(s) not read: " + esShownKeys(unlisted));
    }
    if (result.status === "ok" || result.status === "not_found") { result.status = "partial"; }
}

// The global object, used only to find probe_<area>_<name> functions by name (the one lookup the
// lint accepts; the name is checked first).
var ES_GLOBAL = this;  // lint-allow: this, global-lookup
var ES_PROBE_NAME_RE = /^probe_[a-z0-9_]+$/;

function esProbeFunction(id) {
    var name = "probe_" + String(id).replace(/\./g, "_");
    if (!ES_PROBE_NAME_RE.test(name)) { return null; }
    var fn = ES_GLOBAL[name];  // lint-allow: global-lookup
    return typeof fn === "function" ? fn : null;
}

function esRunProbeFunction(meta) {
    var fn = esProbeFunction(meta.id);
    var result;
    if (fn === null) { result = newEsResult("error"); result.error = "not implemented"; return result; }
    try {
        result = fn();
        if (!esIsTable(result) || !Object.prototype.hasOwnProperty.call(result, "status")) {
            result = newEsResult("error");
            result.error = "probe returned no result";
        }
    } catch (e) {
        result = newEsResult("error");
        result.error = esErrorText(e);
    }
    return result;
}

function invokeEsProbe(meta) {
    var start = getEsUtc();
    var reason = getEsSkipReason(meta);
    var result;
    if (reason) {
        result = newEsResult("skipped");
        result.notes = [reason];
    } else {
        ES_DENIED_READS = [];
        ES_REG_UNLISTED = [];
        result = esRunProbeFunction(meta);
        addEsDeniedNote(result);
    }
    var probeMs = getEsElapsedMs(start);
    var envelope;
    try { envelope = completeEsEnvelope(meta, result, probeMs); }
    catch (e) {
        var failed = newEsResult("error");
        failed.error = "could not complete the probe result: " + esErrorText(e);
        envelope = completeEsEnvelope(meta, failed, probeMs);
    }
    ES_RESULTS[meta.id] = envelope;
    var redactMs = getEsElapsedMs(start) - probeMs;
    writeEsLog(meta.id + " " + envelope.status + " " + envelope.duration_ms + "ms (redaction " + redactMs + "ms)" + (envelope.error ? " " + envelope.error : ""));
    return envelope;
}

function esCompleted(status) { return esContains(["ok", "partial", "not_found", "not_applicable"], status); }

function testEsDependency(result, id) {
    var status = getEsStatus(id);
    if (esCompleted(status)) { return true; }
    result.status = "error";
    result.error = "depends on " + id + ", which is " + (status || "not run");
    return false;
}

function testEsInputComplete(result, id) {
    var status = getEsStatus(id);
    if (esCompleted(status)) { return true; }
    result.notes.push(id + " is " + (status || "not run") + ": what it would have added is missing");
    if (result.status === "ok" || result.status === "not_found") { result.status = "partial"; }
    return false;
}

function getEsData(id) {
    var envelope = Object.prototype.hasOwnProperty.call(ES_RESULTS, id) ? ES_RESULTS[id] : null;
    return envelope && esIsTable(envelope.data) ? envelope.data : {};
}

function getEsStatus(id) {
    return Object.prototype.hasOwnProperty.call(ES_RESULTS, id) ? String(ES_RESULTS[id].status) : null;
}

// ------------------------------------------------------------------ output and temp folders

function getEsSafeHostName() {
    return (getEsEnv("COMPUTERNAME") || "host").replace(/[^A-Za-z0-9._-]/g, "_");
}

function getEsDefaultOutputParents() {
    // The current directory, the profile, then TEMP; never a network, OneDrive, Desktop or
    // Documents folder. --out is used as given.
    initializeEsDrives();
    var candidates = [ES_START_CWD, getEsEnv("USERPROFILE"), getEsEnv("TEMP")];
    var personal = getEsPersonalFolders();
    var parents = [];
    for (var i = 0; i < candidates.length; i++) {
        if (!candidates[i]) { continue; }
        if (testEsNetworkPath(candidates[i]) || testEsUnderFolder(candidates[i], personal)) {
            writeEsLog("output: skipped " + candidates[i] + " (network, OneDrive, Desktop or Documents folder)");
            continue;
        }
        if (getEsCredentialFolder(candidates[i])) {
            writeEsLog("output: skipped " + candidates[i] + " (credential store)");
            continue;
        }
        parents.push(candidates[i]);
    }
    return parents;
}

function esCreateFolderTree(path) {
    // New-Item -Force for --out: the missing folders of an absolute path.
    var full = ES_FSO.GetAbsolutePathName(path);
    if (ES_FSO.FolderExists(full)) { return; }
    var parent = ES_FSO.GetParentFolderName(full);
    if (parent && parent !== full) { esCreateFolderTree(parent); }
    ES_FSO.CreateFolder(full);
}

function newEsOutputFolder() {
    var name = "envscan-" + getEsSafeHostName() + "-" + formatEsStamp(ES_STARTED);
    var parents = ES_OPT.out ? [String(ES_OPT.out)] : getEsDefaultOutputParents();
    for (var i = 0; i < parents.length; i++) {
        if (!parents[i]) { continue; }
        try {
            if (!ES_FSO.FolderExists(parents[i])) {
                if (!ES_OPT.out) { continue; }
                esCreateFolderTree(parents[i]);
            }
            var folder = esJoinPath(ES_FSO.GetAbsolutePathName(parents[i]), name);
            ES_FSO.CreateFolder(folder);
            return folder;
        } catch (e) {
            writeEsLog("cannot write output under " + parents[i] + ": " + esErrorText(e));
        }
    }
    return null;
}

var ES_TEST_TEMP_MARK = "__ES_TEST_TEMP_REPORT";

function initializeEsTemp() {
    // A new, randomly named folder (never an existing one: TEMP may be shared). Call
    // initializeEsDrives first: a TEMP on a mapped network drive is refused (testEsLocalPath).
    // Children run from the root of the drive of the trusted Windows folder (never SystemDrive).
    var base = getEsEnv("TEMP") || getEsEnv("USERPROFILE");
    if (!base || !testEsLocalPath(base) || base.indexOf("%") >= 0) { throw new Error("no usable TEMP folder: " + base); }
    if (getEsCredentialFolder(base)) { throw new Error("no usable TEMP folder: " + base + " (credential store)"); }
    var windows = getEsWindowsDir();
    if (!windows) { throw new Error("the Windows folder is not a trusted local path"); }
    var folder = null;
    for (var attempt = 0; attempt < 5 && !folder; attempt++) {
        var candidate = esJoinPath(base, "envscan-" + esRandomDigits() + "-" + Math.floor(Math.random() * 100000));
        try { ES_FSO.CreateFolder(candidate); folder = candidate; } catch (e) { folder = null; }
    }
    if (!folder) { throw new Error("cannot create a temporary folder under " + base); }
    ES_TMP = folder;
    ES_EMPTY_IN = esJoinPath(folder, "stdin.empty");
    ES_FSO.CreateTextFile(ES_EMPTY_IN, false, false).Close();
    ES_CHILD_CWD = windows.substr(0, 2) + "\\";
    // Test hook (tests/js_harness.py run_js): name the folder on stderr so the harness can remove
    // a folder a snippet left behind. Prints a path only; changes nothing.
    if (getEsEnv(ES_TEST_TEMP_MARK) === "1") { writeEsProgress(ES_TEST_TEMP_MARK + "=" + folder); }
}

function esInitForTests(workerScript) {
    // For library snippets (tests/js_harness.py run_js): call it FIRST, before any other
    // statement. When cscript started this snippet as a WMI worker it serves the request and
    // quits, so the rest of the snippet never runs inside a worker. Otherwise it prepares what a
    // scan prepares for probes: env snapshot, redaction rules (when loaded), a scanner temp
    // folder (remove it with removeEsTemp() in a finally) and the worker script (the snippet
    // itself unless workerScript, e.g. the built dist envscan.js, is given).
    var args = esScriptArguments();
    if (args.length === 3 && args[0] === ES_WORKER_OPTION) {
        var code = invokeEsWmiWorker(args[1], args[2]);
        WScript.Quit(code === null ? 2 : code);
    }
    if (getEsEnv(ES_WORKER_MARK)) { WScript.Quit(2); }
    ES_WORKER_SCRIPT = workerScript || ES_SCRIPT_PATH;
    ES_CIM_CACHE = {};
    saveEsEnvSnapshot();
    if (typeof initializeEsRedaction === "function") { initializeEsRedaction(); }
    initializeEsDrives();
    initializeEsTemp();
}

function esScriptArguments() {
    var list = [];
    for (var i = 0; i < WScript.Arguments.length; i++) { list.push(String(WScript.Arguments(i))); }
    return list;
}

function removeEsTemp() {
    if (ES_TMP && ES_FSO.FolderExists(ES_TMP)) {
        try { ES_FSO.DeleteFolder(ES_TMP, true); } catch (e) { writeEsLog("cannot remove " + ES_TMP + ": " + esErrorText(e)); }  // lint-allow: temp-cleanup
    }
    ES_TMP = null;
}
