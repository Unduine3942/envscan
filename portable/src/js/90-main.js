// ---------------------------------------------------------------------------
// 90-main: the scan and the entry logic (excluded from build/lib/envscan-lib.js).
// Port of src/ps/90-main.ps1.
// ---------------------------------------------------------------------------

var ES_EXIT_CODE = 2;
var ES_EXIT_BASE = 0;
var ES_EXIT_BASE_VAR = "__ES_EXIT_BASE";

function esStdout(line) {
    try { WScript.StdOut.WriteLine(esAsciiText(String(line))); } catch (e) { /* no stdout */ }
}

function showEsProbeList() {
    for (var i = 0; i < ES_PROBES.length; i++) {
        var probe = ES_PROBES[i];
        esStdout(probe.id + "  [" + probe.tier + "]  " + probe.title);
        for (var k = 0; k < probe.footprint.length; k++) { esStdout("    - " + probe.footprint[k]); }
    }
}

function getEsCounts() {
    var counts = { __order: ES_STATUSES.slice(0) };
    for (var i = 0; i < ES_STATUSES.length; i++) { counts[ES_STATUSES[i]] = 0; }
    var ids = esKeys(ES_RESULTS);
    for (var k = 0; k < ids.length; k++) { counts[ES_RESULTS[ids[k]].status] = (counts[ES_RESULTS[ids[k]].status] || 0) + 1; }
    return counts;
}

function getEsExitCode() {
    var ids = esKeys(ES_RESULTS);
    for (var i = 0; i < ids.length; i++) {
        if (esContains(["partial", "denied", "timeout", "error"], ES_RESULTS[ids[i]].status)) { return 1; }
    }
    return ES_BUDGET_SKIPS > 0 ? 1 : 0;
}

function newEsHostBlock() {
    var os = getEsData("os.identity");
    var version = os.version ? String(os.version) : "";
    if (os.build) { version = esTrim(version + " build " + os.build); }
    var arch = os.arch ? String(os.arch) : "";
    if (!esContains(["x86_64", "x86", "arm64", "arm", "ia64"], arch)) { arch = "other"; }
    return {
        __order: ["os_family", "os_name", "os_version", "arch", "hostname"],
        os_family: "windows", os_name: os.name ? String(os.name) : "Windows", os_version: version, arch: arch,
        hostname: os.hostname ? String(os.hostname) : (getEsEnv("COMPUTERNAME") || "")
    };
}

function getEsShellVersion() {
    var engine = "JScript";
    try { engine += " " + ScriptEngineMajorVersion() + "." + ScriptEngineMinorVersion() + "." + ScriptEngineBuildVersion(); } catch (e) { /* unknown */ }
    try { engine += " (Windows Script Host " + WScript.Version + ")"; } catch (e2) { /* unknown */ }
    return engine;
}

function newEsReport(folder, tiers, findings, exitCode) {
    var finished = getEsUtc();
    var probes = { __order: [] };
    for (var i = 0; i < ES_PROBES.length; i++) { probes.__order.push(ES_PROBES[i].id); }
    var ids = esKeys(ES_RESULTS);
    for (var k = 0; k < ids.length; k++) { probes[ids[k]] = ES_RESULTS[ids[k]]; }
    var run = {
        __order: ["started_utc", "finished_utc", "duration_ms", "tiers", "flags", "cwd", "out_dir", "exit_code", "redaction", "counts"],
        started_utc: formatEsUtc(ES_STARTED), finished_utc: formatEsUtc(finished), duration_ms: getEsElapsedMs(ES_STARTED),
        tiers: tiers, flags: esProtectedList(ES_ARGS, protectEsValue), cwd: ES_START_CWD, out_dir: folder,
        exit_code: exitCode, redaction: !!ES_OPT.redact, counts: getEsCounts()
    };
    return {
        __order: ["schema", "scanner", "run", "host", "findings", "probes"],
        schema: ES_SCHEMA,
        scanner: { __order: ["name", "version", "impl", "shell_version"], name: ES_NAME, version: ES_VERSION, impl: ES_IMPL,
            shell_version: getEsShellVersion() },
        run: run, host: newEsHostBlock(), findings: findings, probes: probes
    };
}

function formatEsProgressLine(index, total, id, envelope) {
    var counter = "[" + esPadLeft(String(index), String(total).length) + "/" + total + "]";
    return counter + " " + esPadRight(id + " ", 36, ".") + " " + esPadRight(String(envelope.status), 14)
        + esPadLeft(String(envelope.duration_ms), 7) + " ms";
}

function invokeEsProbeLoop(probes) {
    try {
        try { enterEsChildEnv(); } catch (e) { writeEsLog("child environment: " + esErrorText(e)); }
        try { initializeEsDrives(); } catch (e2) { writeEsLog("network drive detection failed: " + esErrorText(e2)); }
        for (var i = 0; i < probes.length; i++) {
            try {
                var envelope = invokeEsProbe(probes[i]);
                writeEsProgress(formatEsProgressLine(i + 1, probes.length, probes[i].id, envelope));
            } catch (e3) { writeEsLog(probes[i].id + " failed outside the probe: " + esErrorText(e3)); }
        }
    } finally {
        exitEsChildEnv();
        removeEsTemp();
    }
}

function writeEsSecondaryOutputs(folder, report) {
    // envscan.md, AGENT_BRIEF.md and envscan.log; one failing does not stop the others.
    var ok = true;
    var outputs = [
        ["envscan.md", "convertToEsMarkdownReport", typeof convertToEsMarkdownReport === "function" ? convertToEsMarkdownReport : null],
        ["AGENT_BRIEF.md", "convertToEsBrief", typeof convertToEsBrief === "function" ? convertToEsBrief : null]
    ];
    for (var i = 0; i < outputs.length; i++) {
        var mark = getEsUtc();
        try {
            var render = outputs[i][2];
            if (render === null) { throw new Error(outputs[i][1] + " is not implemented"); }
            writeEsTextFile(esJoinPath(folder, outputs[i][0]), render(report));
            writeEsLog(outputs[i][0] + " written in " + getEsElapsedMs(mark) + " ms");
        } catch (e) {
            writeEsLog("cannot write " + outputs[i][0] + ": " + esErrorText(e));
            writeEsProgress("envscan: cannot write " + outputs[i][0] + ": " + esErrorText(e));
            ok = false;
        }
    }
    try { writeEsTextFile(esJoinPath(folder, "envscan.log"), ES_LOG.join("\r\n")); } catch (e2) { ok = false; }
    return ok;
}

function esPrepareScan() {
    // Temp and output folders; the output folder path, or null after a fatal message.
    ES_STARTED = getEsUtc();
    ES_CIM_CACHE = {};
    initializeEsRedaction();
    saveEsEnvSnapshot();
    // Network drives first: initializeEsTemp refuses a TEMP on a mapped network drive.
    try { initializeEsDrives(); } catch (e0) { writeEsLog("network drive detection failed: " + esErrorText(e0)); }
    try { initializeEsTemp(); }
    catch (e) { writeEsFatal("envscan: cannot create a temporary folder: " + esErrorText(e)); return null; }
    var folder = null;
    try { folder = newEsOutputFolder(); } catch (e2) { writeEsLog("output folder: " + esErrorText(e2)); }
    if (!folder) {
        writeEsFatal("envscan: cannot create an output folder; use --out DIR");
        removeEsTemp();
    }
    return folder;
}

function esFindings() {
    var mark = getEsUtc();
    var findings = [];
    try { findings = getEsFindings(); } catch (e) { writeEsLog("findings failed: " + esErrorText(e)); }
    writeEsLog("findings: " + findings.length + " in " + getEsElapsedMs(mark) + " ms");
    return findings;
}

function invokeEnvScan(args) {
    var errors = readEsArguments(args);
    if (errors.length > 0) {
        var lines = [];
        for (var i = 0; i < errors.length; i++) { lines.push("envscan: " + errors[i]); }
        writeEsFatal(lines.concat(ES_USAGE));
        return 2;
    }
    if (ES_OPT.help) { for (var h = 0; h < ES_USAGE.length; h++) { esStdout(ES_USAGE[h]); } return 0; }
    if (ES_OPT.version) { esStdout("envscan " + ES_VERSION + " (jscript)"); return 0; }
    if (ES_OPT.list) { showEsProbeList(); return 0; }
    var folder = esPrepareScan();
    if (!folder) { return 2; }
    var tiers = ["default"];
    if (ES_OPT.deep) { tiers.push("deep"); }
    if (ES_OPT.net) { tiers.push("net"); }
    writeEsProgress("envscan " + ES_VERSION + " (jscript): " + ES_PROBES.length + " probes, tiers " + tiers.join(",") + " -> " + folder);
    invokeEsProbeLoop(ES_PROBES);
    var findings = esFindings();
    var exitCode = getEsExitCode();
    var report = newEsReport(folder, tiers, findings, exitCode);
    try { writeEsTextFile(esJoinPath(folder, "envscan.json"), convertToEsJson(report)); }
    catch (e) { writeEsFatal("envscan: cannot write envscan.json: " + esErrorText(e)); return 2; }
    if (!writeEsSecondaryOutputs(folder, report)) { exitCode = 1; }
    writeEsProgress("envscan: done in " + Math.floor(getEsElapsedMs(ES_STARTED) / 1000) + " s, exit code " + exitCode);
    esStdout(folder);
    return exitCode;
}

function readEsExitBase() {
    // __ES_EXIT_BASE (set only by envscan.cmd): read once, removed before any child starts.
    var base = getEsEnv(ES_EXIT_BASE_VAR);
    if (base !== null) { setEsEnvValue(ES_EXIT_BASE_VAR, null); }
    return base === "100" ? 100 : 0;
}

function invokeEsEntry() {
    // The exit code of the whole run (with the launcher's offset).
    ES_EXIT_BASE = readEsExitBase();
    ES_ARGS = esScriptArguments();
    var code = 2;
    try {
        if (ES_ARGS.length === 3 && ES_ARGS[0] === ES_WORKER_OPTION) {
            var worker = invokeEsWmiWorker(ES_ARGS[1], ES_ARGS[2]);
            if (worker !== null) { return worker; }
        }
        code = invokeEnvScan(ES_ARGS);
    } catch (e) {
        // Never exit 1 here: the launcher would mistake it for a refusal.
        writeEsFatal("envscan: internal error: " + esErrorText(e));
        code = 2;
    }
    ES_EXIT_CODE = code;
    return code + ES_EXIT_BASE;
}
