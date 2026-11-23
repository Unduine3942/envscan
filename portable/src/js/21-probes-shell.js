// ---------------------------------------------------------------------------
// 21-probes-shell: shells and script hosts (port of probe_shell_info from
// src/ps/21-probes-user.ps1). The scanner runs in Windows Script Host, so the
// PowerShell facts (execution policy, engines, policies) come from the registry.
// ---------------------------------------------------------------------------

var JSSHELL_POLICY_NAMES = ["Unrestricted", "RemoteSigned", "AllSigned", "Restricted", "Undefined", "Default"];
var JSSHELL_SHELL_IDS = "\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell";
var JSSHELL_PS_POLICY = "\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell";
var JSSHELL_WSH_KEY = "\\Software\\Microsoft\\Windows Script Host\\Settings";
var JSSHELL_WSH_NAMES = ["Enabled", "IgnoreUserSettings", "TrustPolicy", "UseWINSAFER"];

function jsShell_policyName(value) {
    // Canonical spelling of an execution policy value (PowerShell parses them ignoring case).
    var text = esTrim(jsOs_str(value));
    for (var i = 0; i < JSSHELL_POLICY_NAMES.length; i++) {
        if (JSSHELL_POLICY_NAMES[i].toLowerCase() === text.toLowerCase()) { return JSSHELL_POLICY_NAMES[i]; }
    }
    return text || "Undefined";
}

function jsShell_gpoPolicy(hive) {
    // "Turn on Script Execution": EnableScripts 0 = Restricted, 1 = the ExecutionPolicy value.
    var key = hive + ":" + JSSHELL_PS_POLICY;
    var enable = getEsRegValue(key, "EnableScripts");
    if (enable === null || enable === undefined) { return "Undefined"; }
    if (Number(enable) === 0) { return "Restricted"; }
    return jsShell_policyName(getEsRegValue(key, "ExecutionPolicy"));
}

function jsShell_defaultPolicy() {
    // Windows PowerShell's default without any setting: RemoteSigned on servers, else Restricted.
    var productType = getEsData("os.identity").product_type;
    if (productType === null || productType === undefined) { return null; }
    return Number(productType) !== 1 ? "RemoteSigned" : "Restricted";
}

function getEsExecutionPolicies(result) {
    // Policy per scope (keys in Get-ExecutionPolicy -List order under __order) and the effective one,
    // read from where Windows PowerShell keeps them; PowerShell itself is not run.
    result.sources.push("registry HKLM and HKCU" + JSSHELL_PS_POLICY + " (EnableScripts, ExecutionPolicy)",
        "environment PSExecutionPolicyPreference", "registry HKCU and HKLM" + JSSHELL_SHELL_IDS + " (ExecutionPolicy)");
    var process = getEsOrigEnv("PSExecutionPolicyPreference");
    var scopes = {
        __order: ["MachinePolicy", "UserPolicy", "Process", "CurrentUser", "LocalMachine"],
        MachinePolicy: jsShell_gpoPolicy("HKLM"),
        UserPolicy: jsShell_gpoPolicy("HKCU"),
        Process: process ? jsShell_policyName(process) : "Undefined",
        CurrentUser: jsShell_policyName(getEsRegValue("HKCU:" + JSSHELL_SHELL_IDS, "ExecutionPolicy")),
        LocalMachine: jsShell_policyName(getEsRegValue("HKLM:" + JSSHELL_SHELL_IDS, "ExecutionPolicy"))
    };
    var effective = null;
    for (var i = 0; i < scopes.__order.length && effective === null; i++) {
        var value = scopes[scopes.__order[i]];
        if (value !== "Undefined") { effective = value; }
    }
    if (effective === null) { effective = jsShell_defaultPolicy(); }
    return { scopes: scopes, effective: effective };
}

function jsShell_entryPath(entry) {
    // getEsDirEntries rows: a full path under one of these names, or an FSO item.
    if (entry === null || entry === undefined) { return null; }
    if (typeof entry === "string") { return entry; }
    var names = ["FullName", "full_name", "path", "Path"];
    for (var i = 0; i < names.length; i++) {
        if (entry[names[i]]) { return String(entry[names[i]]); }
    }
    return null;
}

function jsShell_fileVersion(path) {
    try { return String(ES_FSO.GetFileVersion(path)) || null; } catch (e) { return null; }
}

function getEsPowerShellEngines(result) {
    var engines = [];
    var majors = ["1", "3"];
    for (var i = 0; i < majors.length; i++) {
        var key = "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\" + majors[i] + "\\PowerShellEngine";
        result.sources.push("registry " + key.replace(/^HKLM:/, "HKLM"));
        var version = getEsRegValue(key, "PowerShellVersion");
        if (version) { engines.push({ name: "Windows PowerShell", version: String(version), path: jsOs_str(getEsRegValue(key, "ApplicationBase")) }); }
    }
    var root = esJoinPath(jsOs_str(getEsEnv("ProgramFiles")), "PowerShell");
    result.sources.push("list " + root);
    var dirs = getEsDirEntries(root, 50) || [];
    for (var j = 0; j < dirs.length; j++) {
        var dir = jsShell_entryPath(dirs[j]);
        if (!dir) { continue; }
        var exe = esJoinPath(dir, "pwsh.exe");
        if (testEsSafePath(exe, "Leaf")) { engines.push({ name: "PowerShell", version: jsShell_fileVersion(exe), path: exe }); }
    }
    return engines;
}

function jsShell_wshSettings(result) {
    // Windows Script Host settings of both hives (Enabled, IgnoreUserSettings, TrustPolicy, UseWINSAFER).
    var out = {};
    var hives = ["HKLM", "HKCU"];
    for (var i = 0; i < hives.length; i++) {
        result.sources.push("registry " + hives[i] + JSSHELL_WSH_KEY + " (" + JSSHELL_WSH_NAMES.join(", ") + ")");
        var values = {};
        for (var j = 0; j < JSSHELL_WSH_NAMES.length; j++) {
            var value = getEsRegValue(hives[i] + ":" + JSSHELL_WSH_KEY, JSSHELL_WSH_NAMES[j]);
            values[JSSHELL_WSH_NAMES[j]] = value === undefined ? null : value;
        }
        out[hives[i]] = values;
    }
    return out;
}

function getEsCmdSettings(result) {
    // cmd.exe AutoRun (redacted) and DisableCMD, and whether Windows Script Host is enabled.
    var settings = { autorun: {}, disabled: null, wsh_enabled: true };
    var hives = ["HKLM", "HKCU"];
    for (var i = 0; i < hives.length; i++) {
        result.sources.push("registry " + hives[i] + "\\Software\\Microsoft\\Command Processor (AutoRun)");
        var autorun = getEsRegValue(hives[i] + ":\\Software\\Microsoft\\Command Processor", "AutoRun");
        if (autorun) { settings.autorun[hives[i]] = protectEsCommandLine(String(autorun)); }
    }
    var policyHives = ["HKCU", "HKLM"];
    for (var j = 0; j < policyHives.length; j++) {
        result.sources.push("registry " + policyHives[j] + "\\Software\\Policies\\Microsoft\\Windows\\System (DisableCMD)");
        var disabled = getEsRegValue(policyHives[j] + ":\\Software\\Policies\\Microsoft\\Windows\\System", "DisableCMD");
        if (disabled !== null && disabled !== undefined && settings.disabled === null) { settings.disabled = Number(disabled); }
    }
    settings.wsh = jsShell_wshSettings(result);
    for (var hive in settings.wsh) {
        var enabled = settings.wsh[hive].Enabled;
        if (esHas(settings.wsh, hive) && enabled !== null && String(enabled) === "0") { settings.wsh_enabled = false; }
    }
    return settings;
}

function jsShell_zoneId(result) {
    // Mark of the web of the scanner script (the Zone.Identifier stream; read only).
    if (!ES_SCRIPT_PATH) { return null; }
    result.sources.push("read envscan.js:Zone.Identifier");
    var text = "";
    try {
        var stream = ES_FSO.OpenTextFile(ES_SCRIPT_PATH + ":Zone.Identifier", 1, false, 0);
        try { text = stream.AtEndOfStream ? "" : String(stream.ReadAll()); } finally { stream.Close(); }
    } catch (e) { return null; }
    var m = /ZoneId=(\d+)/.exec(text);
    return m ? parseInt(m[1], 10) : null;
}

function jsShell_powerShellPolicies(result) {
    var out = {};
    var hives = ["HKLM", "HKCU"];
    for (var i = 0; i < hives.length; i++) {
        result.sources.push("registry " + hives[i] + JSSHELL_PS_POLICY);
        var tree = getEsRegTree(hives[i] + ":" + JSSHELL_PS_POLICY, 50);
        if (tree && esKeys(tree).length > 0) { out[hives[i]] = protectEsTable(tree); }
    }
    return out;
}

function jsShell_hostFacts(d) {
    d.current_shell = "cscript";
    d.shell_version = jsOs_str(WScript.Version);
    d.script_engine = ScriptEngine() + " " + ScriptEngineMajorVersion() + "." + ScriptEngineMinorVersion() + "." + ScriptEngineBuildVersion();
    d.edition = null;
    d.clr_version = null;
    d.host = jsOs_hostName();
    d.language_mode = ES_LANGUAGE_MODE;
    var lockdown = getEsOrigEnv("__PSLockdownPolicy");
    d.powershell_lockdown_policy = (lockdown === null || lockdown === undefined) ? null : lockdown;
}

function probe_shell_info() {
    var r = newEsResult();
    var d = r.data;
    r.sources.push("WScript.Version, ScriptEngine version", "environment __PSLockdownPolicy");
    jsShell_hostFacts(d);
    var policy = getEsExecutionPolicies(r);
    var policies = policy.scopes;
    d.effective_policy = policy.effective;
    d.execution_policy = policies;
    d.policy_from_gpo = (policies.MachinePolicy !== "Undefined" || policies.UserPolicy !== "Undefined");
    addEsNote(r, "PowerShell facts are read from the registry (PowerShell is not run by the WSH port); effective_policy is what Windows PowerShell would use", "");
    d.powershell_installed = getEsPowerShellEngines(r);
    d.powershell_policies = jsShell_powerShellPolicies(r);
    var cmd = getEsCmdSettings(r);
    d.cmd_autorun = cmd.autorun;
    d.cmd_disabled = cmd.disabled;
    d.wsh_enabled = cmd.wsh_enabled;
    d.wsh_settings = cmd.wsh;
    d.script_zone_id = jsShell_zoneId(r);
    d.comspec = getEsOrigEnv("ComSpec");
    d.pathext = getEsOrigEnv("PATHEXT");
    return r;
}
