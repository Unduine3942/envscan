// ---------------------------------------------------------------------------
// 41-brief: AGENT_BRIEF.md - at most ~150 lines for a coding agent, with the
// fixed headings from docs/DEVELOPING.md. Missing data is said, never implied.
// Port of 41-brief.ps1: every section function returns an array of lines (ps1 writes
// them to the pipeline). Data lookups ignore key case, like ps1 hashtables.
// The sections after "Blockers and warnings" are in 41-brief-net.js.
// ---------------------------------------------------------------------------

var ES_BRIEF_TOOL_CATS = ["runtime", "build", "pkg", "vcs", "container", "cloud", "db", "shell"];
var ES_BRIEF_MAX_TOOLS = 40;

// ------------------------------------------------------------------ value helpers

function jsBrief_g(table, key) {
    // $table['key']: null when table is not a table or has no such key (any case).
    if (!esIsTable(table)) { return null; }
    var value = jsHlp_getI(table, key);
    return value === undefined ? null : value;
}

function jsBrief_has(table, key) {
    // $table.ContainsKey('key') (case-insensitive).
    if (!esIsTable(table)) { return false; }
    for (var k in table) {
        if (esHas(table, k) && k.toLowerCase() === String(key).toLowerCase()) { return true; }
    }
    return false;
}

function jsBrief_d(id) {
    var data = getEsData(id);
    return esIsTable(data) ? data : {};
}

function jsBrief_int(value) {
    // [int]$x for counts: null and text that is not a number count as 0.
    if (value === null || value === undefined || value === "") { return 0; }
    var n = Number(value);
    return isNaN(n) ? 0 : Math.round(n);
}

function jsBrief_join(list, separator) {
    // $list -join $separator ([string] of each item).
    var parts = [];
    for (var i = 0; i < list.length; i++) { parts.push(jsMd_str(list[i])); }
    return parts.join(separator);
}

function jsBrief_first(list, count) {
    // Select-Object -First count (nulls skipped).
    return jsMd_selectFirst(list, count);
}

function jsBrief_languageMode() {
    return (typeof ES_LANGUAGE_MODE !== "undefined" && ES_LANGUAGE_MODE) ? String(ES_LANGUAGE_MODE) : "unknown";
}

function formatEsYesNo(value) {
    if (value === null || value === undefined) { return "unknown"; }
    if (jsMd_truthy(value)) { return "yes"; }
    return "no";
}

function formatEsOr(value, dflt) {
    if (value === null || value === undefined || jsMd_str(value) === "") { return dflt === undefined ? "unknown" : jsMd_str(dflt); }
    return jsMd_str(value);
}

function getEsNoneText(id, text) {
    // Text for an empty result: only a probe that completed may say "none".
    var none = (text === undefined) ? "none" : String(text);
    var status = getEsStatus(id);
    if (status === "ok" || status === "not_found" || status === "not_applicable") { return none; }
    if (status === "partial") { return none + " (incomplete; see Not checked)"; }
    return "not checked";
}

function testEsRan(id) {
    // The probe ran to the end (perhaps partly): a default it reports (unset, no) is a fact.
    var status = getEsStatus(id);
    return status === "ok" || status === "partial" || status === "not_found" || status === "not_applicable";
}

function formatEsLongPaths(enabled, enabledText, disabledText) {
    if (enabled === true) { return enabledText; }
    if (enabled === false) { return disabledText; }
    return "unknown";
}

// ------------------------------------------------------------------ Platform

function jsBrief_platformHost() {
    var os = jsBrief_d("os.identity");
    var health = jsBrief_d("os.health");
    var cpu = jsBrief_d("hw.cpu");
    var memory = jsBrief_d("hw.memory");
    var g = jsBrief_g;
    var join = "domain membership unknown";
    if (g(os, "domain_joined") === true) { join = "domain " + jsMd_str(g(os, "domain")); }
    else if (g(os, "domain_joined") === false) { join = "workgroup " + formatEsOr(g(os, "workgroup"), "-"); }
    return [
        "- OS: " + formatEsOr(g(os, "name"), "Windows") + " " + formatEsOr(g(os, "display_version"), "") + " (build " + formatEsOr(g(os, "build")) + ", " + formatEsOr(g(os, "install_type")) + "); arch " + formatEsOr(g(os, "arch")) + ", " + formatEsOr(g(os, "userland_bits")) + "-bit; scanner process " + formatEsOr(g(os, "process_arch")),
        "- Host: " + formatEsOr(g(os, "hostname")) + "; " + join + "; Entra/Azure AD joined: " + formatEsYesNo(g(os, "directory_joined")) + "; last boot " + formatEsOr(g(health, "last_boot_utc")) + "; pending reboot: " + formatEsYesNo(g(health, "pending_reboot")),
        "- Hardware: " + formatEsOr(g(cpu, "model")) + ", " + formatEsOr(g(cpu, "cores")) + " cores / " + formatEsOr(g(cpu, "logical")) + " threads; RAM " + formatEsOr(g(memory, "total_mb")) + " MB (" + formatEsOr(g(memory, "available_mb")) + " MB available); page file " + formatEsOr(g(memory, "swap_total_mb")) + " MB"
    ];
}

function jsBrief_virtLine() {
    var virt = jsBrief_d("virt.platform");
    var g = jsBrief_g;
    var distros = jsMd_where(g(virt, "wsl_distros"));
    var wsl = [];
    for (var i = 0; i < distros.length; i++) { wsl.push(jsMd_str(g(distros[i], "name")) + " (WSL" + jsMd_str(g(distros[i], "version")) + ")"); }
    var container = g(virt, "container");
    var engine = "unknown";
    if (jsMd_truthy(container) && jsMd_truthy(g(container, "detected"))) { engine = jsMd_str(g(container, "engine")); }
    else if (jsMd_truthy(container) && testEsRan("virt.platform")) { engine = "no"; }
    var product = jsMd_truthy(g(virt, "vm_product")) ? " (" + jsMd_str(g(virt, "vm_product")) + ")" : "";
    return "- Virtualization: " + formatEsOr(g(virt, "virtualization")) + product + "; container: " + engine + "; WSL distros: " + (wsl.length > 0 ? wsl.join(", ") : getEsNoneText("virt.platform")) + "; Docker Desktop: " + formatEsYesNo(g(virt, "docker_desktop"));
}

function jsBrief_platformSession() {
    var session = jsBrief_d("session.context");
    var user = jsBrief_d("user.identity");
    var userProfile = jsBrief_d("user.profile");
    var g = jsBrief_g;
    return [
        jsBrief_virtLine(),
        "- Session: " + formatEsOr(g(session, "type")) + " (session " + formatEsOr(g(session, "session_id")) + "), interactive: " + formatEsYesNo(g(session, "interactive")) + ", terminal " + formatEsOr(g(session, "terminal")),
        "- User: " + formatEsOr(g(user, "domain"), "") + "\\" + formatEsOr(g(user, "name")) + "; elevated admin: " + formatEsYesNo(g(user, "is_admin")) + "; profile " + formatEsOr(g(userProfile, "profile_type")) + " at " + formatEsOr(g(userProfile, "home")) + "; Developer Mode: " + formatEsYesNo(g(user, "developer_mode"))
    ];
}

function jsBrief_isWsh() {
    // The scan ran in the Windows Script Host (shell.info of envscan.js): PowerShell was not run.
    return jsHlp_eqI(jsBrief_g(jsBrief_d("shell.info"), "current_shell"), "cscript");
}

function jsBrief_shellText(shell, policy) {
    // The shell part of the Shell line: PowerShell (ps) or the Windows Script Host (WSH port).
    var g = jsBrief_g;
    if (jsBrief_isWsh()) {
        return "Windows Script Host " + formatEsOr(g(shell, "shell_version")) + ", " + formatEsOr(g(shell, "script_engine")) + " (PowerShell not run; execution policy " + policy + " read from the registry)";
    }
    return "PowerShell " + formatEsOr(g(shell, "shell_version")) + " " + formatEsOr(g(shell, "edition"), "") + ", " + jsBrief_languageMode() + "; execution policy " + policy;
}

function jsBrief_platformShell() {
    var shell = jsBrief_d("shell.info");
    var locale = jsBrief_d("os.time_locale");
    var g = jsBrief_g;
    var policy = "unknown";
    var label = jsBrief_isWsh() ? " (Windows PowerShell would use: " : " (this run: ";
    if (jsMd_truthy(g(shell, "execution_policy"))) { policy = formatEsOr(getEsPersistentPolicy(g(shell, "execution_policy"))) + label + formatEsOr(g(shell, "effective_policy")) + ")"; }
    var cmd = "unknown";
    if (testEsRan("shell.info")) { cmd = formatEsYesNo(jsMd_truthy(g(shell, "cmd_disabled")) && jsBrief_int(g(shell, "cmd_disabled")) > 0); }
    return [
        "- Shell: " + jsBrief_shellText(shell, policy) + "; cmd disabled by policy: " + cmd,
        "- Locale: " + formatEsOr(g(locale, "timezone")) + " (UTC" + formatEsOr(g(locale, "utc_offset")) + "), culture " + formatEsOr(g(locale, "locale")) + ", ANSI code page " + formatEsOr(g(locale, "codepage_ansi")) + ", OEM " + formatEsOr(g(locale, "codepage_oem")) + ", decimal separator '" + formatEsOr(g(locale, "decimal_separator")) + "'"
    ];
}

function getEsBriefPlatform() {
    return jsBrief_platformHost().concat(jsBrief_platformSession(), jsBrief_platformShell());
}

// ------------------------------------------------------------------ Runtimes and tools

function formatEsBriefTool(id, tool) {
    var g = jsBrief_g;
    var text = "- " + jsMd_str(g(tool, "name")) + " " + formatEsOr(g(tool, "version"), "(version not read)");
    if (jsMd_truthy(g(tool, "binary_arch"))) { text += " [" + jsMd_str(g(tool, "binary_arch")) + "]"; }
    text += " - " + formatEsMdText(jsMd_str(g(tool, "path")));
    if (jsMd_truthy(g(tool, "reason"))) { text += " (not run: " + jsMd_str(g(tool, "reason")) + ")"; }
    return text;
}

function getEsBriefTools() {
    var tools = jsBrief_g(jsBrief_d("tools.inventory"), "tools");
    if (!jsMd_truthy(tools)) { return ["- Tool inventory not available (see Not checked)."]; }
    var out = [];
    var listed = 0;
    var others = [];
    var ids = jsMd_keys(tools);
    for (var i = 0; i < ids.length; i++) {
        var tool = tools[ids[i]];
        if (!jsMd_truthy(jsBrief_g(tool, "found"))) { continue; }
        if (esContainsI(ES_BRIEF_TOOL_CATS, jsBrief_g(tool, "cat")) && listed < ES_BRIEF_MAX_TOOLS) { out.push(formatEsBriefTool(ids[i], tool)); listed++; }
        else { others.push(ids[i]); }
    }
    if (listed === 0) { out.push("- Runtimes, compilers, package managers: " + getEsNoneText("tools.inventory", "none on PATH or in known locations")); }
    if (others.length > 0) { out.push("- Also present: " + others.join(", ")); }
    return out;
}

function jsBrief_javaLine() {
    var g = jsBrief_g;
    var java = jsBrief_d("runtime.java");
    var items = jsMd_where(g(java, "jdks"));
    var jdks = [];
    for (var i = 0; i < items.length; i++) {
        var j = items[i];
        jdks.push(formatEsOr(g(j, "version")) + " " + formatEsOr(g(j, "vendor"), "") + " [" + formatEsOr(g(j, "arch")) + (jsMd_truthy(g(j, "is_jdk")) ? ", JDK" : ", JRE") + "] " + formatEsMdText(jsMd_str(g(j, "path"))));
    }
    var javaHome = formatEsOr(g(java, "java_home"), testEsRan("runtime.java") ? "unset" : "not checked");
    return "- Java: " + (jdks.length > 0 ? jdks.join("; ") : getEsNoneText("runtime.java")) + "; JAVA_HOME=" + javaHome;
}

function jsBrief_firstTokens(list, separator) {
    // ($_ -split separator)[0] of each truthy item.
    var items = jsMd_where(list);
    var out = [];
    for (var i = 0; i < items.length; i++) { out.push(jsMd_str(items[i]).split(separator)[0]); }
    return out;
}

function jsBrief_dotnetLine() {
    var g = jsBrief_g;
    var dotnet = jsBrief_d("runtime.dotnet");
    var none = getEsNoneText("runtime.dotnet");
    var framework = none;
    var fw = g(dotnet, "framework");
    if (jsMd_truthy(fw) && jsMd_truthy(g(fw, "version"))) { framework = jsMd_str(g(fw, "version")); }
    return "- .NET: Framework " + framework + "; SDKs: " + formatEsOr(jsBrief_firstTokens(g(dotnet, "sdks"), " ").join(", "), none) + "; runtimes: " + formatEsOr(jsBrief_firstTokens(g(dotnet, "runtimes"), " [").join(", "), none);
}

function jsBrief_pythonLine() {
    var g = jsBrief_g;
    var python = jsBrief_d("runtime.python");
    var items = jsMd_where(g(python, "interpreters"));
    var interpreters = [];
    for (var i = 0; i < items.length; i++) {
        if (jsMd_truthy(g(items[i], "store_alias"))) { continue; }
        interpreters.push(formatEsOr(g(items[i], "version")) + " " + formatEsMdText(jsMd_str(g(items[i], "path"))));
    }
    var store = jsMd_where(g(python, "store_packages"));
    if (store.length > 0) { interpreters.push("Microsoft Store Python " + jsBrief_join(store, ", ")); }
    var text = "not checked";
    if (interpreters.length > 0) { text = interpreters.join("; "); }
    else if (getEsStatus("runtime.python") === "not_found") { text = "none installed (Store aliases, if any, only open the Store)"; }
    return "- Python: " + text;
}

function jsBrief_msvcLine() {
    var g = jsBrief_g;
    var msvc = jsBrief_d("toolchain.msvc");
    var items = jsMd_where(g(msvc, "instances"));
    var instances = [];
    for (var i = 0; i < items.length; i++) { instances.push(formatEsOr(g(items[i], "displayName"), "Visual Studio") + " " + formatEsOr(g(items[i], "installationVersion"), "")); }
    return "- C/C++ toolchain: " + (instances.length > 0 ? instances.join("; ") : getEsNoneText("toolchain.msvc", "no Visual Studio instance")) + "; Windows SDKs: " + formatEsOr(jsBrief_join(jsMd_psArray(g(msvc, "windows_sdks")), ", "), getEsNoneText("toolchain.msvc"));
}

function jsBrief_managerLines() {
    var g = jsBrief_g;
    var items = jsMd_where(g(jsBrief_d("runtime.version_managers"), "managers"));
    var managers = [];
    for (var i = 0; i < items.length; i++) {
        var all = jsHlp_list(g(items[i], "versions"));
        var versions = [];
        for (var v = 0; v < all.length && versions.length < 6; v++) { if (!/^\./.test(jsMd_str(all[v]))) { versions.push(all[v]); } }
        managers.push(jsMd_str(g(items[i], "name")) + " (" + formatEsOr(jsBrief_join(versions, ", "), "no versions") + ")");
    }
    return managers.length > 0 ? ["- Version managers (shims not run): " + managers.join("; ")] : [];
}

function jsBrief_nativeLine() {
    var g = jsBrief_g;
    var native = jsBrief_d("native.deps");
    var vcItems = jsMd_where(g(native, "vcredist"));
    var odbcItems = jsMd_where(g(native, "odbc_drivers"));
    var vc = [];
    var odbc = [];
    for (var i = 0; i < vcItems.length; i++) { vc.push(jsMd_str(g(vcItems[i], "arch")) + " " + jsMd_str(g(vcItems[i], "version"))); }
    for (var j = 0; j < odbcItems.length; j++) { odbc.push(g(odbcItems[j], "name")); }
    var none = getEsNoneText("native.deps");
    return "- Native runtimes: UCRT " + formatEsOr(g(native, "ucrt")) + "; VC++ 2015+ redist: " + formatEsOr(jsBrief_join(jsMd_sortUniqueI(vc), ", "), none) + "; WebView2: " + formatEsOr(g(native, "webview2"), none) + "; ODBC drivers: " + formatEsOr(joinEsShort(jsMd_sortUniqueI(odbc), 6), none);
}

function getEsBriefRuntimes() {
    // The runtime lines come from their own probes, so they are written without the inventory too.
    return getEsBriefTools().concat([jsBrief_javaLine(), jsBrief_dotnetLine(), jsBrief_pythonLine(), jsBrief_msvcLine()],
        jsBrief_managerLines(), [jsBrief_nativeLine()]);
}

// ------------------------------------------------------------------ Package sources and caches

function jsBrief_configLine(config) {
    var g = jsBrief_g;
    var lines = jsHlp_list(g(config, "lines"));
    var keyLines = [];
    for (var i = 0; i < lines.length && keyLines.length < 4; i++) {
        if (/registry|index|mirror|url|proxy|source|repositor|cafile|strict-ssl|ssl/i.test(jsMd_str(lines[i]))) { keyLines.push(esTrim(jsMd_str(lines[i]))); }
    }
    var summary = keyLines.length > 0 ? keyLines.join(" | ") : jsMd_psArray(g(config, "lines")).length + " line(s), no registry setting";
    return "- " + jsMd_str(g(config, "tool")) + " config " + formatEsMdText(jsMd_str(g(config, "path"))) + ": " + formatEsMdText(summary);
}

function jsBrief_packageExtras(sources) {
    var g = jsBrief_g;
    var out = [];
    var env = g(sources, "env");
    if (esIsTable(env) && jsMd_count(env) > 0) {
        var keys = jsMd_keys(env);
        var pairs = [];
        for (var i = 0; i < keys.length; i++) { pairs.push(keys[i] + "=" + jsMd_str(env[keys[i]])); }
        out.push("- Package environment: " + pairs.join("; "));
    }
    var items = jsMd_where(g(sources, "git_config"));
    var git = [];
    for (var j = 0; j < items.length; j++) {
        if (/insteadof|proxy|ssl|autocrlf|longpaths|symlinks/i.test(jsMd_str(g(items[j], "key")))) { git.push(jsMd_str(g(items[j], "key")) + "=" + jsMd_str(g(items[j], "value"))); }
    }
    if (git.length > 0) { out.push("- git: " + formatEsMdText(jsBrief_first(git, 10).join("; "))); }
    return out;
}

function getEsBriefPackages() {
    var g = jsBrief_g;
    var sources = jsBrief_d("pkg.sources");
    var internal = jsHlp_list(getEsInternalHosts());
    var out = ["- Internal registries/mirrors: " + (internal.length > 0 ? jsBrief_join(internal, ", ") : getEsNoneText("pkg.sources", "none configured"))];
    var configs = jsMd_where(g(sources, "configs"));
    for (var i = 0; i < configs.length && i < 12; i++) { out.push(jsBrief_configLine(configs[i])); }
    if (configs.length === 0) { out.push("- Package-manager configuration files: " + getEsNoneText("pkg.sources", "none for this user or machine")); }
    out = out.concat(jsBrief_packageExtras(sources));
    var items = jsMd_where(g(jsBrief_d("pkg.caches"), "caches"));
    var caches = [];
    for (var c = 0; c < items.length; c++) { caches.push(jsMd_str(g(items[c], "tool")) + " " + formatEsMdText(jsMd_str(g(items[c], "path"))) + " (" + jsMd_str(g(items[c], "entries")) + " entries)"); }
    out.push("- Offline caches: " + (caches.length > 0 ? caches.join("; ") : getEsNoneText("pkg.caches")));
    return out;
}

// ------------------------------------------------------------------ Blockers and warnings

function getEsBriefFindings(findings, incomplete) {
    var list = jsMd_where(findings);
    var serious = [];
    var info = [];
    for (var i = 0; i < list.length; i++) { if (jsHlp_eqI(list[i].severity, "info")) { info.push(list[i]); } else { serious.push(list[i]); } }
    var out = [];
    // Findings come only from checked facts, so say how much was not checked.
    if (serious.length === 0 && incomplete > 0) { out.push("- No blockers or warnings found; " + incomplete + " probes were not fully checked (see Not checked)."); }
    else if (serious.length === 0) { out.push("- No blockers or warnings."); }
    for (var s = 0; s < serious.length; s++) {
        var f = serious[s];
        out.push("- **" + jsMd_str(f.severity).toUpperCase() + "** " + jsMd_str(f.title) + ": " + formatEsMdText(f.detail) + ". Fix: " + jsMd_str(f.recommendation));
    }
    for (var n = 0; n < info.length; n++) { out.push("- info: " + jsMd_str(info[n].title) + ": " + formatEsMdText(info[n].detail)); }
    return out;
}
