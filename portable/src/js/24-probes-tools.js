// ---------------------------------------------------------------------------
// 24-probes-tools: tool inventory, version managers, Java, .NET, Python, Visual Studio /
// Windows SDK, native runtime libraries (port of src/ps/24-probes-tools.ps1).
// ---------------------------------------------------------------------------

var ES_JAVA_VENDOR_DIRS = ["Java", "Eclipse Adoptium", "Eclipse Foundation", "Microsoft", "Zulu", "Amazon Corretto", "BellSoft", "Semeru", "RedHat", "OpenJDK"];
var ES_FRAMEWORK_RELEASES = [
    [533320, "4.8.1"], [528040, "4.8"], [461808, "4.7.2"], [461308, "4.7.1"], [460798, "4.7"],
    [394802, "4.6.2"], [394254, "4.6.1"], [393295, "4.6"], [379893, "4.5.2"], [378675, "4.5.1"], [378389, "4.5"]
];

// ------------------------------------------------------------------ small helpers (JScript only)

function jsTools_isSet(value) { return value !== null && value !== undefined && String(value) !== ""; }

function jsTools_text(value) { return jsTools_isSet(value) ? String(value) : ""; }

function jsTools_leaf(path) {
    var p = jsGit_trimEnd(String(path), "\\");
    return p.substring(p.lastIndexOf("\\") + 1);
}

function jsTools_cleanPath(path) {
    // PowerShell .Trim().Trim('"'): spaces around, then double quotes around.
    var p = esTrim(String(path));
    while (p.charAt(0) === "\"") { p = p.substring(1); }
    while (p.length > 0 && p.charAt(p.length - 1) === "\"") { p = p.substring(0, p.length - 1); }
    return p;
}

function jsTools_valueI(values, name) {
    // A value of a registry value table by case-insensitive name, or null.
    if (!values) { return null; }
    var lower = name.toLowerCase();
    for (var key in values) {
        if (esHas(values, key) && key.toLowerCase() === lower) { return values[key]; }
    }
    return null;
}

function jsTools_nonEmptyTrimmed(text, pattern) {
    // The trimmed non-empty lines of a text (matching pattern when given).
    var lines = String(text || "").split("\n");
    var out = [];
    for (var i = 0; i < lines.length; i++) {
        var line = esTrim(lines[i]);
        if (line && (!pattern || pattern.test(line))) { out[out.length] = line; }
    }
    return out;
}

function getEsFirstLines(text, count) {
    var lines = String(text || "").split("\n");
    var out = [];
    for (var i = 0; i < lines.length && out.length < count; i++) {
        var line = lines[i].replace(/\r+$/, "");
        if (esTrim(line)) { out[out.length] = line; }
    }
    return out.join("\n");
}

function getEsVersionToken(text) {
    // The first version-like token, skipping the JVM's "Picked up JAVA_TOOL_OPTIONS: ..."
    // banners (printed before the version; their options often hold numbers such as TLSv1.2).
    var lines = String(text || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (/^\s*Picked up (JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS):/i.test(line)) { continue; }
        var m = /(\d+(\.\d+)+[\-+._A-Za-z0-9]*)/.exec(line);
        if (m) {
            var clean = esTrim(line);
            return { version: m[1].substring(0, 40), line: clean.substring(0, 160) };
        }
    }
    return { version: null, line: null };
}

function getEsBinaryArch(path) {
    // The PE machine of a program; not read through a link that is not followed.
    var ext = getEsExtension(path);
    if (testEsAppAlias(path) || (ext !== ".exe" && ext !== ".com")) { return null; }
    if (getEsPathLinkReason(path)) { return null; }
    return getEsPeMachine(path);
}

// ------------------------------------------------------------------ tools.inventory

function jsTools_primary(tool, matchList) {
    // The first match that may be run (a real binary beats a Store alias or shim), else the first.
    for (var i = 0; i < matchList.length; i++) {
        if (!getEsNoRunReason(tool, matchList[i].path)) { return matchList[i]; }
    }
    return matchList[0];
}

function jsTools_newRecord(tool, matchList, primary) {
    var paths = [];
    for (var i = 0; i < matchList.length; i++) { paths[paths.length] = matchList[i].path; }
    return {
        name: tool.name, cat: tool.cat, found: true, path: primary.path, on_path: primary.on_path,
        paths: paths, version: null, version_line: null,
        executed: false, reason: getEsNoRunReason(tool, primary.path), exit_code: null,
        binary_arch: getEsBinaryArch(primary.path)
    };
}

function jsTools_budgetLeft() {
    return ((getEsUtc().getTime() - ES_STARTED.getTime()) / 1000) <= ES_OPT.budget;
}

function getEsToolRecord(result, tool) {
    var matchList = findEsExecutable(tool.exe, tool.dirs);
    if (matchList.length === 0) { return { name: tool.name, cat: tool.cat, found: false }; }
    var primary = jsTools_primary(tool, matchList);
    var record = jsTools_newRecord(tool, matchList, primary);
    if (record.reason) { return record; }
    if (!jsTools_budgetLeft()) {
        record.reason = "scan budget exhausted";
        addEsNote(result, "scan budget exhausted before every tool version was read", "partial");
        return record;
    }
    var run = invokeEsCommand(primary.path, tool.args, 0, undefined, 80);
    result.sources[result.sources.length] = "run " + run.command;
    record.executed = true;
    record.exit_code = run.exit_code;
    var text = getEsCommandText(run);
    if (run.timed_out) { record.reason = "timed out"; addEsNote(result, tool.id + ": timed out", "partial"); }
    else if (run.error) { record.reason = run.error; }
    var token = getEsVersionToken(text);
    record.version = token.version;
    record.version_line = token.line;
    if (text) { result.raw[tool.id] = getEsFirstLines(text, 6); }
    return record;
}

function probe_tools_inventory() {
    var r = newEsResult();
    r.sources = r.sources.concat(["list PATH directories (" + getEsPathDirs().length + " local)", "known install directories from spec/tools.toml"]);
    var tools = {};
    var found = 0;
    var executed = 0;
    for (var i = 0; i < ES_TOOLS.length; i++) {
        var record = getEsToolRecord(r, ES_TOOLS[i]);
        tools[ES_TOOLS[i].id] = record;
        if (record.found) { found++; }
        if (record.executed) { executed++; }
    }
    r.data.tools = tools;
    r.data.found_count = found;
    r.data.executed_count = executed;
    r.data.searched_count = ES_TOOLS.length;
    r.data.link_dirs = ES_PATH_LINK_DIRS.slice(0);
    addEsPathLinkNotes(r);
    return r;
}

function jsTools_linkNote(result, id, tool) {
    // A tool found only in a folder that is a link (FSO cannot read its target) is never run;
    // the probe says so, since its version is not known.
    var reason = (tool && tool.found) ? jsTools_text(tool.reason) : "";
    if (reason.indexOf("link target unknown") !== 0) { return; }
    addEsNote(result, id + " found at " + tool.path + " (link target unknown; not run, version not read)", "");
}

function getEsTool(id) {
    var tools = getEsData("tools.inventory")["tools"];
    if (tools && esHas(tools, id)) { return tools[id]; }
    return null;
}

// ------------------------------------------------------------------ runtime.version_managers

function jsTools_shimDirs(manager, dirs) {
    var shims = [];
    for (var i = 0; i < dirs.length; i++) {
        var lower = dirs[i].toLowerCase().replace(/\\/g, "/");
        for (var j = 0; j < manager.markers.length; j++) {
            if (manager.markers[j] && lower.indexOf(String(manager.markers[j])) >= 0) { shims[shims.length] = dirs[i]; break; }
        }
    }
    return shims;
}

function jsTools_managerVersions(r, manager) {
    var versions = [];
    for (var i = 0; i < manager.versions.length; i++) {
        var pattern = String(manager.versions[i]);
        r.sources[r.sources.length] = "list " + pattern;
        var nested = pattern.length >= 3 && pattern.substring(pattern.length - 3) === "*/*";
        var paths = expandEsPathPattern(pattern, r);
        for (var j = 0; j < paths.length; j++) {
            if (!esIsDir(paths[j])) { continue; }
            var label = jsTools_leaf(paths[j]);
            if (nested) { label = jsTools_leaf(getEsParentDir(jsGit_trimEnd(paths[j], "\\"))) + "/" + label; }
            if (!esContainsI(versions, label)) { versions[versions.length] = label; }
        }
    }
    return versions;
}

function probe_runtime_version_managers() {
    var r = newEsResult();
    var managers = [];
    var dirs = getEsPathDirs();
    for (var i = 0; i < ES_VMANAGERS.length; i++) {
        var manager = ES_VMANAGERS[i];
        var shims = jsTools_shimDirs(manager, dirs);
        var versions = jsTools_managerVersions(r, manager);
        if (shims.length > 0 || versions.length > 0) {
            managers[managers.length] = { id: manager.id, name: manager.name, shim_dirs: shims, versions: versions };
        }
    }
    r.data.managers = managers;
    r.data.nvm_symlink = getEsOrigEnv("NVM_SYMLINK");
    if (managers.length === 0) { r.status = "not_found"; }
    addEsPathLinkNotes(r);
    return r;
}

// ------------------------------------------------------------------ Java

function readEsJavaRelease(result, javaHome) {
    // The release file of a Java home (a missing one is common and not noted; one that is a
    // link off the local disk is noted and not read).
    var info = { version: null, vendor: null, arch: null, image: null };
    var path = esJoinPath(javaHome, "release");
    var release = readEsTextFile(path, 8192);
    addEsReadNote(result, path, release.error);
    var names = { JAVA_VERSION: "version", IMPLEMENTOR: "vendor", OS_ARCH: "arch", IMAGE_TYPE: "image" };
    var lines = String(release.text || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
        var m = /^\s*(JAVA_VERSION|IMPLEMENTOR|OS_ARCH|IMAGE_TYPE)\s*=\s*"?([^"]*)"?/i.exec(lines[i]);
        if (m) { info[names[m[1].toUpperCase()]] = m[2]; }
    }
    return info;
}

function addEsJavaHome(homes, path, source) {
    if (!path) { return; }
    var clean = jsGit_trimEnd(jsTools_cleanPath(path), "\\");
    if (!testEsLocalPath(clean)) { return; }
    if (!testEsSafePath(esJoinPath(clean, "bin\\java.exe"), "Leaf")) { return; }
    var key = clean.toLowerCase();
    if (!esHas(homes, key)) { homes[key] = { path: clean, source: source }; }
}

function jsTools_javaRoots() {
    var roots = [];
    var programs = [getEsOrigEnv("ProgramFiles"), getEsOrigEnv("ProgramFiles(x86)")];
    for (var i = 0; i < programs.length; i++) {
        if (!programs[i]) { continue; }
        for (var j = 0; j < ES_JAVA_VENDOR_DIRS.length; j++) { roots[roots.length] = esJoinPath(programs[i], ES_JAVA_VENDOR_DIRS[j]); }
    }
    var profilePath = getEsOrigEnv("USERPROFILE");
    if (profilePath) { roots[roots.length] = esJoinPath(profilePath, ".jdks"); }
    return roots;
}

function addEsJavaInstallDirs(result, homes) {
    // Java homes in the vendor folders under Program Files and in ~\.jdks (IntelliJ downloads).
    var roots = jsTools_javaRoots();
    for (var i = 0; i < roots.length; i++) {
        if (!testEsLocalPath(roots[i]) || !testEsListableFolder(result, roots[i])) { continue; }
        result.sources[result.sources.length] = "list " + roots[i];
        var dirs = jsPkg_subdirs(roots[i], 200);
        for (var j = 0; j < dirs.length; j++) { addEsJavaHome(homes, dirs[j].path, "install directory"); }
    }
}

function jsTools_javaRegistryHomes(r, homes) {
    var views = ["SOFTWARE", "SOFTWARE\\WOW6432Node"];
    var kinds = ["JDK", "JRE", "Java Development Kit", "Java Runtime Environment"];
    for (var i = 0; i < views.length; i++) {
        for (var j = 0; j < kinds.length; j++) {
            var base = "HKLM:\\" + views[i] + "\\JavaSoft\\" + kinds[j];
            var versions = getEsRegSubkeys(base);
            for (var k = 0; k < versions.length; k++) {
                addEsJavaHome(homes, getEsRegValue(base + "\\" + versions[k], "JavaHome"), "registry");
            }
        }
        r.sources[r.sources.length] = "registry HKLM\\" + views[i] + "\\JavaSoft";
    }
}

function jsTools_jdkEntry(r, entry) {
    var release = readEsJavaRelease(r, entry.path);
    r.sources[r.sources.length] = "read " + esJoinPath(entry.path, "release");
    return {
        path: entry.path, source: entry.source, version: release.version, vendor: release.vendor,
        arch: getEsPeMachine(esJoinPath(entry.path, "bin\\java.exe")), release_arch: release.arch,
        is_jdk: esIsFile(esJoinPath(entry.path, "bin\\javac.exe")), image_type: release.image
    };
}

function probe_runtime_java() {
    var r = newEsResult();
    var homes = {};
    var javaHome = getEsOrigEnv("JAVA_HOME");
    r.sources[r.sources.length] = "environment JAVA_HOME";
    addEsJavaHome(homes, javaHome, "JAVA_HOME");
    var pathJava = getEsTool("java");
    if (pathJava && pathJava.found && /\\bin\\java\.exe$/i.test(String(pathJava.path))) {
        addEsJavaHome(homes, getEsParentDir(getEsParentDir(String(pathJava.path))), "PATH");
    }
    jsTools_javaRegistryHomes(r, homes);
    addEsJavaInstallDirs(r, homes);
    var keys = esKeys(homes);
    var jdks = [];
    for (var i = 0; i < keys.length; i++) { jdks[jdks.length] = jsTools_jdkEntry(r, homes[keys[i]]); }
    r.data.java_home = javaHome;
    r.data.java_home_valid = javaHome ? esHas(homes, jsGit_trimEnd(jsTools_cleanPath(javaHome), "\\").toLowerCase()) : null;
    r.data.path_java = (pathJava && pathJava.found) ? { path: pathJava.path, version: pathJava.version } : null;
    jsTools_linkNote(r, "java", pathJava);
    r.data.jdks = jdks;
    if (jdks.length === 0) { r.status = "not_found"; }
    if (javaHome && !r.data.java_home_valid) { addEsNote(r, "JAVA_HOME does not point to a Java installation", ""); }
    addEsPathLinkNotes(r);
    return r;
}

// ------------------------------------------------------------------ .NET

function jsTools_frameworkVersion(release) {
    if (!jsTools_isSet(release)) { return null; }
    var n = parseInt(String(release), 10);
    for (var i = 0; i < ES_FRAMEWORK_RELEASES.length; i++) {
        if (n >= ES_FRAMEWORK_RELEASES[i][0]) { return ES_FRAMEWORK_RELEASES[i][1]; }
    }
    return null;
}

function jsTools_dotnetLists(r, d, dotnet) {
    var pairs = [["sdks", "--list-sdks"], ["runtimes", "--list-runtimes"]];
    for (var i = 0; i < pairs.length; i++) {
        // An empty list is valid (runtime-only install); only a failed run is incomplete.
        var run = invokeEsTool(r, "dotnet " + pairs[i][1], dotnet, [pairs[i][1]], 0, undefined, true);
        if (run.exit_code !== null && run.exit_code !== undefined && run.exit_code !== 0) {
            addEsNote(r, "dotnet " + pairs[i][1] + ": exit code " + run.exit_code, "partial");
        }
        d[pairs[i][0]] = jsTools_nonEmptyTrimmed(run.stdout, /^\S+ (\d|\[)/);
    }
}

function jsTools_dotnetFolders(r, d) {
    var programFiles = jsTools_text(getEsOrigEnv("ProgramFiles"));
    if (!testEsLocalPath(programFiles)) { return; }
    var pairs = [["sdks", "sdk"], ["runtimes", "shared\\Microsoft.NETCore.App"]];
    for (var i = 0; i < pairs.length; i++) {
        var dir = esJoinPath(esJoinPath(programFiles, "dotnet"), pairs[i][1]);
        if (!testEsSafePath(dir, "Container")) { continue; }
        r.sources[r.sources.length] = "list " + dir;
        var names = [];
        var dirs = jsPkg_subdirs(dir, 200);
        for (var j = 0; j < dirs.length; j++) { if (/^\d/.test(dirs[j].name)) { names[names.length] = dirs[j].name; } }
        d[pairs[i][0]] = names;
    }
}

function probe_runtime_dotnet() {
    var r = newEsResult();
    var d = r.data;
    var ndp = "HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP";
    r.sources[r.sources.length] = "registry HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP";
    var release = getEsRegValue(ndp + "\\v4\\Full", "Release");
    var version = jsTools_frameworkVersion(release);
    d.framework = { release: jsTools_isSet(release) ? release : null, version: version };
    var legacy = [];
    var names = ["v2.0.50727", "v3.0", "v3.5"];
    for (var i = 0; i < names.length; i++) {
        if (jsTools_text(getEsRegValue(ndp + "\\" + names[i], "Install")) === "1") { legacy[legacy.length] = names[i]; }
    }
    d.framework_legacy = legacy;
    d.sdks = [];
    d.runtimes = [];
    var tool = getEsTool("dotnet");
    jsTools_linkNote(r, "dotnet", tool);
    if (tool && tool.found && !tool.reason) { jsTools_dotnetLists(r, d, String(tool.path)); }
    else { jsTools_dotnetFolders(r, d); }
    if (!version && legacy.length === 0 && d.sdks.length === 0 && d.runtimes.length === 0) { r.status = "not_found"; }
    addEsPathLinkNotes(r);
    return r;
}

// ------------------------------------------------------------------ Python

var ES_STORE_PYTHON_RE = /^PythonSoftwareFoundation\.Python\.(\d+\.\d+)_/i;
var ES_PYTHON_PATTERNS = ["{env:LOCALAPPDATA}/Programs/Python/Python*/python.exe", "{env:ProgramFiles}/Python*/python.exe",
    "{env:ProgramFiles(x86)}/Python*/python.exe", "{env:SystemDrive}/Python*/python.exe", "~/miniconda3/python.exe",
    "~/anaconda3/python.exe", "{env:ProgramData}/miniconda3/python.exe", "{env:ProgramData}/anaconda3/python.exe",
    "~/.pyenv/pyenv-win/versions/*/python.exe"];
var ES_PYTHONCORE_KEYS = ["HKCU:\\SOFTWARE\\Python\\PythonCore", "HKLM:\\SOFTWARE\\Python\\PythonCore", "HKLM:\\SOFTWARE\\WOW6432Node\\Python\\PythonCore"];

function getEsStorePythons() {
    var apps = esJoinPath(jsTools_text(getEsOrigEnv("LOCALAPPDATA")), "Microsoft\\WindowsApps");
    var out = [];
    if (!testEsLocalPath(apps)) { return out; }
    var dirs = jsPkg_subdirs(apps, 500);
    for (var i = 0; i < dirs.length; i++) {
        var m = ES_STORE_PYTHON_RE.exec(dirs[i].name);
        if (m) { out[out.length] = m[1]; }
    }
    return out;
}

function jsTools_storeAliasExists(path) {
    // A Store app-execution alias (a reparse point in WindowsApps) is listed as ps lists it,
    // without following it; the folders above it must not be links.
    if (!testEsAppAlias(path) || getEsRefusedFolder(path)) { return false; }
    try { return !!ES_FSO.FileExists(path); } catch (e) { return false; }
}

function addEsPythonCandidate(seen, path, source) {
    if (!path) { return; }
    var clean = jsTools_cleanPath(path);
    if (!testEsLocalPath(clean)) { return; }
    if (!jsTools_storeAliasExists(clean) && !testEsSafePath(clean, "Leaf")) { return; }
    var key = clean.toLowerCase();
    if (!esHas(seen, key)) { seen[key] = { path: clean, source: source }; }
}

function jsTools_regDefault(path) {
    // The default value of a key (Get-ItemProperty "(default)"): RegRead of "<key>\\".
    var split = esRegSplit(path);
    if (!split) { return null; }
    try { return ES_SHELL.RegRead(split.shell + "\\"); } catch (e) { return null; }
}

function jsTools_pythonCoreExe(base, version) {
    var key = base + "\\" + version + "\\InstallPath";
    var exe = getEsRegValue(key, "ExecutablePath");
    if (exe) { return String(exe); }
    var dir = jsTools_regDefault(key);
    return dir ? esJoinPath(String(dir), "python.exe") : null;
}

function findEsPythonCandidates(result) {
    // Interpreter candidates from PATH, known install folders and the PythonCore registry keys.
    var seen = {};
    var i;
    var matches = findEsExecutable(["python", "python3"], []);
    for (i = 0; i < matches.length; i++) { addEsPythonCandidate(seen, matches[i].path, "PATH"); }
    for (i = 0; i < ES_PYTHON_PATTERNS.length; i++) {
        var paths = expandEsPathPattern(ES_PYTHON_PATTERNS[i], result);
        for (var j = 0; j < paths.length; j++) { addEsPythonCandidate(seen, paths[j], "install directory"); }
    }
    result.sources = result.sources.concat(["list PATH and known Python install directories", "registry HKLM and HKCU \\SOFTWARE\\Python\\PythonCore"]);
    for (i = 0; i < ES_PYTHONCORE_KEYS.length; i++) {
        var versions = getEsRegSubkeys(ES_PYTHONCORE_KEYS[i]);
        for (var k = 0; k < versions.length; k++) {
            addEsPythonCandidate(seen, jsTools_pythonCoreExe(ES_PYTHONCORE_KEYS[i], versions[k]), "registry");
        }
    }
    return seen;
}

function getEsPyLauncherList(result) {
    // Interpreters registered with the py launcher (py -0p), when a runnable launcher exists.
    var rule = { id: "py", mode: "version" };
    var found = findEsExecutable(["py"], ["{env:SystemRoot}", "{env:LOCALAPPDATA}/Programs/Python/Launcher"]);
    for (var i = 0; i < found.length; i++) {
        if (getEsNoRunReason(rule, found[i].path)) { continue; }
        var run = invokeEsTool(result, "py -0p", found[i].path, ["-0p"]);
        return jsTools_nonEmptyTrimmed(run.stdout, null);
    }
    return [];
}

function jsTools_pythonEntry(r, candidate, state) {
    // One interpreter; run with --version (at most 10 runs) unless it must never run.
    var pythonTool = { id: "python", mode: "version" };
    // Never run shims (pyenv-win .bat, .ps1), Store aliases or other non-executables.
    var noRun = getEsNoRunReason(pythonTool, candidate.path);
    var entry = { path: candidate.path, source: candidate.source, store_alias: testEsAppAlias(candidate.path), version: null, arch: null, not_run: noRun };
    if (!noRun && state.runs < 10) {
        state.runs++;
        var run = invokeEsTool(r, "python " + state.runs, candidate.path, ["--version"]);
        entry.version = getEsVersionToken(getEsCommandText(run)).version;
        entry.arch = getEsPeMachine(candidate.path);
    }
    return entry;
}

function probe_runtime_python() {
    var r = newEsResult();
    var seen = findEsPythonCandidates(r);
    var store = getEsStorePythons();
    var interpreters = [];
    var state = { runs: 0 };
    var keys = esKeys(seen);
    var real = 0;
    for (var i = 0; i < keys.length; i++) {
        var entry = jsTools_pythonEntry(r, seen[keys[i]], state);
        interpreters[interpreters.length] = entry;
        if (!entry.store_alias && !entry.not_run) { real++; }
    }
    r.data.interpreters = interpreters;
    r.data.launcher = getEsPyLauncherList(r);
    r.data.store_packages = store;
    r.data.real_count = real + store.length;
    if (r.data.real_count === 0) {
        r.status = "not_found";
        if (interpreters.length > 0) { addEsNote(r, "only Microsoft Store aliases or shims that are never run were found; no runnable Python interpreter", ""); }
    }
    addEsPathLinkNotes(r);
    return r;
}

// ------------------------------------------------------------------ Visual Studio and SDKs

var ES_VSWHERE_WANTED = ["instanceId", "installationName", "installationPath", "installationVersion", "displayName", "productId", "isComplete", "isPrerelease"];

function jsTools_parseVswhere(text) {
    // The instances in vswhere -format text output: "name: value" lines, each instance from
    // its instanceId line on.
    var instances = [];
    var current = null;
    var lines = String(text || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
        var m = /^([A-Za-z_]+):\s?([\s\S]*)$/.exec(lines[i]);
        if (!m) { continue; }
        if (m[1].toLowerCase() === "instanceid") {
            if (current) { instances[instances.length] = current; }
            current = {};
        }
        if (current && esContainsI(ES_VSWHERE_WANTED, m[1])) { current[m[1]] = m[2].replace(/\r+$/, ""); }
    }
    if (current) { instances[instances.length] = current; }
    return instances;
}

function jsTools_windowsSdks(r) {
    var sdks = [];
    var views = ["SOFTWARE", "SOFTWARE\\WOW6432Node"];
    for (var i = 0; i < views.length; i++) {
        r.sources[r.sources.length] = "registry HKLM\\" + views[i] + "\\Microsoft\\Windows Kits\\Installed Roots";
        var root = getEsRegValue("HKLM:\\" + views[i] + "\\Microsoft\\Windows Kits\\Installed Roots", "KitsRoot10");
        if (!root) { continue; }
        var include = esJoinPath(String(root), "Include");
        if (!testEsLocalPath(include) || !testEsSafePath(include, "Container")) { continue; }
        r.sources[r.sources.length] = "list " + include;
        var dirs = jsPkg_subdirs(include, 100);
        for (var j = 0; j < dirs.length; j++) {
            if (/^10\./.test(dirs[j].name) && !esContainsI(sdks, dirs[j].name)) { sdks[sdks.length] = dirs[j].name; }
        }
    }
    return sdks.sort(jsPkg_compareI);
}

function probe_toolchain_msvc() {
    var r = newEsResult();
    var d = r.data;
    d.instances = [];
    // ProgramFiles(x86) does not exist on 32-bit Windows.
    var programFiles = jsTools_text(getEsOrigEnv("ProgramFiles(x86)")) || jsTools_text(getEsOrigEnv("ProgramFiles"));
    var vswhere = testEsLocalPath(programFiles) ? esJoinPath(programFiles, "Microsoft Visual Studio\\Installer\\vswhere.exe") : null;
    if (vswhere && testEsSafePath(vswhere, "Leaf")) {
        var run = invokeEsTool(r, "vswhere", vswhere, ["-all", "-products", "*", "-format", "text", "-nologo", "-utf8"], 0, "UTF8", true);
        d.instances = jsTools_parseVswhere(run.stdout);
    }
    var sdks = jsTools_windowsSdks(r);
    d.windows_sdks = sdks;
    var msbuild = getEsTool("msbuild");
    d.msbuild = (msbuild && msbuild.found) ? { path: msbuild.path, version: msbuild.version } : null;
    jsTools_linkNote(r, "msbuild", msbuild);
    var cl = getEsTool("cl");
    jsTools_linkNote(r, "cl", cl);
    d.cl_on_path = !!(cl && cl.found);
    if (d.instances.length === 0 && sdks.length === 0 && !d.msbuild) { r.status = "not_found"; }
    addEsPathLinkNotes(r);
    return r;
}

// ------------------------------------------------------------------ native libraries

function jsTools_vcRuntimes(r) {
    var vc = [];
    var views = [["SOFTWARE", ""], ["SOFTWARE\\WOW6432Node", "(32-bit view)"]];
    for (var i = 0; i < views.length; i++) {
        var base = "HKLM:\\" + views[i][0] + "\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes";
        r.sources[r.sources.length] = "registry HKLM\\" + views[i][0] + "\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes";
        var archs = getEsRegSubkeys(base);
        for (var j = 0; j < archs.length; j++) {
            var values = getEsRegValues(base + "\\" + archs[j]);
            if (values && jsTools_text(jsTools_valueI(values, "Installed")) === "1") {
                vc[vc.length] = { arch: archs[j].toLowerCase(), version: jsTools_text(jsTools_valueI(values, "Version")), view: views[i][1] };
            }
        }
    }
    return vc;
}

function jsTools_ucrtVersion(r) {
    // The file version of ucrtbase.dll. FSO GetFileVersion gives the numeric version only
    // (e.g. 10.0.26100.1); ps reads FileVersion, which may add " (WinBuild.160101.0800)".
    // Accepted difference: no other allowed source has the version string.
    var ucrtPath = esJoinPath(jsTools_text(getEsEnv("SystemRoot")), "System32\\ucrtbase.dll");
    r.sources[r.sources.length] = "read version of " + ucrtPath;
    try {
        var version = String(ES_FSO.GetFileVersion(ucrtPath));
        return version ? version : null;
    } catch (e) { return null; }
}

var ES_WEBVIEW2_KEYS = ["HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "HKLM:\\SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "HKCU:\\Software\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"];

function jsTools_webview2() {
    for (var i = 0; i < ES_WEBVIEW2_KEYS.length; i++) {
        var version = getEsRegValue(ES_WEBVIEW2_KEYS[i], "pv");
        if (jsTools_isSet(version) && String(version) !== "0.0.0.0") { return String(version); }
    }
    return null;
}

function jsTools_odbcDrivers(r) {
    var odbc = [];
    var views = [["SOFTWARE", 64], ["SOFTWARE\\WOW6432Node", 32]];
    for (var i = 0; i < views.length; i++) {
        r.sources[r.sources.length] = "registry HKLM\\" + views[i][0] + "\\ODBC\\ODBCINST.INI\\ODBC Drivers";
        var values = getEsRegValues("HKLM:\\" + views[i][0] + "\\ODBC\\ODBCINST.INI\\ODBC Drivers");
        if (!values) { continue; }
        var names = esKeys(values).sort(jsPkg_compareI);
        for (var j = 0; j < names.length; j++) { odbc[odbc.length] = { name: names[j], bits: views[i][1] }; }
    }
    return odbc;
}

function jsTools_oracleHomes(r) {
    var oracle = [];
    var views = ["SOFTWARE", "SOFTWARE\\WOW6432Node"];
    for (var i = 0; i < views.length; i++) {
        var base = "HKLM:\\" + views[i] + "\\ORACLE";
        r.sources[r.sources.length] = "registry HKLM\\" + views[i] + "\\ORACLE";
        var names = getEsRegSubkeys(base);
        for (var j = 0; j < names.length; j++) {
            if (!/^KEY_/i.test(names[j])) { continue; }
            oracle[oracle.length] = { name: names[j], home: jsTools_text(getEsRegValue(base + "\\" + names[j], "ORACLE_HOME")) };
        }
    }
    return oracle;
}

function probe_native_deps() {
    var r = newEsResult();
    var d = r.data;
    d.vcredist = jsTools_vcRuntimes(r);
    var ucrt = jsTools_ucrtVersion(r);
    d.ucrt = ucrt;
    d.libc = { kind: "ucrt", version: ucrt };
    d.webview2 = jsTools_webview2();
    r.sources[r.sources.length] = "registry HKLM and HKCU EdgeUpdate\\Clients (WebView2 runtime)";
    d.odbc_drivers = jsTools_odbcDrivers(r);
    d.oracle_homes = jsTools_oracleHomes(r);
    d.glibcxx_max = null;
    d.libssl = [];
    return r;
}
