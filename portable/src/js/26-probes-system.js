// ---------------------------------------------------------------------------
// 26-probes-system: writable locations, file system semantics, execution test
// (deep), processes, services, scheduled tasks. Port of src/ps/26-probes-system.ps1.
// JScript has no ACL API: where the ps1 reads a directory ACL (system drive root, Program
// Files, personal and synced folders), writability is unknown (null) with a note.
// ---------------------------------------------------------------------------

var ES_MAX_PROCESSES = 600;
var ES_MAX_SERVICES = 800;
var ES_MAX_TASKS = 300;
var ES_INSTALL_LOCATION_IDS = ["local_programs", "local_appdata", "programdata", "home", "system_drive_root"];
// The deep exec test writes and runs scripts only where no other user can write.
var ES_EXEC_TEST_IDS = ["temp", "local_appdata", "local_programs", "appdata", "home"];
var ES_CMD_META_RE = /[&|<>^%!()"]/;

function jsSys_str(value) {
    // PowerShell [string] cast: $null -> "".
    return (value === null || value === undefined) ? "" : String(value);
}

function jsSys_trimEndSlash(text) { return jsSys_str(text).replace(/\\+$/, ""); }

function jsSys_parent(path) {
    // Split-Path -Parent.
    var text = jsSys_str(path);
    var cut = text.lastIndexOf("\\");
    if (cut < 0) { return null; }
    var parent = text.substring(0, cut);
    return (/^[A-Za-z]:$/.test(parent)) ? parent + "\\" : parent;
}

function joinEsPathSafe(parent, child) {
    if (!parent) { return null; }
    return esJoinPath(parent, child);
}

function jsSys_currentDir() {
    // The directory the scan was started from (the ps1 reads Get-Location).
    if (typeof ES_START_CWD != "undefined" && ES_START_CWD) { return ES_START_CWD; }
    try { return String(ES_SHELL.CurrentDirectory); } catch (e) { return null; }
}

function getEsCandidateDirs() {
    var scriptDir = ES_SCRIPT_PATH ? jsSys_parent(ES_SCRIPT_PATH) : null;
    var drive = jsSys_str(getEsOrigEnv("SystemDrive"));
    if (!drive) { drive = "C:"; }
    var local = getEsOrigEnv("LOCALAPPDATA");
    return jsSys_withoutCredentialStores([
        { id: "temp", path: getEsOrigEnv("TEMP"), method: "write-test" },
        { id: "local_appdata", path: local, method: "write-test" },
        { id: "local_programs", path: joinEsPathSafe(local, "Programs"), method: "write-test" },
        { id: "appdata", path: getEsOrigEnv("APPDATA"), method: "write-test" },
        { id: "home", path: getEsOrigEnv("USERPROFILE"), method: "write-test" },
        { id: "programdata", path: getEsOrigEnv("ProgramData"), method: "write-test" },
        { id: "cwd", path: jsSys_currentDir(), method: "write-test" },
        { id: "script_dir", path: scriptDir, method: "write-test" },
        { id: "system_drive_root", path: drive + "\\", method: "acl" },
        { id: "program_files", path: getEsOrigEnv("ProgramFiles"), method: "acl" }
    ]);
}

function jsSys_withoutCredentialStores(candidates) {
    // A location in or below a credential store (cwd or TEMP in ~\.ssh, ...) is never tested,
    // listed or written: it is left out (and logged).
    var out = [];
    for (var i = 0; i < candidates.length; i++) {
        if (candidates[i].path && getEsCredentialFolder(String(candidates[i].path))) {
            writeEsLog("fs.locations: " + candidates[i].id + " skipped (credential store)");
            continue;
        }
        out.push(candidates[i]);
    }
    return out;
}

function jsSys_expand(value) {
    // A REG_EXPAND_SZ shell folder as Get-ItemProperty returns it: expanded.
    var text = jsSys_str(value);
    if (text.indexOf("%") < 0) { return text; }
    try { return String(ES_SHELL.ExpandEnvironmentStrings(text)); } catch (e) { return text; }
}

function jsSys_lowerUnique(folders) {
    // Where-Object { $_ } | TrimEnd('\') lower-case | Sort-Object -Unique.
    var out = [];
    for (var i = 0; i < folders.length; i++) {
        if (!folders[i]) { continue; }
        var folder = esLower(jsSys_trimEndSlash(folders[i]));
        if (!esContains(out, folder)) { out.push(folder); }
    }
    out.sort();
    return out;
}

function getEsPersonalFolders() {
    // Desktop, Documents and OneDrive roots (lower-case): never written to; synced folders
    // would also upload a test file.
    var folders = [];
    var profilePath = jsSys_str(getEsOrigEnv("USERPROFILE"));
    if (profilePath) { folders.push(esJoinPath(profilePath, "Desktop"), esJoinPath(profilePath, "Documents")); }
    var shell = getEsRegValues("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");
    var names = ["Desktop", "Personal", "{F42EE2D3-909F-4907-8871-4C22FC0BF756}"];
    for (var i = 0; i < names.length; i++) {
        var value = jsNet_pick(shell, names[i]);
        if (value) { folders.push(jsSys_expand(value)); }
    }
    folders.push(getEsOrigEnv("OneDrive"), getEsOrigEnv("OneDriveCommercial"), getEsOrigEnv("OneDriveConsumer"));
    return jsSys_lowerUnique(folders);
}

function testEsUnderFolder(path, folders) {
    var lower = esLower(jsSys_trimEndSlash(path));
    for (var i = 0; i < folders.length; i++) {
        if (lower == folders[i] || esStartsWith(lower, folders[i] + "\\")) { return true; }
    }
    return false;
}

function jsSys_oneDriveRoots() {
    var roots = [getEsOrigEnv("OneDrive"), getEsOrigEnv("OneDriveCommercial"), getEsOrigEnv("OneDriveConsumer")];
    var out = [];
    for (var i = 0; i < roots.length; i++) { if (roots[i]) { out.push(esLower(jsSys_trimEndSlash(roots[i]))); } }
    return out;
}

function jsSys_newLocation(candidate) {
    var path = jsSys_str(candidate.path);
    return {
        id: candidate.id, path: path ? path : null, method: candidate.method, exists: false,
        writable: null, can_create_dirs: null, free_mb: null, fstype: null, network: false, onedrive: false, noexec: null
    };
}

function jsSys_checkLocation(r, entry, ctx) {
    var path = entry.path;
    entry.network = testEsNetworkPath(path);
    entry.onedrive = testEsUnderFolder(path, ctx.oneDrive);
    if (entry.method == "write-test" && testEsUnderFolder(path, ctx.personal)) {
        // Desktop, Documents and synced folders: judged from the ACL, no file written.
        entry.method = "acl";
        entry.write_test_skipped = "personal or synced folder";
    }
    if (!testEsLocalPath(path)) { return; }
    entry.exists = testEsSafePath(path, "Container");
    if (entry.exists && entry.method == "write-test") {
        r.sources.push("write and delete a test file in " + path);
        entry.writable = testEsWritableDir(path);
    } else if (entry.exists) {
        var access = getEsSddlAccess(path);
        entry.writable = access.create_files;
        entry.can_create_dirs = access.create_dirs;
        if (entry.writable === null || entry.writable === undefined) { ctx.unknown.push(entry.id); }
    }
    var volume = getEsVolumeFor(path);
    if (volume) { entry.free_mb = volume["free_mb"]; entry.fstype = volume["fstype"]; }
}

function jsSys_installIds(locations) {
    var install = [];
    for (var i = 0; i < locations.length; i++) {
        var l = locations[i];
        if (esContains(ES_INSTALL_LOCATION_IDS, l.id) && (l.writable === true || (l.id == "system_drive_root" && l.can_create_dirs === true))) {
            install.push(l.id);
        }
    }
    return install;
}

function probe_fs_locations() {
    var r = newEsResult();
    var ctx = { personal: getEsPersonalFolders(), oneDrive: jsSys_oneDriveRoots(), unknown: [] };
    r.sources.push("registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders (Desktop, Documents)");
    var locations = [];
    var candidates = getEsCandidateDirs();
    for (var i = 0; i < candidates.length; i++) {
        var entry = jsSys_newLocation(candidates[i]);
        if (entry.path) { jsSys_checkLocation(r, entry, ctx); }
        locations.push(entry);
    }
    r.data.locations = locations;
    r.data.writable_install_locations = jsSys_installIds(locations);
    if (ctx.unknown.length > 0) {
        addEsNote(r, "directory ACLs cannot be read in the WSH port: writability unknown for " + ctx.unknown.join(", ") + " (no test file is written there)", "partial");
    }
    return r;
}

// ------------------------------------------------------------------ file system semantics

function jsSys_exists(path) {
    // Test-Path -LiteralPath: a file, a folder, or a link to either.
    try { return ES_FSO.FileExists(path) || ES_FSO.FolderExists(path); } catch (e) { return false; }
}

function getEsLinkOutcome(link, text) {
    if (jsSys_exists(link)) { return { result: "ok", detail: null }; }
    var detail = esTrim(jsSys_str(text));
    if (detail.length > 200) { detail = detail.substring(0, 200); }
    if (/privilege|1314|Administrator/i.test(detail)) { return { result: "denied", detail: detail }; }
    return { result: "error", detail: detail };
}

function testEsLinkCreation(result, kind, link, target) {
    // Kind: HardLink, Junction or SymbolicLink, all through cmd mklink (the ps1 path for
    // PowerShell 2-4; JScript has no New-Item).
    var flags = { HardLink: "/H", Junction: "/J", SymbolicLink: null };
    var args = ["/d", "/c", "mklink"];
    if (flags[kind]) { args.push(flags[kind]); }
    args.push(link, target);
    var run = invokeEsCommand(getEsSystemTool("cmd.exe"), args, 15);
    result.sources.push("run cmd /c mklink " + jsSys_str(flags[kind]) + " (in the scanner temp folder)");
    return getEsLinkOutcome(link, getEsCommandText(run));
}

function jsSys_writeNewFile(path, text) {
    // A new file only (CreateTextFile with overwrite false fails when it exists).
    var stream = ES_FSO.CreateTextFile(path, false, false);
    try { stream.WriteLine(text); } finally { stream.Close(); }
}

function jsSys_removeQuietly(path, folder) {
    try {
        if (folder) { ES_FSO.DeleteFolder(path, true); } else { ES_FSO.DeleteFile(path, true); }  // lint-allow: temp-cleanup
    } catch (e) { writeEsLog("could not remove " + path + ": " + esErrorText(e)); }
}

function jsSys_cleanFsBase(base) {
    // Links first (deleting a link never touches its target), then the folder.
    var files = ["symlink.tmp", "hard.tmp"];
    for (var i = 0; i < files.length; i++) {
        var file = esJoinPath(base, files[i]);
        if (ES_FSO.FileExists(file)) { jsSys_removeQuietly(file, false); }
    }
    var junction = esJoinPath(base, "junction");
    if (ES_FSO.FolderExists(junction)) { jsSys_removeQuietly(junction, true); }
    if (ES_FSO.FolderExists(base)) { jsSys_removeQuietly(base, true); }
}

function jsSys_linkTests(r, d, base, file) {
    var junctionTarget = esJoinPath(base, "jtarget");
    if (!ES_FSO.FolderExists(junctionTarget)) { ES_FSO.CreateFolder(junctionTarget); }
    d.hardlink = testEsLinkCreation(r, "HardLink", esJoinPath(base, "hard.tmp"), file).result;
    d.junction = testEsLinkCreation(r, "Junction", esJoinPath(base, "junction"), junctionTarget).result;
    var symlink = testEsLinkCreation(r, "SymbolicLink", esJoinPath(base, "symlink.tmp"), file);
    d.symlink = symlink.result;
    d.symlink_detail = symlink.detail;
}

function jsSys_shortNames(value) {
    var names = { v0: "enabled", v1: "disabled", v2: "per-volume", v3: "disabled except system volume" };
    var name = names["v" + jsSys_str(value)];
    return (name === undefined) ? null : name;
}

function probe_fs_semantics() {
    var r = newEsResult();
    var d = r.data;
    var base = esJoinPath(ES_TMP, "fs");
    if (!ES_FSO.FolderExists(base)) { ES_FSO.CreateFolder(base); }
    r.sources.push("write and delete test files in the scanner temp folder");
    try {
        var file = esJoinPath(base, "Case.tmp");
        jsSys_writeNewFile(file, "envscan");
        d.case_sensitive = !jsSys_exists(esJoinPath(base, "CASE.TMP"));
        jsSys_linkTests(r, d, base, file);
    } finally { jsSys_cleanFsBase(base); }
    var fsKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem";
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem (LongPathsEnabled, NtfsDisable8dot3NameCreation)");
    d.long_paths_enabled = (jsSys_str(getEsRegValue(fsKey, "LongPathsEnabled")) == "1");
    d.short_names = jsSys_shortNames(getEsRegValue(fsKey, "NtfsDisable8dot3NameCreation"));
    d.name_max = 255;
    d.path_max = d.long_paths_enabled ? 32767 : 260;
    var volume = getEsVolumeFor(jsSys_str(ES_TMP));
    d.temp_fstype = volume ? volume["fstype"] : null;
    return r;
}

// ------------------------------------------------------------------ execution test (deep)

function getEsExecOutcome(run) {
    var text = getEsCommandText(run);
    var detail = (text.length > 300) ? text.substring(0, 300) : text;
    if (/envscan-exec-ok/i.test(text)) { return { outcome: "ok", detail: null }; }
    if (run.timed_out) { return { outcome: "error", detail: "timed out" }; }
    if (/blocked|group policy|disabled|digitally signed|execution polic|restriction|AppLocker|denied|administrator/i.test(text)) {
        return { outcome: "blocked", detail: detail };
    }
    if (run.error) { detail = run.error; }
    return { outcome: "error", detail: detail };
}

function invokeEsExecTest(result, location, test) {
    // Creates the script as a new file (never an existing one), runs it, always deletes it.
    var entry = { id: location["id"], path: test.file, kind: test.kind, outcome: "error", detail: null };
    if (test.kind == "cmd" && ES_CMD_META_RE.test(test.file)) {
        entry.outcome = "skipped";
        entry.detail = "path contains cmd.exe metacharacters";
        return entry;
    }
    var created = false;
    try {
        jsSys_writeNewFile(test.file, test.body);
        created = true;
        var run = invokeEsCommand(test.exe, test.args.concat([test.file]), 30);
        result.sources.push("run " + run.command);
        var outcome = getEsExecOutcome(run);
        entry.outcome = outcome.outcome;
        entry.detail = outcome.detail;
    } catch (e) {
        entry.detail = esErrorText(e);
    } finally {
        if (created) { jsSys_removeQuietly(test.file, false); }
    }
    return entry;
}

function jsSys_execLocations() {
    var all = getEsData("fs.locations")["locations"] || [];
    var out = [];
    for (var i = 0; i < all.length; i++) {
        var l = all[i];
        if (l && l["writable"] === true && l["method"] == "write-test" && esContains(ES_EXEC_TEST_IDS, l["id"])) { out.push(l); }
    }
    return out;
}

function jsSys_execTests(stem) {
    var powershell = getEsSystemTool("WindowsPowerShell\\v1.0\\powershell.exe");
    return [
        { kind: "cmd", file: stem + ".cmd", body: "@echo envscan-exec-ok", exe: getEsSystemTool("cmd.exe"), args: ["/d", "/c"] },
        { kind: "ps1", file: stem + ".ps1", body: "Write-Output 'envscan-exec-ok'", exe: powershell, args: ["-NoProfile", "-NonInteractive", "-File"] }
    ];
}

function probe_fs_exec_test() {
    var r = newEsResult();
    if (!testEsDependency(r, "fs.locations")) { return r; }
    var locations = jsSys_execLocations();
    if (locations.length === 0) { r.status = "not_found"; r.notes.push("no writable per-user location to test"); return r; }
    var results = [];
    for (var i = 0; i < locations.length; i++) {
        var stem = esJoinPath(jsSys_str(locations[i]["path"]), "envscan-exec-" + Math.floor(Math.random() * 1000000000) + "-" + Math.floor(Math.random() * 1000000000));
        var tests = jsSys_execTests(stem);
        for (var j = 0; j < tests.length; j++) { results.push(invokeEsExecTest(r, locations[i], tests[j])); }
    }
    r.data.results = results;
    return r;
}
