// ---------------------------------------------------------------------------
// 21-probes-user: running user, profile, privileges (deep), environment and
// PATH analysis (port of src/ps/21-probes-user.ps1; shell.info is in 21-probes-shell.js).
// ---------------------------------------------------------------------------

var ES_SID_NAMES = {
    "S-1-1-0": "Everyone", "S-1-2-0": "LOCAL", "S-1-2-1": "CONSOLE LOGON", "S-1-5-2": "NETWORK",
    "S-1-5-4": "INTERACTIVE", "S-1-5-6": "SERVICE", "S-1-5-11": "Authenticated Users",
    "S-1-5-14": "REMOTE INTERACTIVE LOGON", "S-1-5-15": "This Organization", "S-1-5-113": "Local account",
    "S-1-5-114": "Local account and member of Administrators", "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users", "S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users", "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users", "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers", "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users", "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-36": "Cloud Account Authentication", "S-1-18-1": "Authentication authority asserted identity"
};
var ES_DOMAIN_RIDS = { "512": "Domain Admins", "513": "Domain Users (or local None)", "514": "Domain Guests", "519": "Enterprise Admins", "525": "Protected Users" };
var ES_SHELL_FOLDERS = {
    "Personal": "Documents", "Desktop": "Desktop", "AppData": "AppData", "Local AppData": "LocalAppData",
    "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads", "My Pictures": "Pictures", "Favorites": "Favorites",
    "Start Menu": "StartMenu", "Templates": "Templates", "Cache": "InternetCache"
};
var JSUSER_UAC_NAMES = ["EnableLUA", "ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorUser", "PromptOnSecureDesktop", "FilterAdministratorToken"];

function jsUser_lookupI(table, name) {
    // Case-insensitive own-key lookup (ps hashtables); undefined when absent.
    var lower = jsOs_str(name).toLowerCase();
    for (var key in table) {
        if (esHas(table, key) && key.toLowerCase() === lower) { return table[key]; }
    }
    return undefined;
}

function convertToEsGroupName(sid) {
    if (esHas(ES_SID_NAMES, sid)) { return ES_SID_NAMES[sid]; }
    var m = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/.exec(jsOs_str(sid));
    if (m && esHas(ES_DOMAIN_RIDS, m[1])) { return ES_DOMAIN_RIDS[m[1]] + " (" + sid + ")"; }
    return sid;
}

function jsUser_groups(r, d, info) {
    d.groups = [];
    d.group_sids = [];
    if (info.groups_source === "token") {
        var sids = info.group_sids || [];
        for (var i = 0; i < sids.length; i++) {
            d.group_sids.push(sids[i]);
            d.groups.push(convertToEsGroupName(sids[i]));
        }
    } else {
        addEsNote(r, "group membership is not readable from Windows Script Host (with --deep: whoami /all)", "");
    }
}

function jsUser_uac(r) {
    var key = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    r.sources.push("registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System (UAC values)");
    var uac = {};
    for (var i = 0; i < JSUSER_UAC_NAMES.length; i++) {
        var value = getEsRegValue(key, JSUSER_UAC_NAMES[i]);
        uac[JSUSER_UAC_NAMES[i]] = value === undefined ? null : value;
    }
    return uac;
}

function probe_user_identity() {
    var r = newEsResult();
    var d = r.data;
    r.sources.push("environment USERNAME, USERDOMAIN, USERDNSDOMAIN, USERPROFILE, LOGONSERVER");
    var info = getEsTokenInfo();
    r.sources.push("token information (" + info.groups_source + ")");
    d.name = getEsOrigEnv("USERNAME");
    d.domain = getEsOrigEnv("USERDOMAIN");
    d.dns_domain = getEsOrigEnv("USERDNSDOMAIN");
    d.logon_server = getEsOrigEnv("LOGONSERVER");
    d.local_account = !!(d.domain && d.domain.toLowerCase() === jsOs_str(getEsOrigEnv("COMPUTERNAME")).toLowerCase());
    d.sid = info.user_sid === undefined ? null : info.user_sid;
    d.uid = null;
    d.gid = null;
    d.groups_source = info.groups_source;
    jsUser_groups(r, d, info);
    d.is_admin = (info.is_admin === undefined) ? null : info.is_admin;
    d.elevation_method = (info.elevation_method === undefined) ? null : info.elevation_method;
    if (d.is_admin === null) { addEsNote(r, "elevation could not be determined", "partial"); }
    d.integrity = null;
    d.home = getEsOrigEnv("USERPROFILE");
    d.shell = getEsOrigEnv("ComSpec");
    d.passwd_entry = null;
    d.uac = jsUser_uac(r);
    var unlock = getEsRegValues("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock");
    r.sources.push("registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock");
    d.developer_mode = !!(unlock && Number(jsOs_val(unlock, "AllowDevelopmentWithoutDevLicense")) === 1);
    return r;
}

// ------------------------------------------------------------------ profile

function getEsShellFolders() {
    // REG_EXPAND_SZ values arrive expanded (engine registry readers, like Get-ItemProperty).
    var values = getEsRegValues("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");
    return values ? values : {};
}

function jsUser_kindFromEntry(r, entry, kind) {
    if (!entry) { addEsNote(r, "own ProfileList entry not found", ""); return; }
    var state = jsOs_val(entry.values, "State");
    var central = jsOs_str(jsOs_val(entry.values, "CentralProfile"));
    kind.state = state;
    if (central) { kind.type = "roaming"; kind.central = central; }
    if (state !== null && (Number(state) & 0x1) !== 0) { kind.type = "mandatory"; }
    if ((state !== null && (Number(state) & 0x800) !== 0) || /\.bak$/i.test(jsOs_str(entry.key))) { kind.type = "temporary"; }
}

function getEsProfileKind(result, profilePath) {
    // Profile type from the own ProfileList entry, the profile folder name and NTUSER.MAN.
    var entry = findEsProfileEntry(getEsTokenInfo().user_sid);
    result.sources.push("registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList (own entry)");
    var kind = { type: "local", state: null, central: null };
    jsUser_kindFromEntry(result, entry, kind);
    var leaf = jsOs_str(profilePath).replace(/\\+$/, "");
    leaf = leaf.substr(leaf.lastIndexOf("\\") + 1);
    if (/^TEMP(\.|$)/i.test(leaf)) { kind.type = "temporary"; }
    if (testEsLocalPath(profilePath) && testEsSafePath(esJoinPath(profilePath, "NTUSER.MAN"))) { kind.type = "mandatory"; }
    return kind;
}

function jsUser_oneDriveRoots() {
    var roots = [];
    var names = ["OneDrive", "OneDriveCommercial"];
    for (var i = 0; i < names.length; i++) {
        var value = getEsOrigEnv(names[i]);
        if (value) { roots.push(value.toLowerCase()); }
    }
    return roots;
}

function jsUser_sortedUnique(items) {
    // Sort-Object -Unique: case-insensitive order, case-insensitive duplicates dropped.
    var copy = items.slice(0);
    copy.sort(function (a, b) { var x = a.toLowerCase(); var y = b.toLowerCase(); return x < y ? -1 : (x > y ? 1 : 0); });
    var out = [];
    for (var i = 0; i < copy.length; i++) {
        if (out.length === 0 || out[out.length - 1].toLowerCase() !== copy[i].toLowerCase()) { out.push(copy[i]); }
    }
    return out;
}

function getEsFolderRedirection(result, profilePath) {
    // Known shell folders, those outside the local profile, and those inside OneDrive.
    var folders = getEsShellFolders();
    result.sources.push("registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");
    var redirected = {};
    var known = {};
    var oneDrive = jsUser_oneDriveRoots();
    var profileLower = jsOs_str(profilePath).toLowerCase();
    var inOneDrive = [];
    for (var name in folders) {
        if (!esHas(folders, name)) { continue; }
        var label = jsUser_lookupI(ES_SHELL_FOLDERS, name);
        var isKnown = label !== undefined;
        if (!isKnown) { label = name; }
        var path = jsOs_str(folders[name]);
        var pathLower = path.toLowerCase();
        if (isKnown) { known[label] = path; }
        var local = !!(profileLower && esStartsWith(pathLower, profileLower));
        if (!local || testEsNetworkPath(path)) { redirected[label] = path; }
        for (var i = 0; i < oneDrive.length; i++) { if (esStartsWith(pathLower, oneDrive[i])) { inOneDrive.push(label); } }
    }
    return { known: known, redirected: redirected, in_onedrive: jsUser_sortedUnique(inOneDrive) };
}

function jsUser_fslogix(r) {
    r.sources.push("registry HKLM\\SOFTWARE\\FSLogix\\Profiles");
    var values = getEsRegValues("HKLM:\\SOFTWARE\\FSLogix\\Profiles");
    if (!values) { return null; }
    return { enabled: Number(jsOs_val(values, "Enabled")) === 1, vhd_locations: jsOs_val(values, "VHDLocations"), volume_type: jsOs_val(values, "VolumeType") };
}

function probe_user_profile() {
    var r = newEsResult();
    var d = r.data;
    var profilePath = getEsOrigEnv("USERPROFILE");
    r.sources.push("environment USERPROFILE, HOMEDRIVE, HOMEPATH, HOMESHARE, OneDrive, OneDriveCommercial");
    d.home = profilePath;
    var homeDrive = getEsOrigEnv("HOMEDRIVE");
    d.homeshare = getEsOrigEnv("HOMESHARE");
    d.homedrive = homeDrive;
    d.homepath = getEsOrigEnv("HOMEPATH");
    d.home_network = !!(testEsNetworkPath(profilePath) || d.homeshare || testEsNetworkPath(jsOs_str(homeDrive)));
    d.appdata_network = !!testEsNetworkPath(getEsOrigEnv("APPDATA"));
    var kind = getEsProfileKind(r, jsOs_str(profilePath));
    d.profile_type = kind.type;
    d.profile_state = kind.state;
    d.central_profile = kind.central;
    var folders = getEsFolderRedirection(r, jsOs_str(profilePath));
    d.known_folders = folders.known;
    d.redirected_folders = folders.redirected;
    d.onedrive = { personal: getEsOrigEnv("OneDrive"), commercial: getEsOrigEnv("OneDriveCommercial"), folders_in_onedrive: folders.in_onedrive };
    d.fslogix = jsUser_fslogix(r);
    return r;
}

// ------------------------------------------------------------------ privileges (deep)

function jsUser_matchesUnique(text, re) {
    var found = text.match(re) || [];
    var out = [];
    for (var i = 0; i < found.length; i++) { out.push(found[i]); }
    out.sort();
    var unique = [];
    for (var j = 0; j < out.length; j++) { if (unique.length === 0 || unique[unique.length - 1] !== out[j]) { unique.push(out[j]); } }
    return unique;
}

function probe_user_privileges() {
    var r = newEsResult();
    var d = r.data;
    var whoami = invokeEsTool(r, "whoami /all", getEsSystemTool("whoami.exe"), ["/all"]);
    var text = jsOs_str(getEsCommandText(whoami));
    d.privileges = jsUser_matchesUnique(text, /\bSe[A-Za-z]+Privilege\b/g);
    d.group_sids = jsUser_matchesUnique(text, /\bS-1-[0-9-]+\b/g);
    d.integrity = null;
    var m = /\bS-1-16-(\d+)\b/.exec(text);
    if (m) {
        var levels = { "4096": "low", "8192": "medium", "8448": "medium-plus", "12288": "high", "16384": "system" };
        d.integrity = esHas(levels, m[1]) ? levels[m[1]] : null;
    }
    d.admin_capable = esContains(d.group_sids, "S-1-5-32-544") || esContains(d.group_sids, "S-1-5-114");
    invokeEsTool(r, "gpresult /r /scope user", getEsSystemTool("gpresult.exe"), ["/r", "/scope", "user"], 60);
    return r;
}

// ------------------------------------------------------------------ environment

function probe_env_vars() {
    var r = newEsResult();
    var d = r.data;
    r.sources.push("process environment (before the scanner changed anything)", "registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "registry HKCU\\Environment");
    var processEnv = {};
    var redacted = 0;
    var names = esKeys(ES_ENV_SNAPSHOT);
    for (var i = 0; i < names.length; i++) {
        var value = protectEsNamedValue(names[i], ES_ENV_SNAPSHOT[names[i]]);
        if (value === ES_PLACEHOLDER) { redacted++; }
        processEnv[names[i]] = value;
    }
    d.process = processEnv;
    var machine = getEsRegValues("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
    var user = getEsRegValues("HKCU:\\Environment");
    if (machine === null || machine === undefined) { addEsNote(r, "machine environment key unreadable", "partial"); machine = {}; }
    if (user === null || user === undefined) { user = {}; }
    d.machine = protectEsTable(machine);
    d.user = protectEsTable(user);
    d.redacted = redacted;
    d.count = names.length;
    return r;
}

function jsUser_cleanPath(value) {
    // Trim, then the quotes, then trailing backslashes (ps .Trim().Trim('"').TrimEnd('\')).
    return esTrim(jsOs_str(value)).replace(/^"+|"+$/g, "").replace(/\\+$/, "");
}

function getEsPathList(value) {
    var parts = jsOs_str(value).split(";");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
        var clean = jsUser_cleanPath(parts[i]).toLowerCase();
        if (clean) { out.push(clean); }
    }
    return out;
}

function jsUser_uniquePaths(entries, test) {
    // Select-Object -Unique over the matching entries' paths (case-sensitive, first order kept).
    var out = [];
    for (var i = 0; i < entries.length; i++) {
        if (test(entries[i]) && !esContains(out, entries[i].path)) { out.push(entries[i].path); }
    }
    return out;
}

function getEsPathIssues(entries, systemPosition) {
    // Distinct PATH entries per issue; writable_before_system32 lists entries searched first.
    return {
        missing: jsUser_uniquePaths(entries, function (e) { return e.exists === false; }),
        duplicate: jsUser_uniquePaths(entries, function (e) { return e.duplicate; }),
        relative: jsUser_uniquePaths(entries, function (e) { return e.relative; }),
        network: jsUser_uniquePaths(entries, function (e) { return e.network; }),
        writable: jsUser_uniquePaths(entries, function (e) { return e.writable === true; }),
        writable_before_system32: jsUser_uniquePaths(entries, function (e) {
            return e.writable === true && systemPosition !== null && e.position < systemPosition;
        })
    };
}

function jsUser_pathEntry(path, position, lists, seen) {
    var clean = path.replace(/^"+|"+$/g, "").replace(/\\+$/, "");
    var key = clean.toLowerCase();
    var scope = esContains(lists.machine, key) ? "machine" : (esContains(lists.user, key) ? "user" : "process");
    var network = !!testEsNetworkPath(clean);
    var relative = !/^([A-Za-z]:\\|\\\\)/.test(clean);
    var entry = {
        path: path, scope: scope, network: network, relative: relative, duplicate: esHas(seen, key),
        quoted: path.indexOf("\"") >= 0, unexpanded: /%[^%]+%/.test(path), exists: null, writable: null, position: position
    };
    seen[key] = true;
    // A link (junction) or a folder below one is not followed in WSH: exists stays unknown.
    if (!network && !relative && !getEsPathLinkReason(clean)) {
        entry.exists = !!testEsSafePath(clean, "Container");
        if (entry.exists) { entry.writable = getEsSddlAccess(clean + "\\").create_files; }
    }
    if (entry.writable === undefined) { entry.writable = null; }
    return entry;
}

function jsUser_pathNotes(r, entries) {
    var unknown = 0;
    for (var i = 0; i < entries.length; i++) { if (entries[i].exists === true && entries[i].writable === null) { unknown++; } }
    var linked = 0;
    for (var j = 0; j < entries.length; j++) { if (entries[j].exists === null && !entries[j].network && !entries[j].relative) { linked++; } }
    if (linked > 0) { addEsNote(r, linked + " PATH entries not checked: they are, or lie below, a link whose target cannot be read here", "partial"); }
    if (unknown > 0) { addEsNote(r, "writable unknown for " + unknown + " PATH entries: their directory ACL could not be read", "partial"); }
    if (getEsTokenInfo().groups_source !== "token") { addEsNote(r, "writable is computed from ACLs with assumed standard-user groups (no token access in Windows Script Host)", ""); }
}

function probe_env_path() {
    var r = newEsResult();
    var d = r.data;
    r.sources.push("process PATH", "registry machine and user Path", "directory ACLs of local PATH entries (read, no writes)");
    var raw = jsOs_str(getEsOrigEnv("Path"));
    var lists = {
        machine: getEsPathList(getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path")),
        user: getEsPathList(getEsRegValue("HKCU:\\Environment", "Path"))
    };
    var system32 = (jsOs_str(getEsEnv("SystemRoot")) + "\\system32").toLowerCase();
    var seen = {};
    var entries = [];
    var empty = 0;
    var systemPosition = null;
    var parts = raw.split(";");
    for (var i = 0; i < parts.length; i++) {
        var path = esTrim(parts[i]);
        if (!path) { empty++; continue; }
        var entry = jsUser_pathEntry(path, entries.length + 1, lists, seen);
        if (path.replace(/^"+|"+$/g, "").replace(/\\+$/, "").toLowerCase() === system32 && systemPosition === null) { systemPosition = entry.position; }
        entries.push(entry);
    }
    d.separator = ";";
    d.length = raw.length;
    d.count = entries.length;
    d.empty_entries = empty;
    d.entries = entries;
    d.issues = getEsPathIssues(entries, systemPosition);
    jsUser_pathNotes(r, entries);
    return r;
}
