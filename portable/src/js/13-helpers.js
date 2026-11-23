// ---------------------------------------------------------------------------
// 13-helpers: shared probe helpers - original environment, token SIDs, write
// access from SDDL, PATH index and executable lookup, URLs (port of 13-helpers.ps1).
//
// Token and ACL: JScript has no token or ACL API, and the allowed sources (WMI
// local classes, registry, FSO) do not give them either (Win32_LogicalFileSecuritySetting
// translates SIDs, which may contact a domain controller; icacls/cacls/whoami are not run).
// So, exactly as ps1 does in ConstrainedLanguage:
//   getEsTokenInfo()  -> {user_sid: from ProfileList (by profile path) or null,
//                         group_sids: ES_DEFAULT_GROUP_SIDS without Administrators,
//                         groups_source: "assumed", is_admin: null, elevation_method: null}
//   getEsAclSddl(p)   -> throws Error(JSHLP_NO_ACL_NOTE)
//   getEsSddlAccess(p)-> {create_files: null, create_dirs: null, error: <reason>}
// Callers put JSHLP_NO_TOKEN_NOTE / the error text in a note. jsHlp_sddlAccess(sddl, sids)
// keeps the ps1 DACL evaluation for an SDDL string obtained elsewhere.
// ---------------------------------------------------------------------------

var ES_PATH_DIRS = null;
var ES_PATH_LINK_DIRS = [];
var ES_PATH_INDEX = null;
var ES_PATH_RANK = null;
var ES_PATHEXT = null;
var ES_TOKEN_INFO = null;
var ES_PROFILE_ENTRY = null;
var ES_RUNNABLE_EXT = [".exe", ".com", ".bat", ".cmd"];
var JSHLP_PATH_LIST_MAX = 20000;
var JSHLP_NO_TOKEN_NOTE = "the Windows Script Host has no token API: elevation is unknown and group SIDs are assumed (standard user)";
var JSHLP_NO_ACL_NOTE = "ACLs are not readable from the Windows Script Host (no ACL API; icacls is not run)";

// SDDL aliases for the trustees that matter to a standard user.
var ES_SDDL_ALIASES = {
    "WD": "S-1-1-0", "AU": "S-1-5-11", "IU": "S-1-5-4", "BU": "S-1-5-32-545", "BA": "S-1-5-32-544",
    "SY": "S-1-5-18", "PU": "S-1-5-32-547", "AC": "S-1-15-2-1", "CO": "S-1-3-0", "OW": "S-1-3-4",
    "LS": "S-1-5-19", "NS": "S-1-5-20", "NU": "S-1-5-2", "RD": "S-1-5-32-555", "SU": "S-1-5-6"
};
var ES_DEFAULT_GROUP_SIDS = ["S-1-1-0", "S-1-2-0", "S-1-5-4", "S-1-5-11", "S-1-5-15", "S-1-5-32-545"];

// ------------------------------------------------------------------ small JScript-only utilities

function jsHlp_trimChars(text, chars, start, end) {
    // String.Trim(chars) / TrimStart / TrimEnd for a set of single characters.
    var s = String(text);
    var a = 0;
    var b = s.length;
    while (start && a < b && chars.indexOf(s.charAt(a)) >= 0) { a++; }
    while (end && b > a && chars.indexOf(s.charAt(b - 1)) >= 0) { b--; }
    return s.substring(a, b);
}

function jsHlp_getI(table, name) {
    // A value of a plain object by case-insensitive key (ps hashtables), or null.
    if (!table) { return null; }
    if (esHas(table, name)) { return table[name]; }
    var lower = String(name).toLowerCase();
    for (var k in table) {
        if (esHas(table, k) && k.toLowerCase() === lower) { return table[k]; }
    }
    return null;
}

function jsHlp_eqI(a, b) {
    // PowerShell -eq on strings: case-insensitive; null equals only null/undefined.
    if (a === null || a === undefined || b === null || b === undefined) { return (a === null || a === undefined) && (b === null || b === undefined); }
    return String(a).toLowerCase() === String(b).toLowerCase();
}

function jsHlp_list(value) {
    // @($x | Where-Object { $_ }) without the filter: null -> [], array -> itself, else [value].
    if (value === null || value === undefined) { return []; }
    return esIsArray(value) ? value : [value];
}

// ------------------------------------------------------------------ environment

function getEsOrigEnv(name) {
    // Value from the environment captured before the child environment was applied.
    if (!name) { return null; }
    var spelled = ES_ENV_SNAPSHOT_NAMES[String(name).toLowerCase()];
    if (spelled === undefined || !esHas(ES_ENV_SNAPSHOT, spelled)) { return null; }
    return String(ES_ENV_SNAPSHOT[spelled]);
}

function getEsEnvSubset(names) {
    // NAME -> redacted value for each listed variable that is set (names are case-insensitive).
    var out = {};
    var seen = {};
    var list = jsHlp_list(names);
    for (var i = 0; i < list.length; i++) {
        var key = String(list[i]);
        if (seen["k" + key.toLowerCase()]) { continue; }
        seen["k" + key.toLowerCase()] = true;
        var value = getEsOrigEnv(key);
        if (value !== null) { out[key] = protectEsNamedValue(key, value); }
    }
    return out;
}

// ------------------------------------------------------------------ user token and profile

function findEsProfileEntry(sid) {
    // The ProfileList entry of the running user: by SID when known, else by profile path.
    var base = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    var profilePath = jsHlp_trimChars(getEsEnv("USERPROFILE") || "", "\\", false, true);
    var names = sid ? [sid, sid + ".bak"] : jsHlp_list(getEsRegSubkeys(base));
    for (var i = 0; i < names.length; i++) {
        var name = String(names[i]);
        if (!/^S-1-(5-21|12-1)-/i.test(name)) { continue; }
        var values = getEsRegValues(base + "\\" + name);
        if (values === null || values === undefined) { continue; }
        var imageValue = jsHlp_getI(values, "ProfileImagePath");
        var image = jsHlp_trimChars(imageValue === null ? "" : imageValue, "\\", false, true);
        if (sid || (image && jsHlp_eqI(image, profilePath))) {
            return { key: name, sid: name.replace(/\.bak$/i, ""), values: values };
        }
    }
    return null;
}

function getEsTokenInfo() {
    // User SID (ProfileList), assumed group SIDs, elevation unknown: see the header.
    if (ES_TOKEN_INFO !== null) { return ES_TOKEN_INFO; }
    var userSid = null;
    var entry = null;
    try { entry = findEsProfileEntry(""); } catch (e) { writeEsLog("profile lookup failed: " + esErrorText(e)); }
    if (entry) { userSid = entry.sid; }
    var groups = [];
    for (var i = 0; i < ES_DEFAULT_GROUP_SIDS.length; i++) {
        // Administrators grants access only to an elevated token (deny-only otherwise).
        if (ES_DEFAULT_GROUP_SIDS[i] !== "S-1-5-32-544") { groups.push(ES_DEFAULT_GROUP_SIDS[i]); }
    }
    ES_TOKEN_INFO = { user_sid: userSid, group_sids: groups, groups_source: "assumed", is_admin: null, elevation_method: null };
    return ES_TOKEN_INFO;
}

function getEsTrusteeSids() {
    // SIDs that grant access to this process: user, groups, and Administrators only when elevated.
    var info = getEsTokenInfo();
    var sids = info.group_sids.slice(0);
    if (info.user_sid) { sids.push(info.user_sid); }
    if (info.is_admin) { sids.push("S-1-5-32-544"); }
    return sids;
}

// ------------------------------------------------------------------ write access from SDDL

function testEsSddlRight(rights, bit) {
    // True when an ACE right string grants bit (0x2 add file, 0x4 add subdirectory) or generic write.
    var text = String(rights);
    if (/^0x[0-9A-Fa-f]+$/i.test(text)) {
        var mask = parseInt(text.substr(2), 16);
        return ((mask & (bit | 0x10000000 | 0x40000000)) !== 0);
    }
    for (var i = 0; i + 1 < text.length; i += 2) {
        var code = text.substr(i, 2).toUpperCase();
        if (code === "GA" || code === "GW" || code === "FA" || code === "FW") { return true; }
        if (bit === 2 && code === "DC") { return true; }
        if (bit === 4 && code === "LC") { return true; }
    }
    return false;
}

function getEsAclSddl(path) {
    // No ACL API in JScript (see the header): always throws, so callers record the reason.
    throw new Error(JSHLP_NO_ACL_NOTE);
}

function getEsSddlAccess(path) {
    // Whether this user may create files / subdirectories in path, read from the DACL without writing.
    var result = { create_files: null, create_dirs: null, error: null };
    if (!testEsLocalPath(path)) { result.error = "not an absolute local path"; return result; }
    var sddl = null;
    try { sddl = getEsAclSddl(path); } catch (e) { result.error = esErrorText(e); return result; }
    return jsHlp_sddlAccess(sddl, getEsTrusteeSids());
}

function jsHlp_sddlTrustees(sddl, sids) {
    // OWNER RIGHTS (OW) entries apply when this user, or one of its groups, owns the object.
    var out = sids.slice(0);
    var m = /^O:(S-1-[0-9-]+|[A-Z][A-Z])/i.exec(sddl);
    if (m) {
        var owner = m[1];
        var alias = jsHlp_getI(ES_SDDL_ALIASES, owner);
        if (alias !== null) { owner = alias; }
        if (esContainsI(out, owner)) { out.push("S-1-3-4"); }
    }
    return out;
}

function jsHlp_aceInheritOnly(flags) {
    for (var i = 0; i + 1 < flags.length; i += 2) { if (flags.substr(i, 2) === "IO") { return true; } }
    return false;
}

function jsHlp_sddlAccess(sddl, sids) {
    // The DACL evaluation of Get-EsSddlAccess for an SDDL string and the trustee SIDs.
    var result = { create_files: null, create_dirs: null, error: null };
    var text = String(sddl);
    var start = text.indexOf("D:");
    if (start < 0) { result.error = "no DACL"; return result; }
    var dacl = text.substr(start);
    var end = dacl.indexOf("S:");
    if (end > 0) { dacl = dacl.substr(0, end); }
    var trustees = jsHlp_sddlTrustees(text, sids);
    var allow = { b2: false, b4: false };
    var deny = { b2: false, b4: false };
    var re = /\((A|D|XA|XD);([A-Z]*);([^;]*);[^;]*;[^;]*;([^;)]+)/g;
    var ace;
    while ((ace = re.exec(dacl)) !== null) {
        if (jsHlp_aceInheritOnly(ace[2])) { continue; }
        var trustee = ace[4];
        var alias = jsHlp_getI(ES_SDDL_ALIASES, trustee);
        if (alias !== null) { trustee = alias; }
        if (!esContainsI(trustees, trustee)) { continue; }
        var isDeny = ace[1].charAt(0).toUpperCase() === "D" || ace[1].toUpperCase() === "XD";
        if (testEsSddlRight(ace[3], 2)) { if (isDeny) { deny.b2 = true; } else { allow.b2 = true; } }
        if (testEsSddlRight(ace[3], 4)) { if (isDeny) { deny.b4 = true; } else { allow.b4 = true; } }
    }
    result.create_files = (allow.b2 && !deny.b2);
    result.create_dirs = (allow.b4 && !deny.b4);
    return result;
}

// ------------------------------------------------------------------ PATH and executables

function jsHlp_isLinkPathDir(dir) {
    // A PATH folder that is (or is below) a link whose target FSO cannot read. It is never
    // listed and nothing inside it is tested: the target could be a credential store.
    return getEsPathLinkReason(dir) === "link target unknown";
}

function addEsPathLinkNotes(result) {
    // Makes the PATH folders skipped as links visible: a note each, and the probe partial
    // (a tool not found may be in one of them, so its absence is unknown).
    getEsPathDirs();
    for (var i = 0; i < ES_PATH_LINK_DIRS.length; i++) {
        addEsNote(result, "PATH folder " + ES_PATH_LINK_DIRS[i] + " is a link whose target cannot be read in the WSH port; tools in it were not checked", "partial");
    }
    if (ES_PATH_LINK_DIRS.length > 0 && result.status === "not_found") { result.status = "partial"; }
}

function getEsPathDirs() {
    // Absolute, local, existing PATH directories in order; network and relative entries are
    // skipped, and so is a folder that is (or is below) a link that is not followed; those are
    // kept in ES_PATH_LINK_DIRS for addEsPathLinkNotes.
    if (ES_PATH_DIRS !== null) { return ES_PATH_DIRS; }
    var dirs = [];
    var links = [];
    var seen = {};
    var entries = String(getEsOrigEnv("Path") || "").split(";");
    for (var i = 0; i < entries.length; i++) {
        var dir = jsHlp_trimChars(esTrim(entries[i]), "\"", true, true);
        if (!/^[A-Za-z]:\\/.test(dir) || testEsNetworkPath(dir)) { continue; }
        dir = jsHlp_trimChars(dir, "\\", false, true);
        var key = "k" + dir.toLowerCase();
        if (seen[key]) { continue; }
        seen[key] = true;
        if (testEsSafePath(dir, "Container")) { dirs.push(dir); }
        else if (jsHlp_isLinkPathDir(dir)) { links.push(dir); }
    }
    ES_PATH_LINK_DIRS = links;
    ES_PATH_DIRS = dirs;
    return dirs;
}

function jsHlp_listNames(dir) {
    // File and folder names in dir (Get-ChildItem -Name -Force), at most JSHLP_PATH_LIST_MAX.
    var names = [];
    var folder = ES_FSO.GetFolder(dir + "\\");
    var sets = [folder.Files, folder.SubFolders];
    for (var s = 0; s < sets.length; s++) {
        for (var items = new Enumerator(sets[s]); !items.atEnd() && names.length < JSHLP_PATH_LIST_MAX; items.moveNext()) {
            names.push(String(items.item().Name));
        }
    }
    return names;
}

function getEsPathIndex() {
    // "k" + lower-case file name -> full paths in PATH order; each PATH directory is listed once.
    if (ES_PATH_INDEX !== null) { return ES_PATH_INDEX; }
    var index = {};
    var rank = {};
    var dirs = getEsPathDirs();
    for (var i = 0; i < dirs.length; i++) {
        rank["k" + dirs[i].toLowerCase()] = i + 1;
        var names = [];
        try { names = jsHlp_listNames(dirs[i]); }
        catch (e) { writeEsLog("cannot list PATH directory " + dirs[i] + ": " + esErrorText(e)); continue; }
        for (var j = 0; j < names.length; j++) {
            var key = "k" + names[j].toLowerCase();
            var full = dirs[i] + "\\" + names[j];
            index[key] = esHas(index, key) ? index[key].concat([full]) : [full];
        }
    }
    ES_PATH_INDEX = index;
    ES_PATH_RANK = rank;
    return index;
}

function getEsPathExt() {
    if (ES_PATHEXT !== null) { return ES_PATHEXT; }
    var value = getEsOrigEnv("PATHEXT");
    if (!value) { value = ".COM;.EXE;.BAT;.CMD"; }
    var parts = String(value).split(";");
    var exts = [];
    for (var i = 0; i < parts.length; i++) {
        var ext = esTrim(parts[i]).toLowerCase();
        if (/^\.[a-z0-9]+$/.test(ext)) { exts.push(ext); }
    }
    if (!esContains(exts, ".ps1")) { exts.push(".ps1"); }
    ES_PATHEXT = exts;
    return exts;
}

function getEsParentDir(path) {
    var p = String(path);
    var slash = p.lastIndexOf("\\");
    if (slash <= 0) { return p; }
    return p.substr(0, slash);
}

function getEsExtension(path) {
    var p = String(path);
    var leaf = p.substr(p.lastIndexOf("\\") + 1);
    var dot = leaf.lastIndexOf(".");
    if (dot < 0) { return ""; }
    return leaf.substr(dot).toLowerCase();
}

function jsHlp_pathMatches(name, index, exts) {
    // PATH matches of one name, sorted by PATH directory, then PATHEXT order.
    var found = [];
    for (var e = 0; e < exts.length; e++) {
        var key = "k" + (String(name) + exts[e]).toLowerCase();
        if (!esHas(index, key)) { continue; }
        var paths = index[key];
        for (var p = 0; p < paths.length; p++) {
            var dirRank = ES_PATH_RANK["k" + getEsParentDir(paths[p]).toLowerCase()] || 0;
            found.push({ path: paths[p], on_path: true, rank: (100 * dirRank) + e + 1 });
        }
    }
    found.sort(function (a, b) { return a.rank - b.rank; });
    return found;
}

function jsHlp_dirMatches(names, patterns) {
    // Matches in the spec's extra directories (not on PATH), runnable extensions and .ps1.
    var found = [];
    var exts = ES_RUNNABLE_EXT.concat([".ps1"]);
    var list = jsHlp_list(patterns);
    for (var i = 0; i < list.length; i++) {
        var dirs = jsHlp_list(expandEsPathPattern(String(list[i])));
        for (var d = 0; d < dirs.length; d++) {
            if (getEsPathLinkReason(dirs[d])) { continue; }
            for (var n = 0; n < names.length; n++) {
                for (var e = 0; e < exts.length; e++) {
                    var candidate = jsHlp_trimChars(dirs[d], "\\", false, true) + "\\" + String(names[n]) + exts[e];
                    if (esIsFile(candidate)) { found.push({ path: candidate, on_path: false, rank: 0 }); }
                }
            }
        }
    }
    return found;
}

function findEsExecutable(names, dirs) {
    // Every match as {path, on_path, rank}: PATH order (PATHEXT order inside a directory) for the
    // first name that matches, then the other names, then the spec's extra directories.
    var nameList = jsHlp_list(names);
    var index = getEsPathIndex();
    var exts = getEsPathExt();
    var found = [];
    for (var i = 0; i < nameList.length; i++) { found = found.concat(jsHlp_pathMatches(nameList[i], index, exts)); }
    found = found.concat(jsHlp_dirMatches(nameList, dirs));
    var unique = [];
    var seen = {};
    for (var j = 0; j < found.length; j++) {
        var key = "k" + found[j].path.toLowerCase();
        if (!seen[key]) { seen[key] = true; unique.push(found[j]); }
    }
    return unique;
}

function jsHlp_hasRunnable(dir, stem) {
    var exts = ES_RUNNABLE_EXT.concat([""]);
    for (var i = 0; i < exts.length; i++) { if (esIsFile(dir + "\\" + stem + exts[i])) { return true; } }
    return false;
}

function getEsShimManager(path) {
    // Name of the version manager whose shim directory holds path, else null.
    var dir = getEsParentDir(path).toLowerCase().replace(/\\/g, "/");
    for (var i = 0; i < ES_VMANAGERS.length; i++) {
        var manager = ES_VMANAGERS[i];
        var markers = jsHlp_list(manager.markers);
        for (var m = 0; m < markers.length; m++) {
            if (!markers[m] || dir.indexOf(String(markers[m])) < 0) { continue; }
            if (manager.requires && !jsHlp_hasRunnable(getEsParentDir(path), manager.requires)) { continue; }
            return String(manager.name);
        }
    }
    return null;
}

function testEsAppAlias(path) {
    return String(path).toLowerCase().replace(/\\/g, "/").indexOf("/microsoft/windowsapps/") >= 0;
}

function testEsWslLauncher(path) {
    return /\\windows\\(system32|sysnative|syswow64)\\(bash|wsl|wslhost)\.exe$/.test(String(path).toLowerCase());
}

function getEsNoRunReason(tool, path) {
    // Why a located executable must not be run, or null when it may be.
    if (jsHlp_eqI(tool.mode, "presence")) { return "inventory only (spec mode presence)"; }
    var ext = getEsExtension(path);
    if (ext === ".ps1") { return "PowerShell script shim; not run inside the scanner session"; }
    if (!esContains(ES_RUNNABLE_EXT, ext)) { return "file type " + ext + " is not run"; }
    if (testEsAppAlias(path) && !jsHlp_eqI(tool.id, "winget")) { return "app execution alias (WindowsApps); not run"; }
    if (testEsWslLauncher(path)) { return "WSL launcher; not run"; }
    var manager = getEsShimManager(path);
    if (manager) { return "version-manager shim (" + manager + "); not run"; }
    var link = getEsPathLinkReason(path);
    if (link) { return link + "; not run"; }
    return null;
}

function findEsToolPath(id) {
    // First runnable path of a spec tool (usable before tools.inventory has run), or null.
    for (var i = 0; i < ES_TOOLS.length; i++) {
        var tool = ES_TOOLS[i];
        if (!jsHlp_eqI(tool.id, id)) { continue; }
        var matches = findEsExecutable(tool.exe, tool.dirs);
        for (var m = 0; m < matches.length; m++) {
            if (!getEsNoRunReason(tool, matches[m].path)) { return matches[m].path; }
        }
    }
    return null;
}
