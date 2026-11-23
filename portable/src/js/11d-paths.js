// ---------------------------------------------------------------------------
// 11d-paths: path guards, links, network drives and credential stores.
// Port of the files-and-paths part of src/ps/11-exec.ps1.
//
// Links: FSO shows a reparse point (attribute 1024) but cannot read its target. As in the
// ps1 on PowerShell 2-4, every reparse point (symbolic link, junction, and also cloud-file and
// app-alias reparse points) therefore counts as a link with an unknown target: it is never
// followed, read, listed or run, and the probe notes "<path> not read: link target unknown".
// Network drives: drive letters whose type is remote (FSO DriveType 3, which asks Windows, not the
// server) plus the persistent mappings under HKCU\Network. Never Win32_LogicalDisk.
// ---------------------------------------------------------------------------

var ES_LINK_REASONS = ["link to a network path", "link to a credential store", "link target unknown",
    "network path", "not a local path", "credential store"];
var ES_LINK_CACHE = {};
var ES_REPARSE_POINT = 1024;

function testEsNetworkPath(path) {
    if (!path) { return false; }
    var p = String(path);
    if (esStartsWith(p, "\\\\")) { return true; }
    var m = /^([A-Za-z]):/.exec(p);
    return m ? esContains(ES_NETWORK_DRIVES, m[1].toUpperCase() + ":") : false;
}

function initializeEsDrives() {
    var targets = {};
    try {
        var drives = new Enumerator(ES_FSO.Drives);
        for (; !drives.atEnd(); drives.moveNext()) {
            var drive = drives.item();
            if (drive.DriveType === 3) { targets[String(drive.DriveLetter).toUpperCase() + ":"] = null; }
        }
    } catch (e) { writeEsLog("drive list failed: " + esErrorText(e)); }
    // Persistent mappings: one RegRead per letter (WScript.Shell, no WMI), so this also works
    // before the scanner temp folder and the StdRegProv check exist (it runs before
    // initializeEsTemp, which refuses a TEMP on a network drive).
    for (var code = 65; code <= 90; code++) {
        var letter = String.fromCharCode(code);
        var drive2 = letter + ":";
        if (esHas(targets, drive2) && targets[drive2]) { continue; }
        try { ES_SHELL.RegRead("HKCU\\Network\\" + letter + "\\"); } catch (e2) { continue; }
        var remote = esRegReadShell(esRegSplit("HKCU:\\Network\\" + letter), "RemotePath");
        targets[drive2] = remote === undefined || remote === null ? null : String(remote);
    }
    ES_NETWORK_DRIVE_TARGETS = targets;
    ES_NETWORK_DRIVES = esKeys(targets);
}

function testEsLocalPath(path) {
    // An absolute path on a local drive (X:\...); never relative, root- or drive-relative,
    // device, UNC or a mapped network drive.
    if (!path || !/^[A-Za-z]:\\/.test(String(path))) { return false; }
    return !testEsNetworkPath(path);
}

function convertToEsFlatPath(path, dropDots) {
    // Text normalisation: "/" to "\", no empty or "." component, ".." folded (never above the
    // drive or share); a \\?\, \\.\, \??\ or UNC prefix stays. dropDots: trailing dots and spaces
    // of each component go, and a component of only dots and spaces disappears.
    var p = String(path).replace(/\//g, "\\");
    var prefix = "";
    var m = /^(\\\\[?.]\\|\\\?\?\\|\\\\)/.exec(p);
    if (m) { prefix = m[1]; p = p.substr(prefix.length); }
    var floor = prefix === "\\\\" ? 2 : 1;
    var parts = [];
    var pieces = p.split("\\");
    for (var i = 0; i < pieces.length; i++) {
        var part = pieces[i];
        if (part === "" || part === ".") { continue; }
        if (part === "..") { if (parts.length > floor) { parts.pop(); } continue; }
        if (dropDots) { part = part.replace(/[. ]+$/, ""); if (part === "") { continue; } }
        parts.push(part);
    }
    var flat = parts.join("\\");
    if (parts.length === 1 && prefix === "" && /^[A-Za-z]:$/.test(parts[0])) { flat += "\\"; }
    return prefix + flat;
}

function esRegexEscape(text) { return String(text).replace(/[\\^$.*+?()[\]{}|\/-]/g, "\\$&"); }

function joinEsAlternation(names) {
    var parts = [];
    for (var i = 0; i < (names || []).length; i++) { parts.push(esRegexEscape(String(names[i]).toLowerCase())); }
    return parts.join("|");
}

var ES_CRED_FOLDER_RE = new RegExp("\\\\(" + joinEsAlternation(ES_CRED_FOLDERS) + ")\\\\");
var ES_CRED_FILE_RE = new RegExp("(\\\\(" + joinEsAlternation(ES_CRED_FILES) + ")|(" + joinEsAlternation(ES_CRED_SUFFIXES) + "))$");
var ES_CRED_KEY_RE = new RegExp("\\.(" + joinEsAlternation(ES_CRED_KEY_EXTENSIONS) + ")$");

function getEsShortNamePrefixes() {
    // The first two letters of every component of every credential folder and file name.
    var seen = {};
    var names = (ES_CRED_FOLDERS || []).concat(ES_CRED_FILES || []);
    for (var i = 0; i < names.length; i++) {
        var components = String(names[i]).toLowerCase().split("\\");
        for (var j = 0; j < components.length; j++) {
            var short = components[j].replace(/^\.+/, "").substr(0, 2);
            if (short.length > 0) { seen[short] = true; }
        }
    }
    return esKeys(seen);
}

var ES_SHORT_PREFIX_RE = new RegExp("^(?:" + joinEsAlternation(getEsShortNamePrefixes()) + ")");

function testEsShortNameRisk(path) {
    // A "~<digit>" component that may be the 8.3 name of a credential store.
    var raw = String(path).split("\\");
    var parts = [];
    for (var i = 0; i < raw.length; i++) { if (raw[i]) { parts.push(raw[i]); } }
    for (var k = 0; k < parts.length; k++) {
        if (!/~[0-9]/.test(parts[k])) { continue; }
        if (k === parts.length - 1 || ES_SHORT_PREFIX_RE.test(parts[k].replace(/^\.+/, "").toLowerCase())) { return true; }
    }
    return false;
}

function testEsCredentialPath(path) {
    // A credential store, never opened or tested (spec [credentials]); text only, any case.
    if (!path) { return false; }
    var p = "\\" + convertToEsFlatPath(path, true).toLowerCase().replace(/^(\\\\[?.]\\|\\\?\?\\)/, "");
    if (p.replace(/^\\[a-z]:/, "").indexOf(":") >= 0) { return true; }
    if (testEsShortNameRisk(p)) { return true; }
    if (ES_CRED_FOLDER_RE.test(p + "\\")) { return true; }
    if (ES_CRED_FILE_RE.test(p)) { return true; }
    var leaf = p.substr(p.lastIndexOf("\\") + 1);
    return ES_CRED_KEY_RE.test(p) && !esContainsI(ES_TRUST_STORE_NAMES, leaf);
}

function testEsDeviceName(path) {
    // A reserved device name as the last component (CON, NUL.txt, COM1, CONIN$ ...).
    var p = String(path);
    var leaf = p.substr(Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")) + 1);
    var dot = leaf.indexOf(".");
    if (dot >= 0) { leaf = leaf.substr(0, dot); }
    return /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$)$/i.test(leaf.replace(/ +$/, ""));
}

// ------------------------------------------------------------------ links

function esGetItem(path) {
    // The FSO File or Folder object at path (no link is followed to get it), or null.
    try {
        if (ES_FSO.FolderExists(path)) { return ES_FSO.GetFolder(path); }
        if (ES_FSO.FileExists(path)) { return ES_FSO.GetFile(path); }
    } catch (e) { /* not readable */ }
    return null;
}

function getEsNonLocalReason(path) {
    var p = String(path || "").replace(/\//g, "\\");
    if (/^[A-Za-z]:$/.test(p)) { p += "\\"; }
    if (testEsLocalPath(p)) { return null; }
    if (/^\\\\[?.]\\(?!UNC\\)/i.test(p)) { return "not a local path"; }
    if (testEsNetworkPath(p)) { return "network path"; }
    return "not a local path";
}

function testEsLinkItem(item) {
    // Any reparse point (FSO cannot tell link kinds apart; see the header).
    try { return item !== null && (item.Attributes & ES_REPARSE_POINT) !== 0; } catch (e) { return true; }
}

function getEsLinkTarget(item, path) {
    // FSO cannot read link targets: always unknown.
    return null;
}

function getEsLinkReason(item, path) {
    // Why the item at path is not read or listed: every link has an unknown target here.
    if (!testEsLinkItem(item)) { return null; }
    var target = getEsLinkTarget(item, path);
    return target ? null : "link target unknown";
}

function getEsCachedLinkReason(path) {
    var nonLocal = getEsNonLocalReason(path);
    if (nonLocal) { return nonLocal; }
    var key = String(path).toLowerCase();
    if (Object.prototype.hasOwnProperty.call(ES_LINK_CACHE, key)) { return ES_LINK_CACHE[key]; }
    var item = esGetItem(String(path));
    var reason = item === null ? "" : String(getEsLinkReason(item, path) || "");
    ES_LINK_CACHE[key] = reason;
    return reason;
}

function getEsCredentialFolder(path) {
    // The shortest part of path (a folder above it, or path itself) that is a credential store
    // (testEsCredentialPath), or null. Text only: nothing is looked at. The folders above are
    // tested as folders (an 8.3 "~1" name is a risk there only when it may abbreviate a
    // credential folder); path itself also as a file.
    var parts = String(path).replace(/\//g, "\\").replace(/\\+$/, "").split("\\");
    var folder = parts[0];
    for (var i = 1; i < parts.length - 1; i++) {
        folder += "\\" + parts[i];
        if (testEsCredentialPath(folder + "\\_")) { return folder; }
    }
    return testEsCredentialPath(path) ? String(path) : null;
}

function getEsRefusedFolder(path) {
    // The first folder above path (from the volume root down, to a * or ? component) that is a
    // link not followed, as {path, reason}; a non-local path is refused as a whole, and a path in
    // or below a credential store (getEsCredentialFolder) before anything is looked at, with the
    // reason "credential store".
    var nonLocal = getEsNonLocalReason(path);
    if (nonLocal) { return { path: path, reason: nonLocal }; }
    var store = getEsCredentialFolder(path);
    if (store) { return { path: store, reason: "credential store" }; }
    var parts = String(path).replace(/\//g, "\\").replace(/\\+$/, "").split("\\");
    var folder = parts[0];
    for (var i = 1; i < parts.length - 1; i++) {
        if (/[*?]/.test(parts[i])) { break; }
        folder += "\\" + parts[i];
        var reason = getEsCachedLinkReason(folder);
        if (reason) { return { path: folder, reason: reason }; }
    }
    return null;
}

function getEsPathLinkReason(path) {
    var refused = getEsRefusedFolder(path);
    if (refused) { return refused.reason; }
    var p = String(path).replace(/\//g, "\\").replace(/\\+$/, "");
    if (p.indexOf("\\") < 0) { return null; }
    return getEsCachedLinkReason(p) || null;
}

function testEsSafePath(path, pathType) {
    // Test-Path (Any, Leaf or Container) for a path whose folders and itself are no links.
    if (getEsPathLinkReason(path)) { return false; }
    var type = esLower(pathType || "any");
    if (type === "leaf") { return esIsFile(path); }
    if (type === "container") { return esIsDir(path); }
    return esPathExists(path);
}

function testEsListableFolder(result, path) {
    var refused = getEsRefusedFolder(path);
    if (!refused) {
        var reason = getEsPathLinkReason(path);
        if (reason) { refused = { path: path, reason: reason }; }
    }
    if (refused) { addEsReadNote(result, refused.path, refused.reason); return false; }
    return esIsDir(path);
}

function addEsReadNote(result, path, problem, label) {
    // "<path> not read: <reason>" (once) for a link, else "<label>: <problem>".
    if (result === null || result === undefined || !problem) { return; }
    if (esContains(ES_LINK_REASONS, problem)) {
        var note = path + " not read: " + problem;
        if (!esContains(result.notes, note)) { addEsNote(result, note, "partial"); }
    } else if (label) { addEsNote(result, label + ": " + problem, "partial"); }
}

// ------------------------------------------------------------------ patterns and globs

function esLikeRegExp(pattern) {
    // PowerShell -like for * and ? (any case).
    var source = "";
    var text = String(pattern);
    for (var i = 0; i < text.length; i++) {
        var ch = text.charAt(i);
        source += ch === "*" ? "[\\s\\S]*" : (ch === "?" ? "[\\s\\S]" : esRegexEscape(ch));
    }
    return new RegExp("^" + source + "$", "i");
}

function expandEsPathPattern(pattern, result) {
    // ~ = profile, {env:NAME} = variable (pattern skipped when unset), * and ? = glob. Returns
    // existing absolute local paths only; credential stores, devices and paths below a link
    // that is not followed are dropped before they are tested.
    var path = String(pattern);
    if (esStartsWith(path, "~")) { path = (getEsEnv("USERPROFILE") || "") + path.substr(1); }
    for (var round = 0; /\{env:([A-Za-z0-9_()]+)\}/.test(path); round++) {
        var name = /\{env:([A-Za-z0-9_()]+)\}/.exec(path)[1];
        var value = getEsEnv(name);
        if (!value || round >= 8) { return []; }
        path = path.split("{env:" + name + "}").join(value.replace(/\\+$/, ""));
    }
    path = path.replace(/\//g, "\\");
    if (!testEsLocalPath(path) || testEsCredentialPath(path) || testEsDeviceName(path)) { return []; }
    var refused = getEsRefusedFolder(path);
    if (refused) { addEsReadNote(result, refused.path, refused.reason); return []; }
    if (/[*?]/.test(path)) { return expandEsGlob(path, result); }
    return esPathExists(path) ? [path] : [];
}

function esFolderNames(folder) {
    // Names of the entries of a folder (folders and files, hidden ones too).
    var names = [];
    try {
        var item = ES_FSO.GetFolder(folder + "\\");
        var sub = new Enumerator(item.SubFolders);
        for (; !sub.atEnd(); sub.moveNext()) { names.push(String(sub.item().Name)); }
        var files = new Enumerator(item.Files);
        for (; !files.atEnd(); files.moveNext()) { names.push(String(files.item().Name)); }
    } catch (e) { /* not listable */ }
    return names;
}

function esGlobStep(current, part, result) {
    var next = [];
    var like = /[*?]/.test(part) ? esLikeRegExp(part) : null;
    for (var b = 0; b < current.length; b++) {
        if (!like) { next.push(current[b] + "\\" + part); continue; }
        var link = getEsPathLinkReason(current[b]);
        if (link) { addEsReadNote(result, current[b], link); continue; }
        var names = esFolderNames(current[b]);
        for (var n = 0; n < names.length; n++) { if (like.test(names[n])) { next.push(current[b] + "\\" + names[n]); } }
    }
    var kept = [];
    for (var k = 0; k < next.length; k++) {
        if (!testEsCredentialPath(next[k]) && !testEsDeviceName(next[k])) { kept.push(next[k]); }
    }
    return kept;
}

function expandEsGlob(path, result) {
    // Existing matches of a path with * or ? components, expanded one component at a time.
    var parts = String(path).split("\\");
    var current = [parts[0]];
    for (var i = 1; i < parts.length; i++) { current = esGlobStep(current, parts[i], result); }
    var found = [];
    for (var c = 0; c < current.length; c++) {
        var refused = getEsRefusedFolder(current[c]);
        if (refused) { addEsReadNote(result, refused.path, refused.reason); continue; }
        if (esPathExists(current[c])) { found.push(current[c]); }
    }
    return found;
}
