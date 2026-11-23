// ---------------------------------------------------------------------------
// 23-git-config: git's configuration for pkg.sources (port of src/ps/23-git-config.ps1):
// git config --list run so that it reads no repository and nothing on the network, and the
// include files it names, read one level deep by the scanner itself (git runs with
// --no-includes).
// ---------------------------------------------------------------------------

function jsGit_trimEnd(text, ch) {
    // text without every trailing ch (PowerShell TrimEnd(ch)).
    var s = String(text);
    while (s.length > 0 && s.charAt(s.length - 1) === ch) { s = s.substring(0, s.length - 1); }
    return s;
}

function jsGit_slashes(text) {
    // "/" as "\" (PowerShell .Replace('/', '\')).
    return String(text).replace(/\//g, "\\");
}

function getEsGitHome() {
    // The home folder Git for Windows uses: HOME, else HOMEDRIVE + HOMEPATH when that folder
    // exists, else USERPROFILE. Only an absolute local path is checked: a home on the network
    // (or a relative one) is kept as it is and never touched.
    var gitHome = getEsOrigEnv("HOME");
    var drive = getEsOrigEnv("HOMEDRIVE");
    var homePath = getEsOrigEnv("HOMEPATH");
    if (!gitHome && drive && homePath) {
        var candidate = drive + homePath;
        if (!testEsLocalPath(candidate) || getEsPathLinkReason(candidate) || esIsDir(candidate)) { gitHome = candidate; }
    }
    if (!gitHome) { gitHome = getEsOrigEnv("USERPROFILE"); }
    return gitHome ? String(gitHome) : null;
}

function joinEsGitPath(folder, child) {
    // Folder\Child as text (nothing is looked up).
    if (!folder) { return null; }
    return jsGit_trimEnd(jsGit_slashes(folder), "\\") + "\\" + child;
}

function getEsGitLocations() {
    // The configuration locations of the git child, in order: the variable that replaces a
    // location git must not read, the label and scope of its note and the paths to check. HOME
    // covers the home folder and its .gitconfig; XDG_CONFIG_HOME its git folder (default
    // <home>\.config\git, below_home); ProgramData the system-wide file of Git for Windows
    // (strict: anything but a local path is refused, and GIT_CONFIG_NOSYSTEM=1 switches the
    // system scope off).
    var gitHome = getEsGitHome() || "";
    var xdg = getEsOrigEnv("XDG_CONFIG_HOME") || "";
    var xdgPaths = xdg ? [xdg, joinEsGitPath(xdg, "git")] : [joinEsGitPath(gitHome, ".config\\git")];
    var programData = getEsOrigEnv("ProgramData") || "";
    var pdPaths = programData ? [programData, joinEsGitPath(programData, "Git"), joinEsGitPath(programData, "Git\\config")] : [];
    return [
        { name: "HOME", label: "git home folder", scope: "global", paths: [gitHome, joinEsGitPath(gitHome, ".gitconfig")] },
        { name: "XDG_CONFIG_HOME", label: "XDG_CONFIG_HOME", scope: "global", paths: xdgPaths, below_home: !xdg },
        { name: "GIT_CONFIG_GLOBAL", label: "GIT_CONFIG_GLOBAL", scope: "global", paths: [getEsOrigEnv("GIT_CONFIG_GLOBAL")] },
        { name: "GIT_CONFIG_SYSTEM", label: "GIT_CONFIG_SYSTEM", scope: "system", paths: [getEsOrigEnv("GIT_CONFIG_SYSTEM")] },
        { name: "GIT_CONFIG_NOSYSTEM", label: "ProgramData", scope: "system", strict: true, paths: pdPaths }
    ];
}

function getEsGitLocationProblem(path, strict) {
    // Why git must not read a location: it is on a network path, or it (or a folder above it)
    // is a link that is not followed (getEsPathLinkReason). A relative path is git's own
    // business, unless strict. null when git may read it.
    if (!path) { return null; }
    var p = jsGit_slashes(path);
    if (testEsNetworkPath(p)) { return "is on a network path"; }
    if (!testEsLocalPath(p)) { return strict ? "is not a local path" : null; }
    var link = getEsPathLinkReason(p);
    if (link) { return "is behind a link (" + link + ")"; }
    return null;
}

function jsGit_firstProblem(location) {
    // The first path of a location git must not read, as {path, problem}, else null.
    for (var i = 0; i < location.paths.length; i++) {
        var path = location.paths[i];
        if (!path) { continue; }
        var problem = getEsGitLocationProblem(String(path), location.strict === true);
        if (problem) { return { path: String(path), problem: problem }; }
    }
    return null;
}

function getEsGitChildEnv(result) {
    // Environment of the git child: the repository search stops at the scanner temp folder,
    // and a configuration location on a network path or behind a link (getEsGitLocations) is
    // replaced by an empty local folder, or the system scope is switched off (partial, noted).
    var local = esJoinPath(ES_TMP, "githome");
    var overrides = { GIT_CEILING_DIRECTORIES: getEsParentDir(ES_TMP) };
    var locations = getEsGitLocations();
    for (var i = 0; i < locations.length; i++) {
        var location = locations[i];
        // The default XDG folder lies in the home folder: a replaced home replaces it too.
        if (location.below_home && esHas(overrides, "HOME")) { continue; }
        var found = jsGit_firstProblem(location);
        if (!found) { continue; }
        var name = location.name;
        if (name === "GIT_CONFIG_NOSYSTEM") {
            overrides[name] = "1";
        } else {
            if (!ES_FSO.FolderExists(local)) { ES_FSO.CreateFolder(local); }
            overrides[name] = name.indexOf("GIT_CONFIG_") === 0 ? esJoinPath(local, "none") : local;
        }
        addEsNote(result, location.label + " " + found.path + " " + found.problem + ": " + location.scope +
            " git configuration from there is not read", "partial");
    }
    return overrides;
}

function invokeEsCommandWithEnv(overrides, parameters) {
    // invokeEsCommand with environment variables set for the child only (restored after);
    // they pass the child allowlist as per-call extras.
    // Previous values are restored exactly (an empty variable stays an empty one).
    var saved = [];
    var names = esKeys(overrides);
    try {
        for (var i = 0; i < names.length; i++) {
            saved.push([names[i], getEsEnvExact(names[i])]);
            setEsEnvValue(names[i], overrides[names[i]]);
        }
        return withEsChildExtras(names, function () {
            return invokeEsCommand(parameters.filePath, parameters.args, parameters.timeoutSec,
                parameters.encoding, parameters.maxLines, parameters.workingDirectory);
        });
    } finally {
        restoreEsChildEnv(saved);
    }
}

var ES_GIT_ESCAPES = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, "\"": 34, "\\": 92 };

function jsGit_unquoteBody(body) {
    // The body of a C-quoted git path as text, or null (see convertFromEsGitQuoted).
    var out = "";
    var bytes = [];
    for (var i = 0; i < body.length; i++) {
        var ch = body.charAt(i);
        if (ch === "\"") { return null; }
        if (ch === "\\") {
            var octal = /^[0-3][0-7][0-7]/.exec(body.substring(i + 1));
            if (octal) {
                var d = octal[0];
                bytes[bytes.length] = (d.charCodeAt(0) - 48) * 64 + (d.charCodeAt(1) - 48) * 8 + (d.charCodeAt(2) - 48);
                i += 3;
                continue;
            }
            if (i + 1 >= body.length) { return null; }
            var next = body.charAt(i + 1);
            if (!esHas(ES_GIT_ESCAPES, next)) { return null; }
            bytes[bytes.length] = ES_GIT_ESCAPES[next];
            i++;
            continue;
        }
        if (bytes.length > 0) { out += convertFromEsUtf8Bytes(bytes); bytes = []; }
        out += ch;
    }
    if (bytes.length > 0) { out += convertFromEsUtf8Bytes(bytes); }
    return out;
}

function convertFromEsGitQuoted(text) {
    // A path as git prints it: an unusual one (a backslash, a quote, a non-ASCII character) is
    // in double quotes with C escapes, each byte of a non-ASCII character as \ooo (octal,
    // UTF-8). Text without a leading quote is returned unchanged; null when the quoted form does
    // not decode (no closing quote, an escape git never writes, bytes that are not UTF-8).
    var t = String(text);
    if (t.charAt(0) !== "\"") { return t; }
    if (t.length < 2 || t.charAt(t.length - 1) !== "\"") { return null; }
    var out = jsGit_unquoteBody(t.substring(1, t.length - 1));
    if (out === null || out.indexOf(String.fromCharCode(0xFFFD)) >= 0) { return null; }
    return out;
}

function getEsGitOriginFile(origin) {
    // The file of a --show-origin origin ("file:<path>") as a Windows path; null for another
    // origin (command line, standard input, blob) or none.
    if (!origin || String(origin).indexOf("file:") !== 0) { return null; }
    var path = convertFromEsGitQuoted(String(origin).substring(5));
    if (!path) { return null; }
    return jsGit_slashes(path);
}

function resolveEsGitIncludePath(value, originFile, gitHome) {
    // The file an include.path names, as git resolves it: ~/ is the git home folder, a relative
    // path is relative to the folder of the file that has the include. null where git would
    // use the current drive or location, another user's home, its install prefix (%(prefix)/)
    // or the folder of an origin that is not a file; also for device paths.
    var path = jsGit_slashes(value);
    if (path.indexOf("~\\") === 0) {
        if (!gitHome) { return null; }
        return jsGit_trimEnd(jsGit_slashes(gitHome), "\\") + path.substring(1);
    }
    if (/^\\\\[.?]\\/.test(path)) { return null; }
    if (/^[A-Za-z]:\\/.test(path) || path.indexOf("\\\\") === 0) { return path; }
    if (/^(\\|[A-Za-z]:|~|%\()/.test(path) || !originFile) { return null; }
    return getEsParentDir(originFile) + "\\" + path;
}

function jsGit_configArgs(context, extra) {
    var args = ["config", "--list"];
    if (context.show_origin) { args[args.length] = "--show-origin"; }
    if (context.no_includes) { args[args.length] = "--no-includes"; }
    for (var i = 0; i < extra.length; i++) { args[args.length] = extra[i]; }
    return args;
}

function invokeEsGitConfigList(result, context, extra) {
    // git config --list --show-origin --no-includes <extra>, from the scanner's own empty temp
    // folder (no repository configuration). A git that rejects --show-origin (before 2.8) or
    // --no-includes (before 1.7.10, which reads no includes) runs again without that option.
    var more = extra || [];
    while (true) {
        var parameters = { filePath: context.git, args: jsGit_configArgs(context, more), timeoutSec: 0,
            encoding: "UTF8", maxLines: 4000, workingDirectory: ES_TMP };
        var run = invokeEsCommandWithEnv(context.env, parameters);
        result.sources[result.sources.length] = "run " + run.command;
        run.ok = (!run.timed_out && !run.error && run.exit_code === 0);
        if (run.ok || run.timed_out || run.error) { return run; }
        var text = String(run.stdout || "") + "\n" + String(run.stderr || "");
        if (context.show_origin && /(^|[^\-\w])show-origin/.test(text)) { context.show_origin = false; }
        else if (context.no_includes && /(^|[^\-\w])no-includes/.test(text)) { context.no_includes = false; }
        else { return run; }
    }
}

function getEsGitProblem(run) {
    if (run.timed_out) { return "timed out"; }
    if (run.error) { return String(run.error); }
    var lines = String(run.stderr || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
        var line = esTrim(lines[i]);
        if (line) { return "exit code " + run.exit_code + ": " + line; }
    }
    return "exit code " + run.exit_code;
}

var ES_GIT_LINE_ORIGIN_RE = /^([^\t]*)\t([^=]+)=?([\s\S]*)$/;
var ES_GIT_LINE_PLAIN_RE = /^()([^=]+)=?([\s\S]*)$/;

function jsGit_addEntry(out, from, key, value) {
    // One git setting into out: the redacted item and the endpoints of its raw value (and of
    // the base of url.<base>.insteadOf, a mirror).
    out.items[out.items.length] = { origin: from, key: protectEsValue(key), value: protectEsNamedValue(key, value) };
    var found = getEsEndpointUrls(value);
    var mirror = /^url\.([\s\S]+)\.(push)?insteadof$/i.exec(key);
    if (mirror) { found = found.concat(getEsEndpointUrls(mirror[1])); }
    for (var i = 0; i < found.length; i++) { out.urls[out.urls.length] = found[i]; }
}

function jsGit_includeOf(key, from, value) {
    // The include directive of a setting ({origin, value, condition}), else null.
    if (/^include\.path$/i.test(key)) { return { origin: from, value: value, condition: null }; }
    var m = /^includeif\.([\s\S]+)\.path$/i.exec(key);
    if (m) { return { origin: from, value: value, condition: m[1] }; }
    return null;
}

function addEsGitEntries(out, text, origin, hasOrigin) {
    // The entries of one git config --list output into out (items redacted, urls, proxy_urls).
    // origin (an include file) replaces the listed origin. Endpoints come from the raw values;
    // proxies from the names of the settings (15-proxy), per origin. Returns the include
    // directives: {origin, value, condition}.
    var pattern = hasOrigin ? ES_GIT_LINE_ORIGIN_RE : ES_GIT_LINE_PLAIN_RE;
    var includes = [];
    var proxy = { state: newEsProxyState(), origin: "" };
    var lines = String(text || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
        var m = pattern.exec(lines[i]);
        if (!m) { continue; }
        var setting = jsGit_trimEnd(lines[i].substring(m[1].length + (hasOrigin ? 1 : 0)), "\r");
        var from = origin ? origin : m[1];
        var key = esTrim(m[2]);
        var value = jsGit_trimEnd(m[3], "\r");
        jsGit_addEntry(out, from, key, value);
        if (from !== proxy.origin) { addEsGitProxyUrls(out, proxy); proxy.origin = from; }
        addEsProxyGitLine(proxy.state, setting);
        var include = jsGit_includeOf(key, from, value);
        if (include) { includes[includes.length] = include; }
    }
    addEsGitProxyUrls(out, proxy);
    return includes;
}

function addEsGitProxyUrls(out, proxy) {
    // The proxies of the git settings of one origin, as {tool: "git", url, source}, and the
    // settings found by name (net.proxy package_managers) when out collects them.
    var settings = completeEsProxySource(proxy.state);
    var origin = protectEsValue(proxy.origin);
    var urls = convertToEsProxyUrls(settings);
    for (var i = 0; i < urls.length; i++) {
        out.proxy_urls[out.proxy_urls.length] = { tool: "git", url: urls[i], source: origin };
    }
    if (esHas(out, "proxy_settings")) {
        out.proxy_settings = out.proxy_settings.concat(convertToEsProxySettingItems(settings, "git", origin));
    }
}

function addEsGitIncludeNote(result, reason, path, status) {
    var note = "git include not read (" + reason + "): " + path;
    if (!esContains(result.notes, note)) { addEsNote(result, note, status === undefined ? "partial" : status); }
}

function getEsGitIncludePathReason(path) {
    // Why an include path is not read, from its text alone (null: it may be). A credential
    // store (testEsCredentialPath) and a device name are never opened, tested or listed.
    if (!path) { return "not a local path"; }
    if (testEsCredentialPath(path)) { return "credential store"; }
    if (testEsNetworkPath(path)) { return "network path"; }
    if (!testEsLocalPath(path)) { return "not a local path"; }
    if (testEsDeviceName(path)) { return "unreadable"; }
    return null;
}

function getEsGitIncludeFileReason(path) {
    // Why a local include file is not read, without opening it: "missing" (skipped, as git
    // skips it), "unreadable" (a folder), "network path" (a cloud placeholder, which downloads
    // when read, or a link to the network), "credential store" (a link to one) or "not a local
    // path" (a link to an unknown target), for the file and every folder above it. null: git
    // may read it.
    var refused = getEsRefusedFolder(path);
    if (refused) { return convertToEsGitLinkReason(refused.reason); }
    if (esIsDir(path)) { return "unreadable"; }
    if (!esIsFile(path)) { return "missing"; }
    var item = esGetItem(path);
    if (item === null) { return "missing"; }
    if (testEsPlaceholderFile(item)) { return "network path"; }
    return convertToEsGitLinkReason(getEsLinkReason(item, path));
}

function convertToEsGitLinkReason(linkReason) {
    // A getEsLinkReason reason as the reason of a git include note; null for no reason.
    if (!linkReason) { return null; }
    if (linkReason.indexOf("network path") >= 0) { return "network path"; }
    if (linkReason.indexOf("credential store") >= 0) { return "credential store"; }
    return "not a local path";
}

function jsGit_includeFile(context, include) {
    // The resolved path of an include and why it is not read: {path, reason}; reason
    // "missing" (skipped silently) or "seen" (already read) need no note.
    var path = resolveEsGitIncludePath(String(include.value), getEsGitOriginFile(include.origin), context.home);
    var reason = getEsGitIncludePathReason(path);
    if (!reason) {
        var key = path.toLowerCase();
        if (esHas(context.seen, key)) { return { path: path, reason: "seen" }; }
        context.seen[key] = true;
        reason = getEsGitIncludeFileReason(path);
    }
    return { path: path, reason: reason };
}

function readEsGitInclude(result, context, include, out) {
    // One include.path: listed with --file when it names a regular file on a local drive (each
    // file once), otherwise noted. Returns the include directives in that file.
    var file = jsGit_includeFile(context, include);
    var reason = file.reason;
    if (reason === "seen" || reason === "missing") { return []; }
    if (!reason) {
        var run = invokeEsGitConfigList(result, context, ["--file", file.path]);
        if (run.ok) { return addEsGitEntries(out, String(run.stdout || ""), "file:" + file.path, context.show_origin); }
        reason = "unreadable";
    }
    addEsGitIncludeNote(result, reason, file.path ? file.path : String(include.value));
    return [];
}

function readEsGitIncludes(result, context, includes, out) {
    // include.path files are read one level deep: an include inside one is noted (partial).
    // includeIf.<condition>.path is only noted: its condition is not evaluated (no status
    // change).
    var nested = [];
    var i;
    for (i = 0; i < includes.length; i++) {
        if (includes[i].condition !== null) {
            addEsGitIncludeNote(result, "condition " + includes[i].condition, includes[i].value, "");
            continue;
        }
        nested = nested.concat(readEsGitInclude(result, context, includes[i], out));
    }
    for (i = 0; i < nested.length; i++) {
        if (nested[i].condition !== null) { addEsGitIncludeNote(result, "condition " + nested[i].condition, nested[i].value, ""); }
        else { addEsGitIncludeNote(result, "nested include", nested[i].value); }
    }
}

function jsGit_uniqueSorted(values) {
    // Sort-Object -Unique of lower-case strings: sorted, each once.
    var sorted = values.slice(0).sort();
    var out = [];
    for (var i = 0; i < sorted.length; i++) {
        if (i === 0 || sorted[i] !== sorted[i - 1]) { out[out.length] = sorted[i]; }
    }
    return out;
}

function getEsGitConfig(result) {
    // git config --list as {items, urls, proxy_urls, proxy_settings}, with the files its
    // include.path entries name (one level). git itself never follows an include:
    // --no-includes (a git without that option has no includes, so none are read).
    var git = findEsToolPath("git");
    if (!git) { return null; }
    var childEnv;
    try { childEnv = getEsGitChildEnv(result); }
    catch (e) { addEsNote(result, "git config not run: " + esErrorText(e), "partial"); return null; }
    // ~/ in an include is the user's real home, also when git runs with a local stand-in for a
    // home on the network: an include there is then noted as a network path, not missed.
    var context = { git: git, env: childEnv, home: getEsGitHome(), show_origin: true, no_includes: true, seen: {} };
    var run = invokeEsGitConfigList(result, context);
    if (!run.ok) {
        addEsNote(result, "git config: " + getEsGitProblem(run), "partial");
        if (run.timed_out || run.error) { return null; }
    }
    var out = { items: [], urls: [], proxy_urls: [], proxy_settings: [] };
    var includes = addEsGitEntries(out, String(run.stdout || ""), "", context.show_origin);
    if (context.no_includes) { readEsGitIncludes(result, context, includes, out); }
    out.urls = jsGit_uniqueSorted(out.urls);
    return out;
}
