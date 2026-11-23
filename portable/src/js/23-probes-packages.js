// ---------------------------------------------------------------------------
// 23-probes-packages: package sources and mirrors, offline caches, installed software,
// optional Windows features (port of src/ps/23-probes-packages.ps1).
// ---------------------------------------------------------------------------

var ES_MAX_CONFIG_FILES = 20;
var ES_MAX_PACKAGES = 2000;

// ------------------------------------------------------------------ directory entries (JScript only)

// getEsDirEntries gives plain copies with the ps1 member names (Name, FullName, PSIsContainer).
function jsPkg_entryName(entry) { return String(entry.Name); }
function jsPkg_entryPath(entry) { return String(entry.FullName); }
function jsPkg_entryIsDir(entry) { return entry.PSIsContainer === true; }

function jsPkg_subdirs(path, max) {
    // The folders in a folder as {name, path} (getEsDirEntries: none below a link not followed).
    var entries = getEsDirEntries(path, max);
    var out = [];
    for (var i = 0; i < entries.length; i++) {
        if (jsPkg_entryIsDir(entries[i])) { out[out.length] = { name: jsPkg_entryName(entries[i]), path: jsPkg_entryPath(entries[i]) }; }
    }
    return out;
}

function jsPkg_push(list, value) { list[list.length] = value; }

function jsPkg_compareI(a, b) {
    // Case-insensitive order (PowerShell Sort-Object on strings), then code-unit order.
    var x = String(a).toLowerCase();
    var y = String(b).toLowerCase();
    if (x < y) { return -1; }
    if (x > y) { return 1; }
    return a < b ? -1 : (a > b ? 1 : 0);
}

function jsPkg_splitLines(text) {
    // Lines of a text without their trailing CR.
    var lines = String(text).split("\n");
    var out = [];
    for (var i = 0; i < lines.length; i++) { out[out.length] = lines[i].replace(/\r+$/, ""); }
    return out;
}

// ------------------------------------------------------------------ pkg.sources

function testEsLineMatch(line, patterns) {
    var lower = String(line).toLowerCase();
    for (var i = 0; i < patterns.length; i++) {
        if (lower.indexOf(String(patterns[i]).toLowerCase()) >= 0) { return true; }
    }
    return false;
}

function jsPkg_rawLines(config, file) {
    // The raw lines an entry keeps, as envscan.sh keeps them (es_config_raw): no blank lines,
    // no comment lines outside "lines" mode, no last line cut by the byte cap.
    var raw = jsPkg_splitLines(file.text);
    if (file.truncated && String(file.text).length >= config.max_bytes) { raw = raw.slice(0, raw.length - 1); }
    var out = [];
    for (var i = 0; i < raw.length; i++) {
        var line = raw[i];
        if (config.mode === "lines") { if (!testEsLineMatch(line, config.match)) { continue; } }
        else if (/^[ \t]*[#;]/.test(line)) { continue; }
        if (/^[ \t]*$/.test(line)) { continue; }
        out[out.length] = line;
    }
    return out;
}

function jsPkg_keptLines(config, text) {
    // The redacted lines of an entry (all, or the matching ones in "lines" mode).
    var lines = jsPkg_splitLines(text);
    if (config.mode !== "lines") { return lines; }
    var out = [];
    for (var i = 0; i < lines.length; i++) { if (testEsLineMatch(lines[i], config.match)) { out[out.length] = lines[i]; } }
    return out;
}

function readEsConfigFile(config, path) {
    var entry = { id: config.id, tool: config.tool, path: path, scope: config.scope, lines: [], urls: [], proxy_urls: [], truncated: false, error: null };
    if (config.mode === "list") {
        // A folder that is a link is listed only when it ends on a local path (getEsLinkReason).
        entry.error = getEsPathLinkReason(path);
        if (!entry.error) {
            var entries = getEsDirEntries(path, 200);
            for (var i = 0; i < entries.length; i++) { jsPkg_push(entry.lines, jsPkg_entryName(entries[i])); }
        }
        return entry;
    }
    var file = readEsTextFile(path, config.max_bytes);
    if (file.error) { entry.error = file.error; return entry; }
    // Endpoints (scheme://host[:port], never userinfo) and proxy settings (by their names,
    // 15-proxy) from the raw lines this entry keeps.
    var raw = jsPkg_rawLines(config, file);
    entry.urls = getEsEndpointUrls(raw.join("\n"));
    var settings = getEsConfigProxySettings(raw);
    entry.proxy_urls = convertToEsProxyUrls(settings);
    // For net.proxy (probe_pkg_sources moves them out of the entry).
    entry.proxy_settings = convertToEsProxySettingItems(settings, config.tool, path);
    // Redact the whole text first: secret blocks (JSON/YAML) and private keys span lines.
    entry.lines = jsPkg_keptLines(config, protectEsText(String(file.text)));
    entry.truncated = file.truncated === true;
    return entry;
}

function jsPkg_configPaths(result, config) {
    // The existing paths of a configs entry (files, or folders in "list" mode), at most 20.
    var paths = [];
    var isList = (config.mode === "list");
    for (var i = 0; i < config.paths.length; i++) {
        var found = expandEsPathPattern(String(config.paths[i]), result);
        for (var j = 0; j < found.length; j++) {
            if (esContains(paths, found[j])) { continue; }
            if (esIsDir(found[j]) !== isList) { continue; }
            if (paths.length < ES_MAX_CONFIG_FILES) { paths[paths.length] = found[j]; }
        }
    }
    return paths;
}

function getEsConfigEntries(result, configs) {
    var entries = [];
    for (var i = 0; i < configs.length; i++) {
        var paths = jsPkg_configPaths(result, configs[i]);
        for (var j = 0; j < paths.length; j++) {
            jsPkg_push(result.sources, "read " + paths[j]);
            var entry = readEsConfigFile(configs[i], paths[j]);
            addEsReadNote(result, paths[j], entry.error, "read " + paths[j]);
            entries[entries.length] = entry;
        }
    }
    return entries;
}

function jsPkg_collectConfigs(configs, urls, proxies, settings) {
    // The endpoints, proxy URLs and proxy settings of the config entries (the settings are
    // moved out of each entry, for net.proxy).
    for (var i = 0; i < configs.length; i++) {
        var entry = configs[i];
        var j;
        for (j = 0; j < entry.urls.length; j++) { urls[urls.length] = entry.urls[j]; }
        for (j = 0; j < entry.proxy_urls.length; j++) { proxies[proxies.length] = { tool: entry.tool, url: entry.proxy_urls[j], source: entry.path }; }
        var found = entry.proxy_settings || [];
        for (j = 0; j < found.length; j++) { if (found[j]) { settings[settings.length] = found[j]; } }
        delete entry["proxy_settings"];
    }
}

function probe_pkg_sources() {
    var r = newEsResult();
    var d = r.data;
    var configs = getEsConfigEntries(r, ES_CONFIGS);
    d.configs = configs;
    d.env = getEsEnvSubset(ES_PACKAGE_ENV);
    jsPkg_push(r.sources, "environment package variables");
    var git = getEsGitConfig(r);
    var urls = [];
    var proxies = [];
    var settings = [];
    d.git_config = git ? git.items : [];
    if (git) { urls = urls.concat(git.urls); proxies = proxies.concat(git.proxy_urls); }
    // The settings found by name, for net.proxy (as envscan.sh: the files, then git).
    jsPkg_collectConfigs(configs, urls, proxies, settings);
    if (git) { settings = settings.concat(git.proxy_settings); }
    ES_PKG_PROXY_SETTINGS = settings;
    // Endpoints from the raw variable values (the data keeps the redacted ones).
    var names = esKeys(d.env);
    for (var i = 0; i < names.length; i++) { urls = urls.concat(getEsEndpointUrls(getEsOrigEnv(names[i]) || "")); }
    d.endpoints = jsPkg_uniqueSortedI(urls);
    d.proxy_urls = proxies;
    d.config_count = configs.length;
    return r;
}

function jsPkg_uniqueSortedI(values) {
    // Sort-Object -Unique: non-empty values, sorted case-insensitively, each once (any case).
    var sorted = [];
    for (var i = 0; i < values.length; i++) { if (values[i]) { sorted[sorted.length] = String(values[i]); } }
    sorted.sort(jsPkg_compareI);
    var out = [];
    for (var j = 0; j < sorted.length; j++) {
        if (j === 0 || sorted[j].toLowerCase() !== sorted[j - 1].toLowerCase()) { out[out.length] = sorted[j]; }
    }
    return out;
}

// ------------------------------------------------------------------ pkg.caches

function getEsDirSummary(path, max) {
    var limit = max === undefined ? 10000 : max;
    var count = getEsDirEntries(path, limit + 1).length;
    var modified = null;
    try { modified = new Date(ES_FSO.GetFolder(path).DateLastModified); } catch (e) { modified = null; }
    return { entries: count > limit ? limit : count, truncated: count > limit, modified_utc: modified };
}

function jsPkg_addCache(r, cache, path, seen, caches) {
    var key = path.toLowerCase();
    if (esHas(seen, key) || !esIsDir(path)) { return; }
    seen[key] = true;
    // A cache folder that is a link is listed only when it ends on a local path.
    var link = getEsPathLinkReason(path);
    if (link) { addEsReadNote(r, path, link); return; }
    jsPkg_push(r.sources, "list " + path);
    var summary = getEsDirSummary(path);
    caches[caches.length] = { id: cache.id, tool: cache.tool, path: path, entries: summary.entries, truncated: summary.truncated, modified_utc: summary.modified_utc };
}

function probe_pkg_caches() {
    var r = newEsResult();
    var caches = [];
    var seen = {};
    for (var i = 0; i < ES_CACHES.length; i++) {
        var cache = ES_CACHES[i];
        for (var j = 0; j < cache.paths.length; j++) {
            var found = expandEsPathPattern(String(cache.paths[j]), r);
            for (var k = 0; k < found.length; k++) { jsPkg_addCache(r, cache, found[k], seen, caches); }
        }
    }
    r.data.caches = caches;
    // Caches left out because they are links are not "not found": the probe is partial.
    if (caches.length === 0 && r.status === "ok") { r.status = "not_found"; jsPkg_push(r.notes, "no known dependency cache directory exists for this user"); }
    return r;
}

// ------------------------------------------------------------------ pkg.installed

var ES_UNINSTALL_VIEWS = [
    ["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "machine"],
    ["HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "machine-32bit"],
    ["HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "user"]
];

function jsPkg_uninstallItem(key, source) {
    // One Uninstall subkey as a package, or null (no name, a system component, an update).
    var name = getEsRegValue(key, "DisplayName");
    if (name === null || name === undefined || String(name) === "") { return null; }
    if (String(getEsRegValue(key, "SystemComponent")) === "1") { return null; }
    if (getEsRegValue(key, "ParentKeyName")) { return null; }
    var release = getEsRegValue(key, "ReleaseType");
    if (release !== null && release !== undefined && /update|hotfix/i.test(String(release))) { return null; }
    var version = getEsRegValue(key, "DisplayVersion");
    var publisher = getEsRegValue(key, "Publisher");
    return { name: String(name), version: version === null || version === undefined ? "" : String(version),
        publisher: publisher === null || publisher === undefined ? "" : String(publisher), source: source };
}

function getEsUninstallEntries(result) {
    var packages = [];
    for (var i = 0; i < ES_UNINSTALL_VIEWS.length; i++) {
        var view = ES_UNINSTALL_VIEWS[i];
        jsPkg_push(result.sources, "registry " + view[0].replace(/^(HK..):/, "$1"));
        if (!testEsRegKey(view[0])) { continue; }
        var subkeys = getEsRegSubkeys(view[0]);
        for (var j = 0; j < subkeys.length; j++) {
            var item = jsPkg_uninstallItem(view[0] + "\\" + subkeys[j], view[1]);
            if (item) { packages[packages.length] = item; }
        }
    }
    return packages;
}

function getEsAppxGroup(result) {
    // Store (Appx) packages: Get-AppxPackage has no WSH equivalent (the AppModel repository in
    // the registry also lists staged, framework and other users' packages), so the count is
    // unknown, never 0.
    addEsNote(result, "Store (Appx) packages are listed only when the scan runs in Windows PowerShell", "partial");
    return { name: "appx", items: [], listed: false };
}

function jsPkg_manifestVersion(result, manifest) {
    // The version in a package manifest (nuspec or scoop manifest.json), or null.
    var refused = getEsRefusedFolder(manifest);
    if (refused) { addEsReadNote(result, refused.path, refused.reason); return null; }
    if (!esIsFile(manifest)) { return null; }
    var file = readEsTextFile(manifest, 8192);
    addEsReadNote(result, manifest, file.error);
    var m = /"?<?version"?>?\s*[:>]?\s*"?([0-9][^"<\s,]*)/i.exec(String(file.text || ""));
    return m ? m[1] : null;
}

function getEsFolderPackages(result, roots, source, manifestPattern) {
    var packages = [];
    for (var i = 0; i < roots.length; i++) {
        var root = roots[i];
        if (!root || !testEsLocalPath(root) || !testEsListableFolder(result, root)) { continue; }
        jsPkg_push(result.sources, "list " + root);
        var dirs = jsPkg_subdirs(root, 1000);
        for (var j = 0; j < dirs.length; j++) {
            var version = null;
            if (manifestPattern) {
                // A package folder (or "current") that is a link not followed is noted, not entered.
                version = jsPkg_manifestVersion(result, esJoinPath(dirs[j].path, manifestPattern.replace("<name>", dirs[j].name)));
            }
            packages[packages.length] = { name: dirs[j].name, version: version, publisher: null, source: source };
        }
    }
    return packages;
}

function jsPkg_moduleVersions(dir) {
    var versions = [];
    var subdirs = jsPkg_subdirs(dir, 50);
    for (var i = 0; i < subdirs.length; i++) {
        if (/^\d+(\.\d+)+$/.test(subdirs[i].name)) { versions[versions.length] = subdirs[i].name; }
    }
    return versions.join(", ");
}

function getEsModulePackages(result) {
    var packages = [];
    var roots = String(getEsOrigEnv("PSModulePath") || "").split(";");
    for (var i = 0; i < roots.length; i++) {
        var root = roots[i];
        if (!root || !testEsLocalPath(root) || !testEsListableFolder(result, root)) { continue; }
        jsPkg_push(result.sources, "list " + root);
        var dirs = jsPkg_subdirs(root, 500);
        for (var j = 0; j < dirs.length; j++) {
            packages[packages.length] = { name: dirs[j].name, version: jsPkg_moduleVersions(dirs[j].path), publisher: null, source: "psmodule" };
        }
    }
    return packages;
}

function jsPkg_scoopRoots() {
    var roots = [];
    var scoop = getEsOrigEnv("SCOOP");
    var profilePath = getEsOrigEnv("USERPROFILE");
    var programData = getEsOrigEnv("ProgramData");
    if (scoop) { roots[roots.length] = esJoinPath(scoop, "apps"); }
    if (profilePath) { roots[roots.length] = esJoinPath(profilePath, "scoop\\apps"); }
    if (programData) { roots[roots.length] = esJoinPath(programData, "scoop\\apps"); }
    return roots;
}

function jsPkg_installedGroups(r) {
    var programData = getEsOrigEnv("ProgramData");
    var choco = getEsOrigEnv("ChocolateyInstall");
    if (!choco && programData) { choco = esJoinPath(programData, "chocolatey"); }
    return [
        { name: "uninstall-registry", items: getEsUninstallEntries(r) },
        getEsAppxGroup(r),
        { name: "chocolatey", items: choco ? getEsFolderPackages(r, [esJoinPath(choco, "lib")], "chocolatey", "<name>.nuspec") : [] },
        { name: "scoop", items: getEsFolderPackages(r, jsPkg_scoopRoots(), "scoop", "current\\manifest.json") },
        { name: "powershell-modules", items: getEsModulePackages(r) }
    ];
}

function jsPkg_compareByName(a, b) { return jsPkg_compareI(a.name, b.name); }

function probe_pkg_installed() {
    var r = newEsResult();
    var groups = jsPkg_installedGroups(r);
    var all = [];
    var managers = [];
    for (var i = 0; i < groups.length; i++) {
        // A source that could not be read has an unknown count, never 0.
        var count = groups[i].listed === false ? null : groups[i].items.length;
        managers[managers.length] = { name: groups[i].name, count: count };
        all = all.concat(groups[i].items);
    }
    all.sort(jsPkg_compareByName);
    r.data.managers = managers;
    r.data.count = all.length;
    r.data.packages = all.slice(0, ES_MAX_PACKAGES);
    r.data.truncated = all.length > ES_MAX_PACKAGES;
    return r;
}

// ------------------------------------------------------------------ pkg.features

function probe_pkg_features() {
    var r = newEsResult();
    var items = addEsCimItems(r, "Win32_OptionalFeature", "root/cimv2", "InstallState=1", ["Name"]);
    var names = [];
    for (var i = 0; i < items.length; i++) { names[names.length] = String(items[i].Name); }
    names.sort(jsPkg_compareI);
    r.data.enabled = names;
    r.data.count = names.length;
    r.data.powershell_v2_engine = esContainsI(names, "MicrosoftWindowsPowerShellV2Root");
    if (names.length === 0 && r.status === "ok") { addEsNote(r, "no enabled optional features were returned", "partial"); }
    return r;
}
