// ---------------------------------------------------------------------------
// 30-findings-host: the resource, file system, user, platform and scan checks of
// src/ps/30-findings.ps1, and getEsFindings (the checks in order, sorted by severity).
// Shares the PowerShell value helpers (jsFd*) of 30-findings.js.
// ---------------------------------------------------------------------------

var JS_FD_CHECK_NAMES = [
    "Get-EsExecFindings", "Get-EsTlsFindings", "Get-EsPackageFindings", "Get-EsNetworkFindings",
    "Get-EsResourceFindings", "Get-EsFsFindings", "Get-EsUserFindings", "Get-EsPlatformFindings", "Get-EsScanFindings"
];

function jsFdIsFalse(v) {
    // $v -eq $false: $false, 0 and the text "False".
    return v === false || v === 0 || (typeof v === "string" && v.toLowerCase() === "false");
}

function jsFdIsTrue(v) {
    // $v -eq $true: $true, a non-zero number and the text "True".
    return v === true || (typeof v === "number" && v !== 0) || (typeof v === "string" && v.toLowerCase() === "true");
}

// ------------------------------------------------------------------ resources and file system

function getEsResourceFindings() {
    var out = [], memory = jsFdData("hw.memory");
    var available = jsFdGet(memory, "available_mb");
    if (available !== null && available !== undefined && jsFdInt(available) < jsFdInt(ES_THRESHOLDS.memory_min_mb)) {
        jsFdAdd(out, newEsFinding("limits.memory_low", jsFdStr(available) + " MB available of " + jsFdStr(jsFdGet(memory, "total_mb")) + " MB", ["hw.memory"]));
    }
    var low = [], volumes = jsFdList(jsFdGet(jsFdData("hw.storage"), "volumes"));
    for (var i = 0; i < volumes.length; i++) {
        var free = jsFdGet(volumes[i], "free_mb");
        if (!jsFdEqI(jsFdGet(volumes[i], "kind"), "local") || free === null || free === undefined) { continue; }
        if (jsFdInt(free) < jsFdInt(ES_THRESHOLDS.disk_free_min_mb)) { low.push(jsFdStr(jsFdGet(volumes[i], "mount")) + " " + jsFdStr(free) + " MB free"); }
    }
    if (low.length > 0) { jsFdAdd(out, newEsFinding("fs.low_disk", joinEsShort(low), ["hw.storage"])); }
    return out;
}

function getEsFsFindings() {
    var out = [], semantics = jsFdData("fs.semantics");
    if (jsFdHas(semantics, "long_paths_enabled") && jsFdIsFalse(jsFdGet(semantics, "long_paths_enabled"))) {
        jsFdAdd(out, newEsFinding("fs.long_paths_disabled", "LongPathsEnabled is 0 or missing", ["fs.semantics"]));
    }
    var symlink = jsFdGet(semantics, "symlink");
    if (jsFdTruthy(symlink) && !jsFdEqI(symlink, "ok")) {
        var mode = jsFdTruthy(jsFdGet(jsFdData("user.identity"), "developer_mode")) ? "Developer Mode on" : "Developer Mode off";
        jsFdAdd(out, newEsFinding("fs.symlinks_unavailable", "Symbolic link test: " + jsFdStr(symlink) + " (" + mode + ")", ["fs.semantics", "user.identity"]));
    }
    if (jsFdHas(semantics, "case_sensitive") && jsFdIsFalse(jsFdGet(semantics, "case_sensitive"))) {
        jsFdAdd(out, newEsFinding("fs.case_insensitive", "Temp directory is case-insensitive (Windows default)", ["fs.semantics"]));
    }
    var writable = jsFdList(jsFdGet(jsFdData("fs.locations"), "writable_install_locations"));
    if (testEsHasFacts(["fs.locations"]) && writable.length === 0) {
        jsFdAdd(out, newEsFinding("fs.no_writable_install_dir", "None of LOCALAPPDATA, LOCALAPPDATA\\Programs, ProgramData, the profile or the system drive root accepts new files", ["fs.locations"]));
    }
    return out;
}

// ------------------------------------------------------------------ user and locale

function jsFdProfileReasons(userProfile) {
    var reasons = [], type = jsFdGet(userProfile, "profile_type");
    if (jsFdTruthy(type) && !jsFdEqI(type, "local")) { reasons.push("profile type " + jsFdStr(type)); }
    var redirected = jsFdGet(userProfile, "redirected_folders");
    if (esIsTable(redirected) && jsFdTableKeys(redirected).length > 0) { reasons.push("redirected: " + jsFdTableKeys(redirected).join(", ")); }
    var fslogix = jsFdGet(userProfile, "fslogix");
    if (jsFdTruthy(fslogix) && jsFdTruthy(jsFdGet(fslogix, "enabled"))) { reasons.push("FSLogix profile container"); }
    return reasons;
}

function jsFdNetworkReasons(userProfile) {
    var network = [];
    if (jsFdTruthy(jsFdGet(userProfile, "home_network"))) { network.push("home or HOMESHARE is on a network share"); }
    if (jsFdTruthy(jsFdGet(userProfile, "appdata_network"))) { network.push("APPDATA is on a network share"); }
    var onedrive = jsFdGet(userProfile, "onedrive");
    var synced = jsFdTruthy(onedrive) ? jsFdList(jsFdGet(onedrive, "folders_in_onedrive")) : [];
    if (synced.length > 0) { network.push("in OneDrive: " + synced.join(", ")); }
    return network;
}

function getEsUserFindings() {
    var out = [];
    if (jsFdIsTrue(jsFdGet(jsFdData("user.identity"), "is_admin"))) {
        jsFdAdd(out, newEsFinding("user.is_admin", "The scanning process is elevated", ["user.identity"]));
    }
    var userProfile = jsFdData("user.profile");
    var reasons = jsFdProfileReasons(userProfile);
    if (reasons.length > 0) { jsFdAdd(out, newEsFinding("user.profile_nonpersistent", joinEsShort(reasons), ["user.profile"])); }
    var network = jsFdNetworkReasons(userProfile);
    if (network.length > 0) { jsFdAdd(out, newEsFinding("user.home_network", joinEsShort(network), ["user.profile"])); }
    var locale = jsFdData("os.time_locale"), ansi = jsFdGet(locale, "codepage_ansi");
    if (jsFdTruthy(ansi) && jsFdStr(ansi) !== "65001") {
        var detail = "ANSI code page " + jsFdStr(ansi) + ", OEM " + jsFdStr(jsFdGet(locale, "codepage_oem")) + ", console " + jsFdStr(jsFdGet(locale, "codepage_console"));
        jsFdAdd(out, newEsFinding("locale.non_utf8", detail, ["os.time_locale"]));
    }
    if (jsFdStr(jsFdGet(locale, "decimal_separator")) === ",") {
        jsFdAdd(out, newEsFinding("locale.decimal_comma", "Locale " + jsFdStr(jsFdGet(locale, "locale")) + " uses a decimal comma", ["os.time_locale"]));
    }
    return out;
}

// ------------------------------------------------------------------ platform

function jsFdArchDiffers(osArch, arch) {
    return (jsFdEqI(osArch, "x86_64") && jsFdEqI(arch, "x86")) || (jsFdEqI(osArch, "arm64") && !jsFdEqI(arch, "arm64"));
}

function getEsArchMismatches() {
    var osArch = jsFdStr(jsFdGet(jsFdData("os.identity"), "arch")), items = [];
    var tools = jsFdGet(jsFdData("tools.inventory"), "tools");
    var ids = jsFdTableKeys(tools);
    for (var i = 0; i < ids.length; i++) {
        // py.exe is a 32-bit launcher by design; it starts interpreters of any architecture.
        var tool = jsFdGet(tools, ids[i]), arch = jsFdGet(tool, "binary_arch");
        if (!jsFdTruthy(jsFdGet(tool, "found")) || !jsFdEqI(jsFdGet(tool, "cat"), "runtime") || !jsFdTruthy(arch) || jsFdEqI(ids[i], "py")) { continue; }
        if (jsFdArchDiffers(osArch, jsFdStr(arch))) { items.push(ids[i] + " is " + jsFdStr(arch)); }
    }
    var jdks = jsFdList(jsFdGet(jsFdData("runtime.java"), "jdks"));
    for (var j = 0; j < jdks.length; j++) {
        var jarch = jsFdGet(jdks[j], "arch");
        if (jsFdTruthy(jarch) && jsFdArchDiffers(osArch, jsFdStr(jarch))) { items.push("Java " + jsFdStr(jsFdGet(jdks[j], "version")) + " is " + jsFdStr(jarch)); }
    }
    if (jsFdTruthy(jsFdGet(jsFdData("os.identity"), "wow64_process"))) { items.push("the scanner itself ran as a 32-bit process"); }
    return items;
}

function jsFdLegacy() {
    // Windows builds out of support and updates not listed as installed. (The ps1 check of its
    // own PowerShell version has no counterpart: envscan.js does not run in PowerShell.)
    var identity = jsFdData("os.identity"), legacy = [];
    var m = /^(\d+)/.exec(jsFdStr(jsFdGet(identity, "build")));
    if (m) {
        var build = parseInt(m[1], 10), productType = jsFdGet(identity, "product_type");
        var server = jsFdTruthy(productType) && jsFdInt(productType) !== 1;
        if ((server && build < 17763) || (!server && build < 19044)) { legacy.push(jsFdStr(jsFdGet(identity, "name")) + " build " + jsFdStr(jsFdGet(identity, "build"))); }
    }
    var updates = jsFdGet(jsFdData("os.updates"), "legacy_updates"), names = jsFdTableKeys(updates);
    for (var i = 0; i < names.length; i++) {
        if (!jsFdTruthy(updates[names[i]])) { legacy.push("not listed as installed: " + names[i]); }
    }
    return legacy;
}

function jsFdShims() {
    var tools = jsFdGet(jsFdData("tools.inventory"), "tools"), ids = jsFdTableKeys(tools), shims = [];
    for (var i = 0; i < ids.length; i++) {
        if (/shim/i.test(jsFdStr(jsFdGet(jsFdGet(tools, ids[i]), "reason")))) { shims.push(ids[i]); }
    }
    return shims;
}

function getEsPlatformFindings() {
    var out = [], mismatch = getEsArchMismatches();
    if (mismatch.length > 0) {
        jsFdAdd(out, newEsFinding("arch.mismatch", "OS is " + jsFdStr(jsFdGet(jsFdData("os.identity"), "arch")) + "; " + joinEsShort(mismatch), ["tools.inventory", "runtime.java", "os.identity"]));
    }
    var health = jsFdData("os.health");
    if (jsFdTruthy(jsFdGet(health, "pending_reboot"))) {
        var reasons = jsFdGet(health, "pending_reasons");
        var text = esIsArray(reasons) ? jsFdJoin(reasons, ", ") : jsFdStr(reasons);
        jsFdAdd(out, newEsFinding("os.pending_reboot", "Pending: " + text, ["os.health"]));
    }
    var legacy = jsFdLegacy();
    if (legacy.length > 0) { jsFdAdd(out, newEsFinding("os.legacy", joinEsShort(legacy), ["os.identity", "os.updates"])); }
    var container = jsFdGet(jsFdData("virt.platform"), "container");
    if (jsFdTruthy(container) && jsFdTruthy(jsFdGet(container, "detected"))) {
        jsFdAdd(out, newEsFinding("container.detected", "Engine: " + jsFdStr(jsFdGet(container, "engine")), ["virt.platform"]));
    }
    var session = jsFdStr(jsFdGet(jsFdData("session.context"), "type"));
    if (esContainsI(["service", "ssh"], session)) { jsFdAdd(out, newEsFinding("session.headless", "Session type " + session, ["session.context"])); }
    if (getEsStatus("runtime.python") === "not_found") {
        jsFdAdd(out, newEsFinding("runtime.python_absent", "No Python interpreter (Store aliases do not count)", ["runtime.python"]));
    }
    var shims = jsFdShims();
    if (shims.length > 0) { jsFdAdd(out, newEsFinding("runtime.shims_not_run", "Not run: " + joinEsShort(shims, 8), ["tools.inventory", "runtime.version_managers"])); }
    if (jsFdTruthy(jsFdGet(jsFdData("sec.crypto"), "fips"))) { jsFdAdd(out, newEsFinding("crypto.fips", "FipsAlgorithmPolicy Enabled = 1", ["sec.crypto"])); }
    var weak = getEsWeakDotnetTls();
    if (weak) { jsFdAdd(out, newEsFinding("crypto.weak_dotnet_tls", weak, ["runtime.dotnet", "sec.crypto"])); }
    return out;
}

function jsFdJoin(items, separator) {
    var parts = [];
    for (var i = 0; i < items.length; i++) { parts.push(jsFdStr(items[i])); }
    return parts.join(separator);
}

function jsFdStrong(entry) {
    return jsFdTruthy(entry) && (jsFdStr(jsFdGet(entry, "SchUseStrongCrypto")) === "1" || jsFdStr(jsFdGet(entry, "SystemDefaultTlsVersions")) === "1");
}

function getEsWeakDotnetTls() {
    // Concludes from a missing SchUseStrongCrypto value, so sec.crypto must have completed.
    if (!testEsHasFacts(["sec.crypto"])) { return ""; }
    var dotnet = jsFdData("runtime.dotnet");
    var strong = jsFdGet(jsFdData("sec.crypto"), "dotnet_strong_crypto");
    if (!jsFdTruthy(strong)) { strong = {}; }
    var issues = [], framework = jsFdGet(dotnet, "framework"), release = null;
    if (jsFdTruthy(framework)) { release = jsFdGet(framework, "release"); }
    if (release !== null && release !== undefined && jsFdInt(release) < 460798 && !jsFdStrong(jsFdGet(strong, "v4.0.30319"))) {
        issues.push(".NET Framework " + jsFdStr(jsFdGet(framework, "version")) + " without SchUseStrongCrypto");
    }
    var legacy = jsFdGet(dotnet, "framework_legacy");
    if (esContainsI(esIsArray(legacy) ? legacy : [legacy], "v3.5") && !jsFdStrong(jsFdGet(strong, "v2.0.50727"))) {
        issues.push(".NET 3.5 apps without SchUseStrongCrypto");
    }
    return joinEsShort(issues);
}

// ------------------------------------------------------------------ scan, all findings

function getEsScanFindings() {
    var out = [], incomplete = [], ids = esKeys(ES_RESULTS);
    for (var i = 0; i < ids.length; i++) {
        var envelope = ES_RESULTS[ids[i]];
        if (envelope && esContains(["partial", "denied", "timeout", "error"], envelope.status)) { incomplete.push(ids[i]); }
    }
    if (incomplete.length > 0) {
        jsFdAdd(out, newEsFinding("scan.partial", incomplete.length + " probe(s): " + joinEsShort(incomplete, 8), incomplete));
    }
    return out;
}

function getEsFindings() {
    var all = [], i, j;
    for (i = 0; i < ES_FINDING_CHECKS.length; i++) {
        try {
            var found = ES_FINDING_CHECKS[i]();
            for (j = 0; j < found.length; j++) { if (esIsTable(found[j])) { all.push(found[j]); } }
        } catch (e) {
            writeEsLog("finding check " + JS_FD_CHECK_NAMES[i] + " failed: " + esErrorText(e));
        }
    }
    var ordered = [], severities = ["blocker", "warning", "info"];
    for (i = 0; i < severities.length; i++) {
        for (j = 0; j < all.length; j++) { if (all[j].severity === severities[i]) { ordered.push(all[j]); } }
    }
    return ordered;
}
