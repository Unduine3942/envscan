// ---------------------------------------------------------------------------
// 22-probes-trust: trusted root certificates (port of probe_tls_trust from
// src/ps/22-probes-security.ps1). WSH has no Cert: drive: the logical stores are
// rebuilt from their physical registry stores, and each certificate's subject,
// issuer and expiry are read from its Blob (22-probes-certder.js).
// ---------------------------------------------------------------------------

var ES_BUILTIN_ROOT_RE = /Microsoft|MSFT|NO LIABILITY ACCEPTED|Thawte Timestamping CA|Symantec Enterprise Mobile Root/i;
// Physical stores of the LocalMachine\Root logical store, in the order they are listed.
var JSTRUST_MACHINE_STORES = [
    ["machine", "HKLM:\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates"],
    ["group_policy", "HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates"],
    ["enterprise", "HKLM:\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates"],
    ["authroot", "HKLM:\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates"]
];
var JSTRUST_USER_STORES = [
    ["user", "HKCU:\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates"],
    ["user_policy", "HKCU:\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates"]
];
var JSTRUST_CA_STORES = ["HKLM:\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates",
    "HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\CA\\Certificates",
    "HKLM:\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\CA\\Certificates"];

function getEsThumbprintSet(key) {
    var set = {};
    var names = getEsRegSubkeys(key);
    for (var i = 0; i < names.length; i++) { set[names[i].toUpperCase()] = true; }
    return set;
}

function getEsCertOrigin(thumbprint, subject, sets) {
    if (esHas(sets.group_policy, thumbprint)) { return "group_policy"; }
    if (esHas(sets.enterprise, thumbprint)) { return "enterprise"; }
    if (esHas(sets.authroot, thumbprint)) { return "authroot"; }
    if (esHas(sets.machine, thumbprint)) { return ES_BUILTIN_ROOT_RE.test(jsOs_str(subject)) ? "builtin" : "local"; }
    return "unknown";
}

function jsTrust_blobBytes(path) {
    // The Blob value of one certificate key as byte values, else null.
    // getEsRegBinary (engine) returns all bytes; getEsRegValue gives at most 256 (too few for a certificate).
    var value = (typeof getEsRegBinary === "function") ? getEsRegBinary(path, "Blob") : getEsRegValue(path, "Blob");
    if (value === null || value === undefined) { return null; }
    return esIsArray(value) ? value : jsDer_hexBytes(value);
}

function jsTrust_entry(key, thumbprint, store, sets, fixedOrigin) {
    // ConvertTo-EsCertEntry: subject and expiry from the Blob; null facts when it is unreadable.
    var info = jsDer_parseBlob(jsTrust_blobBytes(key + "\\" + thumbprint));
    var subject = info ? info.subject : null;
    return {
        subject: subject, issuer: info ? info.issuer : null, thumbprint: thumbprint,
        not_after: (info && info.not_after) ? formatEsUtc(info.not_after) : null, store: store,
        origin: fixedOrigin || getEsCertOrigin(thumbprint, subject, sets)
    };
}

function jsTrust_storeEntries(stores, store, sets, keep) {
    // One entry per certificate of each physical store of the logical store: like the Cert:
    // drive, a certificate kept in two physical stores is listed twice.
    var out = [];
    for (var i = 0; i < stores.length; i++) {
        var names = getEsRegSubkeys(stores[i][1]);
        for (var j = 0; j < names.length; j++) {
            var origin = keep ? keep(names[j].toUpperCase()) : null;
            if (keep && !origin) { continue; }
            out.push(jsTrust_entry(stores[i][1], names[j], store, sets, origin));
        }
    }
    return out;
}

function getEsRootEntries(result, sets) {
    // Machine roots with their origin, plus the roots added for this user (directly or by policy).
    result.sources.push("registry LocalMachine\\Root physical stores (certificate Blobs)");
    var roots = jsTrust_storeEntries(JSTRUST_MACHINE_STORES, "LocalMachine\\Root", sets, null);
    result.sources.push("registry CurrentUser\\Root physical stores (user-added entries; certificate Blobs)");
    // CurrentUser\Root also holds every LocalMachine root; only the user-added ones are kept.
    var userStores = JSTRUST_USER_STORES.concat(JSTRUST_MACHINE_STORES);
    var user = jsTrust_storeEntries(userStores, "CurrentUser\\Root", sets, function (thumb) {
        if (esHas(sets.user_policy, thumb)) { return "user_group_policy"; }
        return esHas(sets.user, thumb) ? "user" : null;
    });
    var unread = 0;
    var all = roots.concat(user);
    for (var i = 0; i < all.length; i++) { if (all[i].subject === null) { unread++; } }
    if (unread > 0) { addEsNote(result, unread + " root certificate(s) without a readable subject (Blob could not be parsed)", "partial"); }
    return all;
}

function jsTrust_sets() {
    var sets = {};
    var stores = JSTRUST_MACHINE_STORES.concat(JSTRUST_USER_STORES);
    for (var i = 0; i < stores.length; i++) { sets[stores[i][0]] = getEsThumbprintSet(stores[i][1]); }
    return sets;
}

function jsTrust_intermediateCount(result) {
    result.sources.push("registry LocalMachine\\CA physical stores (count)");
    // Like Get-ChildItem Cert:\LocalMachine\CA: every certificate of every physical store.
    var count = 0;
    for (var i = 0; i < JSTRUST_CA_STORES.length; i++) { count += getEsRegSubkeys(JSTRUST_CA_STORES[i]).length; }
    return count;
}

function jsTrust_enterprise(roots) {
    var added = ["group_policy", "enterprise", "local", "user", "user_group_policy"];
    var subjects = [];
    var thumbs = [];
    for (var i = 0; i < roots.length; i++) {
        var root = roots[i];
        if (!esContains(added, root.origin) || /^CN=localhost$/i.test(jsOs_str(root.subject))) { continue; }
        if (root.subject !== null) { subjects.push(root.subject); }
        thumbs.push(root.thumbprint);
    }
    return { subjects: jsUser_sortedUnique(subjects), thumbprints: jsUser_sortedUnique(thumbs) };
}

function jsTrust_counts(d, roots, now) {
    var machine = 0;
    var user = 0;
    var expired = 0;
    for (var i = 0; i < roots.length; i++) {
        if (roots[i].store === "LocalMachine\\Root") { machine++; } else if (roots[i].store === "CurrentUser\\Root") { user++; }
        if (roots[i].not_after && roots[i].not_after < formatEsUtc(now)) { expired++; }
    }
    d.root_count = machine;
    d.user_root_count = user;
    d.expired_roots = expired;
}

function getEsJavaCacerts(javaHome) {
    if (!testEsLocalPath(javaHome)) { return null; }
    var relatives = ["lib\\security\\cacerts", "jre\\lib\\security\\cacerts"];
    for (var i = 0; i < relatives.length; i++) {
        var path = esJoinPath(javaHome, relatives[i]);
        // Below a folder link that is not followed: not tested here, noted by the caller.
        if (getEsRefusedFolder(path)) { return { path: path, size: null, modified_utc: null }; }
        if (esIsFile(path)) {
            var file = ES_FSO.GetFile(path);
            return { path: path, size: Number(file.Size), modified_utc: formatEsUtc(new Date(file.DateLastModified)) };
        }
    }
    return null;
}

function jsTrust_java(r, d) {
    d.runtime_trust = getEsEnvSubset(ES_TLS_ENV);
    r.sources.push("environment TLS variables");
    var javaHome = getEsOrigEnv("JAVA_HOME");
    d.java_home_cacerts = getEsJavaCacerts(javaHome);
    if (javaHome && testEsNetworkPath(javaHome)) { addEsNote(r, "JAVA_HOME is on a network path; its cacerts was not read", ""); }
    else if (javaHome) { r.sources.push("read %JAVA_HOME%\\lib\\security\\cacerts (size and date)"); }
}

function probe_tls_trust() {
    var r = newEsResult();
    var d = r.data;
    var sets = jsTrust_sets();
    r.sources.push("registry HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates", "registry HKLM\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates",
        "registry HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\{AuthRoot,ROOT}\\Certificates (names)", "registry HKCU\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates (names)");
    var roots = getEsRootEntries(r, sets);
    var enterprise = jsTrust_enterprise(roots);
    d.roots = roots;
    d.enterprise_roots = enterprise.subjects;
    d.enterprise_thumbprints = enterprise.thumbprints;
    jsTrust_counts(d, roots, getEsUtc());
    d.authroot_count = esKeys(sets.authroot).length;
    d.intermediate_count = jsTrust_intermediateCount(r);
    r.sources.push("registry HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot (DisableRootAutoUpdate)");
    var disable = getEsRegValue("HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot", "DisableRootAutoUpdate");
    d.root_auto_update = !(jsOs_str(disable) === "1");
    jsTrust_java(r, d);
    d.bundles = [];
    d.custom_anchors = [];
    return r;
}
