// ---------------------------------------------------------------------------
// 30-findings: conclusions drawn from probe data. Severity, title and recommendation come from
// spec/findings.toml; each check writes the detail. A finding that depends on something being
// absent only fires when the probes that would have found it completed (status ok or
// not_found). Port of src/ps/30-findings.ps1; the PowerShell truth and comparison rules
// (empty array false, case-insensitive -eq and hashtable keys) are written out explicitly.
// ---------------------------------------------------------------------------

var ES_FINDING_CHECKS = [
    getEsExecFindings, getEsTlsFindings, getEsPackageFindings, getEsNetworkFindings,
    getEsResourceFindings, getEsFsFindings, getEsUserFindings, getEsPlatformFindings, getEsScanFindings
];
// Host suffixes from spec/configs.toml public_hosts (shared with the sh scanner).
var ES_PUBLIC_REGISTRY_RE = new RegExp("(^|\\.)(" + convertToEsAlternation(ES_PUBLIC_HOSTS) + ")$", "i");
// PowerShell major version for the default execution policy: the powershell.exe that the policy
// governs when envscan.js runs (Windows PowerShell 5.1) unless the engine knows better.
var JS_FD_PS_MAJOR = 5;

// ------------------------------------------------------------------ PowerShell value rules

function jsFdTruthy(v) {
    // PowerShell truth: $null, $false, 0, "" and an empty array are false; an array of one item
    // is that item's truth.
    if (v === null || v === undefined || v === false || v === 0 || v === "") { return false; }
    if (typeof v === "number" && v !== v) { return false; }
    if (esIsArray(v)) { return v.length > 1 || (v.length === 1 && jsFdTruthy(v[0])); }
    return true;
}

function jsFdList(v) {
    // @($v | Where-Object { $_ }): the true items of an array (a single value as one item).
    var items = esIsArray(v) ? v : (v === null || v === undefined ? [] : [v]);
    var out = [];
    for (var i = 0; i < items.length; i++) { if (jsFdTruthy(items[i])) { out.push(items[i]); } }
    return out;
}

function jsFdStr(v) {
    // [string]$v: $null is "", an array its items joined by spaces, booleans True/False.
    if (v === null || v === undefined) { return ""; }
    if (v === true) { return "True"; }
    if (v === false) { return "False"; }
    if (esIsArray(v)) {
        var parts = [];
        for (var i = 0; i < v.length; i++) { parts.push(jsFdStr(v[i])); }
        return parts.join(" ");
    }
    return String(v);
}

function jsFdInt(v) {
    // [int]$v / [long]$v ($null and "" are 0).
    if (v === null || v === undefined || v === "" || v === false) { return 0; }
    if (v === true) { return 1; }
    var n = Number(v);
    return n === n ? Math.round(n) : 0;
}

function jsFdEqI(a, b) { return jsFdStr(a).toLowerCase() === String(b).toLowerCase(); }

function jsFdGet(table, name) {
    // $table[$name] with the case-insensitive keys of a PowerShell hashtable; null when absent.
    if (!esIsTable(table)) { return null; }
    if (esHas(table, name)) { return table[name]; }
    var lower = String(name).toLowerCase();
    for (var k in table) {
        if (esHas(table, k) && k.toLowerCase() === lower) { return table[k]; }
    }
    return null;
}

function jsFdHas(table, name) {
    if (!esIsTable(table)) { return false; }
    var lower = String(name).toLowerCase();
    for (var k in table) { if (esHas(table, k) && k.toLowerCase() === lower) { return true; } }
    return false;
}

function jsFdTableKeys(table) {
    // The keys of a table, sorted (Sort-Object), "__order" left out.
    var keys = esKeys(table), out = [];
    for (var i = 0; i < keys.length; i++) { if (keys[i] !== "__order") { out.push(keys[i]); } }
    return out;
}

function jsFdData(id) { return getEsData(id) || {}; }

// ------------------------------------------------------------------ helpers

function newEsFinding(id, detail, evidence) {
    var spec = esHas(ES_FINDINGS, id) ? ES_FINDINGS[id] : null;
    if (!spec) { writeEsLog("unknown finding id " + id); return null; }
    return {
        __order: ["id", "severity", "title", "detail", "recommendation", "evidence"],
        id: id, severity: String(spec.severity), title: String(spec.title),
        recommendation: String(spec.recommendation),
        detail: protectEsValue(String(detail)), evidence: [].concat(evidence || [])
    };
}

function testEsCompleted(ids) {
    // Completed: ok, not_found, or not_applicable (a probe that does not apply has nothing to find).
    for (var i = 0; i < ids.length; i++) {
        if (!esContains(["ok", "not_found", "not_applicable"], getEsStatus(ids[i]))) { return false; }
    }
    return true;
}

function testEsHasFacts(ids) {
    // The probe ran and looked: ok or not_found. A not_applicable probe published no facts, so a
    // rule that concludes from a missing value (no default route, no writable folder) stays silent.
    for (var i = 0; i < ids.length; i++) {
        if (!esContains(["ok", "not_found"], getEsStatus(ids[i]))) { return false; }
    }
    return true;
}

function joinEsShort(items, max) {
    var limit = (max === undefined || max === null) ? 4 : max;
    var list = jsFdList(items), shown = [];
    for (var i = 0; i < list.length && i < limit; i++) { shown.push(jsFdStr(list[i])); }
    var text = shown.join("; ");
    if (list.length > limit) { text += "; +" + (list.length - limit) + " more"; }
    return text;
}

function jsFdAdd(out, finding) { if (finding) { out.push(finding); } }

// ------------------------------------------------------------------ execution

function getEsPersistentPolicy(policies) {
    // Execution policy without the process scope; null when no scope could be read. Defaults:
    // PowerShell 6+ and Windows Server 2012 R2+ RemoteSigned, Windows clients Restricted.
    if (!esIsTable(policies)) { return null; }
    var scopes = ["MachinePolicy", "UserPolicy", "CurrentUser", "LocalMachine"], known = false;
    for (var i = 0; i < scopes.length; i++) {
        if (!jsFdHas(policies, scopes[i])) { continue; }
        known = true;
        var value = jsFdStr(jsFdGet(policies, scopes[i]));
        if (value && !jsFdEqI(value, "Undefined")) { return value; }
    }
    if (!known) { return null; }
    var major = (typeof ES_PS_MAJOR === "number") ? ES_PS_MAJOR : JS_FD_PS_MAJOR;
    if (major >= 6) { return "RemoteSigned"; }
    var productType = jsFdGet(jsFdData("os.identity"), "product_type");
    if (jsFdTruthy(productType) && jsFdInt(productType) !== 1 && major >= 4) { return "RemoteSigned"; }
    return "Restricted";
}

function getEsExecFindings() {
    var out = [];
    if (!ES_FULL_LANGUAGE) { jsFdAdd(out, newEsFinding("exec.ps_constrained", "Language mode: " + ES_LANGUAGE_MODE, ["shell.info"])); }
    var enforced = jsFdList(jsFdGet(jsFdData("sec.app_control"), "enforced"));
    if (enforced.length > 0) { jsFdAdd(out, newEsFinding("exec.app_control", joinEsShort(enforced), ["sec.app_control"])); }
    var shell = jsFdData("shell.info");
    var policies = jsFdGet(shell, "execution_policy");
    if (jsFdTruthy(policies)) {
        var persistent = getEsPersistentPolicy(policies);
        if (persistent !== null && esContainsI(["Restricted", "AllSigned"], persistent)) {
            var source = jsFdTruthy(jsFdGet(shell, "policy_from_gpo")) ? "set by Group Policy" : "local setting or OS default";
            jsFdAdd(out, newEsFinding("exec.policy_restricted", "Execution policy " + persistent + " (" + source + ")", ["shell.info"]));
        }
    }
    var disabled = jsFdGet(shell, "cmd_disabled");
    if (jsFdTruthy(disabled) && (jsFdInt(disabled) === 1 || jsFdInt(disabled) === 2)) {
        jsFdAdd(out, newEsFinding("exec.cmd_disabled", "DisableCMD = " + jsFdStr(disabled), ["shell.info"]));
    }
    return out;
}

// ------------------------------------------------------------------ TLS

function testEsVerifyOff(text) {
    return /(strict-ssl|sslverify|ssl_verify|ssl-verify|verify_ssl|http\.sslverify)\s*[=:]\s*"?(false|0|no)\b/i.test(text)
        || /\btrusted-host\b/i.test(text);
}

function jsFdCaNote(trust) {
    // Which runtime CA variables are set, and git's http.sslbackend.
    var runtime = jsFdGet(trust, "runtime_trust"), configured = [];
    var keys = jsFdTableKeys(runtime);
    for (var i = 0; i < keys.length; i++) {
        if (/CA_CERTS|CA_BUNDLE|CERT_FILE|CERT_DIR|SSL_CAINFO/i.test(keys[i])) { configured.push(keys[i]); }
    }
    var note = configured.length > 0 ? "runtime CA variables set: " + configured.join(", ") : "no runtime CA variable is set";
    var backend = "", items = jsFdList(jsFdGet(jsFdData("pkg.sources"), "git_config"));
    for (var j = 0; j < items.length; j++) {
        if (jsFdEqI(jsFdGet(items[j], "key"), "http.sslbackend")) { backend = jsFdStr(jsFdGet(items[j], "value")); }
    }
    return backend ? note + "; git http.sslbackend=" + backend : note;
}

function jsFdEnterpriseCa(trust) {
    var raw = jsFdGet(trust, "enterprise_roots");
    var roots = esIsArray(raw) ? raw : (raw === null || raw === undefined ? [] : [raw]);
    if (roots.length === 0 || !jsFdTruthy(roots[0])) { return null; }
    var names = [];
    for (var i = 0; i < roots.length; i++) {
        var m = /CN=([^,]+)/i.exec(jsFdStr(roots[i]));
        names.push(m ? m[1] : jsFdStr(roots[i]));
    }
    var detail = roots.length + " added root(s): " + joinEsShort(names, 3) + "; " + jsFdCaNote(trust);
    return newEsFinding("tls.enterprise_ca", detail, ["tls.trust", "pkg.sources"]);
}

function jsFdVerifyEvidence(trust) {
    var evidence = [], runtime = jsFdGet(trust, "runtime_trust");
    if (jsFdTruthy(runtime)) {
        if (jsFdStr(jsFdGet(runtime, "NODE_TLS_REJECT_UNAUTHORIZED")) === "0") { evidence.push("NODE_TLS_REJECT_UNAUTHORIZED=0"); }
        if (jsFdHas(runtime, "GIT_SSL_NO_VERIFY")) { evidence.push("GIT_SSL_NO_VERIFY is set"); }
        if (jsFdStr(jsFdGet(runtime, "PYTHONHTTPSVERIFY")) === "0") { evidence.push("PYTHONHTTPSVERIFY=0"); }
    }
    var sources = jsFdData("pkg.sources"), configs = jsFdList(jsFdGet(sources, "configs"));
    for (var i = 0; i < configs.length; i++) {
        var lines = esIsArray(jsFdGet(configs[i], "lines")) ? jsFdGet(configs[i], "lines") : [jsFdGet(configs[i], "lines")];
        for (var j = 0; j < lines.length; j++) {
            if (testEsVerifyOff(jsFdStr(lines[j]))) { evidence.push(jsFdStr(jsFdGet(configs[i], "tool")) + ": " + esTrim(jsFdStr(lines[j]))); }
        }
    }
    var items = jsFdList(jsFdGet(sources, "git_config"));
    for (var k = 0; k < items.length; k++) {
        var pair = jsFdStr(jsFdGet(items[k], "key")) + "=" + jsFdStr(jsFdGet(items[k], "value"));
        if (testEsVerifyOff(pair)) { evidence.push("git: " + pair); }
    }
    return evidence;
}

function getEsTlsFindings() {
    var out = [], trust = jsFdData("tls.trust");
    jsFdAdd(out, jsFdEnterpriseCa(trust));
    if (jsFdHas(trust, "root_auto_update") && jsFdGet(trust, "root_auto_update") === false) {
        jsFdAdd(out, newEsFinding("tls.offline_pki", "Root certificate auto-update is disabled by policy (DisableRootAutoUpdate=1)", ["tls.trust"]));
    }
    var evidence = jsFdVerifyEvidence(trust);
    if (evidence.length > 0) { jsFdAdd(out, newEsFinding("tls.verification_disabled", joinEsShort(evidence), ["tls.trust", "pkg.sources"])); }
    return out;
}

// ------------------------------------------------------------------ packages and network

function getEsInternalHosts() {
    var hosts = [], urls = jsFdList(jsFdGet(jsFdData("pkg.sources"), "endpoints"));
    for (var i = 0; i < urls.length; i++) {
        var endpoint = convertToEsEndpoint(jsFdStr(urls[i]), "");
        if (endpoint && !ES_PUBLIC_REGISTRY_RE.test(endpoint.host) && !esContainsI(hosts, endpoint.host)) { hosts.push(endpoint.host); }
    }
    return hosts;
}

function getEsPackageFindings() {
    var out = [], internal = getEsInternalHosts();
    if (internal.length > 0) { jsFdAdd(out, newEsFinding("pkg.mirror", joinEsShort(internal, 5), ["pkg.sources"])); }
    var caches = jsFdList(jsFdGet(jsFdData("pkg.caches"), "caches")), parts = [];
    for (var i = 0; i < caches.length; i++) {
        parts.push(jsFdStr(jsFdGet(caches[i], "tool")) + " (" + jsFdStr(jsFdGet(caches[i], "entries")) + " entries)");
    }
    if (caches.length > 0) { jsFdAdd(out, newEsFinding("pkg.offline_cache", joinEsShort(parts, 6), ["pkg.caches"])); }
    var anyProxy = jsFdTruthy(jsFdGet(jsFdData("net.proxy"), "any_proxy"));
    if (internal.length === 0 && caches.length === 0 && !anyProxy && testEsCompleted(["pkg.sources", "pkg.caches", "net.proxy"])) {
        jsFdAdd(out, newEsFinding("pkg.no_source", "No proxy, internal registry or dependency cache is configured for this user; without direct internet access, package installs will fail", ["pkg.sources", "pkg.caches", "net.proxy"]));
    }
    return out;
}

function jsFdProxyParts(proxy) {
    var parts = [], endpoints = jsFdList(jsFdGet(proxy, "proxy_endpoints"));
    for (var i = 0; i < endpoints.length; i++) {
        var e = endpoints[i];
        parts.push(jsFdStr(jsFdGet(e, "host")) + ":" + jsFdStr(jsFdGet(e, "port")) + " (" + jsFdStr(jsFdGet(e, "source")) + ")");
    }
    var pac = jsFdGet(jsFdGet(proxy, "wininet"), "pac_url");
    if (jsFdTruthy(pac)) { parts.push("PAC " + jsFdStr(pac)); }
    return parts;
}

function getEsNetworkFindings() {
    var out = [], proxy = jsFdData("net.proxy");
    if (jsFdTruthy(jsFdGet(proxy, "any_proxy"))) { jsFdAdd(out, newEsFinding("net.proxy_configured", joinEsShort(jsFdProxyParts(proxy)), ["net.proxy"])); }
    var wininet = jsFdGet(proxy, "wininet"), winhttp = jsFdGet(proxy, "winhttp");
    if (jsFdTruthy(wininet) && jsFdTruthy(winhttp) && (jsFdTruthy(jsFdGet(wininet, "enabled")) || jsFdTruthy(jsFdGet(wininet, "pac_url")))
        && jsFdTruthy(jsFdGet(winhttp, "direct"))) {
        jsFdAdd(out, newEsFinding("net.proxy_user_only", "WinINET/PAC proxy is set for this user; WinHTTP is direct", ["net.proxy"]));
    }
    if (testEsHasFacts(["net.routes"]) && jsFdInt(jsFdGet(jsFdData("net.routes"), "default_route_count")) === 0) {
        jsFdAdd(out, newEsFinding("net.no_route", "No default route", ["net.routes"]));
    }
    var excluded = jsFdList(jsFdGet(jsFdData("net.ports"), "common_ports_excluded"));
    if (excluded.length > 0) { jsFdAdd(out, newEsFinding("net.excluded_ports", "Excluded: " + excluded.join(", "), ["net.ports"])); }
    var used = jsFdList(jsFdGet(jsFdData("net.listening"), "common_ports_in_use"));
    if (used.length > 0) { jsFdAdd(out, newEsFinding("net.ports_in_use", "In use: " + used.join(", "), ["net.listening"])); }
    return out;
}
