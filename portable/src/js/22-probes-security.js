// ---------------------------------------------------------------------------
// 22-probes-security: application control, crypto policy, antivirus and policy
// hive (deep), Java truststore (deep). Port of src/ps/22-probes-security.ps1;
// trusted roots (tls.trust) are in 22-probes-trust.js.
// ---------------------------------------------------------------------------

var ES_MITIGATION_EXES = ["node.exe", "java.exe", "javaw.exe", "python.exe", "pythonw.exe", "dotnet.exe", "powershell.exe",
    "pwsh.exe", "cmd.exe", "msbuild.exe", "git.exe", "code.exe", "chrome.exe", "msedge.exe", "ruby.exe", "perl.exe", "go.exe"];
// Policy keys never opened: any key named *Exclusion* (Defender path, process and extension
// exclusions, ASROnlyExclusions, ...), AllowedApplications (Controlled Folder Access), "Policy
// Manager" (the MDM mirror of the Defender policy), Installer, Winlogon and IPSec (stock Windows
// denies it to standard users). Value names never read: Exclu* and *Exclusion*
// (ASROnlyPerRuleExclusions, ...). Matched against the subkey path below the tree root, which
// starts with a backslash; "$" without the m flag is the very end, like .NET \z.
var ES_POLICY_SKIP_RE = /\\([^\\]*Exclusion[^\\]*|AllowedApplications|Installer|Winlogon|Policy Manager|IPSec)(\\|$)/i;
var ES_POLICY_SKIP_VALUE_RE = /^Exclu|Exclusion/i;

function convertToEsEnforcement(value) {
    if (value === null || value === undefined) { return null; }
    var n = Number(value);
    if (n === 0) { return "off"; }
    if (n === 1) { return "audit"; }
    if (n === 2) { return "enforced"; }
    return String(value);
}

function jsSec_appLockerCollections(base) {
    var collections = {};
    var counts = {};
    var names = getEsRegSubkeys(base);
    for (var i = 0; i < names.length; i++) {
        var key = base + "\\" + names[i];
        var count = getEsRegSubkeys(key).length;
        var mode = getEsRegValue(key, "EnforcementMode");
        var state = "NoRules";
        if (count > 0) { state = (mode === null || mode === undefined || Number(mode) === 1) ? "Enforced" : "AuditOnly"; }
        collections[names[i]] = state;
        counts[names[i]] = count;
    }
    return { collections: collections, counts: counts };
}

function getEsAppLocker(result) {
    var base = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2";
    result.sources.push("registry HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2 (AppLocker)");
    var found = jsSec_appLockerCollections(base);
    var names = esKeys(found.collections);
    var enforced = [];
    for (var i = 0; i < names.length; i++) { if (found.collections[names[i]] === "Enforced") { enforced.push(names[i]); } }
    var service = jsOs_first(jsOs_cim(result, "Win32_Service", ["Name", "State"], "root/cimv2", "Name='AppIDSvc'"));
    return {
        configured: names.length > 0, collections: found.collections, rule_counts: found.counts,
        enforced_collections: enforced, identity_service: service ? jsOs_str(service.State) : null
    };
}

function jsSec_saferRuleCount(key) {
    var rules = 0;
    var kinds = ["Paths", "Hashes", "UrlZones"];
    var levels = getEsRegSubkeys(key);
    for (var i = 0; i < levels.length; i++) {
        for (var j = 0; j < kinds.length; j++) { rules += getEsRegSubkeys(key + "\\" + levels[i] + "\\" + kinds[j]).length; }
    }
    return rules;
}

function getEsSaferPolicy(result) {
    var levels = { "0": "Disallowed", "131072": "Basic User", "262144": "Unrestricted" };
    var hives = ["HKLM", "HKCU"];
    for (var i = 0; i < hives.length; i++) {
        var key = hives[i] + ":\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";
        result.sources.push("registry " + hives[i] + "\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers (SRP)");
        var values = getEsRegValues(key);
        if (values === null || values === undefined) { continue; }
        var rules = jsSec_saferRuleCount(key);
        var level = jsOs_val(values, "DefaultLevel");
        if (level === null && rules === 0) { continue; }
        var name = jsOs_str(level);
        return {
            hive: hives[i], default_level: level, default_level_name: esHas(levels, name) ? levels[name] : null,
            transparent_enabled: jsOs_val(values, "TransparentEnabled"), policy_scope: jsOs_val(values, "PolicyScope"),
            executable_types: jsOs_val(values, "ExecutableTypes"), rule_count: rules,
            enforced: (name === "0" || name === "131072")
        };
    }
    return null;
}

function jsSec_array(value) {
    if (value === null || value === undefined) { return []; }
    return esIsArray(value) ? value : [value];
}

function jsSec_wdac(result) {
    var guard = jsOs_first(jsOs_cim(result, "Win32_DeviceGuard", ["CodeIntegrityPolicyEnforcementStatus",
        "UsermodeCodeIntegrityPolicyEnforcementStatus", "VirtualizationBasedSecurityStatus",
        "SecurityServicesConfigured", "SecurityServicesRunning"], "root/Microsoft/Windows/DeviceGuard"));
    if (!guard) { return null; }
    return {
        kmci: convertToEsEnforcement(guard.CodeIntegrityPolicyEnforcementStatus),
        umci: convertToEsEnforcement(guard.UsermodeCodeIntegrityPolicyEnforcementStatus),
        vbs: guard.VirtualizationBasedSecurityStatus === undefined ? null : guard.VirtualizationBasedSecurityStatus,
        services_configured: jsSec_array(guard.SecurityServicesConfigured),
        services_running: jsSec_array(guard.SecurityServicesRunning)
    };
}

function jsSec_exploitProtection(r) {
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel (MitigationOptions)");
    var kernel = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";
    var ifeo = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
    r.sources.push("registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<runtime>.exe (MitigationOptions)");
    var processes = {};
    for (var i = 0; i < ES_MITIGATION_EXES.length; i++) {
        var value = getEsRegValue(ifeo + ES_MITIGATION_EXES[i], "MitigationOptions");
        if (value !== null && value !== undefined) { processes[ES_MITIGATION_EXES[i]] = value; }
    }
    return {
        system: jsSec_null(getEsRegValue(kernel, "MitigationOptions")),
        system_audit: jsSec_null(getEsRegValue(kernel, "MitigationAuditOptions")),
        processes: processes
    };
}

function jsSec_null(value) {
    return value === undefined ? null : value;
}

function jsSec_smartAppControl(value) {
    var text = jsOs_str(value);
    if (text === "0") { return "off"; }
    if (text === "1") { return "on"; }
    if (text === "2") { return "evaluation"; }
    return null;
}

function jsSec_enforced(d) {
    var enforced = [];
    if (d.applocker.enforced_collections.length > 0) { enforced.push("AppLocker (" + d.applocker.enforced_collections.join(", ") + ")"); }
    if (d.srp && d.srp.enforced) { enforced.push("Software Restriction Policies (default " + d.srp.default_level_name + ")"); }
    if (d.wdac && d.wdac.umci === "enforced") { enforced.push("WDAC user-mode code integrity"); }
    if (d.smart_app_control === "on") { enforced.push("Smart App Control"); }
    return enforced;
}

function probe_sec_app_control() {
    var r = newEsResult();
    var d = r.data;
    d.applocker = getEsAppLocker(r);
    d.srp = getEsSaferPolicy(r);
    d.wdac = jsSec_wdac(r);
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy (VerifiedAndReputablePolicyState)");
    d.smart_app_control = jsSec_smartAppControl(getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", "VerifiedAndReputablePolicyState"));
    d.exploit_protection = jsSec_exploitProtection(r);
    r.sources.push("registry HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System (EnableSmartScreen)", "registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments");
    d.smartscreen = {
        policy_enabled: jsSec_null(getEsRegValue("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System", "EnableSmartScreen")),
        policy_level: jsSec_null(getEsRegValue("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System", "ShellSmartScreenLevel"))
    };
    d.attachments_save_zone_information = jsSec_null(getEsRegValue("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments", "SaveZoneInformation"));
    d.enforced = jsSec_enforced(d);
    return r;
}

// ------------------------------------------------------------------ crypto policy

function jsSec_dotnetStrongCrypto(r) {
    var strong = {};
    var views = [["", ""], ["WOW6432Node\\", " (32-bit)"]];
    var versions = ["v2.0.50727", "v4.0.30319"];
    for (var i = 0; i < views.length; i++) {
        for (var j = 0; j < versions.length; j++) {
            var key = "HKLM:\\SOFTWARE\\" + views[i][0] + "Microsoft\\.NETFramework\\" + versions[j];
            r.sources.push("registry " + key.replace(/^HKLM:/, "HKLM"));
            var values = getEsRegValues(key);
            if (values === null || values === undefined) { continue; }
            strong[versions[j] + views[i][1]] = {
                SchUseStrongCrypto: jsOs_val(values, "SchUseStrongCrypto"),
                SystemDefaultTlsVersions: jsOs_val(values, "SystemDefaultTlsVersions")
            };
        }
    }
    return strong;
}

function jsSec_winHttp(r) {
    var winhttp = {};
    var views = [["", "native"], ["WOW6432Node\\", "32-bit"]];
    for (var i = 0; i < views.length; i++) {
        var key = "HKLM:\\SOFTWARE\\" + views[i][0] + "Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp";
        r.sources.push("registry " + key.replace(/^HKLM:/, "HKLM") + " (DefaultSecureProtocols)");
        winhttp[views[i][1]] = jsSec_null(getEsRegValue(key, "DefaultSecureProtocols"));
    }
    return winhttp;
}

function probe_sec_crypto() {
    var r = newEsResult();
    var d = r.data;
    // The only value ever read below Lsa.
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy (Enabled only)");
    var fips = getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy", "Enabled");
    d.fips = (jsOs_str(fips) === "1");
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols");
    d.schannel = getEsRegTree("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols", 60);
    d.dotnet_strong_crypto = jsSec_dotnetStrongCrypto(r);
    d.winhttp_default_secure_protocols = jsSec_winHttp(r);
    d.crypto_policy = null;
    d.openssl_dir = null;
    return r;
}

// ------------------------------------------------------------------ antivirus and policy hive (deep)

function limitEsTableValues(table, maxLength) {
    var max = maxLength || 400;
    var out = {};
    for (var key in table) {
        if (!esHas(table, key)) { continue; }
        var value = table[key];
        if (typeof value === "string" && value.length > max) { value = value.substr(0, max) + "..."; }
        out[key] = value;
    }
    return out;
}

function jsSec_productState(value) {
    var hex = (Number(value) >>> 0).toString(16);
    while (hex.length < 6) { hex = "0" + hex; }
    return "0x" + hex;
}

function jsSec_antivirus(r, d) {
    var query = getEsCimSafe("AntiVirusProduct", "root/SecurityCenter2", "", ["displayName", "productState", "pathToSignedProductExe"]);
    r.sources.push("CIM root/SecurityCenter2:AntiVirusProduct");
    if (query.status === "ok") {
        d.antivirus = [];
        for (var i = 0; i < query.items.length; i++) {
            var item = query.items[i];
            d.antivirus.push({ name: jsOs_str(item.displayName), product_state: jsSec_productState(item.productState), path: jsOs_str(item.pathToSignedProductExe) });
        }
        return;
    }
    d.antivirus = null;
    var productType = getEsData("os.identity").product_type;
    if (productType && Number(productType) !== 1) { r.notes.push("SecurityCenter2 does not exist on Windows Server; antivirus products are not listed"); }
    else { addEsNote(r, "SecurityCenter2: " + query.error, "partial"); }
}

function probe_sec_av() {
    var r = newEsResult();
    var d = r.data;
    jsSec_antivirus(r, d);
    r.sources.push("registry HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender (keys named *Exclusion*, AllowedApplications or Policy Manager and values named Exclu* or *Exclusion* are never read)");
    d.defender_policy = limitEsTableValues(protectEsTable(getEsRegTree("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", 200, ES_POLICY_SKIP_RE, ES_POLICY_SKIP_VALUE_RE)));
    var policies = {};
    var hives = ["HKLM", "HKCU"];
    for (var i = 0; i < hives.length; i++) {
        r.sources.push("registry " + hives[i] + "\\SOFTWARE\\Policies (capped; keys named *Exclusion*, AllowedApplications, Policy Manager, Installer, Winlogon or IPSec and values named Exclu* or *Exclusion* are never read)");
        policies[hives[i]] = limitEsTableValues(protectEsTable(getEsRegTree(hives[i] + ":\\SOFTWARE\\Policies", 600, ES_POLICY_SKIP_RE, ES_POLICY_SKIP_VALUE_RE)));
    }
    d.policies = policies;
    return r;
}

// ------------------------------------------------------------------ Java truststore (deep)

function jsSec_javaHome(jdks) {
    for (var i = 0; i < jdks.length; i++) { if (jdks[i] && jdks[i].source === "JAVA_HOME") { return jdks[i].path; } }
    return (jdks.length > 0 && jdks[0]) ? jdks[0].path : null;
}

function jsSec_sha1List(text) {
    var re = /\bSHA-?1\s*:\s*((?:[0-9A-F]{2}:){19}[0-9A-F]{2})/gi;
    var out = [];
    var m = re.exec(text);
    while (m) {
        out.push(m[1].replace(/:/g, "").toUpperCase());
        m = re.exec(text);
    }
    return out;
}

function jsSec_compareRoots(r, d, sha1) {
    var trust = getEsData("tls.trust");
    var status = getEsStatus("tls.trust");
    if (status !== "ok" && status !== "partial") { addEsNote(r, "tls.trust did not complete: enterprise roots were not compared", "partial"); }
    var wanted = trust.enterprise_thumbprints || [];
    var subjects = {};
    var roots = trust.roots || [];
    for (var i = 0; i < roots.length; i++) { if (roots[i]) { subjects[jsOs_str(roots[i].thumbprint)] = jsOs_str(roots[i].subject); } }
    d.enterprise_roots_present = [];
    d.enterprise_roots_missing = [];
    for (var j = 0; j < wanted.length; j++) {
        if (!wanted[j]) { continue; }
        var label = esHas(subjects, wanted[j]) ? subjects[wanted[j]] : null;
        if (esContainsI(sha1, wanted[j])) { d.enterprise_roots_present.push(label); } else { d.enterprise_roots_missing.push(label); }
    }
}

function jsSec_keytoolRun(r, javaHome, keytool, cacerts) {
    // keytool opens the keystore: a cacerts that is a link off the local disk is not read.
    var link = getEsPathLinkReason(cacerts.path);
    if (link) { addEsReadNote(r, cacerts.path, link); return null; }
    var noRun = getEsNoRunReason({ id: "keytool", mode: "version" }, keytool);
    if (noRun) { addEsNote(r, "keytool not run: " + noRun, "partial"); return null; }
    var run = invokeEsCommand(keytool, ["-list", "-v", "-keystore", cacerts.path, "-storepass", "changeit"], undefined, undefined, 40000);
    r.sources.push("run " + run.command);
    if (run.timed_out) { r.status = "timeout"; return null; }
    return run;
}

function probe_tls_java_cacerts() {
    var r = newEsResult();
    var d = r.data;
    if (!testEsDependency(r, "runtime.java")) { return r; }
    var jdks = getEsData("runtime.java").jdks || [];
    var javaHome = jsSec_javaHome(jdks);
    if (!javaHome) { r.status = "not_found"; r.notes.push("no Java installation found"); return r; }
    var keytool = esJoinPath(javaHome, "bin\\keytool.exe");
    var cacerts = getEsJavaCacerts(javaHome);
    if (!esIsFile(keytool) || !cacerts) { r.status = "not_found"; r.notes.push("keytool or cacerts missing under " + javaHome); return r; }
    var run = jsSec_keytoolRun(r, javaHome, keytool, cacerts);
    if (!run) { return r; }
    var text = jsOs_str(getEsCommandText(run));
    var sha1 = jsSec_sha1List(text);
    d.java_home = javaHome;
    d.keytool = keytool;
    d.cacerts = cacerts;
    d.entries = sha1.length;
    jsSec_compareRoots(r, d, sha1);
    if (sha1.length === 0) { addEsNote(r, "keytool listed no certificates (exit code " + run.exit_code + ")", "partial"); r.raw.keytool = text; }
    return r;
}
