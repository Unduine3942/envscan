// ---------------------------------------------------------------------------
// 11c-registry: registry readers. Port of the registry part of src/ps/11-exec.ps1.
//
// Paths use the ps1 syntax: 'HKLM:\SOFTWARE\...', 'HKCU:\...' (also HKCR:, HKU:, HKCC:,
// 'Registry::HKEY_...' and 'HKEY_...'). Keys and value names (with their types) are listed with
// WMI StdRegProv in this process; values are read with WScript.Shell RegRead (faster, and it
// returns REG_EXPAND_SZ unexpanded, which is then expanded with this process's environment as
// PowerShell does; StdRegProv would expand with the WMI host's environment). QWORD values and
// value names holding "\" are read with StdRegProv. Both use the view of this process (64-bit
// from the System32 cscript; the ps1 has the same rule). Before the first StdRegProv use in a
// scan, the WMI worker checks that StdRegProv answers within the timeout; when it does not, keys
// cannot be listed (getEsRegValues/getEsRegSubkeys return nothing and the probe is partial with
// "registry listing unavailable ...") and single values are read with RegRead only.
// Values keep the ps1 shapes: REG_BINARY as lower-case hex of at most 256 bytes, REG_MULTI_SZ as
// an array of strings, REG_DWORD unsigned, REG_QWORD a number up to 2^53 and a decimal string
// above. Value names keep the registry's spelling (look them up with that spelling).
// ---------------------------------------------------------------------------

var ES_REG_HIVES = {
    hklm: [2147483650, "HKLM"], hkey_local_machine: [2147483650, "HKLM"],
    hkcu: [2147483649, "HKCU"], hkey_current_user: [2147483649, "HKCU"],
    hkcr: [2147483648, "HKCR"], hkey_classes_root: [2147483648, "HKCR"],
    hku: [2147483651, "HKEY_USERS"], hkey_users: [2147483651, "HKEY_USERS"],
    hkcc: [2147483653, "HKEY_CURRENT_CONFIG"], hkey_current_config: [2147483653, "HKEY_CURRENT_CONFIG"]
};
var ES_DENIED_READS = [];
var ES_REG_UNLISTED = [];
var ES_REG_PROV = null;
var ES_REG_STATE = null;
var ES_REG_INPARAMS = {};
var ES_REG_ACCESS_DENIED = 5;

function esRegSplit(path) {
    // {hive, key, shell} for a ps1 registry path, or null.
    var text = String(path || "").replace(/^(Microsoft\.PowerShell\.Core\\)?Registry::/i, "");
    var m = /^([A-Za-z_]+):?(\\(.*))?$/.exec(text);
    if (!m || !Object.prototype.hasOwnProperty.call(ES_REG_HIVES, m[1].toLowerCase())) { return null; }
    var hive = ES_REG_HIVES[m[1].toLowerCase()];
    var key = (m[3] || "").replace(/\\+$/, "");
    return { hive: hive[0], key: key, shell: hive[1] + (key ? "\\" + key : "") };
}

function esToRegExp(pattern) {
    // A ps1 -match pattern (case-insensitive; (?i), \A and \z allowed) as a JScript RegExp.
    if (!pattern) { return null; }
    if (pattern instanceof RegExp) { return pattern; }
    var source = String(pattern).replace(/^\(\?i\)/, "").replace(/\\A/g, "^").replace(/\\z/g, "$");
    return new RegExp(source, "i");
}

function addEsDeniedRead(path, reason) {
    // A key this user may not read (StdRegProv return value 5, or reason 'denied').
    if (reason !== ES_REG_ACCESS_DENIED && reason !== "denied" && reason !== "PermissionDenied") { return; }
    if (!esContains(ES_DENIED_READS, String(path))) { ES_DENIED_READS.push(String(path)); }
}

function esRegUnlisted(path) {
    if (!esContains(ES_REG_UNLISTED, String(path))) { ES_REG_UNLISTED.push(String(path)); }
}

// ------------------------------------------------------------------ StdRegProv

function esRegCheck() {
    // Worker side: StdRegProv answers one listing.
    var provider = esWorkerConnect("root/default").Get("StdRegProv");
    var params = provider.Methods_.Item("EnumKey").InParameters.SpawnInstance_();  // lint-allow: wmi-inparams
    params.hDefKey = 2147483650;
    params.sSubKeyName = "SOFTWARE";
    provider.ExecMethod_("EnumKey", params);
}

function esRegProvider() {
    // The in-process StdRegProv, or null when WMI did not answer the worker's check.
    if (ES_REG_STATE === null) {
        ES_REG_STATE = "ok";
        try {
            if (ES_TMP) {
                var reply = invokeEsWorker(["reg-check"], ES_OPT.timeout, "StdRegProv");
                if (reply.status !== "ok") { throw new Error(reply.error); }
            }
            ES_REG_PROV = esWorkerConnect("root/default").Get("StdRegProv");
        } catch (e) {
            ES_REG_STATE = "broken";
            writeEsLog("registry listing unavailable (StdRegProv): " + esErrorText(e));
        }
    }
    return ES_REG_STATE === "ok" ? ES_REG_PROV : null;
}

function esRegCall(method, split, valueName) {
    // The StdRegProv out parameters, or null when StdRegProv is unavailable.
    var provider = esRegProvider();
    if (!provider) { return null; }
    if (!ES_REG_INPARAMS[method]) {
        ES_REG_INPARAMS[method] = provider.Methods_.Item(method).InParameters;  // lint-allow: wmi-inparams
    }
    var params = ES_REG_INPARAMS[method].SpawnInstance_();
    params.hDefKey = split.hive;
    params.sSubKeyName = split.key;
    if (valueName !== undefined) { params.sValueName = valueName; }
    return provider.ExecMethod_(method, params);
}

function esVbList(value) {
    if (value === null || value === undefined) { return []; }
    try { return new VBArray(value).toArray(); } catch (e) { return []; }
}

// ------------------------------------------------------------------ value conversion

function convertToEsRegValue(value) {
    // ps1 ConvertTo-EsRegValue: bytes as hex (256 max), lists as strings, DWORD unsigned.
    if (value === null || value === undefined) { return null; }
    if (typeof value === "unknown") { value = esVbList(value); }
    if (esIsArray(value)) {
        var out = [];
        for (var i = 0; i < value.length; i++) { out.push(value[i] === null ? "" : String(value[i])); }
        return out;
    }
    if (typeof value === "number") { return value < 0 && value >= -2147483648 ? value + 4294967296 : value; }
    return String(value);
}

function esRegBytesHex(value) {
    var bytes = esVbList(value);
    var parts = [];
    for (var i = 0; i < bytes.length && i < 256; i++) { parts.push(esPadLeft((bytes[i] & 255).toString(16), 2, "0")); }
    return parts.join("");
}

function esRegQword(text) {
    if (text === null || text === undefined) { return null; }
    var number = Number(text);
    return number <= 9007199254740991 ? number : String(text);
}

function esRegReadShell(split, name) {
    // RegRead of one value; undefined when it fails.
    if (!name || name.indexOf("\\") >= 0) { return undefined; }
    try { return ES_SHELL.RegRead(split.shell + "\\" + name); } catch (e) { return undefined; }
}

function esRegTypedValue(split, name, type) {
    // One value of a known type (EnumValues): 1 SZ, 2 EXPAND_SZ, 3 BINARY, 4 DWORD, 7 MULTI_SZ, 11 QWORD.
    var shell = type === 11 ? undefined : esRegReadShell(split, name);
    if (shell !== undefined) {
        if (type === 2) { return ES_SHELL.ExpandEnvironmentStrings(String(shell)); }
        if (type === 3) { return esRegBytesHex(shell); }
        return convertToEsRegValue(shell);
    }
    var getters = { 1: ["GetStringValue", "sValue"], 2: ["GetExpandedStringValue", "sValue"], 3: ["GetBinaryValue", "uValue"],
        4: ["GetDWORDValue", "uValue"], 7: ["GetMultiStringValue", "sValue"], 11: ["GetQWORDValue", "uValue"] };
    var getter = getters[type];
    if (!getter) { return null; }
    var out = esRegCall(getter[0], split, name);
    if (!out || out.ReturnValue !== 0) { return null; }
    if (type === 3) { return esRegBytesHex(out[getter[1]]); }
    if (type === 11) { return esRegQword(out[getter[1]]); }
    return convertToEsRegValue(out[getter[1]]);
}

function esRegEnumValues(path, split) {
    // {names, types} of a key; null when missing, denied (recorded) or not listable.
    var out = esRegCall("EnumValues", split);
    if (out === null) { esRegUnlisted(path); return null; }
    if (out.ReturnValue === ES_REG_ACCESS_DENIED) { addEsDeniedRead(path, ES_REG_ACCESS_DENIED); return null; }
    if (out.ReturnValue !== 0) { return null; }
    return { names: esVbList(out.sNames), types: esVbList(out.Types) };
}

// ------------------------------------------------------------------ public readers

function testEsRegKey(path) {
    var split = esRegSplit(path);
    if (!split) { return false; }
    var out = esRegCall("EnumKey", split);
    if (out === null) {
        try { ES_SHELL.RegRead(split.shell + "\\"); return true; } catch (e) { return false; }
    }
    return out.ReturnValue === 0 || out.ReturnValue === ES_REG_ACCESS_DENIED;
}

function getEsRegValues(path, skipValuePattern) {
    // Values of one key as name -> value, or null when the key is missing or unreadable.
    // Value names matching skipValuePattern are never read.
    var split = esRegSplit(path);
    if (!split) { return null; }
    var listed = esRegEnumValues(path, split);
    if (listed === null) { return null; }
    var skip = esToRegExp(skipValuePattern);
    var values = {};
    for (var i = 0; i < listed.names.length; i++) {
        var name = String(listed.names[i] === null ? "" : listed.names[i]);
        if (name === "" || name === "(default)" || (skip && skip.test(name))) { continue; }
        values[name] = esRegTypedValue(split, name, listed.types[i]);
    }
    return values;
}

function getEsRegValue(path, name) {
    var split = esRegSplit(path);
    if (!split) { return null; }
    var valueName = String(name === null || name === undefined ? "" : name);
    var shell = esRegReadShell(split, valueName);
    var simple = shell !== undefined && (typeof shell === "number" || (typeof shell === "string" && shell.indexOf("%") < 0));
    if (simple) { return convertToEsRegValue(shell); }
    var listed = esRegEnumValues(path, split);
    if (listed === null) { return shell === undefined ? null : convertToEsRegValue(shell); }
    for (var i = 0; i < listed.names.length; i++) {
        if (String(listed.names[i]).toLowerCase() === valueName.toLowerCase()) {
            return esRegTypedValue(split, String(listed.names[i]), listed.types[i]);
        }
    }
    return null;
}

function getEsRegBinary(path, name) {
    // Every byte of a REG_BINARY value as an array of numbers, or null (missing, other type,
    // unreadable; a denied key is recorded through addEsDeniedRead).
    var split = esRegSplit(path);
    if (!split) { return null; }
    var shell = esRegReadShell(split, String(name || ""));
    if (typeof shell === "unknown") {
        var list = esVbList(shell);
        if (list.length === 0 || typeof list[0] === "number") { return list; }
        return null;
    }
    if (shell !== undefined) { return null; }
    var out = esRegCall("GetBinaryValue", split, String(name || ""));
    if (out === null) { esRegUnlisted(path); return null; }
    if (out.ReturnValue === ES_REG_ACCESS_DENIED) { addEsDeniedRead(path, ES_REG_ACCESS_DENIED); return null; }
    return out.ReturnValue === 0 ? esVbList(out.uValue) : null;
}

function getEsRegValue32(path, name) {
    // The 32-bit view of a HKLM\SOFTWARE value, through its WOW6432Node path.
    return getEsRegValue(String(path).replace(/^(HKLM:?\\SOFTWARE)\\(?!WOW6432Node\\)/i, "$1\\WOW6432Node\\"), name);
}

function getEsRegSubkeys(path) {
    // Subkey names; a key this user may not list is recorded as a denied read.
    var split = esRegSplit(path);
    if (!split) { return []; }
    var out = esRegCall("EnumKey", split);
    if (out === null) { esRegUnlisted(path); return []; }
    if (out.ReturnValue === ES_REG_ACCESS_DENIED) { addEsDeniedRead(path, ES_REG_ACCESS_DENIED); return []; }
    if (out.ReturnValue !== 0) { return []; }
    var names = esVbList(out.sNames);
    var list = [];
    for (var i = 0; i < names.length; i++) { if (names[i]) { list.push(String(names[i])); } }
    return list;
}

function getEsRegTree(path, maxKeys, skipPattern, skipValuePattern) {
    // Every value under a key, flattened as "subkey\name" -> value (capped). Subkeys whose path
    // below `path` matches skipPattern are never opened.
    var max = maxKeys > 0 ? maxKeys : 400;
    var skip = esToRegExp(skipPattern);
    var out = {};
    var queue = [String(path)];
    var visited = 0;
    while (queue.length > 0 && visited < max) {
        var current = queue.shift();
        visited++;
        var values = getEsRegValues(current, skipValuePattern);
        if (values === null) { continue; }
        var relative = current.substr(String(path).length).replace(/^\\+/, "");
        for (var name in values) {
            if (Object.prototype.hasOwnProperty.call(values, name)) { out[relative ? relative + "\\" + name : name] = values[name]; }
        }
        var subs = getEsRegSubkeys(current);
        for (var i = 0; i < subs.length; i++) {
            var child = current + "\\" + subs[i];
            if (skip && skip.test(child.substr(String(path).length))) { continue; }
            queue.push(child);
        }
    }
    return out;
}
