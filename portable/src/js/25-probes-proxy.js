// ---------------------------------------------------------------------------
// 25-probes-proxy: proxy configuration, listening ports, netstat (deep), firewall.
// Port of src/ps/25-probes-network.ps1 (second part); helpers jsNet_* live in
// 25-probes-network.js.
// ---------------------------------------------------------------------------

// ------------------------------------------------------------------ proxy

function getEsRegBytes(path, name) {
    // A REG_BINARY value as a list of byte values, or null (missing, another type, unreadable),
    // read whole with the engine's RegRead (getEsRegValue would give at most 256 bytes as hex).
    var split = esRegSplit(path);
    if (!split) { return null; }
    var value = esRegReadShell(split, name);
    if (typeof value !== "unknown") { return null; }
    var list = esVbList(value);
    var bytes = [];
    for (var i = 0; i < list.length; i++) {
        if (typeof list[i] !== "number") { return null; }
        bytes.push(list[i] & 255);
    }
    return bytes;
}

function jsNet_blobString(bytes, offset, length) {
    var chars = [];
    for (var i = 0; i < length; i++) { chars.push(String.fromCharCode(bytes[offset + i])); }
    return chars.join("");
}

function convertFromEsProxyBlob(bytes) {
    // WinHTTP/WinINET connection blob: flags at offset 8, then length-prefixed proxy, exclusion and PAC strings.
    var result = { flags: null, proxy: null, exclusions: null, pac_url: null };
    if (bytes === null || bytes === undefined || bytes.length < 16) { return result; }
    result.flags = bytes[8];
    var offset = 12;
    var strings = [];
    for (var n = 0; n < 3; n++) {
        if (offset + 4 > bytes.length) { break; }
        var length = bytes[offset] + 256 * bytes[offset + 1] + 65536 * bytes[offset + 2];
        offset += 4;
        if (offset + length > bytes.length) { break; }
        strings.push(jsNet_blobString(bytes, offset, length));
        offset += length;
    }
    if (strings.length >= 1 && strings[0]) { result.proxy = strings[0]; }
    if (strings.length >= 2 && strings[1]) { result.exclusions = strings[1]; }
    if (strings.length >= 3 && strings[2]) { result.pac_url = strings[2]; }
    return result;
}

function getEsProxyServers(value) {
    // "host:port" or "http=host:port;https=host:port" -> list of host:port strings.
    if (!value) { return []; }
    var parts = String(value).split(";");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
        var server = esTrim(parts[i].replace(/^[A-Za-z]+=/, ""));
        if (server) { out.push(server); }
    }
    return out;
}

function jsNet_winhttp(r) {
    var key = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections";
    r.sources.push("registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections (WinHttpSettings)");
    var blob = convertFromEsProxyBlob(getEsRegBytes(key, "WinHttpSettings"));
    return { proxy: blob.proxy, exclusions: blob.exclusions, direct: !blob.proxy, configured: blob.flags !== null };
}

function jsNet_wininet(r) {
    var userKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    r.sources.push("registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings (ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL, connection flags)");
    var user = getEsRegValues(userKey) || {};
    var connection = convertFromEsProxyBlob(getEsRegBytes(userKey + "\\Connections", "DefaultConnectionSettings"));
    return {
        enabled: jsNet_str(jsNet_pick(user, "ProxyEnable")) == "1", server: jsNet_pick(user, "ProxyServer"),
        exclusions: jsNet_pick(user, "ProxyOverride"), pac_url: jsNet_pick(user, "AutoConfigURL"),
        auto_detect: (connection.flags !== null) ? ((connection.flags & 8) !== 0) : null
    };
}

function jsNet_proxyPolicy(r) {
    var policy = {};
    var hives = ["HKLM", "HKCU"];
    for (var i = 0; i < hives.length; i++) {
        r.sources.push("registry " + hives[i] + "\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        var values = getEsRegValues(hives[i] + ":\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        if (values) { policy[hives[i]] = protectEsTable(values); }
    }
    return policy;
}

function jsNet_addEndpoint(list, value, source) {
    var endpoint = convertToEsEndpoint(value, source);
    if (endpoint) { list.push(endpoint); }
}

function jsNet_proxyEndpoints(d, sources) {
    // Endpoints from raw values (redaction would leave user:<redacted>@ in front of the host).
    var endpoints = [];
    var names = esKeys(d.env);
    for (var i = 0; i < names.length; i++) {
        if (!/^no_proxy$/i.test(names[i])) { jsNet_addEndpoint(endpoints, jsNet_str(getEsOrigEnv(names[i])), "env " + names[i]); }
    }
    var winhttp = getEsProxyServers(d.winhttp.proxy);
    for (var j = 0; j < winhttp.length; j++) { jsNet_addEndpoint(endpoints, winhttp[j], "WinHTTP"); }
    if (d.wininet.enabled) {
        var wininet = getEsProxyServers(jsNet_str(d.wininet.server));
        for (var k = 0; k < wininet.length; k++) { jsNet_addEndpoint(endpoints, wininet[k], "WinINET"); }
    }
    if (d.wininet.pac_url) { jsNet_addEndpoint(endpoints, jsNet_str(d.wininet.pac_url), "PAC URL"); }
    var urls = jsNet_truthy(sources["proxy_urls"]);
    for (var n = 0; n < urls.length; n++) { jsNet_addEndpoint(endpoints, jsNet_str(urls[n]["url"]), "config " + urls[n]["tool"]); }
    return endpoints;
}

function probe_net_proxy() {
    var r = newEsResult();
    var d = r.data;
    d.env = getEsEnvSubset(ES_PROXY_ENV);
    r.sources.push("environment proxy variables");
    d.winhttp = jsNet_winhttp(r);
    d.wininet = jsNet_wininet(r);
    d.policy = jsNet_proxyPolicy(r);
    var sources = getEsData("pkg.sources");
    testEsInputComplete(r, "pkg.sources");
    // The proxy settings pkg.sources found by their names (15-proxy): { tool, setting, value, file }.
    d.package_managers = (esKeys(sources).length > 0) ? jsNet_truthy(ES_PKG_PROXY_SETTINGS) : [];
    d.proxy_endpoints = jsNet_proxyEndpoints(d, sources);
    // WPAD auto-detect is on by default in Windows, so it alone does not count as a configured proxy.
    d.any_proxy = (d.proxy_endpoints.length > 0 || !!d.wininet.pac_url);
    return r;
}

// ------------------------------------------------------------------ listening ports, netstat, firewall

function getEsProcessNames() {
    // Process id -> name without ".exe" (what Get-Process shows), from Win32_Process.
    var names = {};
    var query = getEsCimSafe("Win32_Process", "root/cimv2", "", ["ProcessId", "Name"]);
    for (var i = 0; i < query.items.length; i++) {
        var name = jsNet_str(query.items[i].Name).replace(/\.exe$/i, "");
        names["p" + jsNet_str(query.items[i].ProcessId)] = name;
    }
    return names;
}

function jsNet_listeningTcp(items, names) {
    var sorted = jsNet_stableSort(items, function (item) { return parseInt(item.LocalPort, 10) || 0; }, jsNet_numCompare);
    var seen = {};
    var tcp = [];
    for (var i = 0; i < sorted.length; i++) {
        var item = sorted[i];
        var key = "k" + jsNet_str(item.LocalAddress) + "|" + jsNet_str(item.LocalPort);
        if (seen[key]) { continue; }
        seen[key] = true;
        var name = names["p" + jsNet_str(item.OwningProcess)];
        tcp.push({ address: jsNet_str(item.LocalAddress), port: parseInt(item.LocalPort, 10), pid: parseInt(item.OwningProcess, 10),
            process: (name === undefined) ? null : name });
    }
    return tcp;
}

function jsNet_portList(tcp) {
    var ports = [];
    for (var i = 0; i < tcp.length; i++) { if (!esContains(ports, tcp[i].port)) { ports.push(tcp[i].port); } }
    return jsNet_stableSort(ports, function (p) { return p; }, jsNet_numCompare);
}

function probe_net_listening() {
    var r = newEsResult();
    var items = addEsCimItems(r, "MSFT_NetTCPConnection", "root/StandardCimv2", "State=2", ["LocalAddress", "LocalPort", "OwningProcess"]);
    var names = getEsProcessNames();
    r.sources.push("CIM Win32_Process (names only)");
    var tcp = jsNet_listeningTcp(items, names);
    r.data.tcp = tcp;
    r.data.ports = jsNet_portList(tcp);
    var used = [];
    var common = ES_THRESHOLDS["common_ports"] || [];
    for (var i = 0; i < common.length; i++) { if (esContains(r.data.ports, parseInt(common[i], 10))) { used.push(common[i]); } }
    r.data.common_ports_in_use = used;
    if (r.status != "ok" && tcp.length === 0) { addEsNote(r, "listening ports need Windows 8 / Server 2012 or later without --deep (netstat)", ""); }
    return r;
}

function probe_net_netstat() {
    var r = newEsResult();
    var run = invokeEsTool(r, "netstat -ano", getEsSystemTool("netstat.exe"), ["-ano"], 60);
    var listening = [];
    var lines = jsNet_lines(run.stdout);
    for (var i = 0; i < lines.length; i++) {
        var m = /^\s*TCP\s+(\S+):(\d+)\s+(0\.0\.0\.0:0|\[::\]:0)\s+\S+\s+(\d+)/.exec(lines[i]);
        if (m) { listening.push({ address: m[1], port: parseInt(m[2], 10), pid: parseInt(m[4], 10) }); }
    }
    r.data.tcp_listening = listening;
    return r;
}

function convertToEsFirewallFlag(value) {
    var text = esLower(jsNet_str(value));
    if (text == "1" || text == "true") { return true; }
    if (text == "0" || text == "false") { return false; }
    return null;
}

function jsNet_firewallAction(value) {
    // [string][int]$value: null and "" are 0.
    var actions = { a0: "not_configured", a2: "allow", a4: "block" };
    var number = (value === null || value === undefined || value === "") ? 0 : parseInt(value, 10);
    var action = actions["a" + String(number)];
    return (action === undefined) ? null : action;
}

function jsNet_firewallPolicy() {
    var policy = {};
    var names = ["DomainProfile", "StandardProfile", "PublicProfile"];
    for (var i = 0; i < names.length; i++) {
        var values = getEsRegValues("HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\" + names[i]);
        if (values) {
            policy[names[i]] = { EnableFirewall: jsNet_pick(values, "EnableFirewall"), DefaultInboundAction: jsNet_pick(values, "DefaultInboundAction"),
                DefaultOutboundAction: jsNet_pick(values, "DefaultOutboundAction") };
        }
    }
    return policy;
}

function probe_net_firewall() {
    var r = newEsResult();
    var items = addEsCimItems(r, "MSFT_NetFirewallProfile", "root/StandardCimv2", "", ["Name", "Enabled", "DefaultInboundAction", "DefaultOutboundAction"]);
    var profiles = [];
    for (var i = 0; i < items.length; i++) {
        profiles.push({ name: jsNet_str(items[i].Name), enabled: convertToEsFirewallFlag(items[i].Enabled),
            inbound: jsNet_firewallAction(items[i].DefaultInboundAction), outbound: jsNet_firewallAction(items[i].DefaultOutboundAction) });
    }
    r.data.profiles = profiles;
    r.data.policy = jsNet_firewallPolicy();
    r.sources.push("registry HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall (profile values)");
    return r;
}
