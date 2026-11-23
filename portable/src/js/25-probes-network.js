// ---------------------------------------------------------------------------
// 25-probes-network: port reservations, interfaces, routes, DNS, proxy,
// listening ports, netstat (deep), firewall, reachability (net).
// Port of src/ps/25-probes-network.ps1. JScript has no DNS or TCP API without COM objects
// outside the allowlist, so net.reachability lists the targets with the ps skip reasons and
// contacts nothing (status not_applicable).
// ---------------------------------------------------------------------------

var ES_MAX_REACH_TARGETS = 20;

// ------------------------------------------------------------------ file-local helpers

function jsNet_pick(values, name) {
    // A value of a registry value table by name, ignoring case (registry names are
    // case-insensitive, like a PowerShell hashtable); null when absent.
    if (!values) { return null; }
    var wanted = esLower(name);
    for (var key in values) {
        if (esHas(values, key) && key != "__order" && esLower(key) == wanted) {
            var value = values[key];
            return (value === undefined) ? null : value;
        }
    }
    return null;
}

function jsNet_str(value) {
    // PowerShell [string] cast: $null -> "".
    return (value === null || value === undefined) ? "" : String(value);
}

function jsNet_psArray(value) {
    // PowerShell @(value): $null -> @($null), an array stays, a scalar becomes a list of one.
    if (value === undefined) { return [null]; }
    if (esIsArray(value)) { return value.slice(0); }
    return [value];
}

function jsNet_truthy(values) {
    // @(values | Where-Object { $_ }): the list without null, empty, 0 and false elements.
    var out = [];
    var list = (values === null || values === undefined) ? [] : jsNet_psArray(values);
    for (var i = 0; i < list.length; i++) { if (list[i]) { out.push(list[i]); } }
    return out;
}

function jsNet_unique(values) {
    // Select-Object -Unique (case-sensitive), first occurrence kept.
    var out = [];
    for (var i = 0; i < values.length; i++) { if (!esContains(out, values[i])) { out.push(values[i]); } }
    return out;
}

function jsNet_stableSort(items, keyOf, compare) {
    // A stable sort (JScript's Array.sort is not): ties keep their input order.
    var keyed = [];
    for (var i = 0; i < items.length; i++) { keyed.push({ k: keyOf(items[i]), i: i, v: items[i] }); }
    keyed.sort(function (a, b) {
        var c = compare(a.k, b.k);
        return (c !== 0) ? c : (a.i - b.i);
    });
    var out = [];
    for (var j = 0; j < keyed.length; j++) { out.push(keyed[j].v); }
    return out;
}

function jsNet_numCompare(a, b) { return a - b; }

function jsNet_textCompare(a, b) {
    // Case-insensitive text order (PowerShell sorts strings ignoring case).
    var x = esLower(a);
    var y = esLower(b);
    return (x < y) ? -1 : ((x > y) ? 1 : 0);
}

function jsNet_lines(text) {
    // -split "`n" (a trailing CR stays on each line, like ps).
    return jsNet_str(text).split("\n");
}

// ------------------------------------------------------------------ ports

function jsNet_excludedRanges(text) {
    var ranges = [];
    var lines = jsNet_lines(text);
    for (var i = 0; i < lines.length; i++) {
        var m = /^\s*(\d+)\s+(\d+)(\s+\*)?\s*$/.exec(lines[i]);
        if (m) { ranges.push({ start: parseInt(m[1], 10), end: parseInt(m[2], 10), administered: !!m[3] }); }
    }
    return ranges;
}

function jsNet_ephemeral(text) {
    var numbers = [];
    var re = /:\s*(\d+)/g;
    var m;
    while ((m = re.exec(jsNet_str(text))) !== null) { numbers.push(parseInt(m[1], 10)); }
    if (numbers.length < 2) { return null; }
    return { start: numbers[0], end: numbers[0] + numbers[1] - 1, count: numbers[1] };
}

function jsNet_urls(text) {
    var urls = [];
    var re = /\bhttps?:\/\/\S+/gi;
    var m;
    while ((m = re.exec(jsNet_str(text))) !== null) { urls.push(m[0]); }
    return urls;
}

function jsNet_blockedPorts(ranges) {
    var blocked = [];
    var ports = ES_THRESHOLDS["common_ports"] || [];
    for (var i = 0; i < ports.length; i++) {
        var port = parseInt(ports[i], 10);
        for (var j = 0; j < ranges.length; j++) {
            if (port >= ranges[j].start && port <= ranges[j].end) { blocked.push(port); break; }
        }
    }
    return blocked;
}

function probe_net_ports() {
    var r = newEsResult();
    var d = r.data;
    var netsh = getEsSystemTool("netsh.exe");
    var excluded = invokeEsTool(r, "excludedportrange tcp", netsh, ["int", "ipv4", "show", "excludedportrange", "protocol=tcp"]);
    var ranges = jsNet_excludedRanges(excluded.stdout);
    d.excluded_tcp = ranges;
    var dynamic = invokeEsTool(r, "dynamicport tcp", netsh, ["int", "ipv4", "show", "dynamicport", "tcp"]);
    d.ephemeral = jsNet_ephemeral(dynamic.stdout);
    var urlacl = invokeEsTool(r, "http urlacl", netsh, ["http", "show", "urlacl"]);
    var urls = jsNet_urls(urlacl.stdout);
    d.urlacl_count = urls.length;
    d.urlacl = urls.slice(0, 100);
    d.unprivileged_port_start = null;
    d.common_ports_excluded = jsNet_blockedPorts(ranges);
    return r;
}

// ------------------------------------------------------------------ interfaces, routes, DNS

var JS_NET_CONFIG_PROPS = ["Index", "InterfaceIndex", "Description", "IPAddress", "IPSubnet", "MACAddress",
    "DefaultIPGateway", "DNSServerSearchOrder", "DHCPEnabled", "DNSDomain", "DNSDomainSuffixSearchOrder"];

function jsNet_mtuTable(r) {
    var mtu = {};
    var ipif = getEsCimSafe("MSFT_NetIPInterface", "root/StandardCimv2", "", ["AddressFamily", "InterfaceIndex", "NlMtu"]);
    if (ipif.status != "ok") { return mtu; }
    r.sources.push("CIM root/StandardCimv2:MSFT_NetIPInterface (MTU)");
    for (var i = 0; i < ipif.items.length; i++) {
        var item = ipif.items[i];
        if (parseInt(item.AddressFamily, 10) === 2) { mtu["i" + jsNet_str(item.InterfaceIndex)] = item.NlMtu; }
    }
    return mtu;
}

function jsNet_speedMbps(adapter) {
    if (!adapter || !adapter.Speed || adapter.Speed === "0") { return null; }
    return Math.round(parseFloat(String(adapter.Speed)) / 1000000);
}

function jsNet_interface(config, adapter, mtu) {
    var m = mtu["i" + jsNet_str(config.InterfaceIndex)];
    return {
        name: adapter ? jsNet_str(adapter.NetConnectionID) : null, description: jsNet_str(config.Description),
        addresses: jsNet_psArray(config.IPAddress), subnets: jsNet_psArray(config.IPSubnet), mac: jsNet_str(config.MACAddress),
        mtu: (m === undefined) ? null : m, gateways: jsNet_truthy(config.DefaultIPGateway),
        dns: jsNet_truthy(config.DNSServerSearchOrder), dhcp: !!config.DHCPEnabled,
        dns_domain: jsNet_str(config.DNSDomain), dns_suffixes: jsNet_truthy(config.DNSDomainSuffixSearchOrder),
        speed_mbps: jsNet_speedMbps(adapter),
        index: (config.InterfaceIndex === undefined) ? null : config.InterfaceIndex
    };
}

function probe_net_interfaces() {
    var r = newEsResult();
    var configs = addEsCimItems(r, "Win32_NetworkAdapterConfiguration", "root/cimv2", "IPEnabled=TRUE", JS_NET_CONFIG_PROPS);
    var adapters = addEsCimItems(r, "Win32_NetworkAdapter", "root/cimv2", "NetConnectionID IS NOT NULL", ["DeviceID", "NetConnectionID", "Speed"]);
    var byIndex = {};
    for (var i = 0; i < adapters.length; i++) { byIndex["i" + jsNet_str(adapters[i].DeviceID)] = adapters[i]; }
    var mtu = jsNet_mtuTable(r);
    var interfaces = [];
    for (var j = 0; j < configs.length; j++) {
        interfaces.push(jsNet_interface(configs[j], byIndex["i" + jsNet_str(configs[j].Index)] || null, mtu));
    }
    r.data.interfaces = interfaces;
    if (configs.length === 0 && r.status == "ok") { r.status = "not_found"; r.notes.push("no IP-enabled adapter"); }
    return r;
}

function jsNet_routeLine(parts) { return parts.join(""); }

function jsNet_netRoutes(items, acc) {
    // MSFT_NetRoute: an on-link default route (next hop 0.0.0.0 or ::) has no gateway.
    for (var i = 0; i < items.length; i++) {
        var prefix = jsNet_str(items[i].DestinationPrefix);
        var hop = jsNet_str(items[i].NextHop);
        if (prefix == "0.0.0.0/0" || prefix == "::/0") {
            acc.defaults++;
            if (hop != "0.0.0.0" && hop != "::") { acc.gateways.push(hop); }
        }
        acc.routes.push(jsNet_routeLine([prefix, " via ", hop, " if ", jsNet_str(items[i].InterfaceIndex), " metric ", jsNet_str(items[i].RouteMetric)]));
    }
}

function jsNet_ip4Routes(items, acc) {
    for (var i = 0; i < items.length; i++) {
        var route = items[i];
        if (jsNet_str(route.Destination) == "0.0.0.0" && jsNet_str(route.Mask) == "0.0.0.0") {
            acc.defaults++;
            if (jsNet_str(route.NextHop) != "0.0.0.0") { acc.gateways.push(jsNet_str(route.NextHop)); }
        }
        acc.routes.push(jsNet_routeLine([jsNet_str(route.Destination), "/", jsNet_str(route.Mask), " via ", jsNet_str(route.NextHop),
            " if ", jsNet_str(route.InterfaceIndex), " metric ", jsNet_str(route.Metric1)]));
    }
}

function jsNet_sortedUnique(values) {
    // Sort-Object -Unique: sorted, duplicates ignoring case removed.
    var sorted = jsNet_stableSort(values, function (v) { return v; }, jsNet_textCompare);
    var out = [];
    for (var i = 0; i < sorted.length; i++) {
        if (out.length === 0 || esLower(out[out.length - 1]) != esLower(sorted[i])) { out.push(sorted[i]); }
    }
    return out;
}

function probe_net_routes() {
    var r = newEsResult();
    var d = r.data;
    var query = getEsCimSafe("MSFT_NetRoute", "root/StandardCimv2", "", ["DestinationPrefix", "NextHop", "InterfaceIndex", "RouteMetric"]);
    r.sources.push("CIM root/StandardCimv2:MSFT_NetRoute");
    var acc = { routes: [], gateways: [], defaults: 0 };
    if (query.status == "ok") {
        jsNet_netRoutes(query.items, acc);
    } else {
        jsNet_ip4Routes(addEsCimItems(r, "Win32_IP4RouteTable", "root/cimv2", "", ["Destination", "Mask", "NextHop", "InterfaceIndex", "Metric1"]), acc);
    }
    d.default_route_count = acc.defaults;
    d.default_gateways = jsNet_sortedUnique(acc.gateways);
    d.route_count = acc.routes.length;
    d.routes = acc.routes.slice(0, 200);
    return r;
}

function getEsHostsEntries(result) {
    // The entries of the hosts file: no comments or blank lines, at most 200.
    var hostsPath = esJoinPath(jsNet_str(getEsEnv("SystemRoot")), "System32\\drivers\\etc\\hosts");
    result.sources.push("read " + hostsPath);
    var hosts = readEsTextFile(hostsPath, 65536);
    addEsReadNote(result, hostsPath, hosts.error, "hosts file");
    var out = [];
    var lines = jsNet_lines(hosts.text);
    for (var i = 0; i < lines.length && out.length < 200; i++) {
        var line = esTrim(lines[i]);
        if (line && line.charAt(0) != "#") { out.push(line); }
    }
    return out;
}

function jsNet_dnsInterfaces(r) {
    var interfaces = getEsData("net.interfaces")["interfaces"];
    if (interfaces && interfaces.length > 0 && interfaces[0]) {
        r.sources.push("net.interfaces (DNS servers and suffixes)");
        return interfaces;
    }
    var configs = addEsCimItems(r, "Win32_NetworkAdapterConfiguration", "root/cimv2", "IPEnabled=TRUE", JS_NET_CONFIG_PROPS);
    var out = [];
    for (var i = 0; i < configs.length; i++) {
        out.push({ dns: jsNet_psArray(configs[i].DNSServerSearchOrder), dns_suffixes: jsNet_psArray(configs[i].DNSDomainSuffixSearchOrder) });
    }
    return out;
}

function jsNet_splitList(value) {
    // -split '[,\s]+' without the empty parts.
    var parts = jsNet_str(value).split(/[,\s]+/);
    var out = [];
    for (var i = 0; i < parts.length; i++) { if (parts[i]) { out.push(parts[i]); } }
    return out;
}

function probe_net_dns() {
    var r = newEsResult();
    var d = r.data;
    var interfaces = jsNet_dnsInterfaces(r);
    var servers = [];
    var search = [];
    for (var i = 0; i < interfaces.length; i++) {
        if (!interfaces[i]) { continue; }
        servers = servers.concat(jsNet_truthy(interfaces[i]["dns"]));
        search = search.concat(jsNet_truthy(interfaces[i]["dns_suffixes"]));
    }
    var tcpip = getEsRegValues("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters");
    var policy = getEsRegValues("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient");
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters (SearchList, Domain)");
    r.sources.push("registry HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient");
    if (jsNet_pick(tcpip, "SearchList")) { search = search.concat(jsNet_splitList(jsNet_pick(tcpip, "SearchList"))); }
    if (jsNet_pick(policy, "SearchList")) { search = search.concat(jsNet_splitList(jsNet_pick(policy, "SearchList"))); }
    d.servers = jsNet_unique(servers);
    d.search = jsNet_unique(search);
    d.domain = tcpip ? jsNet_str(jsNet_pick(tcpip, "Domain")) : null;
    d.policy = policy ? policy : {};
    d.llmnr_disabled = !!(policy && jsNet_str(jsNet_pick(policy, "EnableMulticast")) == "0");
    d.nrpt_rules = (getEsRegSubkeys("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig") || []).length;
    d.hosts_entries = getEsHostsEntries(r);
    d.resolver_order = "hosts file, DNS (NRPT, suffix search), LLMNR/NetBIOS";
    return r;
}
