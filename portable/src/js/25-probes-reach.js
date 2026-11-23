// ---------------------------------------------------------------------------
// 25-probes-reach: net.reachability (tier "net").
// The ps1 resolves names ([Net.Dns] or System32 nslookup) and connects with TcpClient. JScript
// has no DNS or TCP API without COM objects outside the allowlist, so the WSH port contacts
// nothing: it lists the targets the ps1 would consider, with the ps1 skip reasons (public
// registries, net_never hosts, public IPv4, IPv6 outside the global and unique-local ranges)
// computed exactly as there (single-label names included), and every other target as not
// checked. Status not_applicable.
// ---------------------------------------------------------------------------

var ES_IPV4_RE = /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/;
var ES_IPV6_WHY = "IPv6 address outside the global and unique-local ranges; never contacted";
var ES_PUBLIC_V4_WHY = "public IPv4 address; never contacted";
var ES_NET_NEVER_WHY = "cloud metadata or link-local address; never contacted";
var ES_PUBLIC_HOST_WHY = "public registry; only internal mirrors and proxies are checked";
var ES_SINGLE_LABEL_WHY = "single-label name; DNS search domains could expand it, so it is not looked up";
var ES_MALFORMED_HOST_WHY = "malformed host name; not looked up";
var ES_WSH_NO_TCP_WHY = "TCP reachability is not available in the WSH port; never contacted";
var ES_WSH_REACH_NOTE = "TCP reachability is not available in the WSH port; use envscan.ps1 or envscan.sh";

function testEsIpv4Allowed(address) {
    // An IPv4 address that may be contacted: private (10/8, 172.16/12, 192.168/16) or shared
    // (100.64/10) only. Every other address (public, loopback, broadcast) fails, and so does any
    // text that is not four decimal octets 0-255 without leading zeros.
    var m = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(String(address));
    if (!m) { return false; }
    var o = [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10), parseInt(m[4], 10)];
    for (var i = 0; i < 4; i++) { if (o[i] > 255) { return false; } }
    if (o[0] === 10) { return true; }
    if (o[0] === 172) { return o[1] >= 16 && o[1] <= 31; }
    if (o[0] === 192) { return o[1] === 168; }
    if (o[0] === 100) { return o[1] >= 64 && o[1] <= 127; }
    return false;
}

function jsNet_trimBrackets(text) {
    // TrimStart('[').TrimEnd(']'): every leading [ and trailing ].
    return text.replace(/^\[+/, "").replace(/\]+$/, "");
}

function testEsIpv6Allowed(address) {
    // An IPv6 address that may be contacted: first hextet 2000-3fff (global unicast) or
    // fc00-fdff (unique local), not in fd00:ec2::/32, no zone id. The same rule as the ps1
    // Test-EsIpv6Allowed and es_ip6_ok in src/sh/28-reach.sh.
    var a = jsNet_trimBrackets(esLower(String(address)));
    if (a.indexOf("%") >= 0 || !/^[0-9a-f:.]+$/.test(a) || a.indexOf(":") < 0) { return false; }
    var first = a.substring(0, a.indexOf(":"));
    if (!/^[0-9a-f]{1,4}$/.test(first)) { return false; }
    var value = parseInt(first, 16);
    if (value >= 0x2000 && value <= 0x3fff) { return true; }
    if (value < 0xfc00 || value > 0xfdff) { return false; }
    if (value !== 0xfd00) { return true; }
    var second = a.substring(a.indexOf(":") + 1).split(":")[0].replace(/^0+/, "");
    return second != "ec2";
}

function jsNet_isPublicHost(hostName) {
    // spec public_hosts: the host itself or a subdomain of one, ignoring case.
    var host = esLower(hostName);
    for (var i = 0; i < ES_PUBLIC_HOSTS.length; i++) {
        var suffix = esLower(ES_PUBLIC_HOSTS[i]);
        if (host == suffix) { return true; }
        if (host.length > suffix.length && host.substring(host.length - suffix.length - 1) == "." + suffix) { return true; }
    }
    return false;
}

function getEsReachSkipReason(hostName) {
    // Why a host is never resolved or contacted, or null. registry.npmjs.org. is registry.npmjs.org.
    var raw = String(hostName);
    var host = raw.replace(/\.$/, "");
    var name = host.indexOf(":") < 0;
    // An empty name or a leading "." (after one trailing dot is removed), or ".." anywhere in the
    // name as written ("host..") is not a host name.
    if (name && (host === "" || host.charAt(0) === "." || raw.indexOf("..") >= 0)) { return ES_MALFORMED_HOST_WHY; }
    if (testEsNetNever(host)) { return ES_NET_NEVER_WHY; }
    if (jsNet_isPublicHost(host)) { return ES_PUBLIC_HOST_WHY; }
    if (!name && !testEsIpv6Allowed(host)) { return ES_IPV6_WHY; }
    // An IPv4 literal written with a trailing dot is never contacted (no resolver may see it).
    if (ES_IPV4_RE.test(host) && (host !== raw || !testEsIpv4Allowed(host))) { return ES_PUBLIC_V4_WHY; }
    // A name without a "." would be completed with the DNS search list (a host name, so not an
    // IPv6 literal). The ps1 and sh look every other name up in its absolute form ("name.");
    // this port resolves nothing, so that half of the rule needs no code here.
    if (name && host.indexOf(".") < 0) { return ES_SINGLE_LABEL_WHY; }
    return null;
}

function newEsSkippedTarget(candidate, reason) {
    // The shared shape of a target that is not contacted: host, port, source, tcp and reason only.
    return { host: candidate["host"], port: candidate["port"], source: candidate["source"], tcp: "skipped", reason: reason };
}

function selectEsReachAddress(addresses) {
    // The address the ps1 would connect to: the first allowed IPv4 address, else the first
    // allowed IPv6 address; null when there is none. Kept for parity; nothing connects here.
    var v6 = null;
    for (var i = 0; i < addresses.length; i++) {
        var text = String(addresses[i]);
        if (text.indexOf(":") < 0) {
            if (testEsIpv4Allowed(text)) { return text; }
        } else if (v6 === null && testEsIpv6Allowed(text)) { v6 = text; }
    }
    return v6;
}

function jsNet_reachCandidates() {
    var candidates = jsNet_truthy(getEsData("net.proxy")["proxy_endpoints"]);
    var urls = getEsData("pkg.sources")["endpoints"];
    var list = (urls === null || urls === undefined) ? [] : jsNet_psArray(urls);
    for (var i = 0; i < list.length; i++) {
        var endpoint = convertToEsEndpoint(jsNet_str(list[i]), "package configuration");
        if (endpoint) { candidates.push(endpoint); }
    }
    return candidates;
}

function jsNet_reachTargets(candidates) {
    // The ps1 loop: de-duplicated by host:port, skip reasons first, then the cap of 20 on
    // the targets that would be looked up. Here those are recorded as not checked.
    var seen = {};
    var acc = { targets: [], looked: 0, over: 0 };
    for (var i = 0; i < candidates.length; i++) {
        var candidate = candidates[i];
        var key = "k" + esLower(jsNet_str(candidate["host"])) + ":" + jsNet_str(candidate["port"]);
        if (seen[key]) { continue; }
        seen[key] = true;
        var reason = getEsReachSkipReason(jsNet_str(candidate["host"]));
        if (reason) { acc.targets.push(newEsSkippedTarget(candidate, reason)); continue; }
        if (acc.looked >= ES_MAX_REACH_TARGETS) { acc.over++; continue; }
        acc.looked++;
        acc.targets.push(newEsSkippedTarget(candidate, ES_WSH_NO_TCP_WHY));
    }
    return acc;
}

function probe_net_reachability() {
    var r = newEsResult();
    var acc = jsNet_reachTargets(jsNet_reachCandidates());
    r.data.targets = acc.targets;
    r.sources.push("net.proxy and pkg.sources data (nothing is resolved or contacted)");
    if (acc.targets.length === 0) {
        r.status = "not_found";
        r.notes.push("no proxy or mirror endpoint was found in local configuration");
    } else {
        r.status = "not_applicable";
        r.notes.push(ES_WSH_REACH_NOTE);
    }
    testEsInputComplete(r, "net.proxy");
    testEsInputComplete(r, "pkg.sources");
    if (acc.targets.length > 0) { r.notes.push(String(acc.targets.length) + " endpoint(s) skipped and never contacted; each target says why"); }
    if (acc.over > 0) { r.notes.push(String(acc.over) + " more endpoint(s) not checked (at most " + ES_MAX_REACH_TARGETS + ")"); }
    return r;
}
