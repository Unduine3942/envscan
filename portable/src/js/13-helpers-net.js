// ---------------------------------------------------------------------------
// 13-helpers-net: URLs and endpoints from configuration text, net-never hosts,
// UTF-8 decoding (port of the URL and text parts of 13-helpers.ps1).
// ---------------------------------------------------------------------------

// XML namespaces and schemas are identifiers, not package sources.
var ES_SCHEMA_URL_RE = /^https?:\/\/(www\.w3\.org|schemas\.(xmlsoap\.org|microsoft\.com|openxmlformats\.org)|json-schema\.org|maven\.apache\.org\/(POM|SETTINGS|xsd|maven-v))/i;

// An http(s) URL, its authority (userinfo@host:port) and the rest. ps1 also requires that the
// URL does not continue a word or a key (credential.https://...) with a lookbehind, which
// JScript lacks: jsHlp_urlStartOk checks the character before the match instead.
var ES_ENDPOINT_URL_RE = /(https?):\/\/([^\/?#\s]*)([^\s"'<>]*)/gi;
// The host[:port] at the start of what follows the last "@" of the authority.
var ES_ENDPOINT_HOST_RE = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(:[0-9]{1,5})?(?![A-Za-z0-9.:\[\]@-])/;
var JSHLP_URL_COMMENT_RE = /^\s*(#|;|<!--|\/\/\s|REM\s)/i;
var JSHLP_XML_ID_RE = /\b(xmlns(:\w+)?|(xsi:)?schemaLocation)\s*=\s*"[^"]*"/gi;

// Default ports of URL schemes; an unknown scheme without an explicit port is not usable.
var ES_SCHEME_PORTS = {
    "http": 80, "https": 443, "socks": 1080, "socks4": 1080, "socks4a": 1080, "socks5": 1080, "socks5h": 1080,
    "ftp": 21, "git": 9418, "ssh": 22
};

function jsHlp_urlStartOk(text, index) {
    // The (?<![A-Za-z0-9.+-]) of the ps1 URL pattern.
    return index === 0 || !/[A-Za-z0-9.+\-]/.test(text.charAt(index - 1));
}

function jsHlp_lineUrls(clean, urls) {
    // Adds scheme://host[:port] of each URL in one line to urls (new array returned).
    var out = urls.slice(0);
    var re = new RegExp(ES_ENDPOINT_URL_RE.source, "gi");
    var m;
    while ((m = re.exec(clean)) !== null) {
        if (!jsHlp_urlStartOk(clean, m.index)) { re.lastIndex = m.index + 1; continue; }
        var authority = m[2];
        var hostMatch = ES_ENDPOINT_HOST_RE.exec(authority.substr(authority.lastIndexOf("@") + 1));
        if (!hostMatch) { continue; }
        // One trailing dot (an absolute DNS name) would let a public host pass as another host.
        var hostPort = hostMatch[0].replace(/\.(:[0-9]+)?$/, "$1");
        var base = (m[1] + "://" + hostPort).toLowerCase();
        if (ES_SCHEMA_URL_RE.test(base + m[3]) || esContains(out, base)) { continue; }
        out.push(base);
    }
    return out;
}

function getEsEndpointUrls(text) {
    // scheme://host[:port] (lower case) of every http(s) URL in configuration text, in order of
    // first appearance. Read from the raw text: redaction would cut a URL at its userinfo, and
    // the result never holds userinfo, a path or a query. Comment lines and XML namespace and
    // schema references are skipped.
    if (!text) { return []; }
    var urls = [];
    var lines = String(text).split("\n");
    for (var i = 0; i < lines.length; i++) {
        if (JSHLP_URL_COMMENT_RE.test(lines[i])) { continue; }
        urls = jsHlp_lineUrls(lines[i].replace(JSHLP_XML_ID_RE, ""), urls);
    }
    return urls;
}

function testEsNetNever(hostName) {
    // Cloud metadata and link-local hosts and addresses (spec net_never): never resolved or
    // contacted. An entry ending in "." or ":" is an address prefix, any other a whole host.
    var raw = (hostName === null || hostName === undefined) ? "" : String(hostName);
    var name = jsHlp_trimChars(jsHlp_trimChars(esTrim(raw), "[", true, false), "]", false, true);
    name = jsHlp_trimChars(name, ".", false, true).toLowerCase();
    if (!name) { return false; }
    for (var i = 0; i < ES_NET_NEVER.length; i++) {
        var entry = String(ES_NET_NEVER[i]);
        var last = entry.charAt(entry.length - 1);
        if (last === "." || last === ":") {
            if (name.length >= entry.length && name.substr(0, entry.length) === entry) { return true; }
        } else if (name === entry) { return true; }
    }
    return false;
}

function jsHlp_endpointHost(hostPort) {
    // [host, port or null] from host[:port], [v6]:port or a bare IPv6 address; null otherwise.
    var m = /^\[([0-9A-Fa-f:.]+)\](?::([0-9]{1,5}))?$/.exec(hostPort) || /^([A-Za-z0-9][A-Za-z0-9.\-]*)(?::([0-9]{1,5}))?$/.exec(hostPort);
    if (m) { return [m[1], m[2] ? parseInt(m[2], 10) : null]; }
    if (/^[0-9A-Fa-f]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*$/.test(hostPort)) { return [hostPort, null]; }
    return null;
}

function convertToEsEndpoint(value, source) {
    // host and port from a URL or host:port. null unless the host is a name, an IPv4 or an
    // IPv6 address; also for localhost and net-never hosts (testEsNetNever).
    if (!value) { return null; }
    var v = jsHlp_trimChars(esTrim(value), "\"'", true, true);
    var port = null;
    var scheme = /^([A-Za-z][A-Za-z0-9+.\-]*):\/\//.exec(v);
    if (scheme) {
        var name = scheme[1].toLowerCase();
        v = v.substr(scheme[0].length);
        port = esHas(ES_SCHEME_PORTS, name) ? ES_SCHEME_PORTS[name] : -1;
    }
    var cut = v.search(/[\/?#\s]/);
    var authority = cut < 0 ? v : v.substr(0, cut);
    var parsed = jsHlp_endpointHost(authority.substr(authority.lastIndexOf("@") + 1));
    if (parsed && parsed[1] !== null) { port = parsed[1]; }
    if (!parsed || port === -1) { return null; }
    var hostName = parsed[0].replace(/\.$/, "").toLowerCase();
    if (testEsNetNever(hostName) || hostName === "localhost" || hostName === "127.0.0.1" || hostName === "::1") { return null; }
    if (!port) { port = 80; }
    return { host: hostName, port: port, source: source };
}

// ------------------------------------------------------------------ text

function jsHlp_utf8Code(bytes, start) {
    // [code point or 0xFFFD, next index] of the UTF-8 sequence at start.
    var b = bytes[start];
    var i = start + 1;
    var more = 0;
    var code;
    if (b < 0x80) { code = b; }
    else if (b < 0xC0 || b >= 0xF8) { code = 0xFFFD; }
    else if (b >= 0xF0) { code = b - 0xF0; more = 3; }
    else if (b >= 0xE0) { code = b - 0xE0; more = 2; }
    else { code = b - 0xC0; more = 1; }
    for (var k = 0; k < more; k++) {
        if (i >= bytes.length || bytes[i] < 0x80 || bytes[i] > 0xBF) { code = 0xFFFD; break; }
        code = code * 64 + (bytes[i] - 0x80);
        i++;
    }
    if (code > 0x10FFFF) { code = 0xFFFD; }
    return [code, i];
}

function convertFromEsUtf8Bytes(bytes) {
    // UTF-8 bytes as text, decoded by hand. A malformed sequence becomes U+FFFD; a code point
    // above U+FFFF a surrogate pair.
    var list = jsHlp_list(bytes);
    var chars = [];
    var i = 0;
    while (i < list.length) {
        var step = jsHlp_utf8Code(list, i);
        var code = step[0];
        i = step[1];
        if (code < 0x10000) { chars.push(String.fromCharCode(code)); continue; }
        var low = (code - 0x10000) % 1024;
        chars.push(String.fromCharCode(0xD800 + (code - 0x10000 - low) / 1024));
        chars.push(String.fromCharCode(0xDC00 + low));
    }
    return chars.join("");
}
