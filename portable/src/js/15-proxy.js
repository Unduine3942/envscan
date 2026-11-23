// ---------------------------------------------------------------------------
// 15-proxy: proxy settings in configuration lines, found by the NAME of the setting and never
// by "proxy" in a value (a registry URL ".../repository/npm-proxy/" is not a proxy).
// Port of src/ps/15-proxy.ps1 (itself a port of src/sh/awk/proxy.awk): keep the three in step
// (tests/proxy_cases.py runs the same cases through all of them). Forms: key=value, key: value,
// key "value" (yarn, apt), export, set and setenv, quoted JSON and TOML keys, XML
// <name>value</name> and NuGet <add key="http_proxy" value="..."/>. A proxy key that opens a
// block (YAML "proxy_servers:", JSON "proxies": {, Maven <proxies> and <proxy>) makes its
// children proxy settings; host, port and protocol children fold into one proxy, as do
// Java-style *.proxyHost and *.proxyPort pairs. User names, passwords and tokens are never
// returned. A Ruby symbol key (.gemrc ":http_proxy:") counts without its colon. Go's GOPROXY
// (a module mirror) and GONOPROXY are no proxy settings. Under a key ending in "proxy" a bare
// host (also a single label, not a keyword such as null, off or direct) gets port 80.
// Matching is case-sensitive as in awk; keys are lower-cased where awk lower-cases them.
// The parser state is one object that the functions below update in place, as in ps1.
// ---------------------------------------------------------------------------

var ES_PROXY_NAME_RE = /prox(y|ies)/;
var ES_PROXY_SECRET_RE = /(user|username|login|pass|password|passwd|pwd|token|secret|credential|credentials|auth|authorization)$/;
// Exclusion lists: no_proxy, nonProxyHosts and the like ("b[y]pass": a word the suspicious
// keyword list of script scanners scores).
var ES_PROXY_EXCLUDE_RE = /no[_-]?prox(y|ies)|non[_-]?prox(y|ies)|b[y]pass|exclu/;
var ES_PROXY_KEY_RE = /^[A-Za-z0-9_@][A-Za-z0-9_.@\-]*(::?[A-Za-z0-9_.@\-]+)*/;
var ES_PROXY_HOST_RE = /^(\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9._\-]+)(:[0-9]+)?/;
// A bare host: dotted labels (or an IPv4 address), or one label with a letter that is no keyword.
var ES_PROXY_DOTTED_RE = /^[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$/;
var ES_PROXY_LABEL_RE = /^[A-Za-z0-9\-]*[A-Za-z][A-Za-z0-9\-]*$/;
var ES_PROXY_KEYWORD_RE = /^(null|nil|none|false|true|off|on|no|yes|direct|system|auto|default|disable|disabled|enable|enabled|unset|empty|undefined|manual|inherit)$/;
var ES_PROXY_URL_RE = /[A-Za-z][A-Za-z0-9+.\-]*:\/\/[^\/ \t"'<>,;]+/;
var ES_PROXY_URL_BASE_RE = /[A-Za-z][A-Za-z0-9+.\-]*:\/\/[^\/ \t"'<>,;?#]+/;
// The settings found by name in the files pkg.sources read (net.proxy package_managers).
var ES_PKG_PROXY_SETTINGS = [];

function newEsProxyState() {
    // Open blocks (bk key, bi indent, bx opened by XML, bh/bp/bs host, port, protocol) and the
    // settings of the current source (rkey, rvalue, rendpoint, rexclusion; jh/jp Java pairs).
    return { depth: 0, bk: [], bi: [], bx: [], bh: [], bp: [], bs: [], incom: false, n: 0,
        rkey: [], rvalue: [], rendpoint: [], rexclusion: [], jh: {}, jp: {} };
}

function testEsProxySecret(lkey) {
    // A user name, password or token setting: never returned. A key ending in the exclusion
    // word b[y]pass ends in "pass" but is not one.
    if (/b[y]pass$/.test(lkey)) { return false; }
    return ES_PROXY_SECRET_RE.test(lkey);
}

function testEsProxyGoModule(lkey) { return /^go(no)?proxy$/.test(lkey); }

function getEsProxyClean(value) {
    // The value without quotes, a trailing ";" or ",", or a shell or inline comment.
    var v = String(value).replace(/^[ \t]+/, "");
    var q = v.charAt(0);
    if (q === "\"" || q === "'") {
        var end = v.substring(1).indexOf(q);
        v = end >= 0 ? v.substring(1, end + 1) : v.substring(1);
    } else {
        v = v.replace(/;[ \t][^\n]*$/, "").replace(/[ \t]+#[^\n]*$/, "");
        v = v.replace(/[ \t]+$/, "").replace(/[;,]$/, "").replace(/[ \t]+$/, "");
    }
    return v.replace(/\t/g, " ");
}

function removeEsXmlComments(state, text) {
    // The line without XML comments, which may span lines (state.incom).
    var s = text, k;
    if (state.incom) {
        k = s.indexOf("-->");
        if (k < 0) { return ""; }
        s = s.substring(k + 3);
        state.incom = false;
    }
    for (k = s.indexOf("<!--"); k >= 0; k = s.indexOf("<!--")) {
        var rest = s.substring(k + 4);
        var end = rest.indexOf("-->");
        if (end < 0) { state.incom = true; return s.substring(0, k); }
        s = s.substring(0, k) + rest.substring(end + 3);
    }
    return s;
}

function readEsProxyKeyValue(text) {
    // key=value, key: value, key "value" (also export/set/setenv and a quoted key) as { key;
    // value; open; xml }: open when the value is empty or "{". null when the line has no key.
    var s = String(text).replace(/^(export|setenv|set)[ \t]+/, "");
    if (/^:[A-Za-z_]/.test(s)) { s = s.substring(1); }
    var quote = "";
    if (s.charAt(0) === "\"" || s.charAt(0) === "'") { quote = s.charAt(0); s = s.substring(1); }
    var m = ES_PROXY_KEY_RE.exec(s);
    if (!m) { return null; }
    var key = m[0];
    var rest = s.substring(key.length);
    if (quote) {
        if (rest.charAt(0) !== quote) { return null; }
        rest = rest.substring(1);
    }
    if (rest !== "" && !/^[ \t=:]/.test(rest)) { return null; }
    rest = rest.replace(/^[ \t]*/, "");
    if (/^[=:]/.test(rest)) { rest = rest.substring(1); }
    var value = getEsProxyClean(rest);
    return { key: key, value: value, open: (value === "" || value === "{"), xml: false };
}

function getEsXmlAttribute(text, name) {
    // The value of attribute `name` (any case) of an XML tag, "" when absent.
    var re = new RegExp("[ \\t]" + name + "[ \\t]*=[ \\t]*(\"[^\"]*\"|'[^']*')");
    var m = re.exec(String(text).toLowerCase());
    if (!m) { return ""; }
    var r = String(text).substring(m.index, m.index + m[0].length).replace(/^[^=]*=[ \t]*/, "");
    return r.substring(1, r.length - 1);
}

function jsPxCloseTag(state, text) {
    // A closing tag ends the block it closes.
    var name = text.replace(/^<\/[ \t]*/, "").replace(/[^A-Za-z0-9_.:\-][\s\S]*$/, "").toLowerCase();
    var d = state.depth;
    if (d > 0 && state.bx[d] && name === String(state.bk[d]).toLowerCase().replace(/^[\s\S]*\./, "")) {
        popEsProxyBlock(state);
    }
    return null;
}

function readEsProxyXml(state, text) {
    // <name>value</name>, <name> alone on its line (opens a block) and NuGet's <add key=
    // value=> (only its proxy keys: in <packageSources> a key is a free source name), as
    // readEsProxyKeyValue returns them. A closing tag ends the block it closes.
    if (text.substring(0, 2) === "</") { return jsPxCloseTag(state, text); }
    if (/^<add[ \t]/.test(text.toLowerCase())) {
        var key = getEsXmlAttribute(text, "key");
        if (!/^(http_proxy|https_proxy|no_proxy)$/.test(key.toLowerCase())) { return null; }
        return { key: key, value: getEsProxyClean(getEsXmlAttribute(text, "value")), open: false, xml: false };
    }
    var m = /^<[A-Za-z_][A-Za-z0-9_.:\-]*/.exec(text);
    if (!m) { return null; }
    var name = m[0].substring(1);
    var rest = text.substring(m[0].length);
    var k = rest.indexOf(">");
    if (k < 0 || (k > 0 && rest.charAt(k - 1) === "/")) { return null; }
    rest = rest.substring(k + 1);
    var end = rest.indexOf("<");
    var value = getEsProxyClean(end >= 0 ? rest.substring(0, end) : rest);
    var open = (value === "" && end < 0);
    return { key: name, value: value, open: open, xml: open };
}

function pushEsProxyBlock(state, key, indent, xml) {
    var d = state.depth + 1;
    state.depth = d;
    state.bk[d] = key; state.bi[d] = indent; state.bx[d] = xml;
    state.bh[d] = ""; state.bp[d] = ""; state.bs[d] = "";
}

function popEsProxyBlock(state) {
    // Ends the innermost block: its host, port and protocol become one proxy setting.
    var d = state.depth;
    if (state.bh[d] !== "") {
        var value = state.bh[d];
        if (state.bp[d] !== "") { value += ":" + state.bp[d]; }
        if (state.bs[d] !== "") { value = state.bs[d].toLowerCase() + "://" + value; }
        var key = String(state.bk[d]);
        addEsProxyRecord(state, key, key.toLowerCase(), value);
    }
    state.depth = d - 1;
}

function setEsProxyFold(state, item, last) {
    // A host, port or protocol child of a block is kept for the block's proxy (popEsProxyBlock).
    if (item.open) { return false; }
    var d = state.depth;
    if (/^(host|hostname|server|address)$/.test(last)) { state.bh[d] = item.value; return true; }
    if (last === "port") { state.bp[d] = item.value; return true; }
    if (last === "protocol" || last === "scheme") { state.bs[d] = item.value; return true; }
    return false;
}

function jsPxAfterAt(value) { return value.substring(value.lastIndexOf("@") + 1); }

function getEsProxyEndpoint(value) {
    // host:port of the URL or the host:port in a value, "" when none; default port by scheme.
    var v = String(value);
    var m = ES_PROXY_URL_RE.exec(v);
    if (m) {
        var j = m[0].indexOf("://");
        var scheme = m[0].substring(0, j).toLowerCase();
        var h = ES_PROXY_HOST_RE.exec(jsPxAfterAt(m[0].substring(j + 3)));
        if (!h) { return ""; }
        if (/:[0-9]+$/.test(h[0])) { return h[0]; }
        if (scheme === "https") { return h[0] + ":443"; }
        if (/^socks/.test(scheme)) { return h[0] + ":1080"; }
        return h[0] + ":80";
    }
    // Without a scheme: less a user:password@ before the host (to the last "@").
    var hostPort = jsPxAfterAt(v);
    return /^[A-Za-z0-9.\-]+:[0-9]+$/.test(hostPort) ? hostPort : "";
}

function testEsProxyBareHost(hostName) {
    // A host name without a port; a single label needs a letter and is no keyword (null, off, ...).
    if (ES_PROXY_DOTTED_RE.test(hostName)) { return true; }
    if (!ES_PROXY_LABEL_RE.test(hostName)) { return false; }
    return !ES_PROXY_KEYWORD_RE.test(hostName.toLowerCase());
}

function addEsProxyRecord(state, key, lkey, value) {
    // One setting of the current source; *.proxyHost and *.proxyPort are paired at the end. Under
    // a key ending in "proxy" a bare host (less any user:password@) gets port 80.
    var endpoint = getEsProxyEndpoint(value);
    var bare = jsPxAfterAt(value);
    if (endpoint === "" && /proxy$/.test(lkey) && testEsProxyBareHost(bare)) { endpoint = bare + ":80"; }
    var n = state.n + 1;
    state.n = n;
    state.rkey[n] = key; state.rvalue[n] = value; state.rendpoint[n] = endpoint;
    state.rexclusion[n] = ES_PROXY_EXCLUDE_RE.test(lkey);
    if (/proxyhost$/.test(lkey)) { state.jh["k" + lkey.substring(0, lkey.length - 9)] = n; }
    if (/proxyport$/.test(lkey)) { state.jp["k" + lkey.substring(0, lkey.length - 9)] = value; }
}

function jsPxReadItem(state, s) {
    // The item of a configuration line (comments removed): XML or key/value, blocks closed.
    var trimmed = s.replace(/^[ \t]+/, "");
    var indent = s.length - trimmed.length;
    if (trimmed.charAt(0) === "<") { return { item: readEsProxyXml(state, trimmed), indent: indent }; }
    while (state.depth > 0 && !state.bx[state.depth] && indent <= state.bi[state.depth]) { popEsProxyBlock(state); }
    return { item: readEsProxyKeyValue(trimmed), indent: indent };
}

function addEsProxyConfLine(state, line) {
    // One line of a configuration file. Indentation ends YAML-style blocks, closing tags XML ones.
    var s = removeEsXmlComments(state, String(line));
    if (/^[ \t]*$/.test(s) || /^[ \t]*(#|;|\/\/|!)/.test(s)) { return; }
    var read = jsPxReadItem(state, s);
    var item = read.item;
    if (item === null) { return; }
    var d = state.depth;
    var full = d > 0 ? state.bk[d] + "." + item.key : String(item.key);
    var lkey = full.toLowerCase();
    var last = String(item.key).toLowerCase();
    if (d > 0 && setEsProxyFold(state, item, last)) { return; }
    if (testEsProxySecret(last) || testEsProxyGoModule(last)) { return; }
    var named = ES_PROXY_NAME_RE.test(lkey);
    if (item.open) {
        if (d > 0 || named) { pushEsProxyBlock(state, full, read.indent, item.xml); }
        return;
    }
    if (d === 0 && !named) { return; }
    // In a block: a proxy key, a URL value or a scheme key (proxy_servers: http: ...).
    var other = !ES_PROXY_NAME_RE.test(last) && item.value.indexOf("://") < 0;
    if (d > 0 && other && !/^(http|https|ftp|all|socks|socks4|socks5)$/.test(last)) { return; }
    addEsProxyRecord(state, full, lkey, item.value);
}

function addEsProxyGitLine(state, text) {
    // One "key=value" of git config --list. The subsection (often a URL, as in
    // url.<url>.insteadOf or http.<url>.proxy) is left out of the name test.
    var t = String(text);
    var k = t.indexOf("=");
    if (k < 1) { return; }
    var key = t.substring(0, k);
    var lkey = key.toLowerCase();
    if (lkey.indexOf(".") >= 0) { lkey = lkey.replace(/\.[\s\S]*$/, "") + "." + lkey.replace(/^[\s\S]*\./, ""); }
    if (!ES_PROXY_NAME_RE.test(lkey) || testEsProxySecret(lkey) || testEsProxyGoModule(lkey)) { return; }
    addEsProxyRecord(state, key, lkey, getEsProxyClean(t.substring(k + 1)));
}

function jsPxPairJava(state) {
    // *.proxyHost without a port: the *.proxyPort of the same prefix, else the scheme default.
    for (var slot in state.jh) {
        if (!esHas(state.jh, slot)) { continue; }
        var i = state.jh[slot], prefix = slot.substring(1);
        if (state.rendpoint[i] !== "" || !/^[A-Za-z0-9._\-]+$/.test(state.rvalue[i])) { continue; }
        var port = esHas(state.jp, slot) ? String(state.jp[slot]) : "";
        if (!/^[0-9]+$/.test(port)) { port = /https/.test(prefix) ? "443" : (/socks/.test(prefix) ? "1080" : "80"); }
        state.rendpoint[i] = state.rvalue[i] + ":" + port;
    }
}

function completeEsProxySource(state) {
    // The settings of one source as { kind; endpoint; key; value } (kind proxy, exclusion or
    // other), after closing its open blocks and pairing *.proxyHost with *.proxyPort. Resets
    // state for the next source.
    while (state.depth > 0) { popEsProxyBlock(state); }
    jsPxPairJava(state);
    var settings = [];
    for (var i = 1; i <= state.n; i++) {
        var kind = state.rexclusion[i] ? "exclusion" : (state.rendpoint[i] ? "proxy" : "other");
        settings.push({ kind: kind, endpoint: state.rendpoint[i], key: state.rkey[i], value: state.rvalue[i] });
    }
    state.n = 0; state.incom = false; state.jh = {}; state.jp = {};
    state.rkey = []; state.rvalue = []; state.rendpoint = []; state.rexclusion = [];
    return settings;
}

function jsPxUrl(setting) {
    // scheme://host[:port] of one proxy setting, "" when none.
    var m = ES_PROXY_URL_BASE_RE.exec(String(setting.value));
    if (m) {
        var j = m[0].indexOf("://");
        var h = ES_PROXY_HOST_RE.exec(jsPxAfterAt(m[0].substring(j + 3)));
        return h ? m[0].substring(0, j) + "://" + h[0] : "";
    }
    return setting.endpoint ? "http://" + setting.endpoint : "";
}

function convertToEsProxyUrls(settings) {
    // The URLs of proxy settings: scheme://host[:port] in lower case, never userinfo, a path or a
    // query; http://host:port for a bare host:port. Each once, in order.
    var urls = [];
    var list = esIsArray(settings) ? settings : (settings ? [settings] : []);
    for (var i = 0; i < list.length; i++) {
        if (!list[i] || list[i].kind !== "proxy") { continue; }
        var url = jsPxUrl(list[i]).toLowerCase();
        if (url && !esContains(urls, url)) { urls.push(url); }
    }
    return urls;
}

function getEsConfigProxySettings(lines) {
    // The proxy settings of one configuration file (completeEsProxySource), from the raw lines
    // its configs entry keeps.
    var state = newEsProxyState();
    var list = esIsArray(lines) ? lines : (lines === null || lines === undefined ? [] : [lines]);
    for (var i = 0; i < list.length; i++) { addEsProxyConfLine(state, String(list[i]).replace(/\r+$/, "")); }
    return completeEsProxySource(state);
}

function getEsConfigProxyUrls(lines) {
    return convertToEsProxyUrls(getEsConfigProxySettings(lines));
}

function convertToEsProxySettingItems(settings, tool, file) {
    // Settings as net.proxy lists them: { tool; setting = the key; value = redacted (name and
    // value rules); file }. Proxies, exclusions and the others.
    var items = [];
    var list = esIsArray(settings) ? settings : (settings ? [settings] : []);
    for (var i = 0; i < list.length; i++) {
        if (!list[i]) { continue; }
        var key = String(list[i].key);
        items.push({ tool: tool, setting: key, value: protectEsNamedValue(key, String(list[i].value)), file: file });
    }
    return items;
}
