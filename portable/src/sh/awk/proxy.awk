# proxy.awk: proxy settings in configuration lines, found by the name of the setting and never
# by a substring of the value (a registry URL ".../repository/npm-proxy/" is not a proxy).
#
# Input: "source TAB text" lines. Sources "git:..." and "env:..." hold "key=value" lines (git
# config --list, environment variables); any other source is a configuration file.
# Output, per proxy setting: "source TAB kind TAB endpoint TAB key TAB value TAB text"
#   kind      proxy (an address is set), exclusion (no_proxy and the like) or other
#   endpoint  host:port of the proxy, or "-"
#   value     "-" when empty (read collapses empty tab fields); tabs become spaces
#   text      the line as read (a folded block: key=value)
# Forms: key=value, key: value, key "value" (yarn, apt), export/set/setenv, quoted JSON and
# TOML keys, XML <name>value</name> and NuGet <add key="http_proxy" value="..."/>. A proxy key that opens a
# block (YAML "proxy_servers:", JSON "proxies": {, Maven <proxies> and <proxy>) makes its
# children proxy settings; host, port and protocol children fold into one proxy, as do
# Java-style *.proxyHost and *.proxyPort pairs. User names, passwords and tokens are never
# output. Comment lines and XML comments are skipped. A Ruby symbol key (.gemrc ":http_proxy:")
# counts without its colon. Go's GOPROXY (a module mirror) and GONOPROXY are no proxy settings.
# A value without a scheme may start with user:password@ (pip, wget): the endpoint leaves it
# out. Under a key ending in "proxy" a bare host (also a single label, not a keyword such as
# null, off or direct) gets port 80.
# src/ps/15-proxy.ps1 is a port of this program: keep the two in step (tests/proxy_cases.py).

BEGIN { split("", JH); split("", JP) }
{
    tab = index($0, "\t")
    if (tab == 0) next
    src = substr($0, 1, tab - 1); txt = substr($0, tab + 1)
    sub(/\r$/, "", txt)
    if (src != cur) { flush(); cur = src }
    if (src ~ /^(git|env):/) plain(txt); else conf(txt)
}
END { flush() }

function secret(lk) {
    if (lk ~ /bypass$/) return 0
    return lk ~ /(user|username|login|pass|password|passwd|pwd|token|secret|credential|credentials|auth|authorization)$/
}

# gomod LK: Go's module settings: GOPROXY names a module mirror (a registry, which es_endpoints
# reports), GONOPROXY the modules fetched without it; neither is an HTTP proxy
function gomod(lk) { return lk ~ /^go(no)?proxy$/ }

# plain TEXT: "key=value" from git config or the environment; for git the proxy test ignores
# the subsection, which may be a URL ("url.<url>.insteadOf")
function plain(text,   k, v, lk, sec) {
    k = index(text, "=")
    if (k < 2) return
    v = substr(text, k + 1); k = substr(text, 1, k - 1); lk = tolower(k)
    if (cur ~ /^git:/ && index(lk, ".") > 0) { sec = lk; sub(/\..*$/, "", sec); sub(/^.*\./, "", lk); lk = sec "." lk }
    if (lk !~ /prox(y|ies)/ || secret(lk) || gomod(lk)) return
    record(k, lk, clean(v), text)
}

# conf TEXT: one configuration file line
function conf(text,   s, ind, full, lk, last) {
    s = uncomment(text)
    if (s ~ /^[ \t]*$/ || s ~ /^[ \t]*(#|;|\/\/|!)/) return
    match(s, /^[ \t]*/); ind = RLENGTH
    sub(/^[ \t]+/, "", s)
    if (substr(s, 1, 1) == "<") { if (!xml(s)) return }
    else {
        while (depth > 0 && !BX[depth] && ind <= BI[depth]) pop()
        if (!keyval(s)) return
    }
    full = (depth > 0 ? BK[depth] "." K : K); lk = tolower(full); last = tolower(K)
    if (depth > 0 && fold(last)) return
    if (secret(last) || gomod(last)) return
    if (OPEN) { if (depth > 0 || lk ~ /prox(y|ies)/) push(full, ind); return }
    if (depth == 0 && lk !~ /prox(y|ies)/) return
    if (depth > 0 && last !~ /prox(y|ies)/ && V !~ /:\/\// && last !~ /^(http|https|ftp|all|socks|socks4|socks5)$/) return
    record(full, lk, V, text)
}

# uncomment TEXT: TEXT without XML comments (which may span lines)
function uncomment(s,   k, e, r) {
    if (incom) { k = index(s, "-->"); if (k == 0) return ""; s = substr(s, k + 3); incom = 0 }
    while ((k = index(s, "<!--")) > 0) {
        r = substr(s, k + 4); e = index(r, "-->")
        if (e == 0) { incom = 1; return substr(s, 1, k - 1) }
        s = substr(s, 1, k - 1) substr(r, e + 3)
    }
    return s
}

# keyval S -> K, V, OPEN (the value is empty or "{": the key opens a block); 0 when S has no key
function keyval(s,   q, r) {
    OPEN = 0; XOPEN = 0
    sub(/^(export|setenv|set)[ \t]+/, "", s)
    if (s ~ /^:[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_]/) s = substr(s, 2)
    q = substr(s, 1, 1)
    if (q == "\"" || q == "'") s = substr(s, 2); else q = ""
    if (!match(s, /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_@][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.@-]*(::?[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.@-]+)*/)) return 0
    K = substr(s, 1, RLENGTH); r = substr(s, RLENGTH + 1)
    if (q != "") { if (substr(r, 1, 1) != q) return 0; r = substr(r, 2) }
    if (r != "" && r !~ /^[ \t=:]/) return 0
    sub(/^[ \t]*/, "", r)
    if (r ~ /^[=:]/) r = substr(r, 2)
    V = clean(r)
    OPEN = (V == "" || V == "{")
    return 1
}

# xml S -> K, V, OPEN for <name>value</name>, <name> (opens a block) and <add key= value=>;
# a closing tag ends the block it closes
function xml(s,   name, r, k, e) {
    OPEN = 0; XOPEN = 0
    if (s ~ /^<\//) {
        name = s; sub(/^<\/[ \t]*/, "", name); sub(/[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.:-].*$/, "", name)
        r = (depth > 0) ? tolower(BK[depth]) : ""; sub(/^.*\./, "", r)
        if (depth > 0 && BX[depth] && tolower(name) == r) pop()
        return 0
    }
    # <add key=...>: only NuGet's proxy keys (in <packageSources> a key is a source's free name)
    if (tolower(s) ~ /^<add[ \t]/) { K = attr(s, "key"); V = clean(attr(s, "value")); return tolower(K) ~ /^(http_proxy|https_proxy|no_proxy)$/ }
    if (!match(s, /^<[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9_.:-]*/)) return 0
    name = substr(s, 2, RLENGTH - 1); r = substr(s, RLENGTH + 1)
    k = index(r, ">")
    if (k == 0 || (k > 1 && substr(r, k - 1, 1) == "/")) return 0
    r = substr(r, k + 1); e = index(r, "<")
    K = name; V = clean(e > 0 ? substr(r, 1, e - 1) : r)
    if (V == "" && e == 0) { OPEN = 1; XOPEN = 1 }
    return 1
}

# attr S NAME: the value of attribute NAME (any case) in the XML tag S, "" when absent
function attr(s, a,   r) {
    if (!match(tolower(s), "[ \t]" a "[ \t]*=[ \t]*(\"[^\"]*\"|'[^']*')")) return ""
    r = substr(s, RSTART, RLENGTH); sub(/^[^=]*=[ \t]*/, "", r)
    return substr(r, 2, length(r) - 2)
}

# clean V: the value without quotes, a trailing ";" or ",", or a shell or inline comment
function clean(v,   q, e) {
    sub(/^[ \t]+/, "", v)
    q = substr(v, 1, 1)
    if (q == "\"" || q == "'") {
        e = index(substr(v, 2), q)
        v = (e > 0) ? substr(v, 2, e - 1) : substr(v, 2)
    } else {
        sub(/;[ \t].*$/, "", v); sub(/[ \t]+#.*$/, "", v)
        sub(/[ \t]+$/, "", v); sub(/[;,]$/, "", v); sub(/[ \t]+$/, "", v)
    }
    gsub(/\t/, " ", v)
    return v
}

# fold LAST: host, port and protocol children of a block are remembered, not output
function fold(last) {
    if (OPEN) return 0
    if (last ~ /^(host|hostname|server|address)$/) { BH[depth] = V; return 1 }
    if (last == "port") { BP[depth] = V; return 1 }
    if (last == "protocol" || last == "scheme") { BS[depth] = V; return 1 }
    return 0
}

function push(full, ind) {
    depth++; BK[depth] = full; BI[depth] = ind; BX[depth] = XOPEN
    BH[depth] = ""; BP[depth] = ""; BS[depth] = ""
}

# pop: end the innermost block; its host, port and protocol become one proxy setting
function pop(   v) {
    if (BH[depth] != "") {
        v = BH[depth] (BP[depth] != "" ? ":" BP[depth] : "")
        if (BS[depth] != "") v = tolower(BS[depth]) "://" v
        record(BK[depth], tolower(BK[depth]), v, BK[depth] "=" v)
    }
    depth--
}

# hostpart V: a value without a scheme, less a user:password@ before its host (to the last "@")
function hostpart(v,   j) {
    for (j = length(v); j > 0; j--) if (substr(v, j, 1) == "@") return substr(v, j + 1)
    return v
}

# barehost H: a host name without a port (one or more labels, or an IPv4 address); a single
# label needs a letter and is no keyword such as null, false, off or direct
function barehost(h) {
    if (h ~ /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9-]+(\.[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9-]+)+$/) return 1
    if (h !~ /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9-]*[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9-]*$/) return 0
    return tolower(h) !~ /^(null|nil|none|false|true|off|on|no|yes|direct|system|auto|default|disable|disabled|enable|enabled|unset|empty|undefined|manual|inherit)$/
}

# endpoint V: host:port of the URL or host:port in V ("" when none); default ports by scheme
function endpoint(v,   u, sch, hp, j) {
    if (match(v, /[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9+.-]*:\/\/[^\/ \t"'<>,;]+/)) {
        u = substr(v, RSTART, RLENGTH); j = index(u, "://")
        sch = tolower(substr(u, 1, j - 1)); hp = substr(u, j + 3)
        for (j = length(hp); j > 0; j--) if (substr(hp, j, 1) == "@") { hp = substr(hp, j + 1); break }
        if (!match(hp, /^(\[[0-9A-Fa-f:.%]+]|[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9._-]+)(:[0-9]+)?/)) return ""
        hp = substr(hp, 1, RLENGTH)
        if (hp !~ /:[0-9]+$/) hp = hp ":" (sch == "https" ? 443 : (sch ~ /^socks/ ? 1080 : 80))
        return hp
    }
    v = hostpart(v)
    if (v ~ /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9.-]+:[0-9]+$/) return v
    return ""
}

# record KEY LKEY VALUE TEXT: buffer one setting of the current source
function record(k, lk, v, text,   ep, p) {
    ep = endpoint(v)
    if (ep == "" && lk ~ /proxy$/ && barehost(hostpart(v))) ep = hostpart(v) ":80"
    n++; OK[n] = k; OV[n] = v; OT[n] = text; OE[n] = ep
    if (lk ~ /proxyhost$/) { p = substr(lk, 1, length(lk) - 9); JH[p] = n }
    if (lk ~ /proxyport$/) { p = substr(lk, 1, length(lk) - 9); JP[p] = v }
    OD[n] = (lk ~ /no[_-]?prox(y|ies)|non[_-]?prox(y|ies)|bypass|exclu/) ? "exclusion" : ""
}

# flush: close open blocks, pair *.proxyHost with *.proxyPort, print the source's settings
function flush(   p, i, kind) {
    while (depth > 0) pop()
    for (p in JH) {
        i = JH[p]
        if (OE[i] != "" || OV[i] !~ /^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0-9._-]+$/) continue
        OE[i] = OV[i] ":" ((p in JP) && JP[p] ~ /^[0-9]+$/ ? JP[p] : (p ~ /https/ ? 443 : (p ~ /socks/ ? 1080 : 80)))
    }
    for (i = 1; i <= n; i++) {
        kind = (OD[i] != "") ? OD[i] : (OE[i] != "" ? "proxy" : "other")
        print cur "\t" kind "\t" (OE[i] == "" || kind == "exclusion" ? "-" : OE[i]) "\t" OK[i] "\t" (OV[i] == "" ? "-" : OV[i]) "\t" OT[i]
    }
    n = 0; incom = 0; split("", JH); split("", JP)
}
