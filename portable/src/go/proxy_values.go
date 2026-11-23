// proxy_values.go: the value helpers of src/sh/awk/proxy.awk (secret, gomod, clean, hostpart,
// barehost, endpoint, attr) and the key tests.
package main

import (
	"regexp"
	"strings"
)

var (
	proxyWordRe   = regexp.MustCompile(`prox(y|ies)`)
	exclusionRe   = regexp.MustCompile(`no[_-]?prox(y|ies)|non[_-]?prox(y|ies)|bypass|exclu`)
	keyvalKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_@][A-Za-z0-9_.@-]*(::?[A-Za-z0-9_.@-]+)*`)
	xmlNameRe     = regexp.MustCompile(`^<[A-Za-z_][A-Za-z0-9_.:-]*`)
	endpointURLRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/ \t"'<>,;]+`)
	endpointHPRe  = regexp.MustCompile(`^(\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?`)
	hostPortRe    = regexp.MustCompile(`^[A-Za-z0-9.-]+:[0-9]+$`)
	digitsEndRe   = regexp.MustCompile(`:[0-9]+$`)
	multiLabelRe  = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	oneLabelRe    = regexp.MustCompile(`^[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*$`)
	javaHostRe    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	attrRes       = map[string]*regexp.Regexp{}
)

var proxySecretSuffixes = []string{
	"user", "username", "login", "pass", "password", "passwd", "pwd", "token", "secret",
	"credential", "credentials", "auth", "authorization",
}

var proxyKeywords = wordSet([]string{
	"null", "nil", "none", "false", "true", "off", "on", "no", "yes", "direct", "system", "auto",
	"default", "disable", "disabled", "enable", "enabled", "unset", "empty", "undefined", "manual",
	"inherit",
})

var proxySchemeKeys = wordSet([]string{"http", "https", "ftp", "all", "socks", "socks4", "socks5"})

func init() {
	for _, re := range []*regexp.Regexp{keyvalKeyRe, xmlNameRe, endpointURLRe, endpointHPRe} {
		re.Longest()
	}
	for _, a := range []string{"key", "value"} {
		re := regexp.MustCompile(`[ \t]` + a + `[ \t]*=[ \t]*("[^"]*"|'[^']*')`)
		re.Longest()
		attrRes[a] = re
	}
}

// proxySecret: a user name, password or token setting (never output)
func proxySecret(lk string) bool {
	if strings.HasSuffix(lk, "bypass") {
		return false
	}
	for _, s := range proxySecretSuffixes {
		if strings.HasSuffix(lk, s) {
			return true
		}
	}
	return false
}

// goModKey: GOPROXY (a module mirror) and GONOPROXY are no HTTP proxy settings
func goModKey(lk string) bool { return lk == "goproxy" || lk == "gonoproxy" }

func isProxyKey(lk string) bool { return proxyWordRe.MatchString(lk) }

// proxyClean: the value without quotes, a trailing ";" or ",", or a shell or inline comment;
// tabs become spaces
func proxyClean(v string) string {
	v = strings.TrimLeft(v, " \t")
	if q := at(v, 0); isQuote(q) {
		if e := strings.IndexByte(v[1:], q); e >= 0 {
			v = v[1 : 1+e]
		} else {
			v = v[1:]
		}
	} else {
		v = cutSemicolonBlank(v)
		v = cutBlankHash(v)
		v = strings.TrimRight(v, " \t")
		if n := len(v); n > 0 && (v[n-1] == ';' || v[n-1] == ',') {
			v = v[:n-1]
		}
		v = strings.TrimRight(v, " \t")
	}
	return strings.ReplaceAll(v, "\t", " ")
}

// cutSemicolonBlank: v before the first ";" followed by a blank
func cutSemicolonBlank(v string) string {
	for i := 0; i+1 < len(v); i++ {
		if v[i] == ';' && (v[i+1] == ' ' || v[i+1] == '\t') {
			return v[:i]
		}
	}
	return v
}

// cutBlankHash: v before the first run of blanks followed by "#"
func cutBlankHash(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] != ' ' && v[i] != '\t' {
			continue
		}
		j := skipBlank(v, i)
		if at(v, j) == '#' && j < len(v) {
			return v[:i]
		}
		i = j - 1
	}
	return v
}

// proxyAttr: the value of attribute a (key or value, any case) in the XML tag s, "" when absent
func proxyAttr(s, a string) string {
	m := attrRes[a].FindStringIndex(lowerASCII(s))
	if m == nil {
		return ""
	}
	r := s[m[0]:m[1]]
	r = strings.TrimLeft(r[strings.IndexByte(r, '=')+1:], " \t")
	return r[1 : len(r)-1]
}

// hostPart: a value without a scheme, less a user:password@ before its host (to the last "@")
func hostPart(v string) string {
	if k := strings.LastIndexByte(v, '@'); k >= 0 {
		return v[k+1:]
	}
	return v
}

// bareHost: a host name without a port (labels or an IPv4 address); a single label needs a
// letter and is no keyword such as null, off or direct
func bareHost(h string) bool {
	if multiLabelRe.MatchString(h) {
		return true
	}
	return oneLabelRe.MatchString(h) && !proxyKeywords[lowerASCII(h)]
}

// proxyEndpoint: host:port of the URL or host:port in v ("" when none); default ports by scheme
func proxyEndpoint(v string) string {
	if u := endpointURLRe.FindString(v); u != "" {
		j := strings.Index(u, "://")
		sch, hp := lowerASCII(u[:j]), hostPart(u[j+3:])
		hp = endpointHPRe.FindString(hp)
		if hp == "" {
			return ""
		}
		if !digitsEndRe.MatchString(hp) {
			hp += ":" + urlDefaultPort(sch)
		}
		return hp
	}
	if v = hostPart(v); hostPortRe.MatchString(v) {
		return v
	}
	return ""
}

// urlDefaultPort: the port of a proxy URL without one, by its scheme
func urlDefaultPort(sch string) string {
	switch {
	case sch == "https":
		return "443"
	case strings.HasPrefix(sch, "socks"):
		return "1080"
	}
	return "80"
}
