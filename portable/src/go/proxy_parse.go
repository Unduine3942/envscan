// proxy_parse.go: port of src/sh/awk/proxy.awk: proxy settings in configuration lines, found
// by the name of the setting and never by a substring of the value. Sources "git:..." and
// "env:..." hold key=value lines; any other source is a configuration file (key=value,
// key: value, key "value", export/set/setenv, JSON/TOML keys, XML elements, NuGet <add>, YAML and
// JSON blocks, Maven <proxies>). Host, port and protocol children of a block fold into one
// proxy, as do Java-style *.proxyHost / *.proxyPort pairs. Output per setting (api ProxySetting):
// Endpoint "" where proxy.awk prints "-" (none, or an exclusion), Value "" when empty.
package main

import "strings"

func init() { proxySettings = parseProxySettings }

type proxyBlock struct {
	key                string
	ind                int
	xml                bool
	host, port, scheme string
}

type proxyRecord struct {
	key, value, text, endpoint string
	exclusion                  bool
}

// proxyParser: the state of proxy.awk for the current source
type proxyParser struct {
	cur     string
	blocks  []proxyBlock
	recs    []proxyRecord
	javaH   map[string]int    // *.proxyHost prefix -> record index
	javaP   map[string]string // *.proxyPort prefix -> value
	incom   bool
	out     []ProxySetting
	k, v    string // keyval / xml results (awk K, V)
	open    bool   // the key opens a block (awk OPEN)
	xmlOpen bool   // ... an XML element block (awk XOPEN)
}

func parseProxySettings(in []SourceLine) []ProxySetting {
	p := &proxyParser{out: []ProxySetting{}}
	p.reset()
	for _, l := range in {
		if l.Source != p.cur {
			p.flush()
			p.cur = l.Source
		}
		txt := strings.TrimSuffix(l.Text, "\r")
		if strings.HasPrefix(l.Source, "git:") || strings.HasPrefix(l.Source, "env:") {
			p.plain(txt)
		} else {
			p.conf(txt)
		}
	}
	p.flush()
	return p.out
}

func (p *proxyParser) reset() {
	p.recs, p.incom = nil, false
	p.javaH, p.javaP = map[string]int{}, map[string]string{}
}

// plain: "key=value" from git config or the environment; for git the proxy test ignores the
// subsection, which may be a URL ("url.<url>.insteadOf")
func (p *proxyParser) plain(text string) {
	k := strings.IndexByte(text, '=')
	if k < 1 {
		return
	}
	key, v := text[:k], text[k+1:]
	lk := lowerASCII(key)
	if strings.HasPrefix(p.cur, "git:") && strings.Contains(lk, ".") {
		lk = lk[:strings.IndexByte(lk, '.')] + "." + lk[strings.LastIndexByte(lk, '.')+1:]
	}
	if !isProxyKey(lk) || proxySecret(lk) || goModKey(lk) {
		return
	}
	p.record(key, lk, proxyClean(v), text)
}

// isCommentLine: blank, or #, ;, // or ! after the indent
func isCommentLine(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return t == "" || t[0] == '#' || t[0] == ';' || t[0] == '!' || strings.HasPrefix(t, "//")
}

// conf: one configuration file line
func (p *proxyParser) conf(text string) {
	s := p.uncomment(text)
	if isCommentLine(s) {
		return
	}
	ind := leadingBlank(s)
	s = s[ind:]
	if s[0] == '<' {
		if !p.xml(s) {
			return
		}
	} else {
		for d := len(p.blocks); d > 0 && !p.blocks[d-1].xml && ind <= p.blocks[d-1].ind; d = len(p.blocks) {
			p.pop()
		}
		if !p.keyval(s) {
			return
		}
	}
	p.setting(text, ind)
}

// setting: K and V of a line, in or out of a block
func (p *proxyParser) setting(text string, ind int) {
	full := p.k
	if d := len(p.blocks); d > 0 {
		full = p.blocks[d-1].key + "." + p.k
	}
	lk, last := lowerASCII(full), lowerASCII(p.k)
	depth := len(p.blocks)
	if depth > 0 && p.fold(last) {
		return
	}
	if proxySecret(last) || goModKey(last) {
		return
	}
	if p.open {
		if depth > 0 || isProxyKey(lk) {
			p.blocks = append(p.blocks, proxyBlock{key: full, ind: ind, xml: p.xmlOpen})
		}
		return
	}
	if depth == 0 && !isProxyKey(lk) {
		return
	}
	if depth > 0 && !isProxyKey(last) && !strings.Contains(p.v, "://") && !proxySchemeKeys[last] {
		return
	}
	p.record(full, lk, p.v, text)
}

// uncomment: the text without XML comments (which may span lines)
func (p *proxyParser) uncomment(s string) string {
	if p.incom {
		k := strings.Index(s, "-->")
		if k < 0 {
			return ""
		}
		s, p.incom = s[k+3:], false
	}
	for {
		k := strings.Index(s, "<!--")
		if k < 0 {
			return s
		}
		e := strings.Index(s[k+4:], "-->")
		if e < 0 {
			p.incom = true
			return s[:k]
		}
		s = s[:k] + s[k+4+e+3:]
	}
}

// keyval: K, V and OPEN (the value is empty or "{") of a key=value line; false: no key
func (p *proxyParser) keyval(s string) bool {
	p.open, p.xmlOpen = false, false
	s = stripSetKeyword(s)
	if len(s) > 1 && s[0] == ':' && (isAlpha(s[1]) || s[1] == '_') {
		s = s[1:]
	}
	var q byte
	if isQuote(at(s, 0)) {
		q, s = s[0], s[1:]
	}
	m := keyvalKeyRe.FindStringIndex(s)
	if m == nil {
		return false
	}
	p.k = s[:m[1]]
	r := s[m[1]:]
	if q != 0 {
		if at(r, 0) != q {
			return false
		}
		r = r[1:]
	}
	if c := at(r, 0); r != "" && c != ' ' && c != '\t' && c != '=' && c != ':' {
		return false
	}
	r = strings.TrimLeft(r, " \t")
	if c := at(r, 0); c == '=' || c == ':' {
		r = r[1:]
	}
	p.v = proxyClean(r)
	p.open = p.v == "" || p.v == "{"
	return true
}

// stripSetKeyword: s without a leading export, setenv or set and blanks
func stripSetKeyword(s string) string {
	for _, kw := range []string{"export", "setenv", "set"} {
		if strings.HasPrefix(s, kw) {
			if j := skipBlank(s, len(kw)); j > len(kw) {
				return s[j:]
			}
		}
	}
	return s
}

// xml: K, V, OPEN for <name>value</name>, <name> (opens a block) and <add key= value=>; a
// closing tag ends the block it closes
func (p *proxyParser) xml(s string) bool {
	p.open, p.xmlOpen = false, false
	if strings.HasPrefix(s, "</") {
		p.closeTag(s)
		return false
	}
	if lo := lowerASCII(window(s, 0, 5)); strings.HasPrefix(lo, "<add") && len(lo) == 5 && (lo[4] == ' ' || lo[4] == '\t') {
		p.k, p.v = proxyAttr(s, "key"), proxyClean(proxyAttr(s, "value"))
		switch lowerASCII(p.k) {
		case "http_proxy", "https_proxy", "no_proxy":
			return true
		}
		return false
	}
	m := xmlNameRe.FindStringIndex(s)
	if m == nil {
		return false
	}
	name, r := s[1:m[1]], s[m[1]:]
	k := strings.IndexByte(r, '>')
	if k < 0 || (k > 0 && r[k-1] == '/') {
		return false
	}
	r = r[k+1:]
	e := strings.IndexByte(r, '<')
	p.k = name
	if e >= 0 {
		p.v = proxyClean(r[:e])
	} else {
		p.v = proxyClean(r)
	}
	if p.v == "" && e < 0 {
		p.open, p.xmlOpen = true, true
	}
	return true
}

func isXMLNameByte(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == ':' || c == '-' }

// closeTag: </name> pops the innermost block when it is the XML element of that name
func (p *proxyParser) closeTag(s string) {
	j := skipBlank(s, 2)
	e := j
	for e < len(s) && isXMLNameByte(s[e]) {
		e++
	}
	name := lowerASCII(s[j:e])
	d := len(p.blocks)
	if d == 0 {
		return
	}
	last := lowerASCII(p.blocks[d-1].key)
	last = last[strings.LastIndexByte(last, '.')+1:]
	if p.blocks[d-1].xml && name == last {
		p.pop()
	}
}

// fold: host, port and protocol children of a block are remembered, not output
func (p *proxyParser) fold(last string) bool {
	if p.open {
		return false
	}
	b := &p.blocks[len(p.blocks)-1]
	switch last {
	case "host", "hostname", "server", "address":
		b.host = p.v
	case "port":
		b.port = p.v
	case "protocol", "scheme":
		b.scheme = p.v
	default:
		return false
	}
	return true
}

// pop: end the innermost block; its host, port and protocol become one proxy setting
func (p *proxyParser) pop() {
	b := p.blocks[len(p.blocks)-1]
	p.blocks = p.blocks[:len(p.blocks)-1]
	if b.host == "" {
		return
	}
	v := b.host
	if b.port != "" {
		v += ":" + b.port
	}
	if b.scheme != "" {
		v = lowerASCII(b.scheme) + "://" + v
	}
	p.record(b.key, lowerASCII(b.key), v, b.key+"="+v)
}

// record: buffer one setting of the current source
func (p *proxyParser) record(k, lk, v, text string) {
	ep := proxyEndpoint(v)
	if ep == "" && strings.HasSuffix(lk, "proxy") && bareHost(hostPart(v)) {
		ep = hostPart(v) + ":80"
	}
	p.recs = append(p.recs, proxyRecord{key: k, value: v, text: text, endpoint: ep, exclusion: exclusionRe.MatchString(lk)})
	if strings.HasSuffix(lk, "proxyhost") {
		p.javaH[lk[:len(lk)-9]] = len(p.recs) - 1
	}
	if strings.HasSuffix(lk, "proxyport") {
		p.javaP[lk[:len(lk)-9]] = v
	}
}

// flush: close open blocks, pair *.proxyHost with *.proxyPort, emit the source's settings
func (p *proxyParser) flush() {
	for len(p.blocks) > 0 {
		p.pop()
	}
	for prefix, i := range p.javaH {
		rec := &p.recs[i]
		if rec.endpoint != "" || !javaHostRe.MatchString(rec.value) {
			continue
		}
		rec.endpoint = rec.value + ":" + javaPort(prefix, p.javaP)
	}
	for _, rec := range p.recs {
		kind, ep := "other", rec.endpoint
		switch {
		case rec.exclusion:
			kind, ep = "exclusion", ""
		case ep != "":
			kind = "proxy"
		}
		p.out = append(p.out, ProxySetting{Source: p.cur, Kind: kind, Endpoint: ep, Key: rec.key, Value: rec.value, Text: rec.text})
	}
	p.reset()
}

// javaPort: the *.proxyPort of the same prefix when numeric, else 443 / 1080 / 80 by the prefix
func javaPort(prefix string, ports map[string]string) string {
	if v, ok := ports[prefix]; ok {
		if allDigits(v) {
			return v
		}
	}
	switch {
	case strings.Contains(prefix, "https"):
		return "443"
	case strings.Contains(prefix, "socks"):
		return "1080"
	}
	return "80"
}
