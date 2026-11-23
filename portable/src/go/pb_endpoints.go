// pb_endpoints.go: endpoint, proxy-URL and configuration-line helpers of pkg.sources (ports of
// es_endpoints, es_proxy_urls and es_config_raw in src/sh/24-pkg.sh, and the F event /
// config_lines of src/sh/awk/json.awk).
package main

import (
	"regexp"
	"strings"
)

// pbEndpoint is one "class TAB scheme://host[:port]" line of es_endpoints.
type pbEndpoint struct{ Class, URL string }

var (
	pbEpComment  = regexp.MustCompile(`^[ \t]*(#|;|//|!)`)
	pbEpSchemaLc = regexp.MustCompile(`[a-z0-9_.:-]*schemalocation[ \t]*=[ \t]*"[^"]*"`)
	pbEpXmlns    = regexp.MustCompile(`xmlns(:[a-z0-9_.-]+)?[ \t]*=[ \t]*"[^"]*"`)
	pbEpURL      = pbLongest(`(https?|ftps?|sftp|ssh|git|git\+ssh|svn|svn\+ssh|socks[45]?h?|rsync|s3|gs|oci|ldaps?|wss?)://[^/ \t"'<>,;)]+`)
	pbEpHost6    = pbLongest(`^\[[0-9a-f:.%]+\](:[0-9]+)?`)
	pbEpHost     = pbLongest(`^[a-z0-9._~%-]+(:[0-9]+)?`)
	pbEpPort     = regexp.MustCompile(`:[0-9]*$`)
	pbEpPriv172  = regexp.MustCompile(`^172\.(1[6-9]|2[0-9]|3[01])\.`)
	pbEpIntSuf   = regexp.MustCompile(`\.(local|corp|internal|intranet|lan|home\.arpa|localdomain)$`)
	pbEpPomPath  = regexp.MustCompile(`^/(pom|xsd|settings|maven-v)`)
	pbEpPreWord  = regexp.MustCompile(`[a-z0-9.-]`)
	pbProxyURL   = pbLongest(`[A-Za-z][A-Za-z0-9+.-]*://[^/ \t"'<>,;?#]+`)
	pbProxyHost  = pbLongest(`^(\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?`)
)

// pbLongest compiles a POSIX-style (leftmost-longest) expression, as awk match() works.
func pbLongest(expr string) *regexp.Regexp {
	re := regexp.MustCompile(expr)
	re.Longest()
	return re
}

// pbDropped: loopback hosts and the net_never hosts are no endpoints.
func pbDropped(h string) bool {
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasPrefix(h, "127.") || h == "::1" {
		return true
	}
	for _, n := range spec.NetNever {
		n = strings.ToLower(n)
		if strings.HasSuffix(n, ".") || strings.HasSuffix(n, ":") {
			if strings.HasPrefix(h, n) {
				return true
			}
		} else if h == n {
			return true
		}
	}
	return false
}

func pbEndpointClass(h string) string {
	if strings.HasPrefix(h, "10.") || strings.HasPrefix(h, "192.168.") || pbEpPriv172.MatchString(h) ||
		!strings.Contains(h, ".") || pbEpIntSuf.MatchString(h) {
		return "internal"
	}
	for _, p := range spec.PublicHosts {
		if p != "" && (h == p || strings.HasSuffix(h, "."+p)) {
			return "public"
		}
	}
	return "custom"
}

// pbStripXMLComments removes <!-- ... --> spans; incom carries an open comment to the next line.
func pbStripXMLComments(lc string, incom *bool) (string, bool) {
	if *incom {
		k := strings.Index(lc, "-->")
		if k < 0 {
			return "", false
		}
		lc, *incom = lc[k+3:], false
	}
	for {
		k := strings.Index(lc, "<!--")
		if k < 0 {
			return lc, true
		}
		rest := lc[k+4:]
		e := strings.Index(rest, "-->")
		if e < 0 {
			*incom = true
			return lc[:k], true
		}
		lc = lc[:k] + " " + rest[e+3:]
	}
}

// pbEndpointOf parses one URL match; ok=false when it is no endpoint.
func pbEndpointOf(u, pre, pth string) (pbEndpoint, bool) {
	if pre != "" && pbEpPreWord.MatchString(pre) {
		return pbEndpoint{}, false
	}
	k := strings.Index(u, "://")
	sch, hp := u[:k], u[k+3:]
	if at := strings.LastIndex(hp, "@"); at >= 0 {
		hp = hp[at+1:]
	}
	m := pbEpHost6.FindString(hp)
	if m == "" {
		m = pbEpHost.FindString(hp)
	}
	if m == "" {
		return pbEndpoint{}, false
	}
	hp = m
	h := pbEpPort.ReplaceAllString(hp, "")
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	h = strings.TrimSuffix(h, ".")
	if h == "" || h == "w3.org" || strings.HasSuffix(h, ".w3.org") || pbDropped(h) {
		return pbEndpoint{}, false
	}
	if h == "maven.apache.org" && pbEpPomPath.MatchString(pth) {
		return pbEndpoint{}, false
	}
	return pbEndpoint{Class: pbEndpointClass(h), URL: sch + "://" + hp}, true
}

// pbEndpoints is sh es_endpoints over "source TAB text" lines (in order, de-duplicated).
func pbEndpoints(in []SourceLine) []pbEndpoint {
	out, seen := []pbEndpoint{}, map[string]bool{}
	prev, incom := "\x00", false
	for _, sl := range in {
		if sl.Source != prev {
			incom, prev = false, sl.Source
		}
		lc, ok := pbStripXMLComments(strings.ToLower(sl.Text), &incom)
		if !ok || pbEpComment.MatchString(lc) {
			continue
		}
		lc = pbEpSchemaLc.ReplaceAllString(lc, " ")
		lc = pbEpXmlns.ReplaceAllString(lc, " ")
		for {
			loc := pbEpURL.FindStringIndex(lc)
			if loc == nil {
				break
			}
			pre := ""
			if loc[0] > 0 {
				pre = lc[loc[0]-1 : loc[0]]
			}
			u := lc[loc[0]:loc[1]]
			lc = lc[loc[1]:]
			pth := lc
			if i := strings.IndexAny(pth, " \t\"'<>,;)"); i >= 0 {
				pth = pth[:i]
			}
			if ep, ok := pbEndpointOf(u, pre, pth); ok && !seen[ep.URL] {
				seen[ep.URL] = true
				out = append(out, ep)
			}
		}
	}
	return out
}

// pbProxyURL is the URL of one proxy setting for es_proxy_urls ("" when none).
func pbProxyURLOf(ps ProxySetting) string {
	v := ps.Value
	if v == "-" {
		v = ""
	}
	if u := pbProxyURL.FindString(v); u != "" {
		k := strings.Index(u, "://")
		sch, hp := u[:k], u[k+3:]
		if at := strings.LastIndex(hp, "@"); at >= 0 {
			hp = hp[at+1:]
		}
		if m := pbProxyHost.FindString(hp); m != "" {
			return strings.ToLower(sch + "://" + m)
		}
		return ""
	}
	if ps.Endpoint != "" && ps.Endpoint != "-" {
		return strings.ToLower("http://" + ps.Endpoint)
	}
	return ""
}

// pbProxyURLs is sh es_proxy_urls: [source, url] for each proxy setting, de-duplicated.
func pbProxyURLs(settings []ProxySetting) [][2]string {
	out, seen := [][2]string{}, map[string]bool{}
	for _, ps := range settings {
		if ps.Kind != "proxy" {
			continue
		}
		u := pbProxyURLOf(ps)
		if u == "" || seen[ps.Source+"\t"+u] {
			continue
		}
		seen[ps.Source+"\t"+u] = true
		out = append(out, [2]string{ps.Source, u})
	}
	return out
}

// pbProxies calls the proxy parser (owner: redact) when there is anything to parse.
func pbProxies(in []SourceLine) []ProxySetting {
	if len(in) == 0 {
		return nil
	}
	return proxySettings(in)
}

// pbConfigText is the result of reading one configuration file the way the F event does.
type pbConfigText struct {
	Raw       []string // the lines read (CR removed) up to the byte cap
	Kept      []int    // indexes of Raw that are kept (not blank, not comments / matching)
	Truncated bool
}

// pbConfigRead applies config_lines' cap and filter to TEXT: the cap counts the line lengths
// plus the line breaks between them; mode "lines" keeps the lines holding a match word (case
// insensitive), other modes the lines that are not blank or comments.
func pbConfigRead(text string, max int, mode string, match []string) pbConfigText {
	if max <= 0 {
		max = 65536
	}
	ct, total := pbConfigText{}, 0
	for _, l := range lines(text) {
		add := len(l)
		if len(ct.Raw) > 0 {
			add++
		}
		if total+add > max {
			ct.Truncated = true
			break
		}
		total += add
		ct.Raw = append(ct.Raw, l)
	}
	for i, l := range ct.Raw {
		if pbConfigKeep(l, mode, match) {
			ct.Kept = append(ct.Kept, i)
		}
	}
	return ct
}

func pbConfigKeep(l, mode string, match []string) bool {
	t := strings.TrimLeft(l, " \t")
	if t == "" {
		return false
	}
	if mode != "lines" {
		return t[0] != '#' && t[0] != ';'
	}
	lc := strings.ToLower(l)
	for _, m := range match {
		if m != "" && strings.Contains(lc, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// pbPrivateKeyMarker: spec/redaction.toml private_key_marker (default "PRIVATE KEY").
func pbPrivateKeyMarker() string {
	if m, ok := spec.Redaction["private_key_marker"].(string); ok && m != "" {
		return m
	}
	return "PRIVATE KEY"
}

const pbPKText = "<redacted: private key>"

// pbConfigLines is the "lines" array of the F event. The text rules run over the whole file
// (a value can span lines: YAML blocks, TOML multi-line strings, XML elements), so the probe
// redacts the read text in one redactText call and keeps the redacted form of each kept line
// (Verbatim: already redacted, like the x events of json.awk). A private key anywhere replaces
// the whole content. With --no-redact the raw lines are kept.
func pbConfigLines(e Env, ct pbConfigText) []any {
	out := []any{}
	if !e.Redact() {
		for _, i := range ct.Kept {
			out = append(out, Verbatim(ct.Raw[i]))
		}
		return out
	}
	joined := strings.Join(ct.Raw, "\n")
	if strings.Contains(joined, pbPrivateKeyMarker()) {
		return append(out, Verbatim(pbPKText))
	}
	red := strings.Split(redactText(joined), "\n")
	for _, i := range ct.Kept {
		if len(red) == len(ct.Raw) {
			out = append(out, Verbatim(red[i]))
		} else {
			out = append(out, Verbatim(redactText(ct.Raw[i]))) // the rules changed the line count
		}
	}
	return out
}

const pbNoRead = "[UTF-16 or binary content not read]"
