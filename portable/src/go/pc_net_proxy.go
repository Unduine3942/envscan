// pc_net_proxy.go: net.proxy (port of src/sh/26-net.sh, Linux; owner: probes-c) and the hand-off
// of pkg.sources' raw proxy settings (sh $ES_TMP/pkg_proxy.tsv and pkg_tools.tsv).
package main

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

func init() {
	registerProbe("net.proxy", probeNetProxy)
}

// pkgProxyFact carries what pkg.sources found for net.proxy: the proxy settings of the package
// manager configuration files and of git (raw, unredacted) and the package manager of each
// configuration file (file -> tool). It is a fact, so it reaches net.proxy only from an ok or
// partial pkg.sources run (a timed-out run publishes nothing); the engine never gives it to the
// report (internalFacts).
const pkgProxyFact = "pkg_proxy_handoff"

type pkgProxyHandoff struct {
	Settings []ProxySetting    `json:"settings"`
	ToolOf   map[string]string `json:"tool_of"`
}

// encodePkgProxyHandoff is the fact value pkg.sources publishes (sh: writes $ES_TMP/pkg_proxy.tsv,
// pkg_tools.tsv).
func encodePkgProxyHandoff(settings []ProxySetting, toolOf map[string]string) string {
	if len(settings) == 0 {
		return ""
	}
	b, err := json.Marshal(pkgProxyHandoff{Settings: settings, ToolOf: toolOf})
	if err != nil {
		return ""
	}
	return string(b)
}

// decodePkgProxyHandoff reads the fact (nothing when it is empty or broken).
func decodePkgProxyHandoff(v string) ([]ProxySetting, map[string]string) {
	var h pkgProxyHandoff
	if v == "" || json.Unmarshal([]byte(v), &h) != nil {
		return nil, nil
	}
	return h.Settings, h.ToolOf
}

var (
	hpURL   = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/ \t]+`)
	hpPlain = regexp.MustCompile(`^[A-Za-z0-9.-]+:[0-9]+$`)
	hpKey   = regexp.MustCompile(`^[^=/:]*=[ \t]*`)
	hpPort  = regexp.MustCompile(`:[0-9]+$`)
)

// hostPort is sh es_hostport: "host:port" of a proxy URL or host:port value ("" when none).
func hostPort(text string) string {
	for _, s := range lines(text) {
		s = strings.NewReplacer("\"", "", "'", "").Replace(s)
		s = hpKey.ReplaceAllString(s, "")
		s = strings.TrimSuffix(s, ";")
		if u := hpURL.FindString(s); u != "" {
			sch, hp, _ := strings.Cut(u, "://")
			sch = strings.ToLower(sch)
			if i := strings.LastIndex(hp, "@"); i >= 0 {
				hp = hp[i+1:]
			}
			if !hpPort.MatchString(hp) {
				switch {
				case sch == "https":
					hp += ":443"
				case strings.HasPrefix(sch, "socks"):
					hp += ":1080"
				default:
					hp += ":80"
				}
			}
			return hp
		}
		if hpPlain.MatchString(s) {
			return s
		}
	}
	return ""
}

// proxyState is sh es_hosts / es_any.
type proxyState struct {
	hosts []string
	any   bool
}

func (p *proxyState) found(kind, endpoint string) {
	if kind != "proxy" {
		return
	}
	p.any = true
	if endpoint != "" && endpoint != "-" {
		p.hosts = append(p.hosts, endpoint)
	}
}

func probeNetProxy(e Env, r *Result) {
	r.Src("environment proxy variables")
	st := &proxyState{}
	r.Data.Set("env", proxyEnv(e, st))
	files := []any{}
	for _, s := range proxySettings(systemProxyLines(e, r)) {
		files = append(files, NewObj().Set("file", s.Source).Set("line", Line(s.Text)))
		st.found(s.Kind, s.Endpoint)
	}
	r.Data.Set("system", NewObj().Set("files", files))
	r.Data.Set("package_managers", pkgProxyItems(r, st, e.Fact(pkgProxyFact)))
	r.Data.Set("winhttp", nil).Set("wininet", nil)
	hosts := dedupLines(st.hosts)
	r.Data.Set("proxy_endpoints", strList(hosts)).Set("proxy_configured", st.any)
	r.Fact("proxy", boolText(st.any))
	r.Fact("proxy_hosts", strings.Join(hosts, "\n"))
}

func proxyEnv(e Env, st *proxyState) *Obj {
	o := NewObj()
	for _, name := range spec.ProxyEnv {
		v, _ := e.Getenv(name)
		if v == "" {
			continue
		}
		o.Set(name, Named{Name: name, Value: v})
		if name == "no_proxy" || name == "NO_PROXY" {
			continue
		}
		st.any = true
		if hp := hostPort(v); hp != "" {
			st.hosts = append(st.hosts, hp)
		}
	}
	return o
}

// systemProxyLines: the lines of the system files sh reads for proxy settings.
func systemProxyLines(e Env, r *Result) []SourceLine {
	paths := []string{"/etc/environment", "/etc/apt/apt.conf"}
	if ents, _, err := e.ReadDir("/etc/apt/apt.conf.d", 0); err == nil {
		for _, d := range ents {
			if !strings.HasPrefix(d.Name, ".") {
				paths = append(paths, "/etc/apt/apt.conf.d/"+d.Name)
			}
		}
	}
	paths = append(paths, "/etc/yum.conf", "/etc/dnf/dnf.conf")
	in := []SourceLine{}
	for _, p := range paths {
		if !readable(e, p) {
			continue
		}
		text, ok := readSrc(e, r, p, "read "+p+" (proxy settings)")
		if !ok {
			continue
		}
		for _, l := range lines(text) {
			in = append(in, SourceLine{Source: p, Text: l})
		}
	}
	return in
}

// pkgProxyItems: the proxy settings pkg.sources found, with their package manager.
func pkgProxyItems(r *Result, st *proxyState, handoff string) []any {
	out := []any{}
	settings, toolOf := decodePkgProxyHandoff(handoff)
	if len(settings) == 0 {
		return out
	}
	r.Src("package-manager proxy settings found by pkg.sources")
	for _, s := range settings {
		tl := toolOf[s.Source]
		if strings.HasPrefix(s.Source, "git:") {
			tl = "git"
		}
		if tl == "" {
			tl = path.Base(s.Source)
		}
		v := s.Value
		if v == "-" {
			v = ""
		}
		out = append(out, NewObj().Set("tool", tl).Set("setting", s.Key).
			Set("value", Named{Name: s.Key, Value: v}).Set("file", s.Source))
		st.found(s.Kind, s.Endpoint)
	}
	return out
}
