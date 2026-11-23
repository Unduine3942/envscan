// pb_pkg.go: pkg.sources (port of src/sh/24-pkg.sh probe_pkg_sources and its helpers).
//
// The raw proxy settings and the file -> package manager map go to net.proxy through the internal
// fact pkgProxyFact (pc_net_proxy.go; sh $ES_TMP/pkg_proxy.tsv and pkg_tools.tsv): published
// only for an ok or partial run, never given to the report and never written to a file.
package main

import (
	"errors"
	"regexp"
	"strings"
)

func init() {
	registerProbe("pkg.sources", probePkgSources)
}

// pbPkgState collects what pkg.sources finds across the configuration files.
type pbPkgState struct {
	cfgLines []SourceLine // kept raw lines of every file (config_lines.txt)
	tools    [][2]string  // path, tool (config_tools.tsv)
	nf       int
	ids      []string
}

func pbConfigOSOK(os string) bool { return os == "all" || os == "unix" || os == "linux" }

// pbConfigItem is sh es_pkg_config_item: one file of the configs list.
func pbConfigItem(e Env, r *Result, st *pbPkgState, c SpecConfig, p string) *Obj {
	o := NewObj().Set("id", c.ID).Set("tool", c.Tool).Set("path", p).Set("scope", c.Scope).Set("mode", c.Mode)
	limit := c.MaxBytes
	if limit <= 0 {
		limit = 65536
	}
	text, _, err := e.ReadText(p, max(1<<20, 2*limit+2))
	if err != nil && !errors.Is(err, ErrBinary) {
		if isRefusal(err) {
			r.Note("%s", err.Error())
		}
		return nil
	}
	cur := []SourceLine{}
	if err != nil {
		o.Set("lines", []any{Verbatim(pbNoRead)}).Set("truncated", false).Set("line_count", 1)
		r.Partial(p + " not read: UTF-16 or binary content")
	} else {
		ct := pbConfigRead(text, limit, c.Mode, c.Match)
		ls := pbConfigLines(e, ct)
		o.Set("lines", ls).Set("truncated", ct.Truncated).Set("line_count", len(ls))
		for _, i := range ct.Kept {
			cur = append(cur, SourceLine{Source: p, Text: ct.Raw[i]})
		}
	}
	urls := []any{}
	for _, ep := range pbEndpoints(cur) {
		urls = append(urls, ep.URL)
	}
	pu := []any{}
	for _, su := range pbProxyURLs(pbProxies(cur)) {
		pu = append(pu, su[1])
	}
	o.Set("urls", urls).Set("proxy_urls", pu)
	st.cfgLines = append(st.cfgLines, cur...)
	st.tools = append(st.tools, [2]string{p, c.Tool})
	return o
}

// pbPkgConfigs is sh es_pkg_configs: the configs list (files of spec/configs.toml).
func pbPkgConfigs(e Env, r *Result, sk *pbSkips, st *pbPkgState) []any {
	items := []any{}
	for _, c := range spec.Configs {
		if !pbConfigOSOK(c.OS) {
			continue
		}
		seen := []string{}
		for _, pat := range c.Paths {
			for _, f := range pbExpand(e, sk, pat) {
				if !pbIsFile(e, f) || len(pbAppendOnce(seen, f)) == len(seen) {
					continue
				}
				if strings.ContainsAny(f, "\t\n") {
					r.Note("skipped a config file whose name contains a tab or line break")
					continue
				}
				seen = append(seen, f)
				it := pbConfigItem(e, r, st, c, f)
				if it == nil {
					continue
				}
				items = append(items, it)
				st.nf++
				st.ids = pbAppendOnce(st.ids, c.ID)
			}
		}
	}
	return items
}

// pbPkgEnv: the package variables that are set (env object) and their "env:NAME" lines.
func pbPkgEnv(e Env) (*Obj, []SourceLine) {
	o, ls := NewObj(), []SourceLine{}
	for _, v := range spec.PackageEnv {
		val, _ := e.Getenv(v)
		if val == "" {
			continue
		}
		o.Set(v, Named{Name: v, Value: val})
		ls = append(ls, SourceLine{Source: "env:" + v, Text: v + "=" + val})
	}
	return o, ls
}

var pbTLSOff = regexp.MustCompile(`strict-ssl[=:]?false|enablestrictssl:?false|sslverify[=:]?(false|0|no)|` +
	`ssl_verify:?(false|0)|verify-peer(false|0)|verify-host(false|0)|trusted-host|disable-tls[=:]?true|` +
	`secure-http[=:]?false|ssl_verify_mode:?0|wagon\.http\.ssl\.insecure=true|ssl\.insecure=true`)

// pbTLSOffLines: "source: text" for lines that turn TLS verification off.
func pbTLSOffLines(groups ...[]SourceLine) []string {
	out := []string{}
	strip := strings.NewReplacer(" ", "", "\t", "", `"`, "", "'", "")
	for _, g := range groups {
		for _, sl := range g {
			field, _, _ := strings.Cut(sl.Text, "\t")
			if pbTLSOff.MatchString(strip.Replace(strings.ToLower(field))) {
				out = append(out, sl.Source+": "+field)
			}
		}
	}
	return out
}

// pbPkgProxyList is sh es_pkg_proxy_list: {tool, url, source} per proxy URL.
func pbPkgProxyList(settings []ProxySetting, tools [][2]string) []any {
	tool := map[string]string{}
	for _, t := range tools {
		if _, ok := tool[t[0]]; !ok {
			tool[t[0]] = t[1]
		}
	}
	out := []any{}
	for _, su := range pbProxyURLs(settings) {
		t, s := "-", su[0]
		if strings.HasPrefix(s, "git:") {
			t, s = "git", s[4:]
		} else if v, ok := tool[s]; ok {
			t = v
		}
		out = append(out, NewObj().Set("tool", t).Set("url", su[1]).Set("source", s))
	}
	return out
}

func pbEndpointLists(eps []pbEndpoint) ([]any, []string, []string) {
	all, in, pub := []any{}, []string{}, []string{}
	for _, ep := range eps {
		all = append(all, ep.URL)
		if ep.Class == "public" {
			pub = append(pub, ep.URL)
		} else {
			in = append(in, ep.URL)
		}
	}
	return all, in, pub
}

func probePkgSources(e Env, r *Result) {
	sk := &pbSkips{}
	st := &pbPkgState{}
	r.Src("read package-manager and repository config files from spec/configs.toml (redacted)")
	d := r.Data
	d.Set("configs", pbPkgConfigs(e, r, sk, st))
	r.Src("environment package variables")
	envObj, envLines := pbPkgEnv(e)
	d.Set("env", envObj)
	gitItems, gitEntries := pbGitConfig(e, r)
	d.Set("git_config", gitItems)
	gitLines := pbGitLines(gitEntries)
	all, in, pub := pbEndpointLists(pbEndpoints(pbConcat(st.cfgLines, envLines, pbGitURLs(gitEntries))))
	d.Set("endpoints", all).Set("internal_endpoints", pbList(pbLines(in))).Set("public_endpoints", pbList(pbLines(pub)))
	off := pbTLSOffLines(st.cfgLines, envLines, gitLines)
	offList := []any{}
	for i, l := range off {
		if i < 50 {
			offList = append(offList, Line(l))
		}
	}
	d.Set("tls_verification_disabled", offList)
	settings := pbProxies(pbConcat(st.cfgLines, gitLines))
	d.Set("proxy_urls", pbPkgProxyList(settings, st.tools))
	d.Set("config_count", num(itoa(st.nf)))
	sk.note(r)
	pbPkgFacts(r, st, in, pub, off, settings)
}

func pbPkgFacts(r *Result, st *pbPkgState, in, pub, off []string, settings []ProxySetting) {
	r.Fact("endpoints_internal", pbLines(in))
	r.Fact("endpoints_public", pbLines(pub))
	r.Fact("pkg_config_count", itoa(st.nf))
	if len(off) > 5 {
		off = off[:5]
	}
	r.Fact("tls_disabled_cfg", strings.Join(off, "\n"))
	r.Fact("pkg_config_ids", strings.Join(st.ids, ", "))
	toolOf := map[string]string{}
	for _, t := range st.tools {
		if _, ok := toolOf[t[0]]; !ok {
			toolOf[t[0]] = t[1]
		}
	}
	// sh: $ES_TMP/pkg_proxy.tsv and pkg_tools.tsv for net.proxy (owner: probes-c)
	r.Fact(pkgProxyFact, encodePkgProxyHandoff(settings, toolOf))
}

func pbConcat(groups ...[]SourceLine) []SourceLine {
	out := []SourceLine{}
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}
