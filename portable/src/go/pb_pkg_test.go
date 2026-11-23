package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func pbConfigs(ids ...SpecConfig) func(d *SpecDoc) { return func(d *SpecDoc) { d.Configs = ids } }

var (
	pbNpmrc = SpecConfig{ID: "npmrc.user", Tool: "npm", OS: "all", Scope: "user", Mode: "content", MaxBytes: 16384,
		Paths: []string{"~/.npmrc", "{env:NPM_CONFIG_USERCONFIG}"}}
	pbPip = SpecConfig{ID: "pip.user", Tool: "pip", OS: "all", Scope: "user", Mode: "content", MaxBytes: 16384,
		Paths: []string{"~/.config/pip/pip.conf", "~/.p*/pip.conf"}}
)

func TestPkgSourcesURLsAndProxyURLsPerFile(t *testing.T) {
	e := pbNewEnv(t)
	pbSwapSpec(t, pbConfigs(pbNpmrc, pbPip, SpecConfig{ID: "mac", OS: "darwin", Paths: []string{"~/.npmrc"}}))
	pbWrite(t, e.Root, map[string]string{
		"/home/u/.npmrc": "registry=https://nexus.corp/repository/npm-proxy/\n" +
			"proxy=http://alice:S3cretPw9@proxy.corp.example:8080\nhttps-proxy=proxy.corp.example:8443\n" +
			"//nexus.corp/repository/npm-proxy/:_authToken=npm_tok_secret\n# strict-ssl=false\nstrict-ssl=false\n",
		"/home/u/.config/pip/pip.conf": "[global]\nindex-url = https://pypi.corp.example/simple\n",
	})
	e.PathBins["git"] = "/usr/bin/git"
	e.Cmds["git config --list --show-origin --no-includes"] = fakeCmd{Stdout: "file:/home/u/.gitconfig\thttp.proxy=http://bob:GitPw9@gitproxy.corp:3128\n" +
		"file:/home/u/.gitconfig\turl.https://git.corp.example/.insteadof=https://github.com/\n"}
	e.Vars["PIP_INDEX_URL"] = "https://pypi.org/simple"
	r := pbRun(e, "pkg.sources")
	d := r.Data
	pbKeys(t, d, "configs", "env", "git_config", "endpoints", "internal_endpoints", "public_endpoints",
		"tls_verification_disabled", "proxy_urls", "config_count")
	cfgs := map[string]*Obj{}
	for _, c := range d.vals["configs"].([]any) {
		cfgs[c.(*Obj).Str("id")] = c.(*Obj)
	}
	npm := cfgs["npmrc.user"]
	pbKeys(t, npm, "id", "tool", "path", "scope", "mode", "lines", "truncated", "line_count", "urls", "proxy_urls")
	pbEq(t, "npm urls", pbStrs(npm.vals["urls"]), []string{"https://nexus.corp", "http://proxy.corp.example:8080"})
	pbEq(t, "npm proxy", pbStrs(npm.vals["proxy_urls"]), []string{"http://proxy.corp.example:8080", "http://proxy.corp.example:8443"})
	pbEq(t, "pip", [2][]string{pbStrs(cfgs["pip.user"].vals["urls"]), pbStrs(cfgs["pip.user"].vals["proxy_urls"])},
		[2][]string{{"https://pypi.corp.example"}, {}})
	ls := pbStrs(npm.vals["lines"])
	pbEq(t, "line_count", npm.vals["line_count"], 5)
	pbEq(t, "redacted line", ls[3], "//nexus.corp/repository/npm-proxy/:_authToken=<redacted>")
	proxies := [][3]string{}
	for _, p := range d.vals["proxy_urls"].([]any) {
		o := p.(*Obj)
		proxies = append(proxies, [3]string{o.Str("tool"), o.Str("url"), o.Str("source")})
	}
	pbEq(t, "proxy list", proxies, [][3]string{{"npm", "http://proxy.corp.example:8080", "/home/u/.npmrc"},
		{"npm", "http://proxy.corp.example:8443", "/home/u/.npmrc"}, {"git", "http://gitproxy.corp:3128", "file:/home/u/.gitconfig"}})
	internal := pbStrs(d.vals["internal_endpoints"])
	if !strings.Contains(strings.Join(internal, " "), "https://git.corp.example") {
		t.Errorf("internal %v", internal)
	}
	pbEq(t, "public", pbStrs(d.vals["public_endpoints"]), []string{"https://pypi.org", "https://github.com"})
	pbEq(t, "tls off", d.vals["tls_verification_disabled"], []any{Line("/home/u/.npmrc: strict-ssl=false")})
	pbEq(t, "env", pbGet(t, d, "env", "PIP_INDEX_URL"), Named{Name: "PIP_INDEX_URL", Value: "https://pypi.org/simple"})
	urls, _ := json.Marshal([]any{pbStrs(npm.vals["urls"]), proxies})
	for _, s := range []string{"S3cretPw9", "GitPw9", "npm_tok_secret", "alice", "npm-proxy"} {
		if strings.Contains(string(urls), s) {
			t.Errorf("%s in %s", s, urls)
		}
	}
	pbEq(t, "count", d.vals["config_count"], NumText("2"))
	pbEq(t, "ids", r.Facts["pkg_config_ids"], "npmrc.user, pip.user")
	pbEq(t, "tls fact", r.Facts["tls_disabled_cfg"], "/home/u/.npmrc: strict-ssl=false")
	settings, toolOf := decodePkgProxyHandoff(r.Facts[pkgProxyFact])
	pbEq(t, "handoff tools", toolOf, map[string]string{"/home/u/.npmrc": "npm", "/home/u/.config/pip/pip.conf": "pip"})
	pbEq(t, "handoff settings", len(settings), 3)
}

func TestPkgSourcesConfigLineRules(t *testing.T) {
	e := pbNewEnv(t)
	bundler := SpecConfig{ID: "bundler", Tool: "bundler", OS: "all", Mode: "lines", MaxBytes: 70,
		Match: []string{"BUNDLE_MIRROR__HTTPS://"}, Paths: []string{"~/.bundle/config"}}
	keyed := SpecConfig{ID: "keyed", Tool: "x", OS: "linux", Mode: "content", MaxBytes: 100, Paths: []string{"/etc/keyed.conf"}}
	bin := SpecConfig{ID: "bin", Tool: "x", OS: "unix", Mode: "content", Paths: []string{"/etc/bin.conf"}}
	creds := SpecConfig{ID: "creds", Tool: "x", OS: "all", Mode: "content", Paths: []string{"~/.docker/config.json"}}
	pbSwapSpec(t, pbConfigs(bundler, keyed, bin, creds))
	pbWrite(t, e.Root, map[string]string{
		"/home/u/.bundle/config":      "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://gems.corp\"\nBUNDLE_PATH: \"vendor\"\n",
		"/etc/keyed.conf":             "a=1\n-----BEGIN RSA PRIVATE KEY-----\nMIIx\n",
		"/etc/bin.conf":               "a\x00b",
		"/home/u/.docker/config.json": "{\"auths\":{\"x\":{\"auth\":\"c2VjcmV0\"}}}",
	})
	e.RefusedP["/home/u/.docker/config.json"] = "credential store"
	r := pbRun(e, "pkg.sources")
	cfgs := map[string]*Obj{}
	for _, c := range r.Data.vals["configs"].([]any) {
		cfgs[c.(*Obj).Str("id")] = c.(*Obj)
	}
	b := cfgs["bundler"]
	pbEq(t, "bundler lines", pbStrs(b.vals["lines"]), []string{`BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "https://gems.corp"`})
	pbEq(t, "bundler truncated", b.vals["truncated"], true)
	pbEq(t, "pk", cfgs["keyed"].vals["lines"], []any{Verbatim(pbPKText)})
	pbEq(t, "binary", cfgs["bin"].vals["lines"], []any{Verbatim(pbNoRead)})
	if _, ok := cfgs["creds"]; ok {
		t.Error("a credential store was read")
	}
	pbEq(t, "status", r.Status, StPartial)
	if !pbHasNote(r, "/etc/bin.conf not read: UTF-16 or binary content") {
		t.Errorf("notes %v", r.Notes)
	}

	e.NoRedact = true
	r = pbRun(e, "pkg.sources")
	for _, c := range r.Data.vals["configs"].([]any) {
		if c.(*Obj).Str("id") == "keyed" {
			pbEq(t, "no-redact", pbStrs(c.(*Obj).vals["lines"])[1], "-----BEGIN RSA PRIVATE KEY-----")
		}
	}
}

func TestPkgSourcesNetworkConfigNotRead(t *testing.T) {
	e := pbNewEnv(t)
	pbSwapSpec(t, pbConfigs(pbNpmrc, pbPip))
	e.NetPaths = []string{"/home/u"}
	pbWrite(t, e.Root, map[string]string{"/home/u/.npmrc": "registry=https://net-mount.example/\n"})
	r := pbRun(e, "pkg.sources")
	if strings.Contains(pbJSONish(r.Data), "net-mount.example") || !pbHasNote(r, "network or autofs") {
		t.Errorf("notes %v", r.Notes)
	}
	pbEq(t, "count", r.Data.vals["config_count"], NumText("0"))
}

func pbJSONish(o *Obj) string {
	var sb strings.Builder
	for _, k := range o.Keys() {
		sb.WriteString(k)
		v := o.vals[k]
		switch x := v.(type) {
		case *Obj:
			sb.WriteString(pbJSONish(x))
		case []any:
			for _, i := range x {
				if ob, ok := i.(*Obj); ok {
					sb.WriteString(pbJSONish(ob))
				} else {
					sb.WriteString(plainString(i))
				}
			}
		default:
			sb.WriteString(plainString(v))
		}
	}
	return sb.String()
}

func TestEndpointsSharedContract(t *testing.T) {
	in := []SourceLine{}
	for _, l := range []string{"registry=https://bob:pw@nexus.corp:8443/repository/npm/", "proxy=http://localhost:3128",
		"mirror=http://127.0.0.1:8080/x", "meta=http://169.254.169.254/latest", "meta2=http://METADATA.google.internal./computeMetadata",
		"v6=http://[::1]:9000/", "v6b=http://[fd00:ec2::254]/", "pub=https://registry.npmjs.org/",
		"# x=https://commented.corp/", `<project xmlns="http://maven.apache.org/POM/4.0.0" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">`,
		"<!-- https://incomment.corp/", "still --> <url>https://after.corp/x</url>", "credential.https://x.corp", "http://10.1.2.3:8081/",
		"<url>http://maven.apache.org/pom</url> s3://bucket.example.com/x"} {
		in = append(in, SourceLine{"/h/.npmrc", l})
	}
	got := []string{}
	for _, ep := range pbEndpoints(in) {
		got = append(got, ep.Class+"\t"+ep.URL)
	}
	pbEq(t, "endpoints", got, []string{"internal\thttps://nexus.corp:8443", "public\thttps://registry.npmjs.org",
		"internal\thttps://after.corp", "internal\thttp://10.1.2.3:8081", "custom\ts3://bucket.example.com"})
}

// TestEndpointsProxyCases: the shared config cases (build/testdata/proxy.json) whose entry
// gives the endpoint bases.
func TestEndpointsProxyCases(t *testing.T) {
	b, err := os.ReadFile("../testdata/proxy.json")
	if err != nil {
		t.Skip("build/testdata/proxy.json not written (tests/shared_cases.py)")
	}
	var doc struct {
		Config []struct {
			Name      string    `json:"name"`
			Text      string    `json:"text"`
			Endpoints *[]string `json:"endpoints"`
			Entry     struct {
				Mode  string   `json:"mode"`
				Match []string `json:"match"`
				Max   int      `json:"max_bytes"`
			} `json:"entry"`
		} `json:"config"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Config {
		if c.Endpoints == nil {
			continue
		}
		ct := pbConfigRead(c.Text, c.Entry.Max, c.Entry.Mode, c.Entry.Match)
		in := []SourceLine{}
		for _, i := range ct.Kept {
			in = append(in, SourceLine{"f", ct.Raw[i]})
		}
		got := []string{}
		for _, ep := range pbEndpoints(in) {
			got = append(got, ep.URL)
		}
		pbEq(t, c.Name, got, append([]string{}, (*c.Endpoints)...))
	}
}

func TestProxyURLs(t *testing.T) {
	got := pbProxyURLs([]ProxySetting{
		{Source: "a", Kind: "proxy", Value: "http://u:p@Proxy.Corp:8080/path"},
		{Source: "a", Kind: "proxy", Value: "http://proxy.corp:8080"},
		{Source: "a", Kind: "proxy", Value: "proxy.corp:3128", Endpoint: "proxy.corp:3128"},
		{Source: "a", Kind: "exclusion", Value: ".corp"},
		{Source: "a", Kind: "proxy", Value: "-", Endpoint: "-"},
		{Source: "b", Kind: "proxy", Value: "socks5://[fd00::1]:1080"},
	})
	pbEq(t, "proxy urls", got, [][2]string{{"a", "http://proxy.corp:8080"}, {"a", "http://proxy.corp:3128"},
		{"b", "socks5://[fd00::1]:1080"}})
}

func TestPkgCachesCapAndCredentialLink(t *testing.T) {
	e := pbNewEnv(t)
	old := pbCacheCap
	pbCacheCap = 3
	t.Cleanup(func() { pbCacheCap = old })
	pbSwapSpec(t, func(d *SpecDoc) {
		d.Caches = []SpecCache{{ID: "npm", Tool: "npm", Paths: []string{"~/.npm/_cacache"}},
			{ID: "pip", Tool: "pip", Paths: []string{"~/.cache/pip"}}, {ID: "maven", Tool: "maven", Paths: []string{"~/.m2/repository"}},
			{ID: "empty", Tool: "x", Paths: []string{"~/.empty"}}}
	})
	pbMkdir(t, e.Root, "/home/u/.npm/_cacache/a", "/home/u/.npm/_cacache/b", "/home/u/.npm/_cacache/c",
		"/home/u/.npm/_cacache/d", "/home/u/.npm/_cacache/.e", "/home/u/.empty")
	pbWrite(t, e.Root, map[string]string{"/home/u/.cache/pip/x": "", "/home/u/.cache/pip/.y": "", "/home/u/.m2/repository/x": ""})
	e.RefusedP["/home/u/.m2/repository"] = "network or autofs mount"
	r := pbRun(e, "pkg.caches")
	items := r.Data.vals["caches"].([]any)
	pbEq(t, "count", len(items), 2)
	npm, pip := items[0].(*Obj), items[1].(*Obj)
	pbEq(t, "npm", []any{npm.vals["entries"], npm.vals["truncated"]}, []any{NumText("3"), true})
	pbEq(t, "pip", []any{pip.vals["entries"], pip.vals["truncated"]}, []any{NumText("2"), false})
	pbEq(t, "truncated", r.Truncated, true)
	if !pbHasNote(r, "counted up to 3 per directory; 1 cache directories") || !pbHasNote(r, "/home/u/.m2/repository") {
		t.Errorf("notes %v", r.Notes)
	}
	pbEq(t, "fact", r.Facts["caches"], "npm\npip\n")

	none := pbNewEnv(t)
	pbEq(t, "not found", pbRun(none, "pkg.caches").Status, StNotFound)
}

func TestPkgInstalled(t *testing.T) {
	e := pbNewEnv(t)
	e.PathBins["dpkg-query"] = "/usr/bin/dpkg-query"
	e.PathBins["apk"] = "/sbin/apk"
	e.PathBins["rpm"] = "/usr/bin/rpm"
	e.Cmds[`dpkg-query -W -f=${Package}\t${Version}\n`] = fakeCmd{Stdout: "zlib1g\t1:1.2.13\nbash\t5.2-1\n"}
	e.Cmds["apk info -v"] = fakeCmd{Stdout: "musl-utils-1.2.4-r2\nlibssl3-3.1.4-r5\nweird\n"}
	e.Cmds[`rpm -qa --qf %{NAME}\t%{VERSION}-%{RELEASE}\n`] = fakeCmd{}
	r := pbRun(e, "pkg.installed")
	pbKeys(t, r.Data, "managers", "packages", "total", "truncated")
	names := []string{}
	for _, p := range r.Data.vals["packages"].([]any) {
		o := p.(*Obj)
		names = append(names, o.Str("source")+":"+o.Str("name")+"="+o.Str("version"))
	}
	pbEq(t, "packages", names, []string{"dpkg:bash=5.2-1", "apk:libssl3=3.1.4-r5", "apk:musl-utils=1.2.4-r2", "apk:weird=", "dpkg:zlib1g=1:1.2.13"})
	pbEq(t, "facts", []string{r.Facts["pkg_managers"], r.Facts["pkg_total"]}, []string{"dpkg apk", "5"})
	pbEq(t, "partial (rpm printed nothing)", r.Status, StPartial)

	big := pbNewEnv(t)
	big.PathBins["pacman"] = "/usr/bin/pacman"
	var sb strings.Builder
	for i := 0; i < 501; i++ {
		sb.WriteString("pkg" + itoa(1000+i) + " 1.0\n")
	}
	big.Cmds["pacman -Q"] = fakeCmd{Stdout: sb.String()}
	r = pbRun(big, "pkg.installed")
	pbEq(t, "trunc", []any{len(r.Data.vals["packages"].([]any)), r.Data.vals["truncated"], r.Truncated}, []any{500, true, true})

	none := pbNewEnv(t)
	r = pbRun(none, "pkg.installed")
	pbEq(t, "none", []any{r.Status, r.Notes}, []any{StNotFound, []string{"no supported package manager was found"}})
}
