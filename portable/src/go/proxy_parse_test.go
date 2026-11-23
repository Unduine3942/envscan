// proxy_parse_test.go: every ProxySetting field for the forms of proxy.awk. Expected rows are the
// output of the reference proxy.awk (gawk --posix, LC_ALL=C) with "-" mapped to "" for Endpoint
// and Value.
package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestProxySettingsFields(t *testing.T) {
	in := []SourceLine{
		{"env:x", "HTTPS_PROXY=http://bob:pw@p.corp:3128"},
		{"env:x", "NO_PROXY=localhost,.corp"},
		{"env:x", "http_proxy="},
		{"env:x", "GOPROXY=https://m.corp"},
		{"env:x", "proxy_password=pw"},
		{"/h/.npmrc", "proxy = off"},
		{"/h/.npmrc", "https-proxy=p2.corp:8080\r"},
		{"/h/.npmrc", "noproxy=a\tb"},
		{"/h/s.xml", "<proxies>"},
		{"/h/s.xml", "  <proxy>"},
		{"/h/s.xml", "    <protocol>https</protocol>"},
		{"/h/s.xml", "    <host>m.corp</host>"},
		{"/h/s.xml", "    <password>x</password>"},
		{"/h/s.xml", "  </proxy>"},
		{"/h/s.xml", "</proxies>"},
		{"/h/g.props", "systemProp.https.proxyHost=g.corp"},
		{"/h/g.props", "systemProp.https.proxyPort=8443"},
	}
	want := []ProxySetting{
		{"env:x", "proxy", "p.corp:3128", "HTTPS_PROXY", "http://bob:pw@p.corp:3128", "HTTPS_PROXY=http://bob:pw@p.corp:3128"},
		{"env:x", "exclusion", "", "NO_PROXY", "localhost,.corp", "NO_PROXY=localhost,.corp"},
		{"env:x", "other", "", "http_proxy", "", "http_proxy="},
		{"/h/.npmrc", "other", "", "proxy", "off", "proxy = off"},
		{"/h/.npmrc", "proxy", "p2.corp:8080", "https-proxy", "p2.corp:8080", "https-proxy=p2.corp:8080"},
		{"/h/.npmrc", "exclusion", "", "noproxy", "a b", "noproxy=a\tb"},
		{"/h/s.xml", "proxy", "m.corp:443", "proxies.proxy", "https://m.corp", "proxies.proxy=https://m.corp"},
		{"/h/g.props", "proxy", "g.corp:8443", "systemProp.https.proxyHost", "g.corp", "systemProp.https.proxyHost=g.corp"},
		{"/h/g.props", "other", "", "systemProp.https.proxyPort", "8443", "systemProp.https.proxyPort=8443"},
	}
	got := proxySettings(in)
	if !reflect.DeepEqual(got, want) {
		for i := range got {
			t.Logf("got %d: %#v", i, got[i])
		}
		t.Fatal("settings differ")
	}
	for _, s := range got {
		if strings.Contains(s.Key, "password") {
			t.Errorf("secret setting output: %#v", s)
		}
	}
}

func TestProxySettingsEmpty(t *testing.T) {
	if got := proxySettings(nil); got == nil || len(got) != 0 {
		t.Errorf("nil input: %#v", got)
	}
}

func TestProxyCommentsAndBlocks(t *testing.T) {
	in := []SourceLine{
		{"/c", "# proxy=http://commented.corp:1"},
		{"/c", "<!-- <proxy><host>old.corp</host></proxy>"},
		{"/c", "-->"},
		{"/c", "\"proxies\": {"},
		{"/c", "  \"http-proxy\": \"http://d.corp:3128\","},
		{"/c", "},"},
		{"/c", ":http_proxy: http://gem.corp:3128"},
		{"/c", "Acquire::http::Proxy \"DIRECT\";"},
	}
	got := proxyURLs(proxySettings(in))
	want := []string{"http://d.corp:3128", "http://gem.corp:3128"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProxyEndpointHelpers(t *testing.T) {
	cases := map[string]string{
		"http://h.corp":         "h.corp:80",
		"https://h.corp":        "h.corp:443",
		"socks5://h.corp":       "h.corp:1080",
		"http://u:p@[::1]:81/x": "[::1]:81",
		"bob:pw@h.corp:3128":    "h.corp:3128",
		"h.corp":                "",
		"http://":               "",
	}
	for v, want := range cases {
		if got := proxyEndpoint(v); got != want {
			t.Errorf("proxyEndpoint(%q) = %q, want %q", v, got, want)
		}
	}
	for h, want := range map[string]bool{"webproxy": true, "a.b": true, "off": false, "123": false, "": false, "DIRECT": false} {
		if bareHost(h) != want {
			t.Errorf("bareHost(%q) != %v", h, want)
		}
	}
}
