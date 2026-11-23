// proxy_shared_test.go: tests/proxy_cases.py (build/testdata/proxy.json) through proxySettings,
// with the sh pipeline around it emulated: es_config_raw (the kept lines of a configs entry) and
// es_proxy_urls (proxy settings -> scheme://host[:port], lower case, once per source).
package main

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

type proxyConfigCase struct {
	Name     string   `json:"name"`
	ConfigID string   `json:"config_id"`
	Text     string   `json:"text"`
	Expected []string `json:"expected"`
	Entry    struct {
		Mode     string   `json:"mode"`
		Match    []string `json:"match"`
		MaxBytes int      `json:"max_bytes"`
	} `json:"entry"`
}

type proxyGitCase struct {
	Name     string   `json:"name"`
	Entries  []string `json:"entries"`
	Expected []string `json:"expected"`
}

// configRawLines is es_config_raw: byte cap, blank lines and (content mode) comment lines
// skipped, lines mode keeps the lines holding a match word (any case).
func configRawLines(source, text, mode string, max int, match []string) []SourceLine {
	if max <= 0 {
		max = 65536
	}
	out := []SourceLine{}
	total := 0
	for nr, line := range lines(text) {
		add := len(line)
		if nr > 0 {
			add++
		}
		if total+add > max {
			break
		}
		total += add
		trim := strings.TrimLeft(line, " \t")
		if trim == "" || (mode != "lines" && (trim[0] == '#' || trim[0] == ';')) {
			continue
		}
		if mode == "lines" && !containsAnyLower(line, match) {
			continue
		}
		out = append(out, SourceLine{Source: source, Text: line})
	}
	return out
}

func containsAnyLower(line string, words []string) bool {
	lc := strings.ToLower(line)
	for _, w := range words {
		if strings.Contains(lc, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

var (
	testURLRe  = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/ \t"'<>,;?#]+`)
	testHostRe = regexp.MustCompile(`^(\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?`)
)

func init() {
	testURLRe.Longest()
	testHostRe.Longest()
}

// proxyURLs is es_proxy_urls: the URLs of the "proxy" settings.
func proxyURLs(settings []ProxySetting) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range settings {
		if s.Kind != "proxy" {
			continue
		}
		u := ""
		if m := testURLRe.FindString(s.Value); m != "" {
			k := strings.Index(m, "://")
			hp := m[k+3:]
			if at := strings.LastIndexByte(hp, '@'); at >= 0 {
				hp = hp[at+1:]
			}
			if h := testHostRe.FindString(hp); h != "" {
				u = m[:k] + "://" + h
			}
		} else if s.Endpoint != "" {
			u = "http://" + s.Endpoint
		}
		if u == "" {
			continue
		}
		key := s.Source + "\t" + strings.ToLower(u)
		if !seen[key] {
			seen[key] = true
			out = append(out, strings.ToLower(u))
		}
	}
	return out
}

func TestProxySharedConfigCases(t *testing.T) {
	var doc struct {
		Config []proxyConfigCase `json:"config"`
		Git    []proxyGitCase    `json:"git"`
	}
	loadTestdata(t, "proxy.json", &doc)
	if len(doc.Config) == 0 || len(doc.Git) == 0 {
		t.Fatal("no proxy cases")
	}
	for _, c := range doc.Config {
		in := configRawLines("/cfg/"+c.ConfigID, c.Text, c.Entry.Mode, c.Entry.MaxBytes, c.Entry.Match)
		got := proxyURLs(proxySettings(in))
		if !reflect.DeepEqual(got, nonNil(c.Expected)) {
			t.Errorf("%s: got %q, want %q", c.Name, got, c.Expected)
		}
	}
	for _, c := range doc.Git {
		in := []SourceLine{}
		for _, e := range c.Entries {
			in = append(in, SourceLine{Source: "git:file:/h/.gitconfig", Text: e})
		}
		got := proxyURLs(proxySettings(in))
		if !reflect.DeepEqual(got, nonNil(c.Expected)) {
			t.Errorf("%s: got %q, want %q", c.Name, got, c.Expected)
		}
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
