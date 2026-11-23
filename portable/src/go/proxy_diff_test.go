// proxy_diff_test.go: optional differential check against the reference proxy.awk. A generator
// (gawk --posix, LC_ALL=C over random configuration lines) writes {"lines": [[source, text]...],
// "want": [awk output lines]}; set ENVSCAN_PROXY_DIFF to that file to run it. Skipped otherwise.
package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// awkProxyLine: a setting as proxy.awk prints it ("-" for an empty endpoint or value)
func awkProxyLine(s ProxySetting) string {
	dash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	return strings.Join([]string{s.Source, s.Kind, dash(s.Endpoint), s.Key, dash(s.Value), s.Text}, "\t")
}

func TestProxyDifferentialAgainstAwk(t *testing.T) {
	path := os.Getenv("ENVSCAN_PROXY_DIFF")
	if path == "" {
		t.Skip("ENVSCAN_PROXY_DIFF not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Lines [][2]string `json:"lines"`
		Want  []string    `json:"want"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	in := make([]SourceLine, len(doc.Lines))
	for i, l := range doc.Lines {
		in[i] = SourceLine{Source: l[0], Text: l[1]}
	}
	got := []string{}
	for _, s := range proxySettings(in) {
		got = append(got, awkProxyLine(s))
	}
	if len(got) != len(doc.Want) {
		t.Errorf("%d settings, awk printed %d", len(got), len(doc.Want))
	}
	bad := 0
	for i := 0; i < len(got) && i < len(doc.Want); i++ {
		if got[i] != doc.Want[i] {
			bad++
			if bad <= 10 {
				t.Errorf("setting %d:\n got  %q\n want %q", i, got[i], doc.Want[i])
			}
		}
	}
}
