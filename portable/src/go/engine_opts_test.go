package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseArgsErrors(t *testing.T) {
	cases := map[string][]string{
		"option --net takes no value":                   {"--net=false"},
		"option --deep takes no value":                  {"-deep=1"},
		"--out needs a value":                           {"--out"},
		"--out needs a directory":                       {"--out="},
		"unknown argument: --bogus":                     {"--bogus"},
		"unknown argument: -":                           {"-"},
		"unknown argument: x":                           {"x"},
		"--timeout needs a positive number of seconds":  {"--timeout", "0"},
		"--budget needs a positive number of seconds":   {"--budget=1.5"},
		"--timeout needs a positive number of seconds ": {"--timeout=-3"},
	}
	for want, args := range cases {
		_, err := parseArgs(args)
		if err == nil || err.Error() != strings.TrimSpace(want) {
			t.Errorf("%v: got %v, want %q", args, err, want)
		}
	}
}

func TestParseArgsValues(t *testing.T) {
	o, err := parseArgs([]string{"-deep", "--net", "--out", "x", "--only=os.*", "--skip", "", "--timeout=5", "--budget", "9", "--no-redact", "--version"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.Deep || !o.Net || o.Out != "x" || o.Only != "os.*" || !o.SkipSet || o.TimeoutSec != 5 || o.BudgetSec != 9 || o.Redact || o.Action != actVersion {
		t.Fatalf("%+v", o)
	}
	want := []string{"-deep", "--net", "--out", "x", "--only=os.*", "--skip", "", "--timeout=5", "--budget", "9", "--no-redact", "--version"}
	if strings.Join(o.Flags, "|") != strings.Join(want, "|") {
		t.Fatalf("flags %q", o.Flags)
	}
	if got := flagList(o.Flags); len(got) != len(want)-1 {
		t.Fatalf("flag list drops empty values: %v", got)
	}
	for _, a := range []string{"--help", "-h", "--list-probes"} {
		o, _ := parseArgs([]string{a})
		if o.Action == actScan {
			t.Errorf("%s: no action", a)
		}
	}
}

func TestCheckSelection(t *testing.T) {
	ids := []string{"os.identity", "os.health", "net.proxy"}
	if s, err := checkSelection(" os.* , ,net.proxy", "--only", true, ids); err != nil || s != "os.*,net.proxy" {
		t.Fatalf("%q %v", s, err)
	}
	errs := map[string]string{
		"x$":   "--only: invalid pattern 'x$' (allowed: letters, digits, . _ - *)",
		"zz.*": "--only: pattern 'zz.*' matches no probe",
		" , ":  "--only needs probe ids",
	}
	for in, want := range errs {
		if _, err := checkSelection(in, "--only", true, ids); err == nil || err.Error() != want {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, err := checkSelection("", "--skip", true, ids); err == nil || err.Error() != "--skip needs probe ids" {
		t.Errorf("empty given: %v", err)
	}
	if s, err := checkSelection("", "--skip", false, ids); err != nil || s != "" {
		t.Errorf("not given: %q %v", s, err)
	}
}

func TestWildMatchAndInList(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{{"net.*", "net.proxy", true}, {"net.*", "os.net", false}, {"*", "a", true}, {"*.id*y", "os.identity", true},
		{"os.identity", "os.identity", true}, {"os.ident", "os.identity", false}, {"a*a", "a", false}, {"*y", "os.identity", true}}
	for _, c := range cases {
		if got := wildMatch(c.pat, c.s); got != c.want {
			t.Errorf("wildMatch(%q,%q)=%v", c.pat, c.s, got)
		}
	}
	if !inList("net.proxy", "os.*, net.*") || inList("fs.x", "os.*,net.*") {
		t.Fatal("inList")
	}
}

func TestListProbesFormat(t *testing.T) {
	var b bytes.Buffer
	listProbes(&b)
	first := strings.SplitN(b.String(), "\n", 3)
	p := spec.Probes[0]
	if first[0] != p.ID+"  ["+p.Tier+"]  "+p.Title || !strings.HasPrefix(first[1], "    - ") {
		t.Fatalf("%q", first[:2])
	}
}

func testEnviron(extra ...string) []string {
	return append([]string{"ENVSCAN_ROOT=/x", "ENVSCAN_TEST_OS=linux"}, extra...)
}

func TestRunMainActions(t *testing.T) {
	needScanBuild(t)
	var out, errb bytes.Buffer
	if rc := runMain([]string{"--version"}, &out, &errb, testEnviron()); rc != 0 || out.String() != "envscan "+spec.Version+" (go)\n" {
		t.Fatalf("version rc=%d %q", rc, out.String())
	}
	out.Reset()
	if rc := runMain([]string{"--help"}, &out, &errb, testEnviron()); rc != 0 || !strings.HasPrefix(out.String(), "usage: envscan") {
		t.Fatalf("help rc=%d", rc)
	}
	out.Reset()
	if rc := runMain([]string{"--list-probes"}, &out, &errb, testEnviron()); rc != 0 || !strings.Contains(out.String(), "os.identity  [default]") {
		t.Fatalf("list rc=%d", rc)
	}
	out.Reset()
	if rc := runMain([]string{"--only", "nope.*"}, &out, &errb, testEnviron()); rc != 2 || out.Len() != 0 ||
		!strings.HasPrefix(errb.String(), "envscan: --only: pattern 'nope.*' matches no probe\nusage:") {
		t.Fatalf("usage rc=%d %q", rc, errb.String())
	}
}
