package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanWith runs a whole scan in-process with test probes and stand-in services.
func scanWith(t *testing.T, args []string, funcs map[string]probeFunc, probes []SpecProbe, extra ...string) (string, string, int) {
	t.Helper()
	root := fixtureRoot(t, "linux-basic")
	out := t.TempDir()
	o, err := parseArgs(append([]string{"--out", out}, args...))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	s := &scan{opts: o, stderr: &stderr, newRun: func(e *realEnv, w io.Writer) *runner {
		rn := newRunner(e, w)
		rn.funcs, rn.probes = funcs, probes
		return rn
	}}
	env := append([]string{"ENVSCAN_ROOT=" + root, "ENVSCAN_TEST_OS=linux", "HOME=/home/u", "TMPDIR=" + t.TempDir(),
		"MY_TOKEN=abc"}, extra...)
	rc := s.run(&stdout, env, testClock)
	return stdout.String(), stderr.String(), rc
}

func TestScanWritesReport(t *testing.T) {
	funcs := map[string]probeFunc{
		"t.ok": func(e Env, r *Result) {
			text, _ := readText(e, r, "/etc/os-release", 0)
			r.Data.Set("pretty", Line(text[:10])).Set("secret", "x SECRET").Set("tok", Named{"MY_TOKEN", "abc"}).Set("n", num("042"))
			r.SetRaw("os-release", text+"SECRET\n")
			r.Fact("os_name", "Ubuntu")
		},
		"t.partial": func(e Env, r *Result) { r.Partial("half") },
		"t.panic":   func(e Env, r *Result) { panic("bad") },
	}
	installStandIns(t)
	stdout, stderr, rc := scanWith(t, []string{"--timeout", "3"}, funcs, testProbes()[:3])
	out := strings.TrimSpace(stdout)
	if rc != 1 || strings.Count(stdout, "\n") != 1 || !strings.Contains(filepath.Base(out), "envscan-") {
		t.Fatalf("rc=%d stdout=%q stderr=%s", rc, stdout, stderr)
	}
	b, err := os.ReadFile(filepath.Join(out, "envscan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	keys := []string{"schema", "scanner", "run", "host", "findings", "probes"}
	for _, k := range keys {
		if _, ok := doc[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
	text := string(b)
	for _, want := range []string{`"impl": "go"`, `"os_name": "Ubuntu"`, `"exit_code": 1`, `"redaction": true`,
		`"secret": "x <redacted>"`, `"tok": "<redacted>"`, `"n": 42`, `"detail": "has <redacted>"`,
		`"test_root": `, `"--timeout",`, `"error": "probe ended unexpectedly (panic: bad)"`, `"started_utc": "2026-01-02T03:04:05Z"`} {
		if !strings.Contains(text, want) {
			t.Errorf("envscan.json lacks %s", want)
		}
	}
	if strings.Contains(text, "SECRET") || strings.Contains(text, `"abc"`) {
		t.Error("secret written")
	}
	brief, _ := os.ReadFile(filepath.Join(out, "AGENT_BRIEF.md"))
	md, _ := os.ReadFile(filepath.Join(out, "envscan.md"))
	logb, _ := os.ReadFile(filepath.Join(out, "envscan.log"))
	if string(brief) != "brief <redacted>\nline2\n" || string(md) != "# md\n" {
		t.Errorf("brief %q md %q", brief, md)
	}
	if !strings.HasPrefix(string(logb), "envscan "+spec.Version+" (go) on ") || !strings.HasSuffix(string(logb), "exit code 1\n") ||
		!strings.Contains(string(logb), "envscan: 3 probes, 1 ok, 2 not fully checked, 0 skipped; exit 1") {
		t.Errorf("log %s", logb)
	}
}

func TestScanNoRedactAndFallbacks(t *testing.T) {
	funcs := map[string]probeFunc{"t.ok": func(e Env, r *Result) { r.Data.Set("s", "SECRET") }}
	installStandIns(t)
	stdout, _, rc := scanWith(t, []string{"--no-redact", "--only", "t.ok"}, funcs, testProbes()[:1])
	if rc != 0 {
		t.Fatal(rc)
	}
	b, _ := os.ReadFile(filepath.Join(strings.TrimSpace(stdout), "envscan.json"))
	if !strings.Contains(string(b), `"s": "SECRET"`) || !strings.Contains(string(b), `"redaction": false`) {
		t.Fatalf("%s", b)
	}
	renderMarkdown = func(*Obj) string { panic("md broke") }
	computeFindings = func(*Obj, []*Result, map[string]string) []any { panic("findings broke") }
	stdout, stderr, rc := scanWith(t, nil, funcs, testProbes()[:1])
	_ = stdout
	if rc != 0 || !strings.Contains(stderr, "error writing envscan.md") {
		t.Fatalf("rc %d %s", rc, stderr)
	}
}

func TestScanFatalOut(t *testing.T) {
	installStandIns(t)
	o := defaultOptions()
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	o.Out = filepath.Join(f, "sub")
	var stdout, stderr bytes.Buffer
	s := &scan{opts: o, stderr: &stderr, newRun: newRunner}
	rc := s.run(&stdout, []string{"ENVSCAN_ROOT=" + t.TempDir(), "TMPDIR=" + t.TempDir()}, testClock)
	if rc != 2 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "envscan: cannot create --out directory: ") {
		t.Fatalf("%d %q", rc, stderr.String())
	}
}
