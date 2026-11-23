package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testClock = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }

// mkTree writes files below root: "path" -> content ("/" suffix = folder).
func mkTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(p, "/")))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// newTestEnv is a realEnv over a test root (ENVSCAN_ROOT) with a fixed clock.
func newTestEnv(t *testing.T, root string, o *options, extra ...string) *realEnv {
	t.Helper()
	if o == nil {
		o = defaultOptions()
	}
	env := append([]string{"ENVSCAN_ROOT=" + root, "ENVSCAN_TEST_OS=linux", "HOME=/home/u",
		"PATH=/usr/bin:/bin:relative::/mnt/nfs/bin", "TMPDIR=" + t.TempDir()}, extra...)
	e := newRealEnv(o, env, testClock)
	t.Cleanup(e.cleanup)
	return e
}

// needLinks skips tests that create symbolic links or FIFOs (not possible without privileges
// on the Windows dev box).
func needLinks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links and FIFOs need Linux (Windows dev box)")
	}
}

// installStandIns sets identity-like services of other agents and restores them afterwards.
func installStandIns(t *testing.T) {
	t.Helper()
	rv, rn, rl, rt, rc := redactValue, redactNamed, redactLine, redactText, redactCmd
	cf, rm, rb := computeFindings, renderMarkdown, renderBrief
	t.Cleanup(func() {
		redactValue, redactNamed, redactLine, redactText, redactCmd = rv, rn, rl, rt, rc
		computeFindings, renderMarkdown, renderBrief = cf, rm, rb
	})
	mark := func(s string) string { return strings.ReplaceAll(s, "SECRET", "<redacted>") }
	redactValue, redactLine, redactText, redactCmd = mark, mark, mark, mark
	redactNamed = func(n, v string) string {
		if strings.Contains(n, "TOKEN") {
			return "<redacted>"
		}
		return v
	}
	computeFindings = func(doc *Obj, rs []*Result, f map[string]string) []any {
		return []any{NewObj().Set("id", "x.y").Set("detail", "has SECRET")}
	}
	renderMarkdown = func(doc *Obj) string { return "# md\n" }
	renderBrief = func(doc *Obj, f map[string]string) string { return "brief SECRET\nline2" }
}
