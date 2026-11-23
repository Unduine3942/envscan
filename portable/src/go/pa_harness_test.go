package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var paProbeIDs = []string{"os.identity", "os.time_locale", "os.health", "hw.cpu", "hw.memory", "hw.storage", "hw.gpu",
	"limits.process", "limits.kernel", "limits.cgroup", "net.ports", "user.identity", "user.profile", "user.privileges",
	"env.vars", "env.path", "shell.info", "shell.userland", "session.context"}

// paLinux: the linux-basic fixture as an Ubuntu host named build01.
func paLinux(t *testing.T) *fakeEnv {
	t.Helper()
	e := newFakeEnv(t, fixtureRoot(t, "linux-basic"))
	e.UnameV = Uname{Sysname: "Linux", Nodename: "build01", Release: "5.15.0-105-generic", Version: "#115-Ubuntu SMP",
		Machine: "x86_64"}
	e.Host = "build01"
	e.MountTab = []Mount{{Device: "/dev/sda1", Dir: "/", Type: "ext4", Options: "rw,relatime"},
		{Device: "proc", Dir: "/proc", Type: "proc", Options: "rw"}}
	paInstallRedaction()
	return e
}

func paInstallRedaction() {
	if redactNamed == nil {
		redactNamed = func(name, value string) string {
			if strings.Contains(strings.ToUpper(name), "TOKEN") || strings.Contains(strings.ToUpper(name), "KEY") {
				return "[REDACTED]"
			}
			return value
		}
	}
}

// paTree builds a root folder from path -> content ("" ending in / = directory).
func paTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func paRun(t *testing.T, e Env, id string) *Result {
	t.Helper()
	f, ok := probeFuncs[id]
	if !ok {
		t.Fatalf("probe %s not registered", id)
	}
	r := newResult(id)
	f(e, r)
	return r
}

// paPlain turns probe data into plain JSON-like values (strings unwrapped, NumText as text).
func paPlain(v any) any {
	switch t := v.(type) {
	case *Obj:
		m := map[string]any{}
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			m[k] = paPlain(x)
		}
		return m
	case []any:
		out := []any{}
		for _, x := range t {
			out = append(out, paPlain(x))
		}
		return out
	case int:
		return itoa(t)
	case uint64:
		return itoa(int(t))
	case NumText:
		return string(t)
	case string, Verbatim, Line, Cmd, Named, Text:
		return plainString(t)
	}
	return v
}

// paWant compares data keys with plain expected values (numbers as decimal strings).
func paWant(t *testing.T, r *Result, want map[string]any) {
	t.Helper()
	for k, w := range want {
		got, ok := r.Data.Get(k)
		if !ok {
			t.Errorf("%s: key %s missing", r.ID, k)
			continue
		}
		if g := paPlain(got); !reflect.DeepEqual(g, w) {
			t.Errorf("%s: %s = %#v, want %#v", r.ID, k, g, w)
		}
	}
}

func paHasNote(r *Result, part string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

// paCommandCases loads a group of tests/data/commands.json (shared with the sh tests).
func paCommandCases(t *testing.T, group string) []map[string]any {
	t.Helper()
	var doc struct {
		Groups map[string][]map[string]any `json:"groups"`
	}
	paths := []string{"../../tests/data/commands.json", "../../../tests/data/commands.json"}
	if dir := os.Getenv("ENVSCAN_TESTDATA_FINDINGS"); dir != "" {
		paths = append([]string{filepath.Join(dir, "commands.json")}, paths...)
	}
	for _, rel := range paths {
		if b, err := os.ReadFile(rel); err == nil {
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			return doc.Groups[group]
		}
	}
	t.Fatal("tests/data/commands.json not found")
	return nil
}

// paJSONPlain turns a decoded JSON value into paPlain's form (numbers as decimal strings).
func paJSONPlain(v any) any {
	switch t := v.(type) {
	case float64:
		b, _ := json.Marshal(t)
		return string(b)
	case map[string]any:
		m := map[string]any{}
		for k, x := range t {
			m[k] = paJSONPlain(x)
		}
		return m
	case []any:
		out := []any{}
		for _, x := range t {
			out = append(out, paJSONPlain(x))
		}
		return out
	}
	return v
}

// TestDistrolessEveryProbeEndsCleanly: no files, no commands, no uname, no limits.
func TestDistrolessEveryProbeEndsCleanly(t *testing.T) {
	paInstallRedaction()
	for _, root := range []string{"", t.TempDir()} {
		e := newFakeEnv(t, root)
		for _, id := range paProbeIDs {
			r := paRun(t, e, id)
			switch r.Status {
			case StOK, StPartial, StNotFound, StNotApplicable:
			default:
				t.Errorf("%s: status %s (%s)", id, r.Status, r.Error)
			}
		}
		if len(e.Ran) != 0 {
			t.Errorf("commands ran without being present: %v", e.Ran)
		}
	}
}

func TestEveryProbeIsRegisteredAndInSpec(t *testing.T) {
	for _, id := range paProbeIDs {
		if _, ok := probeFuncs[id]; !ok {
			t.Errorf("%s not registered", id)
		}
		if _, ok := specProbe(id); !ok {
			t.Errorf("%s not in spec", id)
		}
	}
}

// symlinkOrSkip makes a link (parent folders created); Windows without the privilege fails.
func symlinkOrSkip(t *testing.T, target, link string) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	return os.Symlink(target, link)
}
