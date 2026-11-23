package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// pbRecEnv records the RunOpt of each command (the fake does not).
type pbRecEnv struct {
	*fakeEnv
	opts []RunOpt
}

func (p *pbRecEnv) Run(opt RunOpt, path string, args ...string) CmdResult {
	p.opts = append(p.opts, opt)
	return p.fakeEnv.Run(opt, path, args...)
}

// pbWrite writes FILES (logical path -> content) below root.
func pbWrite(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		real := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(p, "/") {
			continue
		}
		if err := os.WriteFile(real, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func pbMkdir(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// pbStandIns installs simple redaction and proxy stand-ins (restored after the test) and makes
// every regular file executable (Windows test hosts have no execute bits).
func pbStandIns(t *testing.T) {
	t.Helper()
	oldText, oldProxy, oldExec := redactText, proxySettings, pbIsExec
	t.Cleanup(func() { redactText, proxySettings, pbIsExec = oldText, oldProxy, oldExec })
	pbIsExec = func(fi FileInfo) bool { return fi.Type == TypeFile }
	redactText = func(s string) string {
		out := []string{}
		for _, l := range strings.Split(s, "\n") {
			if k, _, ok := strings.Cut(l, "="); ok && (strings.Contains(strings.ToLower(k), "token") ||
				strings.Contains(strings.ToLower(k), "password")) {
				l = k + "=<redacted>"
			}
			out = append(out, l)
		}
		return strings.Join(out, "\n")
	}
	proxySettings = pbProxyStandIn
}

// pbProxyStandIn: key=value (or key: value / key value) where the key ends in "proxy".
func pbProxyStandIn(in []SourceLine) []ProxySetting {
	out := []ProxySetting{}
	for _, sl := range in {
		k, v, ok := strings.Cut(sl.Text, "=")
		if !ok {
			k, v, _ = strings.Cut(sl.Text, " ")
		}
		k, v = strings.TrimSpace(strings.ToLower(k)), strings.Trim(strings.TrimSpace(v), `"`)
		if !strings.HasSuffix(k, "proxy") || strings.HasSuffix(k, "noproxy") {
			continue
		}
		ps := ProxySetting{Source: sl.Source, Kind: "proxy", Key: k, Value: v, Text: sl.Text}
		if !strings.Contains(v, "://") {
			ps.Endpoint = v
		}
		if v == "" {
			ps.Kind = "other"
		}
		out = append(out, ps)
	}
	return out
}

func pbNewEnv(t *testing.T) *fakeEnv {
	t.Helper()
	pbStandIns(t)
	e := newFakeEnv(t, t.TempDir())
	e.Vars["HOME"] = "/home/u"
	e.Vars["PATH"] = "/usr/bin:/bin"
	return e
}

func pbRun(e Env, id string) *Result {
	r := newResult(id)
	probeFuncs[id](e, r)
	return r
}

func pbGet(t *testing.T, o *Obj, keys ...string) any {
	t.Helper()
	var cur any = o
	for _, k := range keys {
		ob, ok := cur.(*Obj)
		if !ok {
			t.Fatalf("%v: not an object at %q", keys, k)
		}
		v, has := ob.Get(k)
		if !has {
			t.Fatalf("%v: missing key %q (have %v)", keys, k, ob.Keys())
		}
		cur = v
	}
	return cur
}

func pbStrs(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, plainString(x))
	}
	return out
}

func pbEq(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

func pbHasNote(r *Result, sub string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func pbRan(e *fakeEnv, sub string) bool {
	for _, c := range e.Ran {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// pbKeys checks the data keys in order (the sh event order).
func pbKeys(t *testing.T, o *Obj, want ...string) {
	t.Helper()
	pbEq(t, "keys", o.Keys(), want)
}

// pbSwapSpec replaces part of the spec for one test.
func pbSwapSpec(t *testing.T, f func(d *SpecDoc)) {
	t.Helper()
	old := *spec
	t.Cleanup(func() { *spec = old })
	f(spec)
}
