// pc_testutil_test.go: test helpers of the probes-c files.
package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// rootedEnv is a fakeEnv whose write methods take LOGICAL paths below Root, like the engine's,
// so that a probe can Stat a place and then MkdirUnique in it with the same path.
type rootedEnv struct{ *fakeEnv }

func newRooted(t *testing.T) *rootedEnv {
	root := t.TempDir()
	f := newFakeEnv(t, root)
	for _, d := range []string{"/scantmp", "/home/u", "/tmp", "/bin"} {
		mustMkdir(t, filepath.Join(root, filepath.FromSlash(d)))
	}
	return &rootedEnv{f}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func (r *rootedEnv) logical(real string) string {
	rel, _ := filepath.Rel(r.Root, real)
	return "/" + filepath.ToSlash(rel)
}

func (r *rootedEnv) TempDir() string { return "/scantmp" }

func (r *rootedEnv) MkdirUnique(parent string) (string, error) {
	d, err := r.fakeEnv.MkdirUnique(r.real(parent))
	if err != nil {
		return "", err
	}
	return r.logical(d), nil
}

func (r *rootedEnv) WriteNew(p string, data []byte, perm uint32) error {
	return r.fakeEnv.WriteNew(r.real(p), data, perm)
}

func (r *rootedEnv) Symlink(target, p string) error { return r.fakeEnv.Symlink(target, r.real(p)) }

func (r *rootedEnv) Link(oldPath, newPath string) error {
	return r.fakeEnv.Link(r.real(oldPath), r.real(newPath))
}

func (r *rootedEnv) RemoveOwn(dir string) error { return r.fakeEnv.RemoveOwn(r.real(dir)) }

// leftovers: test directories the probe did not remove below logical DIR.
func (r *rootedEnv) leftovers(t *testing.T, dir string) []string {
	ents, err := os.ReadDir(r.real(dir))
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, d := range ents {
		if strings.HasPrefix(d.Name(), "envscan-t") {
			out = append(out, d.Name())
		}
	}
	return out
}

func run(e Env, id string, f probeFunc) *Result {
	r := newResult(id)
	f(e, r)
	return r
}

func get(t *testing.T, o *Obj, k string) any {
	t.Helper()
	v, ok := o.Get(k)
	if !ok {
		t.Fatalf("key %q missing (keys %v)", k, o.Keys())
	}
	return v
}

func obj(t *testing.T, v any) *Obj {
	t.Helper()
	o, ok := v.(*Obj)
	if !ok {
		t.Fatalf("not an object: %#v", v)
	}
	return o
}

// strs flattens an array of string-like values.
func strs(t *testing.T, v any) []string {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("not an array: %#v", v)
	}
	out := []string{}
	for _, x := range a {
		out = append(out, plainString(x))
	}
	return out
}

func objs(t *testing.T, v any) []*Obj {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("not an array: %#v", v)
	}
	out := []*Obj{}
	for _, x := range a {
		out = append(out, obj(t, x))
	}
	return out
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

func hasNote(r *Result, sub string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, root, logical, text string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(logical))
	mustMkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// bin makes NAME found on PATH with fake output for "name args".
func bin(e *fakeEnv, key string, c fakeCmd) {
	name, _, _ := strings.Cut(key, " ")
	e.PathBins[name] = "/usr/bin/" + name
	e.Cmds[key] = c
}
