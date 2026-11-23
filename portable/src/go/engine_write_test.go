package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnFolders(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"home/u/Desktop/": "", "tmp/": "", "proc/self/mounts": "srv:/n /mnt/n nfs rw 0 0\n"})
	e := newTestEnv(t, root, nil)
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(e.TempDir()), "envscan.") {
		t.Fatal(e.TempDir())
	}
	d, err := e.MkdirUnique(e.TempDir())
	if err != nil || !strings.HasPrefix(d, e.TempDir()) {
		t.Fatalf("%s %v", d, err)
	}
	f := filepath.Join(d, "probe.txt")
	if err := e.WriteNew(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.WriteNew(f, []byte("y"), 0o600); err == nil {
		t.Fatal("not exclusive")
	}
	if err := e.WriteNew(filepath.Join(e.TempDir(), "x"), nil, 0o600); !isRefusal(err) {
		t.Fatalf("outside own folder: %v", err)
	}
	if ok, why := e.Runnable(f); !ok {
		t.Fatalf("own script: %s", why)
	}
	if ok, _ := e.Runnable(filepath.Join(e.TempDir(), "x")); ok {
		t.Fatal("temp but not own")
	}
	if e.childDir(d) != d || e.childDir("/etc") != string(os.PathSeparator) {
		t.Fatal("childDir")
	}
	ld, err := e.MkdirUnique("/tmp")
	if err != nil || !strings.HasPrefix(ld, "/tmp/.envscan-t.") {
		t.Fatalf("logical %s %v", ld, err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ld))); err != nil {
		t.Fatal("not below the root")
	}
	for _, bad := range []string{"/home/u/Desktop", "/mnt/n", "/home/u/.ssh"} {
		if _, err := e.MkdirUnique(bad); !isRefusal(err) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := e.RemoveOwn(d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) || e.RemoveOwn(d) == nil {
		t.Fatal("removed once")
	}
	tmp := e.TempDir()
	e.cleanup()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("temp left")
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ld))); !os.IsNotExist(err) {
		t.Fatal("own folder left")
	}
}

func TestUnsafeDirsAndOut(t *testing.T) {
	for p, bad := range map[string]bool{"/home/u/Desktop": true, "/home/u/documents/x": true, "/home/u/OneDrive - Corp": true,
		"/home/u/Dropbox": true, "/home/u/work": false, "/home/u/box": true, "/home/u/boxes": false} {
		if (unsafeDirWhy(p, nil) != "") != bad {
			t.Errorf("%s", p)
		}
	}
	if unsafeDirWhy("/home/u/Schreibtisch/x", []string{"/home/u/Schreibtisch"}) == "" {
		t.Error("xdg")
	}
	if xdgDirEnabled("/home/u/", "/home/u") != "" || xdgDirEnabled("/", "/home/u") != "" || xdgDirEnabled("/home/u/Desk//", "/home/u") != "/home/u/Desk" {
		t.Error("xdgEnabled")
	}
	if sanitizeHost("a b/c\xc3.d-e_f") != "a_b_c_.d-e_f" {
		t.Error(sanitizeHost("a b/c\xc3.d-e_f"))
	}
	if shUnquote(` "x y" `) != "x y" || shUnquote("'a'") != "a" || shUnquote(`"a`) != `"a` {
		t.Error("unquote")
	}
	parent := t.TempDir()
	o := defaultOptions()
	o.Out = filepath.Join(parent, "new", "deeper")
	e := newTestEnv(t, t.TempDir(), o)
	out, err := e.pickOut()
	if err != nil || filepath.Base(out) != "envscan-unknown-20260102T030405Z" {
		t.Fatalf("%s %v", out, err)
	}
	out2, err := e.pickOut()
	if err != nil || !strings.HasSuffix(out2, "Z-2") {
		t.Fatalf("second %s %v", out2, err)
	}
}

func TestReadUserDirs(t *testing.T) {
	cfg := t.TempDir()
	f := filepath.Join(cfg, "user-dirs.dirs")
	if err := os.WriteFile(f, []byte("# c\nXDG_DESKTOP_DIR=\"$HOME/Schreibtisch\"\nXDG_DOCUMENTS_DIR=\"$HOME/\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, t.TempDir(), nil)
	desk, docs := e.readUserDirs(f, "/home/u")
	if desk != "/home/u/Schreibtisch" || docs != "/home/u/" {
		t.Fatalf("%q %q", desk, docs)
	}
}
