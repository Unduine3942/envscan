package main

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func filesRoot(t *testing.T) string {
	root := t.TempDir()
	mkTree(t, root, map[string]string{
		"proc/self/mounts":     "/dev/sda1 / ext4 rw 0 0\nsrv:/h /mnt/nfs nfs4 rw 0 0\nsrv:/a /srv/net autofs rw 0 0\n",
		"etc/os-release":       "NAME=Test\n",
		"etc/bin.dat":          "a\x00b",
		"etc/u16le.txt":        "\xff\xfeh\x00i\x00",
		"etc/u16be.txt":        "\xfe\xff\x00h\x00i",
		"etc/u16bad.txt":       "\xff\xfe\x00\xd8",
		"home/u/.ssh/config":   "Host x",
		"home/u/.netrc":        "machine x",
		"home/u/.pip/pip.conf": "[global]",
		"home/u/.pki/x.conf":   "x",
		"home/u/.profile":      "PATH=x",
		"home/u/visible.txt":   "v",
		"mnt/nfs/bin/tool":     "x",
		"srv/net/f":            "x",
		"usr/share/big.txt":    strings.Repeat("x", 100),
		"var/empty/":           "",
	})
	return root
}

func TestReadFileVetting(t *testing.T) {
	e := newTestEnv(t, filesRoot(t), nil)
	if b, tr, err := e.ReadFile("/etc/os-release", 0); err != nil || tr || string(b) != "NAME=Test\n" {
		t.Fatalf("%q %v %v", b, tr, err)
	}
	if b, tr, err := e.ReadFile("/usr/share/big.txt", 10); err != nil || !tr || len(b) != 10 {
		t.Fatalf("cap %d %v %v", len(b), tr, err)
	}
	refused := map[string]string{"/home/u/.ssh/config": whyCred, "/home/u/.netrc": whyCred,
		"/mnt/nfs/bin/tool": whyNet, "/srv/net/f": whyNet, "/home/u/x/../.ssh/config": whyCred, "/home/u/.ssh./config": whyCred}
	for p, why := range refused {
		_, _, err := e.ReadFile(p, 0)
		var r *Refusal
		if !errors.As(err, &r) || r.Reason != why || e.Refused(p) != why {
			t.Errorf("%s: %v (Refused %q)", p, err, e.Refused(p))
		}
	}
	if _, _, err := e.ReadFile("/var/empty", 0); !errors.Is(err, ErrNotRegular) {
		t.Errorf("folder: %v", err)
	}
	if _, _, err := e.ReadFile("/nope", 0); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, _, err := e.ReadFile("relative", 0); !isRefusal(err) {
		t.Errorf("relative: %v", err)
	}
	if e.Refused("/etc/os-release") != "" || !e.IsNetPath("/mnt/nfs/x") || e.IsNetPath("/etc") {
		t.Error("Refused/IsNetPath")
	}
}

func TestReadTextDecoding(t *testing.T) {
	e := newTestEnv(t, filesRoot(t), nil)
	for p, want := range map[string]string{"/etc/u16le.txt": "hi", "/etc/u16be.txt": "hi"} {
		if s, _, err := e.ReadText(p, 0); err != nil || s != want {
			t.Errorf("%s: %q %v", p, s, err)
		}
	}
	for _, p := range []string{"/etc/bin.dat", "/etc/u16bad.txt"} {
		if _, _, err := e.ReadText(p, 0); !errors.Is(err, ErrBinary) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if s, err := decodeText([]byte("\xff\xfeh\x00i\x00j"), true); err != nil || s != "hi" {
		t.Errorf("truncated odd: %q %v", s, err)
	}
	if !validSurrogates([]uint16{0xd83d, 0xde00}) || validSurrogates([]uint16{0xde00}) || validSurrogates([]uint16{0xd83d, 0x41}) {
		t.Error("surrogates")
	}
}

func TestReadDirStatExpand(t *testing.T) {
	e := newTestEnv(t, filesRoot(t), nil)
	ents, tr, err := e.ReadDir("/home/u", 0)
	if err != nil || tr {
		t.Fatal(err)
	}
	var names []string
	for _, d := range ents {
		names = append(names, d.Name)
	}
	got := strings.Join(names, ",")
	if strings.Contains(got, ".ssh") || strings.Contains(got, ".netrc") || !strings.Contains(got, ".pip") {
		t.Fatalf("listing %s", got)
	}
	if ents, tr, _ := e.ReadDir("/home/u", 2); len(ents) != 2 || !tr {
		t.Fatal("max")
	}
	if _, _, err := e.ReadDir("/home/u/.ssh", 0); !isRefusal(err) {
		t.Fatal("store listed")
	}
	if fi, err := e.Stat("/etc/os-release"); err != nil || fi.Type != TypeFile || fi.Size != 10 || fi.Name != "os-release" {
		t.Fatalf("%+v %v", fi, err)
	}
	if fi, err := e.Lstat("/etc"); err != nil || fi.Type != TypeDir {
		t.Fatalf("%+v %v", fi, err)
	}
	if !e.Exists("/home/u/.profile") || e.Exists("/home/u/.ssh") || e.Exists("/nope") {
		t.Fatal("Exists")
	}
	exp := map[string]string{"~/.profile": "/home/u/.profile", "{env:XDGC}/pip": "/cfg/pip", "/abs": "/abs"}
	e.vars["XDGC"] = "/cfg"
	for in, want := range exp {
		if got, ok := e.Expand(in); !ok || got != want {
			t.Errorf("Expand(%q)=%q", in, got)
		}
	}
	for _, in := range []string{"{env:UNSET}/x", "{env:BAD-NAME}/x", "{env:XDGC", "rel/x"} {
		if _, ok := e.Expand(in); ok {
			t.Errorf("Expand(%q) ok", in)
		}
	}
	delete(e.vars, "HOME")
	if _, ok := e.Expand("~/x"); ok {
		t.Error("no HOME")
	}
}

func TestGlob(t *testing.T) {
	e := newTestEnv(t, filesRoot(t), nil)
	pe := &probeEnv{realEnv: e}
	got, _ := pe.Glob("/home/u/.p*/*.conf")
	if strings.Join(got, ",") != "/home/u/.pip/pip.conf,/home/u/.pki/x.conf" {
		t.Fatalf("%v", got)
	}
	if got, _ := pe.Glob("/home/u/*"); strings.Join(got, ",") != "/home/u/visible.txt" {
		t.Fatalf("hidden files and net mount: %v", got)
	}
	if got, _ := pe.Glob("/home/u/.ss*/config"); len(got) != 0 {
		t.Fatalf("store expanded: %v", got)
	}
	if got, _ := pe.Glob("/home/u/.ssh/*"); got != nil {
		t.Fatal("store pattern")
	}
	if got, _ := pe.Glob("/srv/*/f"); got != nil {
		t.Fatal("net base")
	}
	if got, _ := pe.Glob("/etc/os-release"); len(got) != 1 {
		t.Fatal("plain path")
	}
	pe.logSkips("x.y")
	logs := strings.Join(e.logText(), "\n")
	if !strings.Contains(logs, "/srv/*/f") {
		t.Fatalf("log %s", logs)
	}
	if got, _ := pe.Glob("/etc/u16[a-z][a-z].txt"); len(got) != 2 {
		t.Fatalf("class %v", got)
	}
}

func TestSkipNotesLimitAndCredLinks(t *testing.T) {
	pe := &probeEnv{realEnv: newTestEnv(t, t.TempDir(), nil)}
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/a"} {
		pe.record(p, false)
	}
	pe.record("/home/u/.pip", true)
	pe.logSkips("a.b")
	logs := strings.Join(pe.logText(), "\n")
	if !strings.Contains(logs, "a.b: /home/u/.pip not read: link to a credential store") ||
		!strings.Contains(logs, "/a, /b, /c, /d, /e and 2 more") {
		t.Fatalf("%s", logs)
	}
}
