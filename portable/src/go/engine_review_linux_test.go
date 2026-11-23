//go:build linux

// Review fixes that need symbolic links, /proc/self/fd or real modes: Linux only.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLinkChainTooLongIsRefused(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"etc/os-release": "NAME=Test\n", "home/u/": ""})
	for i := 0; i < maxLinkDepth+5; i++ {
		if err := os.Symlink(fmt.Sprintf("l%d", i+1), filepath.Join(root, "home/u", fmt.Sprintf("l%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	last := filepath.Join(root, "home/u", fmt.Sprintf("l%d", maxLinkDepth+5))
	if err := os.Symlink("/etc/os-release", last); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, root, nil)
	if _, _, err := e.ReadFile("/home/u/l0", 0); !isRefusal(err) || e.Refused("/home/u/l0") != whyLoop {
		t.Fatalf("%v %q", err, e.Refused("/home/u/l0"))
	}
}

func TestUnsafeDirThroughLink(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"home/u/Desktop/": "", "tmp/": ""})
	if err := os.Symlink("/home/u/Desktop", filepath.Join(root, "home/u/work")); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, root, nil)
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.MkdirUnique("/home/u/work"); !isRefusal(err) {
		t.Fatalf("MkdirUnique through a link to Desktop: %v", err)
	}
	real := t.TempDir()
	mkTree(t, real, map[string]string{"Desktop/": ""})
	if err := os.Symlink(filepath.Join(real, "Desktop"), filepath.Join(real, "here")); err != nil {
		t.Fatal(err)
	}
	if e.outCandidateOK(filepath.Join(real, "here"), nil) {
		t.Error("output candidate linked to Desktop accepted")
	}
	if !e.outCandidateOK(real, nil) {
		t.Error("plain candidate refused")
	}
}

func TestCommandsRunTheRealPath(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil)
	if got := e.execTarget("/usr/bin/env"); got != "/usr/bin/env" {
		t.Fatalf("executed %s", got)
	}
}

func TestOpenedFileIsRechecked(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"home/u/.ssh/id": "k", "etc/x": "x"})
	e := newTestEnv(t, root, nil)
	f, err := os.Open(filepath.Join(root, "home/u/.ssh/id"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := e.checkOpened(f, e.rv, "/etc/x"); !isRefusal(err) {
		t.Fatalf("opened credential file accepted: %v", err)
	}
	g, err := os.Open(filepath.Join(root, "etc/x"))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err := e.checkOpened(g, e.rv, "/etc/x"); err != nil {
		t.Fatal(err)
	}
}

func TestRunnableChecksResolvedFolder(t *testing.T) {
	real := t.TempDir()
	ww := filepath.Join(real, "ww")
	mkTree(t, real, map[string]string{"ww/tool": "x", "bin/": ""})
	if err := os.Chmod(ww, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(ww, "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ww, "tool"), filepath.Join(real, "bin", "tool")); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, t.TempDir(), nil)
	if ok, why := e.Runnable(filepath.Join(real, "bin", "tool")); ok || why != worldWritableWhy {
		t.Fatalf("%v %q", ok, why)
	}
}
