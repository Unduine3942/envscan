//go:build linux

// Symbolic links and FIFOs cannot be made on the Windows dev box: these run on Linux only.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLinksAreVettedBeforeFollowing(t *testing.T) {
	root := filesRoot(t)
	link := func(target, at string) {
		if err := os.Symlink(target, filepath.Join(root, at)); err != nil {
			t.Fatal(err)
		}
	}
	link("/home/u/.ssh", "home/u/sshlink")
	link(".ssh/config", "home/u/cfglink")
	link("/mnt/nfs/bin", "usr/netbin")
	link("/etc", "home/u/etclink")
	link("loop2", "home/u/loop1")
	link("loop1", "home/u/loop2")
	e := newTestEnv(t, root, nil)
	for p, why := range map[string]string{"/home/u/sshlink/config": whyCredLink, "/home/u/cfglink": whyCredLink, "/usr/netbin/tool": whyNet} {
		if _, _, err := e.ReadFile(p, 0); !isRefusal(err) || e.Refused(p) != why {
			t.Errorf("%s: %v %q", p, err, e.Refused(p))
		}
	}
	if b, _, err := e.ReadFile("/home/u/etclink/os-release", 0); err != nil || string(b) != "NAME=Test\n" {
		t.Errorf("good link: %v", err)
	}
	if fi, err := e.Lstat("/home/u/cfglink"); err != nil || fi.Type != TypeLink {
		t.Errorf("lstat of the link itself: %+v %v", fi, err)
	}
	if t2, err := e.Readlink("/home/u/sshlink"); err != nil || t2 != "/home/u/.ssh" {
		t.Errorf("readlink %q %v", t2, err)
	}
	if _, _, err := e.ReadFile("/home/u/loop1", 0); err == nil {
		t.Error("loop read")
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc/fifo"), 0o600); err == nil {
		if _, _, err := e.ReadFile("/etc/fifo", 0); !errors.Is(err, ErrNotRegular) {
			t.Errorf("fifo: %v", err)
		}
	}
}
