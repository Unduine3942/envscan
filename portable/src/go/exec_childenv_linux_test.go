//go:build linux

package main

import (
	"os"
	"strings"
	"testing"
)

// A real child (env(1)) sees only the allowlisted variables, the spec overrides and LC_ALL=C.
func TestChildProcessSeesOnlyAllowlistedEnv(t *testing.T) {
	const envBin = "/usr/bin/env"
	if _, err := os.Stat(envBin); err != nil {
		t.Skip("no /usr/bin/env")
	}
	e := newTestEnv(t, t.TempDir(), nil, "ENVSCAN_TEST_CHILD_CANARY=canary-123", "HTTP_PROXY=http://u:pw@p:1",
		"GITHUB_TOKEN=ghp_abcdefghijklmnop", "LC_TIME=C.UTF-8", "XDG_RUNTIME_DIR=/run/user/1")
	r := e.Run(RunOpt{}, envBin)
	if r.Exit != 0 {
		t.Fatalf("env: %+v", r)
	}
	out := "\n" + r.Stdout
	for _, gone := range []string{"ENVSCAN_TEST_CHILD_CANARY", "HTTP_PROXY", "GITHUB_TOKEN", "\nENVSCAN_ROOT="} {
		if strings.Contains(out, gone) {
			t.Errorf("%q reached the child", gone)
		}
	}
	for _, want := range []string{"\nPATH=", "\nHOME=/home/u\n", "\nLC_TIME=C.UTF-8\n", "\nXDG_RUNTIME_DIR=/run/user/1\n",
		"\nLC_ALL=C\n", "\nTERM=dumb\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in child env:\n%s", want, r.Stdout)
		}
	}
}

// A real child sees a kept path list without its network entries and a replaced network HOME.
func TestChildProcessSeesVettedPaths(t *testing.T) {
	const envBin = "/usr/bin/env"
	if _, err := os.Stat(envBin); err != nil {
		t.Skip("no /usr/bin/env")
	}
	root := t.TempDir()
	mkTree(t, root, map[string]string{"proc/self/mounts": "srv:/n /net nfs rw 0 0\n"})
	e := newTestEnv(t, root, nil, "LD_LIBRARY_PATH=/net/lib:/usr/lib", "HOME=/net/home/u")
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	r := e.Run(RunOpt{}, envBin)
	if r.Exit != 0 {
		t.Fatalf("env: %+v", r)
	}
	out := "\n" + r.Stdout
	if !strings.Contains(out, "\nLD_LIBRARY_PATH=/usr/lib\n") || strings.Contains(out, "/net/") {
		t.Errorf("child env not vetted:\n%s", r.Stdout)
	}
	if !strings.Contains(out, "\nHOME="+e.TempDir()+"/") {
		t.Errorf("network HOME not replaced:\n%s", r.Stdout)
	}
}
