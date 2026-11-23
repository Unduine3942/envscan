//go:build !linux && envscan_dev

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTestCommandHook(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cmds.json")
	table := `{"uname -s": {"stdout": "Linux\n"}, "uname -n": {"stdout": "box\n"}, "uname -r": {"stdout": "6.1-microsoft\n"},
		"uname -m": {"stdout": "aarch64\n"}, "git --version": {"stdout": "git version 2.43.0\n", "stderr": "w", "exit": 0}}`
	if err := os.WriteFile(f, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, t.TempDir(), nil, "ENVSCAN_TEST_CMDS="+f)
	if e.host != "box" || e.arch != "arm64" || !e.wsl || e.Fact("wsl") != "true" {
		t.Fatalf("uname %+v %s %s", e.uname, e.host, e.arch)
	}
	p, ok := e.Which("git")
	if !ok || p != "/usr/bin/git" {
		t.Fatal(p)
	}
	r := e.Run(RunOpt{MergeStderr: true}, p, "--version")
	if r.Exit != 0 || r.Stdout != "git version 2.43.0\nw" {
		t.Fatalf("%+v", r)
	}
	if r := e.Run(RunOpt{}, p, "status"); r.Exit != 127 {
		t.Fatalf("%+v", r)
	}
	if _, ok := e.Which("nope"); ok {
		t.Fatal("nope")
	}
	if err := checkBuild(map[string]string{"ENVSCAN_ROOT": "/x"}); err == nil {
		t.Fatal("checkBuild")
	}
	e2 := newTestEnv(t, t.TempDir(), nil)
	if _, err := e2.Uname(); err == nil || e2.host != "unknown" {
		t.Fatal("no table")
	}
	if _, err := e2.Rlimit(RlNofile); err == nil {
		t.Fatal("rlimit")
	}
}
