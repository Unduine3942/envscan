package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is the child of the runCommand tests (the test binary started again).
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("ENVSCAN_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		in, _ := io.ReadAll(os.Stdin)
		fmt.Printf("out:%s:stdin=%d:lc=%s", strings.Join(os.Args[len(os.Args)-1:], ""), len(in), os.Getenv("LC_ALL"))
		fmt.Fprint(os.Stderr, "err")
		os.Exit(3)
	case "big":
		fmt.Print(strings.Repeat("x", 5000))
		os.Exit(0)
	case "sleep":
		time.Sleep(20 * time.Second)
	}
	os.Exit(0)
}

func helperSpec(mode string, timeout time.Duration) runSpec {
	exe, _ := os.Executable()
	return runSpec{Path: "/usr/bin/helper", Real: exe, Args: []string{"-test.run=TestHelperProcess", "--", "arg1"},
		Env: append(os.Environ(), "ENVSCAN_HELPER="+mode, "LC_ALL=C"), Dir: os.TempDir(), Timeout: timeout}
}

func TestRunCommandOutputAndExit(t *testing.T) {
	r := runCommand(context.Background(), helperSpec("echo", 30*time.Second), newChildSet())
	if r.Exit != 3 || r.Stdout != "out:arg1:stdin=0:lc=C" || r.Stderr != "err" || r.TimedOut || r.Truncated || r.Path != "/usr/bin/helper" {
		t.Fatalf("%+v", r)
	}
	rs := helperSpec("echo", 30*time.Second)
	rs.Merge = true
	if r := runCommand(context.Background(), rs, newChildSet()); r.Stdout != "out:arg1:stdin=0:lc=Cerr" || r.Stderr != "" {
		t.Fatalf("merged %+v", r)
	}
	rs = helperSpec("big", 30*time.Second)
	rs.MaxBytes = 100
	if r := runCommand(context.Background(), rs, newChildSet()); len(r.Stdout) != 100 || !r.Truncated || r.Exit != 0 {
		t.Fatalf("cap %d %v", len(r.Stdout), r.Truncated)
	}
}

func TestRunCommandTimeoutAndCancel(t *testing.T) {
	start := time.Now()
	r := runCommand(context.Background(), helperSpec("sleep", 300*time.Millisecond), newChildSet())
	if !r.TimedOut || r.Exit == 0 || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	kids := newChildSet()
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	r = runCommand(ctx, helperSpec("sleep", 30*time.Second), kids)
	if r.TimedOut || r.Exit == 0 || len(kids.kills) != 0 {
		t.Fatalf("cancel %+v", r)
	}
	r = runCommand(context.Background(), runSpec{Path: "/x", Real: "/definitely/missing/binary", Timeout: time.Second}, newChildSet())
	if r.Exit != -1 || r.Why == "" {
		t.Fatalf("start failure %+v", r)
	}
	if s := mergeOutput("ab", "cd", 3, new(bool)); s != "abc" {
		t.Fatal(s)
	}
}

func TestChildSetKillAll(t *testing.T) {
	c := newChildSet()
	n := 0
	id, _ := c.start(func() error { return nil }, func() { n++ })
	_, _ = c.start(func() error { return nil }, func() { n++ })
	c.finish(id, nil)
	c.killAll()
	if n != 1 {
		t.Fatal(n)
	}
}
