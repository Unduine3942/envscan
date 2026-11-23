//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHelperSpawner is a child that starts a grandchild holding its stdout, prints the
// grandchild's pid and exits at once (the grandchild keeps the pipe open).
func TestHelperSpawner(t *testing.T) {
	if os.Getenv("ENVSCAN_HELPER") != "spawn" {
		return
	}
	exe, _ := os.Executable()
	gc := exec.Command(exe, "-test.run=TestHelperProcess")
	gc.Env = append(os.Environ(), "ENVSCAN_HELPER=sleep")
	gc.Stdout = os.Stdout
	if err := gc.Start(); err != nil {
		os.Exit(5)
	}
	os.Stdout.WriteString(strconv.Itoa(gc.Process.Pid) + "\n")
	os.Exit(0)
}

func TestWaitDelayKillsTheGroup(t *testing.T) {
	rs := helperSpec("spawn", 30*time.Second)
	rs.Args = []string{"-test.run=TestHelperSpawner"}
	r := runCommand(context.Background(), rs, newChildSet())
	pid, err := strconv.Atoi(strings.TrimSpace(r.Stdout))
	if err != nil {
		t.Fatalf("%+v", r)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatal("grandchild still running after the wait delay")
}
