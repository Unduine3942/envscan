//go:build !linux

// exec_proc_other.go: the development build (Windows) has no process groups; a timeout kills
// the child only. Used by the tests of runCommand; scans of this build never start a child.
package main

import (
	"errors"
	"os/exec"
)

func setProcGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return errors.New("not started")
	}
	return cmd.Process.Kill()
}

func killGroupIfAlive(cmd *exec.Cmd) error { return killGroup(cmd) }

func exitStatus(cmd *exec.Cmd, _ error) int {
	st := cmd.ProcessState
	if st == nil {
		return -1
	}
	if c := st.ExitCode(); c >= 0 {
		return c
	}
	return 128 + 9
}
