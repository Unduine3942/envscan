//go:build linux

// exec_proc_linux.go: process groups on Linux. Every child leads its own process group
// (Setpgid), so a timeout kills the child and everything it started: kill(-pgid, SIGKILL).
package main

import (
	"errors"
	"os/exec"
	"syscall"
)

func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return errors.New("not started")
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// killGroupIfAlive is killGroup for killAll: nothing is signalled once the child was reaped (its
// pid may be in use again).
func killGroupIfAlive(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return errors.New("not started")
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return err
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// exitStatus: the exit status, 128 + signal for a killed child (like sh $?).
func exitStatus(cmd *exec.Cmd, _ error) int {
	st := cmd.ProcessState
	if st == nil {
		return -1
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return st.ExitCode()
}
