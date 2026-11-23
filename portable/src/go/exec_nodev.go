//go:build !linux && !envscan_dev

// exec_nodev.go: a non-Linux build without the envscan_dev tag refuses to scan (sys_nodev.go);
// it has no commands at all.
package main

import "context"

func (e *realEnv) Which(string) (string, bool) { return "", false }

func (e *realEnv) execRv() *resolver { return e.rv }

func (e *realEnv) runBackend(_ context.Context, _ RunOpt, p string, args []string) CmdResult {
	return CmdResult{Path: p, Args: args, Exit: 127, Why: "no commands in this build"}
}
