//go:build linux

// exec_linux.go: commands of the release build: PATH lookup and real children. ENVSCAN_ROOT
// (tests) prefixes file reads only: like envscan.sh, commands are looked up, vetted and run by
// their real paths.
package main

import (
	"context"
	"path/filepath"
)

// Which is es_which over the snapshot PATH.
func (e *realEnv) Which(name string) (string, bool) { return e.whichPath(name) }

// execRv: the resolver of executable paths (real paths).
func (e *realEnv) execRv() *resolver { return e.realRv }

// execTarget: the file that is executed for p (the real path; own scripts below the temp folder
// are real paths already).
func (e *realEnv) execTarget(p string) string {
	if e.underTemp(p) {
		return filepath.Clean(p)
	}
	return p
}

func (e *realEnv) runBackend(ctx context.Context, opt RunOpt, p string, args []string) CmdResult {
	rs := runSpec{Path: p, Real: e.execTarget(p), Args: args, Env: e.childEnv(opt), Dir: e.childDir(opt.Dir),
		Timeout: e.cmdTimeout(opt), MaxBytes: opt.MaxBytes, Merge: opt.MergeStderr}
	return runCommand(ctx, rs, e.children)
}
