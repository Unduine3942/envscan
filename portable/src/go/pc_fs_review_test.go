package main

import (
	"fmt"
	"io/fs"
	"testing"
)

// mkdirErrEnv answers MkdirUnique with a fixed error (the engine's refusal of a resolved path).
type mkdirErrEnv struct {
	*fakeEnv
	err error
}

func (m mkdirErrEnv) MkdirUnique(string) (string, error) { return "", m.err }

func TestLocTestEngineRefusalsAndExhaustion(t *testing.T) {
	fe := newFakeEnv(t, t.TempDir())
	mustMkdir(t, fe.real("/opt"))
	desk := &Refusal{Path: "/opt", Reason: "Desktop and Documents are never written to"}
	l, _ := locTest(mkdirErrEnv{fe, desk}, xdgDirs{}, "opt", "/opt")
	eq(t, "skip", []string{l.state, l.skip, l.writable}, []string{"skipped", desk.Reason, ""})
	full := fmt.Errorf("/opt: no unique folder name left: %w", fs.ErrExist)
	l, _ = locTest(mkdirErrEnv{fe, full}, xdgDirs{}, "opt", "/opt")
	eq(t, "exhausted", []string{l.state, l.writable}, []string{"unknown", ""})
	eq(t, "dotdot", unsafeDir("/home/u/x/../Schreibtisch", xdgDirs{desktop: "/home/u/Schreibtisch"}),
		"the XDG Desktop and Documents directories are never written to")
}
