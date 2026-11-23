//go:build !linux && envscan_dev

// exec_other.go: the development build (Windows, -tags envscan_dev), for tests only. It never starts a child: a
// command exists only when ENVSCAN_TEST_CMDS names a JSON file
// {"name args": {"stdout": "...", "stderr": "...", "exit": N}}, and Run returns that entry.
// Neither the hook nor the variable exists in a build without the envscan_dev tag.
package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
)

type testCmd struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Exit   int    `json:"exit"`
}

var testCmdCache = struct {
	sync.Mutex
	byFile map[string]map[string]testCmd
}{byFile: map[string]map[string]testCmd{}}

// loadTestCmds reads the table named by ENVSCAN_TEST_CMDS (empty when unset or broken).
func loadTestCmds(vars map[string]string) map[string]testCmd {
	file := vars["ENVSCAN_TEST_CMDS"]
	if file == "" {
		return nil
	}
	testCmdCache.Lock()
	defer testCmdCache.Unlock()
	if t, ok := testCmdCache.byFile[file]; ok {
		return t
	}
	t := map[string]testCmd{}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &t)
	}
	testCmdCache.byFile[file] = t
	return t
}

func testCmdKey(p string, args []string) string {
	return strings.TrimSpace(p[strings.LastIndexByte(p, '/')+1:] + " " + strings.Join(args, " "))
}

// execRv: the test build vets executables below ENVSCAN_ROOT (nothing is executed).
func (e *realEnv) execRv() *resolver { return e.rv }

// Which finds NAME only in the test table (as /usr/bin/NAME).
func (e *realEnv) Which(name string) (string, bool) {
	base := name[strings.LastIndexByte(name, '/')+1:]
	for k := range loadTestCmds(e.vars) {
		if first, _, _ := strings.Cut(k, " "); first == base && base != "" {
			return "/usr/bin/" + base, true
		}
	}
	return "", false
}

func (e *realEnv) runBackend(_ context.Context, opt RunOpt, p string, args []string) CmdResult {
	key := testCmdKey(p, args)
	c, ok := loadTestCmds(e.vars)[key]
	if !ok {
		return CmdResult{Path: p, Args: args, Exit: 127, Why: "no test command for " + key}
	}
	res := CmdResult{Path: p, Args: args, Stdout: c.Stdout, Stderr: c.Stderr, Exit: c.Exit}
	if opt.MergeStderr {
		res.Stdout, res.Stderr = c.Stdout+c.Stderr, ""
	}
	return res
}
