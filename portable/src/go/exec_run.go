// exec_run.go: running one child (port of es_exec / es_child / es_watch). The child gets stdin
// from the null device, the child environment, cwd "/" (or an own folder), its own process
// group (exec_proc_linux.go) and a timeout that kills the whole group; Cmd.WaitDelay bounds the
// wait for pipes a grandchild still holds. Output is capped at MaxBytes per stream.
package main

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

const (
	defaultMaxBytes = 4 << 20
	waitDelay       = 2 * time.Second
)

// Run is the Env method; the per-probe Env (engine_runner.go) passes its own context.
func (e *realEnv) Run(opt RunOpt, p string, args ...string) CmdResult {
	return e.runCtx(context.Background(), opt, p, args)
}

func (e *realEnv) runCtx(ctx context.Context, opt RunOpt, p string, args []string) CmdResult {
	if e.isStopping() {
		return CmdResult{Path: p, Args: args, Exit: 126, Why: "the scan is stopping (not executed)"}
	}
	if ok, why := e.Runnable(p); !ok {
		return CmdResult{Path: p, Args: args, Exit: 126, Why: why}
	}
	return e.runBackend(ctx, opt, p, args)
}

func (e *realEnv) cmdTimeout(opt RunOpt) time.Duration {
	if opt.Timeout > 0 {
		return opt.Timeout
	}
	return e.timeout
}

type runSpec struct {
	Path     string // logical path (reported)
	Real     string // what is executed
	Args     []string
	Env      []string
	Dir      string
	Timeout  time.Duration
	MaxBytes int
	Merge    bool
}

// capBuf keeps the first max bytes written to it.
type capBuf struct {
	max int
	b   []byte
	cut bool
}

func (c *capBuf) Write(p []byte) (int, error) {
	room := c.max - len(c.b)
	if room < len(p) {
		c.cut = true
		if room > 0 {
			c.b = append(c.b, p[:room]...)
		}
		return len(p), nil
	}
	c.b = append(c.b, p...)
	return len(p), nil
}

func runCommand(ctx context.Context, rs runSpec, kids *childSet) CmdResult {
	if rs.MaxBytes <= 0 {
		rs.MaxBytes = defaultMaxBytes
	}
	cctx, cancel := context.WithTimeout(ctx, rs.Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, rs.Real, rs.Args...)
	cmd.Env, cmd.Dir = rs.Env, rs.Dir
	out, errb := &capBuf{max: rs.MaxBytes}, &capBuf{max: rs.MaxBytes}
	cmd.Stdout, cmd.Stderr = out, errb
	setProcGroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = waitDelay
	res := CmdResult{Path: rs.Path, Args: rs.Args}
	start := time.Now()
	id, err := kids.start(cmd.Start, func() { _ = killGroupIfAlive(cmd) })
	if err != nil {
		res.Exit, res.Why, res.Duration = -1, err.Error(), time.Since(start)
		return res
	}
	waitErr := cmd.Wait()
	kids.finish(id, func() {
		if errors.Is(waitErr, exec.ErrWaitDelay) {
			_ = killGroup(cmd) // the child is gone; what it started still holds the pipes
		}
	})
	res.Duration = time.Since(start)
	res.TimedOut = errors.Is(cctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	res.Exit = exitStatus(cmd, waitErr)
	res.Stdout, res.Stderr = string(out.b), string(errb.b)
	res.Truncated = out.cut || errb.cut
	if rs.Merge {
		res.Stdout, res.Stderr = mergeOutput(res.Stdout, res.Stderr, rs.MaxBytes, &res.Truncated), ""
	}
	return res
}

// mergeOutput is es_cmd_merged: stderr appended after stdout, capped.
func mergeOutput(stdout, stderr string, max int, cut *bool) string {
	s := stdout + stderr
	if len(s) > max {
		*cut = true
		s = s[:max]
	}
	return s
}

// childSet: the running children, so that a signal or the end of the scan can kill them. A
// child is started and registered under the lock, and removed under the lock right after it was
// waited for, so killAll neither misses a child nor signals one that was already reaped. After
// killAll no child starts.
type childSet struct {
	mu     sync.Mutex
	next   int
	kills  map[int]func()
	closed bool
}

var errStopping = errors.New("the scan is stopping (not started)")

func newChildSet() *childSet { return &childSet{kills: map[int]func(){}} }

// start runs startFn and registers kill for the started child.
func (c *childSet) start(startFn func() error, kill func()) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errStopping
	}
	if err := startFn(); err != nil {
		return 0, err
	}
	c.next++
	c.kills[c.next] = kill
	return c.next, nil
}

// finish runs after (may be nil) and forgets the child, both under the lock.
func (c *childSet) finish(id int, after func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if after != nil {
		after()
	}
	delete(c.kills, id)
}

// killAll kills every running child and closes the set.
func (c *childSet) killAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, k := range c.kills {
		k()
	}
}
