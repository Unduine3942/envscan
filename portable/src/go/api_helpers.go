// api_helpers.go: the sh probe-context helpers every probe uses (owner: main).
package main

import (
	"errors"
	"io/fs"
	"strings"
)

// tool is sh es_tool: find NAME on PATH and run it unless it must not run. Records the source
// "run NAME ARGS" (with the resolved path, like sh) and a partial note on timeout. Exit 127 when
// absent (nothing recorded), 126 when refused (note "<path>: <why>").
func tool(e Env, r *Result, opt RunOpt, name string, args ...string) CmdResult {
	p, ok := e.Which(name)
	if !ok {
		return CmdResult{Exit: 127, Why: "not found"}
	}
	return runPath(e, r, opt, p, args...)
}

// runPath is sh es_cmd for an already resolved path (also refuses what must not run).
func runPath(e Env, r *Result, opt RunOpt, p string, args ...string) CmdResult {
	if ok, why := e.Runnable(p); !ok {
		r.Note("%s: %s", p, why)
		return CmdResult{Path: p, Args: args, Exit: 126, Why: why}
	}
	r.Src("run %s", strings.TrimSpace(p+" "+strings.Join(args, " ")))
	c := e.Run(opt, p, args...)
	if c.TimedOut {
		t := opt.Timeout
		if t == 0 {
			t = e.Timeout()
		}
		r.Partial("timed out after " + t.String() + ": " + strings.TrimSpace(p+" "+strings.Join(args, " ")))
	}
	return c
}

// needTool is sh es_need: like tool, but a present tool that fails or prints nothing makes the
// probe partial ("<cmd> printed nothing" / "<cmd> failed (exit status N)"). ok = usable output.
func needTool(e Env, r *Result, opt RunOpt, name string, args ...string) (CmdResult, bool) {
	c := tool(e, r, opt, name, args...)
	if c.Exit == 126 || c.Exit == 127 {
		return c, false
	}
	label := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if c.Exit != 0 || strings.TrimSpace(c.Stdout) == "" {
		if !c.TimedOut {
			if c.Exit == 0 {
				r.Partial(label + " printed nothing")
			} else {
				r.Partial(label + " failed (exit status " + itoa(c.Exit) + ")")
			}
		}
		return c, false
	}
	return c, true
}

// readText is sh es_read + es_text_ok: the text of PATH (at most max bytes, 0 = 1 MiB) and a
// "read PATH" source. Missing file: ok=false, nothing recorded. Refused: note. Binary/UTF-16:
// partial "<path> not read: UTF-16 or binary content".
func readText(e Env, r *Result, path string, max int) (string, bool) {
	if max <= 0 {
		max = 1 << 20
	}
	text, truncated, err := e.ReadText(path, max)
	switch {
	case err == nil:
		r.Src("read %s", path)
		if truncated {
			r.Truncated = true
		}
		return text, true
	case errors.Is(err, ErrBinary):
		r.Src("read %s", path)
		r.Partial(path + " not read: UTF-16 or binary content")
	case isRefusal(err):
		r.Note("%s", err.Error())
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, ErrNotRegular):
	default:
		r.Note("%s: %v", path, err)
	}
	return "", false
}

// readFirstLine is sh es_read1: the first line of a small file without its CR (blanks kept);
// an empty file is ok=false.
func readFirstLine(e Env, r *Result, path string) (string, bool) {
	text, ok := readText(e, r, path, 65536)
	if !ok || text == "" {
		return "", false
	}
	first, _, _ := strings.Cut(text, "\n")
	return strings.TrimSuffix(first, "\r"), true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
