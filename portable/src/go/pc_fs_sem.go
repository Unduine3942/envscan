// pc_fs_sem.go: fs.semantics and fs.exec_test (port of src/sh/27-fs.sh, Linux; owner: probes-c).
// Test files are made only in new directories of Env.MkdirUnique and removed with RemoveOwn.
package main

import (
	"errors"
	"io/fs"
	"regexp"
	"strings"
)

func init() {
	registerProbe("fs.semantics", probeFSSemantics)
	registerProbe("fs.exec_test", probeFSExecTest)
}

var permDeniedRe = regexp.MustCompile(`(?i)permission|not permitted|privilege`)

// semResult: case sensitivity, symbolic and hard links in a new directory (sh es_cs, es_sl, es_hl).
type semResult struct{ cs, sl, slnote, hl string }

func semTest(e Env, r *Result) semResult {
	s := semResult{}
	d, err := e.MkdirUnique(e.TempDir())
	if err != nil {
		r.Partial("could not create a test directory in the scanner's temp directory")
		return s
	}
	defer func() { _ = e.RemoveOwn(d) }()
	if err := e.WriteNew(d+"/CaseTest", nil, 0o600); err != nil {
		r.Partial("could not create a test directory in the scanner's temp directory")
		return s
	}
	s.cs = boolText(!e.Exists(d + "/casetest"))
	if err := e.Symlink("CaseTest", d+"/symlink-test"); err == nil {
		if st, lerr := e.Lstat(d + "/symlink-test"); lerr == nil && st.Type == TypeLink {
			s.sl = "ok"
		} else {
			s.sl, s.slnote = "error", "the symbolic link was not created as a link"
		}
	} else if errors.Is(err, fs.ErrPermission) || permDeniedRe.MatchString(err.Error()) {
		s.sl = "denied"
	} else {
		s.sl, s.slnote = "error", firstLine(err.Error())
	}
	s.hl = boolText(e.Link(d+"/CaseTest", d+"/hardlink-test") == nil)
	return s
}

// getconfNum runs getconf NAME DIR when present; the number it prints, else "".
func getconfNum(e Env, r *Result, name, dir string) string {
	c := tool(e, r, RunOpt{}, "getconf", name, dir)
	if c.Exit != 0 {
		return ""
	}
	if l := firstLine(c.Stdout); isNum(l) {
		return l
	}
	return ""
}

func probeFSSemantics(e Env, r *Result) {
	tmp := e.TempDir()
	r.Src("create and remove test files in a new private directory under the scanner temp directory (%s)", tmp)
	s := semTest(e, r)
	nmax := getconfNum(e, r, "NAME_MAX", tmp)
	pmax := getconfNum(e, r, "PATH_MAX", tmp)
	if nmax == "" {
		r.Note("getconf NAME_MAX gave no value")
	}
	r.Data.Set("case_sensitive", boolOrNil(s.cs)).Set("symlink", strOrNil(s.sl))
	if s.slnote != "" {
		r.Data.Set("symlink_detail", s.slnote)
	}
	r.Data.Set("hardlink", boolOrNil(s.hl)).Set("junction", nil).Set("long_paths_enabled", nil).
		Set("short_names", nil).Set("name_max", num(nmax)).Set("path_max", num(pmax)).Set("tested_in", tmp)
	r.Fact("case_sensitive", s.cs)
	r.Fact("symlink", s.sl)
	r.Fact("symlink_detail", s.slnote)
}

// ---------------------------------------------------------------- fs.exec_test

const execScript = "#!/bin/sh\nprintf \"envscan-exec-ok\\n\"\n"

var blockedRe = regexp.MustCompile(`(?i)permission denied|not permitted|operation not permitted`)

// execTry is sh es_exec_try: write a #!/bin/sh script into a new directory in DIR and run it.
func execTry(e Env, r *Result, dir string) (outcome, detail string) {
	d, err := e.MkdirUnique(dir)
	if err != nil {
		return "error", "could not create a new test directory"
	}
	defer func() { _ = e.RemoveOwn(d) }()
	f := d + "/envscan-exec.sh"
	if err := e.WriteNew(f, []byte(execScript), 0o700); err != nil {
		return "error", "could not write the test script"
	}
	if ok, why := e.Runnable(f); !ok {
		return "error", "not run: " + why
	}
	c := runPath(e, r, RunOpt{}, f)
	errText := c.Stderr
	if errText == "" {
		errText = c.Why
	}
	outcome = "error"
	if c.Exit == 0 && strings.Contains(c.Stdout, "envscan-exec-ok") {
		outcome = "ok"
	} else if c.Exit == 126 || blockedRe.MatchString(errText) {
		outcome = "blocked"
	}
	detail = firstLine(errText)
	if detail == "" {
		detail = "exit status " + itoa(c.Exit)
	}
	return outcome, detail
}

func execItem(id, p, outcome, detail string) *Obj {
	return NewObj().Set("id", id).Set("path", p).Set("kind", "sh-script").Set("outcome", outcome).Set("detail", detail)
}

func execCandidates(e Env) [][2]string {
	home := e.Home()
	c := [][2]string{{"temp", e.TempDir()}, {"home", home}, {"home_local", ""}, {"home_bin", ""}}
	if home != "" {
		c[2][1], c[3][1] = home+"/.local", home+"/bin"
	}
	return c
}

func probeFSExecTest(e Env, r *Result) {
	r.Src("create a new private directory in the scanner temp directory and under HOME, ~/.local, ~/bin; write a #!/bin/sh script there, chmod 700, run it, remove the directory")
	x := readXDGDirs(e, r)
	noSh := !e.Exists("/bin/sh")
	arr := []any{}
	blocked, n, nosh := "", 0, 0
	for _, c := range execCandidates(e) {
		id, p := c[0], c[1]
		if p == "" {
			continue
		}
		if _, skip, why := netOrRefused(e, p); skip {
			arr = append(arr, execItem(id, p, "skipped", why))
			continue
		}
		st, err := e.Stat(p)
		if err != nil || st.Type != TypeDir || !access(e, st, 2) {
			continue
		}
		if w := unsafeDir(p, x); w != "" {
			arr = append(arr, execItem(id, p, "skipped", w))
			continue
		}
		if noSh {
			arr = append(arr, execItem(id, p, "skipped", "no /bin/sh: the #!/bin/sh test script cannot run here (not a noexec result)"))
			nosh++
			continue
		}
		out, det := execTry(e, r, p)
		if out == "blocked" {
			blocked += id + " "
		}
		arr = append(arr, execItem(id, p, out, det))
		n++
	}
	r.Data.Set("results", arr)
	switch {
	case nosh > 0 && n == 0:
		r.Partial("no /bin/sh: the exec test script could not run (no test was made; this is not a noexec result)")
	case n == 0:
		r.Partial("no writable per-user directory to test")
	}
	r.Fact("exec_blocked", blocked)
}
