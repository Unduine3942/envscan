// pb_git.go: git configuration for pkg.sources (port of src/sh/24-git.sh).
//
// git runs in a new empty directory below the scanner temp directory (e.MkdirUnique), with
// GIT_CEILING_DIRECTORIES at its parent and GIT_DIR, GIT_WORK_TREE and the other repository
// variables unset ("NAME=" in RunOpt.Env), so that no repository configuration is read. It runs
// with --no-includes; the scanner reads each unconditional include one level deep, only from a
// local path, and notes the others (see the header of 24-git.sh for the note texts).
package main

import (
	"regexp"
	"strings"
)

// pbGitEntry is one "origin TAB key=value" line of git config --list --show-origin.
type pbGitEntry struct{ Origin, KV string }

func (g pbGitEntry) key() string   { k, _, _ := strings.Cut(g.KV, "="); return k }
func (g pbGitEntry) value() string { _, v, _ := strings.Cut(g.KV, "="); return v }

type pbGit struct {
	e       Env
	r       *Result
	opt     RunOpt
	noinc   bool   // --no-includes is known (git >= 1.7.10)
	home    string // the user's HOME, for ~/ includes
	seen    []string
	entries []pbGitEntry
}

var (
	pbGitOptFail = regexp.MustCompile(`(?i)unknown (option|switch)|usage:`)
	pbIncludeRe  = regexp.MustCompile(`(?i)^include\.path$`)
	pbIncludeIf  = regexp.MustCompile(`(?i)^includeif\..*\.path$`)
)

var pbGitRepoVars = []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
	"GIT_NAMESPACE", "GIT_OBJECT_DIRECTORY"}

// pbGitNetVars: HOME, XDG_CONFIG_HOME, GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM values that are
// not local paths (network or autofs mount, or a link into a credential store).
func pbGitNetVars(e Env) [][2]string {
	out := [][2]string{}
	for _, v := range []string{"HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"} {
		if x, _ := e.Getenv(v); x != "" && !pbLocal(e, nil, x) {
			out = append(out, [2]string{v, x})
		}
	}
	return out
}

// pbGitEnv is sh es_git_env: each variable of pbGitNetVars is replaced, for git only, by an
// empty local directory (a missing file in it for GIT_CONFIG_*), so git reads nothing there.
func pbGitEnv(r *Result, vars [][2]string, scratch string) []string {
	env := []string{}
	for _, nv := range vars {
		v, x := nv[0], nv[1]
		repl := scratch
		if strings.HasPrefix(v, "GIT_CONFIG_") {
			repl = scratch + "/none"
		}
		env = append(env, v+"="+repl)
		label, which := v, "global"
		if v == "HOME" {
			label = "git home folder"
		}
		if v == "GIT_CONFIG_SYSTEM" {
			which = "system"
		}
		r.Partial(label + " " + x + " is on a network path: " + which + " git configuration from there is not read")
	}
	return env
}

func (g *pbGit) run(args ...string) CmdResult {
	return tool(g.e, g.r, g.opt, "git", args...)
}

func (g *pbGit) failed(c CmdResult) bool {
	if pbGitOptFail.MatchString(c.Stderr) {
		return false
	}
	g.r.Partial("git config --list failed (exit status " + itoa(c.Exit) + ")")
	return true
}

// list is sh es_git_list (with the fallbacks for a git before 2.8 and before 1.7.10).
func (g *pbGit) list() bool {
	g.noinc = true
	c := g.run("config", "--list", "--show-origin", "--no-includes")
	if c.Exit == 0 {
		for _, l := range lines(c.Stdout) {
			if strings.TrimSpace(l) != "" {
				o, kv, _ := strings.Cut(l, "\t")
				g.entries = append(g.entries, pbGitEntry{o, kv})
			}
		}
		return true
	}
	if c.Exit == 126 || c.Exit == 127 || g.failed(c) {
		return false
	}
	if c = g.run("config", "--list", "--no-includes"); c.Exit != 0 {
		if g.failed(c) {
			return false
		}
		g.noinc = false
		if c = g.run("config", "--list"); c.Exit != 0 {
			g.r.Partial("git config --list failed (exit status " + itoa(c.Exit) + ")")
			return false
		}
	}
	for _, l := range lines(c.Stdout) {
		if strings.TrimSpace(l) != "" {
			g.entries = append(g.entries, pbGitEntry{"unknown", l})
		}
	}
	return true
}

func (g *pbGit) noread(reason, p string) { g.r.Partial("git include not read (" + reason + "): " + p) }

func (g *pbGit) cond(key, v string) {
	c := key[strings.Index(key, ".")+1:]
	c = c[:strings.LastIndex(c, ".")]
	g.r.Note("git include not read (condition %s): %s", c, v)
}

// incpath is sh es_git_incpath: the file an include.path names; ok=false when not a local path.
func (g *pbGit) incpath(origin, v string) (string, bool) {
	switch {
	case strings.HasPrefix(v, "~/"):
		if g.home == "" {
			return v, false
		}
		return strings.TrimSuffix(g.home, "/") + "/" + v[2:], true
	case strings.HasPrefix(v, "/"):
		return v, true
	case v == "", strings.HasPrefix(v, "~"), strings.HasPrefix(v, "%("), strings.HasPrefix(v, `\`):
		return v, false
	case len(v) >= 2 && v[1] == ':' && pbIsLetter(v[0]):
		return v, false
	case strings.HasPrefix(origin, "file:/"):
		return pbDir(strings.TrimPrefix(origin, "file:")) + "/" + v, true
	}
	return v, false
}

func pbIsLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

// include is sh es_git_include: read one unconditional include, one level deep.
func (g *pbGit) include(origin, v string, out *[]pbGitEntry) {
	gi, ok := g.incpath(origin, v)
	if !ok {
		g.noread("not a local path", gi)
		return
	}
	if why := g.e.Refused(gi); why != "" {
		g.noread(pbRefusalWord(why), gi)
		return
	}
	if _, ok, why := pbResolve(g.e, gi); !ok {
		g.noread(pbRefusalWord(why), gi)
		return
	}
	for _, s := range g.seen {
		if s == gi {
			return
		}
	}
	g.seen = append(g.seen, gi)
	fi, err := g.e.Stat(gi)
	if err != nil && !isRefusal(err) {
		return // missing: git skips it too
	}
	if err != nil || fi.Type != TypeFile {
		g.noread("unreadable", gi)
		return
	}
	args := []string{"config", "--list"}
	if g.noinc {
		args = append(args, "--no-includes")
	}
	c := g.run(append(args, "--file", gi)...)
	if c.Exit != 0 {
		g.noread("unreadable", gi)
		return
	}
	for _, l := range lines(c.Stdout) {
		if strings.TrimSpace(l) == "" {
			continue
		}
		*out = append(*out, pbGitEntry{"file:" + gi, l})
		k, val, _ := strings.Cut(l, "=")
		if pbIncludeRe.MatchString(k) {
			g.noread("nested include", val)
		} else if pbIncludeIf.MatchString(k) {
			g.cond(k, val)
		}
	}
}

func pbRefusalWord(why string) string {
	if strings.Contains(why, "credential") {
		return "credential store"
	}
	return "network path"
}

// includes is sh es_git_includes.
func (g *pbGit) includes() {
	if !g.noinc {
		return
	}
	extra := []pbGitEntry{}
	for _, en := range g.entries {
		k := en.key()
		if pbIncludeRe.MatchString(k) {
			g.include(en.Origin, en.value(), &extra)
		} else if pbIncludeIf.MatchString(k) {
			g.cond(k, en.value())
		}
	}
	g.entries = append(g.entries, extra...)
}

// pbGitConfig is sh es_git_config: the git_config list and the raw entries (for the endpoint,
// proxy and TLS checks).
func pbGitConfig(e Env, r *Result) ([]any, []pbGitEntry) {
	g := &pbGit{e: e, r: r}
	g.home, _ = e.Getenv("HOME")
	if _, ok := e.Which("git"); ok {
		g.prepare()
	}
	items := []any{}
	for _, en := range g.entries {
		if en.KV == "" {
			continue
		}
		v := strings.NewReplacer("\r", " ", "\n", " ").Replace(en.value())
		items = append(items, NewObj().Set("origin", en.Origin).Set("key", en.key()).
			Set("value", Named{Name: en.key(), Value: v}))
	}
	return items, g.entries
}

// prepare makes the empty working directory, sets the child environment and lists.
func (g *pbGit) prepare() {
	cwd, err := g.e.MkdirUnique(g.e.TempDir())
	if err != nil {
		g.r.Partial("could not create an empty directory for git config")
		return
	}
	defer g.e.RemoveOwn(cwd)
	env := []string{"GIT_CEILING_DIRECTORIES=" + g.e.TempDir()}
	for _, v := range pbGitRepoVars {
		if _, set := g.e.Getenv(v); set {
			env = append(env, v+"=")
		}
	}
	if nv := pbGitNetVars(g.e); len(nv) > 0 {
		scratch, err := g.e.MkdirUnique(g.e.TempDir())
		if err != nil {
			g.r.Partial("could not create an empty directory for git config")
			return
		}
		defer g.e.RemoveOwn(scratch)
		env = append(env, pbGitEnv(g.r, nv, scratch)...)
	}
	g.opt = RunOpt{Dir: cwd, Env: env}
	if g.list() {
		g.includes()
	}
}

// pbGitLines: "git:<origin> TAB key=value" (sh git_lines.txt).
func pbGitLines(entries []pbGitEntry) []SourceLine {
	out := []SourceLine{}
	for _, en := range entries {
		out = append(out, SourceLine{Source: "git:" + en.Origin, Text: en.KV})
	}
	return out
}

// pbGitURLs: "git:<origin> TAB <subsection> <value>" (sh git_urls.txt): the URL subsection of
// url.<base>.insteadOf, http.<url>.*, lfs.<url>.* and the values; credential.* is left out.
func pbGitURLs(entries []pbGitEntry) []SourceLine {
	out := []SourceLine{}
	for _, en := range entries {
		k := en.key()
		sec, rest, _ := strings.Cut(k, ".")
		if strings.ToLower(sec) == "credential" {
			continue
		}
		sb := ""
		if i := strings.LastIndex(rest, "."); i >= 0 {
			sb = rest[:i]
		}
		out = append(out, SourceLine{Source: "git:" + en.Origin, Text: sb + " " + en.value()})
	}
	return out
}
