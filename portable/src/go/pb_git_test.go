package main

import (
	"strings"
	"testing"
)

// pbGitSetup: git on PATH answering --list --show-origin with LISTING (lines as in the sh tests).
func pbGitSetup(t *testing.T, listing ...string) (*pbRecEnv, *Result) {
	t.Helper()
	e := pbNewEnv(t)
	e.PathBins["git"] = "/usr/bin/git"
	e.Cmds["git config --list --show-origin --no-includes"] = fakeCmd{Stdout: strings.Join(listing, "\n") + "\n"}
	return &pbRecEnv{fakeEnv: e}, newResult("pkg.sources")
}

func pbGitRuns(e *pbRecEnv) []string {
	out := []string{}
	for _, c := range e.Ran {
		if strings.HasPrefix(c, "git ") {
			out = append(out, c)
		}
	}
	return out
}

func TestGitLocalIncludeIsFollowedOnce(t *testing.T) {
	e, r := pbGitSetup(t, "file:/home/u/.gitconfig\tuser.name=Bob",
		"file:/home/u/.gitconfig\tinclude.path=~/inc/extra.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=/home/u/inc/extra.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=rel.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=~/missing.gitconfig")
	pbWrite(t, e.Root, map[string]string{"/home/u/inc/extra.gitconfig": "x", "/home/u/rel.gitconfig": "y"})
	e.Cmds["git config --list --no-includes --file /home/u/inc/extra.gitconfig"] = fakeCmd{Stdout: "http.proxy=http://incproxy.corp:3128\n"}
	e.Cmds["git config --list --no-includes --file /home/u/rel.gitconfig"] = fakeCmd{Stdout: "url.https://nexus.corp/git/.insteadof=https://github.com/\n"}
	items, entries := pbGitConfig(e, r)
	pbEq(t, "calls", pbGitRuns(e), []string{"git config --list --show-origin --no-includes",
		"git config --list --no-includes --file /home/u/inc/extra.gitconfig",
		"git config --list --no-includes --file /home/u/rel.gitconfig"})
	last := entries[len(entries)-1]
	pbEq(t, "included", last, pbGitEntry{"file:/home/u/rel.gitconfig", "url.https://nexus.corp/git/.insteadof=https://github.com/"})
	pbEq(t, "notes", [2]any{len(r.Notes), r.Status}, [2]any{0, StOK})
	first := items[0].(*Obj)
	pbEq(t, "item", []any{first.Str("origin"), first.Str("key"), first.vals["value"]},
		[]any{"file:/home/u/.gitconfig", "user.name", Named{Name: "user.name", Value: "Bob"}})
	// git runs in a new empty directory, discovery stopped at the scanner temp directory
	opt := e.opts[0]
	if opt.Dir == "" || !strings.HasPrefix(opt.Dir, e.TempDir()) || opt.Dir == e.TempDir() {
		t.Errorf("dir %q", opt.Dir)
	}
	pbEq(t, "env", opt.Env, []string{"GIT_CEILING_DIRECTORIES=" + e.TempDir()})
}

func TestGitIncludesNotReadMakeThePartial(t *testing.T) {
	e, r := pbGitSetup(t, "file:/home/u/.gitconfig\tinclude.path=/net/shared.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=~bob/x.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=%(prefix)/etc/x.gitconfig",
		"command line:\tinclude.path=relative.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=~/adir.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=C:/shared/x.gitconfig",
		"file:\"/home/u/caf\\303\\251/.gitconfig\"\tinclude.path=quoted.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=~/.git-credentials",
		"file:/home/u/.gitconfig\tinclude.path=nested.gitconfig")
	e.NetPaths = []string{"/net"}
	e.RefusedP["/home/u/.git-credentials"] = "credential store"
	pbWrite(t, e.Root, map[string]string{"/net/shared.gitconfig": "x", "/home/u/.git-credentials": "https://bob:CredPw9@git.corp\n",
		"/home/u/nested.gitconfig": "x"})
	pbMkdir(t, e.Root, "/home/u/adir.gitconfig")
	e.Cmds["git config --list --no-includes --file /home/u/nested.gitconfig"] = fakeCmd{Stdout: "core.editor=vi\ninclude.path=/srv/deeper.gitconfig\n"}
	_, entries := pbGitConfig(e, r)
	pbEq(t, "notes", r.Notes, []string{"git include not read (network path): /net/shared.gitconfig",
		"git include not read (not a local path): ~bob/x.gitconfig",
		"git include not read (not a local path): %(prefix)/etc/x.gitconfig",
		"git include not read (not a local path): relative.gitconfig",
		"git include not read (unreadable): /home/u/adir.gitconfig",
		"git include not read (not a local path): C:/shared/x.gitconfig",
		"git include not read (not a local path): quoted.gitconfig",
		"git include not read (credential store): /home/u/.git-credentials",
		"git include not read (nested include): /srv/deeper.gitconfig"})
	pbEq(t, "status", r.Status, StPartial)
	for _, c := range e.Ran {
		if strings.Contains(c, "shared") || strings.Contains(c, "deeper") || strings.Contains(c, "adir") || strings.Contains(c, "credentials") {
			t.Errorf("ran %s", c)
		}
	}
	pbEq(t, "nested entry", entries[len(entries)-2], pbGitEntry{"file:/home/u/nested.gitconfig", "core.editor=vi"})
}

func TestGitNetworkHomeIsNeverRead(t *testing.T) {
	e, r := pbGitSetup(t, "file:/etc/gitconfig\tinclude.path=~/x.gitconfig")
	e.NetPaths = []string{"/home/u"}
	e.Vars["GIT_DIR"] = "/work/repo/.git"
	pbGitConfig(e, r)
	pbEq(t, "notes", r.Notes, []string{"git home folder /home/u is on a network path: global git configuration from there is not read",
		"git include not read (network path): /home/u/x.gitconfig"})
	pbEq(t, "calls", pbGitRuns(e), []string{"git config --list --show-origin --no-includes"})
	env := strings.Join(e.opts[0].Env, " ")
	if !strings.Contains(env, "GIT_DIR=") || !strings.Contains(env, "HOME="+e.TempDir()) {
		t.Errorf("env %v", e.opts[0].Env)
	}
}

func TestGitConditionalIncludeIsOnlyNoted(t *testing.T) {
	e, r := pbGitSetup(t, "file:/home/u/.gitconfig\tincludeif.gitdir:~/work/.path=~/work.gitconfig",
		"file:/home/u/.gitconfig\tinclude.path=~/work.gitconfig")
	pbWrite(t, e.Root, map[string]string{"/home/u/work.gitconfig": "x"})
	e.Cmds["git config --list --no-includes --file /home/u/work.gitconfig"] = fakeCmd{Stdout: "includeif.onbranch:main.path=branch.gitconfig\n"}
	pbGitConfig(e, r)
	pbEq(t, "notes", r.Notes, []string{"git include not read (condition gitdir:~/work/): ~/work.gitconfig",
		"git include not read (condition onbranch:main): branch.gitconfig"})
	pbEq(t, "status", r.Status, StOK)
}

func TestGitOlderThan1710FallsBack(t *testing.T) {
	e, r := pbGitSetup(t)
	usage := fakeCmd{Exit: 129, Stderr: "error: unknown option `show-origin'\nusage: git config [options]\n"}
	e.Cmds["git config --list --show-origin --no-includes"] = usage
	e.Cmds["git config --list --no-includes"] = usage
	e.Cmds["git config --list"] = fakeCmd{Stdout: "http.proxy=http://oldproxy.corp:3128\ninclude.path=/etc/x.gitconfig\n"}
	_, entries := pbGitConfig(e, r)
	pbEq(t, "calls", pbGitRuns(e), []string{"git config --list --show-origin --no-includes",
		"git config --list --no-includes", "git config --list"})
	pbEq(t, "entries", entries, []pbGitEntry{{"unknown", "http.proxy=http://oldproxy.corp:3128"}, {"unknown", "include.path=/etc/x.gitconfig"}})
	pbEq(t, "notes", len(r.Notes), 0)
}

func TestGitFailureAndAbsence(t *testing.T) {
	e, r := pbGitSetup(t)
	e.Cmds["git config --list --show-origin --no-includes"] = fakeCmd{Exit: 128, Stderr: "fatal: bad config\n"}
	items, _ := pbGitConfig(e, r)
	pbEq(t, "items", len(items), 0)
	pbEq(t, "notes", r.Notes, []string{"git config --list failed (exit status 128)"})

	none := pbNewEnv(t)
	r2 := newResult("pkg.sources")
	items, _ = pbGitConfig(none, r2)
	pbEq(t, "no git", []any{len(items), r2.Status, len(none.Ran)}, []any{0, StOK, 0})
}

func TestGitURLsAndLines(t *testing.T) {
	en := []pbGitEntry{{"file:/h/.gitconfig", "url.https://nexus.corp/git/.insteadof=https://github.com/"},
		{"file:/h/.gitconfig", "credential.https://git.corp.username=bob"},
		{"file:/h/.gitconfig", "http.sslverify=false"}}
	pbEq(t, "urls", pbGitURLs(en), []SourceLine{{"git:file:/h/.gitconfig", "https://nexus.corp/git/ https://github.com/"},
		{"git:file:/h/.gitconfig", " false"}})
	pbEq(t, "lines", pbGitLines(en)[2], SourceLine{"git:file:/h/.gitconfig", "http.sslverify=false"})
}
