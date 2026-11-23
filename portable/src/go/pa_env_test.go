package main

import (
	"reflect"
	"runtime"
	"testing"
)

func TestEnvVars(t *testing.T) {
	e := paLinux(t)
	e.Vars = map[string]string{"PATH": "/usr/bin", "A1": "x", "A": "y", "GITHUB_TOKEN": "ghp_secret",
		"SSH_PRIVATE_KEY": "-----BEGIN-----\nAAAA\n-----END-----", "BAD\tNAME": "v"}
	r := paRun(t, e, "env.vars")
	proc := mustGet(r, "process").(*Obj)
	if got := proc.Keys(); !reflect.DeepEqual(got, []string{"A", "A1", "GITHUB_TOKEN", "PATH", "SSH_PRIVATE_KEY"}) {
		t.Errorf("keys %v", got)
	}
	if v, _ := proc.Get("GITHUB_TOKEN"); v != (Named{Name: "GITHUB_TOKEN", Value: "ghp_secret"}) {
		t.Errorf("value kind %#v", v)
	}
	paWant(t, r, map[string]any{"redacted": "2", "machine": nil, "user": nil})
	if !reflect.DeepEqual(r.Data.Keys(), []string{"process", "redacted", "machine", "user"}) || r.Status != StOK {
		t.Errorf("keys %v status %s", r.Data.Keys(), r.Status)
	}
	e.NoRedact = true
	paWant(t, paRun(t, e, "env.vars"), map[string]any{"redacted": "0"})
	e.Vars = map[string]string{}
	if r := paRun(t, e, "env.vars"); r.Status != StPartial {
		t.Errorf("empty env: %s", r.Status)
	}
}

func TestEnvPath(t *testing.T) {
	root := paTree(t, map[string]string{"usr/bin/": "", "work/bin/": ""})
	e := newFakeEnv(t, root)
	e.MountTab = []Mount{{"/dev/sda1", "/", "ext4", "rw"}, {"srv:/x", "/net", "nfs", "rw"}}
	e.NetPaths = []string{"/net"}
	e.Vars = map[string]string{"PATH": "/usr/bin:/nope:/net/bin:bin:/usr/bin:", "PWD": "/work"}
	r := paRun(t, e, "env.path")
	ents := paPlain(mustGet(r, "entries")).([]any)
	if len(ents) != 6 {
		t.Fatalf("entries %v", ents)
	}
	want := []map[string]any{
		{"path": "/usr/bin", "exists": true, "writable": true, "network": false, "duplicate": false, "relative": false},
		{"path": "/nope", "exists": false, "writable": false, "network": false},
		{"path": "/net/bin", "exists": nil, "writable": nil, "network": true},
		{"path": "bin", "exists": true, "network": nil, "relative": true},
		{"path": "/usr/bin", "duplicate": true},
		{"path": "", "exists": true, "relative": true},
	}
	for i, w := range want {
		got := ents[i].(map[string]any)
		for k, v := range w {
			if got[k] != v {
				t.Errorf("entry %d %s = %v, want %v", i, k, got[k], v)
			}
		}
	}
	paWant(t, r, map[string]any{"missing_count": "1", "relative_count": "2", "writable_count": "4", "separator": ":"})
	if r.Facts["path_relative"] != "2" || r.Facts["path_missing"] != "1" {
		t.Errorf("facts %v", r.Facts)
	}
	delete(e.Vars, "PWD")
	e.Vars["PATH"] = ""
	paWant(t, paRun(t, e, "env.path"), map[string]any{"entries": []any{}, "missing_count": "0"})
}

func TestSessionContext(t *testing.T) {
	e := newFakeEnv(t, "")
	r := paRun(t, e, "session.context")
	paWant(t, r, map[string]any{"type": "unknown", "interactive": false, "display": nil, "display_available": false,
		"terminals": map[string]any{"stdin": false, "stdout": false, "stderr": false}})
	e.Tty[1] = true
	e.Vars = map[string]string{"WAYLAND_DISPLAY": "wayland-0", "TERM": "xterm"}
	paWant(t, paRun(t, e, "session.context"), map[string]any{"type": "console", "display": "wayland-0", "terminal": "xterm"})
	e.Tty = map[int]bool{}
	e.Vars = map[string]string{"INVOCATION_ID": "x"}
	paWant(t, paRun(t, e, "session.context"), map[string]any{"type": "service"})
	e.Vars = map[string]string{"SSH_CONNECTION": "10.0.0.1 5 10.0.0.2 22"}
	e.Tty[0] = true
	r = paRun(t, e, "session.context")
	paWant(t, r, map[string]any{"type": "ssh", "interactive": true, "tty": true, "ssh_connection": "10.0.0.1 5 10.0.0.2 22"})
	if r.Facts["session_type"] != "ssh" || r.Facts["display"] != "false" {
		t.Errorf("facts %v", r.Facts)
	}
}

func TestShellInfo(t *testing.T) {
	root := paTree(t, map[string]string{"etc/shells": "# shells\n/bin/sh\n/bin/bash\n\n", "bin/dash": "",
		"opt/a/pwsh": "", "opt/b/pwsh": ""})
	e := newFakeEnv(t, root)
	if err := symlinkOrSkip(t, "dash", root+"/bin/sh"); err != nil {
		t.Logf("no symlink: %v", err)
	}
	e.Vars = map[string]string{"SHELL": "/bin/bash", "PATH": "/opt/a:/opt/b:/opt/a"}
	e.UmaskV, e.HasUmask = 0o022, true
	e.PathBins["bash"] = "/bin/bash"
	e.Cmds["bash --version"] = fakeCmd{Stdout: "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nCopyright\n"}
	r := paRun(t, e, "shell.info")
	paWant(t, r, map[string]any{"current_shell": paNoShell, "shell_version": runtime.Version(), "login_shell": "/bin/bash",
		"bash_version": "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)", "zsh_version": nil,
		"shells": []any{"/bin/sh", "/bin/bash"}, "umask": "0022", "language_mode": nil})
	if r.Facts["bash_version"] != "5.1.16" || r.Facts["login_shell"] != "/bin/bash" {
		t.Errorf("facts %v", r.Facts)
	}
	if fi, err := e.Lstat("/bin/sh"); err == nil && fi.Type == TypeLink {
		paWant(t, r, map[string]any{"sh_target": "dash"})
	}
	if pw := paPlain(mustGet(r, "powershell_installed")).([]any); runtime.GOOS != "windows" && len(pw) != 0 {
		// fixture files are not executable (mode 0644): none is listed
		t.Errorf("pwsh %v", pw)
	}
}

func TestShellUserland(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	for _, n := range []string{"sed", "awk", "grep", "tar", "date"} {
		e.PathBins[n] = "/usr/bin/" + n
	}
	e.PathBins["perl"] = "/usr/bin/perl"
	e.Cmds["sed --version"] = fakeCmd{Stdout: "sed (GNU sed) 4.8\n"}
	e.Cmds["awk --version"] = fakeCmd{Stderr: "awk: not an option: --version\n", Exit: 2}
	e.Cmds["awk -W version"] = fakeCmd{Stdout: "mawk 1.3.4 20200120\nCopyright\n"}
	e.Cmds["grep --version"] = fakeCmd{Stderr: "BusyBox v1.36.1 multi-call binary.\n", Exit: 1}
	e.Cmds["tar --version"] = fakeCmd{Stdout: "bsdtar 3.6.2 - libarchive 3.6.2\n"}
	e.Cmds["date --version"] = fakeCmd{Stdout: "date (uutils coreutils) 0.0.27\n"}
	r := paRun(t, e, "shell.userland")
	paWant(t, r, map[string]any{"sed": "gnu", "awk": "other", "grep": "busybox", "tar": "bsd", "date": "other",
		"find": nil, "perl": "/usr/bin/perl"})
	det := paPlain(mustGet(r, "details")).(map[string]any)
	if aw := det["awk"].(map[string]any); aw["version_line"] != "mawk 1.3.4 20200120" || aw["path"] != "/usr/bin/awk" {
		t.Errorf("awk %v", aw)
	}
	if r.Facts["userland"] != "sed=gnu awk=other grep=busybox tar=bsd date=other" {
		t.Errorf("fact %q", r.Facts["userland"])
	}
	e2 := newFakeEnv(t, "")
	r = paRun(t, e2, "shell.userland")
	paWant(t, r, map[string]any{"details": map[string]any{}, "sed": nil, "perl": nil})
	if r.Status != StOK || r.Facts["userland"] != "" {
		t.Errorf("distroless: %s %v", r.Status, r.Facts)
	}
}
