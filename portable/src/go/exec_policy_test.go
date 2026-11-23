package main

import (
	"os"
	"strings"
	"testing"
)

func TestRunnableRefusals(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"proc/self/mounts": "srv:/n /mnt/nfs nfs rw 0 0\n",
		"home/u/.asdf/shims/node": "x", "usr/bin/git": "x", "home/u/.cargo/bin/cargo": "x"})
	e := newTestEnv(t, root, nil, "DOCKER_HOST=tcp://h:2375", "CONTAINER_HOST=x")
	cases := map[string]string{
		"/mnt/nfs/bin/x":           "on a network or autofs mount (not executed)",
		"/home/u/.ssh/helper":      "link to a credential store (not executed)",
		"/home/u/.asdf/shims/node": "version-manager shim (asdf, not executed)",
		"/opt/x/run.ps1":           "PowerShell shim (not executed)",
		"/c/Users/u/AppData/Local/Microsoft/WindowsApps/python.exe": "Windows app execution alias (not executed; may open the Microsoft Store)",
		"/usr/bin/docker": "DOCKER_HOST points to a remote engine (not executed)",
		"/usr/bin/podman": "CONTAINER_HOST or CONTAINER_CONNECTION selects a remote podman engine (not executed)",
	}
	for p, want := range cases {
		if ok, why := e.Runnable(p); ok || why != want {
			t.Errorf("%s: %v %q", p, ok, why)
		}
	}
	if ok, why := e.Runnable("/usr/bin/git"); !ok {
		t.Errorf("git: %s", why)
	}
	// rustup's marker needs the rustup executable in the folder (not there: not a shim)
	if ok, why := e.Runnable("/home/u/.cargo/bin/cargo"); !ok {
		t.Errorf("cargo: %s", why)
	}
	if r := e.Run(RunOpt{}, "/mnt/nfs/bin/x"); r.Exit != 126 || !strings.Contains(r.Why, "network") {
		t.Errorf("run refused: %+v", r)
	}
	if pathRuleWhy("/mnt/c/Windows/x.exe", true) == "" || pathRuleWhy("/mnt/c/Windows/x.exe", false) != "" || pathRuleWhy("/mnt/cd/x", true) != "" {
		t.Error("wsl rule")
	}
	if runnableOSWhy("/usr/bin/docker", map[string]string{"DOCKER_CONTEXT": "x"}) == "" || runnableOSWhy("/usr/bin/docker", map[string]string{"DOCKER_HOST": "unix:///x"}) != "" {
		t.Error("docker rule")
	}
}

func TestWhichSkipsUnsafeEntries(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil)
	if !e.pathSkip["/mnt/nfs/bin"] && len(e.rv.netmnts) > 0 {
		t.Error("net PATH entry kept")
	}
	if _, ok := e.whichPath(""); ok {
		t.Error("empty name")
	}
	if _, ok := e.whichPath("definitely-not-here"); ok {
		t.Error("found")
	}
}

func TestChildEnv(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil, "CDPATH=/x", "LC_ALL=de_DE.UTF-8", "DOCKER_CONTEXT=remote", "KEEP=1")
	env := strings.Join(e.childEnv(RunOpt{Env: []string{"XDG_CACHE_HOME=/c", "bad name=1"}}), "\n") + "\n"
	for _, want := range []string{"LC_ALL=C\n", "DOCKER_CONTEXT=default\n", "XDG_CACHE_HOME=/c\n", "GIT_TERMINAL_PROMPT=0\n", "TERM=dumb\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(env, "CDPATH") || strings.Contains(env, "bad name") || strings.Contains(env, "KEEP=") {
		t.Error("CDPATH, bad name or a variable outside the allowlist kept")
	}
	user := strings.Join(e.childEnv(RunOpt{UserLocale: true}), "\n")
	if !strings.Contains(user, "LC_ALL=de_DE.UTF-8") {
		t.Error("user locale")
	}
	e2 := newTestEnv(t, t.TempDir(), nil)
	if strings.Contains(strings.Join(e2.childEnv(RunOpt{UserLocale: true}), "\n"), "LC_ALL=") {
		t.Error("unset LC_ALL kept unset")
	}
}

// Only allowlisted scan-start variables (spec child_env_keep, exact names) reach a child; the
// spec overrides and the per-call extras still apply on top, and env.vars keeps everything.
func TestChildEnvAllowlist(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil, "ENVSCAN_TEST_CHILD_CANARY=canary-123", "HTTP_PROXY=http://u:pw@p:1",
		"https_proxy=http://u:pw@p:1", "GITHUB_TOKEN=ghp_abcdefghijklmnop", "LD_PRELOAD=/tmp/x.so", "NODE_OPTIONS=--require=x",
		"BASH_ENV=/tmp/b", "ENV=/tmp/e", "DOCKER_HOST=tcp://h:1", "LC_TIME=de_DE.UTF-8", "XDG_RUNTIME_DIR=/run/user/1",
		"path=/lower", "Home=/mixed", "LC_=x", "XDG_CONFIG_HOME=/home/u/.config", "PROGRAMFILES(X86)=/x86",
		"JAVA_HOME=/opt/jdk", "TERM=xterm-256color", "GIT_TERMINAL_PROMPT=1")
	env := "\n" + strings.Join(e.childEnv(RunOpt{Env: []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_DIR=/r/.git"}}), "\n") + "\n"
	for _, gone := range []string{"ENVSCAN_TEST_CHILD_CANARY", "canary-123", "HTTP_PROXY", "https_proxy", "GITHUB_TOKEN",
		"ghp_", "LD_PRELOAD", "NODE_OPTIONS", "BASH_ENV", "\nENV=", "DOCKER_HOST", "\npath=", "\nHome=", "(X86)",
		"ENVSCAN_ROOT", "ENVSCAN_TEST_OS"} {
		if strings.Contains(env, gone) {
			t.Errorf("%q reached the child", gone)
		}
	}
	for _, want := range []string{"\nPATH=/usr/bin:/bin:relative::/mnt/nfs/bin\n", "\nHOME=/home/u\n", "\nLC_TIME=de_DE.UTF-8\n",
		"\nXDG_RUNTIME_DIR=/run/user/1\n", "\nXDG_CONFIG_HOME=/home/u/.config\n", "\nLC_=x\n", "\nJAVA_HOME=/opt/jdk\n",
		"\nTMPDIR=", "\nTERM=dumb\n", "\nGIT_TERMINAL_PROMPT=0\n", "\nLC_ALL=C\n", "\nDOCKER_CONTEXT=default\n",
		"\nGIT_CONFIG_NOSYSTEM=1\n", "\nGIT_DIR=/r/.git\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %q in\n%s", want, env)
		}
	}
	if e.vars["ENVSCAN_TEST_CHILD_CANARY"] != "canary-123" || e.vars["HTTP_PROXY"] == "" {
		t.Error("the scan-start snapshot lost a variable")
	}
}

func TestChildKeepName(t *testing.T) {
	for name, want := range map[string]bool{"PATH": true, "HOME": true, "LC_ALL": true, "XDG_X": true, "_BPXK_A": true,
		"DOTNET_ROOT(X86)": false, "PROGRAMFILES(X86)": false, "path": false, "PATHX": false, "LC": false, "": false,
		"HTTPS_PROXY": false, "GIT_CONFIG_PARAMETERS": false} {
		if got := childKeepName(name); got != want {
			t.Errorf("childKeepName(%q) = %v", name, got)
		}
	}
	if len(spec.ChildEnvKeepNames) == 0 || len(spec.ChildEnvKeepPrefixes) == 0 {
		t.Fatal("child_env_keep missing from spec.json")
	}
}

// Kept variables holding paths are vetted (spec child_env home_paths, path_lists, other absolute
// paths) without touching them: refused homes become the empty folder (temp variables the
// scanner's temp folder), refused list entries are dropped (an emptied list is removed), any other
// refused absolute path is removed.
func TestChildEnvVetsKeptPaths(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"proc/self/mounts": "srv:/n /net nfs rw 0 0\nsrv:/m /mnt/nfs nfs4 rw 0 0\n"})
	e := newTestEnv(t, root, nil, "LD_LIBRARY_PATH=/net/lib:/usr/lib", "PATH=/net/bin:/usr/bin:relative::/mnt/nfs/x",
		"HOME=/net/home/u", "XDG_STATE_HOME=/home/u/.aws/state", "TMP=/mnt/nfs/tmp", "TEMP=/tmp/u",
		"JAVA_HOME=/net/jdk", "SSL_CERT_FILE=/home/u/.ssh/ca.pem", "GOROOT=/usr/lib/go", "OPENSSL_CONF=rel/conf",
		"XDG_DATA_DIRS=/net/share", "FONTCONFIG_PATH=/etc/fonts:/net/f", "LC_PAPER=/net/x", "XDG_CACHE_HOME=/var/cache/u")
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	vars := childVars(e.childEnv(RunOpt{}))
	want := map[string]string{"LD_LIBRARY_PATH": "/usr/lib", "PATH": "/usr/bin:relative:", "TMP": e.TempDir(),
		"TEMP": "/tmp/u", "GOROOT": "/usr/lib/go", "OPENSSL_CONF": "rel/conf", "FONTCONFIG_PATH": "/etc/fonts",
		"XDG_CACHE_HOME": "/var/cache/u"}
	for k, v := range want {
		if vars[k] != v {
			t.Errorf("%s=%q, want %q", k, vars[k], v)
		}
	}
	for _, k := range []string{"JAVA_HOME", "SSL_CERT_FILE", "XDG_DATA_DIRS", "LC_PAPER"} {
		if v, ok := vars[k]; ok {
			t.Errorf("%s=%q kept", k, v)
		}
	}
	for _, k := range []string{"HOME", "XDG_STATE_HOME"} {
		if v := vars[k]; !strings.HasPrefix(v, e.TempDir()+string(os.PathSeparator)) {
			t.Errorf("%s=%q not replaced by a folder in the temp folder", k, v)
		}
	}
	if e.vars["LD_LIBRARY_PATH"] != "/net/lib:/usr/lib" || e.vars["JAVA_HOME"] != "/net/jdk" {
		t.Error("the scan-start snapshot changed")
	}
	if got := childVars(e.childEnv(RunOpt{Env: []string{"HOME=/net/explicit"}}))["HOME"]; got != "/net/explicit" {
		t.Errorf("a probe's own extra HOME changed: %q", got)
	}
}

func TestChildEnvVetsNothingWhenLocal(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil, "LD_LIBRARY_PATH=/opt/a/lib:/usr/lib", "JAVA_HOME=/opt/jdk")
	vars := childVars(e.childEnv(RunOpt{}))
	if vars["LD_LIBRARY_PATH"] != "/opt/a/lib:/usr/lib" || vars["JAVA_HOME"] != "/opt/jdk" ||
		vars["PATH"] != "/usr/bin:/bin:relative::/mnt/nfs/bin" || vars["HOME"] != "/home/u" {
		t.Errorf("local values changed: %v", vars)
	}
	if len(spec.ChildEnvHomePaths) == 0 || len(spec.ChildEnvPathLists) == 0 {
		t.Fatal("child_env home_paths or path_lists missing from spec.json")
	}
}

func childVars(env []string) map[string]string {
	vars := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		vars[k] = v
	}
	return vars
}
