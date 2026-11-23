package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Review fixes of the engine (items of the Go port review; see the report of the fix round).

func TestUnsafeDirFoldsDotDot(t *testing.T) {
	xdg := []string{"/home/u/Schreibtisch"}
	if unsafeDirWhy("/home/u/x/../Schreibtisch/y", xdg) == "" {
		t.Error("xdg dir reached through .. not refused")
	}
	if unsafeDirWhy("/home/u/x/..", nil) != "" {
		t.Error("plain folder refused")
	}
}

func TestMkdirUniqueRefusesXdgThroughDotDot(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"home/u/Schreibtisch/": "", "home/u/x/": ""})
	e := newTestEnv(t, root, nil, "XDG_DESKTOP_DIR=/home/u/Schreibtisch")
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.MkdirUnique("/home/u/x/../Schreibtisch"); !isRefusal(err) {
		t.Fatalf("got %v", err)
	}
}

func TestOwnPathsAreCleaned(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil)
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	if e.underTemp(e.TempDir() + "/../x") {
		t.Error("underTemp accepted ..")
	}
	d, err := e.MkdirUnique(e.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if e.inOwn(d + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "x") {
		t.Error("inOwn accepted ..")
	}
	if err := e.WriteNew(d+"/../escape", []byte("x"), 0o600); !isRefusal(err) {
		t.Errorf("write through ..: %v", err)
	}
}

var hexName = regexp.MustCompile(`^(envscan|\.envscan-t)\.[0-9a-f]{16}$`)

func TestRandomOwnNames(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil)
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	if !hexName.MatchString(filepath.Base(e.TempDir())) {
		t.Errorf("temp name %s", filepath.Base(e.TempDir()))
	}
	d, err := e.MkdirUnique(e.TempDir())
	if err != nil || !hexName.MatchString(filepath.Base(d)) {
		t.Fatalf("%s %v", d, err)
	}
	old := randSuffix
	t.Cleanup(func() { randSuffix = old })
	randSuffix = func() string { return "0000000000000000" }
	if err := os.Mkdir(filepath.Join(e.TempDir(), ".envscan-t.0000000000000000"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := e.MkdirUnique(e.TempDir()); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("exhaustion: %v", err)
	}
}

func TestStoppingRefusesNewWork(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil)
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	tmp := e.TempDir()
	e.cleanup()
	if _, err := e.MkdirUnique(tmp); err == nil {
		t.Error("MkdirUnique after cleanup")
	}
	if r := e.Run(RunOpt{}, "/usr/bin/git"); r.Exit != 126 || !strings.Contains(r.Why, "stopping") {
		t.Errorf("Run after cleanup: %+v", r)
	}
}

func TestRunnerRemovesFoldersOfTimedOutProbe(t *testing.T) {
	rn, _ := newTestRunner(t, nil, map[string]string{})
	if err := rn.e.initTemp(); err != nil {
		t.Fatal(err)
	}
	made := make(chan string, 1)
	late := make(chan error, 1)
	release := make(chan struct{})
	rn.funcs = map[string]probeFunc{"t.slow": func(e Env, r *Result) {
		d, err := e.MkdirUnique(e.TempDir())
		if err != nil {
			made <- ""
			return
		}
		made <- d
		<-release
		_, err = e.MkdirUnique(e.TempDir())
		late <- err
	}}
	rn.probes = []SpecProbe{{ID: "t.slow", Title: "slow", Tier: "default", Scope: "machine"}}
	recs := rn.runAll("/out")
	if recs[0].Res.Status != StTimeout {
		t.Fatalf("status %s", recs[0].Res.Status)
	}
	d := <-made
	if d == "" {
		t.Fatal("probe could not make its folder")
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Errorf("folder of the timed-out probe left: %v", err)
	}
	close(release)
	select {
	case err := <-late:
		if err == nil {
			t.Error("timed-out probe made a new folder")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not finish")
	}
}

func TestRealMountsAddedToNetTable(t *testing.T) {
	realTable := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(realTable, []byte("srv:/r /mnt/realnfs nfs4 rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := realMountsFiles
	t.Cleanup(func() { realMountsFiles = old })
	realMountsFiles = []string{realTable}
	root := t.TempDir()
	mkTree(t, root, map[string]string{"proc/self/mounts": "srv:/n /mnt/nfs nfs rw 0 0\n"})
	e := newTestEnv(t, root, nil)
	for _, p := range []string{"/mnt/nfs/x", "/mnt/realnfs/x"} {
		if e.Refused(p) != whyNet || e.realRv.refusedWhy(p) != whyNet {
			t.Errorf("%s: %q %q", p, e.Refused(p), e.realRv.refusedWhy(p))
		}
	}
	if len(e.Mounts()) != 1 {
		t.Errorf("reported mounts changed: %+v", e.Mounts())
	}
}

// needScanBuild skips tests that run runMain in a non-Linux build without -tags envscan_dev
// (that build never scans).
func needScanBuild(t *testing.T) {
	t.Helper()
	if checkBuild(map[string]string{"ENVSCAN_ROOT": "/x", "ENVSCAN_TEST_OS": "linux"}) != nil {
		t.Skip("this build never scans (non-Linux without -tags envscan_dev)")
	}
}

func TestRootRefusal(t *testing.T) {
	rv := &resolver{netmnts: []string{"/mnt/realnfs"}}
	cases := map[string]string{"/mnt/realnfs/fixture": whyNet, `\\srv\share\fixture`: whyNet,
		"/home/u/.ssh/fixture": whyCred, "/home/u/fixtures": ""}
	for root, want := range cases {
		if got := rootRefusedWhy(root, rv); got != want {
			t.Errorf("%s: %q want %q", root, got, want)
		}
	}
	needScanBuild(t)
	var out, errb bytes.Buffer
	code := runMain(nil, &out, &errb, []string{`ENVSCAN_ROOT=\\srv\share\fixture`, "ENVSCAN_TEST_OS=linux"})
	if code != 2 || !strings.Contains(errb.String(), "ENVSCAN_ROOT") || out.Len() != 0 {
		t.Errorf("exit %d stderr %q", code, errb.String())
	}
}

func TestOpenedPathRecheck(t *testing.T) {
	e := newTestEnv(t, `C:\root`, nil)
	e.rv.root = "/srv/root"
	e.rv.netmnts = []string{"/mnt/nfs"}
	cases := map[string]string{"/srv/root/etc/os-release": "", "/srv/root/home/u/.ssh/id_rsa": whyCredLink,
		"/srv/root/mnt/nfs/x": whyNet, "/mnt/nfs/x": whyNet, "/home/u/.aws/credentials": whyCredLink,
		"/srv/rootx/home/u/.ssh/id_rsa": whyCredLink, "/etc/hosts (deleted)": ""}
	for p, want := range cases {
		if got := e.openedWhy(p, e.rv); got != want {
			t.Errorf("%s: %q want %q", p, got, want)
		}
	}
}

func TestChildEnvReplacesRefusedHomes(t *testing.T) {
	root := t.TempDir()
	mkTree(t, root, map[string]string{"proc/self/mounts": "srv:/n /mnt/nfs nfs rw 0 0\n"})
	e := newTestEnv(t, root, nil, "HOME=/mnt/nfs/home/u", "XDG_CONFIG_HOME=/home/u/.ssh/cfg",
		"XDG_CACHE_HOME=/var/cache/u", "XDG_DATA_HOME=relative/data")
	if err := e.initTemp(); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{}
	for _, kv := range e.childEnv(RunOpt{}) {
		k, v, _ := strings.Cut(kv, "=")
		vars[k] = v
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME"} {
		v := vars[k]
		if !strings.HasPrefix(v, e.TempDir()) {
			t.Errorf("%s=%s", k, v)
			continue
		}
		if fi, err := os.Stat(v); err != nil || !fi.IsDir() {
			t.Errorf("%s: %v", k, err)
		}
		if ents, _ := os.ReadDir(v); len(ents) != 0 {
			t.Errorf("%s not empty", k)
		}
	}
	if vars["XDG_CACHE_HOME"] != "/var/cache/u" || vars["XDG_DATA_HOME"] != "relative/data" {
		t.Errorf("kept values changed: %v", vars)
	}
	if strings.Contains(strings.Join(e.childEnv(RunOpt{Env: []string{"HOME=/x"}}), "\n"), "HOME=/mnt/nfs") {
		t.Error("network HOME passed on")
	}
}

func TestExplicitOutRefusals(t *testing.T) {
	for _, out := range []string{"/home/u/.ssh/out", "/home/u/.aws/../.ssh", `\\srv\share\out`, "/mnt/realnfs/out"} {
		o := defaultOptions()
		o.Out = out
		e := newTestEnv(t, t.TempDir(), o)
		e.realRv.netmnts = []string{"/mnt/realnfs"}
		_, err := e.pickOut()
		var fe *fatalError
		if !errors.As(err, &fe) || !strings.Contains(err.Error(), "--out") {
			t.Errorf("%s: %v", out, err)
		}
	}
}

func TestRunnablePassesReason(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil)
	if ok, why := e.Runnable("relative/tool"); ok || why != "not an absolute path (not executed)" {
		t.Errorf("%v %q", ok, why)
	}
}

func TestExecDirRules(t *testing.T) {
	const me, other = 1000, 1001
	cases := []struct {
		dirMode         uint32
		dirUID, fileUID int
		bad             bool
	}{
		{0o755, 0, 0, false},
		{0o777, 0, 0, true},      // world-writable, no sticky
		{0o1777, 0, 0, false},    // sticky, file owned by root
		{0o1777, 0, me, false},   // sticky, file ours
		{0o1777, 0, other, true}, // sticky, file of someone else
		{0o775, other, me, true}, // group-writable, folder of someone else
		{0o775, me, me, false},   // group-writable, our folder
		{0o775, 0, other, false}, // group-writable, root's folder
		{0o1777, -1, -1, false},  // owners unknown: only the mode rule
		{0o777, -1, -1, true},
	}
	for _, c := range cases {
		if got := execDirWhy(c.dirMode, c.dirUID, c.fileUID, me) != ""; got != c.bad {
			t.Errorf("%+v: %v", c, got)
		}
	}
	if parentDir("/tool") != "/" || parentDir("/usr/bin/x") != "/usr/bin" {
		t.Error("parentDir")
	}
}

func TestHandoffFactStaysInternal(t *testing.T) {
	e := newTestEnv(t, t.TempDir(), nil)
	e.publishFacts(map[string]string{"pkg_proxy_handoff": "raw", "proxy": "true"})
	if e.Fact("pkg_proxy_handoff") != "raw" {
		t.Error("later probes must see the hand-off")
	}
	if _, ok := e.allFacts()["pkg_proxy_handoff"]; ok {
		t.Error("hand-off passed to the report")
	}
}
