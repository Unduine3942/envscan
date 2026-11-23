package main

import (
	"testing"
)

func basicMounts() []Mount {
	return []Mount{
		{Device: "/dev/sda1", Dir: "/", Type: "ext4", Options: "rw,relatime"},
		{Device: "proc", Dir: "/proc", Type: "proc", Options: "rw,nosuid,nodev,noexec"},
		{Device: "/dev/sdb1", Dir: "/mnt/data disk", Type: "ext4", Options: "rw,noexec"},
		{Device: "/dev/sdc1", Dir: `/mnt/back\slash`, Type: "xfs", Options: "rw"},
		{Device: "tmpfs", Dir: "/tmp", Type: "tmpfs", Options: "rw,nosuid, noexec"},
		{Device: "srv:/export/home", Dir: "/home/u", Type: "nfs4", Options: "rw,vers=4.2"},
	}
}

func TestMountsDecodedAndKeyPaths(t *testing.T) {
	e := linuxBasic(t)
	e.MountTab = basicMounts()
	e.Vars["HOME"] = "/home/u"
	r := run(e, "fs.mounts", probeFSMounts)
	ms := map[string]*Obj{}
	for _, m := range objs(t, get(t, r.Data, "mounts")) {
		ms[m.Str("mount")] = m
	}
	eq(t, "data disk type", ms["/mnt/data disk"].Str("fstype"), "ext4")
	if ms[`/mnt/back\slash`] == nil {
		t.Fatal("backslash mount missing")
	}
	eq(t, "tmp options", strs(t, get(t, ms["/tmp"], "options")), []string{"rw", "nosuid", "noexec"})
	kp := obj(t, get(t, r.Data, "key_paths"))
	eq(t, "key paths", kp.Keys(), []string{"/", "/tmp", "/var/tmp", "/dev/shm", "/home/u"})
	eq(t, "tmp noexec", get(t, obj(t, get(t, kp, "/tmp")), "noexec"), true)
	eq(t, "count", get(t, r.Data, "count"), NumText("6"))
	eq(t, "noexec_temp", r.Facts["noexec_temp"], "/tmp\n")
	eq(t, "root_ro", r.Facts["root_ro"], "false")
	eq(t, "source", r.Sources, []string{"read /proc/self/mounts (at scan start)"})
	empty := run(newFakeEnv(t, ""), "fs.mounts", probeFSMounts)
	eq(t, "no table", empty.Status, StPartial)
	eq(t, "no table key_paths", obj(t, get(t, empty.Data, "key_paths")).Len(), 0)
}

func TestMountsCapped(t *testing.T) {
	e := newFakeEnv(t, "")
	for i := 0; i < 305; i++ {
		e.MountTab = append(e.MountTab, Mount{Device: "d", Dir: "/m" + itoa(i), Type: "ext4", Options: "ro"})
	}
	r := run(e, "fs.mounts", probeFSMounts)
	eq(t, "capped", len(objs(t, get(t, r.Data, "mounts"))), 300)
	eq(t, "truncated", r.Truncated, true)
}

func TestLocationsWriteOnlyInOwnDirs(t *testing.T) {
	e := newRooted(t)
	e.Vars["HOME"] = "/home/u"
	e.Vars["TMPDIR"] = "/scantmp"
	writeFile(t, e.Root, "/home/u/.config/user-dirs.dirs", "XDG_DESKTOP_DIR=\"$HOME/Schreibtisch\"\nXDG_DOCUMENTS_DIR=\"$HOME/\"\n")
	mustMkdir(t, e.real("/home/u/Schreibtisch"))
	mustMkdir(t, e.real("/home/u/OneDrive"))
	e.Fs["/home/u"] = Statfs{BlockSize: 4096, Bavail: 2560}
	e.Fs["/tmp"] = Statfs{BlockSize: 1024, Bavail: 4096}
	e.MountTab = []Mount{{Dir: "/", Type: "ext4", Options: "rw"}, {Dir: "/tmp", Type: "tmpfs", Options: "rw,noexec"},
		{Dir: "/net", Type: "nfs", Options: "rw"}}
	e.FactsIn["cwd"] = "/net/proj"
	e.FactsIn["script_dir"] = "/home/u/OneDrive"
	e.RefusedP["/home/u/bin"] = "credential store"
	r := run(e, "fs.locations", probeFSLocations)
	locs := map[string]*Obj{}
	for _, l := range objs(t, get(t, r.Data, "locations")) {
		locs[l.Str("id")] = l
	}
	eq(t, "home writable", get(t, locs["home"], "writable"), true)
	eq(t, "home free", get(t, locs["home"], "free_mb"), NumText("10"))
	eq(t, "tmp noexec", get(t, locs["tmp"], "noexec"), true)
	eq(t, "tmp free", get(t, locs["tmp"], "free_mb"), NumText("4"))
	eq(t, "opt absent", get(t, locs["opt"], "exists"), false)
	eq(t, "cwd network", []any{get(t, locs["cwd"], "network"), get(t, locs["cwd"], "exists"), locs["cwd"].Str("note")},
		[]any{true, nil, "not tested: on a network or autofs mount (nfs)"})
	eq(t, "cred link", locs["home_bin"].Str("note"), "not tested: link to a credential store")
	eq(t, "sync", locs["script_dir"].Str("note"), "not tested: synchronised (cloud) folders are never written to")
	eq(t, "leftovers home", e.leftovers(t, "/home/u"), []string{})
	eq(t, "verdict", r.Facts["install_writable"], "true")
	eq(t, "free_home", r.Facts["free_home_mb"], "10")
	eq(t, "free_tmp", r.Facts["free_tmp_mb"], "4")
	eq(t, "status (df failed for some)", r.Status, StPartial)
	x := readXDGDirs(e, newResult("x"))
	eq(t, "xdg desktop", x.desktop, "/home/u/Schreibtisch")
	eq(t, "xdg documents disabled", x.documents, "")
	eq(t, "xdg unsafe", unsafeDir("/home/u/Schreibtisch/sub", x), "the XDG Desktop and Documents directories are never written to")
	eq(t, "desktop", unsafeDir("/home/u/Desktop", x), "Desktop and Documents are never written to")
}

func TestInstallVerdict(t *testing.T) {
	eq(t, "all absent", installVerdict([]string{"home\t/h\t-\t-\t-\tnot_writable", "opt\t/opt\t-\t-\t-\tabsent"}), "false")
	eq(t, "skipped", installVerdict([]string{"home\t/h\t-\t-\t-\tskipped", "tmp\t/tmp\t-\t-\t-\twritable"}), "")
}

func TestSemanticsInOwnTempDir(t *testing.T) {
	e := newRooted(t)
	bin(e.fakeEnv, "getconf NAME_MAX /scantmp", fakeCmd{Stdout: "255\n"})
	e.Cmds["getconf PATH_MAX /scantmp"] = fakeCmd{Stdout: "4096\n"}
	r := run(e, "fs.semantics", probeFSSemantics)
	if cs := get(t, r.Data, "case_sensitive"); cs != true && cs != false {
		t.Errorf("case_sensitive %v", cs)
	}
	switch sl := get(t, r.Data, "symlink"); sl {
	case "ok", "denied", "error":
	default:
		t.Errorf("symlink %v", sl)
	}
	eq(t, "hardlink", get(t, r.Data, "hardlink"), true)
	eq(t, "name_max", get(t, r.Data, "name_max"), NumText("255"))
	eq(t, "path_max", get(t, r.Data, "path_max"), NumText("4096"))
	eq(t, "tested_in", get(t, r.Data, "tested_in"), "/scantmp")
	eq(t, "removed", e.leftovers(t, "/scantmp"), []string{})
	r2 := run(newRooted(t), "fs.semantics", probeFSSemantics)
	eq(t, "no getconf", hasNote(r2, "getconf NAME_MAX gave no value"), true)
	eq(t, "no getconf name_max", get(t, r2.Data, "name_max"), nil)
}

func TestExecTest(t *testing.T) {
	e := newRooted(t)
	e.Vars["HOME"] = "/home/u"
	writeFile(t, e.Root, "/bin/sh", "")
	mustMkdir(t, e.real("/home/u/bin"))
	e.Cmds["envscan-exec.sh"] = fakeCmd{Stdout: "envscan-exec-ok\n"}
	e.MountTab = []Mount{{Dir: "/", Type: "ext4", Options: "rw"}, {Dir: "/home/u/bin", Type: "nfs4", Options: "rw"}}
	r := run(e, "fs.exec_test", probeFSExecTest)
	res := map[string]*Obj{}
	for _, o := range objs(t, get(t, r.Data, "results")) {
		res[o.Str("id")] = o
	}
	eq(t, "temp ok", res["temp"].Str("outcome"), "ok")
	eq(t, "home ok", res["home"].Str("outcome"), "ok")
	eq(t, "bin skipped", []string{res["home_bin"].Str("outcome"), res["home_bin"].Str("detail")},
		[]string{"skipped", "on a network or autofs mount (nfs4)"})
	eq(t, "removed temp", e.leftovers(t, "/scantmp"), []string{})
	eq(t, "removed home", e.leftovers(t, "/home/u"), []string{})
	eq(t, "status", r.Status, StOK)
	e.Cmds["envscan-exec.sh"] = fakeCmd{Stderr: "sh: permission denied\n", Exit: 126}
	r2 := run(e, "fs.exec_test", probeFSExecTest)
	eq(t, "blocked fact", r2.Facts["exec_blocked"], "temp home ")
}

func TestExecTestWithoutBinSh(t *testing.T) {
	e := newRooted(t)
	e.Vars["HOME"] = "/home/u"
	r := run(e, "fs.exec_test", probeFSExecTest)
	for _, o := range objs(t, get(t, r.Data, "results")) {
		eq(t, "outcome", o.Str("outcome"), "skipped")
	}
	eq(t, "status", r.Status, StPartial)
	eq(t, "note", hasNote(r, "no /bin/sh"), true)
	eq(t, "nothing ran", len(e.Ran), 0)
	eq(t, "fact", r.Facts["exec_blocked"], "")
}

func TestAccessBits(t *testing.T) {
	e := newFakeEnv(t, "")
	e.IdsV = Ids{EUID: 1000, EGID: 1000, Groups: []int{27}}
	eq(t, "owner", access(e, FileInfo{UID: 1000, Mode: 0o600}, 2), true)
	eq(t, "group", access(e, FileInfo{UID: 0, GID: 27, Mode: 0o660}, 2), true)
	eq(t, "group no", access(e, FileInfo{UID: 0, GID: 27, Mode: 0o640}, 2), false)
	eq(t, "other", access(e, FileInfo{UID: 0, GID: 0, Mode: 0o666}, 2), true)
	eq(t, "egid", access(e, FileInfo{UID: 0, GID: 1000, Mode: 0o660}, 4), true)
	e.IdsV = Ids{EUID: 0}
	eq(t, "root", access(e, FileInfo{UID: 5, Mode: 0}, 2), true)
	eq(t, "substr", []string{substr("abc", 0, 2), substr("abc", 2, 9), substr("abc", 5, 1)}, []string{"a", "bc", ""})
	eq(t, "mount_src fact", func() string { e.FactsIn["mount_src"] = "run mount"; return mountSource(e) }(), "run mount")
}
