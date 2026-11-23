// pc_fs_loc.go: fs.locations and the write-safety rules shared with fs.exec_test (port of
// src/sh/27-fs.sh, Linux; owner: probes-c). Writes go only through Env.MkdirUnique/RemoveOwn.
package main

import (
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

func init() {
	registerProbe("fs.locations", probeFSLocations)
}

// xdgDirs is sh es_xdg_dirs: the XDG Desktop and Documents directories ("" when unset or disabled).
type xdgDirs struct{ desktop, documents string }

func readXDGDirs(e Env, r *Result) xdgDirs {
	x := xdgDirs{}
	x.desktop, _ = e.Getenv("XDG_DESKTOP_DIR")
	x.documents, _ = e.Getenv("XDG_DOCUMENTS_DIR")
	home := e.Home()
	cfg, _ := e.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = home + "/.config"
	}
	if home != "" {
		if text, ok := readText(e, r, cfg+"/user-dirs.dirs", 65536); ok {
			x = xdgFromFile(x, text, home)
		}
	}
	x.desktop = xdgEnabled(x.desktop, home)
	x.documents = xdgEnabled(x.documents, home)
	return x
}

func xdgFromFile(x xdgDirs, text, home string) xdgDirs {
	for _, l := range lines(text) {
		k, v, ok := strings.Cut(l, "=")
		if !ok || (k != "XDG_DESKTOP_DIR" && k != "XDG_DOCUMENTS_DIR") {
			continue
		}
		v = unquote(v)
		if strings.HasPrefix(v, "$HOME") {
			v = home + strings.TrimPrefix(v, "$HOME")
		}
		if k == "XDG_DESKTOP_DIR" && x.desktop == "" {
			x.desktop = v
		} else if k == "XDG_DOCUMENTS_DIR" && x.documents == "" {
			x.documents = v
		}
	}
	return x
}

// xdgEnabled is sh es_xdg_enabled: DIR normalised, or "" when it is HOME or an ancestor of HOME.
func xdgEnabled(dir, home string) string {
	xe := normDir(dir)
	if home == "" {
		home = "/nonexistent"
	}
	if strings.HasPrefix(normDir(home)+"/", strings.TrimSuffix(xe, "/")+"/") {
		return ""
	}
	return xe
}

var syncMarks = []string{"/onedrive", "/dropbox", "/google drive", "/googledrive", "/my drive/",
	"/library/mobile documents/", "/library/cloudstorage/", "/icloud drive", "/iclouddrive", "/box/",
	"/box sync/", "/nextcloud", "/owncloud", "/seafile", "/pcloud", "/mega/", "/synologydrive"}

// unsafeDir is sh es_unsafe_dir: the reason the scanner must never write in P ("" = allowed).
func unsafeDir(p string, x xdgDirs) string {
	p = path.Clean(p) // ".." folded before matching
	l := strings.ToLower(p) + "/"
	if strings.Contains(l, "/desktop/") || strings.Contains(l, "/documents/") {
		return "Desktop and Documents are never written to"
	}
	for _, m := range syncMarks {
		if strings.Contains(l, m) {
			return "synchronised (cloud) folders are never written to"
		}
	}
	up := normDir(p) + "/"
	for _, xd := range []string{x.desktop, x.documents} {
		if xd != "" && strings.HasPrefix(up, xd+"/") {
			return "the XDG Desktop and Documents directories are never written to"
		}
	}
	return ""
}

// netOrRefused: the place is on a network/autofs mount or refused; why is the user-facing reason.
func netOrRefused(e Env, p string) (fstype string, skip bool, why string) {
	if m, ok := e.MountOf(p); ok {
		fstype = m.Type
	}
	ref := e.Refused(p)
	if (fstype == "" || !isNetworkFSType(fstype)) && ref == "" {
		return fstype, false, ""
	}
	if !isNetworkFSType(fstype) && credRefusal(ref) {
		return fstype, true, "link to a credential store"
	}
	why = "on a network or autofs mount"
	if fstype != "" {
		why += " (" + fstype + ")"
	}
	return fstype, true, why
}

// location is one candidate of fs.locations (sh es_loc_test results; "" = unknown/null).
type location struct {
	id, path, exists, writable, free, fstype, noexec, network, skip, state string
}

func locCandidates(e Env) [][2]string {
	home := e.Home()
	tmpdir, _ := e.Getenv("TMPDIR")
	sub := func(s string) string {
		if home == "" {
			return ""
		}
		return home + s
	}
	return [][2]string{{"tmpdir", tmpdir}, {"tmp", "/tmp"}, {"var_tmp", "/var/tmp"}, {"dev_shm", "/dev/shm"},
		{"home", home}, {"home_local", sub("/.local")}, {"home_bin", sub("/bin")}, {"opt", "/opt"},
		{"usr_local", "/usr/local"}, {"cwd", scanCwd(e)}, {"script_dir", e.Fact("script_dir")}}
}

// locTest is sh es_loc_test: mkdir a new test directory in P and remove it, never touching a
// network, credential, Desktop/Documents or synchronised place.
func locTest(e Env, x xdgDirs, id, p string) (location, bool) {
	l := location{id: id, path: p}
	fstype, skip, why := netOrRefused(e, p)
	l.fstype = fstype
	if m, ok := e.MountOf(p); ok {
		l.noexec, l.network = boolText(flagsOf(m.Options).noexec), boolText(isNetworkFSType(m.Type))
	}
	if skip {
		if why != "link to a credential store" {
			l.network = "true"
		}
		l.skip, l.state = why, "skipped"
		return l, true
	}
	l.exists = boolText(isDir(e, p))
	if w := unsafeDir(p, x); w != "" {
		l.skip, l.state = w, "skipped"
		return l, true
	}
	if l.exists != "true" {
		l.state = "absent"
		return l, true
	}
	var refused string
	if l.writable, l.state, refused = mkdirTest(e, p); refused != "" {
		l.skip, l.state = refused, "skipped"
		return l, true
	}
	free, ok := freeMB(e, p)
	l.free = free
	return l, ok
}

// mkdirTest: writable / not_writable / unknown (an inconclusive test, e.g. no unique name
// left) for directory P. refused is the engine's Desktop/Documents/synchronised reason when the
// resolved place is one of those (the place is then skipped, like the text rule).
func mkdirTest(e Env, p string) (writable, state, refused string) {
	d, err := e.MkdirUnique(p)
	if err == nil {
		_ = e.RemoveOwn(d)
		return "true", "writable", ""
	}
	var rf *Refusal
	if errors.As(err, &rf) && strings.HasSuffix(rf.Reason, "never written to") {
		return "", "", rf.Reason
	}
	if errors.Is(err, fs.ErrExist) || isRefusal(err) {
		return "", "unknown", ""
	}
	return "false", "not_writable", ""
}

// freeMB is the free space of P in MiB from statfs (sh: df -P -k, available KiB / 1024).
func freeMB(e Env, p string) (string, bool) {
	st, err := e.Statfs(p)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(st.Bavail*st.BlockSize/1024/1024, 10), true
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func probeFSLocations(e Env, r *Result) {
	r.Src("create and remove one test directory (mkdir, never an existing name) in each candidate directory")
	x := readXDGDirs(e, r)
	arr := []any{}
	var tsv []string
	wids, fhome, ftmp, nfail := "", "", "", 0
	for _, c := range locCandidates(e) {
		if c[1] == "" {
			continue
		}
		l, ok := locTest(e, x, c[0], c[1])
		if !ok {
			nfail++
		}
		arr = append(arr, locationObj(l))
		tsv = append(tsv, strings.Join([]string{l.id, l.path, dash(l.writable), dash(l.free), dash(l.noexec), l.state}, "\t"))
		if l.writable == "true" {
			wids += l.id + "\t" + l.path + "\n"
		}
		switch {
		case l.id == "home":
			fhome = l.free
		case l.id == "tmpdir", l.id == "tmp" && ftmp == "":
			ftmp = l.free
		}
	}
	r.Data.Set("locations", arr)
	if nfail > 0 {
		r.Partial("df failed for " + strconv.Itoa(nfail) + " location(s); free space unknown there")
	}
	v := installVerdict(tsv)
	if v == "" {
		r.Note("no install location was found writable and at least one was not tested, so whether one is writable is unknown")
	}
	r.Fact("install_writable", v)
	r.Fact("writable_paths", wids)
	r.Fact("free_home_mb", fhome)
	r.Fact("free_tmp_mb", ftmp)
	r.Fact("locations", strings.Join(tsv, "\n"))
}

func locationObj(l location) *Obj {
	o := NewObj().Set("id", l.id).Set("path", l.path).Set("exists", boolOrNil(l.exists)).
		Set("writable", boolOrNil(l.writable)).Set("free_mb", num(l.free)).Set("fstype", strOrNil(l.fstype)).
		Set("noexec", boolOrNil(l.noexec)).Set("network", boolOrNil(l.network))
	if l.skip != "" {
		o.Set("note", "not tested: "+l.skip)
	}
	return o
}

// installVerdict is sh es_install_verdict on the loc.tsv lines.
func installVerdict(tsv []string) string {
	w, u := false, false
	for _, line := range tsv {
		f := strings.Split(line, "\t")
		switch f[0] {
		case "home", "home_local", "home_bin", "opt", "usr_local", "cwd":
		default:
			continue
		}
		if f[5] == "writable" {
			w = true
		} else if f[5] != "not_writable" && f[5] != "absent" {
			u = true
		}
	}
	if w {
		return "true"
	}
	if u {
		return ""
	}
	return "false"
}
