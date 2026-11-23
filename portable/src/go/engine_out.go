// engine_out.go: the output folder (port of es_pick_out, es_unsafe_dir, es_xdg_dirs).
package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// fatalError ends the scan with exit 2 ("envscan: <msg>" on stderr).
type fatalError struct{ msg string }

func (f *fatalError) Error() string { return f.msg }

func fatalf(format string, a ...any) error { return &fatalError{fmt.Sprintf(format, a...)} }

// pickOut is es_pick_out: the parent folder, then a new envscan-<host>-<UTC stamp> folder.
func (e *realEnv) pickOut() (string, error) {
	parent, err := e.outParent()
	if err != nil {
		return "", err
	}
	stamp := e.clock().UTC().Format("20060102T150405Z")
	base := filepath.Join(parent, "envscan-"+sanitizeHost(e.host)+"-"+stamp)
	out := base
	for n := 1; ; n++ {
		err := os.Mkdir(out, 0o700)
		if err == nil {
			return out, nil
		}
		if n >= 20 {
			return "", fatalf("cannot create the output folder under %s", parent)
		}
		out = fmt.Sprintf("%s-%d", base, n+1)
	}
}

func (e *realEnv) outParent() (string, error) {
	if o := e.opts.Out; o != "" {
		return e.explicitOut(o)
	}
	xdg := e.xdgDirs()
	for _, c := range []string{e.cwd, e.vars["HOME"], e.vars["TMPDIR"], "/tmp", "/var/tmp"} {
		if c == "" || !e.outCandidateOK(c, xdg) {
			continue
		}
		if isWritableDir(c) {
			return c, nil
		}
	}
	return "", fatalf("no writable local output directory (current directory, HOME, temp; Desktop, Documents, synchronised folders and network mounts are never used); pass --out DIR")
}

// explicitOut: --out is used as given (no Desktop rule), but never a credential store, a folder
// inside one or a network/autofs mount (by the given or the resolved path).
func (e *realEnv) explicitOut(o string) (string, error) {
	parent := o
	if !filepath.IsAbs(o) && !strings.HasPrefix(o, "/") {
		parent = filepath.Join(e.cwd, o)
	}
	if why := e.outRefusedWhy(parent); why != "" {
		return "", fatalf("--out directory is not used (%s): %s", why, o)
	}
	if fi, err := os.Stat(parent); err != nil || !fi.IsDir() {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", fatalf("cannot create --out directory: %s", o)
		}
	}
	if !dirWritable(parent) {
		return "", fatalf("--out directory is not writable: %s", o)
	}
	return parent, nil
}

func (e *realEnv) outRefusedWhy(p string) string {
	sp := filepath.ToSlash(p)
	if isUNC(sp) || isUNC(p) {
		return whyNet
	}
	if credPath(sp) || credPath(path.Clean(sp)) {
		return whyCred
	}
	if strings.HasPrefix(sp, "/") {
		return e.realRv.refusedWhy(path.Clean(sp))
	}
	return ""
}

// outCandidateOK: a default output candidate is local and neither its path nor its resolved
// path is a Desktop, Documents or synchronised folder.
func (e *realEnv) outCandidateOK(c string, xdg []string) bool {
	if !e.localReal(c) || unsafeDirWhy(filepath.ToSlash(c), xdg) != "" {
		return false
	}
	sc := filepath.ToSlash(c)
	if !strings.HasPrefix(sc, "/") {
		return true
	}
	r, err := e.realRv.vet(sc)
	return err == nil && unsafeDirWhy(r, xdg) == ""
}

// sanitizeHost: tr -c 'A-Za-z0-9._-' '_' (byte-wise).
func sanitizeHost(h string) string {
	b := []byte(h)
	for i, c := range b {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			b[i] = '_'
		}
	}
	return string(b)
}

var syncedMarks = []string{"/onedrive", "/dropbox", "/google drive", "/googledrive", "/my drive/",
	"/library/mobile documents/", "/library/cloudstorage/", "/icloud drive", "/iclouddrive", "/box/",
	"/box sync/", "/nextcloud", "/owncloud", "/seafile", "/pcloud", "/mega/", "/synologydrive"}

// unsafeDirWhy is es_unsafe_dir: "" or why the scanner must never write there.
func unsafeDirWhy(p string, xdg []string) string {
	p = path.Clean(p) // ".." folded before matching
	lp := asciiLower(p) + "/"
	if strings.Contains(lp, "/desktop/") || strings.Contains(lp, "/documents/") {
		return "Desktop and Documents are never written to"
	}
	for _, m := range syncedMarks {
		if strings.Contains(lp, m) {
			return "synchronised (cloud) folders are never written to"
		}
	}
	np := normDirText(p) + "/"
	for _, d := range xdg {
		if d != "" && strings.HasPrefix(np, d+"/") {
			return "the XDG Desktop and Documents directories are never written to"
		}
	}
	return ""
}

// xdgDirs is es_xdg_dirs: the XDG Desktop and Documents folders (environment first, then
// ~/.config/user-dirs.dirs), "" when one is HOME or above it.
func (e *realEnv) xdgDirs() []string {
	desk, docs := e.vars["XDG_DESKTOP_DIR"], e.vars["XDG_DOCUMENTS_DIR"]
	home := e.vars["HOME"]
	if home != "" {
		cfg := e.vars["XDG_CONFIG_HOME"]
		if cfg == "" {
			cfg = home + "/.config"
		}
		d2, o2 := e.readUserDirs(cfg+"/user-dirs.dirs", home)
		if desk == "" {
			desk = d2
		}
		if docs == "" {
			docs = o2
		}
	}
	return []string{xdgDirEnabled(desk, home), xdgDirEnabled(docs, home)}
}

func (e *realEnv) readUserDirs(file, home string) (desk, docs string) {
	if !e.localReal(file) {
		return "", ""
	}
	b, _, err := readRegularChecked(file, 65536, func(f *os.File) error { return e.checkOpened(f, e.realRv, file) })
	if err != nil {
		return "", ""
	}
	for _, l := range lines(string(b)) {
		k, v, ok := strings.Cut(l, "=")
		if !ok || (k != "XDG_DESKTOP_DIR" && k != "XDG_DOCUMENTS_DIR") {
			continue
		}
		v = shUnquote(v)
		if strings.HasPrefix(v, "$HOME") {
			v = home + v[len("$HOME"):]
		}
		if k == "XDG_DESKTOP_DIR" && desk == "" {
			desk = v
		} else if k == "XDG_DOCUMENTS_DIR" && docs == "" {
			docs = v
		}
	}
	return desk, docs
}

// unquote is es_unquote: trimmed, one pair of surrounding quotes removed.
func shUnquote(s string) string {
	s = shTrim(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func xdgDirEnabled(dir, home string) string {
	xe := normDirText(dir)
	if home == "" {
		home = "/nonexistent"
	}
	if strings.HasPrefix(normDirText(home)+"/", strings.TrimSuffix(xe, "/")+"/") {
		return ""
	}
	return xe
}
