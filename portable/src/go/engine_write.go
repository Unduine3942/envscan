// engine_write.go: the only writes of a scan besides the output folder: the private temp
// folder (es_mktemp / es_tmp_check) and exclusive, self-deleting test folders (es_mkdir_test /
// es_clean_list). Nothing is written outside a folder this run made.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var errNoTemp = errors.New("cannot create a private temporary directory (TMPDIR, /tmp, /var/tmp, HOME)")

const mkdirTries = 5

// randSuffix: 16 random hex digits for the names of own folders (a name planted in advance
// cannot block them). A variable so that tests can force a collision.
var randSuffix = func() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("envscan: no random source: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// initTemp is es_mktemp: TMPDIR, /tmp, /var/tmp, HOME (never on a network mount); a new 0700
// folder envscan.<random> made exclusively.
func (e *realEnv) initTemp() error {
	for _, base := range []string{e.vars["TMPDIR"], "/tmp", "/var/tmp", e.vars["HOME"]} {
		if base == "" || !e.localReal(base) || !isWritableDir(base) {
			continue
		}
		for try := 0; try < mkdirTries; try++ {
			d := filepath.Join(base, "envscan."+randSuffix())
			if err := e.mkdirLocked(d, func() { e.tmp = d }); err == nil || errors.Is(err, errStopping) {
				return err
			}
		}
	}
	return errNoTemp
}

// localReal is es_local_path for a real path (output and temp candidates).
func (e *realEnv) localReal(p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	return e.realRv.refusedWhy(filepath.ToSlash(p)) == "" || !strings.HasPrefix(filepath.ToSlash(p), "/")
}

func isWritableDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir() && dirWritable(p)
}

func (e *realEnv) TempDir() string { return e.tmp }

// ownSpace maps a path given to a write method to a real path: below TempDir() it is real
// (cleaned), otherwise it is logical (ENVSCAN_ROOT is added).
func (e *realEnv) ownSpace(p string) string {
	if e.underTemp(p) {
		return filepath.Clean(p)
	}
	return e.rv.real(p)
}

// underTemp: the cleaned path is the temp folder or below it ("..": never outside).
func (e *realEnv) underTemp(p string) bool {
	return e.tmp != "" && within(filepath.Clean(p), e.tmp)
}

// within: real path c is d or below d (both clean).
func within(c, d string) bool {
	return c == d || strings.HasPrefix(c, strings.TrimSuffix(d, string(os.PathSeparator))+string(os.PathSeparator))
}

func stoppingRefusal(p string) error { return &Refusal{Path: p, Reason: "the scan is stopping"} }

// MkdirUnique makes a new 0700 folder .envscan-t.<random> in parent (exclusive mkdir, so an
// existing file or link is never reused), in the vetted (resolved) parent. Never in Desktop,
// Documents, synced, network or credential folders, by the given or the resolved path.
func (e *realEnv) MkdirUnique(parent string) (string, error) {
	if e.isStopping() {
		return "", stoppingRefusal(parent)
	}
	logical, realParent, err := e.writableParent(parent)
	if err != nil {
		return "", err
	}
	for n := 0; n < mkdirTries; n++ {
		name := ".envscan-t." + randSuffix()
		real := filepath.Join(realParent, name)
		err := e.mkdirLocked(real, func() { e.own[real] = true })
		if errors.Is(err, errStopping) {
			return "", stoppingRefusal(parent)
		}
		if err == nil {
			if logical == "" {
				return real, nil
			}
			return strings.TrimSuffix(logical, "/") + "/" + name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("%s: no unique folder name left: %w", parent, fs.ErrExist)
}

// mkdirLocked makes a 0700 folder and registers it (record) under the lock, so that cleanup
// (which sets stopping under the same lock) either sees it or it is never made.
func (e *realEnv) mkdirLocked(real string, record func()) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return errStopping
	}
	if err := os.Mkdir(real, 0o700); err != nil {
		return err
	}
	record()
	return nil
}

// writableParent vets parent for MkdirUnique: the logical resolved path ("" below the temp
// folder) and the real folder to make the new folder in.
func (e *realEnv) writableParent(parent string) (logical, real string, err error) {
	xdg := e.xdgDirs()
	if why := unsafeDirWhy(filepath.ToSlash(parent), xdg); why != "" {
		return "", "", &Refusal{Path: parent, Reason: why}
	}
	if e.underTemp(parent) {
		real, err = e.ownTempParent(parent)
		return "", real, err
	}
	r, err := e.rv.vet(parent)
	if err != nil {
		return "", "", err
	}
	if why := unsafeDirWhy(r, xdg); why != "" {
		return "", "", &Refusal{Path: parent, Reason: why}
	}
	return r, e.rv.real(r), nil
}

// ownTempParent: a folder below the temp folder, with links resolved; it must still lie below
// the temp folder (a link made in an own folder never leads out of it).
func (e *realEnv) ownTempParent(parent string) (string, error) {
	rp, err := filepath.EvalSymlinks(filepath.Clean(parent))
	if err != nil {
		return "", err
	}
	rt, err := filepath.EvalSymlinks(e.tmp)
	if err != nil || !within(rp, rt) {
		return "", outsideOwn(parent)
	}
	return rp, nil
}

// inOwn: the (cleaned) real path lies inside a folder made by MkdirUnique.
func (e *realEnv) inOwn(real string) bool {
	c := filepath.Clean(real)
	e.mu.Lock()
	defer e.mu.Unlock()
	for d := range e.own {
		if c != d && within(c, d) {
			return true
		}
	}
	return false
}

// childEmptyDir: an empty 0700 folder in the temp folder, given to children instead of a HOME
// or XDG_* folder that must not be touched (made on first use; "" without a temp folder).
func (e *realEnv) childEmptyDir() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.emptyDir != "" || e.tmp == "" || e.stopping {
		return e.emptyDir
	}
	d := filepath.Join(e.tmp, "empty."+randSuffix())
	if err := os.Mkdir(d, 0o700); err == nil {
		e.emptyDir = d
	}
	return e.emptyDir
}

func outsideOwn(p string) error {
	return &Refusal{Path: p, Reason: "outside the scanner's own folders"}
}

// WriteNew creates a new file exclusively inside an own folder.
func (e *realEnv) WriteNew(p string, data []byte, perm uint32) error {
	real := e.ownSpace(p)
	if !e.inOwn(real) {
		return outsideOwn(p)
	}
	f, err := os.OpenFile(real, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fs.FileMode(perm&0o777))
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (e *realEnv) Symlink(target, p string) error {
	real := e.ownSpace(p)
	if !e.inOwn(real) {
		return outsideOwn(p)
	}
	return os.Symlink(target, real)
}

func (e *realEnv) Link(oldPath, newPath string) error {
	ro, rn := e.ownSpace(oldPath), e.ownSpace(newPath)
	if !e.inOwn(rn) || !e.inOwn(ro) {
		return outsideOwn(newPath)
	}
	return os.Link(ro, rn)
}

// RemoveOwn removes a folder made by MkdirUnique, with its content (links are not followed).
func (e *realEnv) RemoveOwn(dir string) error {
	real := e.ownSpace(dir)
	e.mu.Lock()
	ok := e.own[real]
	delete(e.own, real)
	e.mu.Unlock()
	if !ok {
		return &Refusal{Path: dir, Reason: "not made by this run"}
	}
	return removeOwnDir(real)
}

func removeOwnDir(real string) error {
	fi, err := os.Lstat(real)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New(real + ": not a folder")
	}
	return os.RemoveAll(real)
}

// cleanup removes every own folder left and the temp folder (es_cleanup). From its start no
// command is started and no folder made (stopping).
func (e *realEnv) cleanup() {
	e.mu.Lock()
	e.stopping = true
	e.mu.Unlock()
	e.children.killAll()
	e.mu.Lock()
	dirs := make([]string, 0, len(e.own))
	for d := range e.own {
		dirs = append(dirs, d)
	}
	e.own = map[string]bool{}
	tmp := e.tmp
	e.mu.Unlock()
	for _, d := range dirs {
		_ = removeOwnDir(d)
	}
	if tmp != "" && strings.HasPrefix(filepath.Base(tmp), "envscan.") {
		_ = os.RemoveAll(tmp)
	}
}
