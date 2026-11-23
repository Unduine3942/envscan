// engine_files.go: the vetted file methods of realEnv (port of es_read / es_text_prep /
// es_ltest / es_expand). Every path is a logical path; it is resolved and vetted
// (engine_resolve.go) before any syscall touches it.
package main

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	defaultReadMax = 1 << 20
	defaultDirMax  = 10000
)

// ReadFile reads a regular file (FIFOs, devices and sockets are never opened).
func (e *realEnv) ReadFile(p string, max int) ([]byte, bool, error) {
	r, err := e.rv.vet(p)
	if err != nil {
		return nil, false, err
	}
	return readRegularChecked(e.rv.real(r), max, func(f *os.File) error { return e.checkOpened(f, e.rv, p) })
}

// readRegularChecked reads a regular file; check (may be nil) vets the file once it is open.
func readRegularChecked(real string, max int, check func(*os.File) error) ([]byte, bool, error) {
	if max <= 0 {
		max = defaultReadMax
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, ErrNotRegular
	}
	f, err := openNoFollow(real)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	if check != nil {
		if err := check(f); err != nil {
			return nil, false, err
		}
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, false, ErrNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

// ReadText is ReadFile plus es_text_prep: UTF-16 with a byte order mark is decoded; NUL bytes
// or undecodable UTF-16 give ErrBinary.
func (e *realEnv) ReadText(p string, max int) (string, bool, error) {
	b, truncated, err := e.ReadFile(p, max)
	if err != nil {
		return "", false, err
	}
	s, err := decodeText(b, truncated)
	return s, truncated, err
}

func decodeText(b []byte, truncated bool) (string, error) {
	if len(b) >= 2 && (b[0] == 0xff && b[1] == 0xfe || b[0] == 0xfe && b[1] == 0xff) {
		body := b[2:]
		if truncated && len(body)%2 == 1 {
			body = body[:len(body)-1]
		}
		s, ok := decodeUTF16(body, b[0] == 0xff)
		if !ok || s == "" || strings.IndexByte(s, 0) >= 0 {
			return "", ErrBinary
		}
		return s, nil
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return "", ErrBinary
	}
	return string(b), nil
}

// decodeUTF16 decodes strictly (odd length or an unpaired surrogate fails, like iconv).
func decodeUTF16(b []byte, le bool) (string, bool) {
	if len(b)%2 == 1 {
		return "", false
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if le {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		} else {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
	}
	if !validSurrogates(u) {
		return "", false
	}
	return string(utf16.Decode(u)), true
}

func validSurrogates(u []uint16) bool {
	for i := 0; i < len(u); i++ {
		switch {
		case u[i] >= 0xd800 && u[i] < 0xdc00:
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return false
			}
			i++
		case u[i] >= 0xdc00 && u[i] <= 0xdfff:
			return false
		}
	}
	return true
}

// ReadDir lists a vetted folder, sorted by name; credential-store entries are left out.
func (e *realEnv) ReadDir(p string, max int) ([]DirEntry, bool, error) {
	r, err := e.rv.vet(p)
	if err != nil {
		return nil, false, err
	}
	des, err := e.readDirChecked(e.rv.real(r), p)
	if err != nil {
		return nil, false, err
	}
	if max <= 0 {
		max = defaultDirMax
	}
	out := []DirEntry{}
	for _, d := range des {
		if credPath(path.Join(r, d.Name())) {
			continue
		}
		if len(out) == max {
			return out, true, nil
		}
		out = append(out, DirEntry{Name: d.Name(), Type: modeType(d.Type())})
	}
	return out, false, nil
}

// readDirChecked lists a folder, sorted by name, after vetting the folder once it is open.
func (e *realEnv) readDirChecked(real, p string) ([]fs.DirEntry, error) {
	f, err := os.Open(real)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := e.checkOpened(f, e.rv, p); err != nil {
		return nil, err
	}
	des, err := f.ReadDir(-1)
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })
	return des, err
}

// checkOpened: after open, the path the file has now (Linux /proc/self/fd) is vetted again, so a
// link or mount swapped in between the check and the open is noticed. Without /proc nothing
// changes.
func (e *realEnv) checkOpened(f *os.File, rv *resolver, p string) error {
	now, ok := fdPath(f)
	if !ok {
		return nil
	}
	if why := e.openedWhy(now, rv); why != "" {
		return &Refusal{Path: p, Reason: why}
	}
	return nil
}

// openedWhy: "" or why an open file at real path now must not be read (the path as it is and,
// below the test root, as a logical path).
func (e *realEnv) openedWhy(now string, rv *resolver) string {
	now = strings.TrimSuffix(now, " (deleted)")
	cands := []string{now}
	if root := filepath.ToSlash(rv.root); root != "" {
		if now == root {
			cands = append(cands, "/")
		} else if strings.HasPrefix(now, root+"/") {
			cands = append(cands, now[len(root):])
		}
	}
	for _, c := range cands {
		if onNetfs(c, rv.netmnts) {
			return whyNet
		}
		if credPath(c) {
			return whyCredLink
		}
	}
	return ""
}

func modeType(m fs.FileMode) FileType {
	switch {
	case m&fs.ModeSymlink != 0:
		return TypeLink
	case m.IsDir():
		return TypeDir
	case m.IsRegular():
		return TypeFile
	}
	return TypeOther
}

func toFileInfo(name string, fi fs.FileInfo) FileInfo {
	m := fi.Mode()
	mode := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	uid, gid := fileOwner(fi)
	return FileInfo{Name: name, Type: modeType(m), Size: fi.Size(), Mode: mode, ModTime: fi.ModTime(), UID: uid, GID: gid}
}

// Stat follows links only after vetting their targets (the resolved path is lstat'ed).
func (e *realEnv) Stat(p string) (FileInfo, error) {
	r, err := e.rv.vet(p)
	if err != nil {
		return FileInfo{}, err
	}
	fi, err := os.Lstat(e.rv.real(r))
	if err != nil {
		return FileInfo{}, err
	}
	return toFileInfo(path.Base(p), fi), nil
}

// Lstat does not follow the last component (its folder is resolved and vetted).
func (e *realEnv) Lstat(p string) (FileInfo, error) {
	r, err := e.rv.vetParent(p)
	if err != nil {
		return FileInfo{}, err
	}
	fi, err := os.Lstat(e.rv.real(r))
	if err != nil {
		return FileInfo{}, err
	}
	return toFileInfo(path.Base(p), fi), nil
}

func (e *realEnv) Readlink(p string) (string, error) {
	r, err := e.rv.vetParent(p)
	if err != nil {
		return "", err
	}
	t, err := os.Readlink(e.rv.real(r))
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(t, "\\", "/"), nil
}

func (e *realEnv) Exists(p string) bool { _, err := e.Lstat(p); return err == nil }

func (e *realEnv) Refused(p string) string { return e.rv.refusedWhy(p) }

// Expand is the text part of es_expand: "~" = HOME, "{env:NAME}" = the variable (false when it
// is unset or empty, or the result is not absolute).
func (e *realEnv) Expand(p string) (string, bool) {
	return expandPath(p, e.vars)
}

func expandPath(p string, vars map[string]string) (string, bool) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		h := vars["HOME"]
		if h == "" {
			return "", false
		}
		p = h + p[1:]
	}
	for {
		i := strings.Index(p, "{env:")
		if i < 0 {
			break
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			return "", false
		}
		name := p[i+5 : i+j]
		v := vars[name]
		if !validEnvName(name) || v == "" {
			return "", false
		}
		p = p[:i] + v + p[i+j+1:]
	}
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	return p, true
}

func validEnvName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func sortedUnique(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
