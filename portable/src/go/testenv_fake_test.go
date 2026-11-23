// testenv_fake_test.go: fakeEnv, an Env for unit tests (owner: main). Files come from a real
// directory tree (Root, e.g. ../../tests/fixtures/linux-basic or t.TempDir()); commands from a
// table; everything else from fields. Add fields here through main, never a private copy.
package main

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

type fakeCmd struct {
	Stdout, Stderr string
	Exit           int
	TimedOut       bool
}

type fakeEnv struct {
	T        *testing.T
	Root     string             // real folder holding the logical "/" ("" = no files)
	Vars     map[string]string  // environment snapshot
	Cmds     map[string]fakeCmd // "name arg1 arg2" (name = base name) -> result
	PathBins map[string]string  // name -> resolved path for Which ("" = not found)
	NoRun    map[string]string  // resolved path -> why it must not run (shims etc.)
	RefusedP map[string]string  // logical path prefix -> refusal reason
	NetPaths []string           // logical prefixes on network mounts
	MountTab []Mount
	FactsIn  map[string]string
	OSName   string
	ArchName string
	DeepOn   bool
	NetOn    bool
	NoRedact bool
	UnameV   Uname
	IdsV     Ids
	Limits   map[string]Rlimit
	Fs       map[string]Statfs
	Tty      map[int]bool
	UmaskV   uint32
	HasUmask bool
	Host     string
	Clock    time.Time
	Temp     string // real temp dir (t.TempDir() when empty)
	Ran      []string
	Logs     []string
	own      map[string]bool
}

func newFakeEnv(t *testing.T, root string) *fakeEnv {
	return &fakeEnv{T: t, Root: root, Vars: map[string]string{}, Cmds: map[string]fakeCmd{},
		PathBins: map[string]string{}, NoRun: map[string]string{}, RefusedP: map[string]string{},
		FactsIn: map[string]string{}, OSName: "linux", ArchName: "x86_64", Limits: map[string]Rlimit{},
		Fs: map[string]Statfs{}, Tty: map[int]bool{}, Host: "testhost",
		Clock: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), own: map[string]bool{}}
}

func (f *fakeEnv) real(p string) string { return filepath.Join(f.Root, filepath.FromSlash(p)) }

func (f *fakeEnv) OS() string             { return f.OSName }
func (f *fakeEnv) Arch() string           { return f.ArchName }
func (f *fakeEnv) Deep() bool             { return f.DeepOn }
func (f *fakeEnv) Net() bool              { return f.NetOn }
func (f *fakeEnv) Redact() bool           { return !f.NoRedact }
func (f *fakeEnv) Timeout() time.Duration { return 10 * time.Second }
func (f *fakeEnv) Deadline() time.Time    { return f.Clock.Add(time.Hour) }
func (f *fakeEnv) TestRoot() string       { return "" }
func (f *fakeEnv) Log(msg string)         { f.Logs = append(f.Logs, msg) }
func (f *fakeEnv) Now() time.Time         { return f.Clock }
func (f *fakeEnv) Hostname() string       { return f.Host }
func (f *fakeEnv) Fact(k string) string   { return f.FactsIn[k] }
func (f *fakeEnv) Home() string           { return f.Vars["HOME"] }

func (f *fakeEnv) Getenv(n string) (string, bool) { v, ok := f.Vars[n]; return v, ok }

func (f *fakeEnv) Environ() []string {
	out := make([]string, 0, len(f.Vars))
	for k, v := range f.Vars {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func (f *fakeEnv) Refused(p string) string {
	for prefix, why := range f.RefusedP {
		if p == prefix || strings.HasPrefix(p, strings.TrimSuffix(prefix, "/")+"/") {
			return why
		}
	}
	if f.IsNetPath(p) {
		return "network or autofs mount"
	}
	return ""
}

func (f *fakeEnv) check(p string) error {
	if why := f.Refused(p); why != "" {
		return &Refusal{Path: p, Reason: why}
	}
	if f.Root == "" {
		return fs.ErrNotExist
	}
	return nil
}

func (f *fakeEnv) ReadFile(p string, max int) ([]byte, bool, error) {
	if err := f.check(p); err != nil {
		return nil, false, err
	}
	st, err := os.Stat(f.real(p))
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, false, ErrNotRegular
	}
	b, err := os.ReadFile(f.real(p))
	if err != nil {
		return nil, false, err
	}
	if max > 0 && len(b) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

func (f *fakeEnv) ReadText(p string, max int) (string, bool, error) {
	b, tr, err := f.ReadFile(p, max)
	if err != nil {
		return "", false, err
	}
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u)), tr, nil
	}
	if strings.IndexByte(string(b), 0) >= 0 {
		return "", false, ErrBinary
	}
	return string(b), tr, nil
}

func (f *fakeEnv) ReadDir(p string, max int) ([]DirEntry, bool, error) {
	if err := f.check(p); err != nil {
		return nil, false, err
	}
	des, err := os.ReadDir(f.real(p))
	if err != nil {
		return nil, false, err
	}
	if max <= 0 {
		max = 10000
	}
	out := []DirEntry{}
	for _, d := range des {
		if len(out) == max {
			return out, true, nil
		}
		out = append(out, DirEntry{Name: d.Name(), Type: fileType(d.Type())})
	}
	return out, false, nil
}

func fileType(m fs.FileMode) FileType {
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

func (f *fakeEnv) info(p string, st fs.FileInfo) FileInfo {
	return FileInfo{Name: path.Base(p), Type: fileType(st.Mode()), Size: st.Size(),
		Mode: uint32(st.Mode().Perm()), ModTime: st.ModTime(), UID: -1, GID: -1}
}

func (f *fakeEnv) Stat(p string) (FileInfo, error) {
	if err := f.check(p); err != nil {
		return FileInfo{}, err
	}
	st, err := os.Stat(f.real(p))
	if err != nil {
		return FileInfo{}, err
	}
	return f.info(p, st), nil
}

func (f *fakeEnv) Lstat(p string) (FileInfo, error) {
	if err := f.check(p); err != nil {
		return FileInfo{}, err
	}
	st, err := os.Lstat(f.real(p))
	if err != nil {
		return FileInfo{}, err
	}
	return f.info(p, st), nil
}

func (f *fakeEnv) Readlink(p string) (string, error) {
	if err := f.check(p); err != nil {
		return "", err
	}
	return os.Readlink(f.real(p))
}

func (f *fakeEnv) Exists(p string) bool { _, err := f.Lstat(p); return err == nil }

func (f *fakeEnv) Glob(pattern string) ([]string, error) {
	if f.Root == "" {
		return nil, nil
	}
	matches, err := filepath.Glob(f.real(pattern))
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, m := range matches {
		rel, _ := filepath.Rel(f.Root, m)
		lp := "/" + filepath.ToSlash(rel)
		if f.Refused(lp) == "" {
			out = append(out, lp)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeEnv) Expand(p string) (string, bool) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		h := f.Home()
		if h == "" {
			return "", false
		}
		p = h + p[1:]
	}
	for {
		i := strings.Index(p, "{env:")
		if i < 0 {
			return p, true
		}
		j := strings.Index(p[i:], "}")
		if j < 0 {
			return "", false
		}
		v, ok := f.Vars[p[i+5:i+j]]
		if !ok || v == "" {
			return "", false
		}
		p = p[:i] + v + p[i+j+1:]
	}
}

func (f *fakeEnv) Mounts() []Mount { return f.MountTab }

func (f *fakeEnv) MountOf(p string) (Mount, bool) {
	best, ok := Mount{}, false
	for _, m := range f.MountTab {
		if p == m.Dir || m.Dir == "/" || strings.HasPrefix(p, strings.TrimSuffix(m.Dir, "/")+"/") {
			if !ok || len(m.Dir) > len(best.Dir) {
				best, ok = m, true
			}
		}
	}
	return best, ok
}

func (f *fakeEnv) IsNetPath(p string) bool {
	for _, n := range f.NetPaths {
		if p == n || strings.HasPrefix(p, strings.TrimSuffix(n, "/")+"/") {
			return true
		}
	}
	return false
}

func (f *fakeEnv) Which(name string) (string, bool) {
	p, ok := f.PathBins[name]
	return p, ok && p != ""
}

func (f *fakeEnv) Runnable(p string) (bool, string) {
	if why, bad := f.NoRun[p]; bad {
		return false, why
	}
	return true, ""
}

func (f *fakeEnv) Run(opt RunOpt, p string, args ...string) CmdResult {
	key := strings.TrimSpace(path.Base(p) + " " + strings.Join(args, " "))
	f.Ran = append(f.Ran, key)
	if ok, why := f.Runnable(p); !ok {
		return CmdResult{Path: p, Args: args, Exit: 126, Why: why}
	}
	c, found := f.Cmds[key]
	if !found {
		return CmdResult{Path: p, Args: args, Exit: 127, Why: "no fake for " + key}
	}
	out := c.Stdout
	errText := c.Stderr
	if opt.MergeStderr {
		out, errText = out+errText, ""
	}
	return CmdResult{Path: p, Args: args, Stdout: out, Stderr: errText, Exit: c.Exit, TimedOut: c.TimedOut}
}

func (f *fakeEnv) Uname() (Uname, error) {
	if f.UnameV.Sysname == "" {
		return Uname{}, errors.New("no uname in fake")
	}
	return f.UnameV, nil
}

func (f *fakeEnv) Ids() Ids { return f.IdsV }

func (f *fakeEnv) Rlimit(name string) (Rlimit, error) {
	if l, ok := f.Limits[name]; ok {
		return l, nil
	}
	return Rlimit{}, errors.New("no limit " + name)
}

func (f *fakeEnv) Statfs(p string) (Statfs, error) {
	if s, ok := f.Fs[p]; ok {
		return s, nil
	}
	return Statfs{}, fs.ErrNotExist
}

func (f *fakeEnv) Isatty(fd int) bool    { return f.Tty[fd] }
func (f *fakeEnv) Umask() (uint32, bool) { return f.UmaskV, f.HasUmask }

func (f *fakeEnv) TempDir() string {
	if f.Temp == "" {
		f.Temp = f.T.TempDir()
	}
	return f.Temp
}

// The write methods work on real paths below TempDir() (tests check what was made and removed).
func (f *fakeEnv) MkdirUnique(parent string) (string, error) {
	d, err := os.MkdirTemp(parent, "envscan-t")
	if err == nil {
		f.own[d] = true
	}
	return d, err
}

func (f *fakeEnv) ownDir(p string) bool {
	for d := range f.own {
		if strings.HasPrefix(p, d+string(os.PathSeparator)) || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

func (f *fakeEnv) WriteNew(p string, data []byte, perm uint32) error {
	if !f.ownDir(p) {
		return &Refusal{Path: p, Reason: "outside the scanner's own folders"}
	}
	h, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fs.FileMode(perm))
	if err != nil {
		return err
	}
	_, err = h.Write(data)
	if cerr := h.Close(); err == nil {
		err = cerr
	}
	return err
}

func (f *fakeEnv) Symlink(target, p string) error {
	if !f.ownDir(p) {
		return &Refusal{Path: p, Reason: "outside the scanner's own folders"}
	}
	return os.Symlink(target, p)
}

func (f *fakeEnv) Link(oldPath, newPath string) error {
	if !f.ownDir(newPath) {
		return &Refusal{Path: newPath, Reason: "outside the scanner's own folders"}
	}
	return os.Link(oldPath, newPath)
}

func (f *fakeEnv) RemoveOwn(dir string) error {
	if !f.own[dir] {
		return &Refusal{Path: dir, Reason: "not made by this run"}
	}
	delete(f.own, dir)
	return os.RemoveAll(dir)
}

// fixtureRoot is tests/fixtures/<name> seen from a staged build folder (build/<x>/) or src/go.
func fixtureRoot(t *testing.T, name string) string {
	t.Helper()
	for _, rel := range []string{"../../tests/fixtures", "../../../tests/fixtures"} {
		p, _ := filepath.Abs(filepath.Join(rel, name))
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	if env := os.Getenv("ENVSCAN_FIXTURES"); env != "" {
		return filepath.Join(env, name)
	}
	t.Fatalf("fixture %s not found (set ENVSCAN_FIXTURES)", name)
	return ""
}

var _ Env = (*fakeEnv)(nil)
