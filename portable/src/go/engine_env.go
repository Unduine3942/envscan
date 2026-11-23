// engine_env.go: realEnv, the Env of a real scan (scan context, environment snapshot, mount
// table, facts, log). Port of es_init / es_detect_os / es_env_capture / es_mounts_init /
// es_netmnts_init / es_path_init of envscan.sh. File, command and write methods live in
// engine_files.go, engine_glob.go, engine_write.go and exec_*.go.
package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type realEnv struct {
	opts     *options
	rv       *resolver // logical paths below ENVSCAN_ROOT
	realRv   *resolver // real paths (output and temp folders)
	root     string
	osName   string
	arch     string
	host     string
	wsl      bool
	vars     map[string]string
	environ  []string
	mounts   []Mount
	mountSrc string
	pathSkip map[string]bool
	uname    Uname
	unameErr error
	tty      [3]bool
	umask    uint32
	hasUmask bool
	t0       time.Time
	deadline time.Time
	timeout  time.Duration
	cwd      string
	tmp      string
	clock    func() time.Time
	children *childSet

	rootWhy string // "" or why ENVSCAN_ROOT itself must not be used (the scan refuses to start)

	mu       sync.Mutex        // guards the fields below
	stopping bool              // cleanup started: no new command, no new folder
	emptyDir string            // the empty folder for refused HOME / XDG_* of children (made on first use)
	keptEnv  map[string]string // the vetted allowlisted scan-start variables of children (first use)
	facts    map[string]string
	own      map[string]bool // real paths of folders made by MkdirUnique
	shimSeen map[string]string
	wwSeen   map[string]FileInfo
	logLines []string
}

// newRealEnv takes the scan-start snapshot (environment, uname, ttys, umask, mount table).
// environ is os.Environ(); clock is time.Now outside tests.
func newRealEnv(o *options, environ []string, clock func() time.Time) *realEnv {
	e := &realEnv{opts: o, clock: clock, facts: map[string]string{}, own: map[string]bool{},
		shimSeen: map[string]string{}, wwSeen: map[string]FileInfo{}, children: newChildSet()}
	e.vars, e.environ = snapshotEnv(environ)
	e.root = strings.TrimRight(e.vars["ENVSCAN_ROOT"], "/")
	if e.vars["ENVSCAN_ROOT"] != "" && e.root == "" {
		e.root = "/"
	}
	e.t0 = clock()
	e.deadline = e.t0.Add(time.Duration(o.BudgetSec) * time.Second)
	e.timeout = time.Duration(o.TimeoutSec) * time.Second
	e.cwd = logicalCwd(e.vars["PWD"])
	e.detectOS()
	for fd := 0; fd < 3; fd++ {
		e.tty[fd] = sysIsatty(fd)
	}
	e.umask, e.hasUmask = sysUmask()
	e.rv = &resolver{root: e.rootForPaths()}
	e.realRv = &resolver{}
	e.pathSkip = map[string]bool{}
	if e.initMounts(); e.rootWhy != "" {
		return e
	}
	e.initPathSkip()
	e.initStartFacts()
	return e
}

// initStartFacts: the facts sh has before the first probe (ES_F_wsl, ES_MOUNT_SRC, ES_CWD and
// the folder of the running program).
func (e *realEnv) initStartFacts() {
	e.facts["wsl"] = factBool(e.wsl)
	e.facts["mount_src"] = e.mountSrc
	e.facts["cwd"] = e.cwd
	e.facts["script_dir"] = ""
	if exe, err := os.Executable(); err == nil {
		e.facts["script_dir"] = filepath.ToSlash(filepath.Dir(exe))
	}
}

func (e *realEnv) rootForPaths() string {
	if e.root == "/" {
		return ""
	}
	return e.root
}

// snapshotEnv: the environment as a map and as sorted "NAME=value" lines (names with line
// breaks or tabs are left out, like es_env_capture).
func snapshotEnv(environ []string) (map[string]string, []string) {
	vars := map[string]string{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" || strings.ContainsAny(k, "\t\r\n") {
			continue
		}
		vars[k] = v
	}
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, k := range names {
		out = append(out, k+"="+vars[k])
	}
	return vars, out
}

// detectOS is es_detect_os (Linux only).
func (e *realEnv) detectOS() {
	e.osName = sysOSName(e.vars)
	e.uname, e.unameErr = sysUname(e.vars)
	if e.unameErr == nil {
		e.arch = normArch(e.uname.Machine)
	} else {
		e.arch = normArch(goArchMachine())
	}
	e.host = e.uname.Nodename
	if e.host == "" {
		e.host = "unknown"
	}
	rel := e.uname.Release
	e.wsl = e.osName == "linux" && (strings.Contains(rel, "microsoft") || strings.Contains(rel, "Microsoft"))
}

// realMountsFiles: the mount tables of the running system. They are always read; with
// ENVSCAN_ROOT the root's table is added (network mount points of both are refused).
var realMountsFiles = []string{"/proc/self/mounts", "/proc/mounts"}

// initMounts is es_mounts_init + es_netmnts_init: /proc/self/mounts, /proc/mounts, else mount(8).
// Below a test root, the real table is read first and the root itself is vetted with it.
func (e *realEnv) initMounts() {
	var realNet []string
	if e.rv.root != "" {
		ms, _ := readMountTable(realMountsFiles, func(f string) string { return f })
		realNet = netMountPoints(ms)
		e.realRv.netmnts = realNet
		if e.rootWhy = rootRefusedWhy(e.rv.root, e.realRv); e.rootWhy != "" {
			return
		}
	}
	e.mounts, e.mountSrc = readMountTable(mountFiles, e.rv.real)
	if e.mounts == nil {
		e.mounts = e.mountsFromCommand()
	}
	nm := append(netMountPoints(e.mounts), realNet...)
	e.rv.netmnts, e.realRv.netmnts = nm, nm
}

var mountFiles = []string{"/proc/self/mounts", "/proc/mounts"}

// readMountTable: the first readable, non-empty table of files (real maps a name to the file
// system) and "read <file>".
func readMountTable(files []string, real func(string) string) ([]Mount, string) {
	for _, f := range files {
		b, err := os.ReadFile(real(f))
		if err != nil {
			continue
		}
		if ms := parseProcMounts(string(b)); len(ms) > 0 {
			return ms, "read " + f
		}
	}
	return nil, ""
}

// rootRefusedWhy: "" or why ENVSCAN_ROOT itself must not be scanned (a network or autofs
// mount, a UNC path, or a credential store or a folder inside one).
func rootRefusedWhy(root string, rv *resolver) string {
	p := filepath.ToSlash(root)
	if isUNC(p) || isUNC(root) {
		return whyNet
	}
	if credPath(p) {
		return whyCred
	}
	if strings.HasPrefix(p, "/") {
		return rv.refusedWhy(p)
	}
	return ""
}

func (e *realEnv) mountsFromCommand() []Mount {
	p, ok := e.Which("mount")
	if !ok {
		return nil
	}
	e.mountSrc = "run mount"
	c := e.Run(RunOpt{}, p)
	return parseMountCmd(c.Stdout)
}

// initPathSkip is es_path_init: PATH entries on network mounts (or into credential stores),
// vetted like executables (real paths in the release build).
func (e *realEnv) initPathSkip() {
	for _, d := range strings.Split(e.vars["PATH"], ":") {
		if strings.HasPrefix(d, "/") && e.execRv().refusedWhy(d) != "" {
			e.pathSkip[d] = true
		}
	}
}

func factBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ---- Env: scan context

func (e *realEnv) OS() string             { return e.osName }
func (e *realEnv) Arch() string           { return e.arch }
func (e *realEnv) Deep() bool             { return e.opts.Deep }
func (e *realEnv) Net() bool              { return e.opts.Net }
func (e *realEnv) Redact() bool           { return e.opts.Redact }
func (e *realEnv) Timeout() time.Duration { return e.timeout }
func (e *realEnv) Deadline() time.Time    { return e.deadline }
func (e *realEnv) TestRoot() string       { return e.root }
func (e *realEnv) Now() time.Time         { return e.clock() }
func (e *realEnv) Hostname() string       { return e.host }

// Log is es_log: a line for envscan.log.
func (e *realEnv) Log(msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logLines = append(e.logLines, msg)
}

func (e *realEnv) logText() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.logLines...)
}

// ---- Env: environment snapshot

func (e *realEnv) Getenv(name string) (string, bool) { v, ok := e.vars[name]; return v, ok }
func (e *realEnv) Environ() []string                 { return append([]string(nil), e.environ...) }
func (e *realEnv) Home() string                      { return e.vars["HOME"] }

// ---- Env: mounts

func (e *realEnv) Mounts() []Mount { return append([]Mount(nil), e.mounts...) }

func (e *realEnv) MountOf(p string) (Mount, bool) {
	r, kind := e.rv.resolve(p)
	if kind == resCred || kind == resLoop {
		r = p
	}
	return mountOf(r, e.mounts)
}

func (e *realEnv) IsNetPath(p string) bool {
	_, kind := e.rv.resolve(p)
	return kind == resNet
}

// ---- Env: system calls

func (e *realEnv) Uname() (Uname, error)              { return e.uname, e.unameErr }
func (e *realEnv) Ids() Ids                           { return sysIds() }
func (e *realEnv) Rlimit(name string) (Rlimit, error) { return sysRlimit(name) }
func (e *realEnv) Umask() (uint32, bool)              { return e.umask, e.hasUmask }

func (e *realEnv) Isatty(fd int) bool {
	if fd < 0 || fd > 2 {
		return false
	}
	return e.tty[fd]
}

// Statfs: a vetted path; the type name comes from the mount table.
func (e *realEnv) Statfs(p string) (Statfs, error) {
	r, err := e.rv.vet(p)
	if err != nil {
		return Statfs{}, err
	}
	st, err := sysStatfs(e.rv.real(r))
	if err != nil {
		return Statfs{}, err
	}
	if m, ok := mountOf(r, e.mounts); ok {
		st.Type = m.Type
	}
	return st, nil
}

// ---- Env: facts

func (e *realEnv) Fact(key string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.facts[key]
}

func (e *realEnv) publishFacts(f map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, v := range f {
		e.facts[k] = v
	}
}

// internalFacts pass data between probes only (raw, unredacted): never given to the report.
var internalFacts = map[string]bool{"pkg_proxy_handoff": true}

func (e *realEnv) allFacts() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]string, len(e.facts))
	for k, v := range e.facts {
		if !internalFacts[k] {
			out[k] = v
		}
	}
	return out
}

// isStopping: cleanup has started (a signal or the end of the scan).
func (e *realEnv) isStopping() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopping
}

// logicalCwd is sh ES_CWD=$(pwd): PWD when it names the current folder, else os.Getwd.
func logicalCwd(pwd string) string {
	wd, err := os.Getwd()
	if pwd != "" && filepath.IsAbs(pwd) {
		if a, err1 := os.Stat(pwd); err1 == nil {
			if b, err2 := os.Stat("."); err2 == nil && os.SameFile(a, b) {
				return pwd
			}
		}
	}
	if err != nil {
		return ""
	}
	return wd
}
