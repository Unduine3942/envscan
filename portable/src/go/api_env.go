// api_env.go: Env, the only way a probe touches the system (owner: main).
//
// The engine implements it for real (engine files); tests use fakeEnv (env_fake_test.go). All
// paths are LOGICAL absolute paths ("/etc/os-release"); the engine adds the test-only
// ENVSCAN_ROOT prefix. Every file method vets the path first (sh es_local_path / es_cred_path /
// es_ca_path rules): a path on a network or autofs mount, a credential store, or a link that
// leads into either is never touched and returns an *Refusal error. Nothing here follows a link
// before its target has been vetted.
package main

import (
	"errors"
	"time"
)

// Refusal is returned for paths the scanner must not touch. Reason is user-facing
// ("network or autofs mount", "credential store").
type Refusal struct{ Path, Reason string }

func (r *Refusal) Error() string { return r.Path + ": not touched (" + r.Reason + ")" }

// ErrBinary: the file is UTF-16 that cannot be decoded to text, or holds NUL bytes (sh es_text_ok).
var ErrBinary = errors.New("UTF-16 or binary content")

// ErrNotRegular: a FIFO, device or socket (never opened).
var ErrNotRegular = errors.New("not a regular file")

func isRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}

type FileType int

const (
	TypeOther FileType = iota
	TypeFile
	TypeDir
	TypeLink
)

type FileInfo struct {
	Name    string
	Type    FileType // Lstat: TypeLink for a link; Stat: the target's type
	Size    int64
	Mode    uint32 // permission bits (0o777 plus setuid/setgid/sticky as 0o7000)
	ModTime time.Time
	UID     int // -1 when unknown
	GID     int
}

type DirEntry struct {
	Name string
	Type FileType // from the directory listing (TypeLink for links; never followed)
}

type CmdResult struct {
	Path      string // resolved executable ("" when not found)
	Args      []string
	Stdout    string
	Stderr    string // "" when MergeStderr
	Exit      int    // 0..255; 126 = refused (shim, network mount, ...); 127 = not found; -1 = could not start
	Why       string // reason for 126 / -1
	TimedOut  bool
	Truncated bool // output cut at RunOpt.MaxBytes
	Duration  time.Duration
}

// RunOpt: zero value = default timeout, stdout and stderr apart, LC_ALL=C, cwd "/".
type RunOpt struct {
	Timeout     time.Duration // 0 = the scan's --timeout
	MergeStderr bool          // stderr appended to Stdout (sh es_cmd_merged)
	UserLocale  bool          // keep the user's locale (os.time_locale only)
	Dir         string        // working directory: must be a directory made by MkdirUnique, else "/"
	Env         []string      // extra NAME=value (only what the footprint says, e.g. XDG_CACHE_HOME)
	MaxBytes    int           // 0 = 4 MiB
}

type Uname struct{ Sysname, Nodename, Release, Version, Machine string }

type Statfs struct {
	Type                             string // file system type name from the mount table, "" when unknown
	BlockSize, Blocks, Bfree, Bavail uint64
	Files, Ffree                     uint64
}

type Mount struct{ Device, Dir, Type, Options string }

type Ids struct {
	UID, GID, EUID, EGID int
	Groups               []int
}

// Rlimit values are decimal text or "unlimited" (sh ulimit output form).
type Rlimit struct{ Soft, Hard string }

// Rlimit names (resource ids are the engine's business).
const (
	RlNofile  = "nofile"
	RlNproc   = "nproc"
	RlStack   = "stack"   // bytes
	RlCore    = "core"    // bytes
	RlMemlock = "memlock" // bytes
	RlAS      = "as"      // bytes
	RlData    = "data"
	RlFsize   = "fsize"
	RlCPU     = "cpu"
)

type Env interface {
	// ---- scan context
	OS() string   // "linux" (release); fixtures may say otherwise in test mode
	Arch() string // normalized like sh es_norm_arch: x86_64, arm64, s390x, ppc64le, ...
	Deep() bool
	Net() bool
	Redact() bool
	Timeout() time.Duration // per-command default (--timeout)
	Deadline() time.Time    // scan budget end
	TestRoot() string       // ENVSCAN_ROOT ("" normally); only for run.test_root and notes
	Log(msg string)

	// ---- environment (snapshot taken at scan start, before the scanner changed anything)
	Getenv(name string) (string, bool)
	Environ() []string // "NAME=value", sorted by name
	Home() string      // HOME from the snapshot ("" when unset)

	// ---- files (vetted; logical paths)
	ReadFile(path string, max int) ([]byte, bool, error)    // data, truncated, err (regular files only)
	ReadText(path string, max int) (string, bool, error)    // like ReadFile; UTF-16 decoded; ErrBinary otherwise
	ReadDir(path string, max int) ([]DirEntry, bool, error) // sorted by name; at most max (0 = 10000), truncated flag
	Stat(path string) (FileInfo, error)                     // follows a link only after vetting its target
	Lstat(path string) (FileInfo, error)
	Readlink(path string) (string, error)
	Glob(pattern string) ([]string, error) // sorted; skips (never lists) refused folders
	Exists(path string) bool               // Lstat succeeds
	Refused(path string) string            // "" or the refusal reason (no syscall on a refused path)
	Expand(path string) (string, bool)     // spec path: "~" = HOME, "{env:NAME}" (false when unset)

	// ---- mounts (mount table read at scan start)
	Mounts() []Mount
	MountOf(path string) (Mount, bool) // the mount that holds path (longest prefix)
	IsNetPath(path string) bool        // on a network or autofs mount

	// ---- commands
	// Which finds NAME on PATH (entries on network mounts are not searched). It does not say whether
	// the file may run: Run refuses shims, WSL /mnt binaries and network mounts (Exit 126, Why).
	Which(name string) (string, bool)
	Runnable(path string) (bool, string) // ok, or the reason it must not run
	Run(opt RunOpt, path string, args ...string) CmdResult

	// ---- system calls
	Uname() (Uname, error)
	Ids() Ids
	Rlimit(name string) (Rlimit, error)
	Statfs(path string) (Statfs, error) // vetted path; never on a network mount
	Isatty(fd int) bool                 // fd 0, 1, 2 at scan start
	Umask() (uint32, bool)              // from /proc/self/status at scan start (never the umask syscall)
	Hostname() string
	Now() time.Time

	// ---- writes (only below dirs this run made; never Desktop, Documents, synced or network folders)
	TempDir() string                                      // the scanner's private temp dir (real path)
	MkdirUnique(parent string) (string, error)            // new 0700 dir with a unique name in parent (logical path)
	WriteNew(path string, data []byte, perm uint32) error // exclusive create inside an own dir
	Symlink(target, path string) error                    // inside an own dir
	Link(oldPath, newPath string) error                   // hard link inside an own dir
	RemoveOwn(dir string) error                           // remove a dir made by MkdirUnique, with its content

	// ---- facts of earlier probes (ok/partial ones) and from scan start
	Fact(key string) string
}
