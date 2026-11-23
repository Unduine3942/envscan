//go:build linux

// sys_linux.go: the system calls of the release build. Isatty uses no ioctl (that would need
// unsafe): a descriptor is a terminal when fstat says character device and /proc/self/fd/N
// links to /dev/pts/*, /dev/tty* or /dev/console.
package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func sysOSName(map[string]string) string { return "linux" }

// checkBuild: the release build runs anywhere.
func checkBuild(map[string]string) error { return nil }

func cstr[T int8 | uint8](a []T) string {
	b := make([]byte, 0, len(a))
	for _, c := range a {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func sysUname(map[string]string) (Uname, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return Uname{}, err
	}
	return Uname{Sysname: cstr(u.Sysname[:]), Nodename: cstr(u.Nodename[:]), Release: cstr(u.Release[:]),
		Version: cstr(u.Version[:]), Machine: cstr(u.Machine[:])}, nil
}

func sysIds() Ids {
	g, _ := syscall.Getgroups()
	return Ids{UID: syscall.Getuid(), GID: syscall.Getgid(), EUID: syscall.Geteuid(), EGID: syscall.Getegid(), Groups: g}
}

// sysRlimit: raw getrlimit values (bytes for the size limits, seconds for cpu).
func sysRlimit(name string) (Rlimit, error) {
	id, ok := rlimitIDs[name]
	if !ok {
		return Rlimit{}, errors.New("unknown limit " + name)
	}
	var r syscall.Rlimit
	if err := syscall.Getrlimit(id, &r); err != nil {
		return Rlimit{}, err
	}
	soft := uint64(r.Cur)
	if id == rlimitIDs[RlNofile] {
		v, err := origNofileSoft(soft, uint64(r.Max))
		if err != nil {
			return Rlimit{}, err
		}
		soft = v
	}
	return Rlimit{Soft: rlimitText(soft), Hard: rlimitText(uint64(r.Max))}, nil
}

// parentNofile: the parent's soft RLIMIT_NOFILE at scan start (what this process inherited),
// read from /proc/<ppid>/limits when the parent runs under our uid.
var parentNofile, parentNofileOK = readParentNofile()

func readParentNofile() (uint64, bool) {
	pp := strconv.Itoa(os.Getppid())
	fi, err := os.Stat("/proc/" + pp)
	if err != nil {
		return 0, false
	}
	if uid, _ := fileOwner(fi); uid != os.Getuid() {
		return 0, false
	}
	b, err := os.ReadFile("/proc/" + pp + "/limits")
	if err != nil {
		return 0, false
	}
	return parseLimitsSoft(string(b), "Max open files")
}

// origNofileSoft undoes the Go runtime's start-up raise of the soft RLIMIT_NOFILE (package
// syscall sets it to hard-1 when it was lower). A soft limit of hard-1 is taken from the parent
// (the inherited value); when that is unknown or also hard-1 (a Go parent), it is an error.
func origNofileSoft(soft, hard uint64) (uint64, error) {
	if hard == ^uint64(0) || soft != hard-1 {
		return soft, nil
	}
	if parentNofileOK && parentNofile != hard-1 {
		return parentNofile, nil
	}
	return 0, errors.New("the original soft open-files limit is unknown (the Go runtime raised it at start)")
}

func sysStatfs(real string) (Statfs, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(real, &st); err != nil {
		return Statfs{}, err
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return Statfs{BlockSize: bs, Blocks: uint64(st.Blocks), Bfree: uint64(st.Bfree),
		Bavail: uint64(st.Bavail), Files: uint64(st.Files), Ffree: uint64(st.Ffree)}, nil
}

func sysIsatty(fd int) bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return false
	}
	t, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return false
	}
	return strings.HasPrefix(t, "/dev/pts/") || strings.HasPrefix(t, "/dev/tty") || t == "/dev/console"
}

// sysUmask: the process umask from /proc/self/status (never the umask syscall, which changes it).
func sysUmask() (uint32, bool) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	return parseUmask(string(b))
}

func fileOwner(fi os.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

// openNoFollow opens for reading without following a last-component link and without
// blocking on a FIFO that appeared after the lstat check.
func openNoFollow(real string) (*os.File, error) {
	return os.OpenFile(real, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

// fdPath: the path an open file has now (/proc/self/fd/N), false when /proc is not there.
func fdPath(f *os.File) (string, bool) {
	t, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	return t, err == nil
}

// unixModes: file modes and owners carry the Unix permission bits.
const unixModes = true

func dirWritable(p string) bool { return syscall.Access(p, 2) == nil }

func catchSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}
}
