// sys_common.go: system facts that need no syscall (port of es_norm_arch).
package main

import (
	"runtime"
	"strconv"
	"strings"
)

// normArch is es_norm_arch.
func normArch(m string) string {
	switch m {
	case "x86_64", "amd64", "AMD64", "x64", "X86_64":
		return "x86_64"
	case "i386", "i486", "i586", "i686", "x86", "i86pc", "i86", "X86":
		return "x86"
	case "aarch64", "arm64", "ARM64", "aarch64_be", "arm64e":
		return "arm64"
	case "ppc64le", "powerpc64le":
		return "ppc64le"
	case "ppc64", "powerpc64":
		return "ppc64"
	case "ppc", "powerpc":
		return "ppc"
	case "s390x", "riscv64", "ia64", "sparc":
		return m
	case "sparc64", "sun4u", "sun4v", "sparcv9":
		return "sparc64"
	}
	switch {
	case strings.HasPrefix(m, "arm"), strings.HasPrefix(m, "ARM"):
		return "arm"
	case strings.HasPrefix(m, "mips"):
		return "mips"
	}
	return "other"
}

// goArchMachine: the machine name of the running binary (when uname is not available).
func goArchMachine() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "386":
		return "i686"
	}
	return runtime.GOARCH
}

// parseUmask reads the "Umask:" line of /proc/self/status (octal).
func parseUmask(status string) (uint32, bool) {
	for _, l := range lines(status) {
		if v, ok := strings.CutPrefix(l, "Umask:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 8, 32)
			return uint32(n), err == nil
		}
	}
	return 0, false
}

// Rlimit resource numbers on Linux (asm-generic; amd64, arm64, s390x, ppc64le agree).
var rlimitIDs = map[string]int{RlCPU: 0, RlFsize: 1, RlData: 2, RlStack: 3, RlCore: 4, RlNproc: 6,
	RlNofile: 7, RlMemlock: 8, RlAS: 9}

// rlimitText: decimal, or "unlimited" for RLIM_INFINITY.
func rlimitText(v uint64) string {
	if v == ^uint64(0) {
		return "unlimited"
	}
	return strconv.FormatUint(v, 10)
}

// parseLimitsSoft reads the soft value of one row of /proc/<pid>/limits ("unlimited" or digits).
func parseLimitsSoft(text, row string) (uint64, bool) {
	for _, l := range lines(text) {
		rest, ok := strings.CutPrefix(l, row)
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0, false
		}
		if f[0] == "unlimited" {
			return ^uint64(0), true
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		return n, err == nil
	}
	return 0, false
}
