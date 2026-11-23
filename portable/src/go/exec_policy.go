// exec_policy.go: what the scanner may execute (port of es_which, es_exec_file, es_runnable,
// es_runnable_os, es_runnable_dir, es_shim_of and es_child / es_child_env of envscan.sh).
// Never: version-manager shims, WSL /mnt binaries, binaries on network mounts or reached through
// a link into a credential store, PowerShell shims, Windows app aliases, corepack shims, remote
// container engines, binaries in world-writable folders without the sticky bit.
package main

import (
	"os"
	"path"
	"slices"
	"sort"
	"strings"
)

// whichPath is es_which over the snapshot PATH (relative and empty entries and entries on
// network mounts are skipped).
func (e *realEnv) whichPath(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if strings.Contains(name, "/") {
		return name, e.execFile(name)
	}
	for _, d := range strings.Split(e.vars["PATH"], ":") {
		if !strings.HasPrefix(d, "/") || e.pathSkip[d] {
			continue
		}
		c := strings.TrimSuffix(d, "/") + "/" + name
		if e.execFile(c) {
			return c, true
		}
	}
	return "", false
}

// execFile is es_exec_file: an executable regular file, reached only through vetted links.
func (e *realEnv) execFile(p string) bool {
	rv := e.execRv()
	r, err := rv.vet(p)
	if err != nil {
		return false
	}
	fi, err := os.Lstat(rv.real(r))
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// Runnable is es_runnable: ok, or the reason the scanner must not execute p.
func (e *realEnv) Runnable(p string) (bool, string) {
	if e.underTemp(p) {
		return e.ownRunnable(p)
	}
	if why := e.execRv().refusedWhy(p); why != "" {
		return false, refusedRunWhy(why)
	}
	if id := e.shimOf(dirOf(p)); id != "" {
		return false, "version-manager shim (" + id + ", not executed)"
	}
	if why := pathRuleWhy(p, e.wsl); why != "" {
		return false, why
	}
	if why := e.linkShimWhy(p); why != "" {
		return false, why
	}
	if why := runnableOSWhy(p, e.vars); why != "" {
		return false, why
	}
	if why := e.runnableDirWhy(p); why != "" {
		return false, why
	}
	return true, ""
}

// refusedRunWhy: the user-facing reason for a refused executable path.
func refusedRunWhy(why string) string {
	switch why {
	case whyCred, whyCredLink:
		return "link to a credential store (not executed)"
	case whyNet:
		return "on a network or autofs mount (not executed)"
	}
	return why + " (not executed)"
}

func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

func pathRuleWhy(p string, wsl bool) string {
	if wsl && len(p) >= 7 && strings.HasPrefix(p, "/mnt/") && isLetter(p[5]) && p[6] == '/' {
		return "Windows binary under /mnt (WSL interop, not executed)"
	}
	if strings.HasSuffix(p, ".ps1") {
		return "PowerShell shim (not executed)"
	}
	if isWindowsAppsPath(p) {
		return "Windows app execution alias (not executed; may open the Microsoft Store)"
	}
	return ""
}

// isWindowsAppsPath matches */[Mm]icrosoft/[Ww]indows[Aa]pps/*.
func isWindowsAppsPath(p string) bool {
	const n = len("/microsoft/windowsapps/")
	for i := 0; i+n <= len(p); i++ {
		s := p[i : i+n]
		if s[0] == '/' && (s[1] == 'M' || s[1] == 'm') && s[2:11] == "icrosoft/" && (s[11] == 'W' || s[11] == 'w') &&
			s[12:18] == "indows" && (s[18] == 'A' || s[18] == 'a') && s[19:23] == "pps/" {
			return true
		}
	}
	return false
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// linkShimWhy: a link that leads to a corepack or version-manager shim.
func (e *realEnv) linkShimWhy(p string) string {
	rv := e.execRv()
	if _, isLink := rv.linkTarget(p); !isLink {
		return ""
	}
	real, _ := rv.resolve(p)
	if strings.Contains(real, "/corepack/") {
		return "corepack shim (may download, not executed)"
	}
	if id := e.shimOf(dirOf(real)); id != "" {
		return "link to a version-manager shim (" + id + ", not executed)"
	}
	return ""
}

// runnableOSWhy is es_runnable_os on Linux: remote container engines.
func runnableOSWhy(p string, vars map[string]string) string {
	switch p[strings.LastIndexByte(p, '/')+1:] {
	case "docker", "docker.exe", "docker-compose":
		h := vars["DOCKER_HOST"]
		for _, pre := range []string{"tcp://", "ssh://", "http://", "https://"} {
			if strings.HasPrefix(h, pre) {
				return "DOCKER_HOST points to a remote engine (not executed)"
			}
		}
		if vars["DOCKER_CONTEXT"] != "" {
			return "DOCKER_CONTEXT is set and may name a remote engine (not executed)"
		}
	case "podman", "podman.exe", "podman-remote":
		if vars["CONTAINER_HOST"]+vars["CONTAINER_CONNECTION"] != "" {
			return "CONTAINER_HOST or CONTAINER_CONNECTION selects a remote podman engine (not executed)"
		}
	}
	return ""
}

const (
	worldWritableWhy = "in a world-writable directory without the sticky bit (not executed)"
	stickyOtherWhy   = "in a world-writable directory and owned by another user (not executed)"
	groupOtherWhy    = "in a group-writable directory of another user (not executed)"
)

// runnableDirWhy is es_runnable_dir plus the owner rules, for the folder of the given path and
// the folder of the resolved path (each folder's mode and owner are remembered).
func (e *realEnv) runnableDirWhy(p string) string {
	if !unixModes {
		return ""
	}
	rv := e.execRv()
	file, err := e.execStat(rv, p)
	if err != nil {
		return ""
	}
	me := sysIds().EUID
	dirs := []string{parentDir(p)}
	if r, err := rv.vet(p); err == nil && parentDir(r) != dirs[0] {
		dirs = append(dirs, parentDir(r))
	}
	for _, d := range dirs {
		fi, ok := e.dirInfo(rv, d)
		if !ok {
			continue
		}
		if why := execDirWhy(fi.Mode, fi.UID, file.UID, me); why != "" {
			return why
		}
	}
	return ""
}

// execDirWhy: "" or why a file owned by fileUID in a folder (mode, owner dirUID) must not run
// for user me (-1 = unknown owner: only the mode rule applies).
func execDirWhy(dirMode uint32, dirUID, fileUID, me int) string {
	trusted := func(uid int) bool { return uid < 0 || uid == 0 || uid == me }
	switch {
	case dirMode&0o002 != 0 && dirMode&0o1000 == 0:
		return worldWritableWhy
	case dirMode&0o002 != 0 && !trusted(fileUID):
		return stickyOtherWhy
	case dirMode&0o020 != 0 && !trusted(dirUID):
		return groupOtherWhy
	}
	return ""
}

// parentDir: the folder of an absolute path ("/" for a file directly under "/").
func parentDir(p string) string {
	if d := dirOf(p); d != "" {
		return d
	}
	return "/"
}

// dirInfo: the mode and owner of a folder (remembered per folder).
func (e *realEnv) dirInfo(rv *resolver, d string) (FileInfo, bool) {
	e.mu.Lock()
	fi, seen := e.wwSeen[d]
	e.mu.Unlock()
	if seen {
		return fi, fi.Name != ""
	}
	got, err := e.execStat(rv, d)
	if err != nil {
		got = FileInfo{}
	} else {
		got.Name = d
	}
	e.mu.Lock()
	e.wwSeen[d] = got
	e.mu.Unlock()
	return got, got.Name != ""
}

// execStat: Stat through the resolver of executables.
func (e *realEnv) execStat(rv *resolver, p string) (FileInfo, error) {
	r, err := rv.vet(p)
	if err != nil {
		return FileInfo{}, err
	}
	fi, err := os.Lstat(rv.real(r))
	if err != nil {
		return FileInfo{}, err
	}
	return toFileInfo(path.Base(p), fi), nil
}

// shimOf is es_shim_of: the version manager whose marker the lower-cased folder holds (and
// whose required executable is in it), "" when none.
func (e *realEnv) shimOf(dir string) string {
	d := normDirText(dir)
	e.mu.Lock()
	id, seen := e.shimSeen[d]
	e.mu.Unlock()
	if seen {
		return id
	}
	id = e.findShim(d)
	e.mu.Lock()
	e.shimSeen[d] = id
	e.mu.Unlock()
	return id
}

func (e *realEnv) findShim(d string) string {
	ld := asciiLower(d)
	for _, vm := range spec.VManagers {
		for _, m := range vm.Markers {
			if m == "" || !strings.Contains(ld, asciiLower(m)) {
				continue
			}
			if vm.Requires != "" && !e.execFile(d+"/"+vm.Requires) && !e.execFile(d+"/"+vm.Requires+".exe") {
				continue
			}
			return vm.ID
		}
	}
	return ""
}

// childEnv is es_child + es_child_env: the scan-start variables of the spec allowlist
// (child_env_keep), the spec child_env, DOCKER_CONTEXT=default, LC_ALL=C (or the user's LC_ALL
// for UserLocale), then the call's extra variables. Everything else (proxies, tokens,
// LD_PRELOAD, NODE_OPTIONS, BASH_ENV, DOCKER_HOST, ...) stays out; env.vars still reports it.
func (e *realEnv) childEnv(opt RunOpt) []string {
	m := make(map[string]string, len(spec.ChildEnvKeepNames)+len(spec.ChildEnv)+8)
	for k, v := range e.keptChildVars() {
		m[k] = v
	}
	for k, v := range spec.ChildEnv {
		m[k] = v
	}
	m["DOCKER_CONTEXT"] = "default"
	m["LC_ALL"] = "C"
	if opt.UserLocale {
		if orig, ok := e.vars["LC_ALL"]; ok {
			m["LC_ALL"] = orig
		} else {
			delete(m, "LC_ALL")
		}
	}
	for _, kv := range opt.Env {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case !ok || !validEnvName(k):
		case v == "":
			delete(m, k) // "NAME=" unsets NAME in the child
		default:
			m[k] = v
		}
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// childKeepName: NAME is in spec child_env_keep (exact match) or starts with one of its prefixes.
// Windows-only names ("(X86)") never match.
func childKeepName(name string) bool {
	if name == "" || strings.ContainsRune(name, '(') {
		return false
	}
	if slices.Contains(spec.ChildEnvKeepNames, name) {
		return true
	}
	for _, p := range spec.ChildEnvKeepPrefixes {
		if p != "" && strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// keptChildVars: the scan-start variables of the spec allowlist with their paths vetted
// (replaceRefusedHomes); computed once the temp folder exists, then shared (read only).
func (e *realEnv) keptChildVars() map[string]string {
	e.mu.Lock()
	kept := e.keptEnv
	e.mu.Unlock()
	if kept != nil {
		return kept
	}
	kept = map[string]string{}
	for k, v := range e.vars {
		if childKeepName(k) {
			kept[k] = v
		}
	}
	e.replaceRefusedHomes(kept)
	if e.TempDir() != "" {
		e.mu.Lock()
		e.keptEnv = kept
		e.mu.Unlock()
	}
	return kept
}

// replaceRefusedHomes: kept variables holding paths are vetted without touching them (spec
// child_env_keep home_paths and path_lists): a refused home becomes an empty folder in the temp
// folder (TMPDIR, TMP and TEMP: the temp folder itself), refused entries of a ":" list are dropped
// (a list left empty is removed), and any other refused absolute path is removed.
func (e *realEnv) replaceRefusedHomes(m map[string]string) {
	for k, v := range m {
		switch {
		case slices.Contains(spec.ChildEnvHomePaths, k):
			if strings.HasPrefix(v, "/") && e.homeRefused(v) {
				m[k] = e.homeStandIn(k)
			}
		case slices.Contains(spec.ChildEnvPathLists, k):
			e.vetPathList(m, k, v)
		case strings.HasPrefix(v, "/") && e.homeRefused(v):
			delete(m, k)
		}
	}
}

// homeStandIn: what a child gets instead of a refused home folder
func (e *realEnv) homeStandIn(k string) string {
	d := ""
	if k == "TMPDIR" || k == "TMP" || k == "TEMP" {
		d = e.TempDir()
	} else {
		d = e.childEmptyDir()
	}
	if d == "" {
		return "/nonexistent"
	}
	return d
}

// vetPathList: the ":" list m[k] without its refused absolute entries; removed when left empty
func (e *realEnv) vetPathList(m map[string]string, k, v string) {
	parts := strings.Split(v, ":")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if !strings.HasPrefix(p, "/") || !e.homeRefused(p) {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(parts) {
		return
	}
	if joined := strings.Join(kept, ":"); joined != "" {
		m[k] = joined
	} else {
		delete(m, k)
	}
}

// homeRefused: v is on a network or autofs mount or is (in) a credential store, for the paths the
// children see and for the logical paths below ENVSCAN_ROOT.
func (e *realEnv) homeRefused(v string) bool {
	for _, rv := range []*resolver{e.rv, e.execRv()} {
		switch rv.refusedWhy(v) {
		case whyNet, whyCred, whyCredLink:
			return true
		}
	}
	return false
}

// childDir: a folder made by MkdirUnique (real path), else "/".
func (e *realEnv) childDir(dir string) string {
	if dir != "" {
		real := e.ownSpace(dir)
		e.mu.Lock()
		ok := e.own[real]
		e.mu.Unlock()
		if ok {
			return real
		}
	}
	return string(os.PathSeparator)
}

// ownRunnable: below the scanner's temp folder (real paths) only a file inside a folder made by
// MkdirUnique may run (the fs.exec_test script).
func (e *realEnv) ownRunnable(p string) (bool, string) {
	if !e.inOwn(p) {
		return false, "in the scanner's temp folder but not in a test folder (not executed)"
	}
	return true, ""
}
