// pc_fs_mounts.go: fs.mounts (port of src/sh/27-fs.sh, Linux; owner: probes-c).
package main

import (
	"strconv"
	"strings"
)

func init() {
	registerProbe("fs.mounts", probeFSMounts)
}

// mountFlags is sh es_flags_of: noexec, nosuid and read-only in a mount option list.
type mountFlags struct{ noexec, nosuid, ro bool }

func flagsOf(options string) mountFlags {
	o := "," + strings.ReplaceAll(options, " ", "") + ","
	return mountFlags{
		noexec: strings.Contains(o, ",noexec,"),
		nosuid: strings.Contains(o, ",nosuid,"),
		ro:     strings.Contains(o, ",ro,") || strings.Contains(o, ",read-only,"),
	}
}

// mountSource is sh ES_MOUNT_SRC: where the engine read the mount table at scan start.
func mountSource(e Env) string {
	if s := e.Fact("mount_src"); s != "" {
		return s
	}
	return "read /proc/self/mounts"
}

// scanCwd is sh ES_CWD: the scanner's working directory at start.
func scanCwd(e Env) string {
	if c := e.Fact("cwd"); c != "" {
		return c
	}
	c, _ := e.Getenv("PWD")
	return c
}

const maxMounts = 300

func probeFSMounts(e Env, r *Result) {
	table := e.Mounts()
	if len(table) == 0 {
		r.Partial("no mount table (no /proc/self/mounts and mount failed)")
		r.Data.Set("mounts", []any{}).Set("key_paths", NewObj())
		return
	}
	r.Src("%s (at scan start)", mountSource(e))
	arr := []any{}
	for i, m := range table {
		if i >= maxMounts {
			break
		}
		opts := []any{}
		for _, o := range strings.Split(m.Options, ",") {
			if o = trimBlank(o); o != "" {
				opts = append(opts, o)
			}
		}
		arr = append(arr, NewObj().Set("device", m.Device).Set("mount", m.Dir).Set("fstype", m.Type).Set("options", opts))
	}
	r.Data.Set("mounts", arr)
	if len(table) > maxMounts {
		r.Truncated = true
		r.Note("mount list capped at 300 of %d entries", len(table))
	}
	keyPaths(e, r)
	r.Data.Set("count", num(strconv.Itoa(len(table))))
}

// keyPaths: the mount, type and flags of /, the temp directories, HOME and the current directory.
func keyPaths(e Env, r *Result) {
	home := e.Home()
	tmpdir, _ := e.Getenv("TMPDIR")
	tmpdirOr := tmpdir
	if tmpdirOr == "" {
		tmpdirOr = "/tmp"
	}
	kp := NewObj()
	nx, rootRO := "", ""
	done := map[string]bool{}
	for _, p := range []string{"/", "/tmp", "/var/tmp", "/dev/shm", home, tmpdir, scanCwd(e)} {
		if p == "" || done[p] {
			continue
		}
		done[p] = true
		m, ok := e.MountOf(p)
		if !ok {
			continue
		}
		fl := flagsOf(m.Options)
		kp.Set(p, NewObj().Set("mount", m.Dir).Set("fstype", m.Type).Set("noexec", fl.noexec).
			Set("nosuid", fl.nosuid).Set("ro", fl.ro))
		if (p == "/tmp" || p == "/var/tmp" || p == "/dev/shm" || p == tmpdirOr) && fl.noexec {
			nx += p + "\n"
		}
		if p == "/" {
			rootRO = boolText(fl.ro)
		}
	}
	r.Data.Set("key_paths", kp)
	r.Fact("noexec_temp", nx)
	r.Fact("root_ro", rootRO)
}
