// pa_env.go: user.profile, env.vars, env.path, session.context (ports of src/sh/22-user.sh).
package main

import (
	"sort"
	"strings"
)

func init() {
	registerProbe("env.vars", probeEnvVars)
	registerProbe("env.path", probeEnvPath)
	registerProbe("session.context", probeSessionContext)
}

// paLocalDir is es_local_path + [ -d ] + [ -w ] for a path from the environment: refused (on a
// network or autofs mount, or a link into one or into a credential store) -> ok=false.
func paLocalDir(e Env, p string) (exists, writable, ok bool) {
	if e.Refused(p) != "" || e.IsNetPath(p) {
		return false, false, false
	}
	rp, local := paResolve(e, p)
	if !local || e.IsNetPath(rp) {
		return false, false, false
	}
	fi, err := e.Stat(p)
	if isRefusal(err) {
		return false, false, false
	}
	if err != nil || fi.Type != TypeDir {
		return false, false, true
	}
	return true, paWritable(e, rp, fi), true
}

func probeUserProfile(e Env, r *Result) {
	r.Src("environment HOME, XDG_*")
	h := paEnv(e, "HOME")
	ex, wr, fs, net, ptype := "", "", "", "", ""
	if h != "" {
		rp, _ := paResolve(e, h)
		if m, ok := e.MountOf(rp); ok {
			r.Src("mount table read at scan start (file system of HOME)")
			fs, net = m.Type, "false"
			if isNetworkFSType(fs) {
				net = "true"
			}
		}
		exists, writable, local := false, false, false
		if net != "true" {
			exists, writable, local = paLocalDir(e, h)
		}
		if local {
			ex, wr = paTF(exists), paTF(writable)
		} else {
			net = "true"
			r.Note("HOME is on a network or autofs mount: it is not tested (exists and writable unknown)")
		}
		ptype = map[string]string{"true": "network", "false": "local"}[net]
	} else {
		r.Partial("HOME is not set")
	}
	d := r.Data
	d.Set("home", strOrNil(h)).Set("home_exists", boolOrNil(ex)).Set("home_writable", boolOrNil(wr))
	d.Set("home_fstype", strOrNil(fs)).Set("home_network", boolOrNil(net)).Set("profile_type", strOrNil(ptype))
	xdg := NewObj()
	for _, n := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
		"XDG_DATA_DIRS", "XDG_CONFIG_DIRS"} {
		if v := paEnv(e, n); v != "" {
			xdg.Set(n, v)
		}
	}
	d.Set("xdg", xdg).Set("redirected_folders", paUserDirs(e, r, h)).Set("onedrive", nil).Set("fslogix", nil)
	r.Fact("home_network", net)
	r.Fact("home_fstype", fs)
}

func paTF(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// paUserDirs: XDG_*_DIR settings of ~/.config/user-dirs.dirs (nil when not readable).
func paUserDirs(e Env, r *Result, h string) any {
	if h == "" {
		return nil
	}
	p := paOr(paEnv(e, "XDG_CONFIG_HOME"), h+"/.config") + "/user-dirs.dirs"
	if _, ok := paResolve(e, p); !ok {
		return nil
	}
	text, _, err := e.ReadText(p, 65536)
	if err != nil {
		return nil
	}
	r.Src("read ~/.config/user-dirs.dirs")
	o := NewObj()
	for _, l := range lines(text) {
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.HasPrefix(k, "XDG_") && strings.HasSuffix(k, "_DIR") && len(k) > len("XDG__DIR")-1 {
			o.Set(k, paUnquote(v))
		}
	}
	return o
}

// ---------------------------------------------------------------- env.vars

// probeEnvVars reports the environment snapshot taken at scan start, each value redacted by
// its name (sh es_env_capture + json.awk envev), and the number of values redaction changed.
func probeEnvVars(e Env, r *Result) {
	r.Src("process environment (captured in memory at scan start; redacted before it is written)")
	type kv struct{ k, v string }
	vars := []kv{}
	for _, s := range e.Environ() {
		k, v, _ := strings.Cut(s, "=")
		if k == "" || strings.ContainsAny(k, "\t\r\n") {
			continue
		}
		vars = append(vars, kv{k, v})
	}
	sort.SliceStable(vars, func(i, j int) bool { return vars[i].k < vars[j].k })
	proc, nred := NewObj(), 0
	for _, x := range vars {
		if e.Redact() && redactNamed(x.k, x.v) != x.v {
			nred++
		}
		proc.Set(x.k, Named{Name: x.k, Value: x.v})
	}
	r.Data.Set("process", proc).Set("redacted", nred).Set("machine", nil).Set("user", nil)
	if len(vars) == 0 {
		r.Partial("the environment could not be captured at scan start")
	}
}

// ---------------------------------------------------------------- env.path

type paPathCount struct{ miss, rel, wr int }

func probeEnvPath(e Env, r *Result) {
	r.Src("process PATH")
	r.Src("test each PATH entry (local file systems only)")
	pathv := paEnv(e, "PATH")
	var parts []string
	if pathv != "" {
		parts = strings.Split(pathv, ":")
	}
	entries, seen, n := []any{}, map[string]bool{}, paPathCount{}
	for _, p := range parts {
		entries = append(entries, paPathEntry(e, p, seen[p], &n))
		seen[p] = true
	}
	d := r.Data
	d.Set("separator", ":").Set("entries", entries)
	d.Set("missing_count", n.miss).Set("relative_count", n.rel).Set("writable_count", n.wr)
	r.Fact("path_relative", itoa(n.rel))
	r.Fact("path_missing", itoa(n.miss))
}

// paPathEntry: one PATH entry. A relative entry is tested against PWD (the shell tests it
// against its working directory); unknown without an absolute PWD.
func paPathEntry(e Env, p string, dup bool, n *paPathCount) *Obj {
	rel := !strings.HasPrefix(p, "/")
	net, ex, wr := "", "", ""
	target := p
	if rel {
		n.rel++
		pwd := paEnv(e, "PWD")
		target = ""
		if strings.HasPrefix(pwd, "/") {
			target = strings.TrimSuffix(pwd, "/") + "/" + paOr(p, ".")
		}
	} else if m, ok := e.MountOf(p); ok {
		net = paTF(isNetworkFSType(m.Type))
	}
	if net != "true" && target != "" {
		exists, writable, local := paLocalDir(e, target)
		if !local {
			net = "true"
		} else {
			ex, wr = paTF(exists), paTF(writable && exists)
			if !exists {
				n.miss++
			}
			if wr == "true" {
				n.wr++
			}
		}
	}
	o := NewObj().Set("path", p).Set("scope", "process").Set("exists", boolOrNil(ex)).Set("writable", boolOrNil(wr))
	return o.Set("network", boolOrNil(net)).Set("duplicate", dup).Set("relative", rel)
}

// ---------------------------------------------------------------- session.context

func probeSessionContext(e Env, r *Result) {
	r.Src("environment SSH_CONNECTION, SSH_TTY, DISPLAY, WAYLAND_DISPLAY, XDG_SESSION_TYPE, XDG_CURRENT_DESKTOP, TERM")
	r.Src("test whether stdin, stdout and stderr are terminals (at scan start)")
	in, out, errt := e.Isatty(0), e.Isatty(1), e.Isatty(2)
	typ := "unknown"
	switch {
	case paEnv(e, "SSH_CONNECTION")+paEnv(e, "SSH_CLIENT")+paEnv(e, "SSH_TTY") != "":
		typ = "ssh"
	case in || out:
		typ = "console"
	case paEnv(e, "INVOCATION_ID")+paEnv(e, "JOURNAL_STREAM") != "":
		typ = "service"
	}
	disp := paOr(paEnv(e, "DISPLAY"), paEnv(e, "WAYLAND_DISPLAY"))
	d := r.Data
	d.Set("type", typ).Set("interactive", in).Set("display", strOrNil(disp)).Set("display_available", disp != "")
	d.Set("terminal", strOrNil(paEnv(e, "TERM"))).Set("tty", in)
	d.Set("terminals", NewObj().Set("stdin", in).Set("stdout", out).Set("stderr", errt))
	d.Set("session_id", strOrNil(paEnv(e, "XDG_SESSION_ID"))).Set("xdg_session_type", strOrNil(paEnv(e, "XDG_SESSION_TYPE")))
	d.Set("desktop", strOrNil(paEnv(e, "XDG_CURRENT_DESKTOP"))).Set("ssh_connection", strOrNil(paEnv(e, "SSH_CONNECTION")))
	r.Fact("session_type", typ)
	r.Fact("display", paTF(disp != ""))
}
