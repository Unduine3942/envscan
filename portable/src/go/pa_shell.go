// pa_shell.go: shell.info and shell.userland (ports of src/sh/22-user.sh).
//
// The static binary has no shell of its own: shell.info reports current_shell "none (static
// binary)" and shell_version the Go runtime version; everything else (SHELL, /etc/shells, the
// /bin/sh link target, bash/zsh --version when present, the umask at scan start) is as in sh.
package main

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

func init() {
	registerProbe("shell.info", probeShellInfo)
	registerProbe("shell.userland", probeShellUserland)
}

const paNoShell = "none (static binary)"

func probeShellInfo(e Env, r *Result) {
	r.Src("environment SHELL")
	sht := ""
	if _, err := e.Stat("/bin/sh"); err == nil {
		r.Src("list /bin/sh link target")
		rp, _ := paResolve(e, "/bin/sh")
		sht = strings.TrimSuffix(paBase(rp), ".exe")
	}
	shells := ""
	if text, ok := readText(e, r, "/etc/shells", 65536); ok {
		for _, l := range lines(text) {
			if strings.HasPrefix(l, "/") {
				shells += l + "\n"
			}
		}
	}
	bv, zv := "", ""
	if c, ok := needTool(e, r, RunOpt{}, "bash", "--version"); ok {
		bv, _ = paFirstLine(c.Stdout)
	}
	if c, ok := needTool(e, r, RunOpt{}, "zsh", "--version"); ok {
		zv, _ = paFirstLine(c.Stdout)
	}
	pw := []any{}
	for _, p := range paWhichAll(e, "pwsh") {
		pw = append(pw, p)
	}
	umask := ""
	if m, ok := e.Umask(); ok {
		umask = fmt.Sprintf("%04o", m)
		r.Src("umask at scan start")
	}
	d := r.Data
	d.Set("current_shell", paNoShell).Set("shell_version", runtime.Version()).Set("login_shell", strOrNil(paEnv(e, "SHELL")))
	d.Set("sh_target", strOrNil(sht)).Set("bash_version", strOrNil(bv)).Set("zsh_version", strOrNil(zv))
	d.Set("shells", nonEmptyLines(shells)).Set("umask", umask).Set("powershell_installed", pw)
	for _, k := range []string{"language_mode", "execution_policy", "effective_policy", "cmd_autorun", "cmd_disabled", "wsh_enabled"} {
		d.Set(k, nil)
	}
	r.Fact("sh_target", sht)
	r.Fact("bash_version", paVersionOf(bv))
	r.Fact("login_shell", paEnv(e, "SHELL"))
}

// ---------------------------------------------------------------- shell.userland

var (
	paBusyRe = regexp.MustCompile(`BusyBox|busybox|not GNU`)
	paBSDRe  = regexp.MustCompile(`BSD|bsdtar|libarchive|awk version 20`)
	paAwkRe  = regexp.MustCompile(`GNU|BusyBox|awk version`)
)

// paFlavor is sh es_flavor: gnu | bsd | busybox | other from the version output (stdout and
// stderr) and, failing that, the resolved path.
func paFlavor(e Env, out, p string) string {
	switch {
	case paBusyRe.MatchString(out):
		return "busybox"
	case paBSDRe.MatchString(out):
		return "bsd"
	case strings.Contains(out, "uutils"):
		return "other"
	case strings.Contains(out, "GNU"):
		return "gnu"
	}
	if rp, _ := paResolve(e, p); strings.Contains(rp, "/busybox") {
		return "busybox"
	}
	return "other"
}

func probeShellUserland(e Env, r *Result) {
	if e.Exists("/bin/busybox") {
		r.Src("list /bin/busybox link targets")
	}
	details, summary := NewObj(), ""
	flavors := map[string]string{}
	for _, t := range []string{"sed", "awk", "grep", "tar", "date", "find"} {
		p, ok := e.Which(t)
		if !ok {
			continue
		}
		fl, ln := paToolFlavor(e, r, t, p)
		flavors[t] = fl
		details.Set(t, NewObj().Set("path", p).Set("flavor", fl).Set("version_line", strOrNil(ln)))
		summary += " " + t + "=" + fl
	}
	d := r.Data
	d.Set("details", details)
	for _, t := range []string{"sed", "awk", "grep", "tar", "date", "find"} {
		d.Set(t, strOrNil(flavors[t]))
	}
	pl, _ := e.Which("perl")
	d.Set("perl", strOrNil(pl))
	r.Fact("userland", strings.TrimPrefix(summary, " "))
}

// paToolFlavor runs "T --version" (and "awk -W version" for an awk that does not say what it is).
func paToolFlavor(e Env, r *Result, t, p string) (string, string) {
	_, out := paRunBoth(e, r, t, "--version")
	mawk := false
	if t == "awk" && !paAwkRe.MatchString(out) {
		_, out = paRunBoth(e, r, "awk", "-W", "version")
		mawk = strings.Contains(out, "mawk")
	}
	fl := paFlavor(e, out, p)
	ln, _ := paFirstLine(out)
	if mawk {
		fl, ln = "other", ""
		for _, l := range lines(out) {
			if strings.Contains(l, "mawk") {
				ln = l
				break
			}
		}
	}
	return fl, ln
}
