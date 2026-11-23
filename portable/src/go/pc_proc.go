// pc_proc.go: proc.list, svc.list and sched.tasks (port of src/sh/27-fs.sh, Linux; owner: probes-c).
package main

import (
	"regexp"
	"strconv"
	"strings"
)

func init() {
	registerProbe("proc.list", probeProcList)
	registerProbe("svc.list", probeSvcList)
	registerProbe("sched.tasks", probeSchedTasks)
}

// nssLocal is sh es_nss_local: user-name lookups stay on this machine (the passwd sources of
// /etc/nsswitch.conf are all local, or there is no nsswitch.conf).
func nssLocal(e Env) bool {
	text, ok := readQuiet(e, "/etc/nsswitch.conf")
	if !ok {
		return true
	}
	for _, src := range strings.Fields(nssLine(text, "passwd:")) {
		switch src {
		case "files", "compat", "systemd", "cache", "db", "extrausers", "altfiles", "usrfiles":
		default:
			if !strings.HasPrefix(src, "[") && !strings.HasSuffix(src, "]") {
				return false
			}
		}
	}
	return true
}

const maxProcs = 500

// psRun runs ps like sh: numeric uids first; names (NSS) only when lookups stay local.
func psRun(e Env, r *Result) (string, string) {
	if c := tool(e, r, RunOpt{}, "ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "uid=", "-o", "comm=", "-o", "args="); c.Exit == 0 && c.Stdout != "" {
		return c.Stdout, "uid"
	}
	if !nssLocal(e) {
		return "", ""
	}
	if c := tool(e, r, RunOpt{}, "ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "user=", "-o", "comm=", "-o", "args="); c.Exit == 0 && c.Stdout != "" {
		return c.Stdout, "user"
	}
	if c := tool(e, r, RunOpt{}, "ps", "-ef"); c.Exit == 0 && c.Stdout != "" {
		return c.Stdout, "ef"
	}
	return "", ""
}

func probeProcList(e Env, r *Result) {
	out, fmtID := psRun(e, r)
	if fmtID == "" {
		if nssLocal(e) {
			r.Partial("ps did not run")
		} else {
			r.Partial("ps -o uid= is not supported here and user names would need a directory (NSS) lookup; processes were not listed")
		}
		r.Data.Set("count", nil).Set("processes", []any{}).Set("truncated", false)
		return
	}
	names := map[string]string{}
	if fmtID == "uid" {
		if text, ok := readSrc(e, r, "/etc/passwd", "read /etc/passwd (names for the numeric uids; no directory lookups)"); ok {
			names = passwdNames(text)
		}
	}
	procs, n := psRows(out, fmtID, names, e.Fact("user"), e.Fact("uid"))
	r.Data.Set("processes", procs)
	r.Data.Set("count", num(strconv.Itoa(n))).Set("truncated", n > maxProcs)
	r.Note("command lines are shown only for this user's own processes")
	if n > maxProcs {
		r.Truncated = true
	}
	r.Fact("proc_count", strconv.Itoa(n))
}

// passwdNames: uid -> the first user name of /etc/passwd with it.
func passwdNames(text string) map[string]string {
	u := map[string]string{}
	for _, l := range lines(text) {
		p := strings.Split(l, ":")
		if len(p) >= 3 && p[2] != "" {
			if _, dup := u[p[2]]; !dup {
				u[p[2]] = p[0]
			}
		}
	}
	return u
}

var psTimeRe = regexp.MustCompile(`^([0-9]+-)?[0-9]+:[0-9][0-9](:[0-9][0-9])?$`)

// psRow: one process of ps output (fmt uid, user or ef).
type psRow struct{ pid, ppid, uid, user, comm, args string }

func parsePS(f []string, fmtID string, names map[string]string) psRow {
	switch fmtID {
	case "uid":
		u := field(f, 3)
		user := u
		if nm, ok := names[u]; ok {
			user = nm
		}
		return psRow{field(f, 1), field(f, 2), u, user, field(f, 4), joinFrom(f, 5)}
	case "user":
		return psRow{field(f, 1), field(f, 2), "", field(f, 3), field(f, 4), joinFrom(f, 5)}
	}
	a := 6
	if isNum(field(f, 4)) {
		a = 8
		for i := 6; i <= 9 && i < len(f); i++ {
			if psTimeRe.MatchString(f[i-1]) {
				a = i + 1
				break
			}
		}
	}
	return psRow{field(f, 2), field(f, 3), "", field(f, 1), lastSeg(field(f, a)), joinFrom(f, a)}
}

func joinFrom(f []string, a int) string {
	if a > len(f) {
		return ""
	}
	return strings.Join(f[a-1:], " ")
}

func psRows(out, fmtID string, names map[string]string, me, myuid string) ([]any, int) {
	procs := []any{}
	n := 0
	for i, l := range lines(out) {
		if fmtID == "ef" && i == 0 {
			continue
		}
		p := parsePS(awkFields(l), fmtID, names)
		own := p.user == me
		if p.uid != "" && myuid != "" {
			own = p.uid == myuid
		}
		n++
		if n > maxProcs {
			continue
		}
		o := NewObj().Set("pid", num(p.pid)).Set("ppid", num(p.ppid)).Set("name", p.comm).Set("user", p.user)
		first, _, _ := strings.Cut(p.args, " ")
		o.Set("path", nil).Set("cmdline", nil)
		if own && strings.HasPrefix(first, "/") {
			o.Set("path", first)
		}
		if own {
			o.Set("cmdline", Cmd(p.args))
		}
		procs = append(procs, o)
	}
	return procs, n
}

// ---------------------------------------------------------------- svc.list

const maxServices = 400

// svcRow: name, display, state, start mode ("" = null).
type svcRow struct{ name, display, state, mode string }

func systemdServices(e Env, r *Result) ([]svcRow, bool) {
	c := tool(e, r, RunOpt{}, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager")
	if c.Exit != 0 || c.Stdout == "" {
		return nil, false
	}
	uf := tool(e, r, RunOpt{}, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
	modes := map[string]string{}
	for _, l := range lines(uf.Stdout) {
		f := awkFields(l)
		modes[field(f, 1)] = field(f, 2)
	}
	rows := []svcRow{}
	for _, l := range lines(c.Stdout) {
		f := awkFields(l)
		i := 1
		if !strings.HasSuffix(field(f, 1), ".service") {
			i = 2
		}
		u := field(f, i)
		row := svcRow{name: u, display: joinFrom(f, i+4), state: field(f, i+2) + "/" + field(f, i+3)}
		if m, ok := modes[u]; ok && m != "-" {
			row.mode = m
		}
		rows = append(rows, row)
	}
	return rows, true
}

func initdServices(e Env, r *Result) ([]svcRow, bool) {
	if !isDir(e, "/etc/init.d") {
		return nil, false
	}
	r.Src("list /etc/init.d")
	rows := []svcRow{}
	ents, _, _ := e.ReadDir("/etc/init.d", 0)
	for _, d := range ents {
		if !strings.HasPrefix(d.Name, ".") && isFile(e, "/etc/init.d/"+d.Name) {
			rows = append(rows, svcRow{name: d.Name})
		}
	}
	return rows, true
}

func probeSvcList(e Env, r *Result) {
	mgr := ""
	rows, ok := systemdServices(e, r)
	if ok {
		mgr = "systemd"
	} else if rows, ok = initdServices(e, r); ok {
		mgr = "sysvinit"
	}
	r.Data.Set("manager", strOrNil(mgr)).Set("count", num(strconv.Itoa(len(rows))))
	arr := []any{}
	for i, s := range rows {
		if i >= maxServices {
			break
		}
		arr = append(arr, NewObj().Set("name", s.name).Set("display", strOrNil(s.display)).
			Set("state", strOrNil(s.state)).Set("start_mode", strOrNil(s.mode)).Set("account", nil).Set("path", nil))
	}
	r.Data.Set("services", arr)
	tr := len(rows) > maxServices
	if tr {
		r.Truncated = true
	}
	r.Data.Set("truncated", tr)
	if mgr == "" {
		r.SetStatus(StNotFound, "no service manager was found (typical inside containers)")
	}
	r.Fact("svc_manager", mgr)
}

// ---------------------------------------------------------------- sched.tasks

var cronSkipRe = regexp.MustCompile(`^[ \t]*(#|$)`)

func probeSchedTasks(e Env, r *Result) {
	cron := []string{}
	if c := tool(e, r, RunOpt{}, "crontab", "-l"); c.Exit == 0 {
		for _, l := range lines(c.Stdout) {
			if !cronSkipRe.MatchString(l) {
				cron = append(cron, l)
			}
		}
	}
	uc := []any{}
	for i, l := range cron {
		if i >= 200 {
			break
		}
		uc = append(uc, Cmd(l))
	}
	r.Data.Set("user_crontab", uc)
	tasks := cronDirTasks(e, r)
	r.Data.Set("tasks", tasks)
	timers := []string{}
	if c := tool(e, r, RunOpt{}, "systemctl", "list-timers", "--all", "--no-pager", "--no-legend"); c.Exit == 0 {
		for _, l := range nonBlankLines(c.Stdout) {
			timers = append(timers, strings.Join(splitKeep(l), " "))
		}
	}
	r.Data.Set("timers", strList(timers))
	r.Data.Set("linger", boolOrNil(linger(e, r)))
	r.Data.Set("count", num(strconv.Itoa(len(tasks)+len(cron))))
}

// splitKeep is awk gsub(/[ \t]+/, " "): runs of blanks become one space (a leading run stays).
func splitKeep(l string) []string { return blankRunRe.Split(l, -1) }

var blankRunRe = regexp.MustCompile(`[ \t]+`)

// lastSeg is awk sub(/.*\//, ""): the text after the last "/".
func lastSeg(s string) string { return s[strings.LastIndex(s, "/")+1:] }

func cronDirTasks(e Env, r *Result) []any {
	out := []any{}
	for _, d := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		if !isDir(e, d) {
			continue
		}
		r.Src("list %s", d)
		ents, _, err := e.ReadDir(d, 0)
		if err != nil {
			continue
		}
		for _, f := range ents {
			if strings.HasPrefix(f.Name, ".") || !isFile(e, d+"/"+f.Name) {
				continue
			}
			out = append(out, NewObj().Set("name", f.Name).Set("path", d).Set("state", "present"))
		}
	}
	return out
}

func linger(e Env, r *Result) string {
	user := e.Fact("user")
	if user == "" {
		return ""
	}
	c := tool(e, r, RunOpt{}, "loginctl", "show-user", user, "-p", "Linger")
	if c.Exit == 127 || c.Exit == 126 {
		return ""
	}
	switch firstLine(c.Stdout) {
	case "Linger=yes":
		return "true"
	case "Linger=no":
		return "false"
	}
	return ""
}
