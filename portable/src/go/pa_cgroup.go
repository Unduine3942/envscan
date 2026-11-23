// pa_cgroup.go: limits.kernel and limits.cgroup (ports of src/sh/21-limits.sh, Linux branches).
package main

import (
	"fmt"
	"strconv"
	"strings"
)

var paSysctls = [][2]string{
	{"fs.file-max", "fs/file-max"}, {"fs.file-nr", "fs/file-nr"},
	{"fs.inotify.max_user_watches", "fs/inotify/max_user_watches"},
	{"fs.inotify.max_user_instances", "fs/inotify/max_user_instances"},
	{"vm.max_map_count", "vm/max_map_count"}, {"vm.overcommit_memory", "vm/overcommit_memory"},
	{"vm.swappiness", "vm/swappiness"}, {"kernel.pid_max", "kernel/pid_max"},
	{"kernel.threads-max", "kernel/threads-max"}, {"kernel.yama.ptrace_scope", "kernel/yama/ptrace_scope"},
	{"kernel.unprivileged_userns_clone", "kernel/unprivileged_userns_clone"},
	{"kernel.perf_event_paranoid", "kernel/perf_event_paranoid"},
	{"user.max_user_namespaces", "user/max_user_namespaces"}, {"net.core.somaxconn", "net/core/somaxconn"},
}

var paSysctlFacts = map[string]string{"fs.inotify.max_user_watches": "inotify_watches",
	"fs.inotify.max_user_instances": "inotify_instances", "vm.max_map_count": "max_map_count",
	"net.core.somaxconn": "somaxconn"}

func probeLimitsKernel(e Env, r *Result) {
	if !paIsDir(e, "/proc/sys") {
		r.SetStatus(StNotApplicable, "no /proc/sys on this system")
		return
	}
	r.Src("read /proc/sys/{fs,vm,kernel,user,net/core} tunables")
	d := r.Data
	for _, kv := range paSysctls {
		l, ok := paRead1Quiet(e, "/proc/sys/"+kv[1])
		if !ok {
			d.Set(kv[0], nil)
			continue
		}
		v := strings.ReplaceAll(l, "\t", " ")
		if paIsNum(v) {
			d.Set(kv[0], num(v))
		} else {
			d.Set(kv[0], v)
		}
		if f, ok := paSysctlFacts[kv[0]]; ok {
			r.Fact(f, v)
		}
	}
	if l, ok := readFirstLine(e, r, "/sys/kernel/mm/transparent_hugepage/enabled"); ok {
		thp := l
		if i := strings.Index(thp, "["); i >= 0 {
			thp = thp[i+1:]
		}
		thp, _, _ = strings.Cut(thp, "]")
		d.Set("transparent_hugepage", thp)
	} else {
		d.Set("transparent_hugepage", nil)
	}
	d.Set("limits_conf", paLimitsConf(e, r))
	d.Set("systemd_default_limits", paSystemdLimits(e, r))
}

// paLimitsConf: the setting lines of limits.conf and limits.d/*.conf as "file: line" (at most 200).
func paLimitsConf(e Env, r *Result) []any {
	files := []string{"/etc/security/limits.conf"}
	if g, err := e.Glob("/etc/security/limits.d/*.conf"); err == nil {
		files = append(files, g...)
	}
	out := ""
	for _, f := range files {
		text, ok := readText(e, r, f, 1<<20)
		if !ok {
			continue
		}
		for _, l := range lines(text) {
			if t := strings.TrimLeft(l, " \t"); t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			out += f + ": " + strings.Join(paBlankRuns(l), " ") + "\n"
		}
	}
	return paListLines(out, 200, paLine)
}

// paBlankRuns splits on runs of blanks but keeps an empty first field for leading blanks
// (awk gsub(/[ \t]+/, " ") turns a leading run into one space).
func paBlankRuns(l string) []string {
	f := strings.Fields(l)
	if l != "" && (l[0] == ' ' || l[0] == '\t') {
		f = append([]string{""}, f...)
	}
	if n := len(l); n > 0 && (l[n-1] == ' ' || l[n-1] == '\t') {
		f = append(f, "")
	}
	return f
}

func paSystemdLimits(e Env, r *Result) *Obj {
	o := NewObj()
	for _, f := range []string{"/etc/systemd/system.conf", "/etc/systemd/user.conf"} {
		text, _, err := e.ReadText(f, 1<<20)
		if err != nil {
			continue
		}
		r.Src("read %s (DefaultLimit*)", f)
		scope := strings.TrimSuffix(paBase(f), ".conf")
		for _, l := range lines(text) {
			k, v, ok := strings.Cut(l, "=")
			if ok && strings.HasPrefix(k, "DefaultLimit") {
				o.Set(scope+"."+k, paTrim(v))
			}
		}
	}
	return o
}

// ---------------------------------------------------------------- limits.cgroup

type paCg struct{ ver, path, mem, cpu, pids string }

func probeLimitsCgroup(e Env, r *Result) {
	self, ok := readText(e, r, "/proc/self/cgroup", 65536)
	if !ok {
		r.SetStatus(StNotApplicable, "no /proc/self/cgroup (not Linux)")
		return
	}
	base := "/sys/fs/cgroup"
	var cg paCg
	switch {
	case e.Exists(base + "/cgroup.controllers"):
		cg = paCgroupV2(e, r, self, base)
	case paIsDir(e, base+"/memory") || paIsDir(e, base+"/cpu") || paIsDir(e, base+"/cpu,cpuacct"):
		cg = paCgroupV1(e, r, self, base)
	}
	r.SetRaw("cgroup", self)
	d := r.Data
	d.Set("version", num(cg.ver)).Set("path", strOrNil(cg.path))
	for _, kv := range [][2]string{{"memory_max_bytes", cg.mem}, {"cpu_quota_cores", cg.cpu}, {"pids_max", cg.pids}} {
		if kv[1] == "max" {
			d.Set(kv[0], "unlimited")
		} else {
			d.Set(kv[0], num(kv[1]))
		}
	}
	if cg.ver == "" {
		r.Partial("cgroup file system not found under /sys/fs/cgroup")
	}
	r.Fact("cg_version", cg.ver)
	r.Fact("cg_mem", cg.mem)
	r.Fact("cg_cpu", cg.cpu)
	r.Fact("cg_pids", cg.pids)
}

// paCgMin is sh es_cg_min: the smaller of two limits ("max" = unlimited).
func paCgMin(cur, v string) string {
	if !paIsNum(v) {
		return cur
	}
	if !paIsNum(cur) || paNumLess(v, cur) {
		return v
	}
	return cur
}

func paCgroupV2(e Env, r *Result, self, base string) paCg {
	cg := paCg{ver: "2", mem: "max", cpu: "max", pids: "max"}
	for _, l := range lines(self) {
		f := strings.SplitN(l, ":", 3)
		if len(f) == 3 && f[0] == "0" && f[1] == "" {
			cg.path = f[2]
			break
		}
	}
	if cg.path == "" {
		cg.path = "/"
	}
	r.Src("read cgroup v2 memory.max, cpu.max, pids.max (own cgroup and parents)")
	for p := cg.path; ; {
		dir := base + strings.TrimSuffix(p, "/")
		if p == "/" {
			dir = base
		}
		if paIsDir(e, dir) {
			paCgV2Dir(e, dir, &cg)
		}
		if p == "/" {
			break
		}
		p = p[:strings.LastIndex(p, "/")]
		if p == "" {
			p = "/"
		}
	}
	return cg
}

func paCgV2Dir(e Env, dir string, cg *paCg) {
	if l, ok := paRead1Quiet(e, dir+"/memory.max"); ok {
		cg.mem = paCgMin(cg.mem, l)
	}
	if l, ok := paRead1Quiet(e, dir+"/pids.max"); ok {
		cg.pids = paCgMin(cg.pids, l)
	}
	if l, ok := paRead1Quiet(e, dir+"/cpu.max"); ok {
		f := append(strings.Fields(l), "", "")
		if paIsNum(f[0]) && paIsNum(f[1]) && strings.TrimLeft(f[1], "0") != "" {
			c := paCores(f[0], f[1])
			cf, _ := strconv.ParseFloat(c, 64)
			cur, _ := strconv.ParseFloat(cg.cpu, 64)
			if cg.cpu == "max" || cf < cur {
				cg.cpu = c
			}
		}
	}
}

// paCores is awk printf "%.2f", q / p.
func paCores(q, p string) string {
	qf, _ := strconv.ParseFloat(q, 64)
	pf, _ := strconv.ParseFloat(p, 64)
	return fmt.Sprintf("%.2f", qf/pf)
}

// paCgV1Line: the "controllers:path" of the first line whose controller list has NAME.
func paCgV1Line(self, name string) (string, string) {
	for _, l := range lines(self) {
		f := strings.SplitN(l, ":", 3)
		if len(f) == 3 && paHasStr(strings.Split(f[1], ","), name) {
			return f[1], f[2]
		}
	}
	return "", ""
}

func paCgroupV1(e Env, r *Result, self, base string) paCg {
	cg := paCg{ver: "1"}
	r.Src("read cgroup v1 memory.limit_in_bytes, cpu.cfs_quota_us, cpu.cfs_period_us, pids.max")
	_, mp := paCgV1Line(self, "memory")
	cctl, cpath := paCgV1Line(self, "cpu")
	_, pp := paCgV1Line(self, "pids")
	cg.path = mp
	for _, d := range []string{base + "/memory" + mp, base + "/memory"} {
		if l, ok := paRead1Quiet(e, d+"/memory.limit_in_bytes"); ok {
			cg.mem = l
			if strings.HasPrefix(l, "9223372036854") && len(l) > 13 && l[13] >= '0' && l[13] <= '9' {
				cg.mem = "max"
			}
			break
		}
	}
	for _, d := range []string{base + "/" + cctl + cpath, base + "/" + cctl, base + "/cpu" + cpath, base + "/cpu"} {
		q, ok := paRead1Quiet(e, d+"/cpu.cfs_quota_us")
		if !ok {
			continue
		}
		per := "100000"
		if l, ok := paRead1Quiet(e, d+"/cpu.cfs_period_us"); ok {
			per = l
		}
		if q == "-1" {
			cg.cpu = "max"
		} else if paIsNum(q) && paIsNum(per) && strings.TrimLeft(per, "0") != "" {
			cg.cpu = paCores(q, per)
		}
		break
	}
	for _, d := range []string{base + "/pids" + pp, base + "/pids"} {
		if l, ok := paRead1Quiet(e, d+"/pids.max"); ok {
			cg.pids = l
			break
		}
	}
	return cg
}
