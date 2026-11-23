// pa_limits.go: limits.process and net.ports (ports of src/sh/21-limits.sh, Linux branches).
//
// limits.process: sh reads /proc/self/limits (the limits of its awk child, which are the shell's)
// and falls back to the ulimit builtin. Go asks getrlimit(2) through Env.Rlimit (bytes and counts;
// stack and memlock are reported in KiB like sh) and reads /proc/self/limits only when Env cannot
// give the open-file limit.
package main

import (
	"strconv"
	"strings"
)

func init() {
	registerProbe("limits.process", probeLimitsProcess)
	registerProbe("limits.kernel", probeLimitsKernel)
	registerProbe("limits.cgroup", probeLimitsCgroup)
	registerProbe("net.ports", probeNetPorts)
}

type paLimits struct{ ns, nh, ps, ph, stk, core, ml, as string }

// paKB divides a numeric byte value by 1024 (sh $((x / 1024))); "unlimited" stays.
func paKB(s string) string {
	if !paIsNum(s) {
		return s
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return s
	}
	return strconv.FormatUint(n/1024, 10)
}

func paRlimits(e Env) (paLimits, bool) {
	nf, err := e.Rlimit(RlNofile)
	if err != nil {
		return paLimits{}, false
	}
	get := func(name string) Rlimit { l, _ := e.Rlimit(name); return l }
	np := get(RlNproc)
	return paLimits{ns: nf.Soft, nh: nf.Hard, ps: np.Soft, ph: np.Hard, stk: paKB(get(RlStack).Soft),
		core: get(RlCore).Soft, ml: paKB(get(RlMemlock).Soft), as: get(RlAS).Soft}, true
}

// paParseProcLimits is the awk of probe_limits_process over /proc/self/limits (fixed columns).
func paParseProcLimits(text string) paLimits {
	var l paLimits
	col := func(s string, from, n int) string {
		if from >= len(s) {
			return ""
		}
		end := from + n
		if end > len(s) {
			end = len(s)
		}
		return strings.ReplaceAll(s[from:end], " ", "")
	}
	for i, line := range lines(text) {
		if i == 0 {
			continue
		}
		name := strings.TrimRight(col2(line, 26), " ")
		soft, hard := col(line, 26, 21), col(line, 47, 21)
		switch name {
		case "Max open files":
			l.ns, l.nh = soft, hard
		case "Max processes":
			l.ps, l.ph = soft, hard
		case "Max stack size":
			l.stk = soft
		case "Max core file size":
			l.core = soft
		case "Max locked memory":
			l.ml = soft
		case "Max address space":
			l.as = soft
		}
	}
	l.stk, l.ml = paKB(l.stk), paKB(l.ml)
	return l
}

func col2(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

func probeLimitsProcess(e Env, r *Result) {
	l, ok := paRlimits(e)
	if ok {
		r.Src("syscall getrlimit (nofile, nproc, stack, core, memlock, as)")
	} else if text, ok2 := readText(e, r, "/proc/self/limits", 65536); ok2 {
		l = paParseProcLimits(text)
	}
	d := r.Data
	d.Set("nofile_soft", num(l.ns)).Set("nofile_hard", num(l.nh)).Set("nproc_soft", num(l.ps)).Set("nproc_hard", num(l.ph))
	d.Set("stack_kb_soft", num(l.stk)).Set("core_soft", num(l.core)).Set("memlock_kb_soft", num(l.ml))
	d.Set("address_space_soft", num(l.as))
	d.Set("units", "core_soft and address_space_soft in bytes; unlimited is the string unlimited")
	if l.ns == "" {
		r.Partial("open-file limit could not be read")
	}
	r.Fact("nofile_soft", l.ns)
	r.Fact("nofile_hard", l.nh)
	r.Fact("nproc_soft", l.ps)
}

// ---------------------------------------------------------------- net.ports

func probeNetPorts(e Env, r *Result) {
	es, ee, ups, res := "", "", "", ""
	if l, ok := readFirstLine(e, r, "/proc/sys/net/ipv4/ip_local_port_range"); ok {
		f := append(strings.Fields(l), "", "")
		es, ee = f[0], f[1]
	}
	if l, ok := readFirstLine(e, r, "/proc/sys/net/ipv4/ip_unprivileged_port_start"); ok {
		ups = l
	}
	if l, ok := readFirstLine(e, r, "/proc/sys/net/ipv4/ip_local_reserved_ports"); ok {
		res = l
	}
	d := r.Data
	d.Set("ephemeral", NewObj().Set("start", num(es)).Set("end", num(ee)))
	excl := []any{}
	if res != "" {
		for _, p := range strings.Split(res, ",") {
			start, end := p, p
			if i := strings.LastIndex(p, "-"); i >= 0 {
				start = p[:i]
			}
			if i := strings.Index(p, "-"); i >= 0 {
				end = p[i+1:]
			}
			excl = append(excl, NewObj().Set("start", num(start)).Set("end", num(end)))
		}
	}
	d.Set("excluded_tcp", excl).Set("unprivileged_port_start", num(ups)).Set("urlacl_count", nil)
	if es == "" {
		r.Partial("ephemeral port range not found")
	}
	r.Fact("eph_start", es)
	r.Fact("eph_end", ee)
	r.Fact("reserved_ports", res)
}
