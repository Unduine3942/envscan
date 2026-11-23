// pa_hw.go: hw.cpu and hw.memory (ports of src/sh/20-os.sh, Linux branches).
package main

import (
	"strconv"
	"strings"
)

func init() {
	registerProbe("hw.cpu", probeHWCPU)
	registerProbe("hw.memory", probeHWMemory)
	registerProbe("hw.storage", probeHWStorage)
	registerProbe("hw.gpu", probeHWGPU)
}

type paCPU struct {
	model, vendor, logical, sockets, cpc, flags, cores string
}

// paParseCPUInfo is the awk of probe_hw_cpu over /proc/cpuinfo.
func paParseCPUInfo(text string) paCPU {
	var c paCPU
	alt, n := "", 0
	sock := map[string]bool{}
	for _, l := range lines(text) {
		k, _, _ := strings.Cut(l, ":")
		k = strings.TrimRight(k, " \t")
		v := l
		if _, after, ok := strings.Cut(l, ":"); ok {
			v = strings.TrimLeft(after, " \t")
		}
		switch {
		case k == "processor" && allDigits(v):
			n++
		case k == "model name" && c.model == "":
			c.model = v
		case (k == "Hardware" || k == "Model" || k == "cpu model" || k == "cpu" || k == "uarch") && alt == "":
			alt = v
		case k == "vendor_id" && c.vendor == "":
			c.vendor = v
		case k == "CPU implementer" && c.vendor == "":
			c.vendor = "arm implementer " + v
		case k == "physical id":
			sock[v] = true
		case k == "cpu cores" && c.cpc == "":
			c.cpc = v
		case (k == "flags" || k == "Features" || k == "features") && c.flags == "":
			c.flags = v
		}
	}
	if c.model == "" {
		c.model = alt
	}
	if n > 0 {
		c.logical = strconv.Itoa(n)
	}
	if len(sock) > 0 {
		c.sockets = strconv.Itoa(len(sock))
		if paIsNum(c.cpc) {
			x, _ := strconv.Atoi(c.cpc)
			c.cores = strconv.Itoa(len(sock) * x)
		}
	}
	return c
}

// paOnlineCPUs counts a cpu list like "0-3,6" (/sys/devices/system/cpu/online, which glibc reads
// for getconf _NPROCESSORS_ONLN).
func paOnlineCPUs(s string) string {
	n := 0
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		a, b, rng := strings.Cut(part, "-")
		x, err1 := strconv.Atoi(a)
		if err1 != nil {
			return ""
		}
		y := x
		if rng {
			var err2 error
			if y, err2 = strconv.Atoi(b); err2 != nil || y < x {
				return ""
			}
		}
		n += y - x + 1
	}
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func probeHWCPU(e Env, r *Result) {
	var c paCPU
	if text, ok := readText(e, r, "/proc/cpuinfo", 8<<20); ok {
		c = paParseCPUInfo(text)
	}
	if c.logical == "" {
		if l, ok := readFirstLine(e, r, "/sys/devices/system/cpu/online"); ok {
			c.logical = paOnlineCPUs(l)
		}
	}
	if c.logical == "" {
		if t := tool(e, r, RunOpt{}, "getconf", "_NPROCESSORS_ONLN"); t.Exit == 0 {
			if l, _ := paFirstLine(t.Stdout); paIsNum(l) {
				c.logical = l
			}
		}
	}
	if c.cores == "" {
		c.cores = c.logical
	}
	lflags := strings.Fields(strings.ToLower(c.flags))
	d := r.Data
	d.Set("model", paOr(c.model, "unknown")).Set("vendor", strOrNil(c.vendor)).Set("cores", num(c.cores))
	d.Set("logical", num(c.logical)).Set("sockets", num(c.sockets))
	feat, avx2 := paCPUFeatures(e.Arch(), c.flags != "", lflags)
	d.Set("features", feat)
	fl := []any{}
	for _, f := range lflags {
		fl = append(fl, f)
	}
	d.Set("flags", fl)
	if c.model == "" {
		r.Partial("CPU model not found")
	}
	r.Fact("cpu_logical", c.logical)
	r.Fact("cpu_model", c.model)
	r.Fact("cpu_avx2", avx2)
}

// paCPUFeatures is the features object of probe_hw_cpu (es_cpu_tf).
func paCPUFeatures(arch string, hasFlags bool, lflags []string) (*Obj, string) {
	tf := func(names ...string) any {
		for _, n := range names {
			if paHasStr(lflags, n) {
				return true
			}
		}
		return false
	}
	o := NewObj()
	keys := []string{"sse4_2", "avx", "avx2", "avx512f", "aes", "neon"}
	switch {
	case (hasFlags || arch == "arm64") && (arch == "x86_64" || arch == "x86"):
		o.Set("sse4_2", tf("sse4_2", "sse4.2")).Set("avx", tf("avx", "avx1.0")).Set("avx2", tf("avx2"))
		o.Set("avx512f", tf("avx512f")).Set("aes", tf("aes")).Set("neon", false)
		return o, strconv.FormatBool(tf("avx2").(bool))
	case (hasFlags || arch == "arm64") && (arch == "arm64" || arch == "arm"):
		o.Set("sse4_2", false).Set("avx", false).Set("avx2", false).Set("avx512f", false).Set("aes", tf("aes"))
		o.Set("neon", arch == "arm64" || tf("neon", "asimd").(bool))
		return o, "false"
	}
	for _, k := range keys {
		o.Set(k, nil)
	}
	return o, ""
}

// ---------------------------------------------------------------- hw.memory

func probeHWMemory(e Env, r *Result) {
	tot, av, st, sf := "", "", "", ""
	if text, ok := readText(e, r, "/proc/meminfo", 1<<20); ok {
		tot, av, st, sf = paParseMeminfo(text)
	}
	if tot == "" {
		tot = paPhysPages(e, r)
	}
	d := r.Data
	d.Set("total_mb", num(tot)).Set("available_mb", num(av)).Set("swap_total_mb", num(st)).Set("swap_free_mb", num(sf))
	if tot == "" {
		r.Partial("total memory could not be determined")
	}
	if av == "" {
		r.Note("available memory is not reported on this system")
	}
	r.Fact("mem_total_mb", tot)
	r.Fact("mem_avail_mb", av)
}

// paParseMeminfo is the awk of probe_hw_memory: MiB values ("" when absent).
func paParseMeminfo(text string) (tot, av, st, sf string) {
	v := map[string]int64{}
	has := map[string]bool{}
	for _, l := range lines(text) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.ParseInt(f[1], 10, 64)
		v[f[0]], has[f[0]] = n, true
	}
	mb := func(k int64) string { return strconv.FormatInt(k/1024, 10) }
	a := v["MemAvailable:"]
	if !has["MemAvailable:"] {
		a = v["MemFree:"] + v["Buffers:"] + v["Cached:"]
	}
	if t := v["MemTotal:"]; t != 0 {
		tot, av = mb(t), mb(a)
	}
	if has["SwapTotal:"] {
		st, sf = mb(v["SwapTotal:"]), mb(v["SwapFree:"])
	}
	return tot, av, st, sf
}

// paPhysPages is the sh fallback: getconf _PHYS_PAGES * getconf PAGESIZE (when present).
func paPhysPages(e Env, r *Result) string {
	c := tool(e, r, RunOpt{}, "getconf", "_PHYS_PAGES")
	pp, _ := paFirstLine(c.Stdout)
	if c.Exit != 0 || !paIsNum(pp) {
		return ""
	}
	c = tool(e, r, RunOpt{}, "getconf", "PAGESIZE")
	ps, _ := paFirstLine(c.Stdout)
	if c.Exit != 0 || !paIsNum(ps) {
		return ""
	}
	p, _ := strconv.ParseFloat(pp, 64)
	s, _ := strconv.ParseFloat(ps, 64)
	return strconv.FormatInt(int64(p*s/1048576), 10)
}
