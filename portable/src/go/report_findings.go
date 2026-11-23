// report_findings.go: port of src/sh/30-findings.sh (Linux rules and the generic ones).
//
// Rules read the facts (sh ES_F_*, here facts[KEY]) that probes published and the probe
// statuses. Severity, title and recommendation come from spec/findings.toml; a rule only
// decides whether the finding applies and writes a one-line detail. Facts of probes that did
// not end ok or partial are absent, so a rule never fires on missing data; a rule that
// concludes from an absence also asks that the probe completed (hasFacts / done).
package main

import (
	"strconv"
	"strings"
)

func init() {
	computeFindings = goComputeFindings
}

type rawFinding struct{ id, detail, evidence string }

// fctx is the state of one findings run.
type fctx struct {
	facts  map[string]string
	status map[string]string // probe id -> status (only probes in the results)
	order  []*Result
	arch   string // sh ES_ARCH (doc host.arch)
	found  []rawFinding
}

func (c *fctx) f(k string) string { return c.facts[k] }

// find is sh es_find ID DETAIL EVIDENCE (tabs and line breaks in DETAIL become spaces).
func (c *fctx) find(id, detail, evidence string) {
	detail = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(detail)
	c.found = append(c.found, rawFinding{id, detail, evidence})
}

// pstatus is sh es_pstatus: the status of a probe, ok=false when it is not in the results.
func (c *fctx) pstatus(id string) (string, bool) {
	s, ok := c.status[id]
	return s, ok
}

// done is sh es_done: ok, not_found or not_applicable.
func (c *fctx) done(id string) bool {
	s, _ := c.pstatus(id)
	return s == StOK || s == StNotFound || s == StNotApplicable
}

// hasFacts is sh es_has_facts: ok or not_found.
func (c *fctx) hasFacts(id string) bool {
	s, _ := c.pstatus(id)
	return s == StOK || s == StNotFound
}

func threshold(name string) float64 {
	v, _ := spec.Thresholds[name].(float64)
	return v
}

func thresholdText(name string) string { return awkPrintNum(threshold(name)) }

func goComputeFindings(doc *Obj, results []*Result, facts map[string]string) []any {
	c := &fctx{facts: facts, status: map[string]string{}, order: results, arch: textOf(objOf(doc, "host"), "arch")}
	if c.facts == nil {
		c.facts = map[string]string{}
	}
	for _, r := range results {
		c.status[r.ID] = r.Status
	}
	c.rulesExec()
	c.rulesTLSPkg()
	c.rulesNet()
	c.rulesPlatform()
	c.rulesLimits()
	c.rulesFSUser()
	c.rulesScan()
	return c.ordered()
}

// ordered: blockers, warnings, info; spec order inside a severity; the first detail of an id wins.
func (c *fctx) ordered() []any {
	first := map[string]rawFinding{}
	for _, f := range c.found {
		if _, dup := first[f.id]; !dup {
			first[f.id] = f
		}
	}
	out := []any{}
	for _, sev := range []string{"blocker", "warning", "info"} {
		for _, s := range spec.Findings {
			f, ok := first[s.ID]
			if s.Severity != sev || !ok {
				continue
			}
			ev := []any{}
			for _, e := range strings.Split(f.evidence, "|") {
				if e != "" {
					ev = append(ev, e)
				}
			}
			out = append(out, NewObj().Set("id", s.ID).Set("severity", s.Severity).Set("title", s.Title).
				Set("detail", f.detail).Set("recommendation", s.Recommendation).Set("evidence", ev))
		}
	}
	return out
}

func (c *fctx) rulesExec() {
	if v := c.f("noexec_temp"); v != "" {
		c.find("exec.noexec_temp", "mounted noexec: "+shJoin(v, 5), "fs.mounts")
	}
	mac := ""
	if c.f("selinux") == "enforcing" {
		mac = "SELinux enforcing"
	}
	if p := c.f("aa_profile"); c.f("apparmor") == "enabled" && p != "" && !strings.HasPrefix(p, "unconfined") {
		mac = appendSep(mac, "; ", "AppArmor profile "+p)
	}
	if c.f("fapolicyd") == "active" {
		mac = appendSep(mac, "; ", "fapolicyd active")
	}
	if mac != "" {
		c.find("exec.mac_enforcing", mac, "sec.app_control")
	}
	ac, ev := "", ""
	if c.f("fapolicyd") == "active" {
		ac, ev = "fapolicyd is active (only trusted executables may run)", "sec.app_control"
	}
	if b := c.f("exec_blocked"); b != "" {
		ac = appendSep(ac, "; ", "execution test blocked in: "+b)
		ev = appendSep(ev, "|", "fs.exec_test")
	}
	if ac != "" {
		c.find("exec.app_control", ac, ev)
	}
}

func (c *fctx) rulesTLSPkg() {
	// the darwin System keychain branch of sh is left out (Linux only)
	if n, ok := shInt(c.f("ca_custom")); ok && n > 0 {
		c.find("tls.enterprise_ca", c.f("ca_custom")+" locally added CA certificate(s): "+shJoin(c.f("ca_subjects"), 3), "tls.trust")
	}
	if c.f("default_route") == "false" && c.hasFacts("net.routes") {
		c.find("tls.offline_pki", "no default route: online revocation checks (CRL/OCSP) and root updates cannot be reached", "net.routes|tls.trust")
	}
	tv := ""
	if v := c.f("tls_disabled_env"); v != "" {
		tv = "environment: " + shJoin(v, 5)
	}
	if v := c.f("tls_disabled_cfg"); v != "" {
		tv = appendSep(tv, "; ", "config: "+shJoin(v, 3))
	}
	if tv != "" {
		c.find("tls.verification_disabled", tv, "tls.trust|pkg.sources")
	}
	if v := c.f("endpoints_internal"); v != "" {
		c.find("pkg.mirror", "configured endpoints: "+shJoin(v, 5), "pkg.sources")
	}
	if v := c.f("caches"); v != "" {
		c.find("pkg.offline_cache", "caches: "+shJoin(v, 8), "pkg.caches")
	}
	if c.done("pkg.sources") && c.done("pkg.caches") && c.done("net.proxy") &&
		c.f("endpoints_internal") == "" && c.f("proxy") != "true" && c.f("caches") == "" {
		d := "no internal registry or mirror in " + c.f("pkg_config_count") + " package config file(s), no proxy, no local dependency cache"
		if v := c.f("endpoints_public"); v != "" {
			d += "; only public endpoints: " + shJoin(v, 3)
		}
		c.find("pkg.no_source", d, "pkg.sources|pkg.caches|net.proxy")
	}
}

func (c *fctx) rulesNet() {
	if c.f("proxy") == "true" {
		c.find("net.proxy_configured", "proxy: "+orDefault(shJoin(c.f("proxy_hosts"), 5), "configured (see net.proxy)"), "net.proxy")
	}
	if c.f("default_route") == "false" && c.hasFacts("net.routes") {
		c.find("net.no_route", "no default gateway in the routing table", "net.routes")
	}
	if lp := c.f("listen_ports"); lp != "" {
		used := ""
		ports, _ := spec.Thresholds["common_ports"].([]any)
		for _, p := range ports {
			ps := awkPrintNum(p.(float64))
			if strings.Contains(" "+lp+" ", " "+ps+" ") {
				used += " " + ps
			}
		}
		if used != "" {
			c.find("net.ports_in_use", "already listening:"+used, "net.listening")
		}
	}
}

func (c *fctx) rulesPlatform() {
	if k := c.f("libc_kind"); k != "" {
		d := k + " " + c.f("libc_version")
		if g := c.f("glibcxx_max"); g != "" {
			d += "; libstdc++ up to GLIBCXX_" + g
		}
		c.find("native.libc", d, "native.deps")
	}
	c.archMismatch()
	if c.f("fips") == "true" {
		c.find("crypto.fips", "FIPS mode enabled (kernel fips_enabled=1"+ifSet(c.f("crypto_policy"), ", crypto policy "+c.f("crypto_policy"))+")", "sec.crypto")
	}
	if c.f("pending_reboot") == "true" {
		c.find("os.pending_reboot", orDefault(shJoin(c.f("pending_reasons"), 3), "reboot pending"), "os.health")
	}
	if l := c.legacy(); l != "" {
		c.find("os.legacy", l, "os.identity|shell.info")
	}
	if c.f("container") == "true" {
		d := "engine: " + orDefault(c.f("container_engine"), "unknown")
		if c.f("kubernetes") == "true" {
			d += ", Kubernetes"
		}
		c.find("container.detected", d, "virt.platform")
	}
	if c.f("root_ro") == "true" {
		c.find("container.readonly_root", "/ is mounted read-only", "fs.mounts|sec.app_control")
	}
	if c.f("display") == "false" {
		c.find("session.headless", "DISPLAY and WAYLAND_DISPLAY are not set (session: "+orDefault(c.f("session_type"), "unknown")+")", "session.context")
	}
	if c.f("python_found") == "false" {
		c.find("runtime.python_absent", "no python3, python or python2 on PATH or in the known locations", "runtime.python")
	}
	if n, ok := shInt(c.f("shims_skipped")); ok && n > 0 {
		c.find("runtime.shims_not_run", c.f("shims_skipped")+" tool(s) resolve to shims that were not executed", "tools.inventory|runtime.version_managers")
	}
}

func (c *fctx) archMismatch() {
	am := ""
	if c.f("rosetta") == "true" {
		am = "the scanner shell runs under Rosetta 2 (x86_64 on arm64)"
	}
	osArch := orDefault(c.f("os_arch"), c.arch)
	if c.f("userland_bits") == "32" {
		switch osArch {
		case "x86_64", "arm64", "ppc64", "ppc64le", "s390x", "sparc64":
			am = appendSep(am, "; ", "32-bit userland on a 64-bit kernel")
		}
	}
	if m := c.f("arch_mismatch"); m != "" {
		am = appendSep(am, "; ", "runtime binaries: "+m+" (OS "+osArch+")")
	}
	if am != "" {
		c.find("arch.mismatch", am, "os.identity|tools.inventory")
	}
}

// legacy is sh es_legacy for Linux: the reason when the OS, kernel or bash is past end of
// support ("" otherwise). The macOS, AIX and Solaris branches are left out.
func (c *fctx) legacy() string {
	v, name := c.f("os_version"), c.f("os_name")
	maj, _, _ := strings.Cut(v, ".")
	if !rpIsNum(maj) {
		maj = ""
	}
	t := ""
	switch c.f("distro_id") {
	case "rhel", "ol", "rocky", "almalinux", "scientific":
		t = when(shLt(maj, "8"), name+" (end of maintenance support)")
	case "centos":
		if strings.Contains(name, "Stream") {
			t = when(shLt(maj, "9"), name+" (end of life)")
		} else {
			t = name + " (CentOS Linux is end of life)"
		}
	case "ubuntu":
		t = when(shLt(maj, "22"), name+" (end of standard support)")
	case "debian":
		t = when(shLt(maj, "12"), name+" (end of support)")
	case "sles", "sled":
		t = when(shLt(maj, "15"), name+" (end of general support)")
	case "alpine":
		t = when(vercmp(v, "3.21") == -1, name+" (branch no longer maintained)")
	}
	if k := c.f("os_kernel"); t == "" && k != "" && vercmp(k, "3.10") == -1 {
		t = "Linux kernel " + k
	}
	if b := c.f("bash_version"); t == "" && b != "" && vercmp(b, "4.0") == -1 {
		t = "bash " + b + " is the default bash (bash 4+ features such as associative arrays are missing)"
	}
	return t
}

// when is text when b holds, else "".
func when(b bool, text string) string {
	if b {
		return text
	}
	return ""
}

func (c *fctx) rulesLimits() {
	if min := thresholdText("nofile_soft_min"); shLt(c.f("nofile_soft"), min) {
		c.find("limits.nofile_low", "soft limit "+c.f("nofile_soft")+" (hard "+orDefault(c.f("nofile_hard"), "unknown")+"); recommended at least "+min, "limits.process")
	}
	il := ""
	if min := thresholdText("inotify_watches_min"); shLt(c.f("inotify_watches"), min) {
		il = "max_user_watches " + c.f("inotify_watches") + " (< " + min + ")"
	}
	if min := thresholdText("inotify_instances_min"); shLt(c.f("inotify_instances"), min) {
		il = appendSep(il, "; ", "max_user_instances "+c.f("inotify_instances")+" (< "+min+")")
	}
	if il != "" {
		c.find("limits.inotify_low", il, "limits.kernel")
	}
	if min := thresholdText("max_map_count_min"); shLt(c.f("max_map_count"), min) {
		c.find("limits.max_map_count_low", "vm.max_map_count "+c.f("max_map_count")+" (< "+min+")", "limits.kernel")
	}
	if cl := c.cgroupLimits(); cl != "" {
		c.find("limits.cgroup", cl, "limits.cgroup|hw.memory|hw.cpu")
	}
	min := thresholdText("memory_min_mb")
	if shLt(c.f("mem_avail_mb"), min) {
		c.find("limits.memory_low", c.f("mem_avail_mb")+" MB available of "+orDefault(c.f("mem_total_mb"), "unknown")+" MB", "hw.memory")
	} else if c.f("mem_avail_mb") == "" && shLt(c.f("mem_total_mb"), min) {
		c.find("limits.memory_low", c.f("mem_total_mb")+" MB total memory", "hw.memory")
	}
}

func (c *fctx) cgroupLimits() string {
	cl := ""
	mem, ok1 := shInt(c.f("cg_mem"))
	total, ok2 := shInt(c.f("mem_total_mb"))
	if ok1 && ok2 && mem/1048576 < total {
		cl = "memory limit " + strconv.FormatInt(mem/1048576, 10) + " MB (host " + c.f("mem_total_mb") + " MB)"
	}
	cpu, logical := c.f("cg_cpu"), c.f("cpu_logical")
	if cpu != "" && cpu != "max" && rpIsNum(logical) {
		lim := awkPrintNum(awkNumber(logical) * threshold("cgroup_cpu_fraction_warn"))
		if awkLess(cpu, lim) {
			cl = appendSep(cl, "; ", "CPU quota "+cpu+" cores (host "+logical+" logical CPUs)")
		}
	}
	return cl
}

func (c *fctx) rulesFSUser() {
	ld := ""
	if min := thresholdText("disk_free_min_mb"); shLt(c.f("free_home_mb"), min) {
		ld = "home: " + c.f("free_home_mb") + " MB free (< " + min + ")"
	}
	if min := thresholdText("temp_free_min_mb"); shLt(c.f("free_tmp_mb"), min) {
		ld = appendSep(ld, "; ", "temp: "+c.f("free_tmp_mb")+" MB free (< "+min+")")
	}
	if ld != "" {
		c.find("fs.low_disk", ld, "fs.locations")
	}
	if s := c.f("symlink"); s == "denied" || s == "error" {
		c.find("fs.symlinks_unavailable", "ln -s in the temp directory: "+s+ifSet(c.f("symlink_detail"), " ("+c.f("symlink_detail")+")"), "fs.semantics")
	}
	if c.f("case_sensitive") == "false" {
		c.find("fs.case_insensitive", "the temp directory's file system ignores case", "fs.semantics")
	}
	if c.f("install_writable") == "false" && c.hasFacts("fs.locations") {
		c.find("fs.no_writable_install_dir", "none of HOME, ~/.local, ~/bin, /opt, /usr/local or the current directory is writable", "fs.locations")
	}
	c.rulesUser()
}

func (c *fctx) rulesUser() {
	if c.f("is_admin") == "true" {
		c.find("user.is_admin", "uid 0 (root)", "user.identity")
	}
	if c.f("passwd_entry") == "false" {
		c.find("user.no_passwd_entry", "uid "+orDefault(c.f("uid"), "unknown")+" has no passwd entry", "user.identity")
	}
	if c.f("home_network") == "true" {
		c.find("user.home_network", "HOME is on "+orDefault(c.f("home_fstype"), "a network file system"), "user.profile")
	}
	if c.f("encoding_utf8") == "false" && c.f("encoding") != "" {
		c.find("locale.non_utf8", "encoding "+c.f("encoding")+" (locale "+orDefault(c.f("locale_name"), "unknown")+")", "os.time_locale")
	}
	if c.f("decimal_sep") == "," {
		c.find("locale.decimal_comma", "locale "+orDefault(c.f("locale_name"), "unknown")+" uses ',' as decimal separator", "os.time_locale")
	}
}

// budgetSkipped is the sh results.tsv kind "budget": a probe skipped because the scan budget
// ran out (the runner's note "scan budget of Ns exhausted").
func budgetSkipped(r *Result) bool {
	if r.Status != StSkipped {
		return false
	}
	for _, n := range r.Notes {
		if strings.HasPrefix(n, "scan budget of ") {
			return true
		}
	}
	return false
}

func (c *fctx) rulesScan() {
	var bad []string
	for _, r := range c.order {
		switch r.Status {
		case StPartial, StDenied, StTimeout, StError:
			bad = append(bad, r.ID)
		default:
			if budgetSkipped(r) {
				bad = append(bad, r.ID)
			}
		}
	}
	if len(bad) > 0 {
		c.find("scan.partial", strconv.Itoa(len(bad))+" probe(s) not fully checked: "+strings.Join(bad, ", "), strings.Join(bad, "|"))
	}
}
