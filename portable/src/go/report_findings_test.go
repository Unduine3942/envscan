// report_findings_test.go: the golden findings cases (tests/data/findings_cases.json) against
// computeFindings, with the sh adapter of tests/findings_harness.py ported to Go.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type findingCase struct {
	Name         string                     `json:"name"`
	Impls        []string                   `json:"impls"`
	Probes       map[string]string          `json:"probes"`
	Facts        map[string]json.RawMessage `json:"facts"`
	PsData       map[string]json.RawMessage `json:"ps_data"`
	ShFacts      map[string]string          `json:"sh_facts"`
	ShOS         string                     `json:"sh_os"`
	Expect       []string                   `json:"expect"`
	ExpectByImpl map[string][]string        `json:"expect_by_impl"`
	Xfail        map[string]string          `json:"xfail"`
}

var harnessDefaultProbes = []string{
	"os.identity", "os.time_locale", "os.health", "hw.memory", "hw.storage", "sec.app_control", "sec.crypto",
	"tls.trust", "net.routes", "net.listening", "net.ports",
	"tools.inventory", "runtime.python", "runtime.dotnet", "virt.platform", "session.context", "shell.info",
	"fs.semantics", "fs.locations", "fs.mounts", "limits.process", "limits.kernel", "limits.cgroup",
	"user.identity", "user.profile", "native.deps",
}

var harnessFactProbe = map[string]string{
	"app_control_enforced": "sec.app_control", "enterprise_roots": "tls.trust", "tls_verify_off_env": "tls.trust",
	"tls_verify_off_config": "pkg.sources", "endpoints_internal": "pkg.sources", "endpoints_public": "pkg.sources",
	"caches": "pkg.caches", "proxy_hosts": "net.proxy", "default_route": "net.routes",
	"listening_common_ports": "net.listening", "os_arch": "os.identity", "runtime_binary_arch": "tools.inventory",
	"fips": "sec.crypto", "pending_reboot": "os.health", "os_identity": "os.identity", "container": "virt.platform",
	"shim_tools": "tools.inventory", "memory": "hw.memory", "disk_free_mb": "fs.locations", "symlink": "fs.semantics",
	"case_sensitive": "fs.semantics", "install_writable": "fs.locations", "is_admin": "user.identity",
	"home_network": "user.profile", "locale": "os.time_locale", "decimal_separator": "os.time_locale",
	"python_found": "runtime.python",
}

func findingsCasesPath(t *testing.T) string {
	if p := os.Getenv("ENVSCAN_TESTDATA_FINDINGS"); p != "" {
		return p
	}
	return filepath.Join("..", "..", "tests", "data", "findings_cases.json")
}

func loadFindingCases(t *testing.T) []findingCase {
	t.Helper()
	b, err := os.ReadFile(findingsCasesPath(t))
	if err != nil {
		t.Skipf("findings cases not available: %v", err)
	}
	var cases []findingCase
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatalf("findings cases: %v", err)
	}
	return cases
}

// harnessStatuses is findings_harness.statuses (with "absent" kept, the caller drops them).
func harnessStatuses(c findingCase) map[string]string {
	st := map[string]string{}
	for _, p := range harnessDefaultProbes {
		st[p] = StOK
	}
	for f := range c.Facts {
		st[harnessFactProbe[f]] = StOK
	}
	for p := range c.PsData {
		st[p] = StOK
	}
	for p, s := range c.Probes {
		st[p] = s
	}
	return st
}

func pyStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	}
	return ""
}

func pyBool(v any) string {
	switch t := v.(type) {
	case bool:
		if t {
			return "true"
		}
	case string:
		if t != "" {
			return "true"
		}
	case []any:
		if len(t) > 0 {
			return "true"
		}
	case float64:
		if t != 0 {
			return "true"
		}
	}
	return "false"
}

func pyLines(v any, conv func(any) string) string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, i := range items {
		out = append(out, conv(i))
	}
	return strings.Join(out, "\n")
}

func urlHost(v any) string {
	u := pyStr(v)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	h, _, _ := strings.Cut(u, "/")
	return h
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// harnessShFact is findings_harness.SH_FACTS[name](value).
func harnessShFact(name string, v any) map[string]string {
	m, _ := v.(map[string]any)
	switch name {
	case "app_control_enforced":
		if pyBool(v) == "true" {
			return map[string]string{"fapolicyd": "active"}
		}
		return nil
	case "enterprise_roots":
		items, _ := v.([]any)
		return map[string]string{"ca_custom": strconv.Itoa(len(items)),
			"ca_subjects": pyLines(v, func(x any) string { return strings.ReplaceAll(pyStr(x), "CN=", "") })}
	case "tls_verify_off_env":
		return map[string]string{"tls_disabled_env": pyLines(v, pyStr)}
	case "tls_verify_off_config":
		return map[string]string{"tls_disabled_cfg": pyLines(v, func(x any) string {
			c, _ := x.(map[string]any)
			return pyStr(c["tool"]) + ": " + pyStr(c["line"])
		})}
	case "endpoints_internal", "endpoints_public":
		return map[string]string{name: pyLines(v, urlHost)}
	case "caches":
		return map[string]string{"caches": pyLines(v, pyStr)}
	case "proxy_hosts":
		return map[string]string{"proxy": pyBool(v), "proxy_hosts": pyLines(v, pyStr)}
	case "default_route", "fips", "case_sensitive", "install_writable", "is_admin", "home_network", "python_found":
		key := map[string]string{"default_route": "default_route", "fips": "fips", "case_sensitive": "case_sensitive",
			"install_writable": "install_writable", "is_admin": "is_admin", "home_network": "home_network",
			"python_found": "python_found"}[name]
		return map[string]string{key: pyBool(v)}
	case "listening_common_ports":
		return map[string]string{"listen_ports": strings.ReplaceAll(pyLines(v, pyStr), "\n", " ")}
	case "os_arch":
		return map[string]string{"os_arch": pyStr(v)}
	case "runtime_binary_arch":
		parts := []string{}
		for _, k := range sortedKeys(m) {
			parts = append(parts, k+" is "+pyStr(m[k]))
		}
		return map[string]string{"arch_mismatch": strings.Join(parts, "; ")}
	case "pending_reboot":
		return map[string]string{"pending_reboot": pyBool(v), "pending_reasons": pyLines(v, pyStr)}
	case "os_identity":
		keys := map[string]string{"name": "os_name", "version": "os_version", "distro_id": "distro_id", "kernel": "os_kernel"}
		out := map[string]string{}
		for k, x := range m {
			if fk, ok := keys[k]; ok {
				out[fk] = pyStr(x)
			}
		}
		return out
	case "container":
		return map[string]string{"container": pyBool(m["detected"]), "container_engine": pyStr(orEmpty(m["engine"])),
			"kubernetes": pyBool(m["kubernetes"])}
	case "shim_tools":
		items, _ := v.([]any)
		return map[string]string{"shims_skipped": strconv.Itoa(len(items))}
	case "memory":
		out := map[string]string{"mem_total_mb": pyStr(m["total_mb"])}
		if m["available_mb"] != nil {
			out["mem_avail_mb"] = pyStr(m["available_mb"])
		}
		return out
	case "disk_free_mb":
		return map[string]string{"free_home_mb": pyStr(v)}
	case "symlink":
		return map[string]string{"symlink": pyStr(v)}
	case "locale":
		return map[string]string{"encoding_utf8": pyBool(m["utf8"]), "encoding": pyStr(orEmpty(m["encoding"]))}
	case "decimal_separator":
		return map[string]string{"decimal_sep": pyStr(v)}
	}
	return nil
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

// harnessInput builds what the engine hands computeFindings for case c: results (sorted by id,
// like the harness's results.tsv) and the facts (findings_harness.sh_facts without ES_F_).
func harnessInput(t *testing.T, c findingCase) ([]*Result, map[string]string) {
	st := harnessStatuses(c)
	noFacts := map[string]bool{StError: true, StTimeout: true, StDenied: true, StSkipped: true, "absent": true}
	facts := map[string]string{}
	for name, raw := range c.Facts {
		s, ok := st[harnessFactProbe[name]]
		if !ok || noFacts[s] {
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: fact %s: %v", c.Name, name, err)
		}
		for k, x := range harnessShFact(name, v) {
			facts[k] = x
		}
	}
	for k, v := range c.ShFacts {
		facts[k] = v
	}
	if _, ok := facts["pkg_config_count"]; !ok {
		facts["pkg_config_count"] = "0"
	}
	ids := []string{}
	for p, s := range st {
		if s != "absent" {
			ids = append(ids, p)
		}
	}
	sort.Strings(ids)
	results := make([]*Result, 0, len(ids))
	for _, id := range ids {
		r := newResult(id)
		r.Status = st[id]
		results = append(results, r)
	}
	return results, facts
}

func findingsDoc(arch string) *Obj {
	return NewObj().Set("host", NewObj().Set("os_family", "linux").Set("arch", arch))
}

func findingIDs(fs []any) []string {
	ids := []string{}
	for _, f := range fs {
		ids = append(ids, f.(*Obj).Str("id"))
	}
	sort.Strings(ids)
	return ids
}

func TestFindingsGoldenCases(t *testing.T) {
	ran := 0
	for _, c := range loadFindingCases(t) {
		c := c
		if !containsStr(c.Impls, "sh") || (c.ShOS != "" && c.ShOS != "linux") {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			results, facts := harnessInput(t, c)
			got := findingIDs(computeFindings(findingsDoc("x86_64"), results, facts))
			want := append([]string{}, c.Expect...)
			if e, ok := c.ExpectByImpl["sh"]; ok {
				want = append([]string{}, e...)
			}
			sort.Strings(want)
			same := strings.Join(got, ",") == strings.Join(want, ",")
			if reason := c.Xfail["sh"]; reason != "" {
				if same {
					t.Fatalf("xfail case passed (strict): %s", reason)
				}
				return
			}
			if !same {
				t.Fatalf("got %v, want %v (facts %v)", got, want, facts)
			}
		})
	}
	if ran < 50 {
		t.Fatalf("only %d sh cases ran", ran)
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestFindingsFieldsAndOrder(t *testing.T) {
	results := []*Result{
		{ID: "hw.gpu", Status: StPartial}, {ID: "net.routes", Status: StOK},
		{ID: "net.dns", Status: StSkipped, Notes: []string{"scan budget of 60s exhausted"}},
	}
	facts := map[string]string{
		"is_admin": "true", "selinux": "enforcing", "noexec_temp": "/tmp\n/dev/shm",
		"default_route": "false", "listen_ports": " 22 80 8080", "pending_reboot": "true",
		"pending_reasons": "kernel\tupdate", "mem_avail_mb": "100", "mem_total_mb": "8000",
	}
	fs := computeFindings(findingsDoc("x86_64"), results, facts)
	ids := []string{}
	for _, f := range fs {
		ids = append(ids, f.(*Obj).Str("id"))
	}
	want := "exec.noexec_temp,tls.offline_pki,limits.memory_low,os.pending_reboot,exec.mac_enforcing,net.no_route,net.ports_in_use,user.is_admin,scan.partial"
	// order: severity (blocker, warning, info), then spec order
	if !specHas("scan.partial") {
		want = strings.TrimSuffix(want, ",scan.partial")
	}
	if strings.Join(ids, ",") != want {
		t.Fatalf("order:\n got %s\nwant %s", strings.Join(ids, ","), want)
	}
	f := findByID(fs, "exec.noexec_temp")
	if strings.Join(f.Keys(), ",") != "id,severity,title,detail,recommendation,evidence" {
		t.Fatalf("keys %v", f.Keys())
	}
	if f.Str("detail") != "mounted noexec: /tmp, /dev/shm" || f.Str("severity") != "warning" {
		t.Fatalf("noexec: %q %q", f.Str("detail"), f.Str("severity"))
	}
	ev, _ := f.Get("evidence")
	if len(ev.([]any)) != 1 || ev.([]any)[0] != "fs.mounts" {
		t.Fatalf("evidence %v", ev)
	}
	checkDetail(t, fs, "net.ports_in_use", "already listening: 80 8080")
	checkDetail(t, fs, "os.pending_reboot", "kernel update")
	checkDetail(t, fs, "limits.memory_low", "100 MB available of 8000 MB")
	checkDetail(t, fs, "tls.offline_pki", "no default route: online revocation checks (CRL/OCSP) and root updates cannot be reached")
	if specHas("scan.partial") {
		checkDetail(t, fs, "scan.partial", "2 probe(s) not fully checked: hw.gpu, net.dns")
		sp := findByID(fs, "scan.partial")
		ev, _ := sp.Get("evidence")
		if len(ev.([]any)) != 2 {
			t.Fatalf("scan.partial evidence %v", ev)
		}
	}
	pki := findByID(fs, "tls.offline_pki")
	ev, _ = pki.Get("evidence")
	if len(ev.([]any)) != 2 || ev.([]any)[1] != "tls.trust" {
		t.Fatalf("pki evidence %v", ev)
	}
}

func specHas(id string) bool {
	for _, f := range spec.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func findByID(fs []any, id string) *Obj {
	for _, f := range fs {
		if o := f.(*Obj); o.Str("id") == id {
			return o
		}
	}
	return nil
}

func checkDetail(t *testing.T, fs []any, id, want string) {
	t.Helper()
	o := findByID(fs, id)
	if o == nil {
		t.Fatalf("%s missing", id)
	}
	if o.Str("detail") != want {
		t.Fatalf("%s detail %q, want %q", id, o.Str("detail"), want)
	}
}

func TestFindingsDetails(t *testing.T) {
	cases := []struct {
		name  string
		facts map[string]string
		id    string
		want  string
	}{
		{"join over max", map[string]string{"caches": "a\nb\n\nc\nd\ne\nf\ng\nh\ni"}, "pkg.offline_cache",
			"caches: a, b, c, d, e, f, g, h, ... (9 in total)"},
		{"cgroup", map[string]string{"cg_mem": "1073741824", "mem_total_mb": "4096", "cg_cpu": "1.5", "cpu_logical": "4"},
			"limits.cgroup", "memory limit 1024 MB (host 4096 MB); CPU quota 1.5 cores (host 4 logical CPUs)"},
		{"inotify", map[string]string{"inotify_watches": "8192", "inotify_instances": "128"}, "limits.inotify_low",
			"max_user_watches 8192 (< 65536); max_user_instances 128 (< 256)"},
		{"nofile", map[string]string{"nofile_soft": "1024"}, "limits.nofile_low",
			"soft limit 1024 (hard unknown); recommended at least 4096"},
		{"disk", map[string]string{"free_home_mb": "10", "free_tmp_mb": "5"}, "fs.low_disk",
			"home: 10 MB free (< 2048); temp: 5 MB free (< 1024)"},
		{"symlink detail", map[string]string{"symlink": "denied", "symlink_detail": "EPERM"}, "fs.symlinks_unavailable",
			"ln -s in the temp directory: denied (EPERM)"},
		{"libc", map[string]string{"libc_kind": "glibc", "libc_version": "2.35", "glibcxx_max": "3.4.30"}, "native.libc",
			"glibc 2.35; libstdc++ up to GLIBCXX_3.4.30"},
		{"32 bit", map[string]string{"userland_bits": "32"}, "arch.mismatch", "32-bit userland on a 64-bit kernel"},
		{"fips policy", map[string]string{"fips": "true", "crypto_policy": "FIPS"}, "crypto.fips",
			"FIPS mode enabled (kernel fips_enabled=1, crypto policy FIPS)"},
		{"container k8s", map[string]string{"container": "true", "kubernetes": "true"}, "container.detected",
			"engine: unknown, Kubernetes"},
		{"headless", map[string]string{"display": "false"}, "session.headless",
			"DISPLAY and WAYLAND_DISPLAY are not set (session: unknown)"},
		{"legacy centos stream", map[string]string{"distro_id": "centos", "os_name": "CentOS Stream 8", "os_version": "8"},
			"os.legacy", "CentOS Stream 8 (end of life)"},
		{"legacy bash", map[string]string{"bash_version": "3.2.57"}, "os.legacy",
			"bash 3.2.57 is the default bash (bash 4+ features such as associative arrays are missing)"},
		{"proxy no hosts", map[string]string{"proxy": "true"}, "net.proxy_configured", "proxy: configured (see net.proxy)"},
		{"tls both", map[string]string{"tls_disabled_env": "A=0", "tls_disabled_cfg": "npm: x\npip: y\ngit: z\nw: v"},
			"tls.verification_disabled", "environment: A=0; config: npm: x, pip: y, git: z, ... (4 in total)"},
		{"locale", map[string]string{"encoding_utf8": "false", "encoding": "ISO-8859-1"}, "locale.non_utf8",
			"encoding ISO-8859-1 (locale unknown)"},
		{"passwd", map[string]string{"passwd_entry": "false", "uid": "1234"}, "user.no_passwd_entry", "uid 1234 has no passwd entry"},
		{"home net", map[string]string{"home_network": "true", "home_fstype": "nfs4"}, "user.home_network", "HOME is on nfs4"},
		{"shims", map[string]string{"shims_skipped": "2"}, "runtime.shims_not_run", "2 tool(s) resolve to shims that were not executed"},
		{"map count", map[string]string{"max_map_count": "65530"}, "limits.max_map_count_low", "vm.max_map_count 65530 (< 262144)"},
		{"mac all", map[string]string{"selinux": "enforcing", "apparmor": "enabled", "aa_profile": "x (enforce)", "fapolicyd": "active"},
			"exec.mac_enforcing", "SELinux enforcing; AppArmor profile x (enforce); fapolicyd active"},
		{"app control", map[string]string{"fapolicyd": "active", "exec_blocked": "/tmp"}, "exec.app_control",
			"fapolicyd is active (only trusted executables may run); execution test blocked in: /tmp"},
		{"newline in detail", map[string]string{"pending_reboot": "true", "pending_reasons": "a\r"}, "os.pending_reboot", "a "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := computeFindings(findingsDoc("x86_64"), nil, c.facts)
			checkDetail(t, fs, c.id, c.want)
		})
	}
}

func TestFindingsNoSourceDetail(t *testing.T) {
	results := []*Result{{ID: "pkg.sources", Status: StOK}, {ID: "pkg.caches", Status: StNotFound},
		{ID: "net.proxy", Status: StNotApplicable}}
	facts := map[string]string{"pkg_config_count": "3", "endpoints_public": "registry.npmjs.org\npypi.org"}
	fs := computeFindings(findingsDoc("x86_64"), results, facts)
	checkDetail(t, fs, "pkg.no_source", "no internal registry or mirror in 3 package config file(s), no proxy, no local dependency cache; only public endpoints: registry.npmjs.org, pypi.org")
}

func TestFindingsHelpers(t *testing.T) {
	if vercmp("3.20.1", "3.21") != -1 || vercmp("3.21", "3.21.0") != 0 || vercmp("4", "3.9") != 1 || vercmp("", "1") != -1 {
		t.Fatal("vercmp")
	}
	if !shLt("10", "20") || shLt("-1", "5") || shLt("", "5") || shLt("99999999999999999999", "5") {
		t.Fatal("shLt")
	}
	if !awkLess("1.5", "3") || awkLess("abc", "") || awkLess("4", "3") || !awkLess("2x", "3") {
		t.Fatal("awkLess")
	}
	if awkPrintNum(6) != "6" || awkPrintNum(0.75*3) != "2.25" || awkPrintNum(1234567.25) != "1.23457e+06" {
		t.Fatalf("awkPrintNum %q", awkPrintNum(1234567.25))
	}
}
