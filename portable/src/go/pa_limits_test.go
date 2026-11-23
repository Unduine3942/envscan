package main

import (
	"reflect"
	"testing"
)

var paLimitKeys = []string{"nofile_soft", "nofile_hard", "nproc_soft", "nproc_hard", "stack_kb_soft", "core_soft",
	"memlock_kb_soft", "address_space_soft"}

func paLimitData(r *Result) map[string]any {
	m := map[string]any{}
	for _, k := range paLimitKeys {
		m[k] = paPlain(mustGet(r, k))
	}
	return m
}

// TestLimitsFromProcSelfLimits: the limits_proc cases of tests/data/commands.json (Env has no
// getrlimit answer, so the file is read like sh).
func TestLimitsFromProcSelfLimits(t *testing.T) {
	for _, c := range paCommandCases(t, "limits_proc") {
		t.Run(c["name"].(string), func(t *testing.T) {
			e := newFakeEnv(t, paTree(t, map[string]string{"proc/self/limits": c["output"].(string)}))
			r := paRun(t, e, "limits.process")
			if got, want := paLimitData(r), paJSONPlain(c["facts"]); !reflect.DeepEqual(got, want) {
				t.Errorf("got %v want %v", got, want)
			}
		})
	}
}

// TestLimitsFromGetrlimit: the linux_bash ulimit case, given as getrlimit values (bytes).
func TestLimitsFromGetrlimit(t *testing.T) {
	e := newFakeEnv(t, "")
	e.Limits = map[string]Rlimit{RlNofile: {"1024", "1048576"}, RlNproc: {"63704", "63704"}, RlStack: {"8388608", "unlimited"},
		RlCore: {"0", "unlimited"}, RlMemlock: {"67108864", "67108864"}, RlAS: {"unlimited", "unlimited"}}
	r := paRun(t, e, "limits.process")
	want := map[string]any{"nofile_soft": "1024", "nofile_hard": "1048576", "nproc_soft": "63704", "nproc_hard": "63704",
		"stack_kb_soft": "8192", "core_soft": "0", "memlock_kb_soft": "65536", "address_space_soft": "unlimited"}
	if got := paLimitData(r); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if r.Status != StOK || r.Facts["nofile_soft"] != "1024" || r.Sources[0] != "syscall getrlimit (nofile, nproc, stack, core, memlock, as)" {
		t.Errorf("status %s facts %v sources %v", r.Status, r.Facts, r.Sources)
	}
	r = paRun(t, newFakeEnv(t, ""), "limits.process")
	if r.Status != StPartial {
		t.Errorf("no limits: %s", r.Status)
	}
}

func TestKernelLimitsFromFixture(t *testing.T) {
	e := paLinux(t)
	r := paRun(t, e, "limits.kernel")
	paWant(t, r, map[string]any{"fs.inotify.max_user_watches": "8192", "fs.inotify.max_user_instances": "128",
		"vm.max_map_count": "65530", "fs.file-max": "9223372036854775807", "transparent_hugepage": "madvise",
		"kernel.yama.ptrace_scope": nil, "fs.file-nr": "3104 0 9223372036854775807",
		"systemd_default_limits": map[string]any{"system.DefaultLimitNOFILE": "65536", "system.DefaultLimitNPROC": "8192"},
		"limits_conf":            []any{}})
	if r.Status != StOK || r.Facts["max_map_count"] != "65530" || r.Facts["inotify_watches"] != "8192" {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
	keys := r.Data.Keys()
	if keys[0] != "fs.file-max" || keys[len(keys)-1] != "systemd_default_limits" {
		t.Errorf("key order %v", keys)
	}
}

func TestKernelLimitsConfAndNoProcSys(t *testing.T) {
	root := paTree(t, map[string]string{"proc/sys/kernel/perf_event_paranoid": "-1\n",
		"etc/security/limits.conf":      "# comment\n\n*\tsoft\tnofile\t4096\n  @dev  hard  nproc 100 \n",
		"etc/security/limits.d/90.conf": "root - core 0\r\n", "etc/security/limits.d/bin.conf": "a\x00b\n"})
	e := newFakeEnv(t, root)
	r := paRun(t, e, "limits.kernel")
	paWant(t, r, map[string]any{"kernel.perf_event_paranoid": "-1", "limits_conf": []any{
		"/etc/security/limits.conf: * soft nofile 4096", "/etc/security/limits.conf:  @dev hard nproc 100 ",
		"/etc/security/limits.d/90.conf: root - core 0"}, "systemd_default_limits": map[string]any{}})
	if r.Status != StPartial || !paHasNote(r, "bin.conf not read") {
		t.Errorf("status %s notes %v", r.Status, r.Notes)
	}
	r = paRun(t, newFakeEnv(t, t.TempDir()), "limits.kernel")
	if r.Status != StNotApplicable || r.Data.Len() != 0 {
		t.Errorf("no /proc/sys: %s", r.Status)
	}
}

func TestCgroupV2FromFixture(t *testing.T) {
	r := paRun(t, paLinux(t), "limits.cgroup")
	paWant(t, r, map[string]any{"version": "2", "path": "/user.slice/user-1000.slice/session-3.scope",
		"memory_max_bytes": "2147483648", "cpu_quota_cores": "1.50", "pids_max": "512"})
	if r.Status != StOK || r.Facts["cg_cpu"] != "1.50" || r.Facts["cg_mem"] != "2147483648" {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
}

func TestCgroupV1AndUnlimited(t *testing.T) {
	root := paTree(t, map[string]string{
		"proc/self/cgroup": "12:pids:/docker/abc\n4:cpu,cpuacct:/docker/abc\n3:memory:/docker/abc\n",
		"sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes":  "9223372036854771712\n",
		"sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_quota_us":  "50000\n",
		"sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_period_us": "100000\n",
		"sys/fs/cgroup/pids/pids.max":                            "max\n",
	})
	r := paRun(t, newFakeEnv(t, root), "limits.cgroup")
	paWant(t, r, map[string]any{"version": "1", "path": "/docker/abc", "memory_max_bytes": "unlimited",
		"cpu_quota_cores": "0.50", "pids_max": "unlimited"})
	root2 := paTree(t, map[string]string{"proc/self/cgroup": "0::/\n", "sys/fs/cgroup/cgroup.controllers": "cpu\n",
		"sys/fs/cgroup/cpu.max": "max 100000\n"})
	r = paRun(t, newFakeEnv(t, root2), "limits.cgroup")
	paWant(t, r, map[string]any{"path": "/", "memory_max_bytes": "unlimited", "cpu_quota_cores": "unlimited"})
	r = paRun(t, newFakeEnv(t, paTree(t, map[string]string{"proc/self/cgroup": "0::/\n"})), "limits.cgroup")
	if r.Status != StPartial || mustGet(r, "version") != nil {
		t.Errorf("no cgroupfs: %s", r.Status)
	}
	if r := paRun(t, newFakeEnv(t, ""), "limits.cgroup"); r.Status != StNotApplicable {
		t.Errorf("no /proc: %s", r.Status)
	}
}

func TestPortsFromFixture(t *testing.T) {
	r := paRun(t, paLinux(t), "net.ports")
	paWant(t, r, map[string]any{"ephemeral": map[string]any{"start": "32768", "end": "60999"},
		"unprivileged_port_start": "1024", "excluded_tcp": []any{}, "urlacl_count": nil})
	root := paTree(t, map[string]string{"proc/sys/net/ipv4/ip_local_reserved_ports": "8080,9000-9010\n"})
	r = paRun(t, newFakeEnv(t, root), "net.ports")
	paWant(t, r, map[string]any{"excluded_tcp": []any{map[string]any{"start": "8080", "end": "8080"},
		map[string]any{"start": "9000", "end": "9010"}}})
	if r.Status != StPartial || r.Facts["reserved_ports"] != "8080,9000-9010" {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
}
