package main

import (
	"testing"
	"time"
)

func TestOSIdentityFromFixture(t *testing.T) {
	e := paLinux(t)
	e.PathBins["uname"] = "/usr/bin/uname"
	e.Cmds["uname -p"] = fakeCmd{Stdout: "unknown\n"}
	e.PathBins["getconf"] = "/usr/bin/getconf"
	e.Cmds["getconf LONG_BIT"] = fakeCmd{Stdout: "64\n"}
	r := paRun(t, e, "os.identity")
	if r.Status != StOK {
		t.Fatalf("status %s notes %v", r.Status, r.Notes)
	}
	paWant(t, r, map[string]any{"name": "Ubuntu 22.04.4 LTS", "version": "22.04", "distro_id": "ubuntu",
		"kernel": "5.15.0-105-generic", "kernel_version": "#115-Ubuntu SMP", "processor": nil, "userland_bits": "64",
		"fqdn": "build01.corp.example", "domain": "corp.example", "domain_joined": false, "kerberos_config": false,
		"debian_version": "bookworm/sid", "distro_like": "debian", "distro_version": "22.04.4 LTS (Jammy Jellyfish)",
		"wsl": false, "wsl_version": nil, "arch": "x86_64", "process_arch": "x86_64", "family": "linux",
		"kernel_banner": "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-007) (gcc 11.4.0) #115-Ubuntu SMP"})
	if r.Facts["os_name"] != "Ubuntu 22.04.4 LTS" || r.Facts["os_kernel"] != "5.15.0-105-generic" || r.Facts["wsl"] != "false" {
		t.Errorf("facts %v", r.Facts)
	}
	if r.Sources[0] != "syscall uname (at scan start)" || !paHasStr(r.Sources, "read /etc/os-release") {
		t.Errorf("sources %v", r.Sources)
	}
}

func TestOSIdentityFallbacks(t *testing.T) {
	root := paTree(t, map[string]string{
		"etc/redhat-release":        "Rocky Linux release 9.3 (Blue Onyx)\n",
		"etc/lsb-release":           "DISTRIB_ID=Rocky\nDISTRIB_RELEASE=9.3\n",
		"proc/sys/kernel/osrelease": "5.15.153.1-microsoft-standard-WSL2\n",
		"etc/sssd/sssd.conf":        "[sssd]\n",
		"etc/resolv.conf":           "domain lab.example\n",
	})
	e := newFakeEnv(t, root)
	e.UnameV = Uname{Sysname: "Linux", Release: "5.15.153.1-microsoft-standard-WSL2", Machine: "x86_64"}
	e.PathBins["getconf"] = "/usr/bin/getconf"
	e.Cmds["getconf LONG_BIT"] = fakeCmd{Stdout: "32\n"}
	r := paRun(t, e, "os.identity")
	paWant(t, r, map[string]any{"name": "Rocky Linux release 9.3 (Blue Onyx)", "version": "9.3", "distro_id": "rocky",
		"wsl": true, "wsl_version": "2", "process_arch": "x86", "domain_joined": true, "sssd_config": true,
		"domain": "lab.example", "fqdn": nil, "hostname": "testhost"})
	if r.Status != StOK {
		t.Errorf("status %s %v", r.Status, r.Notes)
	}
}

func TestOSIdentityNoReleaseFile(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	e.UnameV = Uname{Sysname: "Linux", Release: "6.1.0", Machine: "aarch64"}
	e.ArchName = "arm64"
	r := paRun(t, e, "os.identity")
	paWant(t, r, map[string]any{"name": "Linux 6.1.0", "version": "6.1.0", "kernel": "6.1.0", "userland_bits": nil})
	if r.Status != StPartial || !paHasNote(r, "no os-release") {
		t.Errorf("status %s notes %v", r.Status, r.Notes)
	}
}

func TestTimeLocaleFromFixtureWithoutLocaleCommand(t *testing.T) {
	e := paLinux(t)
	e.Vars["LANG"] = "en_US.UTF-8"
	r := paRun(t, e, "os.time_locale")
	paWant(t, r, map[string]any{"timezone": "Asia/Seoul", "utc_offset": "+0000", "locale": "en_US.UTF-8",
		"locale_source": "environment", "encoding": "UTF-8", "encoding_is_utf8": true, "utf8_available": nil,
		"locale_env": map[string]any{"LANG": "en_US.UTF-8"}, "codepage_ansi": nil})
	if r.Status != StPartial || !paHasNote(r, "locale command is not available") {
		t.Errorf("status %s notes %v", r.Status, r.Notes)
	}
}

func TestTimeLocaleWithLocaleCommand(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	seoul := time.FixedZone("KST", 9*3600)
	e.Clock = time.Date(2026, 1, 2, 3, 4, 5, 0, seoul)
	e.PathBins["locale"] = "/usr/bin/locale"
	e.Cmds["locale"] = fakeCmd{Stdout: "LANG=\nLC_CTYPE=\"C.UTF-8\"\n"}
	e.Cmds["locale charmap"] = fakeCmd{Stdout: "UTF-8\n"}
	e.Cmds["locale -k decimal_point d_fmt"] = fakeCmd{Stdout: "decimal_point=\".\"\nd_fmt=\"%m/%d/%y\"\n"}
	e.Cmds["locale -a"] = fakeCmd{Stdout: "C\nC.utf8\nPOSIX\n"}
	r := paRun(t, e, "os.time_locale")
	paWant(t, r, map[string]any{"utc_offset": "+0900", "locale": "C.UTF-8", "locale_source": "locale command (LC_CTYPE)",
		"encoding": "UTF-8", "utf8_available": true, "decimal_separator": ".", "date_format": "%m/%d/%y", "timezone": nil})
	if r.Status != StOK || r.Facts["decimal_sep"] != "." {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
}

func TestTimeLocalePosixTZRunsDate(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	e.Vars["TZ"] = "JST-9"
	e.PathBins["date"] = "/bin/date"
	e.Cmds["date +%z"] = fakeCmd{Stdout: "+0900\n"}
	r := paRun(t, e, "os.time_locale")
	paWant(t, r, map[string]any{"utc_offset": "+0900", "timezone": "JST-9", "locale": "C", "encoding": "ANSI_X3.4-1968"})
	delete(e.PathBins, "date")
	r = paRun(t, e, "os.time_locale")
	paWant(t, r, map[string]any{"utc_offset": nil})
	if !paHasNote(r, "UTC offset unknown") {
		t.Errorf("notes %v", r.Notes)
	}
}

func TestTimezoneFromLocaltimeLink(t *testing.T) {
	root := paTree(t, map[string]string{"usr/share/zoneinfo/Europe/Berlin": "TZif"})
	e := newFakeEnv(t, root)
	if err := symlinkOrSkip(t, "../usr/share/zoneinfo/Europe/Berlin", root+"/etc/localtime"); err != nil {
		t.Skip("symlinks not available:", err)
	}
	r := paRun(t, e, "os.time_locale")
	paWant(t, r, map[string]any{"timezone": "Europe/Berlin"})
}

func TestHealthFromFixture(t *testing.T) {
	e := paLinux(t)
	r := paRun(t, e, "os.health")
	paWant(t, r, map[string]any{"uptime_seconds": "86400", "last_boot_utc": "2026-01-01T03:04:05Z",
		"load": []any{"0.52", "0.48", "0.40"}, "pending_reboot": nil, "pending_reasons": []any{}})
	if r.Status != StOK || r.Facts["uptime_s"] != "86400" {
		t.Errorf("status %s facts %v", r.Status, r.Facts)
	}
}

func TestHealthPendingRebootAndKernels(t *testing.T) {
	root := paTree(t, map[string]string{"proc/uptime": "100.5 1.0\n", "run/reboot-required": "",
		"run/reboot-required.pkgs": "linux-base\nlibc6\n", "lib/modules/5.15.0-100-generic/": "",
		"lib/modules/5.15.0-105-generic/": ""})
	e := newFakeEnv(t, root)
	e.UnameV = Uname{Sysname: "Linux", Release: "5.15.0-100-generic"}
	r := paRun(t, e, "os.health")
	paWant(t, r, map[string]any{"pending_reboot": true, "load": nil, "pending_reasons": []any{
		"reboot-required flag file present", "packages: linux-base libc6",
		"newer kernel installed: 5.15.0-105-generic (running 5.15.0-100-generic)"}})
	e.UnameV.Release = "5.10.0-1-generic"
	r = paRun(t, e, "os.health")
	if rs := paPlain(mustGet(r, "pending_reasons")).([]any); len(rs) != 3 || rs[2] != "modules of the running kernel 5.10.0-1-generic are no longer installed" {
		t.Errorf("reasons %v", rs)
	}
}

func TestHealthUptimeCommandFallback(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	e.PathBins["uptime"] = "/usr/bin/uptime"
	e.Cmds["uptime"] = fakeCmd{Stdout: " 10:00:00 up 3 days,  2:05,  2 users,  load average: 0.10, 0.20, 0.30\n"}
	r := paRun(t, e, "os.health")
	paWant(t, r, map[string]any{"uptime_seconds": "266700", "load": []any{"0.10", "0.20", "0.30"}})
	e.Cmds["uptime"] = fakeCmd{Stdout: " 10:00:00 up 5 min,  1 user,  load average: 1.00, 2.00, 3.00\n"}
	paWant(t, paRun(t, e, "os.health"), map[string]any{"uptime_seconds": "300"})
	e.Cmds["uptime"] = fakeCmd{Stdout: " 10:00 up 2 hrs, load averages: 1.00 2.00 3.00\n"}
	paWant(t, paRun(t, e, "os.health"), map[string]any{"uptime_seconds": "7200", "load": []any{"1.00", "2.00", "3.00"}})
}

func mustGet(r *Result, k string) any {
	v, _ := r.Data.Get(k)
	return v
}

func TestVersionHelpers(t *testing.T) {
	if paVersionOf("GNU bash, version 5.1.16(1)-release") != "5.1.16" || paVersionOf("x 12 y") != "12" || paVersionOf("none") != "" {
		t.Error("paVersionOf")
	}
	cases := []struct {
		a, b string
		want int
	}{{"5.15.0-105", "5.15.0-99", 1}, {"1.0", "1.0.0", 0}, {"2", "10", -1}, {"", "1", -1}}
	for _, c := range cases {
		if got := paVercmp(c.a, c.b); got != c.want {
			t.Errorf("vercmp(%s,%s)=%d", c.a, c.b, got)
		}
	}
	if paUnquote(` "a b" `) != "a b" || paUnquote(`'x'`) != "x" || paUnquote("v\r") != "v" {
		t.Error("paUnquote")
	}
	if !paNumLess("99", "100") || paNumLess("100", "099") {
		t.Error("paNumLess")
	}
}
