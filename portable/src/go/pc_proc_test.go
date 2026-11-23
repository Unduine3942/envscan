package main

import (
	"strings"
	"testing"
)

const psUID = `    1     0     0 systemd         /sbin/init splash
  812     1   104 dbus-daemon     /usr/bin/dbus-daemon --system --address=systemd:
 2001     1  1000 bash            -bash
 2002  2001  1000 python3         /usr/bin/python3 app.py --token=x
`

func TestProcListNumericUIDs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nmessagebus:x:104:110::/nonexistent:/usr/sbin/nologin\nu:x:1000:1000::/home/u:/bin/bash\n")
	e := newFakeEnv(t, root)
	e.FactsIn["user"], e.FactsIn["uid"] = "u", "1000"
	bin(e, "ps -A -o pid= -o ppid= -o uid= -o comm= -o args=", fakeCmd{Stdout: psUID})
	r := run(e, "proc.list", probeProcList)
	ps := objs(t, get(t, r.Data, "processes"))
	eq(t, "count", get(t, r.Data, "count"), NumText("4"))
	eq(t, "users", []string{ps[0].Str("user"), ps[1].Str("user"), ps[3].Str("user")}, []string{"root", "messagebus", "u"})
	eq(t, "foreign cmdline", get(t, ps[1], "cmdline"), nil)
	eq(t, "own cmdline", get(t, ps[3], "cmdline"), Cmd("/usr/bin/python3 app.py --token=x"))
	eq(t, "own path", get(t, ps[3], "path"), "/usr/bin/python3")
	eq(t, "own no abs path", get(t, ps[2], "path"), nil)
	eq(t, "pid", get(t, ps[3], "pid"), NumText("2002"))
	eq(t, "keys", ps[0].Keys(), []string{"pid", "ppid", "name", "user", "path", "cmdline"})
	eq(t, "fact", r.Facts["proc_count"], "4")
	eq(t, "truncated", get(t, r.Data, "truncated"), false)
}

const psEF = `UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 10:15 ?        00:00:02 /sbin/init
u           2001       1  0 Nov03 pts/0    00:00:00 -bash
`

func TestProcListFallbacks(t *testing.T) {
	e := newFakeEnv(t, t.TempDir())
	e.FactsIn["user"] = "u"
	bin(e, "ps -A -o pid= -o ppid= -o uid= -o comm= -o args=", fakeCmd{Exit: 1, Stderr: "ps: unknown option"})
	e.Cmds["ps -A -o pid= -o ppid= -o user= -o comm= -o args="] = fakeCmd{Exit: 1}
	e.Cmds["ps -ef"] = fakeCmd{Stdout: psEF}
	r := run(e, "proc.list", probeProcList)
	ps := objs(t, get(t, r.Data, "processes"))
	eq(t, "ef rows", len(ps), 2)
	eq(t, "ef name", []string{ps[0].Str("name"), ps[1].Str("name")}, []string{"init", "-bash"})
	eq(t, "ef own", get(t, ps[1], "cmdline"), Cmd("-bash"))
	root := t.TempDir()
	writeFile(t, root, "/etc/nsswitch.conf", "passwd: files sss\n")
	e2 := newFakeEnv(t, root)
	bin(e2, "ps -A -o pid= -o ppid= -o uid= -o comm= -o args=", fakeCmd{Exit: 1})
	r2 := run(e2, "proc.list", probeProcList)
	eq(t, "nss refused", hasNote(r2, "NSS"), true)
	eq(t, "nss not run", strings.Join(e2.Ran, ","), "ps -A -o pid= -o ppid= -o uid= -o comm= -o args=")
	r3 := run(newFakeEnv(t, t.TempDir()), "proc.list", probeProcList)
	eq(t, "no ps", []any{r3.Status, get(t, r3.Data, "count")}, []any{StPartial, nil})
}

func TestProcListCapped(t *testing.T) {
	e := newFakeEnv(t, "")
	var b strings.Builder
	for i := 1; i <= 505; i++ {
		b.WriteString(itoa(i) + " 1 0 x /x\n")
	}
	bin(e, "ps -A -o pid= -o ppid= -o uid= -o comm= -o args=", fakeCmd{Stdout: b.String()})
	r := run(e, "proc.list", probeProcList)
	eq(t, "listed", len(objs(t, get(t, r.Data, "processes"))), 500)
	eq(t, "count", get(t, r.Data, "count"), NumText("505"))
	eq(t, "truncated", []any{get(t, r.Data, "truncated"), r.Truncated}, []any{true, true})
}

// units: a failed unit carries a bullet (U+25CF) before its name.
const units = "  cron.service      loaded active running Regular background program processing daemon\n" +
	"\u25cf ufw.service       loaded failed failed  Uncomplicated firewall\n"
const unitFiles = "cron.service enabled enabled\nufw.service disabled enabled\n"

func TestSvcList(t *testing.T) {
	e := newFakeEnv(t, "")
	bin(e, "systemctl list-units --type=service --all --no-legend --no-pager", fakeCmd{Stdout: units})
	e.Cmds["systemctl list-unit-files --type=service --no-legend --no-pager"] = fakeCmd{Stdout: unitFiles}
	r := run(e, "svc.list", probeSvcList)
	s := objs(t, get(t, r.Data, "services"))
	eq(t, "manager", get(t, r.Data, "manager"), "systemd")
	eq(t, "cron", []string{s[0].Str("name"), s[0].Str("display"), s[0].Str("state"), s[0].Str("start_mode")},
		[]string{"cron.service", "Regular background program processing daemon", "active/running", "enabled"})
	eq(t, "ufw bullet", []string{s[1].Str("name"), s[1].Str("state")}, []string{"ufw.service", "failed/failed"})
	eq(t, "count", get(t, r.Data, "count"), NumText("2"))
	root := t.TempDir()
	writeFile(t, root, "/etc/init.d/ssh", "#!/bin/sh\n")
	writeFile(t, root, "/etc/init.d/.hidden", "")
	r2 := run(newFakeEnv(t, root), "svc.list", probeSvcList)
	eq(t, "sysvinit", get(t, r2.Data, "manager"), "sysvinit")
	eq(t, "init names", len(objs(t, get(t, r2.Data, "services"))), 1)
	r3 := run(newFakeEnv(t, ""), "svc.list", probeSvcList)
	eq(t, "none", []any{r3.Status, get(t, r3.Data, "count")}, []any{StNotFound, NumText("0")})
}

func TestSchedTasks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/cron.d/backup", "0 1 * * * root /backup\n")
	writeFile(t, root, "/etc/cron.daily/logrotate", "")
	e := newFakeEnv(t, root)
	e.FactsIn["user"] = "u"
	bin(e, "crontab -l", fakeCmd{Stdout: "# m h dom mon dow command\n\n*/5 * * * * /home/u/sync.sh\n"})
	bin(e, "systemctl list-timers --all --no-pager --no-legend", fakeCmd{Stdout: "Mon 2026-01-05 00:00:00 UTC  2 days left  n/a  n/a  logrotate.timer  logrotate.service\n\n"})
	bin(e, "loginctl show-user u -p Linger", fakeCmd{Stdout: "Linger=yes\n"})
	r := run(e, "sched.tasks", probeSchedTasks)
	eq(t, "crontab", get(t, r.Data, "user_crontab"), []any{Cmd("*/5 * * * * /home/u/sync.sh")})
	tasks := objs(t, get(t, r.Data, "tasks"))
	eq(t, "tasks", []string{tasks[0].Str("name"), tasks[0].Str("path"), tasks[1].Str("path")},
		[]string{"backup", "/etc/cron.d", "/etc/cron.daily"})
	eq(t, "timers", strs(t, get(t, r.Data, "timers")), []string{"Mon 2026-01-05 00:00:00 UTC 2 days left n/a n/a logrotate.timer logrotate.service"})
	eq(t, "linger", get(t, r.Data, "linger"), true)
	eq(t, "count", get(t, r.Data, "count"), NumText("3"))
	r2 := run(newFakeEnv(t, ""), "sched.tasks", probeSchedTasks)
	eq(t, "empty", []any{get(t, r2.Data, "linger"), get(t, r2.Data, "count"), r2.Status}, []any{nil, NumText("0"), StOK})
}

func TestVirtPlatformContainer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/.dockerenv", "")
	writeFile(t, root, "/proc/1/cgroup", "0::/kubepods/besteffort/pod1\n")
	writeFile(t, root, "/var/run/docker.sock", "")
	e := newFakeEnv(t, root)
	e.Vars["KUBERNETES_SERVICE_HOST"] = "10.96.0.1"
	r := run(e, "virt.platform", probeVirtPlatform)
	c := obj(t, get(t, r.Data, "container"))
	eq(t, "container", []any{get(t, c, "detected"), get(t, c, "engine"), get(t, c, "kubernetes")}, []any{true, "docker", true})
	eq(t, "virtualization", get(t, r.Data, "virtualization"), "container")
	eq(t, "socket path", get(t, obj(t, get(t, r.Data, "docker_socket")), "path"), "/var/run/docker.sock")
	eq(t, "facts", []string{r.Facts["container"], r.Facts["container_engine"], r.Facts["kubernetes"]}, []string{"true", "docker", "true"})
	eq(t, "kvm", get(t, r.Data, "kvm"), nil)
	eq(t, "overlay", overlayRoot("36 35 0:31 / / rw,relatime - overlay overlay rw\n"), true)
}

func TestVirtPlatformVMAndBareMetal(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/sys/class/dmi/id/sys_vendor", "QEMU\n")
	writeFile(t, root, "/sys/class/dmi/id/product_name", "Standard PC (Q35 + ICH9, 2009)\n")
	writeFile(t, root, "/proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu vme hypervisor lahf_lm\n")
	writeFile(t, root, "/proc/self/mountinfo", "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
	r := run(newFakeEnv(t, root), "virt.platform", probeVirtPlatform)
	eq(t, "vm", []any{get(t, r.Data, "virtualization"), get(t, r.Data, "hypervisor"), get(t, r.Data, "vendor")}, []any{"vm", "kvm", "QEMU"})
	root2 := t.TempDir()
	writeFile(t, root2, "/proc/cpuinfo", "flags\t\t: fpu vme\n")
	r2 := run(newFakeEnv(t, root2), "virt.platform", probeVirtPlatform)
	eq(t, "x86 bare", get(t, r2.Data, "virtualization"), "none")
	e3 := newFakeEnv(t, t.TempDir())
	e3.ArchName = "arm64"
	r3 := run(e3, "virt.platform", probeVirtPlatform)
	eq(t, "arm unknown", get(t, r3.Data, "virtualization"), "unknown")
	e4 := newFakeEnv(t, t.TempDir())
	bin(e4, "systemd-detect-virt", fakeCmd{Stdout: "microsoft\n"})
	r4 := run(e4, "virt.platform", probeVirtPlatform)
	eq(t, "sdv", []any{get(t, r4.Data, "virtualization"), get(t, r4.Data, "hypervisor")}, []any{"vm", "microsoft"})
	e5 := newFakeEnv(t, t.TempDir())
	e5.ArchName = "arm64"
	bin(e5, "systemd-detect-virt", fakeCmd{Stdout: "none\n", Exit: 1})
	r5 := run(e5, "virt.platform", probeVirtPlatform)
	eq(t, "sdv none", get(t, r5.Data, "virtualization"), "none")
	e6 := newFakeEnv(t, t.TempDir())
	e6.FactsIn["wsl"] = "true"
	r6 := run(e6, "virt.platform", probeVirtPlatform)
	eq(t, "wsl", get(t, r6.Data, "virtualization"), "wsl")
}

const dockerInfoOut = `Client:
 Context:    default
Server:
 Server Version: 24.0.7
 Storage Driver: overlay2
 Cgroup Version: 2
 HTTP Proxy: http://proxy.corp:3128
 Insecure Registries:
  registry.corp:5000
  127.0.0.0/8
 Registry Mirrors:
  https://mirror.corp/
 Live Restore Enabled: false
`

func TestVirtEngine(t *testing.T) {
	e := newFakeEnv(t, "")
	bin(e, "docker --context default info", fakeCmd{Stdout: dockerInfoOut})
	e.PathBins["podman"] = "/usr/bin/podman"
	r := run(e, "virt.engine", probeVirtEngine)
	d := obj(t, get(t, r.Data, "docker"))
	eq(t, "exit", get(t, d, "exit_code"), NumText("0"))
	eq(t, "server", get(t, d, "server_version"), "24.0.7")
	eq(t, "proxy", get(t, d, "http_proxy"), "http://proxy.corp:3128")
	eq(t, "mirrors", strs(t, get(t, d, "registry_mirrors")), []string{"https://mirror.corp/"})
	eq(t, "insecure", strs(t, get(t, d, "insecure_registries")), []string{"registry.corp:5000", "127.0.0.0/8"})
	eq(t, "podman", obj(t, get(t, r.Data, "podman")).Str("path"), "/usr/bin/podman")
	e2 := newFakeEnv(t, "")
	bin(e2, "docker --context default info", fakeCmd{Stdout: dockerInfoOut})
	e2.Vars["DOCKER_HOST"] = "tcp://203.0.113.5:2375"
	r2 := run(e2, "virt.engine", probeVirtEngine)
	eq(t, "remote not run", len(e2.Ran), 0)
	eq(t, "remote note", hasNote(r2, "DOCKER_HOST"), true)
	eq(t, "remote status", r2.Status, StNotFound)
	e3 := newFakeEnv(t, "")
	bin(e3, "docker --context default info", fakeCmd{})
	e3.Vars["DOCKER_CONTEXT"] = "prod"
	run(e3, "virt.engine", probeVirtEngine)
	eq(t, "context not run", len(e3.Ran), 0)
}
