// pc_virt.go: virt.platform and virt.engine (port of src/sh/27-fs.sh, Linux; owner: probes-c).
package main

import (
	"regexp"
	"strings"
)

func init() {
	registerProbe("virt.platform", probeVirtPlatform)
	registerProbe("virt.engine", probeVirtEngine)
}

// virtState carries the sh variables of probe_virt_platform.
type virtState struct {
	ctr, k8s, vmflag   bool
	eng, hyp, vend     string
	model, sdv, kvm, v string
}

// cgroupEngine: the first /proc/1/cgroup line naming a container engine decides.
func cgroupEngine(text string) string {
	for _, l := range lines(text) {
		for _, m := range [][2]string{{"kubepods", "kubernetes"}, {"libpod", "podman"}, {"docker", "docker"},
			{"containerd", "containerd"}, {"lxc", "lxc"}} {
			if strings.Contains(l, m[0]) {
				return m[1]
			}
		}
	}
	return ""
}

// overlayRoot: /proc/self/mountinfo mounts an overlay file system on "/".
func overlayRoot(text string) bool {
	for _, l := range lines(text) {
		if field(awkFields(l), 5) == "/" && strings.Contains(l, " - overlay ") {
			return true
		}
	}
	return false
}

func (s *virtState) container(eng string) {
	s.ctr = true
	if s.eng == "" {
		s.eng = eng
	}
}

func virtContainer(e Env, r *Result, s *virtState) {
	r.Src("read /.dockerenv, /run/.containerenv, /proc/1/cgroup, /proc/self/mountinfo")
	if e.Exists("/.dockerenv") {
		s.ctr, s.eng = true, "docker"
	}
	if e.Exists("/run/.containerenv") {
		s.ctr, s.eng = true, "podman"
	}
	if text, ok := readQuiet(e, "/proc/1/cgroup"); ok {
		if cg := cgroupEngine(text); cg != "" {
			s.container(cg)
			s.k8s = s.k8s || cg == "kubernetes"
		}
	}
	if text, ok := readQuiet(e, "/proc/self/mountinfo"); ok && overlayRoot(text) {
		s.container("unknown")
	}
	r.Src("environment KUBERNETES_SERVICE_HOST, container, WSL_DISTRO_NAME")
	if v, _ := e.Getenv("KUBERNETES_SERVICE_HOST"); v != "" {
		s.k8s = true
		s.container("kubernetes")
	}
	if v, _ := e.Getenv("container"); v != "" {
		s.container(v)
	}
}

var hypMarks = []struct {
	re  *regexp.Regexp
	hyp string
}{
	{regexp.MustCompile(`QEMU|KVM`), "kvm"}, {regexp.MustCompile(`VMware`), "vmware"},
	{regexp.MustCompile(`Microsoft.*Virtual`), "hyperv"}, {regexp.MustCompile(`innotek|VirtualBox`), "virtualbox"},
	{regexp.MustCompile(`Xen`), "xen"}, {regexp.MustCompile(`Amazon`), "aws"}, {regexp.MustCompile(`Google`), "gce"},
	{regexp.MustCompile(`OpenStack`), "openstack"}, {regexp.MustCompile(`Parallels`), "parallels"},
	{regexp.MustCompile(`Nutanix`), "nutanix"},
}

func hypervisorOf(vendModel string) string {
	for _, m := range hypMarks {
		if m.re.MatchString(vendModel) {
			return m.hyp
		}
	}
	return ""
}

// hypervisorFlag: a "flags" line of /proc/cpuinfo has the hypervisor flag (grep '^flags.* hypervisor').
func hypervisorFlag(text string) bool {
	for _, l := range lines(text) {
		if strings.HasPrefix(l, "flags") && strings.Contains(l[5:], " hypervisor") {
			return true
		}
	}
	return false
}

func virtHardware(e Env, r *Result, s *virtState) {
	if l, ok := readFirstLine(e, r, "/sys/class/dmi/id/sys_vendor"); ok {
		s.vend = l
	}
	if l, ok := readFirstLine(e, r, "/sys/class/dmi/id/product_name"); ok {
		s.model = l
	}
	s.hyp = hypervisorOf(s.vend + " " + s.model)
	if text, ok := readQuiet(e, "/proc/cpuinfo"); ok && hypervisorFlag(text) {
		r.Src("read /proc/cpuinfo (hypervisor flag)")
		s.vmflag = true
	}
	c := tool(e, r, RunOpt{}, "systemd-detect-virt")
	if (c.Exit == 0 || c.Exit == 1) && c.Stdout != "" {
		s.sdv = firstLine(c.Stdout)
	}
	r.Src("test /dev/kvm, /var/run/docker.sock, $XDG_RUNTIME_DIR/podman/podman.sock")
	if st, err := e.Stat("/dev/kvm"); err == nil {
		s.kvm = boolText(access(e, st, 4) && access(e, st, 2))
	}
}

// virtVerdict is sh es_v: container, wsl, vm, none or unknown.
func virtVerdict(e Env, r *Result, s *virtState) {
	switch {
	case s.ctr:
		s.v = "container"
	case e.Fact("wsl") == "true":
		s.v = "wsl"
	case s.hyp != "" || s.vmflag:
		s.v = "vm"
	case s.sdv == "none":
		s.v = "none"
	case s.sdv == "":
		s.v = "unknown"
		switch a := e.Arch(); {
		case a == "x86_64" || a == "amd64" || a == "i86pc" || a == "x86" || len(a) == 4 && a[0] == 'i' && a[2:] == "86":
			if readable(e, "/proc/cpuinfo") {
				s.v = "none"
			}
		}
		if s.v == "unknown" {
			r.Note("no source here can tell a virtual machine from bare metal (no systemd-detect-virt; the cpuinfo hypervisor flag is only reliable on x86)")
		}
	default:
		s.v = "vm"
	}
	if s.hyp == "" {
		switch s.sdv {
		case "none", "", "docker", "podman", "lxc", "wsl", "container-other", "systemd-nspawn":
		default:
			s.hyp = s.sdv
		}
	}
}

func probeVirtPlatform(e Env, r *Result) {
	s := &virtState{}
	virtContainer(e, r, s)
	virtHardware(e, r, s)
	virtVerdict(e, r, s)
	r.Data.Set("virtualization", s.v).Set("hypervisor", strOrNil(s.hyp)).Set("vendor", strOrNil(s.vend)).
		Set("model", strOrNil(s.model)).Set("systemd_detect_virt", strOrNil(s.sdv))
	r.Data.Set("container", NewObj().Set("detected", s.ctr).Set("engine", strOrNil(s.eng)).Set("kubernetes", s.k8s))
	r.Data.Set("wsl_distros", nil)
	sock := NewObj().Set("path", nil).Set("accessible", nil)
	if e.Exists("/var/run/docker.sock") {
		acc := false
		if st, err := e.Stat("/var/run/docker.sock"); err == nil {
			acc = access(e, st, 4) && access(e, st, 2)
		}
		sock.Set("path", "/var/run/docker.sock").Set("accessible", acc)
	}
	r.Data.Set("docker_socket", sock)
	ps := ""
	if xr, _ := e.Getenv("XDG_RUNTIME_DIR"); xr != "" && e.Refused(xr+"/podman/podman.sock") == "" && e.Exists(xr+"/podman/podman.sock") {
		ps = xr + "/podman/podman.sock"
	}
	r.Data.Set("podman_socket", strOrNil(ps)).Set("kvm", boolOrNil(s.kvm))
	r.Fact("virtualization", s.v)
	r.Fact("container", boolText(s.ctr))
	r.Fact("container_engine", s.eng)
	r.Fact("kubernetes", boolText(s.k8s))
}

// ---------------------------------------------------------------- virt.engine

var (
	dockerKeyRe = regexp.MustCompile(`^ *(Server Version|Storage Driver|Cgroup Driver|Cgroup Version|Docker Root Dir|Operating System|Kernel Version|HTTP Proxy|HTTPS Proxy|No Proxy|Security Options|Rootless):`)
	mirrorRe    = regexp.MustCompile(`^ +[a-z]+://`)
	insecureRe  = regexp.MustCompile(`^ +[^ ]`)
)

// dockerRemote is sh es_runnable_os for docker: a remote engine must never be contacted.
func dockerRemote(e Env) string {
	h, _ := e.Getenv("DOCKER_HOST")
	for _, p := range []string{"tcp://", "ssh://", "http://", "https://"} {
		if strings.HasPrefix(h, p) {
			return "DOCKER_HOST points to a remote engine (not executed)"
		}
	}
	if c, _ := e.Getenv("DOCKER_CONTEXT"); c != "" {
		return "DOCKER_CONTEXT is set and may name a remote engine (not executed)"
	}
	return ""
}

// dockerInfo parses docker info output into the docker object (after exit_code).
func dockerInfo(o *Obj, out string) {
	for _, l := range lines(out) {
		if !dockerKeyRe.MatchString(l) {
			continue
		}
		k, v, _ := strings.Cut(l, ":")
		k = strings.ToLower(strings.ReplaceAll(strings.TrimLeft(k, " "), " ", "_"))
		o.Set(k, strings.TrimLeft(v, " "))
	}
	o.Set("registry_mirrors", strList(dockerBlock(out, "Registry Mirrors:", func(l string) bool { return mirrorRe.MatchString(l) })))
	o.Set("insecure_registries", strList(dockerBlock(out, "Insecure Registries:", func(l string) bool {
		return insecureRe.MatchString(l) && !strings.HasSuffix(l, ":")
	})))
}

// dockerBlock: the indented lines after a "  Header:" line that match keep (leading blanks removed).
func dockerBlock(out, header string, keep func(string) bool) []string {
	res := []string{}
	in := false
	for _, l := range lines(out) {
		if strings.HasPrefix(strings.TrimLeft(l, " "), header) {
			in = true
			continue
		}
		if in && keep(l) {
			res = append(res, strings.TrimLeft(l, " "))
			continue
		}
		in = false
	}
	return res
}

func probeVirtEngine(e Env, r *Result) {
	found := false
	if p, ok := e.Which("docker"); ok {
		why := dockerRemote(e)
		if why == "" {
			if ok, w := e.Runnable(p); !ok {
				why = w
			}
		}
		if why != "" {
			r.Note("docker: %s", why)
		} else {
			c := runPath(e, r, RunOpt{MergeStderr: true}, p, "--context", "default", "info")
			r.SetRaw("docker_info", c.Stdout)
			o := NewObj().Set("exit_code", num(itoa(c.Exit)))
			dockerInfo(o, c.Stdout)
			r.Data.Set("docker", o)
			found = true
		}
	}
	if p, ok := e.Which("podman"); ok {
		r.Data.Set("podman", NewObj().Set("path", p).Set("detail", "podman info is not run; the version is in tools.inventory"))
		found = true
	}
	if !found {
		r.SetStatus(StNotFound, "no runnable docker CLI and no podman")
	}
}
