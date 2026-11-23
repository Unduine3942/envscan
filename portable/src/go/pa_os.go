// pa_os.go: os.identity (port of src/sh/20-os.sh probe_os_identity, Linux branches).
package main

import (
	"strings"
)

func init() {
	registerProbe("os.identity", probeOSIdentity)
	registerProbe("os.time_locale", probeOSTimeLocale)
	registerProbe("os.health", probeOSHealth)
}

// paRelease holds what the distribution release files say.
type paRelease struct {
	name, pretty, vid, ver, did, like, build, variant string
	osr, rh, deb, alp                                 string
}

// paUname is uname(2) (sh ES_UNAME_*, read at scan start); empty fields when it failed.
func paUname(e Env) Uname {
	u, err := e.Uname()
	if err != nil {
		return Uname{}
	}
	return u
}

// paIdent is what os.identity found.
type paIdent struct {
	u                                    Uname
	rel                                  paRelease
	processor, banner, kernel, wsl, wslv string
	pretty, vid, bits, osArch, procArch  string
	host, fqdn, dom, krb, sssd, joined   string
}

func probeOSIdentity(e Env, r *Result) {
	x := paIdent{u: paUname(e)}
	r.Src("syscall uname (at scan start)")
	if c := tool(e, r, RunOpt{}, "uname", "-p"); c.Exit == 0 {
		x.processor, _ = paFirstLine(c.Stdout)
	}
	if x.processor == "unknown" {
		x.processor = ""
	}
	x.rel = paReadRelease(e, r)
	x.kernel = x.u.Release
	if l, ok := readFirstLine(e, r, "/proc/version"); ok {
		x.banner = l
	}
	if l, ok := readFirstLine(e, r, "/proc/sys/kernel/osrelease"); ok {
		x.kernel = l
	}
	x.wsl, x.wslv = paWSL(e, x.kernel, x.banner)
	x.pretty = x.rel.pretty
	if x.pretty == "" && x.rel.name != "" {
		x.pretty = x.rel.name + " " + paOr(x.rel.ver, x.rel.vid)
	}
	if x.pretty == "" {
		x.pretty = x.u.Sysname + " " + x.u.Release
	}
	x.pretty = paTrim(x.pretty)
	x.vid = paOr(x.rel.vid, x.u.Release)
	if c := tool(e, r, RunOpt{}, "getconf", "LONG_BIT"); c.Exit == 0 {
		x.bits, _ = paFirstLine(c.Stdout)
	}
	x.osArch, x.procArch = e.Arch(), e.Arch()
	if x.bits == "32" {
		x.procArch = paArch32(x.osArch)
	}
	x.host = paOr(e.Hostname(), "unknown")
	x.fqdn, x.dom = paDomain(e, r, x.host)
	x.krb, x.sssd, x.joined = paDirectory(e, r)
	paIdentData(e, r.Data, &x)
	if e.OS() == "linux" && x.rel.osr == "" && x.rel.rh == "" && x.rel.alp == "" {
		r.Partial("no os-release, lsb-release or distribution release file was readable")
	}
	for k, v := range map[string]string{"os_name": x.pretty, "os_version": x.vid, "os_arch": x.osArch,
		"process_arch": x.procArch, "distro_id": x.rel.did, "os_kernel": x.kernel, "wsl": x.wsl, "rosetta": "",
		"userland_bits": x.bits} {
		r.Fact(k, v)
	}
}

func paIdentData(e Env, d *Obj, x *paIdent) {
	rel := x.rel
	d.Set("family", e.OS()).Set("name", x.pretty).Set("version", strOrNil(x.vid)).Set("build", strOrNil(rel.build))
	d.Set("edition", strOrNil(rel.variant)).Set("kernel", strOrNil(x.kernel)).Set("kernel_version", strOrNil(x.u.Version))
	d.Set("kernel_banner", strOrNil(x.banner)).Set("arch", x.osArch).Set("machine", strOrNil(x.u.Machine))
	d.Set("processor", strOrNil(x.processor)).Set("process_arch", x.procArch).Set("userland_bits", num(x.bits))
	d.Set("hostname", x.host).Set("fqdn", strOrNil(x.fqdn)).Set("domain", strOrNil(x.dom))
	d.Set("domain_joined", boolOrNil(x.joined)).Set("directory_joined", boolOrNil(x.joined))
	d.Set("kerberos_config", boolOrNil(x.krb)).Set("sssd_config", boolOrNil(x.sssd)).Set("install_type", nil)
	d.Set("distro_id", strOrNil(rel.did)).Set("distro_like", strOrNil(rel.like)).Set("distro_version", strOrNil(rel.ver))
	d.Set("redhat_release", strOrNil(rel.rh)).Set("debian_version", strOrNil(rel.deb)).Set("alpine_version", strOrNil(rel.alp))
	paSetWSL(e, d, x.wsl, x.wslv)
	d.Set("rosetta", nil)
}

func paOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func paArch32(a string) string {
	switch a {
	case "x86_64":
		return "x86"
	case "arm64":
		return "arm"
	case "ppc64":
		return "ppc"
	case "sparc64":
		return "sparc"
	}
	return a
}

func paWSL(e Env, kernel, banner string) (string, string) {
	if e.OS() != "linux" {
		return "false", ""
	}
	s := kernel + " " + banner
	switch {
	case strings.Contains(s, "WSL2") || strings.Contains(s, "microsoft-standard"):
		return "true", "2"
	case strings.Contains(s, "Microsoft") || strings.Contains(s, "microsoft"):
		return "true", "1"
	}
	return "false", ""
}

func paSetWSL(e Env, d *Obj, wsl, wslv string) {
	if e.OS() == "linux" {
		d.Set("wsl", boolOrNil(wsl)).Set("wsl_version", num(wslv))
		return
	}
	d.Set("wsl", nil).Set("wsl_version", nil)
}

// paReadRelease reads /etc/os-release (or /usr/lib/os-release), /etc/lsb-release and the
// redhat, debian and alpine release files like sh.
func paReadRelease(e Env, r *Result) paRelease {
	var rel paRelease
	for _, f := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if text, ok := readText(e, r, f, 65536); ok {
			rel.osr = f
			paParseOSRelease(text, &rel)
			break
		}
	}
	if rel.pretty == "" {
		if text, ok := readText(e, r, "/etc/lsb-release", 65536); ok {
			paParseLSB(text, &rel)
		}
	}
	if l, ok := readFirstLine(e, r, "/etc/redhat-release"); ok {
		rel.rh = l
		rel.pretty = paOr(rel.pretty, l)
		if rel.vid == "" {
			rel.vid = paVersionOf(l)
		}
	}
	if l, ok := readFirstLine(e, r, "/etc/debian_version"); ok {
		rel.deb = l
	}
	if l, ok := readFirstLine(e, r, "/etc/alpine-release"); ok {
		rel.alp = l
	}
	return rel
}

func paParseOSRelease(text string, rel *paRelease) {
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = paUnquote(v)
		switch k {
		case "NAME":
			rel.name = v
		case "PRETTY_NAME":
			rel.pretty = v
		case "VERSION_ID":
			rel.vid = v
		case "VERSION":
			rel.ver = v
		case "ID":
			rel.did = v
		case "ID_LIKE":
			rel.like = v
		case "BUILD_ID":
			rel.build = v
		case "VARIANT_ID":
			rel.variant = v
		}
	}
}

func paParseLSB(text string, rel *paRelease) {
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = paUnquote(v)
		switch k {
		case "DISTRIB_ID":
			if rel.did == "" {
				rel.did = strings.ToLower(v)
			}
		case "DISTRIB_RELEASE":
			if rel.vid == "" {
				rel.vid = v
			}
		case "DISTRIB_DESCRIPTION":
			rel.pretty = v
		}
	}
}

// paDomain: the FQDN from the host name or /etc/hosts, the domain from it or /etc/resolv.conf.
func paDomain(e Env, r *Result, host string) (string, string) {
	fqdn := ""
	if strings.Contains(host, ".") {
		fqdn = host
	}
	if fqdn == "" {
		if text, _, err := e.ReadText("/etc/hosts", 1<<20); err == nil {
			r.Src("read /etc/hosts (own host name)")
			fqdn = paHostsFQDN(text, host)
		}
	}
	dom := ""
	if fqdn != "" {
		_, dom, _ = strings.Cut(fqdn, ".")
	}
	if dom == "" {
		if text, _, err := e.ReadText("/etc/resolv.conf", 1<<20); err == nil {
			for _, l := range lines(text) {
				if f := strings.Fields(l); len(f) >= 2 && f[0] == "domain" {
					dom = f[1]
					break
				}
			}
		}
	}
	return fqdn, dom
}

// paHostsFQDN: on a hosts line that names HOST, the first name that starts with "HOST.".
func paHostsFQDN(text, host string) string {
	for _, l := range lines(text) {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		f := strings.Fields(l)
		if len(f) < 2 || !paHasStr(f[1:], host) {
			continue
		}
		for _, n := range f[1:] {
			if strings.HasPrefix(n, host+".") {
				return n
			}
		}
	}
	return ""
}

func paHasStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func paDirectory(e Env, r *Result) (krb, sssd, joined string) {
	krb, sssd = "false", "false"
	if e.Exists("/etc/krb5.conf") {
		krb = "true"
	}
	if e.Exists("/etc/sssd/sssd.conf") {
		sssd = "true"
	}
	r.Src("test /etc/krb5.conf, /etc/sssd/sssd.conf (presence only)")
	if sssd == "true" {
		joined = "true"
	} else if krb == "false" && e.OS() == "linux" {
		joined = "false"
	}
	return krb, sssd, joined
}
