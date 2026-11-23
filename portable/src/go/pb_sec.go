// pb_sec.go: sec.app_control and sec.crypto (port of src/sh/23-sec.sh, Linux branches).
package main

import (
	"strings"
)

func init() {
	registerProbe("sec.app_control", probeSecAppControl)
	registerProbe("sec.crypto", probeSecCrypto)
}

type pbAppControl struct {
	se, secfg, ctx, aa, aaprof, fa, sc, nnp, capEff, lock, rro string
	fainst                                                     bool
}

// pbRawFirstLine reads the first line of a small file that may hold NUL bytes (the
// /proc/self/attr files end in one); NULs are dropped like sh tr -d '\000'. ok=false when the
// file is missing, unreadable or empty.
func pbRawFirstLine(e Env, r *Result, p string) (string, bool) {
	b, _, err := e.ReadFile(p, 65536)
	if err != nil {
		if isRefusal(err) {
			r.Note("%s", err.Error())
		}
		return "", false
	}
	if len(b) == 0 {
		return "", false
	}
	r.Src("read %s", p)
	return strings.ReplaceAll(pbFirstLine(string(b)), "\x00", ""), true
}

func pbSELinux(e Env, r *Result, s *pbAppControl) {
	if l, ok := readFirstLine(e, r, "/sys/fs/selinux/enforce"); ok {
		switch l {
		case "1":
			s.se = "enforcing"
		case "0":
			s.se = "permissive"
		}
	}
	text, _, err := e.ReadText("/etc/selinux/config", 1<<20)
	if err != nil {
		return
	}
	r.Src("read /etc/selinux/config")
	for _, l := range lines(text) {
		k, v, _ := strings.Cut(l, "=")
		if k == "SELINUX" {
			v, _, _ = strings.Cut(v, "=")
			s.secfg = v
			break
		}
	}
	if s.se == "" {
		s.se = "disabled"
	}
}

func pbAppArmor(e Env, r *Result, s *pbAppControl) {
	if l, ok := readFirstLine(e, r, "/sys/module/apparmor/parameters/enabled"); ok {
		switch {
		case strings.HasPrefix(l, "Y"):
			s.aa = "enabled"
		case strings.HasPrefix(l, "N"):
			s.aa = "disabled"
		}
	}
	for _, p := range []string{"/proc/self/attr/apparmor/current", "/proc/self/attr/current"} {
		if v, ok := pbRawFirstLine(e, r, p); ok {
			if s.aa == "enabled" {
				s.aaprof = v
			} else {
				s.ctx = v
			}
			break
		}
	}
}

func pbFapolicyd(e Env, r *Result, s *pbAppControl) {
	if pbIsDir(e, "/etc/fapolicyd") {
		r.Src("list /etc/fapolicyd")
		s.fainst = true
	}
	if _, ok := e.Which("systemctl"); !ok {
		return
	}
	if _, has := e.Which("fapolicyd"); !s.fainst && !has {
		return
	}
	c := tool(e, r, RunOpt{}, "systemctl", "is-active", "fapolicyd")
	if c.Exit != 126 && c.Exit != 127 {
		s.fa = pbFirstLine(c.Stdout)
	}
}

func pbProcStatus(e Env, r *Result, s *pbAppControl) {
	text, _, err := e.ReadText("/proc/self/status", 1<<20)
	if err != nil {
		return
	}
	r.Src("read /proc/self/status (Seccomp, NoNewPrivs, CapEff)")
	for _, l := range lines(text) {
		k, v, _ := strings.Cut(l, ":")
		v = pbTrim(v)
		switch k {
		case "Seccomp":
			s.sc = map[string]string{"0": "disabled", "1": "strict", "2": "filter"}[v]
			if s.sc == "" {
				s.sc = v
			}
		case "NoNewPrivs":
			s.nnp = map[string]string{"1": "true", "0": "false"}[v]
		case "CapEff":
			s.capEff = v
		}
	}
}

func pbLockdownRoot(e Env, r *Result, s *pbAppControl) {
	if l, ok := readFirstLine(e, r, "/sys/kernel/security/lockdown"); ok {
		if i := strings.Index(l, "["); i >= 0 {
			l = l[i+1:]
		}
		l, _, _ = strings.Cut(l, "]")
		s.lock = l
	}
	if m, ok := e.MountOf("/"); ok {
		r.Src("read /proc/self/mounts (root read-only, at scan start)")
		s.rro = "false"
		if strings.Contains(","+m.Options+",", ",ro,") {
			s.rro = "true"
		}
	}
}

func probeSecAppControl(e Env, r *Result) {
	s := &pbAppControl{}
	pbSELinux(e, r, s)
	pbAppArmor(e, r, s)
	pbFapolicyd(e, r, s)
	pbProcStatus(e, r, s)
	pbLockdownRoot(e, r, s)
	d := r.Data
	for _, k := range []string{"applocker", "srp", "wdac", "smart_app_control", "exploit_protection"} {
		d.Set(k, nil)
	}
	d.Set("selinux", strOrNil(s.se)).Set("selinux_config", strOrNil(s.secfg))
	d.Set("selinux_context", strOrNil(s.ctx)).Set("apparmor", strOrNil(s.aa))
	d.Set("apparmor_profile", strOrNil(s.aaprof))
	d.Set("fapolicyd", NewObj().Set("installed", s.fainst).Set("state", strOrNil(s.fa)))
	d.Set("seccomp", strOrNil(s.sc)).Set("no_new_privs", boolOrNil(s.nnp))
	d.Set("cap_eff", strOrNil(s.capEff)).Set("lockdown", strOrNil(s.lock))
	d.Set("root_readonly", boolOrNil(s.rro))
	d.Set("sip", nil).Set("gatekeeper", nil).Set("mdm_enrolled", nil)
	r.Fact("selinux", s.se)
	r.Fact("apparmor", s.aa)
	r.Fact("aa_profile", s.aaprof)
	r.Fact("fapolicyd", s.fa)
	r.Fact("root_ro", s.rro)
	r.Fact("cap_eff", s.capEff)
}

func pbCryptoPolicy(e Env, r *Result) string {
	text, _, err := e.ReadText("/etc/crypto-policies/config", 1<<20)
	if err != nil {
		return ""
	}
	r.Src("read /etc/crypto-policies/config")
	for _, l := range lines(text) {
		if t := strings.TrimLeft(l, " \t"); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return l
	}
	return ""
}

func probeSecCrypto(e Env, r *Result) {
	fips := ""
	if l, ok := readFirstLine(e, r, "/proc/sys/crypto/fips_enabled"); ok {
		fips = map[string]string{"1": "true", "0": "false"}[l]
	} else {
		fips = "false"
		r.Note("/proc/sys/crypto/fips_enabled is absent (kernel without FIPS support)")
	}
	pol := pbCryptoPolicy(e, r)
	ov, od := "", ""
	if c, ok := needTool(e, r, RunOpt{}, "openssl", "version", "-a"); ok {
		r.SetRaw("openssl", c.Stdout)
		ov = pbFirstLine(c.Stdout)
		od = pbOpensslDir(c.Stdout)
	}
	r.Src("environment OPENSSL_CONF")
	conf, _ := e.Getenv("OPENSSL_CONF")
	r.Data.Set("fips", boolOrNil(fips)).Set("crypto_policy", strOrNil(pol))
	r.Data.Set("openssl_version", strOrNil(ov)).Set("openssl_dir", strOrNil(od))
	r.Data.Set("openssl_conf", strOrNil(conf)).Set("schannel", nil).Set("dotnet_strong_crypto", nil)
	r.Fact("fips", fips)
	r.Fact("crypto_policy", pol)
	r.Fact("openssl_version", ov)
}

// pbOpensslDir: the OPENSSLDIR line of openssl version -a, without quotes (awk -F ': ' $2).
func pbOpensslDir(out string) string {
	for _, l := range lines(out) {
		if strings.HasPrefix(l, "OPENSSLDIR") {
			parts := strings.Split(l, ": ")
			if len(parts) < 2 {
				return ""
			}
			return strings.ReplaceAll(parts[1], `"`, "")
		}
	}
	return ""
}
