// pb_tls.go: tls.trust and tls.java_cacerts (port of src/sh/23-sec.sh, Linux branches).
package main

import (
	"regexp"
	"strings"
	"time"
)

func init() {
	registerProbe("tls.trust", probeTLSTrust)
	registerProbe("tls.java_cacerts", probeTLSJavaCacerts)
}

const pbBundleMax = 16 << 20

// pbBundles: the readable CA bundles with their certificate counts (grep -c, lines).
func pbBundles(e Env, sk *pbSkips) ([]any, string, string) {
	items := []any{}
	first, rootc := "", ""
	for _, p := range spec.CABundles {
		if !pbLocal(e, sk, p) {
			continue
		}
		b, _, err := e.ReadFile(p, pbBundleMax)
		if err != nil {
			continue
		}
		n := 0
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, "BEGIN CERTIFICATE") {
				n++
			}
		}
		items = append(items, NewObj().Set("path", p).Set("certs", num(itoa(n))))
		if first == "" {
			first, rootc = p, itoa(n)
		}
	}
	return items, first, rootc
}

// pbAnchors: the files directly in, or one folder below, each custom anchor directory.
func pbAnchors(e Env, sk *pbSkips) []string {
	out := []string{}
	for _, d := range spec.CAAnchorDirs {
		if !pbLocal(e, sk, d) || !pbIsDir(e, d) {
			continue
		}
		for _, pat := range []string{d + "/*", d + "/*/*"} {
			for _, f := range pbGlob(e, sk, pat) {
				if pbIsFile(e, f) {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

// pbAnchorRoots runs openssl x509 on at most 25 anchors; returns the roots items and subjects.
func pbAnchorRoots(e Env, r *Result, anchors []string) ([]any, []string) {
	ossl := ""
	if p, ok := e.Which("openssl"); ok {
		if run, _ := e.Runnable(p); run {
			ossl = p
		}
	}
	roots, subjects := []any{}, []string{}
	for i, f := range anchors {
		subj, until := "", ""
		if ossl != "" && i < 25 {
			c := runPath(e, r, RunOpt{}, ossl, "x509", "-noout", "-subject", "-enddate", "-in", f)
			if c.Exit == 0 {
				for _, l := range lines(c.Stdout) {
					switch {
					case strings.HasPrefix(l, "subject="):
						subj = pbTrim(strings.TrimPrefix(l, "subject="))
					case strings.HasPrefix(l, "notAfter="):
						until = strings.TrimPrefix(l, "notAfter=")
					}
				}
			}
		}
		if subj == "" {
			subj = pbBase(f)
		}
		roots = append(roots, NewObj().Set("subject", subj).Set("thumbprint", nil).
			Set("not_after", strOrNil(until)).Set("store", "anchors").Set("origin", f))
		subjects = append(subjects, subj)
	}
	return roots, subjects
}

// pbRuntimeTrust: the TLS variables that are set, and those that turn verification off.
func pbRuntimeTrust(e Env) (*Obj, []string) {
	o, dis := NewObj(), []string{}
	for _, v := range spec.TLSEnv {
		val, _ := e.Getenv(v)
		if val == "" {
			continue
		}
		o.Set(v, Named{Name: v, Value: val})
		switch {
		case v == "NODE_TLS_REJECT_UNAUTHORIZED" && val == "0", v == "PYTHONHTTPSVERIFY" && val == "0":
			dis = append(dis, v+"=0")
		case v == "GIT_SSL_NO_VERIFY" && val != "0" && val != "false":
			dis = append(dis, v+"="+val)
		}
	}
	return o, dis
}

// pbLsDate is the date of ls -l: "Mon D HH:MM" within six months of now, else "Mon D YYYY".
func pbLsDate(t, now time.Time) string {
	const half = 15778476 * time.Second
	if t.After(now.Add(-half)) && t.Before(now.Add(half)) {
		return t.Format("Jan 2 15:04")
	}
	return t.Format("Jan 2 2006")
}

func pbJavaCacerts(e Env, r *Result, sk *pbSkips) any {
	jh, _ := e.Getenv("JAVA_HOME")
	if jh == "" {
		return nil
	}
	for _, f := range []string{jh + "/lib/security/cacerts", jh + "/jre/lib/security/cacerts"} {
		if !pbLocal(e, sk, f) || !pbIsFile(e, f) {
			continue
		}
		r.Src("read $JAVA_HOME/lib/security/cacerts (size and date)")
		fi, err := e.Stat(f)
		o := NewObj().Set("path", f)
		if err != nil {
			return o.Set("size_bytes", nil).Set("modified", "  ")
		}
		return o.Set("size_bytes", num(itoa(int(fi.Size)))).Set("modified", pbLsDate(fi.ModTime, e.Now()))
	}
	return nil
}

func probeTLSTrust(e Env, r *Result) {
	sk := &pbSkips{}
	r.Src("read CA bundles listed in spec/configs.toml (certificate count)")
	bundles, first, rootc := pbBundles(e, sk)
	r.Src("list custom anchor directories from spec/configs.toml")
	anchors := pbAnchors(e, sk)
	roots, subjects := pbAnchorRoots(e, r, anchors)
	d := r.Data
	d.Set("bundles", bundles).Set("roots", roots)
	d.Set("enterprise_roots", pbList(pbLines(subjects))).Set("custom_anchors", pbList(pbLines(anchors)))
	d.Set("root_count", num(rootc)).Set("authroot_count", nil).Set("root_auto_update", nil)
	d.Set("default_bundle", strOrNil(first))
	r.Src("environment TLS variables")
	rt, dis := pbRuntimeTrust(e)
	d.Set("runtime_trust", rt)
	d.Set("java_cacerts", pbJavaCacerts(e, r, sk))
	if first == "" && len(anchors) == 0 {
		r.Partial("no CA bundle found in the known locations")
	}
	sk.note(r)
	r.Fact("ca_custom", itoa(len(anchors)))
	r.Fact("ca_subjects", pbLines(subjects))
	r.Fact("tls_disabled_env", pbLines(dis))
	r.Fact("ca_bundle", first)
}

// pbKeytool finds keytool ($JAVA_HOME/bin first, then PATH).
func pbKeytool(e Env, sk *pbSkips) string {
	if jh, _ := e.Getenv("JAVA_HOME"); jh != "" {
		p := jh + "/bin/keytool"
		if pbLocal(e, sk, p) && pbExecFile(e, p) {
			return p
		}
	}
	p, _ := e.Which("keytool")
	return p
}

var pbIllegalOpt = regexp.MustCompile(`(?i)illegal option|unknown option`)

func pbRunKeytool(e Env, r *Result, kt string, sk *pbSkips) CmdResult {
	c := runPath(e, r, RunOpt{}, kt, "-list", "-v", "-cacerts", "-storepass", "changeit")
	if c.Exit == 0 || !pbIllegalOpt.MatchString(c.Stdout+"\n"+c.Stderr) {
		return c
	}
	kh := strings.TrimSuffix(kt, "/bin/keytool")
	for _, f := range []string{kh + "/lib/security/cacerts", kh + "/jre/lib/security/cacerts"} {
		if pbLocal(e, sk, f) && pbIsFile(e, f) {
			return runPath(e, r, RunOpt{}, kt, "-list", "-v", "-keystore", f, "-storepass", "changeit")
		}
	}
	return c
}

var pbCNRe = regexp.MustCompile(`CN ?= ?[^,/]+`)
var pbCNPrefix = regexp.MustCompile(`^CN ?= ?`)

func pbKeytoolParse(out string) (string, []string) {
	cnt, owners := "", []string{}
	for _, l := range lines(out) {
		if cnt == "" && strings.Contains(l, "Your keystore contains") {
			for _, f := range strings.Fields(l) {
				if allDigits(f) {
					cnt = f
					break
				}
			}
		}
		if strings.HasPrefix(l, "Owner: ") {
			owners = append(owners, strings.TrimPrefix(l, "Owner: "))
		}
	}
	return cnt, owners
}

func pbMissingRoots(subjects string, owners []string) []string {
	all := strings.Join(owners, "\n")
	missing := []string{}
	for _, s := range lines(subjects) {
		cn := s
		if m := pbCNRe.FindString(s); m != "" {
			cn = pbCNPrefix.ReplaceAllString(m, "")
		}
		if cn != "" && !strings.Contains(all, cn) {
			missing = append(missing, cn)
		}
	}
	return missing
}

func probeTLSJavaCacerts(e Env, r *Result) {
	sk := &pbSkips{}
	defer sk.note(r)
	kt := pbKeytool(e, sk)
	if kt == "" {
		r.SetStatus(StNotFound, "keytool was not found (JAVA_HOME/bin, PATH)")
		return
	}
	if ok, why := e.Runnable(kt); !ok {
		r.SetStatus(StSkipped, kt+": "+why)
		return
	}
	c := pbRunKeytool(e, r, kt, sk)
	if c.Exit != 0 {
		r.SetRaw("keytool", c.Stdout+c.Stderr)
		r.Fail("keytool failed (exit " + itoa(c.Exit) + ")")
		return
	}
	cnt, owners := pbKeytoolParse(c.Stdout)
	ol := []any{}
	for _, o := range owners {
		if o != "" && len(ol) < 400 {
			ol = append(ol, o)
		}
	}
	missing := pbMissingRoots(e.Fact("ca_subjects"), owners)
	r.Data.Set("keytool", kt).Set("entries", num(cnt)).Set("owners", ol)
	r.Data.Set("enterprise_roots_missing", pbList(pbLines(missing)))
	r.Fact("java_missing_roots", pbLines(missing))
}
