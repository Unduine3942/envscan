// pb_native.go: native.deps (port of src/sh/25-tools.sh probe_native_deps, Linux branches).
package main

import (
	"sort"
	"strconv"
	"strings"
)

func init() {
	registerProbe("native.deps", probeNativeDeps)
}

// pbLibstdcxxMax caps the read of libstdc++.so.6 (sh reads the whole file with tr; the library
// is about 2-3 MB).
const pbLibstdcxxMax = 32 << 20

// pbLibc identifies the C library: getconf GNU_LIBC_VERSION, /lib/ld-musl-*, ldd --version.
func pbLibc(e Env, r *Result) (string, string) {
	kind, ver := "", ""
	if c := tool(e, r, RunOpt{}, "getconf", "GNU_LIBC_VERSION"); c.Exit == 0 {
		if l := pbFirstLine(c.Stdout); l != "" {
			f := append(strings.Fields(l), "", "")
			kind, ver = "glibc", f[1]
		}
	}
	if kind == "" {
		if ms, _ := e.Glob("/lib/ld-musl-*"); len(ms) > 0 {
			r.Src("list /lib/ld-musl-*")
			kind = "musl"
		}
	}
	if kind == "glibc" {
		return kind, ver
	}
	p, ok := e.Which("ldd")
	if !ok {
		return kind, ver
	}
	if run, _ := e.Runnable(p); !run {
		return kind, ver
	}
	out := runPath(e, r, RunOpt{MergeStderr: true}, p, "--version").Stdout
	lo := strings.ToLower(out)
	switch {
	case strings.Contains(lo, "musl"):
		kind, ver = "musl", ""
		for _, l := range lines(out) {
			if strings.HasPrefix(l, "Version") {
				f := append(strings.Fields(l), "")
				ver = f[1]
				break
			}
		}
	case kind == "" && (strings.Contains(lo, "glibc") || strings.Contains(lo, "gnu libc")):
		kind = "glibc"
		l := pbFirstLine(out)
		ver = l[strings.LastIndex(l, " ")+1:]
	}
	return kind, ver
}

// pbLdcache: libssl names and the libstdc++.so.6 path from ldconfig -p.
func pbLdcache(e Env, r *Result) ([]string, string) {
	ldc, ok := e.Which("ldconfig")
	if !ok {
		ldc = ""
		for _, f := range []string{"/sbin/ldconfig", "/usr/sbin/ldconfig"} {
			if pbExecFile(e, f) {
				ldc = f
				break
			}
		}
	}
	if ldc == "" {
		return nil, ""
	}
	c := runPath(e, r, RunOpt{}, ldc, "-p")
	if c.Exit != 0 {
		return nil, ""
	}
	ssl, cxx := []string{}, ""
	for _, l := range lines(c.Stdout) {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if strings.HasPrefix(f[0], "libssl.so") {
			ssl = pbAppendOnce(ssl, f[0])
		}
		if f[0] == "libstdc++.so.6" && cxx == "" {
			cxx = f[len(f)-1]
		}
	}
	sort.Strings(ssl)
	return ssl, cxx
}

// pbLibFiles lists /lib*, /usr/lib*, /usr/local/lib for libssl and libstdc++ (no find sweep).
func pbLibFiles(e Env, r *Result) ([]string, string) {
	r.Src("list /lib*, /usr/lib*, /usr/local/lib for libssl and libstdc++")
	ssl, cxx := []string{}, ""
	for _, pat := range []string{"/lib*/libssl.so.*", "/usr/lib*/libssl.so.*", "/usr/lib/*/libssl.so.*", "/usr/local/lib*/libssl.so.*"} {
		ms, _ := e.Glob(pat)
		for _, m := range ms {
			ssl = append(ssl, pbBase(m))
		}
	}
	for _, pat := range []string{"/usr/lib*/libstdc++.so.6", "/usr/lib/*/libstdc++.so.6", "/lib*/libstdc++.so.6", "/lib/*/libstdc++.so.6"} {
		if ms, _ := e.Glob(pat); len(ms) > 0 && cxx == "" {
			cxx = ms[0]
		}
	}
	return ssl, cxx
}

func pbIsWordByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.'
}

// pbGlibcxxMax: the highest GLIBCXX_<version> string in the library bytes (sh tr | grep | awk:
// four numeric components compared).
func pbGlibcxxMax(b []byte) string {
	best, bv := "", [4]int{}
	for i := 0; i < len(b); {
		if !pbIsWordByte(b[i]) {
			i++
			continue
		}
		j := i
		for j < len(b) && pbIsWordByte(b[j]) {
			j++
		}
		tok := string(b[i:j])
		i = j
		if !strings.HasPrefix(tok, "GLIBCXX_") || len(tok) < 9 || tok[8] < '0' || tok[8] > '9' {
			continue
		}
		v := tok[8:]
		a := [4]int{}
		for k, p := range strings.Split(v, ".") {
			if k < 4 {
				a[k] = pbAtoiPrefix(p)
			}
		}
		if best == "" || pbVerGreater(a, bv) {
			best, bv = v, a
		}
	}
	return best
}

func pbVerGreater(a, b [4]int) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// pbAtoiPrefix is awk's string-to-number: the leading digits ("" = 0).
func pbAtoiPrefix(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	v, _ := strconv.Atoi(s[:n])
	return v
}

func pbOdbcDrivers(e Env, r *Result) string {
	text, _, err := e.ReadText("/etc/odbcinst.ini", 1<<20)
	if err != nil {
		return ""
	}
	r.Src("read /etc/odbcinst.ini")
	out := []string{}
	for _, l := range lines(text) {
		if !strings.HasPrefix(l, "[") || !strings.Contains(l[1:], "]") {
			continue
		}
		s := l[1 : strings.Index(l[1:], "]")+1]
		if s != "ODBC" {
			out = append(out, s)
		}
	}
	return strings.Join(out, "\n")
}

func probeNativeDeps(e Env, r *Result) {
	kind, ver := pbLibc(e, r)
	ssl, cxx := pbLdcache(e, r)
	if len(ssl) == 0 && cxx == "" {
		ssl, cxx = pbLibFiles(e, r)
	}
	gx := ""
	if cxx != "" {
		if b, _, err := e.ReadFile(cxx, pbLibstdcxxMax); err == nil {
			r.Src("read libstdc++.so.6 (GLIBCXX version strings)")
			gx = pbGlibcxxMax(b)
		}
	}
	odbc := pbOdbcDrivers(e, r)
	fonts := ""
	opt := RunOpt{Env: []string{"XDG_CACHE_HOME=" + e.TempDir() + "/fc-cache"}}
	if c := tool(e, r, opt, "fc-list"); c.Exit == 0 {
		fonts = itoa(len(lines(c.Stdout)))
	}
	d := r.Data
	d.Set("libc", NewObj().Set("kind", strOrNil(kind)).Set("version", strOrNil(ver)))
	d.Set("glibcxx_max", strOrNil(gx)).Set("libstdcxx_path", strOrNil(cxx))
	d.Set("libssl", pbList(pbLines(ssl)))
	d.Set("vcredist", nil).Set("ucrt", nil).Set("webview2", nil)
	d.Set("odbc_drivers", pbList(odbc)).Set("fonts_count", num(fonts))
	if kind == "" {
		r.Partial("C library could not be identified")
	}
	r.Fact("libc_kind", kind)
	r.Fact("libc_version", ver)
	r.Fact("glibcxx_max", gx)
}
