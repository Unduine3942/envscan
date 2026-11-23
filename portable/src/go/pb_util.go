// pb_util.go: helpers shared by the probes-b files (ports of sh 10-core.sh / 11-policy.sh
// helpers that the Env API does not give directly). Every name starts with "pb" so that it
// cannot clash with another agent's file in the same package.
package main

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

// pbSkips collects what a probe left out (sh ES_NETSKIP / ES_CREDSKIP) for its notes.
type pbSkips struct {
	net  []string
	cred []string
}

func (s *pbSkips) addNet(p string)  { s.net = pbAppendOnce(s.net, p) }
func (s *pbSkips) addCred(p string) { s.cred = pbAppendOnce(s.cred, p) }

// note is sh es_netskip_note: one partial note per link into a credential store and one note
// listing (at most five) paths left out because they are on network or autofs mounts.
func (s *pbSkips) note(r *Result) {
	for _, p := range s.cred {
		r.Partial(p + " not read: link to a credential store")
	}
	if len(s.net) == 0 {
		return
	}
	shown := s.net
	if len(shown) > 5 {
		shown = shown[:5]
	}
	l := strings.Join(shown, ", ")
	if len(s.net) > 5 {
		l += " and " + itoa(len(s.net)-5) + " more"
	}
	r.Note("not read because they are on network or autofs mounts (nothing there is touched): %s", l)
}

// skip files a refusal reason under the right list.
func (s *pbSkips) skip(p, reason string) {
	if strings.Contains(reason, "credential") {
		s.addCred(p)
		return
	}
	s.addNet(p)
}

func pbAppendOnce(list []string, v string) []string {
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}

func pbHasGlob(p string) bool { return strings.ContainsAny(p, "*?[") }

// pbExpand is sh es_expand: the existing paths a spec pattern names ("~", "{env:NAME}", globs).
// A path that names a credential store as written is skipped silently (sh es_cred_path); a path
// on a network or autofs mount, or a link into either, is recorded in sk.
func pbExpand(e Env, sk *pbSkips, pattern string) []string {
	p, ok := e.Expand(pattern)
	if !ok || !strings.HasPrefix(p, "/") {
		return nil
	}
	if !pbHasGlob(p) {
		return pbTake(e, sk, p)
	}
	return pbGlob(e, sk, p)
}

// pbTake is sh es_glob_take: keep P when it exists (a link counts) and may be touched.
func pbTake(e Env, sk *pbSkips, p string) []string {
	if why := e.Refused(p); why != "" {
		if !strings.Contains(why, "credential") {
			sk.addNet(p)
		}
		return nil
	}
	if _, err := e.Lstat(p); err != nil {
		var rf *Refusal
		if asRefusal(err, &rf) {
			sk.skip(p, rf.Reason)
		}
		return nil
	}
	return []string{p}
}

func asRefusal(err error, out **Refusal) bool { return errors.As(err, out) }

// pbGlob is sh es_glob for an absolute pattern: a glob whose base folder is refused, or that has
// a network or autofs mount below its base, is skipped whole (and noted).
func pbGlob(e Env, sk *pbSkips, p string) []string {
	base := p[:strings.IndexAny(p, "*?[")]
	base = base[:strings.LastIndex(base, "/")]
	if base == "" {
		base = "/"
	}
	if why := e.Refused(base); why != "" {
		if !strings.Contains(why, "credential") {
			sk.addNet(p)
		}
		return nil
	}
	if pbNetMountUnder(e, base) {
		sk.addNet(p)
		return nil
	}
	matches, err := e.Glob(p)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, m := range matches {
		out = append(out, pbTake(e, sk, m)...)
	}
	return out
}

// pbNetMountUnder is sh es_netmnt_under: a network or autofs mount point lies below DIR.
func pbNetMountUnder(e Env, dir string) bool {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for _, m := range e.Mounts() {
		if m.Dir != "/" && strings.HasPrefix(m.Dir, prefix) && e.IsNetPath(m.Dir) {
			return true
		}
	}
	return false
}

// pbIsExec says whether a Stat result is an executable regular file (a seam for the tests:
// Windows test hosts have no execute bits).
var pbIsExec = func(fi FileInfo) bool { return fi.Type == TypeFile && fi.Mode&0o111 != 0 }

// pbExecFile is sh es_exec_file: P is an executable file (links followed only after vetting).
func pbExecFile(e Env, p string) bool {
	fi, err := e.Stat(p)
	return err == nil && pbIsExec(fi)
}

// pbIsDir is [ -d P ] on a vetted path.
func pbIsDir(e Env, p string) bool {
	fi, err := e.Stat(p)
	return err == nil && fi.Type == TypeDir
}

// pbIsFile is [ -f P ] on a vetted path.
func pbIsFile(e Env, p string) bool {
	fi, err := e.Stat(p)
	return err == nil && fi.Type == TypeFile
}

// pbPathDirs: the absolute PATH entries that are not on a network or autofs mount (sh
// ES_PATH_SKIP), in order.
func pbPathDirs(e Env) []string {
	v, _ := e.Getenv("PATH")
	out := []string{}
	for _, d := range strings.Split(v, ":") {
		if !strings.HasPrefix(d, "/") || e.Refused(d) != "" || e.IsNetPath(d) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// pbWhichAll is sh es_which_all: every executable NAME on PATH, de-duplicated, in PATH order.
func pbWhichAll(e Env, name string) []string {
	out := []string{}
	for _, d := range pbPathDirs(e) {
		p := d + "/" + name
		if pbExecFile(e, p) {
			out = pbAppendOnce(out, p)
		}
	}
	return out
}

// pbResolve is sh es_resolve: P with every link, "." and ".." resolved. ok is false when a
// component is refused (network mount or credential store); the result then holds the part
// resolved so far plus the unresolved rest, and reason says why.
func pbResolve(e Env, p string) (string, bool, string) {
	if !strings.HasPrefix(p, "/") {
		return p, true, ""
	}
	rest, cur, links := p, "", 0
	for {
		rest = strings.TrimLeft(rest, "/")
		if rest == "" {
			break
		}
		c, after, _ := strings.Cut(rest, "/")
		rest = after
		switch c {
		case ".":
			continue
		case "..":
			cur = cur[:max(strings.LastIndex(cur, "/"), 0)]
			continue
		}
		cur += "/" + c
		fi, why, err := pbLstatVetted(e, cur)
		if why != "" {
			return pbJoinRest(cur, rest), false, why
		}
		if err != nil || fi.Type != TypeLink || links >= 32 {
			continue
		}
		links++
		t, err := e.Readlink(cur)
		if err != nil {
			continue
		}
		if strings.HasPrefix(t, "/") {
			cur = ""
		} else {
			cur = cur[:strings.LastIndex(cur, "/")]
		}
		rest = pbJoinRest(t, rest)
	}
	if cur == "" {
		cur = "/"
	}
	return cur, true, ""
}

// pbLstatVetted: Lstat of P, with the refusal reason when P must not be touched.
func pbLstatVetted(e Env, p string) (FileInfo, string, error) {
	if why := e.Refused(p); why != "" {
		return FileInfo{}, why, nil
	}
	fi, err := e.Lstat(p)
	var rf *Refusal
	if err != nil && asRefusal(err, &rf) {
		return fi, rf.Reason, err
	}
	return fi, "", err
}

func pbJoinRest(cur, rest string) string {
	if rest == "" {
		return cur
	}
	return cur + "/" + rest
}

// pbRealpath is sh es_realpath (the resolved path, also when resolution stopped).
func pbRealpath(e Env, p string) string {
	rp, _, _ := pbResolve(e, p)
	return rp
}

// pbLocal is sh es_local_path / es_ltest's vetting: P resolves without touching a refused path.
func pbLocal(e Env, sk *pbSkips, p string) bool {
	_, ok, why := pbResolve(e, p)
	if !ok && sk != nil {
		sk.skip(p, why)
	}
	return ok
}

// pbTrim is sh es_trim: blanks and tabs around, a trailing CR removed.
func pbTrim(s string) string { return strings.Trim(strings.TrimSuffix(s, "\r"), " \t") }

// pbUnquote is sh es_unquote: trimmed, one pair of surrounding quotes removed.
func pbUnquote(s string) string {
	t := pbTrim(s)
	if len(t) >= 2 && ((t[0] == '"' && t[len(t)-1] == '"') || (t[0] == '\'' && t[len(t)-1] == '\'')) {
		return t[1 : len(t)-1]
	}
	return t
}

var (
	pbDottedRe = regexp.MustCompile(`[0-9]+(\.[0-9]+)+`)
	pbNumberRe = regexp.MustCompile(`[0-9]+`)
)

// pbVersionOf is sh es_version_of: the first dotted version (or bare number) in the first line
// that has one.
func pbVersionOf(text string) string {
	for _, l := range strings.Split(text, "\n") {
		if m := pbDottedRe.FindString(l); m != "" {
			return m
		}
		if m := pbNumberRe.FindString(l); m != "" {
			return m
		}
	}
	return ""
}

// pbNormArch is sh es_norm_arch.
func pbNormArch(a string) string {
	switch a {
	case "x86_64", "amd64", "AMD64", "x64", "X86_64":
		return "x86_64"
	case "i386", "i486", "i586", "i686", "x86", "i86pc", "i86", "X86":
		return "x86"
	case "aarch64", "arm64", "ARM64", "aarch64_be", "arm64e":
		return "arm64"
	case "ppc64le", "powerpc64le":
		return "ppc64le"
	case "ppc64", "powerpc64":
		return "ppc64"
	case "ppc", "powerpc":
		return "ppc"
	case "s390x", "riscv64", "ia64", "sparc":
		return a
	case "sparc64", "sun4u", "sun4v", "sparcv9":
		return "sparc64"
	}
	switch {
	case strings.HasPrefix(a, "arm"), strings.HasPrefix(a, "ARM"):
		return "arm"
	case strings.HasPrefix(a, "mips"):
		return "mips"
	}
	return "other"
}

// pbList is sh es_list: the non-empty lines of TEXT as an array of strings.
func pbList(text string) []any { return nonEmptyLines(text) }

// pbLines joins values as newline-terminated lines (the sh "$x$ES_NL" accumulators).
func pbLines(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	return strings.Join(vals, "\n") + "\n"
}

// pbFirstLine: the first line of TEXT without CR.
func pbFirstLine(text string) string {
	first, _, _ := strings.Cut(text, "\n")
	return strings.TrimSuffix(first, "\r")
}

func pbBase(p string) string { return path.Base(p) }

func pbDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func pbBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
