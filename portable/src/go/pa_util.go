// pa_util.go: small helpers of the probes-a files (ports of sh es_trim, es_unquote, es_version_of,
// es_vercmp, es_is_num, es_iso_epoch, es_resolve, es_which_all and the [ -w ] test).
package main

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// paPseudoFS is sh ES_PSEUDO_FS (10-core.sh).
var paPseudoFS = map[string]bool{}

func init() {
	for _, t := range strings.Fields("proc sysfs devpts cgroup cgroup2 mqueue tracefs securityfs debugfs pstore bpf " +
		"configfs fusectl hugetlbfs binfmt_misc rpc_pipefs nsfs selinuxfs efivarfs autofs devtmpfs ramfs " +
		"fuse.gvfsd-fuse fuse.portal overlay squashfs") {
		paPseudoFS[t] = true
	}
}

// paTrim is sh es_trim: one trailing CR, then blanks (space, tab) on both ends.
func paTrim(s string) string {
	s = strings.TrimSuffix(s, "\r")
	return strings.Trim(s, " \t")
}

// paUnquote is sh es_unquote: es_trim, then one pair of surrounding quotes.
func paUnquote(s string) string {
	s = paTrim(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	if s == "\"" || s == "'" {
		return ""
	}
	return s
}

var (
	paDottedRe = regexp.MustCompile(`[0-9]+(\.[0-9]+)+`)
	paDigitsRe = regexp.MustCompile(`[0-9]+`)
)

// paVersionOf is sh es_version_of: the first dotted version (else bare number) of the first line
// that has one.
func paVersionOf(text string) string {
	for _, l := range lines(text) {
		if m := paDottedRe.FindString(l); m != "" {
			return m
		}
		if m := paDigitsRe.FindString(l); m != "" {
			return m
		}
	}
	return ""
}

// paVercmp is sh es_vercmp: -1, 0, 1 comparing the numeric runs of two versions.
func paVercmp(a, b string) int {
	sep := func(r rune) bool { return r < '0' || r > '9' }
	pa, pb := paSplitKeepEmpty(a, sep), paSplitKeepEmpty(b, sep)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		x, y := paAtoiAt(pa, i), paAtoiAt(pb, i)
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

// paSplitKeepEmpty mirrors awk split(s, A, /[^0-9]+/): leading/trailing empty fields kept.
func paSplitKeepEmpty(s string, sep func(rune) bool) []string {
	if s == "" {
		return nil
	}
	out, cur, inSep := []string{}, "", false
	for _, r := range s {
		if sep(r) {
			if !inSep {
				out = append(out, cur)
				cur = ""
			}
			inSep = true
			continue
		}
		inSep = false
		cur += string(r)
	}
	return append(out, cur)
}

func paAtoiAt(parts []string, i int) float64 {
	if i >= len(parts) {
		return 0
	}
	f, _ := strconv.ParseFloat(parts[i], 64)
	return f
}

// paIsNum is sh es_is_num: an unsigned integer.
func paIsNum(s string) bool { return allDigits(s) }

// paNumLess compares two unsigned integer strings (any length).
func paNumLess(a, b string) bool {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// paISO is sh es_iso_epoch: seconds since the epoch as UTC "YYYY-MM-DDTHH:MM:SSZ".
func paISO(sec int64) string { return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z") }

// paResolve is sh es_resolve: links in every component, ".", ".." and repeated "/" resolved.
// It stops (ok=false) at a path the Env refuses (network/autofs mount, credential store) and
// returns the resolved part plus the unresolved rest.
func paResolve(e Env, p string) (string, bool) {
	if !strings.HasPrefix(p, "/") {
		return p, true
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
			if i := strings.LastIndex(cur, "/"); i >= 0 {
				cur = cur[:i]
			}
			continue
		}
		cur += "/" + c
		if e.Refused(cur) != "" {
			return paJoinRest(cur, rest), false
		}
		fi, err := e.Lstat(cur)
		if err != nil || fi.Type != TypeLink {
			continue
		}
		links++
		if links > 32 {
			break
		}
		t, err := e.Readlink(cur)
		if err != nil {
			continue
		}
		if strings.HasPrefix(t, "/") {
			cur = ""
		} else {
			cur = cur[:strings.LastIndex(cur, "/")]
		}
		rest = paJoinRest(t, rest)
	}
	out := paJoinRest(cur, rest)
	if out == "" {
		out = "/"
	}
	return out, e.Refused(out) == ""
}

func paJoinRest(cur, rest string) string {
	if rest == "" {
		return cur
	}
	return cur + "/" + rest
}

// paBase is ${p##*/}.
func paBase(p string) string { return p[strings.LastIndex(p, "/")+1:] }

// paWritable approximates the shell's [ -w PATH ] (access(2) W_OK) from the file's mode, owner
// and group, the scanner's ids, and a read-only mount. ACLs are not seen.
func paWritable(e Env, p string, fi FileInfo) bool {
	if m, ok := e.MountOf(p); ok && paHasOpt(m.Options, "ro") {
		return false
	}
	ids := e.Ids()
	if ids.EUID == 0 {
		return true
	}
	if fi.UID < 0 || fi.UID == ids.EUID {
		return fi.Mode&0o200 != 0
	}
	if fi.GID == ids.EGID || paHasInt(ids.Groups, fi.GID) {
		return fi.Mode&0o020 != 0
	}
	return fi.Mode&0o002 != 0
}

func paHasOpt(opts, want string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == want {
			return true
		}
	}
	return false
}

func paHasInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// paIsDir is the shell's [ -d PATH ] through Env (a refused path is not a directory).
func paIsDir(e Env, p string) bool {
	fi, err := e.Stat(p)
	return err == nil && fi.Type == TypeDir
}

// paWhichAll is sh es_which_all: every executable NAME in the absolute PATH entries that are not
// on a network or autofs mount (no link into one is followed), de-duplicated.
func paWhichAll(e Env, name string) []string {
	pathv, _ := e.Getenv("PATH")
	out, seen := []string{}, map[string]bool{}
	for _, d := range strings.Split(pathv, ":") {
		if !strings.HasPrefix(d, "/") || e.Refused(d) != "" {
			continue
		}
		if _, ok := paResolve(e, d); !ok {
			continue
		}
		p := d + "/" + name
		fi, err := e.Stat(p)
		if err != nil || fi.Type != TypeFile || fi.Mode&0o111 == 0 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// paRunBoth runs a resolved tool like sh "es_tool ...; cat ERR >> OUT": stdout then stderr.
func paRunBoth(e Env, r *Result, name string, args ...string) (CmdResult, string) {
	c := tool(e, r, RunOpt{}, name, args...)
	return c, c.Stdout + c.Stderr
}

// paFirstLine is sh es_read1 on command output: the first line without CR; ok=false when empty.
func paFirstLine(text string) (string, bool) {
	if text == "" {
		return "", false
	}
	first, _, _ := strings.Cut(text, "\n")
	return strings.TrimSuffix(first, "\r"), true
}

// paListLines is sh es_list_file with a MAX: the first max non-empty lines as type T values.
func paListLines(text string, max int, wrap func(string) any) []any {
	out := []any{}
	for _, l := range lines(text) {
		if l == "" {
			continue
		}
		if max > 0 && len(out) >= max {
			break
		}
		out = append(out, wrap(l))
	}
	return out
}

func paLine(s string) any { return Line(s) }
