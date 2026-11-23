// pc_util.go: helpers shared by the net.*, fs.*, proc.list, svc.list, sched.tasks and virt.* probes
// (owner: probes-c). Small ports of the awk idioms of src/sh/26-net.sh and 27-fs.sh.
package main

import (
	"errors"
	"io/fs"
	"strings"
)

// awkFields splits like awk's default FS: runs of blanks (space, tab) separate fields.
func awkFields(s string) []string {
	return strings.FieldsFunc(s, func(c rune) bool { return c == ' ' || c == '\t' || c == '\n' })
}

// field is awk $n (1-based; "" when absent).
func field(f []string, n int) string {
	if n < 1 || n > len(f) {
		return ""
	}
	return f[n-1]
}

// substr is awk substr(s, start, n) for ASCII text (1-based, clipped).
func substr(s string, start, n int) string {
	if start < 1 {
		n += start - 1
		start = 1
	}
	if n <= 0 || start > len(s) {
		return ""
	}
	end := start - 1 + n
	if end > len(s) {
		end = len(s)
	}
	return s[start-1 : end]
}

// awkInt is awk's "$x + 0" for a leading decimal integer ("" and text give 0).
func awkInt(s string) int {
	n := 0
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n > 1<<40 {
			break
		}
	}
	return n
}

// dedupLines drops empty lines and repeats (awk 'NF && !s[$0]++' on joined text: order kept).
func dedupLines(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range in {
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// strList is es_list: the non-empty lines as an array of strings.
func strList(in []string) []any {
	out := []any{}
	for _, l := range in {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// isNum is es_is_num: an unsigned integer.
func isNum(s string) bool { return allDigits(s) }

// boolText is the sh spelling of a boolean ("true"/"false").
func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// readSrc reads a text file like readText but records SRC (sh es_src text) instead of "read PATH";
// src "" records nothing. Refusals become notes; binary content makes the probe partial.
func readSrc(e Env, r *Result, path, src string) (string, bool) {
	text, truncated, err := e.ReadText(path, 1<<20)
	switch {
	case err == nil:
		if src != "" {
			r.Src("%s", src)
		}
		if truncated {
			r.Truncated = true
		}
		return text, true
	case errors.Is(err, ErrBinary):
		if src != "" {
			r.Src("%s", src)
		}
		r.Partial(path + " not read: UTF-16 or binary content")
	case isRefusal(err):
		r.Note("%s", err.Error())
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, ErrNotRegular):
	default:
		r.Note("%s: %v", path, err)
	}
	return "", false
}

// readQuiet reads a small file without any source or note (sh awk on a file that may be absent).
func readQuiet(e Env, path string) (string, bool) {
	text, _, err := e.ReadText(path, 1<<20)
	return text, err == nil
}

// readable is sh [ -r FILE ] for a regular file, vetted (a refused path is not readable).
func readable(e Env, path string) bool {
	if e.Refused(path) != "" {
		return false
	}
	st, err := e.Stat(path)
	return err == nil && st.Type == TypeFile
}

// isDir is sh [ -d PATH ] on a vetted path (a link is followed after vetting).
func isDir(e Env, path string) bool {
	if e.Refused(path) != "" {
		return false
	}
	st, err := e.Stat(path)
	return err == nil && st.Type == TypeDir
}

// isFile is sh [ -f PATH ].
func isFile(e Env, path string) bool {
	if e.Refused(path) != "" {
		return false
	}
	st, err := e.Stat(path)
	return err == nil && st.Type == TypeFile
}

// access is sh [ -r ] / [ -w ] from the mode bits and the scan's ids (want 4 = read, 2 = write).
// Unknown owners (-1) are judged by the "any" bits.
func access(e Env, st FileInfo, want uint32) bool {
	ids := e.Ids()
	if ids.EUID == 0 && st.UID != -1 {
		return true
	}
	if st.UID != -1 && st.UID == ids.EUID {
		return st.Mode&(want<<6) != 0
	}
	if st.UID == -1 {
		return st.Mode&(want<<6|want<<3|want) != 0
	}
	if inGroup(ids, st.GID) {
		return st.Mode&(want<<3) != 0
	}
	return st.Mode&want != 0
}

func inGroup(ids Ids, gid int) bool {
	if gid == ids.EGID {
		return true
	}
	for _, g := range ids.Groups {
		if g == gid {
			return true
		}
	}
	return false
}

// normDir is sh es_normdir: repeated "/" collapsed and trailing "/" removed (text only).
func normDir(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// trimBlank is sh es_trim: a trailing CR, then leading and trailing blanks removed.
func trimBlank(s string) string {
	s = strings.TrimSuffix(s, "\r")
	return strings.Trim(s, " \t")
}

// unquote is sh es_unquote: trimmed, one pair of surrounding quotes removed.
func unquote(s string) string {
	s = trimBlank(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// credRefusal: the refusal reason names a credential store (sh ES_CREDLINK).
func credRefusal(why string) bool { return strings.Contains(why, "credential") }

// firstLine is the first line of text without CR ("" when empty).
func firstLine(text string) string {
	l, _, _ := strings.Cut(text, "\n")
	return strings.TrimSuffix(l, "\r")
}
